import contextlib
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from source_free import (
    ATTESTATION_ACTION_SHA,
    ATTESTATION_PERMISSION_PROFILE,
    ATTESTER_JOB_ID,
    ATTESTER_NEEDS,
    ATTESTER_PERMISSION_PROFILE,
    ATTESTER_RUNNER,
    ATTESTER_TRIGGER,
    HandoffRefusal,
    MAX_PUBLIC_FILE_BYTES,
    MAX_PUBLIC_OUTPUTS,
    SYNTHETIC_PATHS,
    create_synthetic_git_tree,
    main,
    safe_gate_report,
    scan_public_outputs,
    validate_attestation_permissions,
    validate_attester_permissions,
    write_safe_gate_report,
)


class SyntheticTreeTests(unittest.TestCase):
    def test_generated_git_tree_contains_only_generated_files_and_keeps_canary_local(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "synthetic-tree"
            tree = create_synthetic_git_tree(root)
            self.assertEqual(tree.safe_summary(), {
                "status": "generated",
                "entries": 2,
                "canary": "local-only",
            })
            self.assertEqual(repr(tree), "SyntheticTree(<local-only>)")
            self.assertTrue(re.fullmatch(r"[a-f0-9]{40}", tree.commit_sha))
            self.assertEqual(
                tuple(
                    sorted(
                        path.relative_to(root).as_posix()
                        for path in root.rglob("*")
                        if path.is_file() and ".git" not in path.parts
                    )
                ),
                SYNTHETIC_PATHS,
            )
            self.assertIn(tree.canary.encode("ascii"), (root / ".fixture/secret.txt").read_bytes())
            self.assertIn(tree.canary.encode("ascii"), (root / "src/fixture.txt").read_bytes())

            report_path = Path(temporary) / "public-result.json"
            write_safe_gate_report(
                report_path,
                "linux_capsule",
                "receiver-key-artifact-unverified",
            )
            self.assertTrue(scan_public_outputs((report_path,), tree.canary))
            report_bytes = report_path.read_bytes()
            self.assertNotIn(tree.canary.encode("ascii"), report_bytes)
            self.assertNotIn(str(root).encode("utf-8"), report_bytes)
            self.assertEqual(
                json.loads(report_bytes),
                {
                    "reason": "receiver-key-artifact-unverified",
                    "schema_version": 1,
                    "stage": "linux_capsule",
                    "status": "blocked",
                },
            )

    def test_public_canary_scan_refuses_leaked_bytes_without_echoing_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            canary = "synthetic-" + "a" * 64
            output = Path(temporary) / "public-output"
            output.write_text("leak=" + canary, encoding="ascii")
            with self.assertRaisesRegex(HandoffRefusal, "public-canary-present") as error:
                scan_public_outputs((output,), canary)
            self.assertNotIn(canary, str(error.exception))

    def test_public_output_growth_during_read_is_bounded_and_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "public-output"
            output.write_bytes(b"ok")
            canary = "synthetic-" + "a" * 64
            original_fdopen = os.fdopen
            observed_read_sizes = []

            class GrowingReader:
                def __init__(self, handle):
                    self.handle = handle

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc_value, traceback):
                    self.handle.close()

                def fileno(self):
                    return self.handle.fileno()

                def read(self, size=-1):
                    observed_read_sizes.append(size)
                    with open(output, "ab") as append_handle:
                        append_handle.write(b"x" * (MAX_PUBLIC_FILE_BYTES - 1))
                    return self.handle.read(2)

            def fdopen_with_growth(descriptor, mode="r", *args, **kwargs):
                handle = original_fdopen(descriptor, mode, *args, **kwargs)
                if mode == "rb":
                    return GrowingReader(handle)
                return handle

            with patch.object(os, "fdopen", fdopen_with_growth):
                with self.assertRaisesRegex(HandoffRefusal, "public-output-too-large"):
                    scan_public_outputs((output,), canary)

            self.assertEqual(observed_read_sizes, [MAX_PUBLIC_FILE_BYTES + 1])
            self.assertEqual(output.stat().st_size, MAX_PUBLIC_FILE_BYTES + 1)

    def test_existing_or_linked_synthetic_root_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "occupied"
            root.mkdir()
            (root / "unexpected").write_bytes(b"not synthetic")
            with self.assertRaisesRegex(HandoffRefusal, "synthetic-root-not-empty"):
                create_synthetic_git_tree(root)

            linked = Path(temporary) / "linked"
            linked.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(HandoffRefusal, "synthetic-root-invalid"):
                create_synthetic_git_tree(linked)


class PermissionAndGateTests(unittest.TestCase):
    def test_selected_permission_profile_is_exact_and_rejects_any_widening(self):
        self.assertEqual(
            ATTESTATION_PERMISSION_PROFILE,
            {"id-token": "write", "attestations": "write"},
        )
        self.assertEqual(ATTESTATION_ACTION_SHA, "1e69f48acb82d1966a394da916b4c1698aa569d6")
        self.assertTrue(validate_attestation_permissions(dict(ATTESTATION_PERMISSION_PROFILE)))
        for widened in (
            {"id-token": "write", "attestations": "write", "actions": "read"},
            {"id-token": "write", "attestations": "write", "contents": "read"},
            {"id-token": "write", "attestations": "write", "artifact-metadata": "write"},
            {"id-token": "write"},
            {"id-token": "read", "attestations": "write"},
        ):
            with self.subTest(permission_keys=tuple(sorted(widened))):
                self.assertFalse(validate_attestation_permissions(widened))

    def test_every_unproved_handoff_gate_refuses_with_a_fixed_safe_reason(self):
        from source_free import refuse_unproven_gate

        expected = {
            "receiver-key": "windows-cng-key-lifecycle-unproven",
            "capsule": "same-run-artifact-visibility-unproven",
            "sandbox": "windows-confinement-unproven",
        }
        for gate, reason in expected.items():
            with self.subTest(gate=gate):
                with self.assertRaisesRegex(HandoffRefusal, reason) as error:
                    refuse_unproven_gate(gate)
                self.assertEqual(str(error.exception), reason)

        with self.assertRaisesRegex(HandoffRefusal, "gate-unknown"):
            refuse_unproven_gate("candidate-source")

    def test_gate_reports_accept_only_fixed_sanitized_enums(self):
        self.assertEqual(
            safe_gate_report(
                "windows_receiver",
                "windows-cng-key-lifecycle-unproven",
            ),
            {
                "schema_version": 1,
                "stage": "windows_receiver",
                "status": "blocked",
                "reason": "windows-cng-key-lifecycle-unproven",
            },
        )
        for stage, reason in (
            ("linux_capsule", "arbitrary-run-output"),
            ("unknown", "windows-cng-key-lifecycle-unproven"),
        ):
            with self.subTest(stage=stage, reason=reason):
                with self.assertRaisesRegex(HandoffRefusal, "report-class-invalid"):
                    safe_gate_report(stage, reason)

    def test_cli_refusal_is_nonzero_and_contains_no_generated_material(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["refuse", "--gate", "receiver-key"])
        self.assertEqual(code, 1)
        self.assertEqual(
            output.getvalue(),
            "handoff=refused reason=windows-cng-key-lifecycle-unproven\n",
        )


def attester_job(**changes):
    job = {
        "id": ATTESTER_JOB_ID,
        "needs": list(ATTESTER_NEEDS),
        "runs-on": ATTESTER_RUNNER,
        "checkout": False,
        "trigger": ATTESTER_TRIGGER,
    }
    job.update(changes)
    return job


class ReparseStat:
    def __init__(self, status):
        self.status = status

    def __getattr__(self, name):
        if name == "st_file_attributes":
            return 0x400
        return getattr(self.status, name)


def reparse_lstat(real_lstat):
    def wrapped(path, *args, **kwargs):
        return ReparseStat(real_lstat(path, *args, **kwargs))

    return wrapped


def run_main(arguments):
    output = io.StringIO()
    errors = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
        code = main(arguments)
    return code, output.getvalue(), errors.getvalue()


class AttesterJobBindingTests(unittest.TestCase):
    def test_attester_profile_is_bound_to_the_exact_attester_job(self):
        self.assertEqual(
            ATTESTER_PERMISSION_PROFILE,
            {"id-token": "write", "attestations": "write", "actions": "read"},
        )
        self.assertTrue(validate_attester_permissions(dict(ATTESTER_PERMISSION_PROFILE), attester_job()))
        self.assertTrue(
            validate_attester_permissions(
                dict(ATTESTER_PERMISSION_PROFILE), attester_job(needs=tuple(ATTESTER_NEEDS))
            )
        )

    def test_attester_profile_is_refused_for_any_other_job(self):
        profile = dict(ATTESTER_PERMISSION_PROFILE)
        refused = {
            "source-read job": attester_job(id="source-read", needs=[], checkout=True),
            "windows job": attester_job(id="windows-receiver", **{"runs-on": "windows-2025"}),
            "windows runner only": attester_job(**{"runs-on": "windows-2025"}),
            "latest runner": attester_job(**{"runs-on": "ubuntu-latest"}),
            "no needs": attester_job(needs=[]),
            "other needs": attester_job(needs=["windows-receiver"]),
            "extra needs": attester_job(needs=list(ATTESTER_NEEDS) + ["source-read"]),
            "string needs": attester_job(needs=ATTESTER_NEEDS[0]),
            "checkout": attester_job(checkout=True),
            "checkout as zero": attester_job(checkout=0),
            "push trigger": attester_job(trigger="push"),
            "pull request trigger": attester_job(trigger="pull_request"),
            "other id": attester_job(id="capsule-attester-2"),
            "extra field": attester_job(environment="source-read"),
            "missing field": {key: value for key, value in attester_job().items() if key != "trigger"},
            "none": None,
            "list": [],
            "empty": {},
        }
        for name, job in refused.items():
            with self.subTest(job=name):
                self.assertFalse(validate_attester_permissions(profile, job))

    def test_attester_job_with_a_different_permission_profile_is_refused(self):
        for value in (
            dict(ATTESTATION_PERMISSION_PROFILE),
            {"id-token": "write", "attestations": "write", "actions": "write"},
            {"id-token": "write", "attestations": "write", "actions": "read", "contents": "read"},
            {"id-token": "write", "attestations": "write", "actions": "read", "checks": "read"},
            None,
        ):
            with self.subTest(permission_keys=repr(value)):
                self.assertFalse(validate_attester_permissions(value, attester_job()))

    def test_default_check_never_accepts_the_attester_profile(self):
        self.assertFalse(validate_attestation_permissions(dict(ATTESTER_PERMISSION_PROFILE)))


class PublicOutputContractTests(unittest.TestCase):
    canary = "synthetic-" + "a" * 64

    def make_output(self, temporary, content=b"ok"):
        output = Path(temporary) / "public-output"
        output.write_bytes(content)
        return output

    def test_a_clean_list_or_tuple_of_paths_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = self.make_output(temporary)
            self.assertTrue(scan_public_outputs([output], self.canary))
            self.assertTrue(scan_public_outputs((str(output),), self.canary))

    def test_empty_oversized_and_non_sequence_output_sets_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = self.make_output(temporary)
            for value in (
                (),
                [],
                str(output),
                bytes(str(output), "ascii"),
                output,
                {output},
                iter([output]),
                None,
                [None],
                [b"public-output"],
                [1],
                [output] * (MAX_PUBLIC_OUTPUTS + 1),
            ):
                with self.subTest(value=type(value).__name__):
                    with self.assertRaisesRegex(HandoffRefusal, "public-output-set-invalid"):
                        scan_public_outputs(value, self.canary)
            self.assertTrue(scan_public_outputs([output] * MAX_PUBLIC_OUTPUTS, self.canary))

    def test_malformed_canaries_are_refused_before_any_file_is_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = self.make_output(temporary)
            for canary in (
                None,
                b"synthetic-" + b"a" * 64,
                "",
                "a" * 64,
                "synthetic-" + "a" * 63,
                "synthetic-" + "A" * 64,
                self.canary + "\n",
            ):
                with self.subTest(canary=type(canary).__name__ + str(len(canary or ""))):
                    with self.assertRaisesRegex(HandoffRefusal, "canary-invalid"):
                        scan_public_outputs([output], canary)

    def test_missing_output_is_unreadable(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(HandoffRefusal, "public-output-unreadable"):
                scan_public_outputs([Path(temporary) / "absent"], self.canary)

    def test_directory_output_is_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(HandoffRefusal, "public-output-invalid"):
                scan_public_outputs([Path(temporary)], self.canary)

    def test_reparse_point_output_is_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = self.make_output(temporary)
            with patch.object(os, "lstat", reparse_lstat(os.lstat)):
                with self.assertRaisesRegex(HandoffRefusal, "public-output-invalid"):
                    scan_public_outputs([output], self.canary)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes")
    def test_pipe_swapped_in_after_the_path_check_is_refused_without_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            regular = self.make_output(temporary)
            pipe = Path(temporary) / "pipe"
            os.mkfifo(pipe)
            real_lstat = os.lstat

            def lstat_as_regular(path, *args, **kwargs):
                return real_lstat(regular if Path(path) == pipe else path, *args, **kwargs)

            with patch.object(os, "lstat", lstat_as_regular):
                with self.assertRaisesRegex(HandoffRefusal, "public-output-invalid"):
                    scan_public_outputs([pipe], self.canary)

    def test_output_changed_during_the_read_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = self.make_output(temporary)
            original_fdopen = os.fdopen

            class ChangingReader:
                def __init__(self, handle):
                    self.handle = handle

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc_value, traceback):
                    self.handle.close()

                def fileno(self):
                    return self.handle.fileno()

                def read(self, size=-1):
                    data = self.handle.read(size)
                    with open(output, "ab") as append_handle:
                        append_handle.write(b"y")
                    return data

            def fdopen_with_change(descriptor, mode="r", *args, **kwargs):
                handle = original_fdopen(descriptor, mode, *args, **kwargs)
                if mode == "rb":
                    return ChangingReader(handle)
                return handle

            with patch.object(os, "fdopen", fdopen_with_change):
                with self.assertRaisesRegex(HandoffRefusal, "public-output-changed"):
                    scan_public_outputs([output], self.canary)

    def test_open_failure_after_the_path_check_is_unreadable(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = self.make_output(temporary)
            with patch.object(os, "open", side_effect=PermissionError()):
                with self.assertRaisesRegex(HandoffRefusal, "public-output-unreadable"):
                    scan_public_outputs([output], self.canary)


class GateReportContractTests(unittest.TestCase):
    stage = "windows_receiver"
    reason = "windows-cng-key-lifecycle-unproven"

    def test_report_bytes_are_ascii_json_with_a_single_line_feed(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "report.json"
            write_safe_gate_report(destination, self.stage, self.reason)
            self.assertEqual(
                destination.read_bytes(),
                b'{"reason":"windows-cng-key-lifecycle-unproven","schema_version":1,'
                b'"stage":"windows_receiver","status":"blocked"}\n',
            )

    def test_existing_report_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "report.json"
            destination.write_bytes(b"existing")
            with self.assertRaisesRegex(HandoffRefusal, "report-path-invalid"):
                write_safe_gate_report(destination, self.stage, self.reason)
            self.assertEqual(destination.read_bytes(), b"existing")

    def test_symlink_report_path_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            target.write_bytes(b"existing")
            link = Path(temporary) / "link"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links unavailable")
            with self.assertRaisesRegex(HandoffRefusal, "report-path-invalid"):
                write_safe_gate_report(link, self.stage, self.reason)
            self.assertEqual(target.read_bytes(), b"existing")

    def test_reparse_point_report_path_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "report.json"
            destination.write_bytes(b"existing")
            with patch.object(os, "lstat", reparse_lstat(os.lstat)), patch.object(
                os, "open", side_effect=AssertionError("opened")
            ):
                with self.assertRaisesRegex(HandoffRefusal, "report-path-invalid"):
                    write_safe_gate_report(destination, self.stage, self.reason)
            self.assertEqual(destination.read_bytes(), b"existing")

    def test_unwritable_report_path_fails_with_the_write_class(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "absent-directory" / "report.json"
            with self.assertRaisesRegex(HandoffRefusal, "report-write-failed"):
                write_safe_gate_report(destination, self.stage, self.reason)

    def test_failed_write_after_creation_fails_with_the_write_class(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "report.json"
            with patch.object(os, "fdopen", side_effect=OSError()):
                with self.assertRaisesRegex(HandoffRefusal, "report-write-failed"):
                    write_safe_gate_report(destination, self.stage, self.reason)


class SyntheticRepositoryContractTests(unittest.TestCase):
    def test_reparse_point_root_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            with patch.object(os, "lstat", reparse_lstat(os.lstat)):
                with self.assertRaisesRegex(HandoffRefusal, "synthetic-root-invalid"):
                    create_synthetic_git_tree(root)

    def test_git_failures_fail_with_the_repository_class(self):
        for failure in (subprocess.CalledProcessError(1, "git"), subprocess.TimeoutExpired("git", 1), OSError()):
            with self.subTest(failure=type(failure).__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    with patch("source_free._run_git", side_effect=failure):
                        with self.assertRaisesRegex(HandoffRefusal, "synthetic-repository-failed"):
                            create_synthetic_git_tree(Path(temporary) / "tree")

    def test_unexpected_repository_contents_are_invalid(self):
        def fake(valid_commit, listing):
            def run(root, arguments, environment):
                if arguments[0] == "rev-parse":
                    return valid_commit
                if arguments[0] == "ls-tree":
                    return listing
                return ""

            return run

        cases = (
            ("a" * 40, "src/other.txt"),
            ("a" * 40, "\n".join(reversed(SYNTHETIC_PATHS))),
            ("a" * 40, "\n".join(SYNTHETIC_PATHS + ("extra.txt",))),
            ("not-a-commit", "\n".join(SYNTHETIC_PATHS)),
            ("A" * 40, "\n".join(SYNTHETIC_PATHS)),
        )
        for commit, listing in cases:
            with self.subTest(commit=commit[:6], listing=listing[:8]):
                with tempfile.TemporaryDirectory() as temporary:
                    with patch("source_free._run_git", fake(commit, listing)):
                        with self.assertRaisesRegex(HandoffRefusal, "synthetic-repository-invalid"):
                            create_synthetic_git_tree(Path(temporary) / "tree")


class CommandLineContractTests(unittest.TestCase):
    refusal = "handoff=refused reason=synthetic-input-invalid\n"

    def test_every_gate_refuses_with_exit_one_and_the_fixed_line(self):
        expected = {
            "receiver-key": "windows-cng-key-lifecycle-unproven",
            "capsule": "same-run-artifact-visibility-unproven",
            "sandbox": "windows-confinement-unproven",
        }
        for gate, reason in expected.items():
            with self.subTest(gate=gate):
                code, output, errors = run_main(["refuse", "--gate", gate])
                self.assertEqual((code, output, errors), (1, "handoff=refused reason=" + reason + "\n", ""))

    def test_unknown_gate_is_refused_without_echoing_it(self):
        code, output, errors = run_main(["refuse", "--gate", "secret-gate-name"])
        self.assertEqual((code, output, errors), (1, "handoff=refused reason=gate-unknown\n", ""))

    def test_malformed_arguments_refuse_without_reflecting_input(self):
        for arguments in (
            [],
            ["unlisted-secret-command"],
            ["create"],
            ["refuse"],
            ["refuse", "--gate"],
            ["refuse", "--gate", "capsule", "--unlisted-secret-flag", "value"],
            ["-h"],
            ["--help"],
            ["create", "--help"],
        ):
            with self.subTest(arguments=len(arguments)):
                code, output, errors = run_main(arguments)
                self.assertEqual((code, output, errors), (1, self.refusal, ""))

    def test_unexpected_exceptions_print_only_the_fixed_refusal(self):
        with patch("source_free.create_synthetic_git_tree", side_effect=RuntimeError("private-detail")):
            code, output, errors = run_main(["create", "--root", "unused"])
        self.assertEqual((code, output, errors), (1, self.refusal, ""))

    def test_input_encoding_and_system_errors_print_only_the_fixed_refusal(self):
        for failure in (OSError("private-detail"), UnicodeError("private-detail")):
            with self.subTest(failure=type(failure).__name__):
                with patch("source_free.create_synthetic_git_tree", side_effect=failure):
                    code, output, errors = run_main(["create", "--root", "unused"])
                self.assertEqual((code, output, errors), (1, self.refusal, ""))

    def test_report_command_writes_the_fixed_report_and_refuses_unknown_classes(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "report.json"
            code, output, errors = run_main(
                [
                    "report",
                    "--path",
                    str(destination),
                    "--stage",
                    "windows_receiver",
                    "--reason",
                    "windows-cng-key-lifecycle-unproven",
                ]
            )
            self.assertEqual((code, output, errors), (0, "handoff=gate-report status=blocked\n", ""))
            self.assertTrue(destination.is_file())
            code, output, errors = run_main(
                [
                    "report",
                    "--path",
                    str(Path(temporary) / "other.json"),
                    "--stage",
                    "windows_receiver",
                    "--reason",
                    "private-detail",
                ]
            )
            self.assertEqual((code, output, errors), (1, "handoff=refused reason=report-class-invalid\n", ""))

    def test_create_command_prints_only_the_fixed_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "tree"
            code, output, errors = run_main(["create", "--root", str(root)])
            self.assertEqual(
                (code, output, errors),
                (0, "handoff=synthetic-tree status=generated entries=2 canary=local-only\n", ""),
            )


if __name__ == "__main__":
    unittest.main()
