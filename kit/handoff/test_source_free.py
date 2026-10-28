import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from source_free import (
    ATTESTATION_ACTION_SHA,
    ATTESTATION_PERMISSION_PROFILE,
    ATTESTER_PERMISSION_PROFILE,
    HandoffRefusal,
    MAX_PUBLIC_FILE_BYTES,
    SYNTHETIC_PATHS,
    create_synthetic_git_tree,
    main,
    safe_gate_report,
    scan_public_outputs,
    validate_attestation_permissions,
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
            original_open = Path.open
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
                    with original_open(output, "ab") as append_handle:
                        append_handle.write(b"x" * (MAX_PUBLIC_FILE_BYTES - 1))
                    return self.handle.read(2)

            def open_with_growth(path, mode="r", *args, **kwargs):
                handle = original_open(path, mode, *args, **kwargs)
                if path == output and mode == "rb":
                    return GrowingReader(handle)
                return handle

            with patch.object(Path, "open", open_with_growth):
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

    def test_attester_profile_adds_only_actions_read_and_is_never_the_default(self):
        self.assertEqual(
            ATTESTER_PERMISSION_PROFILE,
            {"id-token": "write", "attestations": "write", "actions": "read"},
        )
        self.assertTrue(
            validate_attestation_permissions(dict(ATTESTER_PERMISSION_PROFILE), attester=True)
        )
        self.assertFalse(validate_attestation_permissions(dict(ATTESTER_PERMISSION_PROFILE)))
        self.assertFalse(
            validate_attestation_permissions(dict(ATTESTATION_PERMISSION_PROFILE), attester=True)
        )
        for widened in (
            {"id-token": "write", "attestations": "write", "actions": "write"},
            {"id-token": "write", "attestations": "write", "actions": "read", "contents": "read"},
            {"id-token": "write", "attestations": "write", "actions": "read", "checks": "read"},
        ):
            with self.subTest(permission_keys=tuple(sorted(widened))):
                self.assertFalse(validate_attestation_permissions(widened, attester=True))
        self.assertFalse(validate_attestation_permissions(dict(ATTESTER_PERMISSION_PROFILE), attester=1))

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


if __name__ == "__main__":
    unittest.main()
