"""Source-free regressions for pre-cut registry preparation."""
import errno
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import bundle
import bounded_registry_io
import constraint_resolver
import project
import rust_preparation_v2 as worker
import rust_preparation_smoke as smoke
import test_acceptance as acceptance
import supervisor

CONTROL_SHA = acceptance.CONTROL_SHA


class PreparationTests(unittest.TestCase):
    def test_execution_preflight_distinguishes_permission_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(os, "ST_NOEXEC", 8, create=True):
            tool = Path(temporary) / "cargo"
            tool.write_bytes(b"public-fixture")
            tool.chmod(0o644)
            with self.assertRaisesRegex(constraint_resolver.Refusal, "execute-file-mode$"):
                constraint_resolver.validate_tool_execution_access(str(tool))
            tool.chmod(0o755)
            for flags, access, expected in (
                (os.ST_NOEXEC, True, "mount-noexec"),
                (0, False, "ancestor-access"),
            ):
                with self.subTest(expected=expected), \
                        patch.object(constraint_resolver.os, "statvfs") as filesystem, \
                        patch.object(constraint_resolver.os, "access", return_value=access):
                    filesystem.return_value.f_flag = flags
                    with self.assertRaisesRegex(constraint_resolver.Refusal, "execute-" + expected + "$"):
                        constraint_resolver.validate_tool_execution_access(str(tool))
            with patch.object(constraint_resolver.os, "statvfs") as filesystem, \
                    patch.object(constraint_resolver.os, "access", side_effect=lambda path, *a, **k: path != tool):
                filesystem.return_value.f_flag = 0
                with self.assertRaisesRegex(constraint_resolver.Refusal, "execute-file-access$"):
                    constraint_resolver.validate_tool_execution_access(str(tool))

    def test_eacces_diagnostic_separates_cwd_mount_interpreter_and_policy_roles(self):
        executable = "/tools/rust/bin/cargo"
        cwd = "/work/resolver/cargo-constraints-fixed/resolver"
        cases = (
            (cwd, ("d", "s", "s", "s", "s"), "eacces-fc-cd-rs-bs-is-ls-p0"),
            (executable, ("s", "s", "n", "s", "s"), "eacces-fe-cs-rs-bn-is-ls-p0"),
            (executable, ("s", "s", "s", "a", "d"), "eacces-fe-cs-rs-bs-ia-lu-p0"),
            (executable, ("s", "s", "s", "s", "s"), "eacces-fe-cs-rs-bs-is-ls-p1"),
            ("/synthetic/unrelated", ("s", "s", "s", "s", "s"), "eacces-fo-cs-rs-bs-is-ls-p1"),
        )
        for filename, values, expected in cases:
            with self.subTest(expected=expected):
                error = OSError(errno.EACCES, "private-error-canary", filename)
                with patch.object(bounded_registry_io, "_process_start_status",
                                  side_effect=[values[0], values[1], values[4]]), \
                     patch.object(bounded_registry_io, "_exec_access_status",
                                  side_effect=[values[2], values[3]]), \
                     patch.object(bounded_registry_io, "_elf_interpreter",
                                  return_value="/lib/loader.so"):
                    detail = bounded_registry_io._permission_start_diagnostic(
                        error, [executable, "--version"], cwd, {"PATH": "/tools/rust/bin"},
                        bounded_registry_io.PhaseBudget.start(10))
                self.assertEqual(detail, expected)
                self.assertNotIn("private", detail)
                self.assertNotIn("/", detail)

    def test_process_start_errors_report_only_fixed_categories(self):
        categories = {
            errno.EACCES: "permission", errno.ENOENT: "missing-file",
            errno.EAGAIN: "process-limit", errno.ENOMEM: "memory",
            errno.EPERM: "policy", errno.ENOEXEC: "format", errno.ETXTBSY: "busy",
            errno.EIO: "os",
        }
        for number, category in categories.items():
            with self.subTest(number=number), patch.object(
                bounded_registry_io.subprocess, "Popen",
                side_effect=OSError(number, "private-path-canary"),
            ):
                expected = (r"^process-start-eacces-fn-cd-rd-bm-iu-lu-p0$"
                            if number == errno.EACCES else "^process-start-" + category + "$")
                with self.assertRaisesRegex(bounded_registry_io.Refusal, expected):
                    bounded_registry_io.run_bounded_process(
                        ["fixed-command"], bounded_registry_io.PhaseBudget.start(10),
                        cwd="/", env={},
                    )

    def request(self):
        return acceptance.OfflineProjectionV2AcceptanceTests()._request()

    def test_empty_baseline_is_explicit_and_candidate_default_still_refuses(self):
        kwargs = dict(source_commit="a" * 40, control_sha="b" * 40,
                      constraints=[], resolver_version="3")
        with self.assertRaisesRegex(constraint_resolver.Refusal, "constraint-count"):
            constraint_resolver.build_constraint_envelope(**kwargs)
        envelope = constraint_resolver.build_constraint_envelope(**kwargs, allow_empty=True)
        constraint_resolver.validate_constraints(
            envelope, expected_source_sha="a" * 40, expected_control_sha="b" * 40,
            allow_empty=True)
        with self.assertRaisesRegex(constraint_resolver.Refusal, "constraint-count"):
            constraint_resolver.validate_constraints(
                envelope, expected_source_sha="a" * 40, expected_control_sha="b" * 40)

    def test_public_constraints_reach_resolver_and_archives_share_one_budget(self):
        payload = project.build_projection(self.request())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deadline_file = root / "deadline.json"
            deadline_file.write_bytes(bundle.canonical_json({
                "schema": 1, "work_deadline": time.monotonic() + 100,
                "cleanup_reserve": 10, "job_seconds": 200}))
            result = {"packages": [], "resolver_lock": b"public resolver lock",
                      "tool_hashes": {"cargo_sha256": "a" * 64},
                      "tool_provenance_status": "binary-hash-bound-origin-unverified"}
            with patch.object(worker.constraint_resolver, "run_cargo_fixed_point", return_value=result) as resolve, \
                    patch.object(worker.bounded_registry_io, "build_bounded_registry",
                                 return_value=([], {"members": 0})) as archive:
                record = worker.prepare(payload, control_sha=CONTROL_SHA, scratch=root,
                                        output=root / "output", deadline_file=deadline_file)
            self.assertIs(resolve.call_args.kwargs["phase_budget"], archive.call_args.args[2])
            self.assertEqual(resolve.call_args.args[0], self.request()["manifest_constraints"]["candidate"])
            self.assertEqual(record["baseline_external_packages"], [])
            self.assertEqual((root / "output/cargo-config.toml").read_text(), worker.CONFIG)
            self.assertEqual({p.name for p in (root / "output").iterdir()},
                             {"projection.json", "cargo-config.toml", "registry-preparation.json"})

    def test_wrong_control_refuses_before_resolution_or_writes(self):
        with patch.object(worker.constraint_resolver, "run_cargo_fixed_point") as resolve:
            with self.assertRaisesRegex(bundle.Refusal, "projection-constraint-binding"):
                worker.prepare(project.build_projection(self.request()), control_sha="c" * 40,
                               scratch=Path("/unused"), output=Path("/unused-output"),
                               deadline_file="/unused-deadline")
            resolve.assert_not_called()

    def test_fifo_input_refuses_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "input"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(bundle.Refusal, "rust-preparation-input-type"):
                worker.read_input(fifo)

    def test_cli_refuses_owner_machine_before_reading_input(self):
        with patch.object(worker.sys, "platform", "darwin"), patch.object(worker, "read_input") as read:
            with self.assertRaisesRegex(bundle.Refusal, "rust-preparation-worker-required"):
                worker.main(["--control-sha", CONTROL_SHA])
            read.assert_not_called()

    def test_public_linux_smoke_refuses_owner_machine_before_creating_files(self):
        args = ["--cargo-path", "unused", "--rustc-path", "unused", "--control-sha", CONTROL_SHA,
                "--deadline-file", "unused", "--owner-uid", "1001", "--owner-gid", "1001"]
        with patch.object(smoke.sys, "platform", "darwin"), patch.object(smoke, "smoke") as execute:
            with self.assertRaisesRegex(bundle.Refusal, "linux-root-required"):
                smoke.main(args)
            execute.assert_not_called()

    def test_smoke_preserves_the_preparation_child_file_limit_without_privileged_raise(self):
        def child(*_args, **kwargs):
            kwargs["preexec_fn"]()
            return type("Child", (), {"wait": lambda _self, **_kwargs: 0})()
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(smoke.deadline, "remaining", return_value=10), \
                    patch.object(smoke.subprocess, "Popen", side_effect=child), \
                    patch.object(smoke.resource, "setrlimit") as limits:
                smoke.run(["unused"], Path(temporary), "fixture", "unused", {})
            self.assertIn((smoke.resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 256 * 1024 * 1024)),
                          [call.args for call in limits.call_args_list])

    def test_worker_failure_reports_codes_without_raw_exception_values(self):
        self.assertEqual(worker.failure_code(worker.constraint_resolver.Refusal("resolver-toolchain-file")),
                         "resolver-toolchain-file")
        self.assertEqual(worker.failure_code(ValueError("private-canary")), "unexpected-value")
        self.assertEqual(worker.failure_code(bundle.Refusal("private-canary\nsecond-line")), "unclassified")

    def test_tool_identity_refusals_distinguish_release_host_size_and_loader(self):
        prefix = b"cargo 1.99.1 "
        host = b"host: x86_64-unknown-linux-gnu"
        valid = prefix + b"(public-build)\nrelease: 1.99.1\n" + host + b"\n"
        constraint_resolver.validate_tool_version_output("cargo", valid, b"", 0, prefix, host)
        cases = ((valid.replace(b"1.99.1", b"1.99.0"), b"", 0, "release"),
                 (valid.replace(host, b"host: other"), b"", 0, "host"),
                 (valid + b"x" * 4096, b"", 0, "size"),
                 (b"", b"error while loading shared libraries: private-canary", 127, "shared-library"),
                 (b"", b"private-canary", 1, "execution"))
        for output, error, status, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(constraint_resolver.Refusal,
                                            "^resolver-cargo-version-" + reason + "$"):
                    constraint_resolver.validate_tool_version_output("cargo", output, error, status, prefix, host)

    def test_worker_loader_uses_only_the_control_mounted_rust_library_path(self):
        with patch.dict(os.environ, {"LD_LIBRARY_PATH": "private-canary"}):
            rust = supervisor._worker_environment("rust", Path("/unused"),
                                                  {"rust_dir": "/tools/rust/bin"})
            node = supervisor._worker_environment("node", Path("/unused"),
                                                  {"node_dir": "/tools/node/bin"})
        self.assertEqual(rust["LD_LIBRARY_PATH"], "/tools/rust/lib")
        self.assertNotIn("LD_LIBRARY_PATH", node)
        self.assertNotIn("private-canary", str(rust))

    def test_diagnostics_prefer_worker_refusal_over_generic_parent_failure(self):
        payload = (b"rust_preparation_worker_refusal=code=resolver-toolchain-file\n"
                   b"dependency_preparation_refusal=stage=prepare-cargo-vendor code=preparation-tool-failed cleanup=confirmed\n")
        self.assertEqual(worker.diagnostic_code(payload), "resolver-toolchain-file")
        for invalid in (b"rust_preparation_worker_refusal=code=bad value\n", b"x" * (1024 * 1024 + 1),
                        b"\x1b[31mrust_preparation_worker_refusal=code=bad\n"):
            self.assertIsNone(worker.diagnostic_code(invalid))
        self.assertEqual(worker.diagnostic_code(
            b"dependency_preparation_exception=stage=prepare-root-mounts class=subprocess-error cleanup=confirmed\n"),
            "exception-prepare-root-mounts-subprocess-error")


if __name__ == "__main__":
    unittest.main()
