"""Source-only contract tests for the trusted Rust licence gate."""

import hashlib
import os
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

import cargo_lock_receipt
import rust_license_gate as gate


class _Cancellation:
    def __init__(self, cancelled=False):
        self.value = cancelled

    def cancelled(self):
        return self.value


class _LockPort:
    def __init__(self, packages=None):
        self.packages = packages

    def validate(self, lock_bytes, identity):
        if hashlib.sha256(lock_bytes).hexdigest() != identity.lock_sha256:
            raise gate.LicenseGateRefusal("lock")
        return gate._validated_lock(identity, self.packages)


class _ArchivePort:
    def __init__(self, packages=None, omit=False):
        self.packages = packages
        self.omit = omit

    def verify_complete(self, lock_bytes, identity, lock_packages):
        del lock_bytes, lock_packages
        packages = () if self.omit else self.packages
        return gate._validated_archives(identity, packages, "f" * 64)


class _ConfigPort:
    def __init__(self, config, accepted_checker_source_sha=None,
                 accepted_checker_sha256=None, accepted_checker_path=None):
        self.config = config
        self.accepted_checker_source_sha = (
            config.checker_source_sha if accepted_checker_source_sha is None
            else accepted_checker_source_sha
        )
        self.accepted_checker_sha256 = (
            config.checker_sha256 if accepted_checker_sha256 is None
            else accepted_checker_sha256
        )
        self.accepted_checker_path = (
            config.checker_path if accepted_checker_path is None else accepted_checker_path
        )

    def for_identity(self, identity):
        if (self.config.identity != identity
                or self.config.checker_source_sha != self.accepted_checker_source_sha
                or self.config.checker_sha256 != self.accepted_checker_sha256
                or self.config.checker_path != self.accepted_checker_path):
            raise gate.LicenseGateRefusal("identity")
        return self.config


class _ProcessPort:
    def __init__(self, **settings):
        allowed = {
            "checker_out", "deny_exit", "timeout", "cancelled", "substituted",
            "cancel_after_checker", "wrong_binding", "wrong_executable",
            "raise_during_run",
        }
        if set(settings) - allowed:
            raise ValueError("unknown process fixture setting")
        self.checker_out = settings.get(
            "checker_out", b"result=conditional-pass authenticated=no\n",
        )
        self.deny_exit = settings.get("deny_exit", 0)
        self.timeout = settings.get("timeout", False)
        self.cancelled = settings.get("cancelled", False)
        self.substituted = settings.get("substituted", False)
        self.cancel_after_checker = settings.get("cancel_after_checker", False)
        self.wrong_binding = settings.get("wrong_binding", False)
        self.wrong_executable = settings.get("wrong_executable", False)
        self.raise_during_run = settings.get("raise_during_run", False)
        self.requests = []
        self.cleaned = []

    def run(self, request):
        self.requests.append(request)
        if self.raise_during_run:
            raise OSError("synthetic process failure")
        if self.substituted:
            return gate.ProcessResult(
                0, False, False, b"", b"", "0" * 64,
                request.executable_sha256, object(),
            )
        is_checker = request.argv == ("--stdin-protocol",)
        if is_checker and self.cancel_after_checker:
            request.cancellation.value = True
        executed_sha256 = request.executable_sha256
        if self.wrong_executable:
            executed_sha256 = "0" * 64
        result = gate._process_result(
            request,
            (0 if is_checker else self.deny_exit, self.timeout, self.cancelled,
             self.checker_out if is_checker else b"", b""),
            executed_sha256,
        )
        if self.wrong_binding:
            return gate.ProcessResult(
                result.exit_code, result.timed_out, result.cancelled,
                result.stdout, result.stderr, "0" * 64,
                result.executable_sha256, gate._SEAL,
            )
        return result

    def cleanup(self, request, result):
        self.cleaned.append((request, result))


def _trusted_ports(lock_port, config_port, archive_port, process_port, cancellation):
    return gate._validated_ports(gate.TrustedPorts(
        lock_port, config_port, archive_port, process_port, cancellation, None,
    ))


class RustLicenseGateTests(unittest.TestCase):
    def setUp(self):
        self.lock = b"synthetic lock fixture\n"
        self.identity = gate.Identity(
            "a" * 40, "fixture-profile", "/synthetic/root",
            hashlib.sha256(self.lock).hexdigest(),
        )
        self.package = gate.Package("serde", "1.0.1", "b" * 64)
        self.packages = (self.package,)
        self.archive = gate.ArchivePackage(
            self.package, self.package.checksum, "MIT", "MIT", True,
            (("LICENSE-MIT", "d" * 64),),
        )
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.checker = root / "checker.fixture"
        self.deny = root / "cargo-deny.fixture"
        self.policy = root / "deny-policy.fixture"
        self.checker.write_bytes(b"synthetic checker identity")
        self.deny.write_bytes(b"synthetic cargo-deny identity")
        self.policy.write_bytes(b"synthetic reviewed policy identity")
        self.config = gate._validated_config(gate.GateConfig(
            self.identity, "2" * 40, str(self.checker),
            self._digest(self.checker), str(self.deny), str(root), self._digest(self.deny),
            "a" * 64, str(self.policy), self._digest(self.policy),
            True, True, gate._cargo_deny_argv_sha256(self.identity, str(self.policy)),
            True, True, "e" * 40, int(time.time()), True, True, None,
        ))

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def _digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _with_config(self, **changes):
        return gate._validated_config(replace(self.config, **changes))

    def _run(self, process=None, archives=None, lock_port=None, cancellation=None):
        runner = process or _ProcessPort()
        archive_port = archives or _ArchivePort((self.archive,))
        lock_validator = lock_port or _LockPort(self.packages)
        cancel = cancellation or _Cancellation()
        receipt = gate.require_rust_license_gate(
            self.lock, self.identity,
            _trusted_ports(lock_validator, _ConfigPort(self.config), archive_port, runner, cancel),
        )
        return receipt, runner

    def test_complete_archive_checker_and_deny_conjunction_returns_receipt(self):
        receipt, process = self._run()
        self.assertEqual(receipt.package_count, 1)
        self.assertEqual(receipt.checker_sha256, self._digest(self.checker))
        self.assertEqual(receipt.advisory_database_commit, "e" * 40)
        self.assertEqual(len(process.requests), 2)
        self.assertEqual(len(process.cleaned), 2)
        self.assertEqual(process.requests[0].timeout_seconds, gate.PROCESS_TIMEOUT_SECONDS)
        self.assertEqual(process.requests[0].output_limit, gate.MAX_OUTPUT_BYTES)
        self.assertEqual(process.requests[0].checker_source_sha, self.config.checker_source_sha)
        self.assertEqual(process.requests[1].checker_source_sha, self.config.checker_source_sha)
        self.assertNotEqual(
            process.requests[0].request_sha256,
            gate._request_binding_sha256(replace(
                process.requests[0], checker_source_sha="3" * 40,
            )),
        )
        self.assertEqual(process.requests[0].stdin.count(b"receipt\t"), 1)
        self.assertEqual(process.requests[1].argv, (
            "--manifest-path", "/synthetic/root/Cargo.toml",
            "--config", str(self.policy), "--workspace", "--all-features", "--locked",
            "--offline", "check", "advisories", "bans", "licenses", "sources",
        ))
        self.assertEqual(process.requests[1].advisory_database_commit, "e" * 40)
        self.assertEqual(
            process.requests[1].cargo_deny_qualification_sha256, "a" * 64,
        )
        self.assertEqual(process.requests[1].identity, self.identity)
        self.assertEqual(process.requests[1].archive_spdx_sha256, "f" * 64)
        self.assertIn(("CARGO_HOME", self.config.cargo_deny_home),
                      process.requests[1].environment)
        self.assertEqual(
            gate._cargo_deny_argv_sha256(self.identity, str(self.policy)),
            self.config.cargo_deny_cli_argv_sha256,
        )

    def test_production_process_adapter_runs_and_unqualified_flags_still_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "real_checker.py"
            executable.write_text(
                "import sys\nsys.stdout.buffer.write(b'real-adapter-ok\\n')\n",
                encoding="ascii",
            )
            identity = gate.Identity(
                "c" * 40, "fixture-profile", str(root / "source"), "d" * 64,
            )
            request = gate.ProcessRequest(
                str(executable), "e" * 40, ("--stdin-protocol",), str(root), b"",
                (("HOME", str(root)), ("LANG", "C"), ("LC_ALL", "C"),
                 ("SystemRoot", os.environ.get("SystemRoot", ""))),
                gate.PROCESS_TIMEOUT_SECONDS, gate.MAX_OUTPUT_BYTES, _Cancellation(),
                hashlib.sha256(executable.read_bytes()).hexdigest(), "f" * 64,
                "a" * 64, "b" * 40, identity, "9" * 64,
            )
            output = gate._run_process(
                gate._PinnedProcessPort(), request, "process",
            )
            self.assertEqual(output, b"real-adapter-ok\n")

        unqualified = self._with_config(
            r108_qualified=False,
            cargo_deny_issue_910_safe=False,
            cargo_deny_affected_patched_controls_qualified=False,
        )
        production_process = gate._PinnedProcessPort()
        with self.assertRaises(gate.LicenseGateRefusal) as raised:
            gate.require_rust_license_gate(
                self.lock, self.identity,
                _trusted_ports(
                    _LockPort(self.packages), _ConfigPort(unqualified),
                    _ArchivePort((self.archive,)), production_process, _Cancellation(),
                ),
            )
        self.assertEqual(raised.exception.reason, "cargo_deny_unqualified")

    def test_missing_archive_and_archive_coverage_mismatch_refuse_before_process(self):
        for port in (_ArchivePort((), omit=True), _ArchivePort(()),
                     _ArchivePort((self.archive, self.archive))):
            process = _ProcessPort()
            with self.subTest(port=port), self.assertRaises(gate.LicenseGateRefusal):
                self._run(process=process, archives=port)
            self.assertEqual(process.requests, [])

    def test_bad_checksum_spdx_or_notice_evidence_refuses_before_checker(self):
        variants = (
            gate.ArchivePackage(
                gate.Package("serde", "1.0.1", "e" * 64), "c" * 64,
                "MIT", "MIT", True, (("LICENSE-MIT", "d" * 64),),
            ),
            gate.ArchivePackage(
                self.package, self.package.checksum, "MIT", "Apache-2.0", True, (),
            ),
            gate.ArchivePackage(
                self.package, self.package.checksum, "MIT", "MIT", False, (),
            ),
            gate.ArchivePackage(
                self.package, self.package.checksum, "MIT", "MIT", True,
                (("../NOTICE", "d" * 64),),
            ),
        )
        for variant in variants:
            process = _ProcessPort()
            with self.subTest(variant=variant), self.assertRaises(gate.LicenseGateRefusal):
                self._run(process=process, archives=_ArchivePort((variant,)))
            self.assertEqual(process.requests, [])

    def test_lock_source_profile_or_checker_identity_substitution_refuses(self):
        process = _ProcessPort()
        with self.assertRaises(gate.LicenseGateRefusal):
            gate.require_rust_license_gate(
                self.lock, gate.Identity(
                    "a" * 40, "other", self.identity.root, self.identity.lock_sha256,
                ),
                _trusted_ports(
                    _LockPort(self.packages), _ConfigPort(self.config),
                    _ArchivePort((self.archive,)), process, _Cancellation(),
                ),
            )
        self.assertEqual(process.requests, [])
        source_mismatch = gate.Identity(
            "f" * 40, self.identity.profile, self.identity.root, self.identity.lock_sha256,
        )
        with self.assertRaises(gate.LicenseGateRefusal):
            gate.require_rust_license_gate(
                self.lock, source_mismatch,
                _trusted_ports(
                    _LockPort(self.packages), _ConfigPort(self.config),
                    _ArchivePort((self.archive,)), process, _Cancellation(),
                ),
            )
        self.assertEqual(process.requests, [])
        self.checker.write_bytes(b"substituted checker")
        with self.assertRaises(gate.LicenseGateRefusal):
            self._run(process=process)
        self.assertEqual(process.requests, [])

    def test_checker_result_substitution_timeout_cancel_and_deny_failure_refuse(self):
        cases = (
            (_ProcessPort(checker_out=b"result=pass authenticated=yes\n"), _Cancellation()),
            (_ProcessPort(timeout=True), _Cancellation()),
            (_ProcessPort(), _Cancellation(cancelled=True)),
            (_ProcessPort(cancel_after_checker=True), _Cancellation()),
            (_ProcessPort(deny_exit=1), _Cancellation()),
            (_ProcessPort(substituted=True), _Cancellation()),
        )
        for process, cancellation in cases:
            with self.subTest(process=process), self.assertRaises(gate.LicenseGateRefusal):
                self._run(process=process, cancellation=cancellation)
        timed_out = _ProcessPort(timeout=True)
        with self.assertRaises(gate.LicenseGateRefusal):
            self._run(process=timed_out)
        self.assertEqual(len(timed_out.cleaned), 1)

    def test_supervisor_binding_and_cleanup_run_after_process_failure(self):
        for process in (_ProcessPort(wrong_binding=True),
                        _ProcessPort(wrong_executable=True),
                        _ProcessPort(raise_during_run=True)):
            with self.subTest(process=process), self.assertRaises(gate.LicenseGateRefusal):
                self._run(process=process)
            self.assertEqual(len(process.cleaned), 1)

    def test_refusal_prevents_any_later_project_command(self):
        process = _ProcessPort(deny_exit=1)
        source_commands = []
        with self.assertRaises(gate.LicenseGateRefusal):
            receipt, unused_process = self._run(process=process)
            gate.require_gate_receipt(receipt, self.identity, self.packages)
            source_commands.append("cargo")
        self.assertEqual(len(process.requests), 2)
        self.assertEqual(source_commands, [])
        with self.assertRaises(gate.LicenseGateRefusal):
            gate.require_gate_receipt(None, self.identity, self.packages)

    def test_unset_binary_or_policy_bindings_refuse_closed(self):
        unset = gate._validated_config(gate.GateConfig(
            self.identity, "UNSET", str(self.checker), self._digest(self.checker),
            str(self.deny), self.config.cargo_deny_home, self._digest(self.deny), "a" * 64,
            str(self.policy), self._digest(self.policy),
            True, True, self.config.cargo_deny_cli_argv_sha256, True, True,
            "e" * 40, int(time.time()), True, True, None,
        ))
        process = _ProcessPort()
        with self.assertRaises(gate.LicenseGateRefusal):
            gate.require_rust_license_gate(
                self.lock, self.identity,
                _trusted_ports(
                    _LockPort(self.packages), _ConfigPort(unset),
                    _ArchivePort((self.archive,)), process, _Cancellation(),
                ),
            )
        self.assertEqual(process.requests, [])

    def test_unqualified_cargo_deny_candidate_and_missing_archive_context_refuse_typed(self):
        unqualified = gate._validated_config(gate.GateConfig(
            self.identity, self.config.checker_source_sha, self.config.checker_path,
            self.config.checker_sha256, self.config.cargo_deny_path,
            self.config.cargo_deny_home, self.config.cargo_deny_sha256,
            self.config.cargo_deny_qualification_sha256,
            self.config.policy_path, self.config.policy_sha256,
            True, False, self.config.cargo_deny_cli_argv_sha256, True, True, "e" * 40,
            int(time.time()), True, True, None,
        ))
        process = _ProcessPort()
        with self.assertRaises(gate.LicenseGateRefusal) as raised:
            gate.require_rust_license_gate(
                self.lock, self.identity,
                _trusted_ports(
                    _LockPort(self.packages), _ConfigPort(unqualified),
                    _ArchivePort((self.archive,)), process, _Cancellation(),
                ),
            )
        self.assertEqual(raised.exception.reason, "cargo_deny_cli_unqualified")
        self.assertEqual(process.requests, [])
        with self.assertRaises(gate.LicenseGateRefusal) as producer:
            gate.require_configured_control(self.lock, self.identity)
        self.assertEqual(producer.exception.reason, "archive_producer_unavailable")
        no_context = gate.Identity(
            self.identity.source_sha, gate.UNSET, self.identity.root, self.identity.lock_sha256,
        )
        with self.assertRaises(gate.LicenseGateRefusal) as context:
            gate.require_configured_control(self.lock, no_context)
        self.assertEqual(context.exception.reason, "archive_context_unavailable")

    def test_missing_cargo_deny_provenance_freshness_or_regression_controls_refuses(self):
        cases = (
            ({"cargo_deny_provenance_qualified": False}, "cargo_deny_unqualified"),
            ({"cargo_deny_cli_argv_sha256": "0" * 64}, "cargo_deny_cli_unqualified"),
            ({"r108_qualified": False}, "cargo_deny_unqualified"),
            ({"advisory_database_fresh": False}, "advisory_database_unavailable"),
            ({"advisory_database_generated_at_epoch": 1}, "advisory_database_unavailable"),
            ({"cargo_deny_issue_910_safe": False}, "cargo_deny_unqualified"),
            ({"cargo_deny_affected_patched_controls_qualified": False},
             "cargo_deny_unqualified"),
        )
        for changes, reason in cases:
            process = _ProcessPort()
            config = self._with_config(**changes)
            with self.subTest(changes=changes), self.assertRaises(
                    gate.LicenseGateRefusal) as raised:
                gate.require_rust_license_gate(
                    self.lock, self.identity,
                    _trusted_ports(
                        _LockPort(self.packages), _ConfigPort(config),
                        _ArchivePort((self.archive,)), process, _Cancellation(),
                    ),
                )
            self.assertEqual(raised.exception.reason, reason)
            self.assertEqual(process.requests, [])

    def test_policy_file_substitution_refuses_before_process(self):
        self.policy.write_bytes(b"substituted policy")
        process = _ProcessPort()
        with self.assertRaises(gate.LicenseGateRefusal):
            self._run(process=process)
        self.assertEqual(process.requests, [])

    def test_cargo_deny_binary_substitution_refuses_before_process(self):
        self.deny.write_bytes(b"substituted cargo-deny")
        process = _ProcessPort()
        with self.assertRaises(gate.LicenseGateRefusal):
            self._run(process=process)
        self.assertEqual(process.requests, [])

    def test_authenticated_checker_source_pair_rejects_substitution_before_process(self):
        process = _ProcessPort()
        with self.assertRaises(gate.LicenseGateRefusal):
            gate.require_rust_license_gate(
                b"changed lock", self.identity,
                _trusted_ports(
                    _LockPort(self.packages), _ConfigPort(self.config),
                    _ArchivePort((self.archive,)), process, _Cancellation(),
                ),
            )
        self.assertEqual(process.requests, [])
        changed = gate._validated_config(gate.GateConfig(
            self.identity, "3" * 40, str(self.checker), self._digest(self.checker),
            str(self.deny), self.config.cargo_deny_home, self._digest(self.deny), "a" * 64,
            str(self.policy), self._digest(self.policy),
            True, True, self.config.cargo_deny_cli_argv_sha256, True, True,
            "e" * 40, int(time.time()), True, True, None,
        ))
        with self.assertRaises(gate.LicenseGateRefusal):
            gate.require_rust_license_gate(
                self.lock, self.identity,
                _trusted_ports(
                    _LockPort(self.packages), _ConfigPort(
                        changed, self.config.checker_source_sha,
                        self.config.checker_sha256,
                    ),
                    _ArchivePort((self.archive,)), process, _Cancellation(),
                ),
            )
        self.assertEqual(process.requests, [])

        unsealed = replace(self.config, seal=None)
        with self.assertRaises(gate.LicenseGateRefusal):
            gate.require_rust_license_gate(
                self.lock, self.identity,
                _trusted_ports(
                    _LockPort(self.packages), _ConfigPort(
                        unsealed, self.config.checker_source_sha,
                        self.config.checker_sha256,
                    ),
                    _ArchivePort((self.archive,)), process, _Cancellation(),
                ),
            )
        self.assertEqual(process.requests, [])

    def test_registry_lock_with_trusted_ports_delegates_and_returns_gate_receipt(self):
        lock = _registry_lock()
        identity = _identity_for(lock)
        process = _ProcessPort()
        ports = _trusted_ports(
            _LockPort(self.packages), _ConfigPort(self._with_config(identity=identity)),
            _ArchivePort((self.archive,)), process, _Cancellation(),
        )
        receipt = gate.require_lock_admission(lock, identity, ports)
        self.assertIs(type(receipt), gate.GateReceipt)
        self.assertEqual(len(process.requests), 2)
        free = _path_lock(("host-root",))
        free_receipt = gate.require_lock_admission(free, _identity_for(free), ports)
        self.assertIs(type(free_receipt), gate.RegistryFreeReceipt)
        self.assertEqual(len(process.requests), 2)


def _path_lock(names, extra_fields="", trailer=""):
    parts = ["version = 4\n"]
    for index, name in enumerate(names):
        block = '\n[[package]]\nname = "' + name + '"\nversion = "0.1.0"\n'
        if index == 0:
            block += extra_fields
        if index == 0 and len(names) > 1:
            block += "dependencies = [\n"
            for dependency in names[1:]:
                block += ' "' + dependency + '",\n'
            block += "]\n"
        parts.append(block)
    parts.append(trailer)
    return "".join(parts).encode("ascii")


def _registry_lock():
    return _path_lock(("root-app",), trailer=(
        '\n[[package]]\nname = "serde"\nversion = "1.0.1"\nsource = "'
        + cargo_lock_receipt.REGISTRY_SOURCE + '"\nchecksum = "' + "b" * 64 + '"\n'
    ))


def _identity_for(lock_bytes, profile="fixture-profile"):
    return gate.Identity(
        "a" * 40, profile, "/synthetic/root", hashlib.sha256(lock_bytes).hexdigest(),
    )


class RegistryFreeAdmissionTests(unittest.TestCase):
    def _reason(self, lock_bytes, identity=None):
        with self.assertRaises(gate.LicenseGateRefusal) as raised:
            gate.require_lock_admission(
                lock_bytes, identity or _identity_for(lock_bytes), gate.TRUSTED_PORTS,
            )
        return raised.exception.reason

    def test_core_shaped_path_only_locks_return_sealed_registry_free_receipts(self):
        shapes = (
            ("host-root", "host-api", "host-core", "host-store"),
            ("fuzz-root", "fuzz-target"),
            ("runtime-a", "runtime-b", "runtime-c", "runtime-d", "runtime-e", "runtime-f", "runtime-x"),
        )
        for names in shapes:
            lock = _path_lock(names)
            identity = _identity_for(lock)
            with self.subTest(packages=len(names)):
                receipt = gate.require_lock_admission(lock, identity, gate.TRUSTED_PORTS)
                self.assertIs(type(receipt), gate.RegistryFreeReceipt)
                self.assertEqual(receipt.workspace_package_count, len(names))
                self.assertEqual(receipt.identity, identity)
                self.assertIs(receipt.seal, gate._SEAL)

    def test_registry_package_without_trusted_ports_refuses_producer_unavailable(self):
        self.assertIs(type(gate.TRUSTED_PORTS), gate.TrustedPorts)
        self.assertEqual(self._reason(_registry_lock()), "archive_producer_unavailable")

    def test_unsupported_lock_shapes_refuse_with_lock(self):
        cases = {
            "checksum_without_source": _path_lock(
                ("root-app",), extra_fields='checksum = "' + "c" * 64 + '"\n'),
            "git_source": _path_lock(("root-app",), extra_fields=(
                'source = "git+https://example.invalid/repo?rev=' + "d" * 40
                + "\x23" + "d" * 40 + '"\n')),
            "metadata": _path_lock(("root-app",), trailer='\n[metadata]\n'),
            "patch_unused": _path_lock(("root-app",), trailer='\n[[patch.unused]]\n'),
            "duplicate": _path_lock(("root-app", "root-app")),
            "empty": b"version = 4\n",
        }
        for label, lock in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self._reason(lock), "lock")

    def test_lock_hash_mismatch_and_bad_shape_refuse(self):
        lock = _path_lock(("root-app",))
        mismatch = gate.Identity("a" * 40, "fixture-profile", "/synthetic/root", "0" * 64)
        self.assertEqual(self._reason(lock, mismatch), "lock")
        self.assertEqual(self._reason(b"", _identity_for(b"")), "lock")
        self.assertEqual(self._reason(lock, object()), "lock")

    def test_an_unset_profile_never_yields_a_registry_free_receipt(self):
        for lock in (_path_lock(("root-app",)), _registry_lock()):
            unset = _identity_for(lock, profile=gate.UNSET)
            with self.subTest(lock=lock[:24]):
                self.assertEqual(self._reason(lock, unset), "lock")

    def test_registry_free_receipt_is_refused_by_both_receipt_validators(self):
        lock = _path_lock(("root-app",))
        identity = _identity_for(lock)
        receipt = gate.require_lock_admission(lock, identity, gate.TRUSTED_PORTS)
        package = gate.Package("serde", "1.0.1", "b" * 64)
        with self.assertRaises(gate.LicenseGateRefusal):
            gate.require_gate_receipt(receipt, identity, (package,))
        with self.assertRaises(gate.LicenseGateRefusal):
            gate.require_vendor_gate_receipt(
                receipt, identity.source_sha, identity.profile, identity.lock_sha256,
                (package,),
            )


if __name__ == "__main__":
    unittest.main()
