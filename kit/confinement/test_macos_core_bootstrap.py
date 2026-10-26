import hashlib
import io
import inspect
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import macos_core_bootstrap as subject


HOOK_PATH = subject.RULES_DIRECTORY + "/hooks/shared/check.sh"
LOCK_PATH = subject.RULES_DIRECTORY + "/shared.lock"


def _lock(file_digest="a" * 64, hook_path=HOOK_PATH, signature="verified"):
    lines = (
        "format 3",
        "source rules-control",
        "profile full",
        "tag v1.2.3",
        "tag-object " + "b" * 40,
        "commit " + "c" * 40,
        "signature " + signature,
        "signer signer@example.invalid",
        "anchor v1.0.0 " + "d" * 40 + " SHA256:" + "A" * 43,
        "signers-sha256 " + "e" * 64,
        "fragment " + "f" * 64,
        "file AGENTS.md " + file_digest,
        "file " + hook_path + " " + "1" * 64,
        "hook PreToolUse Bash " + hook_path,
        "setting includeCoAuthoredBy false",
    )
    return ((chr(35) + " generated fixture\n") + "\n".join(lines) + "\n").encode("ascii")


def _run_runtime_refusal(reason, stage, proof_confirmed):
    token = "!" * 32

    class RuntimeRefusal(Exception):
        def __init__(self, value, where):
            self.reason = value
            self.stage = where

    class Runtime:
        Refusal = RuntimeRefusal
        RevocationState = type("State", (), {})

        @staticmethod
        def revocation_confirmed(state, retained_token, repository_id, request, binding):
            return (
                state.confirmed is True
                and retained_token == token
                and repository_id == "123"
                and request["source_sha"] == "a" * 40
                and binding["run_id"] == "12"
            )

        @staticmethod
        def validated_source(request, binding, root, environ, *, revocation_state=None):
            revocation_state.confirmed = proof_confirmed
            environ.pop("SOURCE_READER_TOKEN", None)
            raise RuntimeRefusal(reason, stage)

    source_reader = type("Reader", (), {
        "run": staticmethod(lambda environ: {
            "schema_version": 1,
            "status": "refused",
            "reason": "revocation_unconfirmed",
            "repository_scope": "unverified",
            "metadata": "unverified",
            "revocation": "unconfirmed",
        }),
    })
    environment = {
        "CI_SHA": "b" * 40,
        subject.CORE_SOURCE_GATE_ENV: "a" * 40,
        subject.CORE_CONTROL_GATE_ENV: "b" * 40,
        "SOURCE_REPOSITORY_ID": "123",
        "GITHUB_RUN_ID": "12",
        "GITHUB_RUN_ATTEMPT": "1",
    }
    binding = {
        "control_sha": "b" * 40,
        "run_id": "12",
        "run_attempt": "1",
        "image_os": "macos-15",
        "image_version": "20261026.1",
    }
    with patch.object(subject, "_load_control", return_value=(object(), object(), Runtime)), \
            patch.object(subject, "_safe_context", return_value=(binding, Path("trusted-root"))), \
            patch.object(subject, "_verify_control_inventory"), \
            patch.object(subject, "_run_summary_probe", return_value={}), \
            patch.object(subject, "_load_control_sibling", return_value=source_reader) as reader_loader:
        line, status = subject.run(
            ("--phase", "bootstrap", "--source-sha", "a" * 40, "--token-stdin"),
            environment,
            token_reader=io.BytesIO(token.encode("ascii")),
        )
    return line, status, environment, reader_loader


class InputTests(unittest.TestCase):
    def test_cli_shape_is_closed(self):
        self.assertEqual(
            subject._parse_arguments(("--phase", "preflight", "--source-sha", "a" * 40)),
            ("preflight", "a" * 40, False),
        )
        self.assertEqual(
            subject._parse_arguments(("--phase", "bootstrap", "--source-sha", "a" * 40, "--token-stdin")),
            ("bootstrap", "a" * 40, True),
        )
        invalid = (
            ("--phase", [], "--source-sha", "a" * 40),
            ("--phase", "bootstrap", "--source-sha", "A" * 40),
            ("--phase", "other", "--source-sha", "a" * 40),
            ("--phase", "preflight", "--source-sha", "a" * 40, "extra"),
            ("--phase", "bootstrap", "--source-sha", "a" * 40),
            ("--phase", "preflight", "--source-sha", "a" * 40, "--token-stdin"),
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments), self.assertRaises(subject.Refusal):
                subject._parse_arguments(arguments)

    def test_token_stdin_is_bounded_and_closed(self):
        token = "!" + "a" * 1000
        self.assertEqual(subject._read_token_stdin(io.BytesIO(token.encode("ascii"))), token)
        self.assertEqual(subject._read_token_stdin(io.BytesIO(b"!" * 4096)), "!" * 4096)
        for payload in (b"", b"with space", b"x" * 4097, b"\xff"):
            with self.subTest(payload_length=len(payload)), self.assertRaises(subject.Refusal):
                subject._read_token_stdin(io.BytesIO(payload))

    def test_source_and_control_gates_match_exactly(self):
        environment = {
            "CI_SHA": "b" * 40,
            subject.CORE_SOURCE_GATE_ENV: "a" * 40,
            subject.CORE_CONTROL_GATE_ENV: "b" * 40,
        }
        self.assertEqual(subject._check_gates("a" * 40, environment), "b" * 40)
        environment[subject.CORE_CONTROL_GATE_ENV] = "c" * 40
        with self.assertRaises(subject.Refusal) as result:
            subject._check_gates("a" * 40, environment)
        self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_gate_refused", "gate"))

    def test_missing_gate_refuses_before_control_loading(self):
        environment = {"CI_SHA": "b" * 40}
        token_reader = io.BytesIO(b"!" * 32)
        with patch.object(subject, "_load_control") as loader:
            line, status = subject.run(
                ("--phase", "bootstrap", "--source-sha", "a" * 40, "--token-stdin"),
                environment,
                token_reader=token_reader,
            )
        self.assertEqual(status, 1)
        self.assertIn("reason=bootstrap_gate_refused stage=gate", line)
        self.assertIn("token-revocation=not-read", line)
        loader.assert_not_called()
        self.assertEqual(token_reader.tell(), 0)

    def test_prelease_failure_revokes_pending_token_and_preserves_failure(self):
        observed_tokens = []

        def revoke(environ):
            observed_tokens.append(environ.get("SOURCE_READER_TOKEN"))
            return {
                "schema_version": 1,
                "status": "passed",
                "reason": "ok",
                "repository_scope": "verified",
                "metadata": "verified",
                "revocation": "confirmed",
            }

        source_reader = type("Reader", (), {
            "run": staticmethod(revoke),
        })
        environment = {
            "CI_SHA": "b" * 40,
            subject.CORE_SOURCE_GATE_ENV: "a" * 40,
            subject.CORE_CONTROL_GATE_ENV: "b" * 40,
            "SOURCE_REPOSITORY_ID": "123",
        }
        with patch.object(
            subject, "_load_control", side_effect=subject.Refusal("control_import_unavailable", "import"),
        ) as loader, patch.object(subject, "_load_control_sibling", return_value=source_reader) as reader_loader:
            line, status = subject.run(
                ("--phase", "bootstrap", "--source-sha", "a" * 40, "--token-stdin"),
                environment,
                token_reader=io.BytesIO(b"!" * 32),
            )
        self.assertEqual(status, 1)
        self.assertIn("reason=control_import_unavailable stage=import", line)
        self.assertIn("token-revocation=confirmed", line)
        self.assertNotIn("SOURCE_READER_TOKEN", environment)
        self.assertEqual(observed_tokens, ["!" * 32])
        loader.assert_called_once()
        reader_loader.assert_called_once_with("macos_source_reader")

    def test_unconfirmed_fallback_refuses_cleanup(self):
        source_reader = type("Reader", (), {
            "run": staticmethod(lambda environ: {
                "schema_version": 1,
                "status": "refused",
                "reason": "revocation_unconfirmed",
                "repository_scope": "verified",
                "metadata": "verified",
                "revocation": "unconfirmed",
            }),
        })
        environment = {
            "CI_SHA": "b" * 40,
            subject.CORE_SOURCE_GATE_ENV: "a" * 40,
            subject.CORE_CONTROL_GATE_ENV: "b" * 40,
        }
        with patch.object(
            subject, "_load_control", side_effect=subject.Refusal("control_import_unavailable", "import"),
        ), patch.object(subject, "_load_control_sibling", return_value=source_reader):
            line, status = subject.run(
                ("--phase", "bootstrap", "--source-sha", "a" * 40, "--token-stdin"),
                environment,
                token_reader=io.BytesIO(b"!" * 32),
            )
        self.assertEqual(status, 1)
        self.assertIn("reason=cleanup_incomplete stage=cleanup", line)
        self.assertIn("token-revocation=unconfirmed", line)
        self.assertIn("SOURCE_READER_TOKEN", environment)

    def test_validator_token_removal_does_not_prove_revocation(self):
        token = "!" * 32
        observed_tokens = []

        class RuntimeRefusal(Exception):
            def __init__(self, reason, stage):
                self.reason = reason
                self.stage = stage

        class Runtime:
            Refusal = RuntimeRefusal
            RevocationState = type("State", (), {})

            @staticmethod
            def revocation_confirmed(state, token, repository_id, request, binding):
                return False

            @staticmethod
            def validated_source(request, binding, root, environ, *, revocation_state=None):
                environ.pop("SOURCE_READER_TOKEN", None)
                raise RuntimeRefusal("revocation_unconfirmed", "revoke")

        def revoke(environ):
            observed_tokens.append(environ.get("SOURCE_READER_TOKEN"))
            return {
                "schema_version": 1,
                "status": "refused",
                "reason": "revocation_unconfirmed",
                "repository_scope": "verified",
                "metadata": "verified",
                "revocation": "unconfirmed",
            }

        source_reader = type("Reader", (), {"run": staticmethod(revoke)})
        environment = {
            "CI_SHA": "b" * 40,
            subject.CORE_SOURCE_GATE_ENV: "a" * 40,
            subject.CORE_CONTROL_GATE_ENV: "b" * 40,
            "GITHUB_RUN_ID": "12",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        binding = {
            "control_sha": "b" * 40,
            "run_id": "12",
            "run_attempt": "1",
            "image_os": "macos-15",
            "image_version": "20261026.1",
        }
        with patch.object(subject, "_load_control", return_value=(object(), object(), Runtime)), \
                patch.object(subject, "_safe_context", return_value=(binding, Path("/trusted"))), \
                patch.object(subject, "_verify_control_inventory"), \
                patch.object(subject, "_run_summary_probe", return_value={}), \
                patch.object(subject, "_load_control_sibling", return_value=source_reader):
            line, status = subject.run(
                ("--phase", "bootstrap", "--source-sha", "a" * 40, "--token-stdin"),
                environment,
                token_reader=io.BytesIO(token.encode("ascii")),
            )
        self.assertEqual(status, 1)
        self.assertIn("reason=cleanup_incomplete stage=cleanup", line)
        self.assertIn("token-revocation=unconfirmed", line)
        self.assertEqual(observed_tokens, [token])

    def test_confirmed_revocation_proof_preserves_before_yield_signature_refusal(self):
        line, status, environment, reader_loader = _run_runtime_refusal(
            "signature_invalid", "signature", True,
        )
        self.assertEqual(status, 1)
        self.assertIn("macos-core-bootstrap=refused", line)
        self.assertIn("reason=signature_invalid stage=source_lease", line)
        self.assertIn("token-revocation=confirmed", line)
        self.assertNotIn("macos-core-bootstrap=verified", line)
        self.assertNotIn("SOURCE_READER_TOKEN", environment)
        reader_loader.assert_not_called()

    def test_cleanup_refusal_keeps_confirmed_token_receipt_without_acceptance(self):
        line, status, environment, reader_loader = _run_runtime_refusal(
            "cleanup_incomplete", "cleanup", True,
        )
        self.assertEqual(status, 1)
        self.assertIn("reason=cleanup_incomplete stage=cleanup", line)
        self.assertIn("token-revocation=confirmed", line)
        self.assertNotIn("macos-core-bootstrap=verified", line)
        self.assertNotIn("SOURCE_READER_TOKEN", environment)
        reader_loader.assert_not_called()

    def test_revoke_fallback_requires_the_exact_reader_record(self):
        good = {
            "schema_version": 1,
            "status": "passed",
            "reason": "ok",
            "repository_scope": "verified",
            "metadata": "verified",
            "revocation": "confirmed",
        }
        invalid = (
            dict(good, schema_version=True),
            dict(good, extra="value"),
            dict(good, status="refused", reason="revocation_unconfirmed", revocation="unconfirmed"),
        )
        for result in invalid:
            reader = type("Reader", (), {"run": staticmethod(lambda environ, value=result: value)})
            environment = {"SOURCE_READER_TOKEN": "!" * 32}
            with self.subTest(schema_version=result["schema_version"]):
                with patch.object(subject, "_load_control_sibling", return_value=reader):
                    self.assertFalse(subject._revoke_pending_token(environment))
                self.assertEqual(environment["SOURCE_READER_TOKEN"], "!" * 32)

    def test_revoke_fallback_import_failure_retains_pending_token(self):
        environment = {"SOURCE_READER_TOKEN": "!" * 32}
        with patch.object(subject, "_load_control_sibling", side_effect=ImportError):
            self.assertFalse(subject._revoke_pending_token(environment))
        self.assertEqual(environment["SOURCE_READER_TOKEN"], "!" * 32)

    def test_revoke_cli_returns_only_the_exact_positive_reader_record(self):
        token = "!" * 32
        seen = []
        result = {
            "schema_version": 1,
            "status": "passed",
            "reason": "ok",
            "repository_scope": "verified",
            "metadata": "verified",
            "revocation": "confirmed",
        }

        def revoke(environ):
            seen.append(environ.get("SOURCE_READER_TOKEN"))
            return result

        reader = type("Reader", (), {"run": staticmethod(revoke)})
        environment = {"SOURCE_REPOSITORY_ID": "123"}
        with patch.object(subject, "_load_control_sibling", return_value=reader):
            line, status = subject._run_revoke_cli(
                ("--phase", "revoke", "--token-stdin"), environment, io.BytesIO(token.encode("ascii")),
            )
        self.assertEqual(status, 0)
        self.assertEqual(
            line,
            '{"metadata":"verified","reason":"ok","repository_scope":"verified",'
            '"revocation":"confirmed","schema_version":1,"status":"passed"}',
        )
        self.assertEqual(seen, [token])
        self.assertNotIn("SOURCE_READER_TOKEN", environment)

    def test_revoke_cli_sanitizes_refusal_and_retains_unconfirmed_token(self):
        token = "!" * 32
        result = {
            "schema_version": 1,
            "status": "refused",
            "reason": "revocation_unconfirmed",
            "repository_scope": "verified",
            "metadata": "verified",
            "revocation": "unconfirmed",
        }
        reader = type("Reader", (), {"run": staticmethod(lambda environ: result)})
        environment = {"SOURCE_REPOSITORY_ID": "123"}
        with patch.object(subject, "_load_control_sibling", return_value=reader):
            line, status = subject._run_revoke_cli(
                ("--phase", "revoke", "--token-stdin"), environment, io.BytesIO(token.encode("ascii")),
            )
        self.assertEqual(status, 1)
        self.assertEqual(
            line,
            '{"metadata":"verified","reason":"revocation_unconfirmed","repository_scope":"verified",'
            '"revocation":"unconfirmed","schema_version":1,"status":"refused"}',
        )
        self.assertEqual(environment["SOURCE_READER_TOKEN"], token)


class LockSchemaTests(unittest.TestCase):
    def test_format_three_lock_schema_accepts_fixed_field_shapes(self):
        parsed = subject._parse_lock(_lock())
        self.assertEqual(parsed["fields"]["format"], "3")
        self.assertEqual(set(parsed["files"]), {"AGENTS.md", HOOK_PATH})

    def test_unknown_duplicate_traversal_and_unverified_fields_refuse(self):
        valid = _lock().decode("ascii")
        invalid = (
            valid + "format 3\n",
            valid + "unexpected value\n",
            valid.replace("file AGENTS.md", "file ../AGENTS.md", 1),
            _lock(signature="unverified").decode("ascii"),
            valid.replace("profile full", "profile partial"),
            valid.replace("hook PreToolUse Bash " + HOOK_PATH, "hook PreToolUse Bash missing.sh"),
        )
        for payload in invalid:
            with self.subTest(payload=payload[:24]), self.assertRaises(subject.Refusal):
                subject._parse_lock(payload.encode("ascii"))

    def test_manifest_checks_every_local_file_hash(self):
        first = b"administrative fixture\n"
        second = b"hook fixture\n"
        first_digest = hashlib.sha256(first).hexdigest()
        second_digest = hashlib.sha256(second).hexdigest()
        lock = _lock(file_digest=first_digest).decode("ascii")
        lock = lock.replace("1" * 64, second_digest)
        values = {
            LOCK_PATH: lock.encode("ascii"),
            "AGENTS.md": first,
            HOOK_PATH: second,
        }
        with patch.object(subject, "_read_source_file", side_effect=lambda root, path, maximum: values[path]):
            result = subject._verify_lock_manifest(Path("synthetic-source"))
        self.assertEqual(result["format"], "3")
        self.assertEqual(result["manifest"], "matched")
        self.assertEqual(result["signers_hash"], "well-formed")
        values["AGENTS.md"] = b"changed\n"
        with patch.object(subject, "_read_source_file", side_effect=lambda root, path, maximum: values[path]):
            with self.assertRaises(subject.Refusal) as mismatch:
                subject._verify_lock_manifest(Path("synthetic-source"))
        self.assertEqual((mismatch.exception.reason, mismatch.exception.stage), ("manifest_mismatch", "manifest"))


class SummaryEvidenceTests(unittest.TestCase):
    def test_summary_probe_uses_fixed_child_args_and_no_environment_file_leak(self):
        self.assertEqual(subject.STANDIN_GUARD_MARKER, b"summary-standin=write-denied\n")
        self.assertIn("os.open(sys.argv[1], os.O_WRONLY | os.O_NOFOLLOW)", subject.STANDIN_GUARD_SCRIPT)
        self.assertNotIn("os.environ", subject.STANDIN_GUARD_SCRIPT)
        self.assertNotIn("subprocess", subject.STANDIN_GUARD_SCRIPT)
        self.assertIn("reviewed_build._prepare_runner_summary(uid)", inspect.getsource(subject._run_summary_probe))
        self.assertIn("reviewed_build._run_real_summary_probe(", inspect.getsource(subject._run_summary_probe))

    def test_success_line_distinguishes_source_signature_from_lock_declaration(self):
        record = {
            "repository_id": "123",
            "source_sha": "a" * 40,
            "base_sha": "a" * 40,
        }
        binding = {
            "control_sha": "b" * 40,
            "run_id": "1",
            "run_attempt": "2",
            "image_os": "macos-test",
            "image_version": "1",
        }
        line = subject._success_line(record, binding, {
            "format": "3",
            "manifest": "matched",
            "signers_hash": "well-formed",
            "fragment_hash": "well-formed",
        })
        self.assertIn("source-signature=verified", line.split())
        self.assertIn("token-revocation=confirmed-before-execution", line.split())
        self.assertIn("rules-lock-signature=declared-verified", line.split())
        self.assertNotIn("signature=verified", line.split())
        self.assertIn("summary-control=append-denied", line.split())
        self.assertIn("summary-sibling=create-denied", line.split())
        self.assertIn("summary-standin=write-denied", line.split())

    def test_lease_record_is_bound_to_core_and_run_identity(self):
        binding = {
            "control_sha": "b" * 40,
            "run_id": "12",
            "run_attempt": "3",
            "image_os": "macos-15",
            "image_version": "20261026.1",
        }
        record = {
            "repository_id": "123",
            "source_sha": "a" * 40,
            "base_sha": "a" * 40,
            "base_branch": "main",
            "concern": "core-bootstrap",
            "candidate_class": "permanent-tip",
            "signature": "verified",
            "rules_lock": "present",
            "tree": "core_administrative",
            "source_execution": "not_run_at_yield",
            "app_build": "not_run",
            "cleanup": "lease_open",
            "control_sha": binding["control_sha"],
            "run_id": binding["run_id"],
            "run_attempt": binding["run_attempt"],
            "image_os": binding["image_os"],
            "image_version": binding["image_version"],
            "repository_scope": "verified",
            "metadata": "verified",
            "token_revocation": "confirmed_before_yield",
            "signer_authority": "bound_base",
            "signatures": "all_new_commits_verified",
            "ancestry": "base_ancestor",
            "revocation_policy": "current_control_fingerprints",
            "worker_access": "not_applicable",
        }
        runtime = type("Runtime", (), {"_format_success": staticmethod(lambda value, current: "verified")})
        checked = subject._validate_lease_record(runtime, record, binding, "a" * 40)
        self.assertEqual(checked["cleanup"], "complete")
        self.assertEqual(record["cleanup"], "lease_open")
        for key, value in (("source_sha", "c" * 40), ("worker_access", "uid_read_only")):
            changed = dict(record)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(subject.Refusal):
                subject._validate_lease_record(runtime, changed, binding, "a" * 40)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires no-follow file access")
    def test_summary_append_requires_the_original_empty_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            os.chmod(path, 0o600)
            info = path.lstat()
            identity = {
                "summary_path": path,
                "summary_device": info.st_dev,
                "summary_inode": info.st_ino,
                "summary_uid": info.st_uid,
                "summary_gid": info.st_gid,
                "summary_mode": stat.S_IMODE(info.st_mode),
            }
            line = "macos-core-bootstrap=verified schema=1"
            subject._append_summary(identity, line)
            self.assertEqual(path.read_bytes(), (line + "\n").encode("ascii"))
            with self.assertRaises(subject.Refusal):
                subject._append_summary(identity, line)

            replacement = Path(directory) / "replacement"
            replacement_descriptor = os.open(replacement, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(replacement_descriptor)
            os.chmod(replacement, 0o600)
            replacement.replace(path)
            with self.assertRaises(subject.Refusal):
                subject._append_summary(identity, line)


if __name__ == "__main__":
    unittest.main()
