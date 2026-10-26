import hashlib
import io
import json
import tarfile
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.request

import macos_rules_bootstrap as bootstrap


CONTROL = "a" * 40
SOURCE = "b" * 40
BASE = "c" * 40


def request_value(**changes):
    value = {
        "source_sha": SOURCE,
        "base_sha": BASE,
        "base_branch": "main",
        "concern": "rules-bootstrap",
    }
    value.update(changes)
    return value


def binding_value(**changes):
    value = {
        "control_sha": CONTROL,
        "run_id": "123456789",
        "run_attempt": "2",
        "image_os": "macos-15-arm64",
        "image_version": "20260907.0337.1",
    }
    value.update(changes)
    return value


def definitions_environment(raw=b"| D99999999 |\n| CI99999999 |\n"):
    return {
        "RULES_ID_DEFINITIONS": raw.decode("ascii"),
        "RULES_ID_DEFINITIONS_SHA256": hashlib.sha256(raw).hexdigest(),
    }


def review_environment(request=None):
    request = request or request_value()
    environment = definitions_environment()
    environment.update({
        "RULES_BOOTSTRAP_ALLOWED_SHA": request["source_sha"],
        "RULES_BOOTSTRAP_ALLOWED_CONTROL_SHA": CONTROL,
        "CI_SHA": CONTROL,
        "SOURCE_REVIEWED_SHA": request["source_sha"],
        "SOURCE_REVIEWED_BASE": request["base_sha"],
        "SOURCE_REVIEWED_BASE_BRANCH": request["base_branch"],
        "SOURCE_REVIEWED_DIFF_SHA256": "d" * 64,
        "SOURCE_CANDIDATE_REF": "refs/heads/chore/test-123",
    })
    return environment


class RequestAndGateTests(unittest.TestCase):
    def test_request_is_exact_fixed_schema(self):
        parsed = bootstrap._parse_request((
            "--source-sha", SOURCE,
            "--base-sha", BASE,
            "--base-branch", "main",
            "--concern", "rules-bootstrap",
        ))
        self.assertEqual(parsed, request_value())
        with self.assertRaises(bootstrap.Refusal):
            bootstrap._parse_request((
                "--source-sha", SOURCE, "--base-sha", BASE, "--base-branch", "main",
                "--concern", "rules-bootstrap", "--suite", "rules.hooks",
            ))
        self.assertEqual(bootstrap._validate_cli(("cleanup-dash",)), ("cleanup-dash", None))

    def test_sha_allowlist_mismatch_refuses_before_snapshot_or_source_reader(self):
        request = request_value()
        binding = binding_value()
        environment = {
            "RULES_BOOTSTRAP_ALLOWED_SHA": "d" * 40,
            "RULES_BOOTSTRAP_ALLOWED_CONTROL_SHA": CONTROL,
            "CI_SHA": CONTROL,
        }
        with patch.object(bootstrap, "_validate_plan_definitions") as plan:
            with self.assertRaisesRegex(bootstrap.Refusal, "bootstrap_gate_refused"):
                bootstrap._validate_bootstrap_gate(request, binding, environment)
        plan.assert_not_called()

    def test_control_sha_allowlist_mismatch_fails_closed(self):
        environment = {
            "RULES_BOOTSTRAP_ALLOWED_SHA": SOURCE,
            "RULES_BOOTSTRAP_ALLOWED_CONTROL_SHA": "d" * 40,
            "CI_SHA": CONTROL,
        }
        with self.assertRaisesRegex(bootstrap.Refusal, "bootstrap_gate_refused"):
            bootstrap._validate_bootstrap_gate(request_value(), binding_value(), environment)

    def test_review_binding_requires_exact_shas_branch_diff_and_safe_ref(self):
        request = request_value()
        definitions, digest, diff = bootstrap._validate_bootstrap_gate(
            request, binding_value(), review_environment(request)
        )
        self.assertEqual(digest, hashlib.sha256(definitions).hexdigest())
        self.assertEqual(diff, "d" * 64)
        for key, value in (
            ("SOURCE_REVIEWED_SHA", "f" * 40),
            ("SOURCE_REVIEWED_BASE", "f" * 40),
            ("SOURCE_REVIEWED_BASE_BRANCH", "develop"),
            ("SOURCE_REVIEWED_DIFF_SHA256", "not-a-digest"),
            ("SOURCE_CANDIDATE_REF", "refs/heads/chore/../bad"),
        ):
            with self.subTest(key=key):
                environment = review_environment(request)
                environment[key] = value
                with self.assertRaisesRegex(bootstrap.Refusal, "bootstrap_gate_refused"):
                    bootstrap._validate_bootstrap_gate(request, binding_value(), environment)

    def test_permanent_tip_requires_its_base_ref(self):
        request = request_value(source_sha=BASE)
        environment = review_environment(request)
        environment["SOURCE_CANDIDATE_REF"] = "refs/heads/main"
        bootstrap._validate_bootstrap_gate(request, binding_value(), environment)
        environment["SOURCE_CANDIDATE_REF"] = "refs/heads/chore/test-123"
        with self.assertRaisesRegex(bootstrap.Refusal, "bootstrap_gate_refused"):
            bootstrap._validate_bootstrap_gate(request, binding_value(), environment)

    def test_id_snapshot_accepts_only_hashed_id_rows(self):
        raw = b"| D99999999 |\n| CI99999999 |\n"
        definitions, digest = bootstrap._validate_plan_definitions(definitions_environment(raw))
        self.assertEqual(definitions, raw)
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

    def test_id_snapshot_rejects_prose_duplicate_rows_and_wrong_digest(self):
        cases = (
            b"| D99999999 | description |\n",
            b"| D99999999 |\n| D99999999 |\n",
            b"| D99999999 |\n\n",
        )
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(bootstrap.Refusal, "plan_snapshot_refused"):
                    bootstrap._validate_plan_definitions(definitions_environment(raw))
        environment = definitions_environment()
        environment["RULES_ID_DEFINITIONS_SHA256"] = "0" * 64
        with self.assertRaisesRegex(bootstrap.Refusal, "plan_snapshot_refused"):
            bootstrap._validate_plan_definitions(environment)

    def test_snapshot_binding_covers_control_run_attempt_and_source(self):
        request = request_value()
        binding = binding_value()
        first = bootstrap._binding_digest(request, binding, "e" * 64, "f" * 64)
        self.assertNotEqual(
            first,
            bootstrap._binding_digest(request, binding_value(run_attempt="3"), "e" * 64, "f" * 64),
        )
        self.assertNotEqual(
            first,
            bootstrap._binding_digest(request_value(source_sha="f" * 40), binding, "e" * 64, "f" * 64),
        )
        self.assertNotEqual(first, bootstrap._binding_digest(request, binding, "e" * 64, "a" * 64))

    def test_run_gate_does_not_load_private_runtime_when_bootstrap_is_closed(self):
        reviewed = object()
        capability = object()
        boundary = object()
        environment = {
            "RULES_BOOTSTRAP_ALLOWED_SHA": "d" * 40,
            "RULES_BOOTSTRAP_ALLOWED_CONTROL_SHA": CONTROL,
            "CI_SHA": CONTROL,
        }
        with patch.object(bootstrap, "_load_control", return_value=(reviewed, capability, boundary)):
            with patch.object(bootstrap, "_public_context", return_value=(binding_value(), "/control")):
                with patch.object(bootstrap, "_load_control_sibling") as loader:
                    with self.assertRaisesRegex(bootstrap.Refusal, "bootstrap_gate_refused"):
                        bootstrap._run(
                            "run", request_value(), environment,
                            {"token_revoke_handled": False},
                        )
        loader.assert_not_called()

    def test_prelease_refusal_explicitly_revokes_token_without_echoing_it(self):
        token = "opaque-test-token-value"
        output = io.StringIO()
        argv = (
            "run", "--source-sha", SOURCE, "--base-sha", BASE,
            "--base-branch", "main", "--concern", "rules-bootstrap",
        )
        with patch.object(bootstrap, "_run", side_effect=bootstrap.Refusal("bootstrap_gate_refused", "bootstrap_gate")):
            with patch.object(bootstrap, "_revoke_pending_token", return_value=True) as revoke:
                with patch("sys.stdout", output):
                    self.assertEqual(bootstrap.main(argv, {"SOURCE_READER_TOKEN": token}), 1)
        revoke.assert_called_once()
        self.assertNotIn(token, output.getvalue())


class PublicBottleTests(unittest.TestCase):
    def test_bottle_urls_are_fixed_public_reads(self):
        self.assertEqual(bootstrap.DASH_BOTTLE_SHA256, "0e104457d0d188129596ee04e4f88ab6039baf9a03e183820caf0aa333d581d0")
        self.assertTrue(bootstrap.DASH_BOTTLE_URL.startswith("https://ghcr.io/v2/homebrew/core/dash-shell/blobs/"))
        self.assertIn("repository:homebrew/core/dash-shell:pull", bootstrap.DASH_TOKEN_URL)

    def test_safe_tar_names_reject_traversal_and_non_posix_paths(self):
        self.assertEqual(bootstrap._safe_tar_name("dash-shell/0.5.13.5/bin/dash"), "dash-shell/0.5.13.5/bin/dash")
        for value in ("/absolute/path", "../escape", "dash-shell/../escape", "dash-shell\\escape", "dash-shell//dash"):
            with self.subTest(value=value):
                self.assertIsNone(bootstrap._safe_tar_name(value))

    def test_cross_host_redirect_drops_registry_authorization(self):
        request = urllib.request.Request(
            "https://ghcr.io/v2/homebrew/core/dash-shell/blobs/sha256:abc",
            headers={"Authorization": "Bearer private-public-read-token", "Accept": "application/octet-stream"},
        )
        redirected = bootstrap._PinnedRedirect().redirect_request(
            request, None, 302, "Found", {}, "https://pkg-containers.githubusercontent.com/blob?sig=public"
        )
        self.assertIsNotNone(redirected)
        self.assertNotIn("Authorization", redirected.headers)

    def test_redirect_to_unapproved_host_is_refused(self):
        request = urllib.request.Request("https://ghcr.io/blob", headers={"Authorization": "Bearer token"})
        redirected = bootstrap._PinnedRedirect().redirect_request(
            request, None, 302, "Found", {}, "https://attacker.invalid/blob"
        )
        self.assertIsNone(redirected)

    def test_invalid_tar_is_closed_refusal(self):
        with self.assertRaisesRegex(bootstrap.Refusal, "dash_bottle_invalid"):
            bootstrap._extract_dash_member(b"not a tarball")

    def test_bounded_archive_extracts_only_the_pinned_regular_binary(self):
        formula = b"verified formula fixture\n"
        binary = b"public dash fixture bytes\n"
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name in ("dash-shell", "dash-shell/0.5.13.5", "dash-shell/0.5.13.5/bin",
                         "dash-shell/0.5.13.5/.brew"):
                directory = tarfile.TarInfo(name)
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                archive.addfile(directory)
            for name, payload, mode in (
                (bootstrap.DASH_BINARY_MEMBER, binary, 0o755),
                (bootstrap.DASH_FORMULA_MEMBER, formula, 0o644),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                member.mode = mode
                archive.addfile(member, io.BytesIO(payload))
        with patch.object(bootstrap, "DASH_FORMULA_SHA256", hashlib.sha256(formula).hexdigest()):
            self.assertEqual(bootstrap._extract_dash_member(output.getvalue()), binary)

    def test_bounded_archive_rejects_link_members(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            link = tarfile.TarInfo("dash-shell/0.5.13.5/bin/dash")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../etc/passwd"
            archive.addfile(link)
        with self.assertRaisesRegex(bootstrap.Refusal, "dash_bottle_invalid"):
            bootstrap._extract_dash_member(output.getvalue())


class LeaseRecordTests(unittest.TestCase):
    def valid_record(self):
        request = request_value()
        binding = binding_value()
        return MappingProxyType({
            "repository_id": "987654321",
            "source_sha": request["source_sha"],
            "base_sha": request["base_sha"],
            "base_branch": request["base_branch"],
            "concern": request["concern"],
            "candidate_class": "signed-descendant",
            "signature": "verified",
            "rules_lock": "not-applicable",
            "tree": "rules_regular_files",
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
            "worker_access": "uid_read_only",
        })

    def test_immutable_runtime_record_is_accepted_only_when_all_gates_match(self):
        bootstrap._validate_lease_record(
            self.valid_record(), request_value(), binding_value(), 502, current_uid=501
        )

    def test_record_with_unconfirmed_revocation_or_wrong_control_is_refused(self):
        for key, value in (("token_revocation", "attempted"), ("control_sha", "d" * 40)):
            with self.subTest(key=key):
                changed = dict(self.valid_record())
                changed[key] = value
                with self.assertRaisesRegex(bootstrap.Refusal, "source_lease_unavailable"):
                    bootstrap._validate_lease_record(
                        MappingProxyType(changed), request_value(), binding_value(), 502, current_uid=501
                    )


class SummaryGuardTests(unittest.TestCase):
    def test_actual_summary_guard_stays_open_through_worker_cleanup(self):
        events = []
        guard = {"parent_probe_name": "summary.kd-probe"}
        capability = SimpleNamespace(
            _protect_runner_controls=lambda root: (501, (), ("summary-path",)),
            _verify_runner_controls_are_private=lambda *args, **kwargs: events.append("controls-verified"),
            _remove_probe_tree=lambda path: events.append("scratch-removed"),
            _probe_uid_processes_present=lambda *args, **kwargs: False,
            _presence_result=lambda value: (value, ()),
        )
        reviewed = SimpleNamespace(
            _prepare_runner_summary=lambda uid: events.append("guard-prepared") or guard,
            _run_real_summary_probe=lambda *args, **kwargs: events.append("actual-summary-probed"),
            _child_environment=lambda *args: {},
            _make_control_scratch=lambda: ("scratch", "standin"),
            _probe_argv=lambda *args: (),
            _run_probe_step=lambda *args, **kwargs: events.append("standin-probed"),
            _assert_standin_unchanged=lambda path: events.append("standin-verified"),
            _remove_summary_parent_probe=lambda guard, name: events.append("probe-removed"),
            _restore_runner_summary=lambda guard: events.append("summary-restored"),
            _close_runner_summary=lambda guard: events.append("guard-closed"),
        )
        guard_state = {"guard": None}
        bootstrap._summary_guard(
            502, "home", {"python": "python"}, reviewed, capability, "root", binding_value(),
            {"CI_STEP_SUMMARY": "summary-path", "GITHUB_STEP_SUMMARY": "summary-path", "RUNNER_HOME": "home"},
            guard_state,
        )
        self.assertIs(guard_state["guard"], guard)
        self.assertIn("actual-summary-probed", events)
        events.append("worker-cleanup")
        bootstrap._finish_summary_guard(guard, reviewed, worker_cleanup_confirmed=True)
        self.assertLess(events.index("worker-cleanup"), events.index("summary-restored"))
        self.assertLess(events.index("summary-restored"), events.index("guard-closed"))

    def test_summary_guard_closes_but_does_not_restore_without_worker_census(self):
        events = []
        reviewed = SimpleNamespace(
            _remove_summary_parent_probe=lambda guard, name: events.append("probe-removed"),
            _restore_runner_summary=lambda guard: events.append("summary-restored"),
            _close_runner_summary=lambda guard: events.append("guard-closed"),
        )
        with self.assertRaisesRegex(bootstrap.Refusal, "cleanup_incomplete"):
            bootstrap._finish_summary_guard(
                {"parent_probe_name": "summary.kd-probe"}, reviewed,
                worker_cleanup_confirmed=False,
            )
        self.assertEqual(events, ["guard-closed"])

    def test_post_command_summary_check_censuses_worker_before_restore_probe(self):
        events = []
        capability = SimpleNamespace(
            _probe_uid_processes_present=lambda *args, **kwargs: events.append("census") or False,
            _presence_result=lambda value: (value, ()),
        )
        reviewed = SimpleNamespace(
            _child_environment=lambda *args: {},
            _run_real_summary_probe=lambda *args, **kwargs: events.append("readback-restore"),
        )
        bootstrap._probe_summary_after_commands(
            {}, 502, "home", {"python": "python"}, reviewed, capability, binding_value()
        )
        self.assertEqual(events, ["census", "readback-restore"])


class OutputTests(unittest.TestCase):
    def test_pending_cleanup_uses_source_reader_when_private_runtime_is_unavailable(self):
        environment = {"SOURCE_READER_TOKEN": "opaque-test-token"}
        record = {
            "schema_version": 1,
            "status": "passed",
            "reason": "ok",
            "repository_scope": "verified",
            "metadata": "verified",
            "revocation": "confirmed",
        }
        calls = []
        reader = SimpleNamespace(run=lambda *, environ: calls.append(environ) or record)

        def load_sibling(name):
            if name == "macos_source_reader":
                return reader
            raise ImportError("runtime module unavailable")

        with patch.object(bootstrap, "_load_control_sibling", side_effect=load_sibling):
            self.assertTrue(bootstrap._revoke_pending_token(environment))
        self.assertEqual(calls, [environment])
        self.assertNotIn("SOURCE_READER_TOKEN", environment)

    def test_missing_source_reader_makes_pending_cleanup_incomplete(self):
        environment = {"SOURCE_READER_TOKEN": "opaque-test-token"}
        with patch.object(bootstrap, "_load_control_sibling", side_effect=ImportError("reader unavailable")):
            with self.assertRaisesRegex(bootstrap.Refusal, "cleanup_incomplete"):
                bootstrap._revoke_pending_token(environment)

    def test_runtime_refusal_remains_the_owner_after_token_consumption(self):
        token = "opaque-test-token"
        output = io.StringIO()
        argv = (
            "run", "--source-sha", SOURCE, "--base-sha", BASE,
            "--base-branch", "main", "--concern", "rules-bootstrap",
        )
        environment = {"SOURCE_READER_TOKEN": token}

        def failed_after_confirmed_revoke(mode, request, env, lifecycle):
            env.pop("SOURCE_READER_TOKEN", None)
            raise bootstrap.Refusal("source_lease_unavailable", "source_lease")

        with patch.object(bootstrap, "_run", side_effect=failed_after_confirmed_revoke):
            with patch.object(bootstrap, "_revoke_pending_token") as revoke:
                with patch("sys.stdout", output):
                    self.assertEqual(bootstrap.main(argv, environment), 1)
        revoke.assert_not_called()
        self.assertNotIn(token, output.getvalue())

    def test_refusal_formatter_never_includes_exception_or_secret_text(self):
        error = bootstrap.Refusal("source_lease_unavailable", "source_lease")
        error.secret = "private-token-value"
        line = bootstrap._format_refusal(error, {"CI_SHA": CONTROL, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"})
        self.assertIn("reason=source_lease_unavailable", line)
        self.assertNotIn("private-token-value", line)

    def test_success_formatter_is_closed_and_marks_memory_as_unverified(self):
        record = {
            "schema_version": 1,
            "control_sha": CONTROL,
            "run_id": "123456789",
            "run_attempt": "2",
            "source_sha": SOURCE,
            "base_sha": BASE,
            "base_branch": "main",
            "candidate_class": "signed-descendant",
            "suites": bootstrap.GATES,
            "token_revocation": "confirmed_before_execution",
            "lease_cleanup": "complete",
            "process_cleanup": "complete",
            "identity_cleanup": "complete",
            "summary_guard": "append_sibling_create_readback_restore",
            "source_tree": "uid_read_only",
            "dash_version": bootstrap.DASH_VERSION,
            "dash_bottle_sha256": bootstrap.DASH_BOTTLE_SHA256,
            "dash_binary_sha256": "e" * 64,
            "definitions_sha256": "f" * 64,
            "reviewed_diff_sha256": "a" * 64,
            "definitions_binding_sha256": "1" * 64,
            "same_job_memory": "not_verified",
        }
        line = bootstrap._format_success(record)
        self.assertIn("same-job-memory=not-verified", line)
        self.assertIn("suites=rules.hooks,rules.sync,rules.static,rules.public,plan-ids", line)
        self.assertIn("summary-guard=append-sibling-create-readback-restore", line)
        self.assertIn("reviewed-diff-sha256=" + "a" * 64, line)
        self.assertNotIn("definitions-sha256", line)
        self.assertNotIn("definitions-binding-sha256", line)
        self.assertNotIn("definitions.md", line)


if __name__ == "__main__":
    unittest.main()
