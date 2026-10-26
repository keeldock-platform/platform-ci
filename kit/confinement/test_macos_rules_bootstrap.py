import hashlib
import io
import json
import tarfile
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.parse
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


def network_record_value(**changes):
    value = {
        "schema_version": 1,
        "status": "observed",
        "mode": "host-level",
        "control_sha": CONTROL,
        "run_id": "123456789",
        "run_attempt": "2",
        "source_sha": SOURCE,
        "interface_count": 2,
        "dns_query_count": 3,
        "tcp_syn_count": 4,
        "dns_name_hashes": ["a" * 64, "b" * 64],
        "tcp_destination_hashes": ["c" * 64],
        "hashes_truncated": False,
        "capture_limited": False,
        "capture": "private",
        "cleanup": "complete",
        "worker_attribution": "not-claimed",
        "completeness": "not-claimed",
        "network_blocking": "not-claimed",
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


def extract_verified_fixture(bottle, formula_sha256=None):
    with patch.object(bootstrap, "DASH_BOTTLE_SHA256", hashlib.sha256(bottle).hexdigest()):
        if formula_sha256 is None:
            return bootstrap._extract_dash_member(bottle)
        with patch.object(bootstrap, "DASH_FORMULA_SHA256", formula_sha256):
            return bootstrap._extract_dash_member(bottle)


def bottle_fixture(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name in ("dash-shell", "dash-shell/0.5.13.5", "dash-shell/0.5.13.5/bin",
                     "dash-shell/0.5.13.5/.brew"):
            directory = tarfile.TarInfo(name)
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            archive.addfile(directory)
        for name, payload, mode in entries:
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = mode
            archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


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
        self.assertEqual(bootstrap._validate_cli(("cleanup-dash",)), ("cleanup-dash", None, False))
        self.assertEqual(
            bootstrap._validate_cli((
                "run", "--token-stdin", "--source-sha", SOURCE, "--base-sha", BASE,
                "--base-branch", "main", "--concern", "rules-bootstrap",
            )),
            ("run", request_value(), True),
        )
        with self.assertRaises(bootstrap.Refusal):
            bootstrap._validate_cli((
                "run", "--source-sha", SOURCE, "--base-sha", BASE,
                "--base-branch", "main", "--concern", "rules-bootstrap",
            ))
        with self.assertRaises(bootstrap.Refusal):
            bootstrap._validate_cli((
                "preflight", "--token-stdin", "--source-sha", SOURCE, "--base-sha", BASE,
                "--base-branch", "main", "--concern", "rules-bootstrap",
            ))

    def test_token_stdin_accepts_only_exact_bounded_header_safe_value(self):
        lifecycle = {"token_revocation": "not-read", "token_reference": None}
        with patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(b"opaque-test-token"))):
            self.assertEqual(bootstrap._read_token_stdin(lifecycle), "opaque-test-token")
        self.assertEqual(lifecycle, {
            "token_revocation": "unconfirmed", "token_reference": "opaque-test-token",
        })

    def test_token_stdin_rejects_trailing_records_and_keeps_only_safe_candidate(self):
        for raw in (b"opaque-test-token\n", b"opaque-test-token\nsecond", b"opaque test token", b"x" * 4097):
            with self.subTest(size=len(raw)):
                lifecycle = {"token_revocation": "not-read", "token_reference": None}
                with patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(raw))):
                    with self.assertRaisesRegex(bootstrap.Refusal, "invalid_input"):
                        bootstrap._read_token_stdin(lifecycle)
                self.assertEqual(lifecycle["token_revocation"], "unconfirmed")
        lifecycle = {"token_revocation": "not-read", "token_reference": None}
        with patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(b"opaque-test-token\nextra"))):
            with self.assertRaises(bootstrap.Refusal):
                bootstrap._read_token_stdin(lifecycle)
        self.assertEqual(lifecycle["token_reference"], "opaque-test-token")
        lifecycle = {"token_revocation": "not-read", "token_reference": None}
        with patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(b"x" * 4096))):
            self.assertEqual(bootstrap._read_token_stdin(lifecycle), "x" * 4096)

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
                            "run", request_value(), True, environment,
                            {"token_revocation": "not-read", "token_reference": None},
                        )
        loader.assert_not_called()

    def test_run_requires_repository_id_before_reading_token(self):
        environment = {"SOURCE_REPOSITORY_ID": ""}
        with patch.object(bootstrap, "_load_control", return_value=(object(), object(), object())):
            with patch.object(bootstrap, "_public_context", return_value=(binding_value(), "/control")):
                with patch.object(
                    bootstrap, "_validate_bootstrap_gate",
                    return_value=(b"| D99999999 |\n", "e" * 64, "f" * 64),
                ):
                    with patch.object(
                        bootstrap, "_verify_prepared_dash",
                        return_value=("dash-dir", {"binary_sha256": "a" * 64}),
                    ):
                        with patch.object(bootstrap, "_read_token_stdin") as read_token:
                            with self.assertRaisesRegex(bootstrap.Refusal, "bootstrap_gate_refused"):
                                bootstrap._run(
                                    "run", request_value(), True, environment,
                                    {"token_revocation": "not-read", "token_reference": None},
                                )
        read_token.assert_not_called()

    def test_prelease_refusal_explicitly_revokes_token_without_echoing_it(self):
        token = "opaque-test-token-value"
        output = io.StringIO()
        argv = (
            "run", "--token-stdin", "--source-sha", SOURCE, "--base-sha", BASE,
            "--base-branch", "main", "--concern", "rules-bootstrap",
        )
        def refused_after_token(mode, request, token_stdin, env, lifecycle):
            lifecycle["token_revocation"] = "unconfirmed"
            lifecycle["token_reference"] = token
            raise bootstrap.Refusal("bootstrap_gate_refused", "bootstrap_gate")

        with patch.object(bootstrap, "_run", side_effect=refused_after_token):
            with patch.object(bootstrap, "_revoke_pending_token", return_value=True) as revoke:
                with patch("sys.stdout", output):
                    self.assertEqual(bootstrap.main(argv, {}), 1)
        revoke.assert_called_once_with({}, token)
        self.assertNotIn(token, output.getvalue())


class PublicBottleTests(unittest.TestCase):
    def test_bottle_urls_are_fixed_public_reads(self):
        self.assertEqual(bootstrap.DASH_BOTTLE_SHA256, "0e104457d0d188129596ee04e4f88ab6039baf9a03e183820caf0aa333d581d0")
        self.assertEqual(bootstrap.DASH_FORMULA_SHA256, "6c709b56df106be6b2109a5a8647e24d4fadb5533394abfc55e564478fd53cb4")
        self.assertTrue(bootstrap.DASH_BOTTLE_URL.startswith("https://ghcr.io/v2/homebrew/core/dash-shell/blobs/"))
        token_url = urllib.parse.urlsplit(bootstrap.DASH_TOKEN_URL)
        self.assertEqual((token_url.scheme, token_url.netloc, token_url.path), ("https", "ghcr.io", "/token"))
        self.assertEqual(
            urllib.parse.parse_qs(token_url.query, keep_blank_values=True, strict_parsing=True),
            {"scope": ["repository:homebrew/core/dash-shell:pull"]},
        )

    def test_safe_tar_names_reject_traversal_and_non_posix_paths(self):
        self.assertEqual(bootstrap._safe_tar_name("dash-shell/0.5.13.5/bin/dash"), "dash-shell/0.5.13.5/bin/dash")
        for value in ("/absolute/path", "../escape", "dash-shell/../escape", "dash-shell\\escape", "dash-shell//dash"):
            with self.subTest(value=value):
                self.assertIsNone(bootstrap._safe_tar_name(value))

    def test_pax_timestamp_and_owner_values_are_strictly_bounded(self):
        self.assertTrue(bootstrap._safe_pax_headers({"mtime": "253402300799.999999999", "uid": "0"}))
        for headers in (
            {"mtime": "253402300800"},
            {"ctime": "-62135596801"},
            {"mtime": "1e9"},
            {"uid": "1"},
            {"path": bootstrap.DASH_BINARY_MEMBER},
        ):
            with self.subTest(headers=headers):
                self.assertFalse(bootstrap._safe_pax_headers(headers))

    def test_native_sparse_and_contiguous_tar_member_types_are_rejected(self):
        regular = tarfile.TarInfo(bootstrap.DASH_BINARY_MEMBER)
        self.assertTrue(bootstrap._safe_archive_member_type(regular))
        for member_type in (tarfile.CONTTYPE, tarfile.GNUTYPE_SPARSE):
            with self.subTest(member_type=member_type):
                member = tarfile.TarInfo(bootstrap.DASH_BINARY_MEMBER)
                member.type = member_type
                self.assertFalse(bootstrap._safe_archive_member_type(member))
        sparse = tarfile.TarInfo(bootstrap.DASH_BINARY_MEMBER)
        sparse.sparse = [(0, 1)]
        self.assertFalse(bootstrap._safe_archive_member_type(sparse))

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
        bottle = b"not a tarball"
        with self.assertRaises(bootstrap.Refusal) as caught:
            extract_verified_fixture(bottle)
        self.assertEqual(caught.exception.reason, "dash_bottle_invalid")
        self.assertEqual(caught.exception.stage, "dash_archive_structure")

    def test_bounded_archive_accepts_only_bounded_pax_metadata(self):
        formula = b"verified formula fixture\n"
        binary = b"public dash fixture bytes\n"
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
            for name in ("dash-shell", "dash-shell/0.5.13.5", "dash-shell/0.5.13.5/bin",
                         "dash-shell/0.5.13.5/.brew"):
                directory = tarfile.TarInfo(name)
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                directory.pax_headers = {"mtime": "1782491111.5", "uid": "0", "gid": "0"}
                archive.addfile(directory)
            for name, payload, mode in (
                (bootstrap.DASH_BINARY_MEMBER, binary, 0o755),
                (bootstrap.DASH_FORMULA_MEMBER, formula, 0o644),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                member.mode = mode
                member.pax_headers = {
                    "mtime": "1782491111.5",
                    "atime": "1782491112",
                    "ctime": "1782491113.5",
                    "LIBARCHIVE.creationtime": "1782491114.25",
                    "uid": "0",
                    "gid": "0",
                    "hdrcharset": "UTF-8",
                }
                archive.addfile(member, io.BytesIO(payload))
        self.assertEqual(
            extract_verified_fixture(output.getvalue(), hashlib.sha256(formula).hexdigest()), binary,
        )

    def test_archive_content_failures_have_closed_stages_and_public_digest(self):
        binary = b"public dash fixture bytes\n"
        formula = b"historical formula fixture\n"
        cases = (
            ((bootstrap.DASH_FORMULA_MEMBER, formula, 0o644), "dash_archive_binary_missing"),
            ((bootstrap.DASH_BINARY_MEMBER, binary, 0o755), "dash_archive_formula_missing"),
        )
        for entry, expected_stage in cases:
            with self.subTest(stage=expected_stage):
                bottle = bottle_fixture((entry,))
                with self.assertRaises(bootstrap.Refusal) as caught:
                    extract_verified_fixture(bottle)
                self.assertEqual(caught.exception.reason, "dash_bottle_invalid")
                self.assertEqual(caught.exception.stage, expected_stage)
                line = bootstrap._format_refusal(
                    caught.exception,
                    {"CI_SHA": CONTROL, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"},
                )
                self.assertNotIn("embedded-formula-sha256=", line)

        bottle = bottle_fixture((
            (bootstrap.DASH_BINARY_MEMBER, binary, 0o755),
            (bootstrap.DASH_FORMULA_MEMBER, formula, 0o644),
        ))
        with self.assertRaises(bootstrap.Refusal) as caught:
            extract_verified_fixture(bottle)
        self.assertEqual(caught.exception.reason, "dash_bottle_invalid")
        self.assertEqual(caught.exception.stage, "dash_archive_formula_digest_mismatch")
        self.assertEqual(caught.exception.embedded_formula_sha256, hashlib.sha256(formula).hexdigest())
        self.assertEqual(
            caught.exception.verified_bottle_sha256,
            hashlib.sha256(bottle).hexdigest(),
        )
        with patch.object(bootstrap, "DASH_BOTTLE_SHA256", hashlib.sha256(bottle).hexdigest()):
            line = bootstrap._format_refusal(
                caught.exception,
                {"CI_SHA": CONTROL, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"},
            )
        self.assertTrue(line.endswith("embedded-formula-sha256=" + hashlib.sha256(formula).hexdigest()))
        self.assertNotIn("historical formula fixture", line)
        self.assertNotIn(bootstrap.DASH_FORMULA_MEMBER, line)

    def test_unpinned_bottle_cannot_emit_formula_digest(self):
        formula = b"historical formula fixture\n"
        bottle = bottle_fixture((
            (bootstrap.DASH_BINARY_MEMBER, b"public dash fixture bytes\n", 0o755),
            (bootstrap.DASH_FORMULA_MEMBER, formula, 0o644),
        ))
        with self.assertRaises(bootstrap.Refusal) as caught:
            bootstrap._extract_dash_member(bottle)
        self.assertEqual(caught.exception.stage, "dash_download")
        line = bootstrap._format_refusal(
            caught.exception,
            {"CI_SHA": CONTROL, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"},
        )
        self.assertNotIn("embedded-formula-sha256=", line)

    def test_pax_path_link_size_and_sparse_overrides_are_closed_refusals(self):
        for key, value in (
            ("path", bootstrap.DASH_BINARY_MEMBER),
            ("linkpath", "unused"),
            ("size", "1"),
            ("GNU.sparse.map", "0,1"),
        ):
            with self.subTest(key=key):
                output = io.BytesIO()
                with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
                    member = tarfile.TarInfo(bootstrap.DASH_BINARY_MEMBER)
                    member.size = 1
                    member.mode = 0o755
                    member.pax_headers = {key: value}
                    archive.addfile(member, io.BytesIO(b"x"))
                with self.assertRaises(bootstrap.Refusal) as caught:
                    extract_verified_fixture(output.getvalue())
                self.assertEqual(caught.exception.reason, "dash_bottle_invalid")
                self.assertEqual(caught.exception.stage, "dash_archive_pax_metadata")

    def test_bounded_archive_rejects_link_members(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            link = tarfile.TarInfo("dash-shell/0.5.13.5/bin/dash")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../etc/passwd"
            archive.addfile(link)
        with self.assertRaises(bootstrap.Refusal) as caught:
            extract_verified_fixture(output.getvalue())
        self.assertEqual(caught.exception.reason, "dash_bottle_invalid")
        self.assertEqual(caught.exception.stage, "dash_archive_member")

    def test_bounded_archive_rejects_contiguous_members(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.GNU_FORMAT) as archive:
            member = tarfile.TarInfo(bootstrap.DASH_BINARY_MEMBER)
            member.type = tarfile.CONTTYPE
            member.mode = 0o755
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaises(bootstrap.Refusal) as caught:
            extract_verified_fixture(output.getvalue())
        self.assertEqual(caught.exception.reason, "dash_bottle_invalid")
        self.assertEqual(caught.exception.stage, "dash_archive_member")


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


class RuntimeLeaseRefusalTests(unittest.TestCase):
    class RuntimeRefusal(Exception):
        def __init__(self, reason, stage):
            self.reason = reason
            self.stage = stage

    def mapped(self, reason, stage):
        runtime = SimpleNamespace(Refusal=self.RuntimeRefusal)
        error = self.RuntimeRefusal(reason, stage)
        return bootstrap._runtime_lease_refusal(runtime, error)

    def test_before_yield_known_reason_is_preserved_as_closed_source_lease_reason(self):
        error = self.mapped("bootstrap_not_approved", "configuration")
        self.assertEqual((error.reason, error.stage), ("bootstrap_not_approved", "source_lease"))

    def test_inside_lease_known_reason_is_preserved_as_closed_source_lease_reason(self):
        error = self.mapped("signature_invalid", "signature")
        self.assertEqual((error.reason, error.stage), ("signature_invalid", "source_lease"))

    def test_before_yield_unknown_reason_is_not_echoed(self):
        reason = "unlisted-reason\nunsafe-detail"
        error = self.mapped(reason, "configuration")
        self.assertEqual((error.reason, error.stage), ("source_lease_unavailable", "source_lease"))
        self.assertNotIn(reason, str(error))

    def test_inside_lease_unknown_reason_is_not_echoed(self):
        reason = "unlisted-reason\nunsafe-detail"
        error = self.mapped(reason, "signature")
        self.assertEqual((error.reason, error.stage), ("source_lease_unavailable", "source_lease"))
        self.assertNotIn(reason, str(error))

    def test_cleanup_refusal_keeps_cleanup_classification(self):
        error = self.mapped("cleanup_incomplete", "cleanup")
        self.assertEqual((error.reason, error.stage), ("cleanup_incomplete", "cleanup_lease"))


class CleanupFailureTests(unittest.TestCase):
    def test_each_cleanup_step_uses_its_fixed_stage(self):
        stages = tuple(sorted(bootstrap.CLEANUP_STAGES))
        for failing_stage in stages:
            with self.subTest(stage=failing_stage):
                calls = []
                steps = []
                for stage in stages:
                    def action(current=stage):
                        calls.append(current)
                        if current == failing_stage:
                            raise RuntimeError("private-cleanup-detail")
                    steps.append((stage, action))
                failure = bootstrap._attempt_cleanup_steps(None, tuple(steps))
                self.assertEqual(calls, list(stages))
                self.assertEqual((failure.reason, failure.stage),
                                 ("cleanup_incomplete", failing_stage))

    def test_cleanup_attempts_all_steps_and_preserves_first_cleanup_leaf(self):
        calls = []
        secret = "private-cleanup-detail"

        def action(name, fails=False):
            def invoke():
                calls.append(name)
                if fails:
                    raise RuntimeError(secret)
            return invoke

        failure = bootstrap._attempt_cleanup_steps(
            bootstrap.Refusal("suite_failed", "rules.hooks"),
            (
                ("cleanup_storage", action("storage", True)),
                ("cleanup_worker", action("worker", True)),
                ("cleanup_summary", action("summary")),
                ("cleanup_dash", action("dash", True)),
            ),
        )
        self.assertEqual(calls, ["storage", "worker", "summary", "dash"])
        self.assertEqual((failure.reason, failure.stage), ("cleanup_incomplete", "cleanup_storage"))
        line = bootstrap._format_refusal(failure, {
            "CI_SHA": CONTROL, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
        })
        self.assertIn("stage=cleanup_storage", line)
        self.assertNotIn(secret, line)

    def test_existing_cleanup_leaf_wins_while_later_cleanup_is_attempted(self):
        calls = []

        def later():
            calls.append("later")
            raise RuntimeError("private-later-detail")

        failure = bootstrap._attempt_cleanup_steps(
            bootstrap.Refusal("cleanup_incomplete", "cleanup_lease"),
            (("cleanup_worker", later),),
        )
        self.assertEqual(calls, ["later"])
        self.assertEqual((failure.reason, failure.stage), ("cleanup_incomplete", "cleanup_lease"))

    def test_first_body_cleanup_survives_lease_exit_and_later_cleanup(self):
        calls = []
        cleanup_state = {"first": None}
        body_failure = bootstrap._cleanup_failure("cleanup_summary", cleanup_state)
        lease_exit_failure = bootstrap._cleanup_failure("cleanup_lease", cleanup_state)

        def fail(name):
            def invoke():
                calls.append(name)
                raise RuntimeError("private-cleanup-detail")
            return invoke

        failure = bootstrap._attempt_cleanup_steps(
            lease_exit_failure,
            (("cleanup_worker", fail("worker")), ("cleanup_dash", fail("dash"))),
            cleanup_state,
        )
        self.assertEqual((body_failure.reason, body_failure.stage),
                         ("cleanup_incomplete", "cleanup_summary"))
        self.assertEqual(calls, ["worker", "dash"])
        self.assertEqual((failure.reason, failure.stage), ("cleanup_incomplete", "cleanup_summary"))

    def test_gate_failure_remains_when_every_cleanup_step_succeeds(self):
        calls = []
        original = bootstrap.Refusal("suite_failed", "rules.sync")
        failure = bootstrap._attempt_cleanup_steps(
            original,
            (("cleanup_worker", lambda: calls.append("worker")),
             ("cleanup_dash", lambda: calls.append("dash"))),
        )
        self.assertIs(failure, original)
        self.assertEqual(calls, ["worker", "dash"])

    def test_unknown_cleanup_step_uses_closed_unknown_label(self):
        failure = bootstrap._attempt_cleanup_steps(
            None, (("untrusted-stage", lambda: (_ for _ in ()).throw(RuntimeError("hidden"))),),
        )
        self.assertEqual((failure.reason, failure.stage), ("cleanup_incomplete", "cleanup_unknown"))


class WorkerPrivilegeTests(unittest.TestCase):
    def test_worker_privilege_uses_the_reviewed_probe_for_the_exact_worker(self):
        events = []
        environment = {"PATH": "/usr/bin:/bin", "HOME": "home", "TMPDIR": "storage"}
        argv = ("python", "-I", "-S", "-B", "-c", "fixed-probe")
        reviewed = SimpleNamespace(
            PRIVILEGE_SCRIPT="fixed-probe",
            PRIVILEGE_MARKER=b"KD-RB:privilege=sudo-denied\n",
            _child_environment=lambda home, storage, toolchain: environment,
            _probe_argv=lambda python, script: argv,
            _run_probe_step=lambda command, uid, **kwargs: events.append((command, uid, kwargs)),
        )
        result = bootstrap._probe_worker_privilege(
            502, "home", "storage", {"python": "python"}, reviewed,
        )
        self.assertEqual(result, "sudo-denied")
        self.assertEqual(events, [(argv, 502, {
            "env": environment,
            "python_executable": "python",
            "stage": "privilege",
            "expected_stdout": b"KD-RB:privilege=sudo-denied\n",
        })])

    def test_worker_privilege_refuses_and_preserves_cleanup_failure(self):
        def fail_probe(*args, **kwargs):
            raise bootstrap.Refusal("runner_controls_unavailable", "runner_controls")

        def fail_cleanup(*args, **kwargs):
            raise bootstrap.Refusal("cleanup_incomplete", "cleanup_unknown")

        reviewed = SimpleNamespace(
            PRIVILEGE_SCRIPT="fixed-probe",
            PRIVILEGE_MARKER=b"KD-RB:privilege=sudo-denied\n",
            _child_environment=lambda *args: {},
            _probe_argv=lambda *args: (),
            _run_probe_step=fail_probe,
        )
        with self.assertRaisesRegex(bootstrap.Refusal, "probe_identity_unavailable"):
            bootstrap._probe_worker_privilege(502, "home", "storage", {"python": "python"}, reviewed)
        reviewed._run_probe_step = fail_cleanup
        with self.assertRaisesRegex(bootstrap.Refusal, "cleanup_incomplete"):
            bootstrap._probe_worker_privilege(502, "home", "storage", {"python": "python"}, reviewed)


class NetworkObservationTests(unittest.TestCase):
    class ObserverRefusal(Exception):
        def __init__(self, reason, stage):
            self.reason = reason
            self.stage = stage

    class ObservationSession:
        pass

    def test_loader_allowlist_adds_only_the_fixed_network_observer(self):
        self.assertEqual(bootstrap.CONTROL_SIBLINGS, frozenset((
            "macos_reviewed_build", "macos_capability", "macos_boundary_guard",
            "macos_private_validation", "macos_source_reader", "macos_network_observer",
        )))
        with self.assertRaises(ImportError):
            bootstrap._load_control_sibling("unreviewed_module")

    def test_observer_uses_the_validated_source_and_run_binding(self):
        binding = binding_value()
        session = self.ObservationSession()
        calls = []
        observer = SimpleNamespace(
            ObserverRefusal=self.ObserverRefusal,
            ObservationSession=self.ObservationSession,
            start_observation=lambda *args: calls.append(args) or session,
        )
        with patch.object(bootstrap, "_load_control_sibling", return_value=observer):
            self.assertEqual(bootstrap._start_network_observation(binding, SOURCE), (observer, session))
        self.assertEqual(calls, [(CONTROL, "123456789", "2", SOURCE)])

    def test_observer_module_contract_failure_has_fixed_import_leaf(self):
        observer = SimpleNamespace(start_observation=lambda *args: object())
        with patch.object(bootstrap, "_load_control_sibling", return_value=observer):
            with self.assertRaises(bootstrap.Refusal) as caught:
                bootstrap._start_network_observation(binding_value(), SOURCE)
        self.assertEqual((caught.exception.reason, caught.exception.stage),
                         ("runner_controls_unavailable", "observer_import"))

    def test_observer_import_failure_has_a_fixed_leaf_without_exception_text(self):
        with patch.object(bootstrap, "_load_control_sibling", side_effect=ImportError("raw import detail")):
            with self.assertRaises(bootstrap.Refusal) as caught:
                bootstrap._start_network_observation(binding_value(), SOURCE)
        self.assertEqual((caught.exception.reason, caught.exception.stage),
                         ("runner_controls_unavailable", "observer_import"))
        self.assertNotIn("raw import detail", str(caught.exception))

    def test_trusted_interface_failure_preserves_only_approved_reason_and_leaf(self):
        def fail_start(*args):
            raise self.ObserverRefusal("interface_unavailable", "interface_hardware")

        observer = SimpleNamespace(
            ObserverRefusal=self.ObserverRefusal,
            ObservationSession=self.ObservationSession,
            start_observation=fail_start,
        )
        with patch.object(bootstrap, "_load_control_sibling", return_value=observer):
            with self.assertRaises(bootstrap.Refusal) as caught:
                bootstrap._start_network_observation(binding_value(), SOURCE)
        self.assertEqual((caught.exception.reason, caught.exception.stage),
                         ("interface_unavailable", "observer_interface_hardware"))

    def test_unknown_or_untrusted_observer_exception_stays_generic(self):
        class UntrustedFailure(Exception):
            reason = "interface_unavailable"
            stage = "interface_hardware"

        def fail_start(*args):
            raise UntrustedFailure("untrusted detail")

        observer = SimpleNamespace(
            ObserverRefusal=self.ObserverRefusal,
            ObservationSession=self.ObservationSession,
            start_observation=fail_start,
        )
        with patch.object(bootstrap, "_load_control_sibling", return_value=observer):
            with self.assertRaises(bootstrap.Refusal) as caught:
                bootstrap._start_network_observation(binding_value(), SOURCE)
        self.assertEqual((caught.exception.reason, caught.exception.stage),
                         ("runner_controls_unavailable", "runner_controls"))
        self.assertNotIn("untrusted detail", str(caught.exception))

        def unknown_start(*args):
            raise self.ObserverRefusal("unsafe detail", "interface_hardware")

        observer.start_observation = unknown_start
        with patch.object(bootstrap, "_load_control_sibling", return_value=observer):
            with self.assertRaises(bootstrap.Refusal) as caught:
                bootstrap._start_network_observation(binding_value(), SOURCE)
        self.assertEqual((caught.exception.reason, caught.exception.stage),
                         ("runner_controls_unavailable", "runner_controls"))
        self.assertNotIn("unsafe detail", str(caught.exception))

    def test_real_observer_record_schema_matches_wrapper_without_host_capture(self):
        observer = bootstrap._load_control_sibling("macos_network_observer")
        binding = {
            "control_sha": CONTROL,
            "run_id": "123456789",
            "run_attempt": "2",
            "source_sha": SOURCE,
        }
        empty_pcap = bytes.fromhex(
            "d4c3b2a10200040000000000000000000002000001000000"
        )
        session = observer.ObservationSession(
            binding,
            "synthetic-capture-dir",
            ({"path": "synthetic-capture", "addresses": frozenset()},),
            frozenset(),
            frozenset(),
            observer.time.monotonic(),
            b"synthetic-per-run-key",
        )
        with patch.object(observer, "_stop_capture"):
            with patch.object(observer, "_read_capture_file", return_value=empty_pcap):
                with patch.object(observer, "_remove_private_directory"):
                    record = session.finish()
        self.assertIs(type(record["dns_name_hashes"]), list)
        self.assertIs(type(record["tcp_destination_hashes"]), list)
        self.assertEqual(
            bootstrap._validate_network_record(record, binding_value(), SOURCE), record
        )

    def test_observation_record_and_public_marker_keep_only_bound_counts_and_hashes(self):
        record = network_record_value()
        result = bootstrap._validate_network_record(record, binding_value(), SOURCE)
        line = bootstrap._format_network_observed(result)
        self.assertIn("mode=host-level", line)
        self.assertIn("control-sha=" + CONTROL, line)
        self.assertIn("source-sha=" + SOURCE, line)
        self.assertIn("dns-name-hashes=" + ",".join(record["dns_name_hashes"]), line)
        self.assertIn("tcp-destination-hashes=" + ",".join(record["tcp_destination_hashes"]), line)
        self.assertIn("worker-attribution=not-claimed", line)
        self.assertIn("completeness=not-claimed", line)
        self.assertIn("network-blocking=not-claimed", line)
        self.assertNotIn("example", line)

    def test_observer_record_refuses_unbound_or_malformed_values(self):
        cases = (
            {"source_sha": "d" * 40},
            {"interface_count": True},
            {"dns_name_hashes": ["b" * 64, "a" * 64]},
            {"tcp_destination_hashes": ["not-a-hash"]},
            {"network_blocking": "blocked"},
            {"unexpected": "value"},
        )
        for changes in cases:
            with self.subTest(keys=tuple(changes)):
                with self.assertRaises(bootstrap.Refusal) as caught:
                    bootstrap._validate_network_record(
                        network_record_value(**changes), binding_value(), SOURCE
                    )
                self.assertEqual((caught.exception.reason, caught.exception.stage),
                                 ("runner_controls_unavailable", "observer_record"))

    def test_observer_finish_preserves_approved_finish_leaf(self):
        observer = SimpleNamespace(ObserverRefusal=self.ObserverRefusal)

        class Session:
            def finish(self):
                raise NetworkObservationTests.ObserverRefusal("observer_unavailable", "finish")

        with self.assertRaises(bootstrap.Refusal) as caught:
            bootstrap._finish_network_observation(observer, Session(), binding_value(), SOURCE)
        self.assertEqual((caught.exception.reason, caught.exception.stage),
                         ("observer_unavailable", "observer_finish"))

    def test_observer_cleanup_refusal_stays_a_cleanup_failure(self):
        observer = SimpleNamespace(ObserverRefusal=self.ObserverRefusal)

        class Session:
            def finish(self):
                raise NetworkObservationTests.ObserverRefusal("cleanup_incomplete", "cleanup")

        with self.assertRaisesRegex(bootstrap.Refusal, "cleanup_incomplete") as caught:
            bootstrap._finish_network_observation(observer, Session(), binding_value(), SOURCE)
        self.assertEqual(caught.exception.stage, "cleanup_unknown")

    def test_missing_observer_marker_has_a_fixed_leaf(self):
        for lifecycle in ({}, {"network_observation_marker": "untrusted marker"}):
            with self.subTest(lifecycle=tuple(lifecycle)):
                with self.assertRaises(bootstrap.Refusal) as caught:
                    bootstrap._required_network_marker(lifecycle)
                self.assertEqual((caught.exception.reason, caught.exception.stage),
                                 ("runner_controls_unavailable", "observer_missing"))


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
        with self.assertRaisesRegex(bootstrap.Refusal, "cleanup_incomplete") as caught:
            bootstrap._finish_summary_guard(
                {"parent_probe_name": "summary.kd-probe"}, reviewed,
                worker_cleanup_confirmed=False,
            )
        self.assertEqual(caught.exception.stage, "cleanup_summary")
        self.assertEqual(events, ["guard-closed"])

    def test_summary_restore_failure_is_first_and_close_is_still_attempted(self):
        events = []

        def fail_restore(guard):
            events.append("restore")
            raise RuntimeError("private-restore-detail")

        def fail_close(guard):
            events.append("close")
            raise RuntimeError("private-close-detail")

        reviewed = SimpleNamespace(
            _remove_summary_parent_probe=lambda guard, name: events.append("probe-removed"),
            _restore_runner_summary=fail_restore,
            _close_runner_summary=fail_close,
        )
        cleanup_state = {"first": None}
        with self.assertRaises(bootstrap.Refusal) as caught:
            bootstrap._finish_summary_guard(
                {"parent_probe_name": "summary.kd-probe"}, reviewed,
                worker_cleanup_confirmed=True, cleanup_state=cleanup_state,
            )
        self.assertEqual(events, ["probe-removed", "restore", "close"])
        self.assertEqual((caught.exception.reason, caught.exception.stage),
                         ("cleanup_incomplete", "cleanup_summary_restore"))
        self.assertEqual(cleanup_state["first"], "cleanup_summary_restore")
        self.assertNotIn("private-restore-detail", str(caught.exception))
        self.assertNotIn("private-close-detail", str(caught.exception))

    def test_summary_close_failure_has_its_own_stage(self):
        events = []

        def fail_close(guard):
            events.append("close")
            raise RuntimeError("private-close-detail")

        reviewed = SimpleNamespace(
            _remove_summary_parent_probe=lambda guard, name: events.append("probe-removed"),
            _restore_runner_summary=lambda guard: events.append("restore"),
            _close_runner_summary=fail_close,
        )
        with self.assertRaises(bootstrap.Refusal) as caught:
            bootstrap._finish_summary_guard(
                {"parent_probe_name": "summary.kd-probe"}, reviewed,
                worker_cleanup_confirmed=True,
            )
        self.assertEqual(events, ["probe-removed", "restore", "close"])
        self.assertEqual((caught.exception.reason, caught.exception.stage),
                         ("cleanup_incomplete", "cleanup_summary_close"))

    def test_post_command_summary_check_censuses_worker_before_restore_probe(self):
        events = []
        capability = SimpleNamespace(
            _probe_uid_processes_present=lambda *args, **kwargs: events.append("census") or (False, ()),
            _presence_result=lambda value: events.append("validate") or value,
        )
        reviewed = SimpleNamespace(
            _child_environment=lambda *args: {},
            _run_real_summary_probe=lambda *args, **kwargs: events.append("readback-restore"),
        )
        bootstrap._probe_summary_after_commands(
            {}, 502, "home", {"python": "python"}, reviewed, capability, binding_value()
        )
        self.assertEqual(events, ["census", "validate", "readback-restore"])

    def test_census_single_allowlisted_class_gets_a_fixed_present_stage(self):
        events = []
        capability = SimpleNamespace(
            _probe_uid_processes_present=lambda *args, **kwargs: (True, ("python",)),
            _presence_result=lambda value: events.append("validated") or value,
        )
        reviewed = SimpleNamespace(
            _child_environment=lambda *args: {},
            _run_real_summary_probe=lambda *args, **kwargs: events.append("probe"),
        )
        with self.assertRaises(bootstrap.Refusal) as caught:
            bootstrap._probe_summary_after_commands(
                {}, 502, "home", {"python": "python"}, reviewed, capability, binding_value()
            )
        self.assertEqual((caught.exception.reason, caught.exception.stage),
                         ("cleanup_incomplete", "cleanup_summary_present_python"))
        self.assertEqual(events, ["validated"])

    def test_present_leaf_survives_later_summary_restore_and_close_failures(self):
        events = []
        cleanup_state = {"first": None}

        def fail_restore(guard):
            events.append("restore")
            raise RuntimeError("private-restore-detail")

        def fail_close(guard):
            events.append("close")
            raise RuntimeError("private-close-detail")

        capability = SimpleNamespace(
            _probe_uid_processes_present=lambda *args, **kwargs: (True, ("ps",)),
            _presence_result=lambda value: value,
        )
        reviewed = SimpleNamespace(
            _child_environment=lambda *args: {},
            _run_real_summary_probe=lambda *args, **kwargs: events.append("probe"),
            _remove_summary_parent_probe=lambda guard, name: events.append("probe-removed"),
            _restore_runner_summary=fail_restore,
            _close_runner_summary=fail_close,
        )
        with self.assertRaises(bootstrap.Refusal) as caught:
            bootstrap._probe_summary_after_commands(
                {}, 502, "home", {"python": "python"}, reviewed, capability, binding_value(),
                cleanup_state,
            )
        self.assertEqual(caught.exception.stage, "cleanup_summary_present_ps")
        with self.assertRaises(bootstrap.Refusal) as finished:
            bootstrap._finish_summary_guard(
                {"parent_probe_name": "summary.kd-probe"}, reviewed,
                worker_cleanup_confirmed=True, cleanup_state=cleanup_state,
            )
        self.assertEqual((finished.exception.reason, finished.exception.stage),
                         ("cleanup_incomplete", "cleanup_summary_present_ps"))
        self.assertEqual(events, ["probe-removed", "restore", "close"])

    def test_multiple_or_unapproved_survivor_classes_use_generic_present_stage(self):
        for classes in (("python", "ps"), ("other",), ("unknown",), ("additional",)):
            with self.subTest(classes=classes):
                events = []
                capability = SimpleNamespace(
                    _probe_uid_processes_present=lambda *args, **kwargs: (True, classes),
                    _presence_result=lambda value: events.append("validated") or value,
                )
                reviewed = SimpleNamespace(
                    _child_environment=lambda *args: {},
                    _run_real_summary_probe=lambda *args, **kwargs: events.append("probe"),
                )
                with self.assertRaises(bootstrap.Refusal) as caught:
                    bootstrap._probe_summary_after_commands(
                        {}, 502, "home", {"python": "python"}, reviewed, capability, binding_value()
                    )
                self.assertEqual((caught.exception.reason, caught.exception.stage),
                                 ("cleanup_incomplete", "cleanup_summary_present"))
                self.assertEqual(events, ["validated"])

    def test_census_validation_failure_is_distinct_and_never_runs_summary_probe(self):
        events = []
        cleanup_state = {"first": None}

        def fail_remove(guard, name):
            events.append("probe-removed")
            raise RuntimeError("private-remove-detail")

        def fail_restore(guard):
            events.append("restore")
            raise RuntimeError("private-restore-detail")

        def fail_close(guard):
            events.append("close")
            raise RuntimeError("private-close-detail")

        def reject_presence(value):
            events.append("validation-failed")
            raise ValueError("private-census-detail")

        capability = SimpleNamespace(
            _probe_uid_processes_present=lambda *args, **kwargs: events.append("census") or object(),
            _presence_result=reject_presence,
        )
        reviewed = SimpleNamespace(
            _child_environment=lambda *args: {},
            _run_real_summary_probe=lambda *args, **kwargs: events.append("probe"),
            _remove_summary_parent_probe=fail_remove,
            _restore_runner_summary=fail_restore,
            _close_runner_summary=fail_close,
        )
        with self.assertRaises(bootstrap.Refusal) as caught:
            bootstrap._probe_summary_after_commands(
                {}, 502, "home", {"python": "python"}, reviewed, capability, binding_value(),
                cleanup_state,
            )
        self.assertEqual((caught.exception.reason, caught.exception.stage),
                         ("cleanup_incomplete", "cleanup_summary_census"))
        self.assertEqual(cleanup_state["first"], "cleanup_summary_census")
        self.assertEqual(events, ["census", "validation-failed"])
        self.assertNotIn("private-census-detail", str(caught.exception))
        with self.assertRaises(bootstrap.Refusal) as finished:
            bootstrap._finish_summary_guard(
                {"parent_probe_name": "summary.kd-probe"}, reviewed,
                worker_cleanup_confirmed=True, cleanup_state=cleanup_state,
            )
        self.assertEqual((finished.exception.reason, finished.exception.stage),
                         ("cleanup_incomplete", "cleanup_summary_census"))
        self.assertEqual(events, ["census", "validation-failed", "probe-removed", "restore", "close"])

    def test_native_preflight_census_failure_is_cleanup_and_blocks_summary_probe(self):
        events = []

        def fail_census(*args, **kwargs):
            events.append("census")
            error = RuntimeError("private-native-detail")
            error.reason = "native_preflight_unavailable"
            error.cleanup_complete = False
            raise error

        capability = SimpleNamespace(
            _probe_uid_processes_present=fail_census,
            _presence_result=lambda value: events.append("validated") or value,
        )
        reviewed = SimpleNamespace(
            _child_environment=lambda *args: {},
            _run_real_summary_probe=lambda *args, **kwargs: events.append("probe"),
        )
        with self.assertRaises(bootstrap.Refusal) as caught:
            bootstrap._probe_summary_after_commands(
                {}, 502, "home", {"python": "python"}, reviewed, capability, binding_value()
            )
        self.assertEqual((caught.exception.reason, caught.exception.stage),
                         ("cleanup_incomplete", "cleanup_summary_census"))
        self.assertEqual(events, ["census"])
        self.assertNotIn("private-native-detail", str(caught.exception))

    def test_summary_probe_cleanup_has_a_fixed_probe_stage(self):
        capability = SimpleNamespace(
            _probe_uid_processes_present=lambda *args, **kwargs: (False, ()),
            _presence_result=lambda value: value,
        )

        def fail_probe(*args, **kwargs):
            raise bootstrap.Refusal("cleanup_incomplete", "cleanup")

        reviewed = SimpleNamespace(
            _child_environment=lambda *args: {},
            _run_real_summary_probe=fail_probe,
        )
        with self.assertRaises(bootstrap.Refusal) as caught:
            bootstrap._probe_summary_after_commands(
                {}, 502, "home", {"python": "python"}, reviewed, capability, binding_value()
            )
        self.assertEqual((caught.exception.reason, caught.exception.stage),
                         ("cleanup_incomplete", "cleanup_summary_probe"))


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
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["SOURCE_READER_TOKEN"], "opaque-test-token")
        self.assertNotIn("SOURCE_READER_TOKEN", environment)

    def test_missing_source_reader_makes_pending_cleanup_incomplete(self):
        environment = {"SOURCE_READER_TOKEN": "opaque-test-token"}
        with patch.object(bootstrap, "_load_control_sibling", side_effect=ImportError("reader unavailable")):
            with self.assertRaisesRegex(bootstrap.Refusal, "cleanup_incomplete") as caught:
                bootstrap._revoke_pending_token(environment)
        self.assertEqual(caught.exception.stage, "cleanup_unknown")

    def test_cleanup_receipt_requires_exact_success_schema(self):
        environment = {"SOURCE_READER_TOKEN": "opaque-test-token"}
        record = {
            "schema_version": 1,
            "status": "passed",
            "reason": "ok",
            "repository_scope": "verified",
            "metadata": "verified",
            "revocation": "confirmed",
            "extra": "untrusted",
        }
        reader = SimpleNamespace(run=lambda *, environ: record)
        with patch.object(bootstrap, "_load_control_sibling", return_value=reader):
            with self.assertRaisesRegex(bootstrap.Refusal, "cleanup_incomplete"):
                bootstrap._revoke_pending_token(environment)
        self.assertIn("SOURCE_READER_TOKEN", environment)

    def test_runtime_revocation_receipt_requires_bound_proof(self):
        token = "opaque-test-token"
        request = request_value()
        binding = binding_value()
        environment = {"SOURCE_REPOSITORY_ID": "987654321"}
        lifecycle = {"token_revocation": "unconfirmed", "token_reference": token}
        calls = []
        runtime = SimpleNamespace(
            revocation_confirmed=lambda *args: calls.append(args) or True,
        )
        state = object()
        self.assertTrue(bootstrap._record_runtime_revocation(
            runtime, state, token, request, binding, environment, lifecycle,
        ))
        self.assertEqual(calls, [(state, token, "987654321", request, binding)])
        self.assertEqual(lifecycle, {"token_revocation": "confirmed", "token_reference": None})

        lifecycle = {"token_revocation": "unconfirmed", "token_reference": token}
        runtime.revocation_confirmed = lambda *args: False
        self.assertFalse(bootstrap._record_runtime_revocation(
            runtime, state, token, request, binding, environment, lifecycle,
        ))
        self.assertEqual(lifecycle, {"token_revocation": "unconfirmed", "token_reference": token})

        environment["SOURCE_REPOSITORY_ID"] = ""
        runtime.revocation_confirmed = lambda *args: True
        self.assertFalse(bootstrap._record_runtime_revocation(
            runtime, state, token, request, binding, environment, lifecycle,
        ))
        self.assertEqual(lifecycle["token_revocation"], "unconfirmed")

    def test_runtime_refusal_remains_the_owner_after_token_consumption(self):
        token = "opaque-test-token"
        output = io.StringIO()
        argv = (
            "run", "--token-stdin", "--source-sha", SOURCE, "--base-sha", BASE,
            "--base-branch", "main", "--concern", "rules-bootstrap",
        )
        environment = {}

        def failed_after_confirmed_revoke(mode, request, token_stdin, env, lifecycle):
            lifecycle["token_revocation"] = "confirmed"
            lifecycle["token_reference"] = None
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
        line = bootstrap._format_refusal(
            error,
            {"CI_SHA": CONTROL, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"},
            {"token_revocation": "unconfirmed"},
        )
        self.assertIn("reason=source_lease_unavailable", line)
        self.assertTrue(line.endswith("token-revocation=unconfirmed"))
        self.assertNotIn("private-token-value", line)

    def test_failed_suite_keeps_a_valid_observation_before_its_refusal(self):
        output = io.StringIO()
        argv = (
            "run", "--token-stdin", "--source-sha", SOURCE, "--base-sha", BASE,
            "--base-branch", "main", "--concern", "rules-bootstrap",
        )
        observed = bootstrap._format_network_observed(
            bootstrap._validate_network_record(network_record_value(), binding_value(), SOURCE)
        )

        def failed_suite(mode, request, token_stdin, env, lifecycle):
            lifecycle["token_revocation"] = "confirmed"
            lifecycle["network_observation_marker"] = observed
            raise bootstrap.Refusal("suite_failed", "rules.hooks")

        with patch.object(bootstrap, "_run", side_effect=failed_suite):
            with patch("sys.stdout", output):
                self.assertEqual(bootstrap.main(argv, {}), 1)
        lines = output.getvalue().splitlines()
        self.assertEqual(lines[0], observed)
        self.assertIn("reason=suite_failed", lines[1])
        self.assertTrue(lines[1].endswith("token-revocation=confirmed"))

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
