import copy
import base64
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path

import role_signer as subject


ROOT = Path(__file__).resolve().parents[2]
CONTROL_SHA = "a" * 40
RUN_ID = "701"
RUN_ATTEMPT = "2"
REPOSITORY = subject.CONTROL_REPOSITORY
REF = "refs/heads/main"
FIXTURE_NOW = int(time.time())
WORKFLOW_REF = REPOSITORY + "/" + subject.CALLER_PROFILES["probe"]["path"] + "@" + REF
DIGEST_PINS = {
    "sourceRepositoryDigest": "sha256:" + "1" * 64,
    "buildSignerDigest": "sha256:" + "2" * 64,
    "buildConfigDigest": "sha256:" + "3" * 64,
    "certificateIssuer": "https://fulcio.example.invalid",
}
CERTIFICATE_FIELDS = (
    "buildSignerURI",
    "subjectAlternativeName",
    "buildConfigURI",
    "githubWorkflowRef",
    "githubWorkflowName",
    "githubWorkflowRepository",
    "githubWorkflowSHA",
    "githubWorkflowTrigger",
    "sourceRepositoryIdentifier",
    "sourceRepositoryURI",
    "sourceRepositoryRef",
    "sourceRepositoryOwnerIdentifier",
    "sourceRepositoryOwnerURI",
    "sourceRepositoryVisibilityAtSigning",
    "sourceRepositoryDigest",
    "buildSignerDigest",
    "buildConfigDigest",
    "buildTrigger",
    "runInvocationURI",
    "runnerEnvironment",
    "issuer",
    "certificateIssuer",
)


def fixture_record(now=FIXTURE_NOW):
    return subject.make_key_record(
        8150001,
        CONTROL_SHA,
        RUN_ID,
        RUN_ATTEMPT,
        WORKFLOW_REF,
        now=now,
    )


def fixture_binding(role="windows-receiver", record=None):
    record = fixture_record() if record is None else record
    capsule = subject.make_synthetic_capsule(record)
    signed_subject = record if role == "windows-receiver" else capsule
    info = subject.validate_key_record(
        record,
        8150001,
        CONTROL_SHA,
        RUN_ID,
        RUN_ATTEMPT,
        WORKFLOW_REF,
        now=FIXTURE_NOW,
    )
    binding = {
        "profile": "probe",
        "role": role,
        "repository": REPOSITORY,
        "control_sha": CONTROL_SHA,
        "ref": REF,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        "transfer_id": info["transfer_id"],
        "key_record": record,
    }
    return record, signed_subject, binding


def fixture_certificate(role="windows-receiver", profile="probe", changes=None):
    expected = subject.certificate_expectations(
        profile,
        REPOSITORY,
        REF,
        CONTROL_SHA,
        RUN_ID,
        RUN_ATTEMPT,
        8150001,
        99101,
        role,
        subject.ROLE_RUNNERS[role],
        dict(DIGEST_PINS),
    )
    certificate = {field: expected[field] for field in CERTIFICATE_FIELDS}
    certificate["sourceRepositoryIdentifier"] = "8150001"
    certificate["sourceRepositoryOwnerIdentifier"] = "99101"
    if changes:
        certificate.update(changes)
    return expected, certificate


def fixture_jobs(run_id=RUN_ID, run_attempt=RUN_ATTEMPT, head_sha=CONTROL_SHA):
    api_root = "https:" + chr(47) * 2 + "api.github.com/repos/" + REPOSITORY
    rows = []
    for index, role in enumerate(subject.ROLE_ORDER, 1):
        rows.append(
            {
                "id": 1000 + index,
                "run_id": int(run_id),
                "run_attempt": int(run_attempt),
                "name": "job-" + role,
                "head_sha": head_sha,
                "status": "completed",
                "conclusion": "success",
                "runner_name": subject.ROLE_RUNNERS[role],
                "check_run_url": api_root + "/check-runs/" + str(2000 + index),
                "steps": [
                    {
                        "number": 1,
                        "name": "attest-role-statement",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ],
            }
        )
    return rows


def fixture_job_snapshot(rows=None):
    return subject.wrap_api_pages(
        "jobs",
        [{"total_count": 3, "jobs": fixture_jobs() if rows is None else rows}],
        RUN_ID,
        RUN_ATTEMPT,
        CONTROL_SHA,
    )


def fixture_api_names():
    return {role: "job-" + role for role in subject.ROLE_ORDER}


def fixture_artifacts():
    rows = []
    transfer = "b" * 32
    for index, role in enumerate(subject.ROLE_ORDER, 1):
        rows.append(
            {
                "id": 3000 + index,
                "name": "role-statement-%s-%s-%s-%s" % (role, RUN_ID, RUN_ATTEMPT, transfer),
                "workflow_run": {"id": int(RUN_ID)},
                "expired": False,
                "size_in_bytes": 4096,
                "digest": "sha256:" + str(index) * 64,
                "created_at": "2026-10-28T10:00:00Z",
                "expires_at": "2026-10-29T10:00:00Z",
            }
        )
    return rows


def fixture_artifact_snapshot(rows=None):
    return subject.wrap_api_pages(
        "artifacts",
        [{"total_count": 3, "artifacts": fixture_artifacts() if rows is None else rows}],
        RUN_ID,
        RUN_ATTEMPT,
        CONTROL_SHA,
    )


def fixture_predicate(role="windows-receiver", record=None):
    record, signed_subject, binding = fixture_binding(role, record)
    predicate = subject.make_predicate(
        binding["profile"],
        role,
        REPOSITORY,
        CONTROL_SHA,
        REF,
        RUN_ID,
        RUN_ATTEMPT,
        record,
        signed_subject,
    )
    return record, signed_subject, binding, predicate


class CanonicalIdentityTests(unittest.TestCase):
    def test_run_invocation_is_built_from_canonical_bounded_integers(self):
        value = subject.canonical_run_invocation(REPOSITORY, RUN_ID, RUN_ATTEMPT)
        self.assertEqual(
            value,
            subject.github_root(REPOSITORY) + "/actions/runs/701/attempts/2",
        )
        self.assertEqual(subject.validate_run_invocation(value, REPOSITORY, RUN_ID, RUN_ATTEMPT), value)

    def test_noncanonical_or_alternate_run_invocation_spellings_are_rejected(self):
        canonical = subject.canonical_run_invocation(REPOSITORY, RUN_ID, RUN_ATTEMPT)
        for value in (
            canonical + "/",
            canonical + "?page=1",
            canonical + chr(35) + "fragment",
            canonical.replace("github.com", "GITHUB.com"),
            canonical.replace("runs/701", "runs/0701"),
            canonical.replace("/attempts/2", "/attempts/%32"),
            canonical.replace("github.com/", "user@github.com/"),
            canonical.replace("github.com/", "github.com:443/"),
        ):
            with self.subTest(value_class="alternate"):
                with self.assertRaises(subject.Refusal):
                    subject.validate_run_invocation(value, REPOSITORY, RUN_ID, RUN_ATTEMPT)

    def test_unsigned_integer_width_and_decimal_encoding_are_bounded(self):
        self.assertEqual(subject.canonical_run_invocation(REPOSITORY, str(subject.MAX_U64), str(subject.MAX_U32)).endswith("/attempts/4294967295"), True)
        for invalid in ("0", "01", "+1", chr(0x661), str(subject.MAX_U64 + 1)):
            with self.subTest(value=invalid):
                with self.assertRaises(subject.Refusal):
                    subject.canonical_run_invocation(REPOSITORY, invalid, RUN_ATTEMPT)
        with self.assertRaises(subject.Refusal):
            subject.canonical_run_invocation(REPOSITORY, RUN_ID, str(subject.MAX_U32 + 1))

    def test_control_repository_name_and_numeric_identifier_are_distinct(self):
        expected, certificate = fixture_certificate()
        self.assertTrue(subject.validate_certificate(certificate, expected))
        for value in (REPOSITORY, "8150002", "08150001", "8150001.0"):
            altered = dict(certificate, sourceRepositoryIdentifier=value)
            with self.subTest(value=value):
                with self.assertRaises(subject.Refusal):
                    subject.validate_certificate(altered, expected)

    def test_nonce_uses_raw_hash_bytes_and_separates_role_and_subject(self):
        record = fixture_record()
        capsule = subject.make_synthetic_capsule(record)
        actual = subject.role_nonce(record, "linux-fetch-encrypt", capsule)
        expected = hashlib.sha256(
            b"KDWH-v1/role-statement-nonce\x00"
            + hashlib.sha256(record).digest()
            + b"linux-fetch-encrypt"
            + b"\x00"
            + hashlib.sha256(capsule).digest()
        ).digest()[:16].hex()
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 32)
        self.assertNotEqual(actual, subject.role_nonce(record, "capsule-attester", capsule))
        self.assertNotEqual(actual, subject.role_nonce(record, "linux-fetch-encrypt", capsule + b"x"))
        self.assertEqual(actual, actual.lower())


class KeyRecordAndPredicateTests(unittest.TestCase):
    def test_fixed_key_record_shape_context_and_fresh_transfer_binding(self):
        first = fixture_record()
        second = fixture_record()
        first_info = subject.validate_key_record(first, 8150001, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, WORKFLOW_REF, now=FIXTURE_NOW)
        second_info = subject.validate_key_record(second, 8150001, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, WORKFLOW_REF, now=FIXTURE_NOW)
        self.assertEqual(len(first), 320)
        self.assertNotEqual(first_info["transfer_id"], second_info["transfer_id"])
        for offset, value in ((40, RUN_ID), (48, RUN_ATTEMPT)):
            self.assertEqual(int.from_bytes(first[offset : offset + (8 if offset == 40 else 4)], "big"), int(value))

    def test_key_record_rejects_context_changes_and_bad_reserved_bytes(self):
        record = fixture_record()
        cases = (
            (record[:12] + (8150002).to_bytes(8, "big") + record[20:], 8150001, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, WORKFLOW_REF),
            (record[:20] + bytes.fromhex("c" * 40) + record[40:], 8150001, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, WORKFLOW_REF),
            (record[:-1] + b"\x01", 8150001, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, WORKFLOW_REF),
        )
        for altered, repository_id, sha, run_id, attempt, ref in cases:
            with self.subTest(record_case="mutated"):
                with self.assertRaises(subject.Refusal):
                    subject.validate_key_record(altered, repository_id, sha, run_id, attempt, ref, now=FIXTURE_NOW)
        with self.assertRaises(subject.Refusal):
            subject.validate_key_record(record, 8150001, CONTROL_SHA, "702", RUN_ATTEMPT, WORKFLOW_REF, now=FIXTURE_NOW)
        with self.assertRaises(subject.Refusal):
            subject.validate_key_record(record, 8150001, CONTROL_SHA, RUN_ID, "1", WORKFLOW_REF, now=FIXTURE_NOW)

    def test_probe_and_production_profiles_have_disjoint_caller_identity(self):
        probe, probe_certificate = fixture_certificate("linux-fetch-encrypt", "probe")
        production, production_certificate = fixture_certificate("linux-fetch-encrypt", "production-synthetic")
        self.assertNotEqual(probe["buildConfigURI"], production["buildConfigURI"])
        self.assertNotEqual(probe["githubWorkflowRef"], production["githubWorkflowRef"])
        self.assertNotEqual(probe["githubWorkflowName"], production["githubWorkflowName"])
        self.assertTrue(subject.validate_certificate(probe_certificate, probe))
        with self.assertRaises(subject.Refusal):
            subject.validate_certificate(probe_certificate, production)
        with self.assertRaises(subject.Refusal):
            subject.validate_certificate(production_certificate, probe)

    def test_certificate_requires_both_role_uri_and_san_and_every_identity_leaf(self):
        expected, certificate = fixture_certificate("capsule-attester")
        self.assertTrue(subject.validate_certificate(certificate, expected))
        for field, value in (
            ("buildSignerURI", subject._role_uri(REPOSITORY, "linux-fetch-encrypt", REF)),
            ("subjectAlternativeName", subject._role_uri(REPOSITORY, "windows-receiver", REF)),
            ("githubWorkflowSHA", "b" * 40),
            ("githubWorkflowTrigger", "push"),
            ("sourceRepositoryURI", subject.github_root("keeldock-platform/other")),
            ("sourceRepositoryRef", "refs/heads/feature"),
            ("buildSignerDigest", "sha256:" + "f" * 64),
        ):
            altered = dict(certificate, **{field: value})
            with self.subTest(field=field):
                with self.assertRaises(subject.Refusal):
                    subject.validate_certificate(altered, expected)

    def test_certificate_missing_type_invalid_and_unresolved_digest_values_fail_closed(self):
        expected, certificate = fixture_certificate()
        for field in ("buildConfigURI", "sourceRepositoryOwnerIdentifier", "runInvocationURI"):
            altered = dict(certificate)
            del altered[field]
            with self.subTest(field=field):
                with self.assertRaises(subject.Refusal):
                    subject.validate_certificate(altered, expected)
        altered = dict(certificate, sourceRepositoryOwnerIdentifier=99101)
        with self.assertRaises(subject.Refusal):
            subject.validate_certificate(altered, expected)
        with self.assertRaisesRegex(subject.Refusal, "digest-profile-unresolved"):
            subject.certificate_expectations(
                "probe", REPOSITORY, REF, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, 8150001, 99101,
                "windows-receiver", "windows-2025", {key: None for key in DIGEST_PINS},
            )

    def test_authenticated_leaf_and_signed_predicate_are_required(self):
        record, signed_subject, binding, predicate = fixture_predicate()
        certificate_expected, certificate = fixture_certificate()
        document = {
            "verificationResult": {
                "signature": {"certificate": certificate},
                "statement": {
                    "predicateType": subject.PREDICATE_TYPE,
                    "predicate": predicate,
                    "subject": [{"name": "subject.bin", "digest": {"sha256": hashlib.sha256(signed_subject).hexdigest()}}],
                },
            }
        }
        self.assertTrue(
            subject.validate_verified_statement(document, signed_subject, predicate, certificate_expected, binding)
        )
        forged = copy.deepcopy(document)
        forged["verificationResult"]["statement"]["predicate"]["role"] = "capsule-attester"
        with self.assertRaises(subject.Refusal):
            subject.validate_verified_statement(forged, signed_subject, predicate, certificate_expected, binding)
        missing = {"verificationResult": {"statement": document["verificationResult"]["statement"], "certificate": certificate}}
        with self.assertRaises(subject.Refusal):
            subject.validate_verified_statement(missing, signed_subject, predicate, certificate_expected, binding)
        forged["verificationResult"]["signature"] = {"certificate": certificate}
        forged["verificationResult"]["statement"]["predicate"] = dict(predicate, certificate=certificate)
        with self.assertRaises(subject.Refusal):
            subject.validate_verified_statement(forged, signed_subject, forged["verificationResult"]["statement"]["predicate"], certificate_expected, binding)

    def test_duplicate_json_fields_and_oversized_inputs_are_rejected(self):
        with self.assertRaisesRegex(subject.Refusal, "duplicate-json-field"):
            subject.load_json_bytes(b'{"role":"one","role":"two"}')
        with self.assertRaisesRegex(subject.Refusal, "json-input-too-large"):
            subject.load_json_bytes(b"x" * (subject.MAX_JSON_BYTES + 1))


class WorkflowAndJobMappingTests(unittest.TestCase):
    def test_checked_in_caller_and_role_graphs_have_exact_pins(self):
        for profile in subject.CALLER_PROFILES:
            with self.subTest(profile=profile):
                result = subject.verify_workflow_bytes(ROOT, profile)
                self.assertEqual(
                    set(result),
                    {subject.CALLER_PROFILES[profile]["path"]} | set(subject.ROLE_PATHS.values()),
                )

    def test_workflow_byte_pin_rejects_changed_callee(self):
        pins = dict(subject.PINNED_WORKFLOW_SHA256)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in pins:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / relative).read_bytes())
            target = root / subject.ROLE_PATHS["linux-fetch-encrypt"]
            target.write_bytes(target.read_bytes() + b"\n")
            with self.assertRaisesRegex(subject.Refusal, "workflow-byte-mismatch"):
                subject.verify_workflow_bytes(root, "probe", pins)

    def test_call_graph_requires_one_fixed_call_per_role_and_one_signing_job(self):
        graph = {
            "caller": {
                "path": subject.CALLER_PROFILES["probe"]["path"],
                "ref": REF,
                "source_access": False,
                "call_sites": [
                    {
                        "role": role,
                        "uses": subject.ROLE_PATHS[role],
                        "profile": "probe",
                        "matrix": False,
                        "dynamic": False,
                        "condition": "main-only",
                    }
                    for role in subject.ROLE_ORDER
                ],
            },
            "roles": [
                {
                    "role": role,
                    "path": subject.ROLE_PATHS[role],
                    "jobs": [role],
                    "sign_steps": ["attest-role-statement"],
                    "nested_calls": [],
                    "matrix": False,
                    "dynamic": False,
                }
                for role in subject.ROLE_ORDER
            ],
        }
        self.assertTrue(subject.validate_call_graph(graph, "probe"))
        duplicate = copy.deepcopy(graph)
        duplicate["caller"]["call_sites"].append(copy.deepcopy(duplicate["caller"]["call_sites"][0]))
        with self.assertRaises(subject.Refusal):
            subject.validate_call_graph(duplicate, "probe")
        matrix = copy.deepcopy(graph)
        matrix["roles"][1]["matrix"] = True
        with self.assertRaises(subject.Refusal):
            subject.validate_call_graph(matrix, "probe")
        dynamic = copy.deepcopy(graph)
        dynamic["caller"]["call_sites"][0]["dynamic"] = True
        with self.assertRaises(subject.Refusal):
            subject.validate_call_graph(dynamic, "probe")

    def test_attempt_specific_jobs_pages_must_be_complete_and_unique(self):
        snapshot = fixture_job_snapshot()
        result = subject.validate_jobs_snapshot(snapshot, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, fixture_api_names())
        self.assertEqual(set(result), set(subject.ROLE_ORDER))
        incomplete = copy.deepcopy(snapshot)
        incomplete["complete"] = False
        with self.assertRaises(subject.Refusal):
            subject.validate_jobs_snapshot(incomplete, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, fixture_api_names())
        stale = copy.deepcopy(snapshot)
        stale["run_attempt"] = "1"
        with self.assertRaises(subject.Refusal):
            subject.validate_jobs_snapshot(stale, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, fixture_api_names())
        duplicate = fixture_job_snapshot(fixture_jobs() + [fixture_jobs()[0]])
        with self.assertRaises(subject.Refusal):
            subject.validate_jobs_snapshot(duplicate, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, fixture_api_names())
        missing = fixture_job_snapshot(fixture_jobs()[:-1])
        with self.assertRaises(subject.Refusal):
            subject.validate_jobs_snapshot(missing, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, fixture_api_names())
        with self.assertRaisesRegex(subject.Refusal, "api-job-map-unresolved"):
            subject.validate_jobs_snapshot(snapshot, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, {role: None for role in subject.ROLE_ORDER})

    def test_linux_step_names_are_fixed_and_hosted_ordinals_remain_unresolved(self):
        for profile in subject.CALLER_PROFILES:
            self.assertEqual(
                subject.API_LINUX_STEP_NAME_PINS[profile],
                {
                    "revoke-source-token": "handoff-revoke-source-token-v1",
                    "verify-token-rejection": "handoff-verify-token-rejection-v1",
                },
            )
            self.assertTrue(all(value is None for value in subject.API_LINUX_STEP_ORDINAL_PINS[profile].values()))

    def test_api_rejects_wrong_sha_run_attempt_status_runner_and_step_shapes(self):
        mutations = (
            ("head_sha", "b" * 40),
            ("run_id", 702),
            ("run_attempt", 3),
            ("status", "unknown"),
            ("runner_name", "self-hosted"),
        )
        for field, value in mutations:
            rows = fixture_jobs()
            rows[0][field] = value
            with self.subTest(field=field):
                with self.assertRaises(subject.Refusal):
                    subject.validate_jobs_snapshot(fixture_job_snapshot(rows), RUN_ID, RUN_ATTEMPT, CONTROL_SHA, fixture_api_names())
        rows = fixture_jobs()
        rows[1]["steps"].append(dict(rows[1]["steps"][0]))
        with self.assertRaises(subject.Refusal):
            subject.validate_jobs_snapshot(fixture_job_snapshot(rows), RUN_ID, RUN_ATTEMPT, CONTROL_SHA, fixture_api_names())

    def test_run_and_repository_metadata_bind_numeric_ids_name_ref_attempt_and_commit(self):
        repository_metadata = {
            "id": 8150001,
            "full_name": REPOSITORY,
            "owner_id": 99101,
            "visibility": "public",
        }
        repository_id, owner_id = subject.validate_repository_metadata(repository_metadata, REPOSITORY)
        self.assertEqual((repository_id, owner_id), (8150001, 99101))
        run_metadata = {
            "id": int(RUN_ID),
            "run_attempt": int(RUN_ATTEMPT),
            "head_sha": CONTROL_SHA,
            "path": subject.CALLER_PROFILES["probe"]["path"],
            "event": "workflow_dispatch",
            "head_branch": "main",
            "repository": {"id": repository_id, "full_name": REPOSITORY},
            "status": "in_progress",
            "conclusion": None,
        }
        self.assertTrue(subject.validate_run_metadata(run_metadata, "probe", REPOSITORY, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, repository_id))
        for field, value in (("run_attempt", 1), ("head_sha", "b" * 40), ("event", "push"), ("head_branch", "feature")):
            altered = dict(run_metadata, **{field: value})
            with self.subTest(field=field):
                with self.assertRaises(subject.Refusal):
                    subject.validate_run_metadata(altered, "probe", REPOSITORY, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, repository_id)
        altered_repository = dict(repository_metadata, full_name="keeldock-platform/other")
        with self.assertRaises(subject.Refusal):
            subject.validate_repository_metadata(altered_repository, REPOSITORY)


class ArtifactAndStageTests(unittest.TestCase):
    def test_artifacts_require_all_pages_one_attempt_one_transfer_and_valid_metadata(self):
        snapshot = fixture_artifact_snapshot()
        result = subject.validate_artifact_inventory(snapshot, RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        self.assertEqual(set(result), set(subject.ROLE_ORDER))
        duplicate = fixture_artifacts() + [fixture_artifacts()[0]]
        with self.assertRaises(subject.Refusal):
            subject.validate_artifact_inventory(fixture_artifact_snapshot(duplicate), RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        stale = fixture_artifacts()
        stale[0]["name"] = stale[0]["name"].replace("-2-", "-1-")
        with self.assertRaises(subject.Refusal):
            subject.validate_artifact_inventory(fixture_artifact_snapshot(stale), RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        expired = fixture_artifacts()
        expired[1]["expired"] = True
        with self.assertRaises(subject.Refusal):
            subject.validate_artifact_inventory(fixture_artifact_snapshot(expired), RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        wrong_transfer = fixture_artifacts()
        wrong_transfer[2]["name"] = wrong_transfer[2]["name"][:-1] + "c"
        with self.assertRaises(subject.Refusal):
            subject.validate_artifact_inventory(fixture_artifact_snapshot(wrong_transfer), RUN_ID, RUN_ATTEMPT, CONTROL_SHA)

    def test_attempt_artifact_selection_requires_one_exact_current_run_match(self):
        snapshot = fixture_artifact_snapshot()
        pages = [page for page in snapshot["pages"]]
        selected = subject.select_artifact_name(
            {"kind": "artifacts", "complete": True, "run_id": RUN_ID, "run_attempt": RUN_ATTEMPT, "head_sha": CONTROL_SHA, "pages": pages},
            RUN_ID,
            RUN_ID,
            RUN_ATTEMPT,
            "windows-receiver",
        )
        self.assertTrue(selected.startswith("role-statement-windows-receiver-701-2-"))
        duplicate = fixture_artifacts() + [fixture_artifacts()[0]]
        wrapped = subject.wrap_api_pages("artifacts", [{"artifacts": duplicate}], RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        with self.assertRaises(subject.Refusal):
            subject.select_artifact_name(wrapped, RUN_ID, RUN_ID, RUN_ATTEMPT, "windows-receiver")

    def test_attestation_inventory_exhaustion_and_same_statement_deduplication(self):
        rows = []
        digests = {}
        for index, role in enumerate(subject.ROLE_ORDER, 1):
            digest = str(index) * 64
            statement_digest = chr(96 + index) * 64
            digests[role] = "sha256:" + digest
            rows.append({"role": role, "subject_digest": digests[role], "statement_digest": statement_digest})
        rows.append(dict(rows[0]))
        snapshot = subject.wrap_api_pages("attestations", [{"attestations": rows}], RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        result = subject.validate_attestation_inventory(snapshot, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, digests)
        self.assertEqual(set(result), set(subject.ROLE_ORDER))
        changed = copy.deepcopy(rows)
        changed.append({"role": "windows-receiver", "subject_digest": digests["windows-receiver"], "statement_digest": "f" * 64})
        altered = subject.wrap_api_pages("attestations", [{"attestations": changed}], RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        with self.assertRaises(subject.Refusal):
            subject.validate_attestation_inventory(altered, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, digests)

    def test_provider_bundle_pages_decode_the_same_signed_statement_bytes(self):
        record, signed_subject, binding, predicate = fixture_predicate("windows-receiver")
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "subject.bin", "digest": {"sha256": hashlib.sha256(signed_subject).hexdigest()}}],
            "predicateType": subject.PREDICATE_TYPE,
            "predicate": predicate,
        }
        payload = json.dumps(statement, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        bundle = {
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(payload).decode("ascii"),
                "signatures": [{"sig": "synthetic"}],
            }
        }
        extracted, parsed = subject.signed_statement_payload(bundle)
        self.assertEqual(extracted, payload)
        self.assertEqual(parsed, statement)
        provider = subject.wrap_api_pages(
            "attestations",
            [{"attestations": [{"bundle": bundle}]}],
            RUN_ID,
            RUN_ATTEMPT,
            CONTROL_SHA,
        )
        normalized = subject.normalize_provider_attestations(
            provider,
            "windows-receiver",
            hashlib.sha256(signed_subject).hexdigest(),
            predicate,
            RUN_ID,
            RUN_ATTEMPT,
            CONTROL_SHA,
        )
        self.assertEqual(
            normalized,
            [{
                "role": "windows-receiver",
                "subject_digest": hashlib.sha256(signed_subject).hexdigest(),
                "statement_digest": hashlib.sha256(payload).hexdigest(),
            }],
        )
        wrong = copy.deepcopy(provider)
        wrong["pages"][0]["attestations"][0]["bundle"]["dsseEnvelope"]["payload"] = base64.b64encode(payload + b"x").decode("ascii")
        with self.assertRaises(subject.Refusal):
            subject.normalize_provider_attestations(
                wrong, "windows-receiver", hashlib.sha256(signed_subject).hexdigest(), predicate,
                RUN_ID, RUN_ATTEMPT, CONTROL_SHA,
            )
        malformed = copy.deepcopy(bundle)
        malformed["dsseEnvelope"]["payload"] = "!"
        with self.assertRaises(subject.Refusal):
            subject.signed_statement_payload(malformed)

    def test_statement_count_deduplicates_views_but_rejects_distinct_second_signature(self):
        artifacts = [
            {
                "role": role,
                "artifact_id": 4000 + index,
                "artifact_name": "statement-" + role,
                "statement_digest": chr(96 + index) * 64,
            }
            for index, role in enumerate(subject.ROLE_ORDER, 1)
        ]
        providers = [{"role": row["role"], "statement_digest": row["statement_digest"]} for row in artifacts]
        accepted = subject.verify_statement_cardinality(artifacts, providers)
        self.assertEqual(set(accepted), set(subject.ROLE_ORDER))
        with self.assertRaises(subject.Refusal):
            subject.verify_statement_cardinality(
                artifacts,
                providers + [{"role": "linux-fetch-encrypt", "statement_digest": "f" * 64}],
            )
        duplicated_artifact = artifacts + [dict(artifacts[0])]
        with self.assertRaises(subject.Refusal):
            subject.verify_statement_cardinality(duplicated_artifact, providers)

    def test_completed_linux_revoke_and_rejection_steps_need_exact_names_ordinals_and_log_line(self):
        rows = fixture_jobs()
        rows[1]["steps"] = [
            {"number": 5, "name": "handoff-revoke-source-token-v1", "status": "completed", "conclusion": "success"},
            {"number": 6, "name": "handoff-verify-token-rejection-v1", "status": "completed", "conclusion": "success"},
        ]
        snapshot = fixture_job_snapshot(rows)
        names = {
            "revoke-source-token": "handoff-revoke-source-token-v1",
            "verify-token-rejection": "handoff-verify-token-rejection-v1",
        }
        ordinals = {"revoke-source-token": 5, "verify-token-rejection": 6}
        logs = {
            "revoke-source-token": "probe=source-free-revocation-simulation status=passed\n",
            "verify-token-rejection": "handoff-revocation=confirmed\n",
        }
        self.assertEqual(
            subject.validate_linux_revocation_evidence(
                snapshot, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, "job-linux-fetch-encrypt", names, ordinals, logs, ["other step"]
            )["conclusion"],
            "success",
        )
        invalid_logs = dict(logs, **{"verify-token-rejection": logs["verify-token-rejection"] * 2})
        with self.assertRaises(subject.Refusal):
            subject.validate_linux_revocation_evidence(
                snapshot, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, "job-linux-fetch-encrypt", names, ordinals, invalid_logs, []
            )
        with self.assertRaises(subject.Refusal):
            subject.validate_linux_revocation_evidence(
                snapshot, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, "job-linux-fetch-encrypt", names, ordinals, logs, ["handoff-revocation=confirmed\n"]
            )
        wrong_ordinal = dict(ordinals, **{"verify-token-rejection": 7})
        with self.assertRaises(subject.Refusal):
            subject.validate_linux_revocation_evidence(
                snapshot, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, "job-linux-fetch-encrypt", names, wrong_ordinal, logs, []
            )
        rows[1]["steps"][0]["conclusion"] = "skipped"
        skipped = fixture_job_snapshot(rows)
        with self.assertRaises(subject.Refusal):
            subject.validate_linux_revocation_evidence(
                skipped, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, "job-linux-fetch-encrypt", names, ordinals, logs, []
            )

    def test_gates_a_to_d_enforce_order_and_exact_required_evidence(self):
        gate_data = {
            "A": {
                "receiver_key_record_valid": True,
                "receiver_statement_valid": True,
                "receiver_subject_exact": True,
                "receiver_nonce_valid": True,
                "workflow_bytes_pinned": True,
                "receiver_job_unique": True,
            },
            "B": {
                "gate_a_passed": True,
                "receiver_binding_valid": True,
                "capsule_subject_exact": True,
                "linux_statement_valid": True,
                "linux_job_completed_successfully": True,
                "revoke_step_completed_successfully": True,
                "verify_rejection_step_completed_successfully": True,
                "revocation_line_count": 1,
            },
            "C": {
                "gate_b_passed": True,
                "receiver_statement_valid": True,
                "linux_statement_valid": True,
                "attester_statement_valid": True,
                "capsule_subject_exact": True,
                "all_nonces_valid": True,
                "attester_job_completed_successfully": True,
                "signed_receipt_valid": True,
                "manifest_authenticated": True,
                "git_objects_validated": True,
            },
            "D": {
                "gate_c_passed": True,
                "jobs_listing_complete": True,
                "artifacts_listing_complete": True,
                "attestations_listing_complete": True,
                "one_unique_job_per_role": True,
                "one_statement_per_role": True,
                "all_expected_jobs_successful": True,
                "fresh_transfer_binding": True,
                "all_remaining_evidence_valid": True,
                "post_run_revocation_confirmed": True,
            },
        }
        for gate, evidence in gate_data.items():
            with self.subTest(gate=gate):
                self.assertTrue(subject.evaluate_gate(gate, evidence))
        for gate, evidence in gate_data.items():
            altered = dict(evidence)
            key = next(iter(altered))
            altered[key] = 0 if key == "revocation_line_count" else False
            with self.subTest(gate=gate, negative=key):
                with self.assertRaises(subject.Refusal):
                    subject.evaluate_gate(gate, altered)
        with self.assertRaises(subject.Refusal):
            subject.evaluate_gate("A", dict(gate_data["A"], linux_statement_valid=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
