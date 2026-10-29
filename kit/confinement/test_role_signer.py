import copy
import base64
import hashlib
import contextlib
import io
import json
import tempfile
import time
import types
import unittest
from unittest import mock
import zipfile
import datetime
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
    "sourceRepositoryDigest": CONTROL_SHA,
    "buildSignerDigest": CONTROL_SHA,
    "buildConfigDigest": CONTROL_SHA,
    "certificateIssuer": subject.CERTIFICATE_ISSUER_PIN,
}
ALTERNATE_DIGEST_VALUES = {
    "sourceRepositoryDigest": "sha256-base64:YWJjZA==",
    "buildSignerDigest": "sha256-base64:ZWZnaA==",
    "buildConfigDigest": "sha256-base64:aWprbA==",
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


def fixture_record(now=FIXTURE_NOW, profile="probe"):
    return subject.make_key_record(
        8150001,
        CONTROL_SHA,
        RUN_ID,
        RUN_ATTEMPT,
        REPOSITORY + "/" + subject.CALLER_PROFILES[profile]["path"] + "@" + REF,
        now=now,
    )


def fixture_binding(role="windows-receiver", record=None, profile="probe"):
    record = fixture_record(profile=profile) if record is None else record
    capsule = subject.make_synthetic_capsule(record)
    signed_subject = record if role == "windows-receiver" else capsule
    info = subject.validate_key_record(
        record,
        8150001,
        CONTROL_SHA,
        RUN_ID,
        RUN_ATTEMPT,
        REPOSITORY + "/" + subject.CALLER_PROFILES[profile]["path"] + "@" + REF,
        now=FIXTURE_NOW,
    )
    binding = {
        "profile": profile,
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


def fixture_certificate(role="windows-receiver", profile="probe", changes=None,
                        digest_values=None):
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
        dict(DIGEST_PINS if digest_values is None else digest_values),
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
                "runner_name": "GitHub Actions %d" % index,
                "labels": [subject.ROLE_RUNNERS[role]],
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
    rows = fixture_jobs() if rows is None else rows
    return subject.wrap_api_pages(
        "jobs",
        [{"total_count": len(rows), "jobs": rows}],
        RUN_ID,
        RUN_ATTEMPT,
        CONTROL_SHA,
    )


def fixture_api_names():
    return {role: "job-" + role for role in subject.ROLE_ORDER}


def fixture_provider_http(rows):
    return b"HTTP/2 200 OK\r\n\r\n" + json.dumps({"attestations": rows}).encode("ascii") + b"\n"


def fixture_provider_snapshot(digest, rows):
    return subject.parse_provider_http(fixture_provider_http(rows), digest,
                                       RUN_ID, RUN_ATTEMPT, CONTROL_SHA)


def fixture_artifacts():
    rows = []
    transfer = "b" * 32
    created = datetime.datetime.now(datetime.timezone.utc)
    expires = created + datetime.timedelta(hours=1)
    for index, role in enumerate(subject.ROLE_ORDER, 1):
        rows.append(
            {
                "id": 3000 + index,
                "name": "role-statement-%s-%s-%s-%s" % (role, RUN_ID, RUN_ATTEMPT, transfer),
                "workflow_run": {"id": int(RUN_ID)},
                "expired": False,
                "size_in_bytes": 4096,
                "digest": "sha256:" + str(index) * 64,
                "created_at": created.isoformat(),
                "expires_at": expires.isoformat(),
            }
        )
    return rows


def fixture_artifact_snapshot(rows=None):
    rows = fixture_artifacts() if rows is None else rows
    return subject.wrap_api_pages(
        "artifacts",
        [{"total_count": len(rows), "artifacts": rows}],
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


def fixture_successful_evidence(root, profile="probe", digest_values=None):
    digest_values = DIGEST_PINS if digest_values is None else digest_values
    record = fixture_record(profile=profile)
    transfer = subject.validate_key_record(record, 8150001, CONTROL_SHA, RUN_ID,
                                           RUN_ATTEMPT, REPOSITORY + "/" +
                                           subject.CALLER_PROFILES[profile]["path"] + "@" + REF)["transfer_id"]
    artifact_root = Path(root) / "artifacts"
    artifact_root.mkdir()
    artifacts = []
    provider_rows = {}
    provider_verified = {}
    now = datetime.datetime.now(datetime.timezone.utc)
    for index, role in enumerate(subject.ROLE_ORDER, 1):
        unused_record, signed_subject, binding = fixture_binding(role, record, profile)
        predicate = subject.make_predicate(profile, role, REPOSITORY, CONTROL_SHA,
                                           REF, RUN_ID, RUN_ATTEMPT, record, signed_subject)
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "subject.bin", "digest": {
                "sha256": hashlib.sha256(signed_subject).hexdigest()}}],
            "predicateType": subject.PREDICATE_TYPE,
            "predicate": predicate,
        }
        payload = json.dumps(statement, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":")).encode("ascii")
        bundle = {"dsseEnvelope": {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [{"sig": "synthetic"}],
        }}
        unused_expected, certificate = fixture_certificate(
            role, profile, digest_values=digest_values)
        verified = {"verificationResult": {
            "signature": {"certificate": certificate}, "statement": statement}}
        name = "role-statement-%s-%s-%s-%s" % (role, RUN_ID, RUN_ATTEMPT, transfer)
        directory = artifact_root / name
        directory.mkdir()
        files = {
            "subject.bin": signed_subject,
            "predicate.json": json.dumps(predicate, sort_keys=True).encode("ascii"),
            "bundle.json": json.dumps(bundle, sort_keys=True).encode("ascii"),
        }
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for filename, value in files.items():
                archive.writestr(filename, value)
                (directory / filename).write_bytes(value)
        archive_bytes = output.getvalue()
        (artifact_root / (name + ".zip")).write_bytes(archive_bytes)
        (directory / "verified.json").write_text(json.dumps(verified), encoding="ascii")
        artifacts.append({
            "id": 3000 + index, "name": name,
            "workflow_run": {"id": int(RUN_ID)},
            "expired": False, "size_in_bytes": len(archive_bytes),
            "digest": "sha256:" + hashlib.sha256(archive_bytes).hexdigest(),
            "created_at": now.isoformat(),
            "expires_at": (now + datetime.timedelta(hours=1)).isoformat(),
        })
        subject_digest = hashlib.sha256(signed_subject).hexdigest()
        provider_rows.setdefault(subject_digest, []).append({"bundle": bundle})
        provider_verified.setdefault(subject_digest, []).append(verified)
    provider_snapshots = {
        digest: {
            "snapshot": fixture_provider_snapshot(digest, rows),
            "verified": provider_verified[digest],
        }
        for digest, rows in provider_rows.items()
    }
    jobs = fixture_jobs()
    jobs[1]["steps"].extend([
        {"number": 5, "name": "handoff-revoke-source-token-v1",
         "status": "completed", "conclusion": "success"},
        {"number": 6, "name": "handoff-verify-token-rejection-v1",
         "status": "completed", "conclusion": "success"},
    ])
    return {
        "profile": profile, "repository": REPOSITORY, "ref": REF,
        "control_sha": CONTROL_SHA, "run_id": RUN_ID, "run_attempt": RUN_ATTEMPT,
        "repository_metadata": {"id": 8150001, "full_name": REPOSITORY,
                                "owner_id": 99101, "visibility": "public"},
        "run_metadata": {"id": int(RUN_ID), "run_attempt": int(RUN_ATTEMPT),
                         "head_sha": CONTROL_SHA,
                         "path": subject.CALLER_PROFILES[profile]["path"],
                         "event": "workflow_dispatch", "head_branch": "main",
                         "repository": {"id": 8150001, "full_name": REPOSITORY},
                         "status": "in_progress", "conclusion": None},
        "jobs_snapshot": fixture_job_snapshot(jobs),
        "artifacts_snapshot": fixture_artifact_snapshot(artifacts),
        "provider_snapshots": provider_snapshots,
        "control_root": ROOT, "evidence_root": root,
        "api_name_pins": fixture_api_names(),
        "digest_pins": {role: dict(digest_values) for role in subject.ROLE_ORDER},
    }


def write_full_cli_evidence(root, evidence):
    directory = Path(root)
    for label, key in (("jobs", "jobs_snapshot"), ("artifacts", "artifacts_snapshot"),
                       ("repository", "repository_metadata"), ("run", "run_metadata")):
        (directory / (label + ".json")).write_text(json.dumps(evidence[key]), encoding="ascii")
    for digest, entry in evidence["provider_snapshots"].items():
        (directory / ("provider-" + digest + ".json")).write_text(
            json.dumps(entry["snapshot"]), encoding="ascii")
        (directory / ("provider-" + digest + "-http.txt")).write_bytes(
            fixture_provider_http(entry["snapshot"]["pages"][0]["attestations"]))
        verified_directory = directory / ("provider-" + digest)
        verified_directory.mkdir()
        for index, verified in enumerate(entry["verified"], 1):
            (verified_directory / ("verified-%d.json" % index)).write_text(
                json.dumps(verified), encoding="ascii")
    log_path = directory / "linux.log"
    log_path.write_text(
        "job-linux-fetch-encrypt\thandoff-revoke-source-token-v1\t2026-10-28T12:00:00Z probe=source-free-revocation-simulation status=passed\n"
        "job-linux-fetch-encrypt\thandoff-verify-token-rejection-v1\t2026-10-28T12:00:01Z handoff-revocation=confirmed\n",
        encoding="ascii")
    parsed = directory / "linux-logs.json"
    if subject.main([
        "parse-linux-logs", "--observe", "--profile", evidence["profile"],
        "--jobs-file", str(directory / "jobs.json"), "--input", str(log_path),
        "--output", str(parsed), "--run-id", RUN_ID,
        "--run-attempt", RUN_ATTEMPT, "--head-sha", CONTROL_SHA,
    ]) != 0:
        raise AssertionError("synthetic-linux-log-layout")


def fixture_transition_arguments(evidence, gate):
    required = subject.ROLE_ORDER[:1] if gate == "A" else subject.ROLE_ORDER[:2]
    artifacts = [row for row in evidence["artifacts_snapshot"]["pages"][0]["artifacts"]
                 if any(row["name"].startswith("role-statement-" + role + "-") for role in required)]
    result = {
        key: evidence[key] for key in (
            "profile", "repository", "ref", "control_sha", "run_id", "run_attempt",
            "repository_metadata", "run_metadata", "jobs_snapshot", "control_root",
            "api_name_pins", "digest_pins",
        )
    }
    result["gate"] = gate
    result["jobs_snapshot"] = copy.deepcopy(evidence["jobs_snapshot"])
    result["jobs_snapshot"]["pages"][0]["jobs"][0]["status"] = "in_progress"
    result["jobs_snapshot"]["pages"][0]["jobs"][0]["conclusion"] = None
    result["artifacts_snapshot"] = fixture_artifact_snapshot(artifacts)
    subject_digests = {
        hashlib.sha256((Path(evidence["evidence_root"]) / "artifacts" /
                        artifact["name"] / "subject.bin").read_bytes()).hexdigest()
        for artifact in artifacts
    }
    result["provider_snapshots"] = {}
    for digest in subject_digests:
        listing = evidence["provider_snapshots"][digest]
        pairs = list(zip(listing["snapshot"]["pages"][0]["attestations"],
                         listing["verified"]))
        selected = [
            (row, verified) for row, verified in pairs
            if subject.signed_statement_payload(row["bundle"])[1]["predicate"]["role"] in required
        ]
        result["provider_snapshots"][digest] = {
            "snapshot": fixture_provider_snapshot(
                digest, [copy.deepcopy(row) for row, unused in selected]),
            "verified": [copy.deepcopy(verified) for unused, verified in selected],
        }
    result["evidence_root"] = Path(evidence["evidence_root"]) / "artifacts"
    if gate == "B":
        result.update({
            "step_name_pins": dict(subject.API_LINUX_STEP_NAME_PINS["probe"]),
            "step_ordinal_pins": {"revoke-source-token": 5, "verify-token-rejection": 6},
            "log_sections": {
                "revoke-source-token": "probe=source-free-revocation-simulation status=passed\n",
                "verify-token-rejection": "handoff-revocation=confirmed\n",
            },
            "other_log_sections": ["other step"],
        })
    return result


def mutate_artifact_nonce(root, artifact):
    directory = Path(root) / "artifacts" / artifact["name"]
    predicate_path = directory / "predicate.json"
    bundle_path = directory / "bundle.json"
    verified_path = directory / "verified.json"
    predicate = json.loads(predicate_path.read_text(encoding="ascii"))
    predicate["nonce"] = "0" * 32
    predicate_path.write_text(json.dumps(predicate), encoding="ascii")
    bundle = json.loads(bundle_path.read_text(encoding="ascii"))
    statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
    statement["predicate"]["nonce"] = "0" * 32
    bundle["dsseEnvelope"]["payload"] = base64.b64encode(
        json.dumps(statement, sort_keys=True).encode("ascii")).decode("ascii")
    bundle_path.write_text(json.dumps(bundle), encoding="ascii")
    verified = json.loads(verified_path.read_text(encoding="ascii"))
    verified["verificationResult"]["statement"]["predicate"]["nonce"] = "0" * 32
    verified_path.write_text(json.dumps(verified), encoding="ascii")
    repack_artifact(root, artifact)


def repack_artifact(root, artifact):
    directory = Path(root) / "artifacts" / artifact["name"]
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for filename in ("subject.bin", "predicate.json", "bundle.json"):
            archive.writestr(filename, (directory / filename).read_bytes())
    archive_bytes = output.getvalue()
    (Path(root) / "artifacts" / (artifact["name"] + ".zip")).write_bytes(archive_bytes)
    artifact["size_in_bytes"] = len(archive_bytes)
    artifact["digest"] = "sha256:" + hashlib.sha256(archive_bytes).hexdigest()


def mutate_artifact_statement_digest(root, artifact):
    directory = Path(root) / "artifacts" / artifact["name"]
    bundle_path = directory / "bundle.json"
    verified_path = directory / "verified.json"
    bundle = json.loads(bundle_path.read_text(encoding="ascii"))
    statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
    statement["subject"][0]["digest"]["sha256"] = "0" * 64
    bundle["dsseEnvelope"]["payload"] = base64.b64encode(
        json.dumps(statement, sort_keys=True).encode("ascii")).decode("ascii")
    bundle_path.write_text(json.dumps(bundle), encoding="ascii")
    verified = json.loads(verified_path.read_text(encoding="ascii"))
    verified["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
    verified_path.write_text(json.dumps(verified), encoding="ascii")
    repack_artifact(root, artifact)


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
        self.assertEqual(probe["githubWorkflowRef"], REF)
        self.assertEqual(production["githubWorkflowRef"], REF)
        self.assertNotEqual(probe["githubWorkflowName"], production["githubWorkflowName"])
        self.assertTrue(subject.validate_certificate(probe_certificate, probe))
        with self.assertRaises(subject.Refusal):
            subject.validate_certificate(probe_certificate, production)
        with self.assertRaises(subject.Refusal):
            subject.validate_certificate(production_certificate, probe)

    def test_expectations_match_literal_claim_values_for_probe_profile(self):
        expected = subject.certificate_expectations(
            "probe",
            REPOSITORY,
            "refs/heads/main",
            "a" * 40,
            "701",
            "2",
            8150001,
            99101,
            "windows-receiver",
            subject.ROLE_RUNNERS["windows-receiver"],
            dict(DIGEST_PINS),
        )
        literal = {
            "githubWorkflowRef": "refs/heads/main",
            "githubWorkflowName": "attestation-role-signer-probe",
            "githubWorkflowRepository": subject.CONTROL_REPOSITORY,
            "githubWorkflowSHA": "a" * 40,
            "githubWorkflowTrigger": "workflow_dispatch",
            "sourceRepositoryRef": "refs/heads/main",
            "sourceRepositoryVisibilityAtSigning": "public",
            "buildTrigger": "workflow_dispatch",
            "runnerEnvironment": "github-hosted",
        }
        for field, value in literal.items():
            with self.subTest(field=field):
                self.assertEqual(expected[field], value)
        self.assertTrue(expected["buildConfigURI"].endswith("/.github/workflows/attestation-role-signer-probe.yml@refs/heads/main"))

    def test_certificate_requires_both_role_uri_and_san_and_every_identity_leaf(self):
        expected, certificate = fixture_certificate("capsule-attester")
        self.assertTrue(subject.validate_certificate(certificate, expected))
        for field in CERTIFICATE_FIELDS:
            value = "2" if field in ("sourceRepositoryIdentifier", "sourceRepositoryOwnerIdentifier") else "wrong"
            altered = dict(certificate, **{field: value})
            with self.subTest(field=field):
                with self.assertRaises(subject.Refusal):
                    subject.validate_certificate(altered, expected)

    def test_certificate_missing_type_invalid_and_unresolved_digest_values_fail_closed(self):
        expected, certificate = fixture_certificate()
        for field in CERTIFICATE_FIELDS:
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

    def test_linux_step_names_and_observed_ordinals_are_pinned(self):
        for profile in subject.CALLER_PROFILES:
            self.assertEqual(
                subject.API_LINUX_STEP_NAME_PINS[profile],
                {
                    "revoke-source-token": "handoff-revoke-source-token-v1",
                    "verify-token-rejection": "handoff-verify-token-rejection-v1",
                },
            )
            self.assertEqual(subject.API_LINUX_STEP_ORDINAL_PINS[profile],
                             {"revoke-source-token": 9, "verify-token-rejection": 10})
            self.assertEqual(subject.API_JOB_NAME_PINS[profile], {
                "windows-receiver": "role-call-windows-receiver-v1 / role-windows-receiver-v1",
                "linux-fetch-encrypt": "role-call-linux-fetch-encrypt-v1 / role-linux-fetch-encrypt-v1",
                "capsule-attester": "role-call-capsule-attester-v1 / role-capsule-attester-v1",
            })

    def test_api_rejects_wrong_sha_run_attempt_status_runner_and_step_shapes(self):
        hosted = subject.validate_jobs_snapshot(fixture_job_snapshot(), RUN_ID,
                                                RUN_ATTEMPT, CONTROL_SHA, fixture_api_names())
        self.assertEqual(hosted["windows-receiver"]["runner_name"], "GitHub Actions 1")
        self.assertEqual(hosted["windows-receiver"]["labels"], ["windows-2025"])
        mutations = (
            ("head_sha", "b" * 40),
            ("run_id", 702),
            ("run_attempt", 3),
            ("status", "unknown"),
            ("runner_name", ""),
            ("labels", ["self-hosted"]),
            ("labels", None),
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
        wrong_transfer[2]["name"] = wrong_transfer[2]["name"][:-1] + ("d" if wrong_transfer[2]["name"].endswith("c") else "c")
        with self.assertRaises(subject.Refusal):
            subject.validate_artifact_inventory(fixture_artifact_snapshot(wrong_transfer), RUN_ID, RUN_ATTEMPT, CONTROL_SHA)

    def test_attempt_artifact_selection_requires_one_exact_current_run_match(self):
        snapshot = fixture_artifact_snapshot()
        pages = [page for page in snapshot["pages"]]
        selected = subject.select_artifact_name(
            {"kind": "artifacts", "complete": True, "total_count": 3,
             "run_id": RUN_ID, "run_attempt": RUN_ATTEMPT,
             "head_sha": CONTROL_SHA, "pages": pages},
            RUN_ID,
            RUN_ID,
            RUN_ATTEMPT,
            "windows-receiver",
        )
        self.assertTrue(selected.startswith("role-statement-windows-receiver-701-2-"))
        duplicate = fixture_artifacts() + [fixture_artifacts()[0]]
        wrapped = subject.wrap_api_pages("artifacts", [{"total_count": len(duplicate), "artifacts": duplicate}], RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
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
        result = subject.validate_attestation_inventory(rows, digests)
        self.assertEqual(set(result), set(subject.ROLE_ORDER))
        changed = copy.deepcopy(rows)
        changed.append({"role": "windows-receiver", "subject_digest": digests["windows-receiver"], "statement_digest": "f" * 64})
        with self.assertRaises(subject.Refusal):
            subject.validate_attestation_inventory(changed, digests)
        misplaced = copy.deepcopy(rows)
        misplaced[0]["subject_digest"] = digests["linux-fetch-encrypt"]
        with self.assertRaises(subject.Refusal):
            subject.validate_attestation_inventory(misplaced, digests)

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
        provider = fixture_provider_snapshot(hashlib.sha256(signed_subject).hexdigest(),
                                             [{"bundle": bundle}])
        certificate_expected, certificate = fixture_certificate("windows-receiver")
        verified = {"verificationResult": {"signature": {"certificate": certificate}, "statement": statement}}
        expectations = {"windows-receiver": {
            "subject": signed_subject, "predicate": predicate,
            "certificate": certificate_expected, "binding": binding,
            "statement_digest": hashlib.sha256(payload).hexdigest(),
        }}
        normalized = subject.normalize_provider_attestations(
            provider,
            hashlib.sha256(signed_subject).hexdigest(),
            expectations,
            [verified],
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
                wrong, hashlib.sha256(signed_subject).hexdigest(), expectations, [verified],
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
        providers = [{"role": row["role"], "subject_digest": "1" * 64,
                      "statement_digest": row["statement_digest"]} for row in artifacts]
        accepted = subject.verify_statement_cardinality(artifacts, providers)
        self.assertEqual(set(accepted), set(subject.ROLE_ORDER))
        with self.assertRaises(subject.Refusal):
            subject.verify_statement_cardinality(
                artifacts,
                providers + [{"role": "linux-fetch-encrypt", "subject_digest": "1" * 64,
                              "statement_digest": "f" * 64}],
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
        with tempfile.TemporaryDirectory() as temporary:
            evidence = fixture_successful_evidence(temporary)
            self.assertEqual(len(evidence["provider_snapshots"]), 2)
            result = subject.verify_source_free_evidence(**evidence)
            self.assertEqual(set(result["predicates"]), set(subject.ROLE_ORDER))
            self.assertEqual(result["subject_digests"]["linux-fetch-encrypt"],
                             result["subject_digests"]["capsule-attester"])
            self.assertTrue(subject.verify_transition_evidence(
                **fixture_transition_arguments(evidence, "A")))
            self.assertTrue(subject.verify_transition_evidence(
                **fixture_transition_arguments(evidence, "B")))
            for gate in ("A", "B"):
                completed = fixture_transition_arguments(evidence, gate)
                receiver = completed["jobs_snapshot"]["pages"][0]["jobs"][0]
                receiver["status"] = "completed"
                receiver["conclusion"] = "success"
                self.assertTrue(subject.verify_transition_evidence(**completed))
                receiver["conclusion"] = "failure"
                with self.assertRaisesRegex(subject.Refusal, "transition-role-job-not-successful"):
                    subject.verify_transition_evidence(**completed)
        for gate in subject.GATE_REQUIREMENTS:
            with self.subTest(gate=gate):
                with self.assertRaises(subject.Refusal):
                    subject.evaluate_gate(gate, {
                        field: (1 if field == "revocation_line_count" else True)
                        for field in subject.GATE_REQUIREMENTS[gate]
                    })

    def test_shared_digest_discovery_authenticates_each_bundle_and_rejects_missing_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = fixture_successful_evidence(temporary)
            self.assertEqual(len(evidence["provider_snapshots"]), 2)
            shared = next(digest for digest, entry in evidence["provider_snapshots"].items()
                          if entry["snapshot"]["observed_count"] == 2)
            missing = copy.deepcopy(evidence)
            missing["provider_snapshots"][shared]["verified"].pop()
            with self.assertRaises(subject.Refusal):
                subject.verify_source_free_evidence(**missing)
            altered = copy.deepcopy(evidence)
            document = altered["provider_snapshots"][shared]["verified"][1]
            document["verificationResult"]["signature"]["certificate"]["buildSignerURI"] = "wrong"
            with self.assertRaises(subject.Refusal):
                subject.verify_source_free_evidence(**altered)
            extra = copy.deepcopy(evidence)
            listing = extra["provider_snapshots"][shared]
            rows = listing["snapshot"]["pages"][0]["attestations"]
            rows.append(copy.deepcopy(rows[0]))
            listing["verified"].append(copy.deepcopy(listing["verified"][0]))
            listing["snapshot"]["observed_count"] = 3
            self.assertTrue(subject.verify_source_free_evidence(**extra))
            truncated = copy.deepcopy(evidence)
            truncated["provider_snapshots"][shared]["snapshot"]["pages"][0]["next_uri"] = \
                subject.provider_start_uri(shared) + "&after=missing"
            with self.assertRaises(subject.Refusal):
                subject.verify_source_free_evidence(**truncated)

    def test_cli_gate_entry_points_use_parsed_evidence_before_transition(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = fixture_successful_evidence(temporary)
            for gate in ("A", "B"):
                with self.subTest(gate=gate):
                    arguments = fixture_transition_arguments(evidence, gate)
                    prefix = Path(temporary) / gate
                    for label, key in (
                        ("repository", "repository_metadata"),
                        ("run", "run_metadata"),
                        ("jobs", "jobs_snapshot"),
                        ("artifacts", "artifacts_snapshot"),
                    ):
                        (Path(str(prefix) + "-" + label + ".json")).write_text(
                            json.dumps(arguments[key]), encoding="ascii")
                    provider_directory = Path(temporary) / (gate + "-providers")
                    provider_directory.mkdir()
                    for digest, entry in arguments["provider_snapshots"].items():
                        (provider_directory / ("provider-" + digest + ".json")).write_text(
                            json.dumps(entry["snapshot"]), encoding="ascii")
                        (provider_directory / ("provider-" + digest + "-http.txt")).write_bytes(
                            fixture_provider_http(entry["snapshot"]["pages"][0]["attestations"]))
                        verified_directory = provider_directory / ("provider-" + digest)
                        verified_directory.mkdir()
                        for index, document in enumerate(entry["verified"], 1):
                            (verified_directory / ("verified-%d.json" % index)).write_text(
                                json.dumps(document), encoding="ascii")
                    command = [
                        "gate-transition", "--gate", gate, "--profile", "probe",
                        "--repository", REPOSITORY, "--ref", REF,
                        "--control-sha", CONTROL_SHA, "--run-id", RUN_ID,
                        "--run-attempt", RUN_ATTEMPT, "--root", str(ROOT),
                        "--jobs-file", str(prefix) + "-jobs.json",
                        "--artifacts-file", str(prefix) + "-artifacts.json",
                        "--repository-metadata", str(prefix) + "-repository.json",
                        "--run-metadata", str(prefix) + "-run.json",
                        "--artifact-directory", str(Path(temporary) / "artifacts"),
                        "--provider-directory", str(provider_directory),
                    ]
                    if gate == "B":
                        log_path = Path(str(prefix) + "-logs.json")
                        raw_path = Path(str(prefix) + "-raw.log")
                        raw_path.write_text(
                            "job-linux-fetch-encrypt\thandoff-revoke-source-token-v1\t2026-10-28T12:00:00.000Z probe=source-free-revocation-simulation status=passed\n"
                            "job-linux-fetch-encrypt\thandoff-verify-token-rejection-v1\t2026-10-28T12:00:01.000Z\thandoff-revocation=confirmed\n",
                            encoding="ascii")
                        parse_command = [
                            "parse-linux-logs", "--profile", "probe", "--observe",
                            "--jobs-file", str(prefix) + "-jobs.json", "--input", str(raw_path),
                            "--output", str(log_path), "--run-id", RUN_ID,
                            "--run-attempt", RUN_ATTEMPT, "--head-sha", CONTROL_SHA,
                        ]
                        self.assertEqual(subject.main(parse_command), 0)
                        self.assertEqual(json.loads(log_path.read_text(encoding="ascii"))["sections"]
                                         ["verify-token-rejection"], "handoff-revocation=confirmed")
                        bad_path = Path(str(prefix) + "-bad.log")
                        bad_path.write_text(raw_path.read_text(encoding="ascii").replace(
                            "2026-10-28T12:00:01.000Z", "bad-timestamp"), encoding="ascii")
                        self.assertEqual(subject.main(parse_command[:parse_command.index("--input") + 1] +
                                                      [str(bad_path)] + parse_command[parse_command.index("--output"):]), 1)
                        command.extend(("--linux-logs", str(log_path)))
                    with mock.patch.object(subject, "API_JOB_NAME_PINS", {"probe": fixture_api_names()}), \
                            mock.patch.object(subject, "API_LINUX_STEP_ORDINAL_PINS", {
                                "probe": {"revoke-source-token": 5, "verify-token-rejection": 6}}):
                        self.assertEqual(subject.main(command), 0)
                    observation_path = Path(str(prefix) + "-observation.json")
                    self.assertEqual(subject.main(command + ["--observe", "--observation-output",
                                                             str(observation_path)]), 0)
                    measured = json.loads(observation_path.read_text(encoding="ascii"))
                    self.assertEqual(measured["acceptance"], "blocked")
                    self.assertEqual(measured["api_job_names"]["windows-receiver"], "job-windows-receiver")
                    self.assertEqual(subject.main(command), 1)
                    raw_provider = next(provider_directory.glob("provider-*-http.txt"))
                    complete_http = raw_provider.read_bytes()
                    raw_provider.write_bytes(complete_http + b"HTTP/2 200 OK\r\n\r\n{}")
                    self.assertEqual(subject.main(command + ["--observe", "--observation-output",
                                                             str(observation_path)]), 1)
                    raw_provider.write_bytes(complete_http)
                    missing = next(provider_directory.glob("provider-*.json"))
                    missing.unlink()
                    self.assertEqual(subject.main(command + ["--observe", "--observation-output",
                                                             str(observation_path)]), 1)

    def test_full_probe_observation_records_mappings_but_cannot_accept_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = fixture_successful_evidence(
                temporary, digest_values=ALTERNATE_DIGEST_VALUES)
            write_full_cli_evidence(temporary, evidence)
            command = [
                "verify-snapshot", "--profile", "probe", "--repository", REPOSITORY,
                "--ref", REF, "--control-sha", CONTROL_SHA, "--run-id", RUN_ID,
                "--run-attempt", RUN_ATTEMPT, "--root", str(ROOT),
                "--jobs-file", str(Path(temporary) / "jobs.json"),
                "--artifacts-file", str(Path(temporary) / "artifacts.json"),
                "--repository-metadata", str(Path(temporary) / "repository.json"),
                "--run-metadata", str(Path(temporary) / "run.json"),
                "--evidence-directory", temporary,
                "--linux-logs", str(Path(temporary) / "linux-logs.json"),
            ]
            output = Path(temporary) / "observed.json"
            self.assertEqual(subject.main(command + ["--observe", "--observation-output", str(output)]), 0)
            observed = json.loads(output.read_text(encoding="ascii"))
            self.assertEqual(observed["acceptance"], "blocked")
            self.assertEqual(observed["certificate_digests"], {
                role: ALTERNATE_DIGEST_VALUES for role in subject.ROLE_ORDER})
            self.assertEqual(set(observed["api_job_names"]), set(subject.ROLE_ORDER))
            self.assertEqual(observed["linux_step_ordinals"], {
                "revoke-source-token": 5, "verify-token-rejection": 6})
            self.assertEqual(observed["api_job_identity"]["windows-receiver"]["job_id"], 1001)
            self.assertEqual(observed["api_job_identity"]["windows-receiver"]["runner_name"],
                             "GitHub Actions 1")
            self.assertEqual(observed["api_job_identity"]["windows-receiver"]["labels"],
                             ["windows-2025"])
            self.assertEqual(subject.main(command), 1)
            production = command.copy()
            production[production.index("probe")] = "production-synthetic"
            self.assertEqual(subject.main(production + ["--observe", "--observation-output", str(output)]), 1)

    def test_observation_bounds_raw_certificate_digest_values(self):
        for value in ("", "x" * 513, "base64:line\nbreak"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                evidence = fixture_successful_evidence(
                    temporary, digest_values=ALTERNATE_DIGEST_VALUES)
                role = subject.ROLE_ORDER[0]
                artifacts = subject.validate_artifact_inventory(
                    evidence["artifacts_snapshot"], RUN_ID, RUN_ATTEMPT,
                    CONTROL_SHA, subject.ROLE_ORDER)
                verified_path = (Path(temporary) / "artifacts" /
                                 artifacts[role][0]["name"] / "verified.json")
                verified = json.loads(verified_path.read_text(encoding="ascii"))
                verified["verificationResult"]["signature"]["certificate"]["sourceRepositoryDigest"] = value
                verified_path.write_text(json.dumps(verified), encoding="ascii")
                with self.assertRaisesRegex(subject.Refusal, "observation-certificate-digest"):
                    subject.observed_pins(
                        evidence["jobs_snapshot"], artifacts, Path(temporary) / "artifacts",
                        (role,), RUN_ID, RUN_ATTEMPT, CONTROL_SHA, "probe")

    def test_production_caller_observation_is_source_free_and_still_refuses_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = fixture_successful_evidence(temporary, "production-synthetic")
            write_full_cli_evidence(temporary, evidence)
            command = [
                "verify-snapshot", "--profile", "production-synthetic",
                "--repository", REPOSITORY, "--ref", REF,
                "--control-sha", CONTROL_SHA, "--run-id", RUN_ID,
                "--run-attempt", RUN_ATTEMPT, "--root", str(ROOT),
                "--jobs-file", str(Path(temporary) / "jobs.json"),
                "--artifacts-file", str(Path(temporary) / "artifacts.json"),
                "--repository-metadata", str(Path(temporary) / "repository.json"),
                "--run-metadata", str(Path(temporary) / "run.json"),
                "--evidence-directory", temporary,
                "--linux-logs", str(Path(temporary) / "linux-logs.json"),
            ]
            output = Path(temporary) / "observed.json"
            self.assertEqual(subject.main(command + ["--observe", "--observation-output", str(output)]), 0)
            observed = json.loads(output.read_text(encoding="ascii"))
            self.assertEqual(observed["profile"], "production-synthetic")
            self.assertEqual(observed["acceptance"], "blocked")
            self.assertEqual(subject.main(command), 1)
            probe = command.copy()
            probe[probe.index("production-synthetic")] = "probe"
            self.assertEqual(subject.main(probe + ["--observe", "--observation-output", str(output)]), 1)

    def test_production_observation_gates_accept_an_in_progress_receiver(self):
        for gate in ("A", "B"):
            with self.subTest(gate=gate), tempfile.TemporaryDirectory() as temporary:
                evidence = fixture_successful_evidence(
                    temporary, "production-synthetic", ALTERNATE_DIGEST_VALUES)
                arguments = fixture_transition_arguments(evidence, gate)
                roles = subject.ROLE_ORDER[:1] if gate == "A" else subject.ROLE_ORDER[:2]
                artifacts = subject.validate_artifact_inventory(
                    arguments["artifacts_snapshot"], RUN_ID, RUN_ATTEMPT, CONTROL_SHA, roles)
                names, digests, ordinals, unused_jobs = subject.observed_pins(
                    arguments["jobs_snapshot"], artifacts, Path(temporary) / "artifacts",
                    roles, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, "production-synthetic")
                for role in roles:
                    self.assertEqual(digests[role], ALTERNATE_DIGEST_VALUES)
                arguments["api_name_pins"] = names
                arguments["digest_pins"] = digests
                if gate == "B":
                    arguments["step_ordinal_pins"] = ordinals
                self.assertTrue(subject.verify_transition_evidence(**arguments))

    def test_truncated_pages_and_partial_rerun_cannot_prove_unique_invocation(self):
        rows = fixture_jobs()
        first_page = rows + [{"name": "unrelated-%d" % index} for index in range(97)]
        hidden = copy.deepcopy(rows[0])
        hidden["id"] = 9001
        hidden["check_run_url"] = hidden["check_run_url"].replace("2001", "9001")
        with self.assertRaisesRegex(subject.Refusal, "api-pagination-incomplete"):
            subject.wrap_api_pages("jobs", [{"total_count": 101, "jobs": first_page}],
                                   RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        complete_pages = subject.wrap_api_pages("jobs", [
            {"total_count": 101, "jobs": first_page},
            {"total_count": 101, "jobs": [hidden]},
        ], RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        with self.assertRaises(subject.Refusal):
            subject.validate_jobs_snapshot(complete_pages, RUN_ID, RUN_ATTEMPT,
                                           CONTROL_SHA, fixture_api_names())
        duplicate = copy.deepcopy(rows[0])
        duplicate["id"] = 9001
        duplicate["check_run_url"] = duplicate["check_run_url"].replace("2001", "9001")
        complete = fixture_job_snapshot(rows + [duplicate])
        with self.assertRaises(subject.Refusal):
            subject.validate_role_job(complete, RUN_ID, RUN_ATTEMPT, CONTROL_SHA,
                                      "windows-receiver", "job-windows-receiver", ("completed",))
        stale = copy.deepcopy(rows)
        stale[0]["run_attempt"] = 1
        with self.assertRaises(subject.Refusal):
            subject.validate_role_job(fixture_job_snapshot(stale), RUN_ID,
                                      RUN_ATTEMPT, CONTROL_SHA, "windows-receiver",
                                      "job-windows-receiver", ("completed",))
        with self.assertRaises(subject.Refusal):
            subject.wrap_api_pages("jobs", [
                {"total_count": 101, "jobs": first_page},
                {"total_count": 102, "jobs": [hidden]},
            ], RUN_ID, RUN_ATTEMPT, CONTROL_SHA)

    def test_provider_cursor_links_prove_exhaustion_without_numbered_pages(self):
        digest = "a" * 64
        first = [{"bundle": {"index": 1}}]
        second = [{"bundle": {"role": "capsule-attester", "invocation": "second"}}]
        cursor = subject.provider_start_uri(digest) + "&after=opaque-cursor"
        header = ('HTTP/2 200 OK\r\nLink: <%s>; rel="next"\r\n\r\n' % cursor).encode("ascii")
        body = json.dumps({"attestations": first}).encode("ascii") + b"\n"
        tail = b"HTTP/2 200 OK\r\n\r\n" + json.dumps({"attestations": second}).encode("ascii")
        snapshot = subject.parse_provider_http(header + body + tail, digest,
                                               RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        self.assertEqual(snapshot["pages"][1]["request_uri"], cursor)
        self.assertEqual(len(subject._validate_snapshot(snapshot, "attestations",
                                                        RUN_ID, RUN_ATTEMPT, CONTROL_SHA)), 2)
        with self.assertRaisesRegex(subject.Refusal, "provider-pagination-incomplete"):
            subject.parse_provider_http(header + body, digest, RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        with self.assertRaisesRegex(subject.Refusal, "provider-after-terminal"):
            subject.parse_provider_http(tail + b"\n" + tail, digest,
                                        RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        wrong = header.replace(b"after=opaque-cursor", b"page=2")
        with self.assertRaisesRegex(subject.Refusal, "provider-cursor-query"):
            subject.parse_provider_http(wrong + body + tail, digest,
                                        RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        snapshot["pages"][1]["request_uri"] = subject.provider_start_uri(digest)
        with self.assertRaisesRegex(subject.Refusal, "provider-cursor-chain"):
            subject._validate_snapshot(snapshot, "attestations", RUN_ID,
                                       RUN_ATTEMPT, CONTROL_SHA)

    def test_provider_deprecation_link_with_type_parameter_is_ignored(self):
        digest = "a" * 64
        docs_host = ".".join(("docs", "github", "com"))
        docs_path = "/".join(("", "en", "rest", "about-the-rest-api", "api-versions"))
        docs_uri = "https:" + chr(47) * 2 + docs_host + docs_path
        response = (
            "HTTP/2 200 OK\r\n"
            "Link: <%s>; rel=\"deprecation\"; type=\"text/html\"\r\n"
            "\r\n"
            "{\"attestations\":[]}"
        ) % docs_uri
        snapshot = subject.parse_provider_http(response.encode("ascii"), digest,
                                               RUN_ID, RUN_ATTEMPT, CONTROL_SHA)
        self.assertEqual(snapshot["observed_count"], 0)
        self.assertIsNone(snapshot["pages"][0]["next_uri"])

    def test_provider_link_relations_are_unique_and_pagination_targets_are_strict(self):
        digest = "a" * 64
        docs_host = ".".join(("docs", "github", "com"))
        docs_path = "/".join(("", "en", "rest", "about-the-rest-api", "api-versions"))
        docs_uri = "https:" + chr(47) * 2 + docs_host + docs_path
        cursor = subject.provider_start_uri(digest) + "&after=opaque-cursor"
        link_value = (
            '<%s>; rel="next"; type="application/json", '
            '<%s>; rel="deprecation"; type="text/html"'
        ) % (cursor, docs_uri)
        self.assertEqual(subject.provider_next_link([("Link", link_value)], digest), cursor)
        for malformed in (
            '<%s>; rel="next", <%s>; rel="next"' % (cursor, cursor),
            '<%s>; rel="next next"' % cursor,
            '<%s>; rel="deprecation"; type=' % docs_uri,
            '<%s>; rel="canonical"' % docs_uri,
        ):
            with self.subTest(link=malformed):
                with self.assertRaisesRegex(subject.Refusal, "provider-link-shape"):
                    subject.provider_next_link([("Link", malformed)], digest)
        for relation in ("last", "prev", "first"):
            with self.subTest(relation=relation):
                with self.assertRaisesRegex(subject.Refusal, "provider-cursor-uri"):
                    subject.provider_next_link([("Link", '<%s>; rel="%s"' % (docs_uri, relation))], digest)

    def test_archive_bytes_size_digest_expiry_and_members_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = fixture_successful_evidence(temporary)
            artifact = evidence["artifacts_snapshot"]["pages"][0]["artifacts"][0]
            archive_path = Path(temporary) / "artifacts" / (artifact["name"] + ".zip")
            archive_bytes = archive_path.read_bytes()
            self.assertEqual(set(subject.validated_archive_members(artifact, archive_bytes)),
                             {"subject.bin", "predicate.json", "bundle.json"})
            for field, value in (("size_in_bytes", len(archive_bytes) + 1),
                                 ("digest", "sha256:" + "0" * 64),
                                 ("expires_at", "2000-01-01T00:00:00+00:00")):
                altered = dict(artifact, **{field: value})
                with self.subTest(field=field):
                    with self.assertRaises(subject.Refusal):
                        subject.validated_archive_members(altered, archive_bytes)
            malicious = io.BytesIO()
            with zipfile.ZipFile(malicious, "w") as archive:
                archive.writestr("../subject.bin", b"wrong")
                archive.writestr("predicate.json", b"{}")
                archive.writestr("bundle.json", b"{}")
            altered = dict(artifact, size_in_bytes=len(malicious.getvalue()),
                           digest="sha256:" + hashlib.sha256(malicious.getvalue()).hexdigest())
            with self.assertRaises(subject.Refusal):
                subject.validated_archive_members(altered, malicious.getvalue())

    def test_transition_gate_rejects_each_required_evidence_class(self):
        for gate, cases in (
            ("A", ("repository-id", "caller", "receiver-job", "receiver-job-duplicate",
                   "receiver-record", "receiver-certificate", "receiver-subject", "receiver-nonce",
                   "workflow-bytes", "receiver-archive", "receiver-size", "receiver-expiry",
                   "receiver-provider-missing", "receiver-provider-identity", "receiver-provider-cursor")),
            ("B", ("gate-a", "receiver-binding", "linux-job", "linux-certificate",
                   "linux-nonce", "capsule-subject",
                   "revoke-step", "verify-step", "revoke-ordinal", "verify-ordinal",
                   "revocation-line", "outside-line", "linux-provider-missing",
                   "linux-provider-identity", "linux-provider-cursor")),
        ):
            for case in cases:
                with self.subTest(gate=gate, case=case):
                    with tempfile.TemporaryDirectory() as temporary:
                        evidence = fixture_successful_evidence(temporary)
                        arguments = fixture_transition_arguments(evidence, gate)
                        rows = arguments["jobs_snapshot"]["pages"][0]["jobs"]
                        artifacts = arguments["artifacts_snapshot"]["pages"][0]["artifacts"]
                        receiver = Path(temporary) / "artifacts" / artifacts[0]["name"]
                        if case == "repository-id":
                            arguments["repository_metadata"]["id"] = 8150002
                        elif case == "caller":
                            arguments["run_metadata"]["path"] = "other.yml"
                        elif case == "receiver-job":
                            rows[0]["conclusion"] = "failure"
                        elif case == "receiver-job-duplicate":
                            rows.append(copy.deepcopy(rows[0]))
                            arguments["jobs_snapshot"]["total_count"] += 1
                            arguments["jobs_snapshot"]["pages"][0]["total_count"] += 1
                        elif case in ("receiver-certificate", "gate-a"):
                            path = receiver / "verified.json"
                            document = json.loads(path.read_text(encoding="ascii"))
                            document["verificationResult"]["signature"]["certificate"]["githubWorkflowSHA"] = "b" * 40
                            path.write_text(json.dumps(document), encoding="ascii")
                        elif case == "receiver-record":
                            path = receiver / "subject.bin"
                            record = path.read_bytes()
                            path.write_bytes(record[:-1] + b"\x01")
                            repack_artifact(temporary, artifacts[0])
                        elif case == "receiver-subject":
                            mutate_artifact_statement_digest(temporary, artifacts[0])
                        elif case == "receiver-nonce":
                            mutate_artifact_nonce(temporary, artifacts[0])
                        elif case == "workflow-bytes":
                            control = Path(temporary) / "control"
                            for relative in subject.PINNED_WORKFLOW_SHA256:
                                path = control / relative
                                path.parent.mkdir(parents=True, exist_ok=True)
                                path.write_bytes((ROOT / relative).read_bytes())
                            target = control / subject.ROLE_PATHS["windows-receiver"]
                            target.write_bytes(target.read_bytes() + b"\n")
                            arguments["control_root"] = control
                        elif case == "receiver-archive":
                            (Path(temporary) / "artifacts" / (artifacts[0]["name"] + ".zip")).write_bytes(b"wrong")
                        elif case == "receiver-size":
                            artifacts[0]["size_in_bytes"] += 1
                        elif case == "receiver-expiry":
                            artifacts[0]["expires_at"] = "2000-01-01T00:00:00+00:00"
                        elif case.startswith("receiver-provider-") or case.startswith("linux-provider-"):
                            target_role = "windows-receiver" if case.startswith("receiver-") else "linux-fetch-encrypt"
                            target_artifact = next(row for row in artifacts if row["name"].startswith(
                                "role-statement-" + target_role + "-"))
                            digest = hashlib.sha256((Path(temporary) / "artifacts" /
                                                     target_artifact["name"] / "subject.bin").read_bytes()).hexdigest()
                            if case.endswith("missing"):
                                arguments["provider_snapshots"].pop(digest)
                            elif case.endswith("identity"):
                                document = arguments["provider_snapshots"][digest]["verified"][0]
                                document["verificationResult"]["signature"]["certificate"]["buildSignerURI"] = "wrong"
                            else:
                                arguments["provider_snapshots"][digest]["snapshot"]["pages"][0]["next_uri"] = \
                                    subject.provider_start_uri(digest) + "&after=missing"
                        elif case == "linux-job":
                            rows[1]["conclusion"] = "failure"
                        elif case == "receiver-binding":
                            artifacts[1]["name"] = artifacts[1]["name"][:-1] + ("d" if artifacts[1]["name"].endswith("c") else "c")
                        elif case == "linux-certificate":
                            path = Path(temporary) / "artifacts" / artifacts[1]["name"] / "verified.json"
                            document = json.loads(path.read_text(encoding="ascii"))
                            document["verificationResult"]["signature"]["certificate"]["buildSignerURI"] = "wrong"
                            path.write_text(json.dumps(document), encoding="ascii")
                        elif case == "capsule-subject":
                            path = Path(temporary) / "artifacts" / artifacts[1]["name"] / "subject.bin"
                            path.write_bytes(b"wrong")
                            repack_artifact(temporary, artifacts[1])
                        elif case == "linux-nonce":
                            mutate_artifact_nonce(temporary, artifacts[1])
                        elif case == "revoke-step":
                            rows[1]["steps"][1]["conclusion"] = "skipped"
                        elif case == "verify-step":
                            rows[1]["steps"][2]["conclusion"] = "skipped"
                        elif case == "revoke-ordinal":
                            arguments["step_ordinal_pins"]["revoke-source-token"] = 7
                        elif case == "verify-ordinal":
                            arguments["step_ordinal_pins"]["verify-token-rejection"] = 7
                        elif case == "revocation-line":
                            arguments["log_sections"]["verify-token-rejection"] += "handoff-revocation=confirmed\n"
                        elif case == "outside-line":
                            arguments["other_log_sections"] = ["handoff-revocation=confirmed\n"]
                        with self.assertRaises(subject.Refusal):
                            subject.verify_transition_evidence(**arguments)


LOG_MARK = chr(35) * 2
UNLABELED_JOB = "role-call-linux-fetch-encrypt-v1 / role-linux-fetch-encrypt-v1"
REVOKE_OUTPUT = "probe=source-free-revocation-simulation status=passed"
REJECTION_OUTPUT = "probe=source-free-revocation-simulation result=synthetic"
CONFIRMED_LINE = "handoff-revocation=confirmed"


def unlabeled_run_block(script, output):
    return (
        [LOG_MARK + "[group]Run set -euo pipefail", "^[[36;1mset -euo pipefail^[[0m"]
        + ["^[[36;1m" + line + "^[[0m" for line in script]
        + ["shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}", "env:",
           "  KD_PROFILE: probe", LOG_MARK + "[endgroup]"]
        + list(output)
    )


def unlabeled_linux_messages():
    messages = [
        "Current runner version: '2.338.0'",
        LOG_MARK + "[group]Runner Image Provisioner",
        "Hosted Compute Agent",
        LOG_MARK + "[endgroup]",
        LOG_MARK + "[group]Run actions/checkout@" + "0" * 40,
        "with:",
        "  persist-credentials: false",
        LOG_MARK + "[endgroup]",
        LOG_MARK + "[group]Getting Git version info",
        "Working directory is the workspace",
        LOG_MARK + "[endgroup]",
        "Checked out the reviewed control files",
    ]
    messages += unlabeled_run_block(
        ["printf '%s\\n' 'unrelated=true'"], ["unrelated=true"])
    messages += unlabeled_run_block(
        ["printf '%s\\n' '" + REVOKE_OUTPUT + "'"], [REVOKE_OUTPUT])
    messages += unlabeled_run_block(
        ["printf '%s\\n' '" + REJECTION_OUTPUT + "'",
         "printf '%s\\n' '" + CONFIRMED_LINE + "'"],
        [REJECTION_OUTPUT, CONFIRMED_LINE])
    messages += [
        LOG_MARK + "[group]Run actions/attest@" + "0" * 40,
        "with:",
        "  push-to-registry: false",
        LOG_MARK + "[endgroup]",
        LOG_MARK + "[group]\x1b[36mAttestation signed using certificate\x1b[0m",
        "Signed",
        LOG_MARK + "[endgroup]",
        "Post job cleanup.",
    ]
    return messages


def unlabeled_linux_log(messages, job=UNLABELED_JOB):
    rows = []
    for number, message in enumerate(messages):
        stamp = "2026-10-29T13:47:%02d.%07dZ" % (number % 60, number)
        prefix = subject.BYTE_ORDER_MARK if number == 0 else ""
        rows.append(job + "\tUNKNOWN STEP\t" + prefix + stamp + " " + message)
    return "\n".join(rows) + "\n"


class UnlabeledLinuxLogTests(unittest.TestCase):
    def parse(self, messages):
        return subject.parse_linux_log_sections(
            unlabeled_linux_log(messages), UNLABELED_JOB,
            subject.API_LINUX_STEP_NAME_PINS["probe"])

    def test_sections_come_from_run_group_markers_when_every_line_is_unlabeled(self):
        parsed = self.parse(unlabeled_linux_messages())
        self.assertEqual(parsed["sections"]["revoke-source-token"], REVOKE_OUTPUT)
        self.assertEqual(parsed["sections"]["verify-token-rejection"],
                         REJECTION_OUTPUT + "\n" + CONFIRMED_LINE)
        self.assertEqual(parsed["other"][0].splitlines().count(CONFIRMED_LINE), 0)
        self.assertIn("Post job cleanup.", parsed["other"][0])
        self.assertIn("unrelated=true", parsed["other"][0])

    def test_required_sections_are_still_required(self):
        messages = unlabeled_linux_messages()
        with self.assertRaisesRegex(subject.Refusal, "linux-log-section-missing"):
            self.parse([line.replace("status=passed", "status=other") for line in messages])
        with self.assertRaisesRegex(subject.Refusal, "linux-log-section-missing"):
            self.parse([line for line in messages if line != REVOKE_OUTPUT])
        with self.assertRaisesRegex(subject.Refusal, "linux-log-section-missing"):
            self.parse([line for line in messages if line != REJECTION_OUTPUT
                        and line != CONFIRMED_LINE])
        with self.assertRaisesRegex(subject.Refusal, "linux-log-section-missing"):
            subject.parse_linux_log_sections(
                "", UNLABELED_JOB, subject.API_LINUX_STEP_NAME_PINS["probe"])

    def test_a_duplicated_step_block_is_ambiguous(self):
        messages = unlabeled_linux_messages()
        duplicate = unlabeled_run_block(
            ["printf '%s\\n' '" + REVOKE_OUTPUT + "'"], [REVOKE_OUTPUT])
        with self.assertRaisesRegex(subject.Refusal, "linux-log-section-ambiguous"):
            self.parse(messages + duplicate)

    def test_job_column_and_timestamps_are_still_enforced(self):
        text = unlabeled_linux_log(unlabeled_linux_messages())
        with self.assertRaisesRegex(subject.Refusal, "linux-log-format"):
            subject.parse_linux_log_sections(
                text, "other-job", subject.API_LINUX_STEP_NAME_PINS["probe"])
        with self.assertRaisesRegex(subject.Refusal, "linux-log-timestamp"):
            subject.parse_linux_log_sections(
                text.replace("2026-10-29T13:47:05", "bad-timestamp", 1), UNLABELED_JOB,
                subject.API_LINUX_STEP_NAME_PINS["probe"])


class GuardedCommandTests(unittest.TestCase):
    def run_guard(self, outcomes, extra=()):
        results = list(outcomes)
        calls = []

        def fake_run(command, **options):
            calls.append(command)
            outcome = results.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        buffer = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            target = str(Path(temporary) / "out.json")
            with mock.patch.object(subject.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(subject.time, "sleep") as sleeper, \
                    contextlib.redirect_stdout(buffer):
                code = subject.main(["guard", "--label", "api-fetch-failed", "--output", target,
                                     *extra, "--", "gh", "api", "route"])
            created = Path(target).exists()
        return code, buffer.getvalue(), calls, sleeper.call_count, created

    def test_failure_prints_one_fixed_reason_without_raw_error_text(self):
        failure = types.SimpleNamespace(
            returncode=1, stderr=b"gh: Not Found (HTTP 404) token=SECRETVALUE")
        code, printed, calls, sleeps, created = self.run_guard([failure])
        self.assertEqual(code, 1)
        self.assertEqual(printed, "probe=role-signer result=unavailable "
                                  "reason=api-fetch-failed exit=1 class=http-404\n")
        self.assertNotIn("SECRETVALUE", printed)
        self.assertEqual(calls, [["gh", "api", "route"]])
        self.assertEqual(sleeps, 0)
        self.assertTrue(created)

    def test_unknown_errors_collapse_to_a_fixed_class(self):
        failure = types.SimpleNamespace(returncode=4, stderr=b"free text with a secret")
        code, printed, unused_calls, unused_sleeps, unused_created = self.run_guard([failure])
        self.assertEqual(code, 1)
        self.assertEqual(printed, "probe=role-signer result=unavailable "
                                  "reason=api-fetch-failed exit=4 class=unclassified\n")

    def test_gh_refusals_map_to_fixed_classes_without_raw_text(self):
        cases = (
            (b"the response contains terminal escape sequences; pass the flag", "escape-sequences"),
            (b"gh: Found (HTTP 302)", "http-redirect"),
            (b"gh: Gone (HTTP 410)", "http-410"),
            (b"gh: Bad Request (HTTP 400)", "http-400"),
            (b"gh: Resource not accessible by integration (HTTP 403)", "http-403"),
            (b"unknown flag: --allow-escape-sequences", "gh-usage"),
            (b"stopped after 10 redirects", "redirect"),
            (b"gh: Bad Gateway (HTTP 502)", "http-5xx"),
        )
        for stderr, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(subject._guard_error_class(stderr), expected)

    def test_retryable_class_is_retried_within_the_bound(self):
        pending = types.SimpleNamespace(
            returncode=1, stderr=b"job 1 is still in progress; logs will be available")
        done = types.SimpleNamespace(returncode=0, stderr=b"")
        code, printed, calls, sleeps, unused_created = self.run_guard(
            [pending, done], ("--attempts", "3", "--pause", "1"))
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(sleeps, 1)
        self.assertEqual(printed, "probe=role-signer retry=api-fetch-failed attempt=1 "
                                  "class=in-progress\n")
        code, printed, calls, sleeps, unused_created = self.run_guard(
            [pending, pending], ("--attempts", "2", "--pause", "1"))
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 2)
        self.assertTrue(printed.endswith("reason=api-fetch-failed exit=1 class=in-progress\n"))

    def test_spawn_failure_and_bad_invocations_are_refused(self):
        code, printed, unused_calls, unused_sleeps, unused_created = self.run_guard(
            [OSError("missing")])
        self.assertEqual(code, 1)
        self.assertEqual(printed, "probe=role-signer result=unavailable "
                                  "reason=api-fetch-failed exit=127 class=spawn-failed\n")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(subject.main(
                ["guard", "--label", "api-fetch-failed", "--output", "unused", "--",
                 "curl", "route"]), 1)
            self.assertEqual(subject.main(
                ["guard", "--label", "api-fetch-failed", "--output", "unused",
                 "--attempts", "11", "--", "gh", "api"]), 1)
        self.assertEqual(buffer.getvalue().splitlines(), [
            "probe=role-signer result=unavailable reason=guard-command",
            "probe=role-signer result=unavailable reason=guard-bounds"])


def bare_linux_log(messages):
    rows = []
    for number, message in enumerate(messages):
        stamp = "2026-10-29T13:47:%02d.%07dZ" % (number % 60, number)
        prefix = subject.BYTE_ORDER_MARK if number == 0 else ""
        rows.append(prefix + stamp + " " + message)
    return "\n".join(rows) + "\n"


class BareJobLogTests(unittest.TestCase):
    def parse(self, text):
        return subject.parse_linux_log_sections(
            text, UNLABELED_JOB, subject.API_LINUX_STEP_NAME_PINS["probe"])

    def test_job_log_without_columns_uses_the_same_group_markers(self):
        messages = unlabeled_linux_messages()
        parsed = self.parse(bare_linux_log(messages))
        self.assertEqual(parsed, self.parse(unlabeled_linux_log(messages)))
        self.assertEqual(parsed["sections"]["revoke-source-token"], REVOKE_OUTPUT)
        self.assertEqual(parsed["sections"]["verify-token-rejection"],
                         REJECTION_OUTPUT + "\n" + CONFIRMED_LINE)

    def test_job_log_lines_still_need_timestamps_and_sections(self):
        messages = unlabeled_linux_messages()
        text = bare_linux_log(messages)
        with self.assertRaisesRegex(subject.Refusal, "linux-log-timestamp"):
            self.parse(text + "no timestamp here\n")
        with self.assertRaisesRegex(subject.Refusal, "linux-log-section-missing"):
            self.parse(bare_linux_log([line for line in messages if line != REVOKE_OUTPUT]))

    def test_raw_escape_bytes_in_the_api_job_log_are_stripped_before_matching(self):
        messages = unlabeled_linux_messages()
        raw = [line.replace("^[[", "\x1b[") for line in messages]
        self.assertEqual(self.parse(bare_linux_log(raw)), self.parse(bare_linux_log(messages)))

    def test_a_run_group_started_inside_a_matched_header_is_refused(self):
        messages = unlabeled_linux_messages()
        script = "^[[36;1mprintf '%s\\n' '" + REVOKE_OUTPUT + "'^[[0m"
        end = messages.index(LOG_MARK + "[endgroup]", messages.index(script))
        del messages[end]
        with self.assertRaisesRegex(subject.Refusal, "linux-log-section-nested"):
            self.parse(bare_linux_log(messages))
        with self.assertRaisesRegex(subject.Refusal, "linux-log-section-nested"):
            self.parse(unlabeled_linux_log(messages))


class JobLogFallbackTests(unittest.TestCase):
    ROUTE = "repos/keeldock-platform/platform-ci/actions/jobs/42/logs"
    VIEW = ("gh", "run", "view", "1", "--repo", "keeldock-platform/platform-ci",
            "--job", "42", "--log")
    PENDING = types.SimpleNamespace(
        returncode=1, stderr=b"run 1 is still in progress; logs will be available")

    def run_view(self, outcomes, route=None, command=None):
        results = list(outcomes)
        calls = []

        def fake_run(call, **options):
            calls.append(call)
            return results.pop(0)

        buffer = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            target = str(Path(temporary) / "out.log")
            with mock.patch.object(subject.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(subject.time, "sleep"), \
                    contextlib.redirect_stdout(buffer):
                code = subject.main(["guard", "--label", "run-view-failed", "--output", target,
                                     "--fallback-route", route or self.ROUTE, "--",
                                     *(command or self.VIEW)])
        return code, buffer.getvalue(), calls

    def test_in_progress_run_view_falls_back_to_the_job_log_route(self):
        done = types.SimpleNamespace(returncode=0, stderr=b"")
        code, printed, calls = self.run_view([self.PENDING, done])
        self.assertEqual(code, 0)
        self.assertEqual(calls, [list(self.VIEW), ["gh", "api", "--allow-escape-sequences", self.ROUTE]])
        self.assertEqual(printed, "probe=role-signer fallback=job-log-api\n")

    def test_fallback_failure_has_its_own_fixed_reason(self):
        missing = types.SimpleNamespace(returncode=1, stderr=b"gh: Not Found (HTTP 404)")
        code, printed, unused_calls = self.run_view([self.PENDING, missing])
        self.assertEqual(code, 1)
        self.assertTrue(printed.endswith(
            "reason=job-log-fetch-failed exit=1 class=http-404\n"))

    def test_other_failures_do_not_fall_back(self):
        missing = types.SimpleNamespace(returncode=1, stderr=b"gh: Not Found (HTTP 404)")
        code, printed, calls = self.run_view([missing])
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 1)
        self.assertTrue(printed.endswith("reason=run-view-failed exit=1 class=http-404\n"))

    def test_route_must_name_the_same_repository_and_job_without_dot_segments(self):
        routes = (
            "repos/keeldock-platform/platform-ci/actions/jobs/43/logs",
            "repos/keeldock-platform/other/actions/jobs/42/logs",
            "repos/other/platform-ci/actions/jobs/42/logs",
            "repos/../platform-ci/actions/jobs/42/logs",
            "repos/keeldock-platform/../actions/jobs/42/logs",
            "repos/keeldock-platform/platform-ci/actions/jobs/42/logs/extra",
            "repos/x/y/issues",
        )
        for route in routes:
            with self.subTest(route=route):
                code, printed, calls = self.run_view([], route=route)
                self.assertEqual(code, 1)
                self.assertEqual(calls, [])
                self.assertEqual(printed, "probe=role-signer result=unavailable "
                                          "reason=guard-command\n")
        dotted = ("gh", "run", "view", "1", "--repo", "../platform-ci", "--job", "42", "--log")
        code, printed, calls = self.run_view(
            [], route="repos/../platform-ci/actions/jobs/42/logs", command=dotted)
        self.assertEqual((code, calls), (1, []))
        code, printed, calls = self.run_view([], command=("gh", "run", "view", "1", "--log"))
        self.assertEqual((code, calls), (1, []))


class CertificatePinTests(unittest.TestCase):
    def expected(self, pins):
        return subject.certificate_expectations(
            "probe", REPOSITORY, REF, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, 8150001, 99101,
            "windows-receiver", subject.ROLE_RUNNERS["windows-receiver"], pins)

    def test_digests_equal_the_control_commit_and_issuer_is_pinned(self):
        pins = subject.resolve_certificate_pins("probe", CONTROL_SHA)
        self.assertEqual(set(pins), set(subject.ROLE_ORDER))
        for role in subject.ROLE_ORDER:
            self.assertEqual(pins[role], {
                "sourceRepositoryDigest": CONTROL_SHA, "buildSignerDigest": CONTROL_SHA,
                "buildConfigDigest": CONTROL_SHA,
                "certificateIssuer": "CN=sigstore-intermediate,O=sigstore.dev"})
        unused_expected, certificate = fixture_certificate()
        self.assertTrue(subject.validate_certificate(
            certificate, self.expected(pins["windows-receiver"])))

    def test_each_digest_field_must_equal_the_control_commit(self):
        expected = self.expected(subject.resolve_certificate_pins("probe", CONTROL_SHA)["windows-receiver"])
        unused_expected, certificate = fixture_certificate()
        for field in subject.CERTIFICATE_DIGEST_FIELDS:
            with self.subTest(field=field):
                altered = dict(certificate, **{field: "b" * 40})
                with self.assertRaisesRegex(subject.Refusal, "certificate-digest-mismatch"):
                    subject.validate_certificate(altered, expected)

    def test_wrong_issuer_and_bad_control_commit_fail_closed(self):
        expected = self.expected(subject.resolve_certificate_pins("probe", CONTROL_SHA)["windows-receiver"])
        unused_expected, certificate = fixture_certificate()
        with self.assertRaisesRegex(subject.Refusal, "certificate-claim-mismatch"):
            subject.validate_certificate(
                dict(certificate, certificateIssuer="CN=other,O=example"), expected)
        for value in (None, "", "short", "A" * 40, "a" * 41, 5):
            with self.subTest(value=value):
                with self.assertRaisesRegex(subject.Refusal, "certificate-control-sha-missing"):
                    subject.resolve_certificate_pins("probe", value)
        with self.assertRaisesRegex(subject.Refusal, "certificate-profile-unresolved"):
            subject.resolve_certificate_pins("unknown", CONTROL_SHA)


if __name__ == "__main__":
    unittest.main(verbosity=2)
