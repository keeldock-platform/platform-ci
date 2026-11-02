import copy
import re
import base64
import hashlib
import contextlib
import io
import json
import os
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
PRISTINE_PINS = dict(subject.PINNED_WORKFLOW_SHA256)
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
        "control_root": install_control_tree(root, profile), "evidence_root": root,
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


ATTEST_STEP = (
    "      - name: sign\n        uses: actions/attest@" + "a" * 40 + " " + chr(35) + " v4.2.2\n"
)
CANDIDATE_REF_MAIN = "refs/heads/main"
CANDIDATE_REF_UNTRUSTED = "refs/heads/untrusted"
RECEIVER_PATH = subject.ROLE_PATHS["windows-producer"]
FETCH_PATH = subject.ROLE_PATHS["linux-fetch-encrypt"]
ATTESTER_PATH = subject.ROLE_PATHS["capsule-attester"]
GENERATOR_POINT = subject.P256_GENERATOR
CAPSULE_TEST_SIZE = 8192


def legacy_role_text(role):
    return (
        "name: " + role + "\non:\n  workflow_call:\n    inputs:\n      profile:\n        required: true\n"
        "        type: string\npermissions: {}\njobs:\n  " + role + ":\n    runs-on: "
        + subject.ROLE_RUNNERS[role] + "\n    steps:\n" + ATTEST_STEP
    )


def legacy_caller_text(profile):
    jobs = ""
    for role in subject.ROLE_ORDER:
        needs = "    needs:\n      - linux-fetch-encrypt\n" if role == "capsule-attester" else ""
        guard = "    if: ${{ github.ref == 'refs/heads/main' }}\n" if role == "windows-receiver" else ""
        jobs += "  %s:\n%s%s    uses: ./%s\n    with:\n      profile: %s\n" % (
            role, guard, needs, subject.ROLE_PATHS[role], profile)
    return "name: caller\non:\n  workflow_dispatch:\npermissions: {}\njobs:\n" + jobs


def candidate_role_text(job_id, runner, names, extra=""):
    inputs = ""
    for name in names:
        required = "true" if name == "profile" else "false"
        inputs += "      %s:\n        required: %s\n        type: string\n" % (name, required)
    return (
        "name: " + job_id + "\non:\n  workflow_call:\n    inputs:\n" + inputs + "permissions: {}\njobs:\n  "
        + job_id + ":\n    if: ${{ inputs.profile == 'candidate' }}\n    runs-on: " + runner + "\n" + extra
        + "    permissions:\n      id-token: write\n      attestations: write\n    steps:\n" + ATTEST_STEP
    )


def candidate_caller_text():
    def call(job_id, path, needs, role=None):
        text = "  %s:\n    needs:\n%s    uses: ./%s\n    with:\n      profile: candidate\n" % (
            job_id, "".join("      - %s\n" % item for item in needs), path)
        if role is not None:
            text += "      role: %s\n" % role
        return text

    return (
        "name: windows-source-admission\non:\n  workflow_dispatch:\n    inputs:\n      mode:\n"
        "        required: true\n        type: string\npermissions: {}\njobs:\n  settings:\n"
        "    if: ${{ github.ref == 'refs/heads/main' || github.ref == 'refs/heads/untrusted' }}\n"
        "    runs-on: ubuntu-24.04\n"
        + call("windows-producer", RECEIVER_PATH, ("settings",), "producer")
        + call("windows-verifier", RECEIVER_PATH, ("settings",), "verifier")
        + call("linux-fetch-encrypt", FETCH_PATH, ("settings",))
        + call("capsule-attester", ATTESTER_PATH, ("settings", "linux-fetch-encrypt"))
        + "  verify-role-evidence:\n    runs-on: ubuntu-24.04\n  audit:\n    runs-on: ubuntu-24.04\n"
    )


def candidate_tree_files():
    return {
        subject.CALLER_PROFILES["candidate"]["path"]: candidate_caller_text(),
        RECEIVER_PATH: candidate_role_text(
            "windows-candidate", "windows-2025", ("profile", "role", "mode", "source_sha"),
            "    environment: ${{ inputs.mode == 'source' && 'windows-source-exec' || '' }}\n"),
        FETCH_PATH: candidate_role_text(
            "linux-fetch-encrypt", "ubuntu-24.04",
            ("profile", "mode", "source_sha", "base_sha", "base_branch", "fingerprint", "environment_name"),
            subject.FETCH_ENVIRONMENT_LINE + "\n"),
        ATTESTER_PATH: candidate_role_text("capsule-attester", "ubuntu-24.04", ("profile", "mode")),
    }


def write_tree(directory, files):
    pins = {}
    for relative, text in files.items():
        path = Path(directory) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("ascii"))
        pins[relative] = hashlib.sha256(text.encode("ascii")).hexdigest()
    return pins


def write_control_tree(directory, profile):
    if profile == "candidate":
        return write_tree(directory, candidate_tree_files())
    files = {subject.CALLER_PROFILES[profile]["path"]: legacy_caller_text(profile)}
    for role in subject.ROLE_ORDER:
        files[subject.ROLE_PATHS[role]] = legacy_role_text(role)
    return write_tree(directory, files)


def install_control_tree(root, profile):
    directory = Path(root) / "fixture-control"
    pins = write_control_tree(directory, profile)
    patcher = mock.patch.dict(subject.PINNED_WORKFLOW_SHA256, pins)
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)
    return directory


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
    def test_checked_in_candidate_caller_and_role_graphs_have_valid_shape(self):
        paths = subject.profile_workflow_paths("candidate")
        pins = {relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() for relative in paths}
        result = subject.verify_workflow_bytes(ROOT, "candidate", pins)
        self.assertEqual(set(result), set(paths))
        self.assertEqual(set(paths), {subject.CALLER_PROFILES["candidate"]["path"]} | set(subject.ROLE_PATHS.values()))
        self.assertTrue(subject.validate_workflow_graph(ROOT, "candidate"))

    def test_legacy_profiles_validate_against_fixture_trees(self):
        for profile in ("probe", "production-synthetic"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                pins = write_control_tree(temporary, profile)
                result = subject.verify_workflow_bytes(temporary, profile, pins)
                self.assertEqual(
                    set(result),
                    {subject.CALLER_PROFILES[profile]["path"]} | set(subject.ROLE_PATHS.values()),
                )
                self.assertEqual(subject.profile_roles(profile), subject.ROLE_ORDER)
                self.assertEqual(subject.profile_refs(profile), (REF,))

    def test_workflow_byte_pin_rejects_changed_callee(self):
        for profile in ("candidate", "probe"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                pins = write_control_tree(root, profile)
                target = root / subject.ROLE_PATHS["linux-fetch-encrypt"]
                target.write_bytes(target.read_bytes() + b"\n")
                with self.assertRaisesRegex(subject.Refusal, "workflow-byte-mismatch"):
                    subject.verify_workflow_bytes(root, profile, pins)

    def test_default_pins_no_longer_name_the_retired_probe_caller(self):
        self.assertNotIn(subject.CALLER_PROFILES["probe"]["path"], PRISTINE_PINS)
        self.assertEqual(
            set(PRISTINE_PINS), {subject.CALLER_PROFILES["candidate"]["path"]} | set(subject.ROLE_PATHS.values()),
        )
        with tempfile.TemporaryDirectory() as temporary:
            write_control_tree(temporary, "probe")
            with mock.patch.dict(subject.PINNED_WORKFLOW_SHA256, PRISTINE_PINS, clear=True):
                with self.assertRaisesRegex(subject.Refusal, "workflow-pin-unresolved"):
                    subject.verify_workflow_bytes(temporary, "probe")

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
        self.assertEqual(set(subject.CALLER_PROFILES), {"probe", "production-synthetic", "candidate"})
        for profile in ("probe", "production-synthetic"):
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
        self.assertEqual(subject.API_LINUX_STEP_NAME_PINS["candidate"], {
            "revoke-source-token": "handoff-revoke-source-token-v1",
            "verify-token-rejection": "handoff-verify-token-rejection-v1",
        })
        self.assertEqual(subject.API_LINUX_STEP_ORDINAL_PINS["candidate"],
                         {"revoke-source-token": 12, "verify-token-rejection": 13})
        self.assertEqual(subject.API_JOB_NAME_PINS["candidate"], {
            role: "role-call-%s-v1 / role-%s-v1" % (role, role) for role in subject.CANDIDATE_ROLES
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
                        "--run-attempt", RUN_ATTEMPT, "--root", str(evidence["control_root"]),
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
                "--run-attempt", RUN_ATTEMPT, "--root", str(evidence["control_root"]),
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
                "--run-attempt", RUN_ATTEMPT, "--root", str(evidence["control_root"]),
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
                            for relative in subject.profile_workflow_paths("probe"):
                                path = control / relative
                                path.parent.mkdir(parents=True, exist_ok=True)
                                path.write_bytes((evidence["control_root"] / relative).read_bytes())
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

    def test_control_bytes_are_stored_in_caret_form_and_tabs_are_kept(self):
        messages = unlabeled_linux_messages()
        messages[2] = "bell\x07 del\x7f esc\x1b[0m tab\tend"
        parsed = self.parse(bare_linux_log(messages))
        other = parsed["other"][0]
        self.assertIn("bell^G del^? esc^[[0m tab\tend", other)
        for text in [other] + list(parsed["sections"].values()):
            self.assertEqual([c for c in text if ord(c) < 32 and c not in "\n\t"], [])
            self.assertNotIn("\x7f", text)

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


def candidate_workflow_ref(ref=REF):
    return REPOSITORY + "/" + subject.CALLER_PROFILES["candidate"]["path"] + "@" + ref


def candidate_record(ref=REF, point=GENERATOR_POINT):
    return subject.make_key_record(
        8150001, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, candidate_workflow_ref(ref), now=FIXTURE_NOW, public_point=point,
    )


def candidate_signed_files(role, record, signed_subject, ref=REF):
    predicate = subject.make_predicate(
        "candidate", role, REPOSITORY, CONTROL_SHA, ref, RUN_ID, RUN_ATTEMPT, record, signed_subject)
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "subject.bin", "digest": {"sha256": hashlib.sha256(signed_subject).hexdigest()}}],
        "predicateType": subject.PREDICATE_TYPE,
        "predicate": predicate,
    }
    payload = json.dumps(statement, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    bundle = {"dsseEnvelope": {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"sig": "synthetic"}],
    }}
    expected = subject.certificate_expectations(
        "candidate", REPOSITORY, ref, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, 8150001, 99101,
        role, subject.ROLE_RUNNERS[role], dict(DIGEST_PINS))
    certificate = {field: expected[field] for field in CERTIFICATE_FIELDS}
    certificate["sourceRepositoryIdentifier"] = "8150001"
    certificate["sourceRepositoryOwnerIdentifier"] = "99101"
    verified = {"verificationResult": {"signature": {"certificate": certificate}, "statement": statement}}
    files = {
        "subject.bin": signed_subject,
        "predicate.json": json.dumps(predicate, sort_keys=True).encode("ascii"),
        "bundle.json": json.dumps(bundle, sort_keys=True).encode("ascii"),
    }
    return files, verified, bundle


def zip_bytes(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    return output.getvalue()


def artifact_row(identifier, name, archive_bytes, head_sha=CONTROL_SHA):
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        "id": identifier, "name": name, "workflow_run": {"id": int(RUN_ID), "head_sha": head_sha},
        "expired": False, "size_in_bytes": len(archive_bytes),
        "digest": "sha256:" + hashlib.sha256(archive_bytes).hexdigest(),
        "created_at": now.isoformat(), "expires_at": (now + datetime.timedelta(hours=1)).isoformat(),
    }


def binding_document(producer, verifier, producer_capsule, verifier_capsule, revocation="confirmed"):
    return {
        "capsule_producer_sha256": hashlib.sha256(producer_capsule).hexdigest(),
        "capsule_verifier_sha256": hashlib.sha256(verifier_capsule).hexdigest(),
        "key_record_producer_sha256": hashlib.sha256(producer).hexdigest(),
        "key_record_verifier_sha256": hashlib.sha256(verifier).hexdigest(),
        "lock_sha256": "3" * 64, "manifest_sha256": "4" * 64, "revocation": revocation,
        "schema": 1, "source_sha": "1" * 40, "tree_id": "2" * 40,
    }


class CandidateWorld:
    def __init__(self, ref=REF, revocation="confirmed", size=CAPSULE_TEST_SIZE):
        self.ref = ref
        self.size = size
        self.producer_record = candidate_record(ref)
        self.verifier_record = candidate_record(ref)
        self.capsules = {"producer": b"P" * size, "verifier": b"V" * size}
        document = binding_document(
            self.producer_record, self.verifier_record, self.capsules["producer"], self.capsules["verifier"],
            revocation)
        self.linux_subject = subject.canonical_json_subject(document)
        attested = dict(document)
        attested["kind"] = "attested"
        attested["linux_subject_sha256"] = hashlib.sha256(self.linux_subject).hexdigest()
        self.attester_subject = subject.canonical_json_subject(attested)
        self.subjects = {
            "windows-producer": (self.producer_record, self.producer_record),
            "windows-verifier": (self.verifier_record, self.verifier_record),
            "linux-fetch-encrypt": (self.producer_record, self.linux_subject),
            "capsule-attester": (self.producer_record, self.attester_subject),
        }
        self.zips = {}
        self.verified = {}
        self.bundles = {}
        self.rows = []
        self.names = {}
        self.statement_files = {}
        for index, role in enumerate(subject.CANDIDATE_ROLES, 1):
            record, signed_subject = self.subjects[role]
            files, verified, bundle = candidate_signed_files(role, record, signed_subject, ref)
            name = "role-statement-%s-%s-%s-%s" % (role, RUN_ID, RUN_ATTEMPT, record[52:68].hex())
            archive = zip_bytes(files)
            self.names[role] = name
            self.zips[3000 + index] = archive
            self.verified[name] = verified
            self.bundles[role] = bundle
            self.statement_files[name] = files
            self.rows.append(artifact_row(3000 + index, name, archive))
        for index, short in enumerate(("producer", "verifier"), 1):
            self.set_capsule(short, zip_bytes({"capsule.bin": self.capsules[short]}))

    def set_capsule(self, short, archive):
        identifier = 3100 + (1 if short == "producer" else 2)
        name = "source-capsule-%s-%s-%s" % (short, RUN_ID, RUN_ATTEMPT)
        self.rows = [row for row in self.rows if row["name"] != name]
        self.zips[identifier] = archive
        self.rows.append(artifact_row(identifier, name, archive))

    def artifact_map(self, roles=subject.CANDIDATE_ROLES):
        result = {}
        for role in roles:
            row = next(item for item in self.rows if item["name"] == self.names[role])
            result[role] = {
                "id": row["id"], "name": row["name"], "transfer_id": self.subjects[role][0][52:68].hex(),
                "expired": False, "digest": row["digest"], "size_in_bytes": row["size_in_bytes"],
                "created_at": row["created_at"], "expires_at": row["expires_at"],
            }
        return result

    def write_evidence(self, root):
        for name, files in self.statement_files.items():
            directory = Path(root) / name
            directory.mkdir(parents=True)
            for filename, value in files.items():
                (directory / filename).write_bytes(value)
            (directory / "verified.json").write_text(json.dumps(self.verified[name]), encoding="ascii")
        for row in self.rows:
            if row["name"] in self.statement_files:
                (Path(root) / (row["name"] + ".zip")).write_bytes(self.zips[row["id"]])

    def gh(self, rows=None, calls=None, attestation=True):
        rows = self.rows if rows is None else rows

        def run(arguments, output_path):
            if calls is not None:
                calls.append(list(arguments))
            if arguments[:3] == ["api", "--paginate", "--slurp"]:
                Path(output_path).write_text(json.dumps([{"total_count": len(rows), "artifacts": rows}]))
                return True
            if arguments[0] == "api" and arguments[1].endswith("/zip"):
                data = self.zips.get(int(arguments[1].split("/")[-2]))
                if data is None:
                    return False
                Path(output_path).write_bytes(data)
                return True
            if arguments[0] == "api" and arguments[2:3] == ["--jq"]:
                Path(output_path).write_text(json.dumps({
                    "id": 8150001, "full_name": REPOSITORY, "owner_id": 99101, "visibility": "public"}))
                return True
            if arguments[:2] == ["attestation", "verify"] and attestation:
                document = self.verified.get(Path(arguments[2]).parent.name)
                if document is None:
                    return False
                Path(output_path).write_text(json.dumps(document))
                return True
            return False

        return run


class CandidateProfileTests(unittest.TestCase):
    UNTRUSTED = CANDIDATE_REF_UNTRUSTED

    def _expected(self, profile, ref, role="windows-producer"):
        return subject.certificate_expectations(
            profile, REPOSITORY, ref, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, 8150001, 99101,
            role, subject.ROLE_RUNNERS[role], dict(DIGEST_PINS),
        )

    def _certificate(self, expected):
        certificate = {field: expected[field] for field in CERTIFICATE_FIELDS}
        certificate["sourceRepositoryIdentifier"] = "8150001"
        certificate["sourceRepositoryOwnerIdentifier"] = "99101"
        return certificate

    def test_profile_tables_carry_the_candidate_role_set_and_both_refs(self):
        candidate = subject.CALLER_PROFILES["candidate"]
        production = subject.CALLER_PROFILES["production-synthetic"]
        self.assertEqual(set(subject.CALLER_PROFILES), {"probe", "production-synthetic", "candidate"})
        self.assertEqual(candidate["path"], production["path"])
        self.assertEqual(candidate["name"], production["name"])
        self.assertEqual(candidate["refs"], (REF, self.UNTRUSTED))
        self.assertNotIn("ref", candidate)
        self.assertEqual(production["refs"], (REF,))
        self.assertEqual(subject.CANDIDATE_ROLES, (
            "windows-producer", "windows-verifier", "linux-fetch-encrypt", "capsule-attester"))
        self.assertEqual(subject.profile_roles("candidate"), subject.CANDIDATE_ROLES)
        self.assertEqual(subject.profile_roles("probe"), subject.ROLE_ORDER)
        self.assertEqual(subject.profile_roles("production-synthetic"), subject.ROLE_ORDER)
        self.assertEqual(
            subject.API_JOB_NAME_PINS["candidate"],
            {role: "role-call-%s-v1 / role-%s-v1" % (role, role) for role in subject.CANDIDATE_ROLES},
        )
        self.assertEqual(set(subject.API_JOB_NAME_PINS["probe"]), set(subject.ROLE_ORDER))
        self.assertEqual(subject.API_LINUX_STEP_ORDINAL_PINS["probe"],
                         {"revoke-source-token": 9, "verify-token-rejection": 10})
        self.assertEqual(subject.API_LINUX_STEP_ORDINAL_PINS["candidate"],
                         {"revoke-source-token": 12, "verify-token-rejection": 13})
        self.assertEqual(
            set(subject.resolve_certificate_pins("candidate", CONTROL_SHA)), set(subject.CANDIDATE_ROLES))
        self.assertEqual(
            set(subject.resolve_certificate_pins("probe", CONTROL_SHA)), set(subject.ROLE_ORDER))
        self.assertEqual(subject.gate_roles("candidate", "A"), subject.CANDIDATE_ROLES[:2])
        self.assertEqual(subject.gate_roles("candidate", "B"), subject.CANDIDATE_ROLES[:3])
        self.assertEqual(subject.gate_roles("probe", "A"), subject.ROLE_ORDER[:1])
        self.assertEqual(subject.gate_roles("probe", "B"), subject.ROLE_ORDER[:2])

    def test_both_windows_roles_share_the_receiver_workflow_and_runner(self):
        for role in ("windows-producer", "windows-verifier", "windows-receiver"):
            self.assertEqual(subject.ROLE_PATHS[role], RECEIVER_PATH)
            self.assertEqual(subject.ROLE_RUNNERS[role], "windows-2025")
        self.assertTrue(subject.ARTIFACT_NAME.fullmatch(
            "role-statement-windows-verifier-1-1-" + "a" * 32))

    def test_certificate_expectations_follow_each_ref_for_every_candidate_role(self):
        for role in subject.CANDIDATE_ROLES:
            for ref in (REF, self.UNTRUSTED):
                with self.subTest(role=role, ref=ref):
                    expected = self._expected("candidate", ref, role)
                    self.assertEqual(expected["githubWorkflowRef"], ref)
                    self.assertEqual(expected["sourceRepositoryRef"], ref)
                    self.assertEqual(expected["githubWorkflowName"], "windows-source-admission")
                    self.assertTrue(expected["buildSignerURI"].endswith(
                        "/" + subject.ROLE_PATHS[role] + "@" + ref))
                    self.assertTrue(expected["buildConfigURI"].endswith(
                        "/.github/workflows/windows-source-admission.yml@" + ref))
            with self.assertRaisesRegex(subject.Refusal, "profile-repository-ref"):
                self._expected("candidate", "refs/heads/develop", role)
        with self.assertRaisesRegex(subject.Refusal, "profile-role-invalid"):
            self._expected("candidate", REF, "windows-receiver")
        with self.assertRaisesRegex(subject.Refusal, "profile-role-invalid"):
            self._expected("probe", REF, "windows-producer")
        with self.assertRaisesRegex(subject.Refusal, "profile-repository-ref"):
            self._expected("production-synthetic", self.UNTRUSTED, "linux-fetch-encrypt")
        with self.assertRaisesRegex(subject.Refusal, "profile-repository-ref"):
            self._expected("probe", self.UNTRUSTED, "linux-fetch-encrypt")

    def test_a_main_certificate_cannot_satisfy_the_untrusted_expectation(self):
        main = self._expected("candidate", REF)
        untrusted = self._expected("candidate", self.UNTRUSTED)
        self.assertTrue(subject.validate_certificate(self._certificate(main), main))
        self.assertTrue(subject.validate_certificate(self._certificate(untrusted), untrusted))
        with self.assertRaises(subject.Refusal):
            subject.validate_certificate(self._certificate(main), untrusted)
        with self.assertRaises(subject.Refusal):
            subject.validate_certificate(self._certificate(untrusted), main)

    def test_the_two_windows_roles_have_distinct_signer_identity_only_by_role_claim(self):
        producer = self._expected("candidate", REF, "windows-producer")
        verifier = self._expected("candidate", REF, "windows-verifier")
        self.assertEqual(producer["buildSignerURI"], verifier["buildSignerURI"])
        self.assertNotEqual(producer["role"], verifier["role"])

    def test_predicates_bind_the_candidate_profile_and_either_ref(self):
        for ref in (REF, self.UNTRUSTED):
            with self.subTest(ref=ref):
                record = candidate_record(ref)
                predicate = subject.make_predicate(
                    "candidate", "windows-producer", REPOSITORY, CONTROL_SHA, ref, RUN_ID, RUN_ATTEMPT,
                    record, record)
                self.assertEqual(predicate["profile"], "candidate")
                self.assertEqual(predicate["controlRef"], ref)
                self.assertEqual(predicate["role"], "windows-producer")
        record = candidate_record(REF)
        for profile, role, ref in (
            ("candidate", "windows-producer", "refs/heads/develop"),
            ("production-synthetic", "windows-receiver", self.UNTRUSTED),
            ("probe", "windows-receiver", self.UNTRUSTED),
        ):
            with self.subTest(profile=profile, ref=ref):
                with self.assertRaisesRegex(subject.Refusal, "profile-ref"):
                    subject.make_predicate(profile, role, REPOSITORY, CONTROL_SHA, ref, RUN_ID,
                                           RUN_ATTEMPT, record, record)
        with self.assertRaisesRegex(subject.Refusal, "role-invalid"):
            subject.make_predicate("candidate", "windows-receiver", REPOSITORY, CONTROL_SHA, REF,
                                   RUN_ID, RUN_ATTEMPT, record, record)
        with self.assertRaises(subject.Refusal):
            subject.make_predicate("candidate", "windows-producer", REPOSITORY, CONTROL_SHA,
                                   self.UNTRUSTED, RUN_ID, RUN_ATTEMPT, record, record)

    def test_run_metadata_accepts_the_branch_of_either_candidate_ref_only(self):
        def document(branch, profile="candidate"):
            return {
                "id": int(RUN_ID), "run_attempt": int(RUN_ATTEMPT), "head_sha": CONTROL_SHA,
                "path": subject.CALLER_PROFILES[profile]["path"], "event": "workflow_dispatch",
                "head_branch": branch, "repository": {"id": 8150001, "full_name": REPOSITORY},
                "status": "in_progress", "conclusion": None,
            }

        for branch in ("main", "untrusted"):
            self.assertTrue(subject.validate_run_metadata(
                document(branch), "candidate", REPOSITORY, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, 8150001))
        self.assertTrue(subject.validate_run_metadata(
            document("main"), "production-synthetic", REPOSITORY, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, 8150001))
        for profile, branch in (("candidate", "feature"), ("candidate", "untrusted/x"), ("candidate", ""),
                                ("production-synthetic", "untrusted"), ("probe", "untrusted")):
            with self.subTest(profile=profile, branch=branch):
                with self.assertRaisesRegex(subject.Refusal, "run-ref-mismatch"):
                    subject.validate_run_metadata(
                        document(branch, profile), profile, REPOSITORY, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, 8150001)

    def test_the_pinned_step_ordinals_match_the_checked_in_fetch_workflow(self):
        text = (ROOT / FETCH_PATH).read_text(encoding="ascii")
        names = re.findall(r"(?m)^      - name: (.+)$", text)
        ordinals = {name: index for index, name in enumerate(names, 2)}
        pins = subject.API_LINUX_STEP_ORDINAL_PINS["candidate"]
        names_by_step = subject.API_LINUX_STEP_NAME_PINS["candidate"]
        self.assertEqual(ordinals["handoff-revoke-source-token-v1"], 12)
        self.assertEqual(ordinals["handoff-verify-token-rejection-v1"], 13)
        for step_id, ordinal in pins.items():
            self.assertEqual(ordinals[names_by_step[step_id]], ordinal)

    def test_candidate_log_markers_find_the_two_revocation_steps(self):
        messages = unlabeled_run_block(["printf '%s\\n' 'unrelated=true'"], ["unrelated=true"])
        messages += unlabeled_run_block(
            ['if [[ "$KD_MODE" == "source" ]]; then', "python3 -B kit/confinement/linux_source_build.py revoke",
             "else", "printf '%s\\n' '" + REVOKE_OUTPUT + "'", "fi"],
            ["linux-source-token=revoked rejection=verified receipt=positive"])
        messages += unlabeled_run_block(
            ["printf '%s\\n' 'handoff-revocation=confirmed'"], [CONFIRMED_LINE])
        names = subject.API_LINUX_STEP_NAME_PINS["candidate"]
        parsed = subject._marker_log_sections(
            messages, names, subject.LINUX_STEP_LOG_MARKERS_BY_PROFILE["candidate"])
        self.assertEqual(parsed["sections"]["verify-token-rejection"], CONFIRMED_LINE)
        self.assertIn("revoked", parsed["sections"]["revoke-source-token"])
        with self.assertRaisesRegex(subject.Refusal, "linux-log-section-missing"):
            subject._marker_log_sections(
                messages, subject.API_LINUX_STEP_NAME_PINS["probe"],
                subject.LINUX_STEP_LOG_MARKERS_BY_PROFILE["probe"])


class PublicPointAndKeyRecordTests(unittest.TestCase):
    def test_the_generator_is_accepted_and_every_malformed_point_is_refused(self):
        self.assertEqual(subject.validate_public_point(GENERATOR_POINT), GENERATOR_POINT)
        off_curve = GENERATOR_POINT[:-1] + bytes([GENERATOR_POINT[-1] ^ 1])
        for point, code in (
            (off_curve, "public-point-curve"),
            (b"\x02" + GENERATOR_POINT[1:], "public-point-shape"),
            (GENERATOR_POINT[:-1], "public-point-shape"),
            (GENERATOR_POINT + b"\x00", "public-point-shape"),
            (b"\x04" + b"\xff" * 64, "public-point-range"),
            (bytearray(GENERATOR_POINT), "public-point-shape"),
        ):
            with self.subTest(code=code, size=len(point)):
                with self.assertRaisesRegex(subject.Refusal, code):
                    subject.validate_public_point(point)

    def test_a_candidate_record_carries_the_receiver_point_and_its_digest_as_key_id(self):
        record = candidate_record()
        self.assertEqual(len(record), subject.KEY_RECORD_SIZE)
        self.assertEqual(record[100:165], GENERATOR_POINT)
        self.assertEqual(record[68:100], hashlib.sha256(GENERATOR_POINT).digest())
        self.assertEqual(record[197:229], hashlib.sha256(b"windows-receiver").digest())
        info = subject.validate_key_record(
            record, 8150001, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, candidate_workflow_ref(),
            now=FIXTURE_NOW, allow_any_point=True)
        self.assertEqual(info["transfer_id"], record[52:68].hex())

    def test_probe_style_records_still_require_the_generator_and_keep_their_layout(self):
        record = fixture_record()
        self.assertEqual(len(record), subject.KEY_RECORD_SIZE)
        self.assertEqual(record[100:165], subject.P256_GENERATOR)
        self.assertEqual(record[68:100], hashlib.sha256(subject.P256_GENERATOR).digest())
        with self.assertRaises(subject.Refusal):
            subject.make_key_record(8150001, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, WORKFLOW_REF,
                                    now=FIXTURE_NOW, public_point=b"\x04" + bytes(64))
        other = bytearray(record)
        other[100:165] = b"\x04" + bytes(range(64))
        other[68:100] = hashlib.sha256(bytes(other[100:165])).digest()
        with self.assertRaisesRegex(subject.Refusal, "key-record-public-point"):
            subject.validate_key_record(bytes(other), 8150001, CONTROL_SHA, RUN_ID, RUN_ATTEMPT,
                                        WORKFLOW_REF, now=FIXTURE_NOW)
        with self.assertRaisesRegex(subject.Refusal, "public-point-curve"):
            subject.validate_key_record(bytes(other), 8150001, CONTROL_SHA, RUN_ID, RUN_ATTEMPT,
                                        WORKFLOW_REF, now=FIXTURE_NOW, allow_any_point=True)


class BindingSubjectTests(unittest.TestCase):
    def setUp(self):
        self.producer = candidate_record()
        self.verifier = candidate_record()
        self.args = (self.producer, self.verifier, "a" * 64, "b" * 64, "1" * 40, "2" * 40, "3" * 64, "4" * 64)

    def test_the_linux_subject_is_canonical_ascii_json_with_exactly_the_bound_fields(self):
        encoded = subject.build_binding_subject(*self.args)
        self.assertTrue(encoded.endswith(b"\n"))
        document = json.loads(encoded)
        self.assertEqual(set(document), set(subject.BINDING_KEYS))
        self.assertEqual(document["revocation"], "confirmed")
        self.assertEqual(document["schema"], 1)
        self.assertEqual(document["key_record_producer_sha256"], hashlib.sha256(self.producer).hexdigest())
        self.assertEqual(document["key_record_verifier_sha256"], hashlib.sha256(self.verifier).hexdigest())
        self.assertEqual(encoded, (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
        self.assertEqual(subject.parse_binding_subject(encoded), document)

    def test_the_attested_subject_adds_the_linux_digest_and_kind_only(self):
        linux = subject.build_binding_subject(*self.args)
        attested = subject.build_attested_subject(linux)
        document = json.loads(attested)
        self.assertEqual(set(document), set(subject.ATTESTED_KEYS))
        self.assertEqual(document["kind"], "attested")
        self.assertEqual(document["linux_subject_sha256"], hashlib.sha256(linux).hexdigest())
        self.assertEqual(subject.parse_binding_subject(attested, attested=True), document)
        with self.assertRaisesRegex(subject.Refusal, "binding-fields"):
            subject.parse_binding_subject(attested)
        with self.assertRaisesRegex(subject.Refusal, "binding-fields"):
            subject.parse_binding_subject(linux, attested=True)

    def test_malformed_values_and_documents_are_refused(self):
        linux = subject.build_binding_subject(*self.args)
        document = json.loads(linux)
        cases = (
            ("source_sha", "A" * 40, "binding-hex"),
            ("tree_id", "2" * 39, "binding-hex"),
            ("lock_sha256", "z" * 64, "binding-hex"),
            ("revocation", "unconfirmed", "binding-revocation"),
            ("schema", 2, "binding-schema"),
            ("schema", True, "binding-schema"),
        )
        for name, value, code in cases:
            with self.subTest(name=name):
                changed = dict(document)
                changed[name] = value
                with self.assertRaisesRegex(subject.Refusal, code):
                    subject.parse_binding_subject(subject.canonical_json_subject(changed))
        extra = dict(document)
        extra["extra"] = "x"
        with self.assertRaisesRegex(subject.Refusal, "binding-fields"):
            subject.parse_binding_subject(subject.canonical_json_subject(extra))
        with self.assertRaisesRegex(subject.Refusal, "binding-not-canonical"):
            subject.parse_binding_subject(json.dumps(document, indent=1).encode("ascii") + b"\n")
        with self.assertRaisesRegex(subject.Refusal, "binding-size"):
            subject.parse_binding_subject(b"x" * 5000)
        with self.assertRaisesRegex(subject.Refusal, "json-invalid"):
            subject.parse_binding_subject(b"not json")
        with self.assertRaisesRegex(subject.Refusal, "binding-hex"):
            subject.build_binding_subject(self.producer, self.verifier, "a" * 64, "b" * 64,
                                          "1" * 40, "2" * 40, "3" * 63, "4" * 64)

    def test_revocation_receipts_follow_the_ref(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "revocation.json"

            def write(**changes):
                value = {
                    "schema_version": 1, "status": "confirmed", "control_sha": CONTROL_SHA,
                    "run_id": RUN_ID, "run_attempt": RUN_ATTEMPT, "installation_id": "7",
                    "rejected_after_revoke": True,
                }
                value.update(changes)
                receipt.write_text(json.dumps(value), encoding="ascii")
                return str(receipt)

            self.assertEqual(subject.validate_revocation_receipt(
                None, REF, CONTROL_SHA, RUN_ID, RUN_ATTEMPT), "confirmed")
            with self.assertRaisesRegex(subject.Refusal, "revocation-receipt-forbidden"):
                subject.validate_revocation_receipt(write(), REF, CONTROL_SHA, RUN_ID, RUN_ATTEMPT)
            with self.assertRaisesRegex(subject.Refusal, "revocation-receipt-required"):
                subject.validate_revocation_receipt(
                    None, CANDIDATE_REF_UNTRUSTED, CONTROL_SHA, RUN_ID, RUN_ATTEMPT)
            self.assertEqual(subject.validate_revocation_receipt(
                write(), CANDIDATE_REF_UNTRUSTED, CONTROL_SHA, RUN_ID, RUN_ATTEMPT), "confirmed")
            for changes in (
                {"status": "unconfirmed"}, {"rejected_after_revoke": False}, {"schema_version": 2},
                {"schema_version": True}, {"control_sha": "b" * 40}, {"run_id": "9"}, {"run_attempt": "9"},
            ):
                with self.subTest(changes=changes):
                    with self.assertRaisesRegex(subject.Refusal, "revocation-receipt-invalid"):
                        subject.validate_revocation_receipt(
                            write(**changes), CANDIDATE_REF_UNTRUSTED, CONTROL_SHA, RUN_ID, RUN_ATTEMPT)
            with self.assertRaisesRegex(subject.Refusal, "revocation-receipt-unavailable"):
                subject.validate_revocation_receipt(
                    str(Path(temporary) / "missing"), CANDIDATE_REF_UNTRUSTED, CONTROL_SHA, RUN_ID, RUN_ATTEMPT)


class CandidateWorkflowGuardTests(unittest.TestCase):
    def _code(self, mutate):
        files = candidate_tree_files()
        mutate(files)
        with tempfile.TemporaryDirectory() as temporary:
            write_tree(temporary, files)
            try:
                subject.validate_workflow_graph(temporary, "candidate")
            except subject.Refusal as error:
                return error.code
        return None

    def _replace(self, relative, old, new, count=-1):
        def mutate(files):
            self.assertIn(old, files[relative])
            files[relative] = files[relative].replace(old, new, count)

        return mutate

    def test_the_compliant_fixture_tree_passes(self):
        self.assertIsNone(self._code(lambda files: None))

    def test_caller_shape_failures_use_the_closed_codes(self):
        caller = subject.CALLER_PROFILES["candidate"]["path"]

        def append(text):
            def mutate(files):
                files[caller] += text
            return mutate

        for code, mutate in (
            ("caller-trigger-shape", append("  workflow_call:\n")),
            ("caller-guard-shape", append("    strategy:\n")),
            ("caller-source-path", append("    environment: linux-source-read\n")),
            ("caller-source-path", append("    secrets: inherit\n")),
            ("caller-masked-failure", append("    continue-on-error: true\n")),
            ("role-job-cardinality", self._replace(caller, "  audit:\n    runs-on: ubuntu-24.04\n", "")),
            ("role-job-cardinality", append("  extra:\n    runs-on: ubuntu-24.04\n")),
            ("handoff-start-order", self._replace(
                caller, "  windows-producer:\n    needs:\n      - settings\n",
                "  windows-producer:\n    needs:\n      - settings\n      - windows-verifier\n")),
            ("handoff-start-order", self._replace(
                caller, "  linux-fetch-encrypt:\n    needs:\n      - settings\n",
                "  linux-fetch-encrypt:\n    needs:\n      - settings\n      - windows-producer\n")),
            ("attester-order", self._replace(
                caller, "      - settings\n      - linux-fetch-encrypt\n", "      - settings\n")),
            ("role-fixed-input", self._replace(caller, "      profile: candidate\n", "      profile: probe\n", 1)),
            ("role-fixed-input", self._replace(caller, "      role: producer\n", "      role: verifier\n")),
            ("role-call-cardinality", self._replace(
                caller, "    uses: ./" + FETCH_PATH + "\n", "    uses: ./" + ATTESTER_PATH + "\n")),
            ("action-pin-invalid", append("    uses: actions/checkout@v4\n")),
        ):
            with self.subTest(code=code):
                self.assertEqual(self._code(mutate), code)

    def test_role_workflow_failures_use_the_closed_codes(self):
        receiver_text = "    runs-on: windows-2025\n"
        attest = "      - name: sign\n        uses: actions/attest@" + "a" * 40
        for code, mutate in (
            ("role-trigger-shape", self._replace(ATTESTER_PATH, "workflow_call:", "workflow_calls:")),
            ("role-input-schema", self._replace(
                ATTESTER_PATH, "      mode:\n        required: false\n", "      mode:\n        required: true\n")),
            ("role-input-schema", self._replace(RECEIVER_PATH, "      role:\n", "      kind:\n")),
            ("role-input-schema", self._replace(FETCH_PATH, "      fingerprint:\n", "      fingerprints:\n")),
            ("role-sign-step-cardinality", self._replace(ATTESTER_PATH, attest, attest + "\n" + attest)),
            ("role-job-cardinality", self._replace(
                RECEIVER_PATH, "jobs:\n", "jobs:\n  second:\n    runs-on: windows-2025\n")),
            ("role-runner", self._replace(RECEIVER_PATH, receiver_text, "    runs-on: ubuntu-24.04\n")),
            ("role-matrix", self._replace(FETCH_PATH, "    permissions:\n", "    strategy:\n    permissions:\n")),
            ("role-nested-call", self._replace(
                ATTESTER_PATH, "    steps:\n", "    uses: ./.github/workflows/other.yml\n    steps:\n")),
            ("role-source-path", self._replace(FETCH_PATH, subject.FETCH_ENVIRONMENT_LINE + "\n", "")),
            ("role-source-path", self._replace(
                RECEIVER_PATH, "windows-source-exec", "linux-source-read")),
            ("role-source-path", self._replace(ATTESTER_PATH, "    steps:\n", "    secrets: inherit\n    steps:\n")),
            ("role-masked-failure", self._replace(
                ATTESTER_PATH, "    steps:\n", "    continue-on-error: true\n    steps:\n")),
            ("role-permissions", self._replace(
                FETCH_PATH, "      id-token: write\n", "      id-token: write\n      contents: write\n")),
            ("action-pin-invalid", self._replace(RECEIVER_PATH, "@" + "a" * 40, "@v4")),
            ("role-fixed-input", self._replace(ATTESTER_PATH, "inputs.profile == 'candidate'", "true")),
        ):
            with self.subTest(code=code):
                self.assertEqual(self._code(mutate), code)

    def test_missing_workflow_files_are_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary:
            files = candidate_tree_files()
            del files[ATTESTER_PATH]
            write_tree(temporary, files)
            with self.assertRaisesRegex(subject.Refusal, "role-workflow-unavailable"):
                subject.validate_workflow_graph(temporary, "candidate")

    def test_candidate_call_graph_accepts_two_receiver_calls_and_the_windows_job_id(self):
        sites = []
        for role in subject.CANDIDATE_ROLES:
            sites.append({"role": role, "uses": subject.ROLE_PATHS[role], "profile": "candidate",
                          "matrix": False, "dynamic": False, "condition": "mode-bound"})
        callees = [
            {"role": role, "path": subject.ROLE_PATHS[role],
             "jobs": ["windows-candidate" if role.startswith("windows-") else role],
             "sign_steps": ["attest-role-statement"], "nested_calls": [], "matrix": False, "dynamic": False}
            for role in subject.CANDIDATE_ROLES
        ]
        graph = {"caller": {"path": subject.CALLER_PROFILES["candidate"]["path"], "ref": CANDIDATE_REF_UNTRUSTED,
                            "source_access": False, "call_sites": sites}, "roles": callees}
        self.assertTrue(subject.validate_call_graph(graph, "candidate"))
        wrong = copy.deepcopy(graph)
        wrong["roles"][0]["jobs"] = ["windows-producer"]
        with self.assertRaisesRegex(subject.Refusal, "callee-job-or-sign-step"):
            subject.validate_call_graph(wrong, "candidate")
        wrong = copy.deepcopy(graph)
        wrong["caller"]["ref"] = "refs/heads/develop"
        with self.assertRaisesRegex(subject.Refusal, "call-graph-profile"):
            subject.validate_call_graph(wrong, "candidate")


class CandidateEvidenceTests(unittest.TestCase):
    def test_the_full_artifact_set_verifies_and_exposes_the_producer_record(self):
        for ref in (REF, CANDIDATE_REF_UNTRUSTED):
            with self.subTest(ref=ref), tempfile.TemporaryDirectory() as temporary:
                world = CandidateWorld(ref)
                world.write_evidence(temporary)
                result = subject.validate_role_artifact_set(
                    "candidate", REPOSITORY, ref, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, 8150001, 99101,
                    world.artifact_map(), temporary,
                    subject.resolve_certificate_pins("candidate", CONTROL_SHA))
                self.assertEqual(result["record"], world.producer_record)
                self.assertEqual(set(result["subject_digests"]), set(subject.CANDIDATE_ROLES))
                self.assertEqual(len(set(result["subject_digests"].values())), 4)

    def test_wrong_ref_binding_and_foreign_statements_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            world = CandidateWorld(REF)
            world.write_evidence(temporary)
            pins = subject.resolve_certificate_pins("candidate", CONTROL_SHA)
            with self.assertRaises(subject.Refusal):
                subject.validate_role_artifact_set(
                    "candidate", REPOSITORY, CANDIDATE_REF_UNTRUSTED, CONTROL_SHA, RUN_ID, RUN_ATTEMPT,
                    8150001, 99101, world.artifact_map(), temporary, pins)
            with self.assertRaisesRegex(subject.Refusal, "role-artifact-map"):
                subject.validate_role_artifact_set(
                    "candidate", REPOSITORY, REF, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, 8150001, 99101,
                    world.artifact_map(subject.CANDIDATE_ROLES[:3]), temporary, pins)

    def test_the_attester_needs_the_linux_statement_before_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            world = CandidateWorld(REF)
            world.write_evidence(temporary)
            pins = subject.resolve_certificate_pins("candidate", CONTROL_SHA)
            roles = ("windows-producer", "windows-verifier", "capsule-attester")
            with self.assertRaisesRegex(subject.Refusal, "linux-statement-missing"):
                subject.validate_role_artifact_set(
                    "candidate", REPOSITORY, REF, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, 8150001, 99101,
                    world.artifact_map(roles), temporary, pins, roles)

    def test_the_linux_subject_must_name_both_key_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            world = CandidateWorld(REF)
            other = candidate_record()
            document = binding_document(
                world.producer_record, other, world.capsules["producer"], world.capsules["verifier"])
            linux = subject.canonical_json_subject(document)
            name = world.names["linux-fetch-encrypt"]
            world.statement_files[name]["subject.bin"] = linux
            record, unused = world.subjects["linux-fetch-encrypt"]
            files, verified, bundle = candidate_signed_files("linux-fetch-encrypt", record, linux, REF)
            world.statement_files[name] = files
            world.verified[name] = verified
            row = next(item for item in world.rows if item["name"] == name)
            archive = zip_bytes(files)
            world.zips[row["id"]] = archive
            row.update(artifact_row(row["id"], name, archive))
            world.write_evidence(temporary)
            with self.assertRaisesRegex(subject.Refusal, "binding-key-record-mismatch"):
                subject.validate_role_artifact_set(
                    "candidate", REPOSITORY, REF, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, 8150001, 99101,
                    world.artifact_map(subject.CANDIDATE_ROLES[:3]), temporary,
                    subject.resolve_certificate_pins("candidate", CONTROL_SHA), subject.CANDIDATE_ROLES[:3])

    def test_artifact_inventory_binds_linux_and_attester_to_the_producer_transfer(self):
        world = CandidateWorld(REF)
        snapshot = fixture_artifact_snapshot([row for row in world.rows if row["name"].startswith("role-statement-")])
        result = subject.validate_artifact_inventory(
            snapshot, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, subject.CANDIDATE_ROLES, "candidate")
        self.assertEqual(set(result), set(subject.CANDIDATE_ROLES))
        self.assertEqual(
            result["linux-fetch-encrypt"][0]["transfer_id"], result["windows-producer"][0]["transfer_id"])
        self.assertNotEqual(
            result["windows-verifier"][0]["transfer_id"], result["windows-producer"][0]["transfer_id"])
        changed = copy.deepcopy(snapshot)
        for row in changed["pages"][0]["artifacts"]:
            if "linux-fetch-encrypt" in row["name"]:
                row["name"] = row["name"][:-1] + ("d" if row["name"].endswith("c") else "c")
        with self.assertRaisesRegex(subject.Refusal, "artifact-transfer-mismatch"):
            subject.validate_artifact_inventory(
                changed, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, subject.CANDIDATE_ROLES, "candidate")
        with self.assertRaisesRegex(subject.Refusal, "artifact-role-cardinality"):
            subject.validate_artifact_inventory(
                snapshot, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, subject.ROLE_ORDER, "probe")

    def test_jobs_snapshot_uses_the_four_candidate_job_names(self):
        rows = []
        api_root = "https:" + chr(47) * 2 + "api.github.com/repos/" + REPOSITORY
        for index, role in enumerate(subject.CANDIDATE_ROLES, 1):
            rows.append({
                "id": 1000 + index, "run_id": int(RUN_ID), "run_attempt": int(RUN_ATTEMPT),
                "name": subject.API_JOB_NAME_PINS["candidate"][role], "head_sha": CONTROL_SHA,
                "status": "completed", "conclusion": "success", "runner_name": "runner %d" % index,
                "labels": [subject.ROLE_RUNNERS[role]], "check_run_url": api_root + "/check-runs/" + str(2000 + index),
                "steps": [{"number": 1, "name": "x", "status": "completed", "conclusion": "success"}],
            })
        snapshot = fixture_job_snapshot(rows)
        result = subject.validate_jobs_snapshot(
            snapshot, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, subject.API_JOB_NAME_PINS["candidate"],
            subject.CANDIDATE_ROLES)
        self.assertEqual(set(result), set(subject.CANDIDATE_ROLES))
        with self.assertRaisesRegex(subject.Refusal, "api-job-map-unresolved"):
            subject.validate_jobs_snapshot(
                snapshot, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, subject.API_JOB_NAME_PINS["candidate"])

    def test_provider_listing_separates_the_two_receiver_statements(self):
        with tempfile.TemporaryDirectory() as temporary:
            world = CandidateWorld(REF)
            world.write_evidence(temporary)
            result = subject.validate_role_artifact_set(
                "candidate", REPOSITORY, REF, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, 8150001, 99101,
                world.artifact_map(), temporary, subject.resolve_certificate_pins("candidate", CONTROL_SHA))
            providers = {}
            for role in subject.CANDIDATE_ROLES:
                digest = result["subject_digests"][role]
                providers[digest] = {
                    "snapshot": fixture_provider_snapshot(digest, [{"bundle": world.bundles[role]}]),
                    "verified": [world.verified[world.names[role]]],
                }
            records = subject.reconcile_provider_evidence(
                result, providers, RUN_ID, RUN_ATTEMPT, CONTROL_SHA, subject.CANDIDATE_ROLES)
            self.assertEqual({item["role"] for item in records}, set(subject.CANDIDATE_ROLES))

    def test_the_whole_snapshot_verifies_for_both_refs(self):
        for ref in (REF, CANDIDATE_REF_UNTRUSTED):
            with self.subTest(ref=ref), tempfile.TemporaryDirectory() as temporary:
                world = CandidateWorld(ref)
                world.write_evidence(Path(temporary) / "artifacts")
                directory = install_control_tree(temporary, "candidate")
                rows = []
                api_root = "https:" + chr(47) * 2 + "api.github.com/repos/" + REPOSITORY
                for index, role in enumerate(subject.CANDIDATE_ROLES, 1):
                    rows.append({
                        "id": 1000 + index, "run_id": int(RUN_ID), "run_attempt": int(RUN_ATTEMPT),
                        "name": subject.API_JOB_NAME_PINS["candidate"][role], "head_sha": CONTROL_SHA,
                        "status": "completed", "conclusion": "success", "runner_name": "runner %d" % index,
                        "labels": [subject.ROLE_RUNNERS[role]],
                        "check_run_url": api_root + "/check-runs/" + str(2000 + index),
                        "steps": [{"number": 1, "name": "x", "status": "completed", "conclusion": "success"}],
                    })
                artifact_rows = [row for row in world.rows if row["name"].startswith("role-statement-")]
                result = subject.validate_role_artifact_set(
                    "candidate", REPOSITORY, ref, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, 8150001, 99101,
                    world.artifact_map(), Path(temporary) / "artifacts",
                    subject.resolve_certificate_pins("candidate", CONTROL_SHA))
                providers = {}
                for role in subject.CANDIDATE_ROLES:
                    digest = result["subject_digests"][role]
                    providers[digest] = {
                        "snapshot": fixture_provider_snapshot(digest, [{"bundle": world.bundles[role]}]),
                        "verified": [world.verified[world.names[role]]],
                    }
                branch = ref[len("refs/heads/"):]
                evidence = subject.verify_source_free_evidence(
                    "candidate", REPOSITORY, ref, CONTROL_SHA, RUN_ID, RUN_ATTEMPT,
                    {"id": 8150001, "full_name": REPOSITORY, "owner_id": 99101, "visibility": "public"},
                    {"id": int(RUN_ID), "run_attempt": int(RUN_ATTEMPT), "head_sha": CONTROL_SHA,
                     "path": subject.CALLER_PROFILES["candidate"]["path"], "event": "workflow_dispatch",
                     "head_branch": branch, "repository": {"id": 8150001, "full_name": REPOSITORY},
                     "status": "in_progress", "conclusion": None},
                    fixture_job_snapshot(rows), fixture_artifact_snapshot(artifact_rows), providers,
                    directory, temporary, subject.API_JOB_NAME_PINS["candidate"],
                    subject.resolve_certificate_pins("candidate", CONTROL_SHA))
                self.assertEqual(evidence["record"], world.producer_record)


class CandidatePrepareTests(unittest.TestCase):
    def _run(self, directory, role, ref=REF, profile="candidate", extra=None, runner=None):
        output = Path(directory) / ("out-" + role + "-" + profile)
        windows = role.startswith("windows-")
        command = [
            "prepare", "--profile", profile, "--role", role, "--repository", REPOSITORY,
            "--repository-id", "8150001", "--control-sha", CONTROL_SHA, "--ref", ref,
            "--run-id", RUN_ID, "--run-attempt", RUN_ATTEMPT,
            "--workflow-ref", REPOSITORY + "/" + subject.CALLER_PROFILES[profile]["path"] + "@" + ref,
            "--runner", runner or ("windows-2025" if windows else "ubuntu-24.04"),
            "--output-directory", str(output),
        ]
        for name, value in (extra or {}).items():
            command += ["--" + name, str(value)]
        captured = io.StringIO()
        marker = Path(directory) / ("github-output-" + role)
        if marker.exists():
            marker.unlink()
        with mock.patch.dict("os.environ", {"GITHUB_OUTPUT": str(marker)}):
            with contextlib.redirect_stdout(captured):
                code = subject.main(command)
        transfer = None
        if marker.exists():
            transfer = marker.read_text(encoding="ascii").strip().split("=", 1)[1]
        return code, captured.getvalue(), output, transfer

    def _files(self, directory, ref=REF):
        root = Path(directory)
        (root / "point.bin").write_bytes(GENERATOR_POINT)
        code, unused, producer_out, producer_transfer = self._run(
            directory, "windows-producer", ref, extra={"public-point-file": root / "point.bin"})
        self.assertEqual(code, 0)
        verifier_directory = root / "verifier"
        verifier_directory.mkdir()
        code, unused, verifier_out, verifier_transfer = self._run(
            verifier_directory, "windows-verifier", ref, extra={"public-point-file": root / "point.bin"})
        self.assertEqual(code, 0)
        (root / "producer.bin").write_bytes((producer_out / "subject.bin").read_bytes())
        (root / "verifier.bin").write_bytes((verifier_out / "subject.bin").read_bytes())
        (root / "capsule-producer.bin").write_bytes(b"producer-capsule")
        (root / "capsule-verifier.bin").write_bytes(b"verifier-capsule")
        return producer_transfer, verifier_transfer

    def _linux_extra(self, root):
        return {
            "receiver-record": root / "producer.bin", "verifier-record": root / "verifier.bin",
            "capsule-producer": root / "capsule-producer.bin", "capsule-verifier": root / "capsule-verifier.bin",
            "source-sha": "1" * 40, "tree-id": "2" * 40, "lock-sha256": "3" * 64, "manifest-sha256": "4" * 64,
        }

    def test_each_candidate_role_prepares_its_exact_subject_on_the_synthetic_ref(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            producer_transfer, verifier_transfer = self._files(temporary)
            self.assertNotEqual(producer_transfer, verifier_transfer)
            record = (root / "producer.bin").read_bytes()
            self.assertEqual(len(record), subject.KEY_RECORD_SIZE)
            self.assertEqual(record[100:165], GENERATOR_POINT)
            self.assertEqual(record[52:68].hex(), producer_transfer)
            code, text, linux_out, linux_transfer = self._run(temporary, "linux-fetch-encrypt", extra=self._linux_extra(root))
            self.assertEqual(code, 0, text)
            self.assertEqual(linux_transfer, producer_transfer)
            linux_subject = (linux_out / "subject.bin").read_bytes()
            document = subject.parse_binding_subject(linux_subject)
            self.assertEqual(document["capsule_producer_sha256"], hashlib.sha256(b"producer-capsule").hexdigest())
            self.assertEqual(document["key_record_verifier_sha256"], hashlib.sha256((root / "verifier.bin").read_bytes()).hexdigest())
            predicate = json.loads((linux_out / "predicate.json").read_text(encoding="ascii"))
            self.assertEqual(predicate["role"], "linux-fetch-encrypt")
            self.assertEqual(predicate["transferId"], producer_transfer)
            (root / "linux-subject.bin").write_bytes(linux_subject)
            extra = self._linux_extra(root)
            for name in ("source-sha", "tree-id", "lock-sha256", "manifest-sha256"):
                del extra[name]
            extra["linux-subject"] = root / "linux-subject.bin"
            code, text, attester_out, attester_transfer = self._run(temporary, "capsule-attester", extra=extra)
            self.assertEqual(code, 0, text)
            self.assertEqual(attester_transfer, producer_transfer)
            self.assertEqual((attester_out / "subject.bin").read_bytes(), subject.build_attested_subject(linux_subject))

    def test_the_source_ref_requires_a_matching_revocation_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._files(temporary, CANDIDATE_REF_UNTRUSTED)
            extra = self._linux_extra(root)
            code, text, unused, unused_transfer = self._run(
                temporary, "linux-fetch-encrypt", CANDIDATE_REF_UNTRUSTED, extra=extra)
            self.assertEqual(code, 1)
            self.assertIn("reason=prepare-flag-missing", text)
            receipt = root / "revocation.json"
            receipt.write_text(json.dumps({
                "schema_version": 1, "status": "confirmed", "control_sha": CONTROL_SHA, "run_id": RUN_ID,
                "run_attempt": RUN_ATTEMPT, "installation_id": "7", "rejected_after_revoke": True}), encoding="ascii")
            extra["revocation-receipt"] = receipt
            code, text, unused, unused_transfer = self._run(
                temporary, "linux-fetch-encrypt", CANDIDATE_REF_UNTRUSTED, extra=extra)
            self.assertEqual(code, 0, text)
            receipt.write_text(json.dumps({"status": "unconfirmed"}), encoding="ascii")
            code, text, unused, unused_transfer = self._run(
                temporary, "linux-fetch-encrypt", CANDIDATE_REF_UNTRUSTED, extra=extra)
            self.assertEqual(code, 1)
            self.assertIn("reason=revocation-receipt-invalid", text)

    def test_the_synthetic_ref_refuses_a_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._files(temporary)
            extra = self._linux_extra(root)
            extra["revocation-receipt"] = root / "producer.bin"
            code, text, unused, unused_transfer = self._run(temporary, "linux-fetch-encrypt", extra=extra)
            self.assertEqual(code, 1)
            self.assertIn("reason=prepare-flag-foreign", text)

    def test_flags_that_do_not_belong_to_the_role_or_profile_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._files(temporary)
            point = root / "point.bin"
            for role, extra, reason in (
                ("windows-producer", {"public-point-file": point, "source-sha": "1" * 40}, "prepare-flag-foreign"),
                ("windows-verifier", {}, "prepare-flag-missing"),
                ("windows-producer", {"public-point-file": point, "receiver-record": root / "producer.bin"},
                 "prepare-flag-foreign"),
            ):
                with self.subTest(role=role, reason=reason):
                    code, text, unused, unused_transfer = self._run(temporary, role, extra=extra)
                    self.assertEqual(code, 1)
                    self.assertIn("reason=" + reason, text)
            extra = self._linux_extra(root)
            del extra["tree-id"]
            code, text, unused, unused_transfer = self._run(temporary, "linux-fetch-encrypt", extra=extra)
            self.assertEqual((code, "reason=prepare-flag-missing" in text), (1, True))
            extra = self._linux_extra(root)
            extra["linux-subject"] = root / "producer.bin"
            code, text, unused, unused_transfer = self._run(temporary, "linux-fetch-encrypt", extra=extra)
            self.assertIn("reason=prepare-flag-foreign", text)
            code, text, unused, unused_transfer = self._run(
                temporary, "windows-receiver", profile="probe", runner="windows-2025", extra={"public-point-file": point})
            self.assertEqual(code, 1)
            self.assertIn("reason=prepare-flag-profile", text)
            code, text, unused, unused_transfer = self._run(
                temporary, "windows-receiver", profile="candidate", runner="windows-2025")
            self.assertIn("reason=prepare-profile-role", text)
            code, text, unused, unused_transfer = self._run(
                temporary, "windows-producer", runner="ubuntu-24.04", extra={"public-point-file": point})
            self.assertIn("reason=prepare-runner", text)

    def test_the_attester_refuses_digests_that_differ_from_the_linux_subject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._files(temporary)
            code, text, linux_out, unused = self._run(temporary, "linux-fetch-encrypt", extra=self._linux_extra(root))
            self.assertEqual(code, 0, text)
            (root / "linux-subject.bin").write_bytes((linux_out / "subject.bin").read_bytes())
            base = {
                "receiver-record": root / "producer.bin", "verifier-record": root / "verifier.bin",
                "capsule-producer": root / "capsule-producer.bin", "capsule-verifier": root / "capsule-verifier.bin",
                "linux-subject": root / "linux-subject.bin",
            }
            (root / "other-capsule.bin").write_bytes(b"other")
            for name, replacement in (
                ("capsule-producer", root / "other-capsule.bin"),
                ("capsule-verifier", root / "other-capsule.bin"),
                ("receiver-record", root / "verifier.bin"),
            ):
                with self.subTest(name=name):
                    extra = dict(base)
                    extra[name] = replacement
                    code, text, unused, unused_transfer = self._run(temporary, "capsule-attester", extra=extra)
                    self.assertEqual(code, 1)
                    self.assertRegex(text, "reason=(binding-mismatch|receiver-records-identical)")
            code, text, unused, unused_transfer = self._run(temporary, "capsule-attester", extra=dict(base))
            self.assertEqual(code, 0, text)

    def test_a_non_curve_public_point_file_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            bad = Path(temporary) / "bad.bin"
            bad.write_bytes(b"\x04" + bytes(64))
            code, text, unused, unused_transfer = self._run(
                temporary, "windows-producer", extra={"public-point-file": bad})
            self.assertEqual(code, 1)
            self.assertIn("reason=public-point-curve", text)

    def test_legacy_prepare_outputs_keep_their_layout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code, text, receiver_out, transfer = self._run(temporary, "windows-receiver", profile="probe",
                                                           runner="windows-2025")
            self.assertEqual(code, 0, text)
            record = (receiver_out / "subject.bin").read_bytes()
            self.assertEqual(len(record), subject.KEY_RECORD_SIZE)
            self.assertEqual(record[100:165], subject.P256_GENERATOR)
            self.assertEqual(record[52:68].hex(), transfer)
            (root / "receiver.bin").write_bytes(record)
            code, text, linux_out, linux_transfer = self._run(
                temporary, "linux-fetch-encrypt", profile="probe",
                extra={"receiver-record": root / "receiver.bin"})
            self.assertEqual(code, 0, text)
            self.assertEqual((linux_out / "subject.bin").read_bytes(), subject.make_synthetic_capsule(record))
            self.assertEqual(linux_transfer, transfer)
            predicate = json.loads((linux_out / "predicate.json").read_text(encoding="ascii"))
            self.assertEqual(predicate["profile"], "probe")
            self.assertEqual(predicate["controlRef"], REF)
            self.assertIn("subject=created role=linux-fetch-encrypt bytes=%d sha256=" % subject.CAPSULE_SIZE, text)


class ReceiveCapsuleTests(unittest.TestCase):
    def _arguments(self, directory, role="windows-producer", ref=REF, seconds=30):
        return types.SimpleNamespace(
            profile="candidate", role=role, repository=REPOSITORY, repository_id="8150001",
            control_sha=CONTROL_SHA, ref=ref, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            deadline_seconds=seconds, output_directory=str(Path(directory) / "capsule"),
        )

    def _receive(self, world, directory, role="windows-producer", ref=REF, gh=None, seconds=30):
        ticks = [0]

        def clock():
            ticks[0] += 10
            return ticks[0]

        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            subject.receive_capsule(
                self._arguments(directory, role, ref, seconds), gh=world.gh() if gh is None else gh,
                sleep=lambda seconds_: None, clock=clock)
        return captured.getvalue()

    def test_both_receivers_obtain_their_own_capsule_and_the_bound_values(self):
        with mock.patch.object(subject, "DESIGN_CAPSULE_SIZE", CAPSULE_TEST_SIZE):
            for ref in (REF, CANDIDATE_REF_UNTRUSTED):
                for short in ("producer", "verifier"):
                    with self.subTest(ref=ref, short=short), tempfile.TemporaryDirectory() as temporary:
                        world = CandidateWorld(ref)
                        calls = []
                        text = self._receive(world, temporary, "windows-" + short, ref, gh=world.gh(calls=calls))
                        digest = hashlib.sha256(world.capsules[short]).hexdigest()
                        self.assertEqual(text, "capsule=received role=windows-%s sha256=%s\n" % (short, digest))
                        output = Path(temporary) / "capsule"
                        self.assertEqual(sorted(item.name for item in output.iterdir()), ["bound.json", "capsule.bin"])
                        self.assertEqual((output / "capsule.bin").read_bytes(), world.capsules[short])
                        bound = json.loads((output / "bound.json").read_text(encoding="ascii"))
                        self.assertEqual(bound, {
                            "capsule_sha256": digest, "source_sha": "1" * 40, "tree_id": "2" * 40,
                            "lock_sha256": "3" * 64, "manifest_sha256": "4" * 64, "revocation": "confirmed"})
                        verifies = [call for call in calls if call[:2] == ["attestation", "verify"]]
                        self.assertEqual(len(verifies), 4)
                        for call in verifies:
                            self.assertIn("--deny-self-hosted-runners", call)
                            self.assertIn(subject.PREDICATE_TYPE, call)
                        self.assertEqual(
                            sorted(item for item in os.listdir(temporary)), ["capsule"])

    def test_a_missing_statement_artifact_runs_to_the_deadline(self):
        with mock.patch.object(subject, "DESIGN_CAPSULE_SIZE", CAPSULE_TEST_SIZE):
            with tempfile.TemporaryDirectory() as temporary:
                world = CandidateWorld()
                rows = [row for row in world.rows if "capsule-attester" not in row["name"]]
                with self.assertRaisesRegex(subject.Refusal, "receive-deadline"):
                    self._receive(world, temporary, gh=world.gh(rows=rows))
                self.assertFalse((Path(temporary) / "capsule").exists())
            with tempfile.TemporaryDirectory() as temporary:
                world = CandidateWorld()
                rows = [row for row in world.rows if not row["name"].startswith("source-capsule-producer")]
                with self.assertRaisesRegex(subject.Refusal, "receive-deadline"):
                    self._receive(world, temporary, gh=world.gh(rows=rows))

    def test_a_capsule_that_differs_from_the_bound_digest_is_refused_and_removed(self):
        with mock.patch.object(subject, "DESIGN_CAPSULE_SIZE", CAPSULE_TEST_SIZE):
            with tempfile.TemporaryDirectory() as temporary:
                world = CandidateWorld()
                world.set_capsule("producer", zip_bytes({"capsule.bin": b"X" * CAPSULE_TEST_SIZE}))
                with self.assertRaisesRegex(subject.Refusal, "receive-capsule-digest"):
                    self._receive(world, temporary)
                self.assertFalse((Path(temporary) / "capsule").exists())

    def test_a_capsule_of_the_wrong_length_or_with_extra_members_is_refused(self):
        with mock.patch.object(subject, "DESIGN_CAPSULE_SIZE", CAPSULE_TEST_SIZE):
            for label, archive, code in (
                ("short", zip_bytes({"capsule.bin": b"P" * (CAPSULE_TEST_SIZE - 1)}), "receive-capsule-length"),
                ("long", zip_bytes({"capsule.bin": b"P" * (CAPSULE_TEST_SIZE + 1)}), "receive-capsule-length"),
                ("extra", zip_bytes({"capsule.bin": b"P" * CAPSULE_TEST_SIZE, "extra.txt": b"x"}),
                 "receive-capsule-members"),
                ("renamed", zip_bytes({"other.bin": b"P" * CAPSULE_TEST_SIZE}), "receive-capsule-members"),
            ):
                with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                    world = CandidateWorld()
                    world.set_capsule("producer", archive)
                    with self.assertRaisesRegex(subject.Refusal, code):
                        self._receive(world, temporary)
                    self.assertFalse((Path(temporary) / "capsule").exists())

    def test_a_capsule_artifact_of_the_wrong_size_class_is_refused(self):
        with mock.patch.object(subject, "DESIGN_CAPSULE_SIZE", CAPSULE_TEST_SIZE):
            with tempfile.TemporaryDirectory() as temporary:
                world = CandidateWorld()
                world.set_capsule("producer", zip_bytes({"capsule.bin": b"P" * 100}))
                with self.assertRaisesRegex(subject.Refusal, "receive-capsule-size"):
                    self._receive(world, temporary)

    def test_a_revocation_that_is_not_confirmed_is_refused(self):
        with mock.patch.object(subject, "DESIGN_CAPSULE_SIZE", CAPSULE_TEST_SIZE):
            with tempfile.TemporaryDirectory() as temporary:
                world = CandidateWorld(revocation="unconfirmed")
                with self.assertRaisesRegex(subject.Refusal, "binding-revocation"):
                    self._receive(world, temporary)
                self.assertFalse((Path(temporary) / "capsule").exists())

    def test_a_linux_statement_signed_for_another_role_is_refused(self):
        with mock.patch.object(subject, "DESIGN_CAPSULE_SIZE", CAPSULE_TEST_SIZE):
            with tempfile.TemporaryDirectory() as temporary:
                world = CandidateWorld()
                linux = next(row for row in world.rows if "linux-fetch-encrypt" in row["name"])
                attester = next(row for row in world.rows if "capsule-attester" in row["name"])
                world.zips[linux["id"]] = world.zips[attester["id"]]
                linux.update(artifact_row(linux["id"], linux["name"], world.zips[linux["id"]]))
                with self.assertRaises(subject.Refusal):
                    self._receive(world, temporary)
                self.assertFalse((Path(temporary) / "capsule").exists())

    def test_attestation_and_download_failures_fail_closed(self):
        with mock.patch.object(subject, "DESIGN_CAPSULE_SIZE", CAPSULE_TEST_SIZE):
            with tempfile.TemporaryDirectory() as temporary:
                world = CandidateWorld()
                with self.assertRaisesRegex(subject.Refusal, "receive-attestation-verify"):
                    self._receive(world, temporary, gh=world.gh(attestation=False))
                self.assertFalse((Path(temporary) / "capsule").exists())
            with tempfile.TemporaryDirectory() as temporary:
                world = CandidateWorld()
                world.zips.pop(3101)
                with self.assertRaisesRegex(subject.Refusal, "receive-download-failed"):
                    self._receive(world, temporary)

    def test_arguments_and_the_output_directory_are_checked_first(self):
        with tempfile.TemporaryDirectory() as temporary:
            world = CandidateWorld()
            for field, value, code in (
                ("profile", "probe", "receive-profile-role"),
                ("role", "windows-receiver", "receive-profile-role"),
                ("ref", "refs/heads/develop", "receive-ref"),
                ("repository", "other/repo", "control-repository"),
                ("deadline_seconds", 0, "receive-deadline-range"),
                ("deadline_seconds", 3601, "receive-deadline-range"),
            ):
                with self.subTest(field=field, value=value):
                    arguments = self._arguments(temporary)
                    setattr(arguments, field, value)
                    with self.assertRaisesRegex(subject.Refusal, code):
                        subject.receive_capsule(arguments, gh=world.gh(), sleep=lambda unused: None)
            occupied = Path(temporary) / "capsule"
            occupied.mkdir()
            (occupied / "stale").write_bytes(b"x")
            with self.assertRaisesRegex(subject.Refusal, "receive-output"):
                subject.receive_capsule(self._arguments(temporary), gh=world.gh(), sleep=lambda unused: None)
            self.assertTrue((occupied / "stale").exists())

    def test_the_command_line_accepts_the_workflow_flags(self):
        parsed = subject.build_parser().parse_args([
            "receive-capsule", "--profile", "candidate", "--role", "windows-verifier", "--repository", REPOSITORY,
            "--repository-id", "8150001", "--control-sha", CONTROL_SHA, "--ref", REF, "--run-id", RUN_ID,
            "--run-attempt", RUN_ATTEMPT, "--deadline-seconds", "1500", "--output-directory", "capsule",
        ])
        self.assertEqual((parsed.role, parsed.deadline_seconds), ("windows-verifier", 1500))
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            subject.build_parser().parse_args([
                "receive-capsule", "--profile", "candidate", "--role", "windows-receiver", "--repository", REPOSITORY,
                "--repository-id", "1", "--control-sha", CONTROL_SHA, "--ref", REF, "--run-id", "1",
                "--run-attempt", "1", "--deadline-seconds", "1", "--output-directory", "x"])


class CandidateFixedPinTests(unittest.TestCase):
    LOGS = {
        "sections": {
            "revoke-source-token": "linux-source-token=revoked rejection=verified receipt=positive\n",
            "verify-token-rejection": "handoff-revocation=confirmed\n",
        },
        "other": [""],
    }

    def _jobs(self, revoke=12, verify=13):
        api_root = "https:" + chr(47) * 2 + "api.github.com/repos/" + REPOSITORY
        rows = []
        for index, role in enumerate(subject.CANDIDATE_ROLES, 1):
            steps = [{"number": 1, "name": "x", "status": "completed", "conclusion": "success"}]
            if role == "linux-fetch-encrypt":
                steps += [
                    {"number": revoke, "name": "handoff-revoke-source-token-v1", "status": "completed",
                     "conclusion": "success"},
                    {"number": verify, "name": "handoff-verify-token-rejection-v1", "status": "completed",
                     "conclusion": "success"},
                ]
            rows.append({
                "id": 1000 + index, "run_id": int(RUN_ID), "run_attempt": int(RUN_ATTEMPT),
                "name": subject.API_JOB_NAME_PINS["candidate"][role], "head_sha": CONTROL_SHA,
                "status": "completed", "conclusion": "success", "runner_name": "runner %d" % index,
                "labels": [subject.ROLE_RUNNERS[role]],
                "check_run_url": api_root + "/check-runs/" + str(2000 + index), "steps": steps,
            })
        return fixture_job_snapshot(rows)

    def _write_logs(self, directory, document=None):
        path = Path(directory) / "linux-logs.json"
        path.write_text(json.dumps(self.LOGS if document is None else document), encoding="ascii")
        return str(path)

    def test_the_fixed_ordinals_and_names_are_twelve_and_thirteen(self):
        self.assertEqual(subject.API_LINUX_STEP_ORDINAL_PINS["candidate"],
                         {"revoke-source-token": 12, "verify-token-rejection": 13})

    def test_verify_snapshot_check_accepts_the_pinned_ordinals_and_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            job = subject.check_fixed_linux_evidence(
                "candidate", self._jobs(), RUN_ID, RUN_ATTEMPT, CONTROL_SHA, self._write_logs(temporary))
            self.assertEqual(job["conclusion"], "success")

    def test_verify_snapshot_check_refuses_a_wrong_ordinal_missing_or_malformed_logs_and_other_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            logs = self._write_logs(temporary)
            for revoke, verify in ((5, 6), (12, 14), (13, 12)):
                with self.subTest(revoke=revoke, verify=verify):
                    with self.assertRaises(subject.Refusal):
                        subject.check_fixed_linux_evidence(
                            "candidate", self._jobs(revoke, verify), RUN_ID, RUN_ATTEMPT, CONTROL_SHA, logs)
            for missing in (None, ""):
                with self.subTest(missing=missing):
                    with self.assertRaisesRegex(subject.Refusal, "linux-logs-missing"):
                        subject.check_fixed_linux_evidence(
                            "candidate", self._jobs(), RUN_ID, RUN_ATTEMPT, CONTROL_SHA, missing)
            for bad in ({"sections": {}}, [], {"sections": {}, "other": [], "extra": 1}):
                with self.subTest(bad=bad):
                    with self.assertRaisesRegex(subject.Refusal, "linux-logs-shape"):
                        subject.check_fixed_linux_evidence(
                            "candidate", self._jobs(), RUN_ID, RUN_ATTEMPT, CONTROL_SHA,
                            self._write_logs(temporary, bad))
            doubled = {"sections": dict(self.LOGS["sections"]), "other": [""]}
            doubled["sections"]["verify-token-rejection"] = "handoff-revocation=confirmed\n" * 2
            with self.assertRaises(subject.Refusal):
                subject.check_fixed_linux_evidence(
                    "candidate", self._jobs(), RUN_ID, RUN_ATTEMPT, CONTROL_SHA, self._write_logs(temporary, doubled))
            for profile in ("probe", "production-synthetic"):
                with self.assertRaisesRegex(subject.Refusal, "profile-invalid"):
                    subject.check_fixed_linux_evidence(profile, self._jobs(), RUN_ID, RUN_ATTEMPT, CONTROL_SHA, logs)

    def _gate_b(self, temporary, ref, jobs, pins, ordinals, logs):
        world = CandidateWorld(ref)
        world.write_evidence(Path(temporary) / "artifacts")
        directory = install_control_tree(temporary, "candidate")
        roles = subject.CANDIDATE_ROLES[:3]
        names = {world.names[role] for role in roles}
        rows = [row for row in world.rows if row["name"] in names]
        providers = {}
        for role in roles:
            digest = hashlib.sha256(world.subjects[role][1]).hexdigest()
            providers[digest] = {
                "snapshot": fixture_provider_snapshot(digest, [{"bundle": world.bundles[role]}]),
                "verified": [world.verified[world.names[role]]],
            }
        branch = ref[len("refs/heads/"):]
        return subject.verify_transition_evidence(
            "B", "candidate", REPOSITORY, ref, CONTROL_SHA, RUN_ID, RUN_ATTEMPT,
            {"id": 8150001, "full_name": REPOSITORY, "owner_id": 99101, "visibility": "public"},
            {"id": int(RUN_ID), "run_attempt": int(RUN_ATTEMPT), "head_sha": CONTROL_SHA,
             "path": subject.CALLER_PROFILES["candidate"]["path"], "event": "workflow_dispatch",
             "head_branch": branch, "repository": {"id": 8150001, "full_name": REPOSITORY},
             "status": "in_progress", "conclusion": None},
            jobs, fixture_artifact_snapshot(rows), providers, directory, Path(temporary) / "artifacts",
            subject.API_JOB_NAME_PINS["candidate"], pins,
            subject.API_LINUX_STEP_NAME_PINS["candidate"], ordinals, logs["sections"], logs["other"])

    def test_gate_b_accepts_the_pinned_digests_and_ordinals_for_both_refs(self):
        for ref in (REF, CANDIDATE_REF_UNTRUSTED):
            with self.subTest(ref=ref), tempfile.TemporaryDirectory() as temporary:
                result = self._gate_b(
                    temporary, ref, self._jobs(), subject.resolve_certificate_pins("candidate", CONTROL_SHA),
                    subject.API_LINUX_STEP_ORDINAL_PINS["candidate"], self.LOGS)
                self.assertEqual(set(result["subject_digests"]), set(subject.CANDIDATE_ROLES[:3]))

    def test_gate_b_refuses_a_wrong_certificate_digest(self):
        pins = subject.resolve_certificate_pins("candidate", CONTROL_SHA)
        wrong = {role: dict(value, sourceRepositoryDigest="b" * 40) for role, value in pins.items()}
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(subject.Refusal, "certificate-digest-mismatch"):
                self._gate_b(temporary, CANDIDATE_REF_UNTRUSTED, self._jobs(), wrong,
                             subject.API_LINUX_STEP_ORDINAL_PINS["candidate"], self.LOGS)

    def test_gate_b_refuses_a_wrong_step_ordinal(self):
        pins = subject.resolve_certificate_pins("candidate", CONTROL_SHA)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(subject.Refusal, "linux-step-ordinal"):
                self._gate_b(temporary, CANDIDATE_REF_UNTRUSTED, self._jobs(5, 6), pins,
                             subject.API_LINUX_STEP_ORDINAL_PINS["candidate"], self.LOGS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
