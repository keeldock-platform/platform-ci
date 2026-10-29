import copy
import hashlib
import unittest

from release_provenance import (
    COMPARISON_POLICY_ID,
    MAX_STATEMENT_BYTES,
    PREDICATE_TYPE_URI,
    PROFILE_VERSION,
    PROVENANCE_DOCUMENT_ROLE,
    STATEMENT_TYPE_URI,
    VerificationRefusal,
    encode_canonical_json,
    signature_message,
    verify_statement,
)


def digest(label):
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class DeterministicFakeVerifier:
    def verify(self, message, signature):
        return signature == hashlib.sha256(b"fixture-key" + message).digest()


class ReleaseProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.release_manifest = {
            "artifacts": [
                {"name": "release-linux-amd64.deb", "sha256": digest("linux-deb")},
                {"name": "release-macos-arm64.tar.gz", "sha256": digest("macos-tar")},
            ],
            "sbom": {"name": "release.cdx.json", "sha256": digest("sbom")},
            "linuxSignatures": [
                {
                    "name": "release-linux-amd64.deb.sig.json",
                    "sha256": digest("linux-signature-envelope"),
                    "artifactName": "release-linux-amd64.deb",
                    "artifactSha256": digest("linux-deb"),
                }
            ],
        }
        self.signer = {"role": "release-role", "keyId": "release-key-test"}
        self.pins = {
            "sourcePins": [
                {"sourceId": "core-source", "revision": "a" * 40},
                {"sourceId": "host-source", "revision": "b" * 40},
            ],
            "lockDigests": {
                "cargo-lock": digest("cargo-lock"),
                "npm-lock": digest("npm-lock"),
            },
            "imageDigests": {
                "build-a-linux": digest("build-a-image"),
                "build-b-linux": digest("build-b-image"),
            },
            "toolPins": {
                "cargo": {"version": "1.99.1", "sha256": digest("cargo-tool")},
                "sbom-merger": {"version": "4.2.0", "sha256": digest("sbom-tool")},
            },
            "sbom": {
                "format": "CycloneDX",
                "schemaVersion": "1.6",
                "generatorId": "sbom-merge",
                "sha256": digest("sbom"),
            },
        }
        self.build_evidence = {
            "runId": "run-2026-10-29-01",
            "inputManifestSha256": digest("build-input-manifest"),
            "buildA": {
                "builderId": "linux-builder-a",
                "outputSetSha256": digest("build-a-output-set"),
            },
            "buildB": {
                "builderId": "linux-builder-b",
                "outputSetSha256": digest("build-b-output-set"),
            },
            "comparison": {
                "policyId": COMPARISON_POLICY_ID,
                "result": "agree",
                "digest": digest("comparison"),
            },
        }
        self.release = {"product": "keeldock", "channel": "uat", "version": "4.7.0"}
        self.expected_context = copy.deepcopy({
            "release": self.release,
            "buildInputManifestSha256": digest("build-input-manifest"),
            "buildEvidence": self.build_evidence,
            "signer": self.signer,
            "pins": self.pins,
        })
        self.allowed_signers = {"release-role": ["release-key-test"]}
        self.statement = self.make_statement()
        self.statement_bytes = encode_canonical_json(self.statement)
        self.expected_message = (
            b"KeelDock/release/v1/provenance\x00"
            + b'{"key_id":"release-key-test","payload":'
            + self.statement_bytes
            + b',"role":"provenance","schema":1}'
        )
        self.signature = hashlib.sha256(
            b"fixture-key" + self.expected_message
        ).digest()
        self.verifier = DeterministicFakeVerifier()

    def make_statement(self, predicate=None, subjects=None):
        if predicate is None:
            predicate = {
                "profileVersion": PROFILE_VERSION,
                "release": copy.deepcopy(self.release),
                "buildInputManifestSha256": digest("build-input-manifest"),
                "buildEvidence": copy.deepcopy(self.build_evidence),
                "signer": copy.deepcopy(self.signer),
                "pins": copy.deepcopy(self.pins),
                "edges": copy.deepcopy(self.release_manifest),
            }
        else:
            predicate = copy.deepcopy(predicate)
        edges = predicate["edges"]
        if subjects is None:
            entries = []
            for artifact in edges["artifacts"]:
                entries.append(
                    {"name": artifact["name"], "digest": {"sha256": artifact["sha256"]}}
                )
            entries.append(
                {"name": edges["sbom"]["name"], "digest": {"sha256": edges["sbom"]["sha256"]}}
            )
            for signature in edges["linuxSignatures"]:
                entries.append(
                    {"name": signature["name"], "digest": {"sha256": signature["sha256"]}}
                )
            subjects = sorted(entries, key=lambda item: item["name"])
        else:
            subjects = copy.deepcopy(subjects)
        return {
            "_type": STATEMENT_TYPE_URI,
            "subject": subjects,
            "predicateType": PREDICATE_TYPE_URI,
            "predicate": predicate,
        }

    def verify(self, statement=None, manifest=None, context=None, signers=None, signature=None):
        value = self.statement_bytes if statement is None else encode_canonical_json(statement)
        return verify_statement(
            value,
            self.release_manifest if manifest is None else manifest,
            self.expected_context if context is None else context,
            self.allowed_signers if signers is None else signers,
            self.signature if signature is None else signature,
            self.verifier,
            PROVENANCE_DOCUMENT_ROLE,
            "release-key-test",
        )

    def assert_refusal(self, expected_code, **arguments):
        with self.assertRaises(VerificationRefusal) as refusal:
            self.verify(**arguments)
        self.assertEqual(refusal.exception.code, expected_code)

    def test_accepts_canonical_statement_with_every_release_subject(self):
        result = self.verify()
        self.assertEqual(result.profile_version, "1")
        self.assertEqual(result.signer_role, "release-role")
        self.assertEqual(result.signer_key_id, "release-key-test")
        self.assertEqual(len(result.subject_names), 4)

    def test_provenance_signing_bytes_match_fixed_vector(self):
        self.assertEqual(
            signature_message(self.statement_bytes, "release-key-test"),
            self.expected_message,
        )

    def test_refuses_signature_from_manifest_domain(self):
        manifest_message = (
            b"KeelDock/release/v1/manifest\x00"
            + b'{"key_id":"release-key-test","payload":'
            + self.statement_bytes
            + b',"role":"manifest","schema":1}'
        )
        manifest_signature = hashlib.sha256(b"fixture-key" + manifest_message).digest()
        self.assert_refusal("invalid-signature", signature=manifest_signature)

    def test_refuses_changed_subject_digest(self):
        changed = self.make_statement()
        changed["subject"][0]["digest"]["sha256"] = digest("altered")
        self.assert_refusal("altered-subject", statement=changed)

    def test_refuses_wrong_signer_role(self):
        changed = self.make_statement()
        changed["predicate"]["signer"]["role"] = "build-role"
        self.assert_refusal("wrong-signer", statement=changed)

    def test_refuses_wrong_signer_key(self):
        changed = self.make_statement()
        changed["predicate"]["signer"]["keyId"] = "untrusted-key"
        self.assert_refusal("wrong-signer", statement=changed)

    def test_refuses_outer_envelope_role_mismatch(self):
        with self.assertRaises(VerificationRefusal) as refusal:
            verify_statement(
                self.statement_bytes,
                self.release_manifest,
                self.expected_context,
                self.allowed_signers,
                self.signature,
                self.verifier,
                "release-role",
                "release-key-test",
            )
        self.assertEqual(refusal.exception.code, "wrong-signer")

    def test_refuses_outer_envelope_key_mismatch(self):
        with self.assertRaises(VerificationRefusal) as refusal:
            verify_statement(
                self.statement_bytes,
                self.release_manifest,
                self.expected_context,
                self.allowed_signers,
                self.signature,
                self.verifier,
                PROVENANCE_DOCUMENT_ROLE,
                "other-key",
            )
        self.assertEqual(refusal.exception.code, "wrong-signer")

    def test_refuses_stale_build_run(self):
        changed = self.make_statement()
        changed["predicate"]["buildEvidence"]["runId"] = "run-old"
        self.assertEqual(
            self.expected_context["buildEvidence"]["runId"], "run-2026-10-29-01"
        )
        self.assert_refusal("stale-build", statement=changed)

    def test_refuses_stale_nested_lock_pin(self):
        changed = self.make_statement()
        changed["predicate"]["pins"]["lockDigests"]["cargo-lock"] = digest("older-lock")
        self.assertEqual(
            self.expected_context["pins"]["lockDigests"]["cargo-lock"],
            digest("cargo-lock"),
        )
        self.assert_refusal("stale-build", statement=changed)

    def test_refuses_missing_build_a_evidence(self):
        changed = self.make_statement()
        del changed["predicate"]["buildEvidence"]["buildA"]
        self.assert_refusal("missing-build", statement=changed)

    def test_refuses_missing_build_b_evidence(self):
        changed = self.make_statement()
        del changed["predicate"]["buildEvidence"]["buildB"]
        self.assert_refusal("missing-build", statement=changed)

    def test_refuses_final_manifest_digest_edge(self):
        changed = self.make_statement()
        changed["predicate"]["finalManifestSha256"] = digest("manifest")
        self.assert_refusal("wrong-edge", statement=changed)

    def test_refuses_latest_document_digest_edge(self):
        changed = self.make_statement()
        changed["predicate"]["latestSha256"] = digest("latest")
        self.assert_refusal("wrong-edge", statement=changed)

    def test_refuses_metadata_sequence_edge(self):
        changed = self.make_statement()
        changed["predicate"]["metadataSequence"] = 12
        self.assert_refusal("wrong-edge", statement=changed)

    def test_refuses_linux_signature_edge_with_wrong_artifact(self):
        changed = self.make_statement()
        changed["predicate"]["edges"]["linuxSignatures"][0]["artifactSha256"] = digest(
            "another-artifact"
        )
        self.assert_refusal("wrong-edge", statement=changed)

    def test_refuses_missing_linux_signature_edge(self):
        changed = self.make_statement()
        changed["predicate"]["edges"]["linuxSignatures"] = []
        self.assert_refusal("wrong-edge", statement=changed)

    def test_refuses_duplicate_object_keys(self):
        raw = (
            b'{"_type":"'
            + STATEMENT_TYPE_URI.encode("ascii")
            + b'","_type":"'
            + STATEMENT_TYPE_URI.encode("ascii")
            + b'"}'
        )
        with self.assertRaises(VerificationRefusal) as refusal:
            verify_statement(
                raw,
                self.release_manifest,
                self.expected_context,
                self.allowed_signers,
                self.signature,
                self.verifier,
                PROVENANCE_DOCUMENT_ROLE,
                "release-key-test",
            )
        self.assertEqual(refusal.exception.code, "duplicate-key")

    def test_refuses_noncanonical_whitespace(self):
        raw = self.statement_bytes + b" "
        with self.assertRaises(VerificationRefusal) as refusal:
            verify_statement(
                raw,
                self.release_manifest,
                self.expected_context,
                self.allowed_signers,
                self.signature,
                self.verifier,
                PROVENANCE_DOCUMENT_ROLE,
                "release-key-test",
            )
        self.assertEqual(refusal.exception.code, "non-canonical-json")

    def test_refuses_oversized_statement(self):
        raw = b" " * (MAX_STATEMENT_BYTES + 1)
        with self.assertRaises(VerificationRefusal) as refusal:
            verify_statement(
                raw,
                self.release_manifest,
                self.expected_context,
                self.allowed_signers,
                self.signature,
                self.verifier,
                PROVENANCE_DOCUMENT_ROLE,
                "release-key-test",
            )
        self.assertEqual(refusal.exception.code, "statement-too-large")

    def test_refuses_unknown_profile_fields(self):
        changed = self.make_statement()
        changed["predicate"]["unexpected"] = "value"
        self.assert_refusal("unknown-field", statement=changed)

    def test_refuses_unsupported_statement_type(self):
        changed = self.make_statement()
        changed["_type"] = "https://in-toto.io/Statement/v2"
        self.assert_refusal("unsupported-statement", statement=changed)

    def test_refuses_invalid_signature(self):
        self.assert_refusal("invalid-signature", signature=b"wrong")

    def test_refuses_missing_release_subject_edge(self):
        changed = self.make_statement()
        changed["subject"] = changed["subject"][:-1]
        self.assert_refusal("wrong-edge", statement=changed)


if __name__ == "__main__":
    unittest.main()
