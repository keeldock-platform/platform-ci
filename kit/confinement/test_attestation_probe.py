import json
import tempfile
import unittest
from pathlib import Path

from attestation_probe import evaluate_mapping, job_identifier, load_json


EXPECTED = {
    "audience": "sigstore",
    "issuer": "https://token.actions.githubusercontent.com",
    "job_id": "931",
    "run_attempt": "2",
    "run_id": "701",
}


def verified_claims(**changes):
    value = {
        "verificationResult": {
            "certificate": {
                "issuer": "https://token.actions.githubusercontent.com",
                "aud": "sigstore",
                "check_run_id": 931,
                "run_id": 701,
                "run_attempt": 2,
            }
        }
    }
    value["verificationResult"]["certificate"].update(changes)
    return value


class AttestationProbeTests(unittest.TestCase):
    def test_exact_job_attempt_issuer_and_audience_are_available(self):
        self.assertEqual(evaluate_mapping(verified_claims(), EXPECTED)[0], "available")

    def test_another_job_cannot_match_the_signed_job_claim(self):
        other = dict(EXPECTED, job_id="932")
        self.assertEqual(evaluate_mapping(verified_claims(), other)[0], "mismatch")

    def test_a_hypothetical_later_attempt_cannot_match_the_signed_attempt(self):
        later = dict(EXPECTED, run_attempt="3")
        self.assertEqual(evaluate_mapping(verified_claims(), later)[0], "mismatch")

    def test_attempt_one_and_hypothetical_attempt_two_are_distinguishable(self):
        first_attempt = verified_claims(run_attempt=1)
        expected_first = dict(EXPECTED, run_attempt="1")
        expected_hypothetical = dict(EXPECTED, run_attempt="2")
        self.assertEqual(evaluate_mapping(first_attempt, expected_first)[0], "available")
        self.assertEqual(evaluate_mapping(first_attempt, expected_hypothetical)[0], "mismatch")

    def test_missing_job_or_attempt_claim_fails_closed_as_unavailable(self):
        value = verified_claims()
        del value["verificationResult"]["certificate"]["check_run_id"]
        del value["verificationResult"]["certificate"]["run_attempt"]
        self.assertEqual(evaluate_mapping(value, EXPECTED)[0], "unavailable")

    def test_predicate_claims_cannot_replace_signed_certificate_claims(self):
        value = {
            "verificationResult": {
                "certificate": {
                    "issuer": "https://token.actions.githubusercontent.com",
                    "aud": "sigstore",
                },
                "statement": {
                    "predicate": {
                        "check_run_id": 931,
                        "run_id": 701,
                        "run_attempt": 2,
                    }
                },
            }
        }
        self.assertEqual(evaluate_mapping(value, EXPECTED)[0], "unavailable")

    def test_wrong_issuer_or_audience_is_rejected(self):
        self.assertEqual(evaluate_mapping(verified_claims(issuer="https://other.invalid"), EXPECTED)[0], "mismatch")
        self.assertEqual(evaluate_mapping(verified_claims(aud="other"), EXPECTED)[0], "mismatch")

    def test_duplicate_json_fields_and_oversized_input_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "claims.json"
            path.write_text('{"a":1,"a":2}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_json(path)
            path.write_bytes(b"x" * (1048576 + 1))
            with self.assertRaises(ValueError):
                load_json(path)

    def test_job_lookup_requires_one_exact_name_and_numeric_identifier(self):
        jobs = {"jobs": [{"name": "attest_minimal_ubuntu", "id": 931}]}
        self.assertEqual(job_identifier(jobs, "attest_minimal_ubuntu"), "931")
        with self.assertRaises(ValueError):
            job_identifier({"jobs": jobs["jobs"] * 2}, "attest_minimal_ubuntu")
        with self.assertRaises(ValueError):
            job_identifier({"jobs": [{"name": "attest_minimal_ubuntu", "id": "bad"}]}, "attest_minimal_ubuntu")


if __name__ == "__main__":
    unittest.main()
