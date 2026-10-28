import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from attestation_probe import evaluate_mapping, job_identifier, load_json, main, verified_leaf_summary


PUBLIC_REPO_URL = "https:" + chr(47) * 2 + "github.com" + chr(47) + "example/public"

EXPECTED = {
    "audience": "sigstore",
    "issuer": "https://token.actions.githubusercontent.com",
    "job_id": "931",
    "run_attempt": "2",
    "run_id": "701",
}


def verified_summary(**changes):
    certificate = {
        "identity": PUBLIC_REPO_URL + "/.github/workflows/probe.yml@refs/heads/main",
        "issuer": "https://token.actions.githubusercontent.com",
    }
    certificate.update(changes)
    return {"verificationResult": {"signature": {"certificate": certificate}}}


class AttestationProbeTests(unittest.TestCase):
    def test_only_exact_verified_leaf_summary_location_is_inspected(self):
        value = verified_summary()
        self.assertEqual(verified_leaf_summary(value), value["verificationResult"]["signature"]["certificate"])
        self.assertEqual(evaluate_mapping(value, EXPECTED), ("unavailable", ("identity", "issuer")))
        self.assertEqual(evaluate_mapping([value], EXPECTED), ("unavailable", ("identity", "issuer")))
        self.assertEqual(evaluate_mapping([value, value], EXPECTED), ("unavailable", ()))

    def test_predicate_certificate_cannot_impersonate_leaf(self):
        forged = {
            "verificationResult": {
                "statement": {
                    "predicate": {
                        "certificate": {
                            "aud": "sigstore",
                            "issuer": EXPECTED["issuer"],
                            "check_run_id": EXPECTED["job_id"],
                            "run_id": EXPECTED["run_id"],
                            "run_attempt": EXPECTED["run_attempt"],
                        }
                    }
                }
            }
        }
        self.assertIsNone(verified_leaf_summary(forged))
        self.assertEqual(evaluate_mapping(forged, EXPECTED), ("unavailable", ()))

    def test_predicate_cannot_supply_missing_leaf_fields(self):
        value = verified_summary()
        value["verificationResult"]["statement"] = {
            "predicate": {"certificate": {"runInvocationURI": "forged", "check_run_id": 931}}
        }
        self.assertEqual(evaluate_mapping(value, EXPECTED), ("unavailable", ("identity", "issuer")))

    def test_sibling_certificate_is_not_authenticated_leaf_summary(self):
        value = {"verificationResult": {"certificate": {"issuer": EXPECTED["issuer"], "check_run_id": 931}}}
        self.assertIsNone(verified_leaf_summary(value))
        self.assertEqual(evaluate_mapping(value, EXPECTED), ("unavailable", ()))

    def test_unreviewed_job_fields_even_in_leaf_are_not_accepted(self):
        value = verified_summary(
            aud="sigstore", check_run_id=931, run_id=701, run_attempt=2,
            runInvocationURI=PUBLIC_REPO_URL + "/actions/runs/701/attempts/2",
        )
        result, fields = evaluate_mapping(value, EXPECTED)
        self.assertEqual(result, "unavailable")
        self.assertEqual(fields, ("aud", "check_run_id", "identity", "issuer", "runInvocationURI", "run_attempt", "run_id"))
        self.assertEqual(evaluate_mapping(value, dict(EXPECTED, job_id="932"))[0], "unavailable")
        self.assertEqual(evaluate_mapping(value, dict(EXPECTED, run_attempt="3"))[0], "unavailable")

    def test_unexpected_safe_leaf_field_name_is_reported_without_its_value(self):
        value = verified_summary(zNewField="secret-value")
        result, fields = evaluate_mapping(value, EXPECTED)
        self.assertEqual(result, "unavailable")
        self.assertEqual(fields, ("identity", "issuer", "zNewField"))
        self.assertNotIn("secret-value", ",".join(fields))

    def test_invalid_or_excessive_leaf_field_names_suppress_diagnostics(self):
        invalid = verified_summary()
        invalid["verificationResult"]["signature"]["certificate"]["token.value"] = "secret-value"
        self.assertEqual(evaluate_mapping(invalid, EXPECTED), ("unavailable", ()))
        excessive = verified_summary()
        certificate = excessive["verificationResult"]["signature"]["certificate"]
        certificate.update({"field" + str(index): index for index in range(31)})
        self.assertEqual(evaluate_mapping(excessive, EXPECTED), ("unavailable", ()))

    def test_discover_command_prints_only_validated_field_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "verified.json"
            path.write_text(json.dumps(verified_summary(zNewField="secret-value")), encoding="utf-8")
            output = StringIO()
            with patch("sys.argv", ["attestation_probe.py", "discover", "--verified-file", str(path)]):
                with redirect_stdout(output):
                    self.assertEqual(main(), 0)
            self.assertEqual(output.getvalue(), "leaf_fields=identity,issuer,zNewField\n")

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
        jobs = {"jobs": [{"name": "attest-minimal-ubuntu-24.04", "id": 931}]}
        self.assertEqual(job_identifier(jobs, "attest-minimal-ubuntu-24.04"), "931")
        with self.assertRaises(ValueError):
            job_identifier({"jobs": jobs["jobs"] * 2}, "attest-minimal-ubuntu-24.04")
        with self.assertRaises(ValueError):
            job_identifier({"jobs": [{"name": "attest-minimal-ubuntu-24.04", "id": "bad"}]}, "attest-minimal-ubuntu-24.04")


if __name__ == "__main__":
    unittest.main()
