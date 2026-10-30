"""Unit coverage for strict ledger parsing and release-tool first use."""

import copy
import json
import unittest
from pathlib import Path

import release_tool_ledger as subject


LEDGER_BYTES = Path(__file__).with_name("release_tool_ledger.json").read_bytes()
SOURCE_URL = "https" + chr(58) + chr(47) + chr(47) + "vendor.example/release"


def _ledger():
    return subject.load_ledger_bytes(LEDGER_BYTES)


def _row(ledger, row_id):
    for row in ledger["rows"]:
        if row["id"] == row_id:
            return row
    raise AssertionError(row_id)


def _fill_admitted_values(row):
    row["status"] = "admitted"
    pins = row["pins"]
    for field in pins:
        if field == "exact_version":
            pins[field] = "synthetic-release"
        elif field == "platform_arch":
            pins[field] = "linux-x86_64"
        elif field == "source_release_identity":
            pins[field] = "synthetic-source-release"
        elif field == "source_url":
            pins[field] = SOURCE_URL
        elif field == "signature_provenance_result":
            pins[field] = {
                "result": "verified",
                "identity": "synthetic-signer",
                "evidence_sha256": "a" * 64,
            }
        elif field == "acquisition_method":
            pins[field] = "verified offline input"
        elif field == "review_ids":
            pins[field] = ["independent-review"]
        elif field == "owner_acceptance_reference":
            pins[field] = "owner-acceptance-record"
        elif field == "test_result_hashes":
            pins[field] = ["b" * 64]
        elif field == "source_revision":
            pins[field] = "c" * 40
        elif field == "archive_set_identity":
            pins[field] = "archive-set-identity"
        elif field == "outer_runner_image_revision":
            pins[field] = "runner-image-revision"
        elif field == "provenance_profile_version":
            pins[field] = "synthetic-profile"
        else:
            pins[field] = "d" * 64
    return row


def _admitted_row(row_id="appimagetool"):
    ledger = _ledger()
    row = _fill_admitted_values(_row(ledger, row_id))
    return ledger, row


def _json_bytes(ledger):
    return json.dumps(ledger, separators=(",", ":")).encode("ascii")


class ReleaseToolLedgerTests(unittest.TestCase):
    def assert_refusal(self, code, operation):
        with self.assertRaises(subject.LedgerRefusal) as raised:
            operation()
        self.assertEqual(raised.exception.code, code)

    def test_committed_ledger_is_complete_and_valid(self):
        ledger = _ledger()
        self.assertTrue(subject.validate_ledger(ledger))
        self.assertEqual(
            tuple(row["id"] for row in ledger["rows"]),
            subject.REQUIRED_ROW_IDS,
        )

    def test_first_use_refuses_every_committed_row(self):
        ledger = _ledger()
        for row_id in subject.REQUIRED_ROW_IDS:
            with self.subTest(row_id=row_id):
                self.assert_refusal(
                    "row_not_admitted",
                    lambda row_id=row_id: subject.first_use_gate(ledger, row_id),
                )

    def test_fully_admitted_synthetic_row_passes(self):
        ledger, row = _admitted_row()
        admitted = subject.first_use_gate(ledger, row["id"])
        self.assertEqual(admitted["id"], "appimagetool")
        self.assertEqual(admitted["status"], "admitted")

    def test_release_cli_source_pins_come_from_row_id(self):
        ledger, row = _admitted_row("release-cli")
        row["kind"] = "cli"
        required = subject._required_pin_fields(row)
        self.assertTrue({
            "source_revision",
            "lock_vendor_digest",
            "executable_sha256",
        }.issubset(required))
        for field in ("source_revision", "lock_vendor_digest", "executable_sha256"):
            row["pins"].pop(field)
        self.assert_refusal(
            "row_policy_invalid",
            lambda: subject.first_use_gate(ledger, row["id"]),
        )

    def test_appimagetool_location_cannot_weaken_image_pins(self):
        ledger = _ledger()
        row = _row(ledger, "appimagetool")
        row["execution_location"] = "trusted host"
        row["pins"].pop("recipe_sha256")
        row["pins"].pop("golden_image_digest")
        required = subject._required_pin_fields(row)
        self.assertTrue({"recipe_sha256", "golden_image_digest"}.issubset(required))
        self.assert_refusal(
            "row_policy_invalid",
            lambda: subject.first_use_gate(ledger, row["id"]),
        )

    def test_partial_fill_is_refused(self):
        ledger = _ledger()
        _row(ledger, "appimagetool")["pins"]["exact_version"] = "synthetic-release"
        self.assert_refusal("pin_partial", lambda: subject.validate_ledger(ledger))

    def test_floating_version_is_refused(self):
        ledger, row = _admitted_row()
        row["pins"]["exact_version"] = "latest"
        self.assert_refusal("floating_value", lambda: subject.first_use_gate(ledger, row["id"]))

    def test_whitespace_only_version_is_refused(self):
        ledger, row = _admitted_row()
        row["pins"]["exact_version"] = "   "
        self.assert_refusal("field_invalid", lambda: subject.first_use_gate(ledger, row["id"]))

    def test_forbidden_acquisition_is_refused(self):
        ledger, row = _admitted_row()
        row["pins"]["acquisition_method"] = "cargo install"
        self.assert_refusal("forbidden_acquisition", lambda: subject.first_use_gate(ledger, row["id"]))

    def test_missing_image_digest_is_refused(self):
        ledger, row = _admitted_row()
        row["pins"]["golden_image_digest"] = subject.NOT_SET
        self.assert_refusal("image_pin_missing", lambda: subject.first_use_gate(ledger, row["id"]))

    def test_source_build_requires_revision_lock_and_executable(self):
        for row_id in ("release-cli", "app-metadata-verifier"):
            for field in ("source_revision", "lock_vendor_digest", "executable_sha256"):
                with self.subTest(row_id=row_id, field=field):
                    ledger, row = _admitted_row(row_id)
                    row["pins"][field] = subject.NOT_SET
                    self.assert_refusal(
                        "source_pin_missing",
                        lambda: subject.first_use_gate(ledger, row["id"]),
                    )

    def test_packer_and_signtool_require_executable_hashes(self):
        for row_id in ("packer", "signtool"):
            with self.subTest(row_id=row_id):
                ledger, row = _admitted_row(row_id)
                row["pins"]["executable_sha256"] = subject.NOT_SET
                self.assert_refusal(
                    "executable_pin_missing",
                    lambda: subject.first_use_gate(ledger, row["id"]),
                )

    def test_package_input_requires_lock_and_archive_set(self):
        ledger, row = _admitted_row("crate-serde")
        row["pins"]["lock_sha256"] = subject.NOT_SET
        self.assert_refusal("package_pin_missing", lambda: subject.first_use_gate(ledger, row["id"]))

    def test_npm_requires_lock_and_archive_set_by_row_id(self):
        for field in ("lock_sha256", "archive_set_identity"):
            with self.subTest(field=field):
                ledger, row = _admitted_row("npm")
                row["pins"][field] = subject.NOT_SET
                self.assert_refusal(
                    "package_pin_missing",
                    lambda: subject.first_use_gate(ledger, row["id"]),
                )

    def test_hosted_route_requires_runner_revision_and_inventory(self):
        ledger, row = _admitted_row("hosted-runner-windows")
        row["pins"]["outer_runner_image_revision"] = subject.NOT_SET
        self.assert_refusal("hosted_pin_missing", lambda: subject.first_use_gate(ledger, row["id"]))

    def test_signer_cannot_be_located_in_a_build_vm(self):
        ledger = _ledger()
        row = _row(ledger, "signtool")
        row["execution_location"] = "build VM"
        row["pins"]["recipe_sha256"] = subject.NOT_SET
        row["pins"]["golden_image_digest"] = subject.NOT_SET
        self.assert_refusal("signer_in_build_vm", lambda: subject.validate_ledger(ledger))

    def test_private_key_class_cannot_be_located_in_a_build_vm(self):
        ledger = _ledger()
        row = _row(ledger, "appimagetool")
        row["credential_class"] = "test-platform-signing-key"
        self.assert_refusal("private_key_location", lambda: subject.validate_ledger(ledger))

    def test_cli_without_provenance_suite_is_refused(self):
        ledger = _ledger()
        row = _row(ledger, "release-cli")
        row["suites"].remove("release.provenance")
        self.assert_refusal("cli_provenance_missing", lambda: subject.validate_ledger(ledger))

    def test_build_verify_does_not_substitute_for_provenance(self):
        ledger = _ledger()
        row = _row(ledger, "release-cli")
        row["suites"] = ["release.build-verify"]
        self.assert_refusal("cli_provenance_missing", lambda: subject.first_use_gate(ledger, row["id"]))

    def test_cli_requires_each_provenance_evidence_item(self):
        cases = (
            ("provenance_profile_version", "provenance_profile_missing"),
            ("provenance_generator_source_sha256", "provenance_generator_source_missing"),
            ("provenance_generator_binary_sha256", "provenance_generator_binary_missing"),
            ("provenance_verifier_source_sha256", "provenance_verifier_source_missing"),
            ("provenance_verifier_binary_sha256", "provenance_verifier_binary_missing"),
            ("provenance_positive_result_sha256", "provenance_positive_missing"),
            ("provenance_altered_subject_sha256", "provenance_altered_subject_missing"),
            ("provenance_wrong_role_key_sha256", "provenance_wrong_role_key_missing"),
            ("provenance_stale_build_sha256", "provenance_stale_build_missing"),
            ("provenance_missing_build_sha256", "provenance_missing_build_missing"),
            ("provenance_wrong_edge_sha256", "provenance_wrong_edge_missing"),
        )
        for field, code in cases:
            with self.subTest(field=field):
                ledger, row = _admitted_row("release-cli")
                row["pins"][field] = subject.NOT_SET
                self.assert_refusal(code, lambda: subject.first_use_gate(ledger, row["id"]))

    def test_pkcs11_must_remain_parked(self):
        ledger = _ledger()
        _row(ledger, "pkcs11-bridge")["status"] = "not_set"
        self.assert_refusal("pkcs11_not_parked", lambda: subject.validate_ledger(ledger))

    def test_ios_signing_rows_must_remain_deferred(self):
        for row_id in subject.DEFERRED_ROW_IDS:
            with self.subTest(row_id=row_id):
                ledger = _ledger()
                _row(ledger, row_id)["status"] = "not_set"
                self.assert_refusal("ios_not_deferred", lambda: subject.validate_ledger(ledger))

    def test_missing_unknown_and_duplicate_rows_are_refused(self):
        missing = _ledger()
        missing["rows"] = [row for row in missing["rows"] if row["id"] != "appimagetool"]
        self.assert_refusal("row_missing", lambda: subject.validate_ledger(missing))
        unknown = _ledger()
        changed = copy.deepcopy(_row(unknown, "appimagetool"))
        changed["id"] = "unknown-tool"
        unknown["rows"].append(changed)
        self.assert_refusal("row_unknown", lambda: subject.validate_ledger(unknown))
        duplicate = _ledger()
        duplicate["rows"].append(copy.deepcopy(_row(duplicate, "appimagetool")))
        self.assert_refusal("row_duplicate", lambda: subject.validate_ledger(duplicate))

    def test_duplicate_json_key_is_refused(self):
        self.assert_refusal(
            "json_duplicate_key",
            lambda: subject.load_ledger_bytes(b'{"schema_version":1,"schema_version":1}'),
        )

    def test_oversize_json_is_refused(self):
        payload = b" " * (subject.MAX_LEDGER_BYTES + 1)
        self.assert_refusal("json_too_large", lambda: subject.load_ledger_bytes(payload))

    def test_non_ascii_json_is_refused(self):
        self.assert_refusal("json_non_ascii", lambda: subject.load_ledger_bytes(b"{\"name\":\"\xc3\"}"))
        self.assert_refusal(
            "json_non_ascii",
            lambda: subject.load_ledger_bytes(b'{"name":"\\u00e9"}'),
        )

    def test_excessive_json_depth_is_refused(self):
        depth = subject.MAX_JSON_DEPTH + 1
        payload = b"[" * depth + b"0" + b"]" * depth
        self.assert_refusal("json_too_deep", lambda: subject.load_ledger_bytes(payload))

    def test_json_constants_are_refused(self):
        for constant in (b"NaN", b"Infinity", b"-Infinity", b"1e999"):
            with self.subTest(constant=constant):
                self.assert_refusal(
                    "json_constant_forbidden",
                    lambda constant=constant: subject.load_ledger_bytes(constant),
                )

    def test_invalid_json_is_refused(self):
        self.assert_refusal("json_invalid", lambda: subject.load_ledger_bytes(b"{"))

    def test_invalid_schema_suite_status_and_field_are_refused(self):
        invalid_shape = _ledger()
        invalid_shape["unexpected"] = True
        self.assert_refusal("ledger_shape_invalid", lambda: subject.validate_ledger(invalid_shape))
        invalid_suite = _ledger()
        invalid_suite["suites"][0] = "release.unknown"
        self.assert_refusal("suite_invalid", lambda: subject.validate_ledger(invalid_suite))
        invalid_status = _ledger()
        _row(invalid_status, "appimagetool")["status"] = "unknown"
        self.assert_refusal("status_invalid", lambda: subject.validate_ledger(invalid_status))
        invalid_field, row = _admitted_row()
        row["pins"]["artifact_sha256"] = "bad"
        self.assert_refusal("field_invalid", lambda: subject.first_use_gate(invalid_field, row["id"]))

    def test_generic_required_field_and_unknown_first_use_are_refused(self):
        ledger, row = _admitted_row()
        row["pins"]["artifact_sha256"] = subject.NOT_SET
        self.assert_refusal("field_missing", lambda: subject.first_use_gate(ledger, row["id"]))
        self.assert_refusal("row_unknown", lambda: subject.first_use_gate(_ledger(), "unknown-tool"))


if __name__ == "__main__":
    unittest.main()
