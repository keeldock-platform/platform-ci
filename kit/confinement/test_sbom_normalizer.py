import base64
import hashlib
import json
import unittest

import cargo_lock_receipt
import sbom_normalizer as subject


CARGO_HASH = "a" * 64
NPM_INTEGRITY = "sha512-" + ("A" * 86) + "=="
NPM_HASH = base64.b64decode(("A" * 86) + "==").hex()
CARGO_LOCK_BYTES = (
    "version = 3\n\n"
    "[[package]]\n"
    "name = \"fixture-app\"\n"
    "version = \"1.0.0\"\n"
    "dependencies = [\"serde 1.0.0 (" + cargo_lock_receipt.REGISTRY_SOURCE + ")\"]\n\n"
    "[[package]]\n"
    "name = \"serde\"\n"
    "version = \"1.0.0\"\n"
    "source = \"" + cargo_lock_receipt.REGISTRY_SOURCE + "\"\n"
    "checksum = \"" + CARGO_HASH + "\"\n"
).encode("ascii")
PACKAGE_LOCK_VALUE = {
    "name": "fixture-root",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {
            "name": "fixture-root",
            "version": "1.0.0",
            "dependencies": {"left-pad": "1.3.0"},
        },
        "node_modules/left-pad": {
            "version": "1.3.0",
            "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "integrity": NPM_INTEGRITY,
            "license": "MIT",
        },
    },
}
PACKAGE_LOCK_BYTES = (json.dumps(PACKAGE_LOCK_VALUE, separators=(",", ":")) + "\n").encode("ascii")
NPM_LOCK_INVENTORY = {
    "inventoryVersion": 1,
    "packageCount": 2,
    "lockfileVersion": 3,
    "lockSha256": hashlib.sha256(PACKAGE_LOCK_BYTES).hexdigest(),
    "packages": [
        {
            "name": "fixture-root",
            "version": "1.0.0",
            "kind": "root",
            "integrity": None,
            "license": None,
            "dependencies": [{"name": "left-pad", "version": "1.3.0"}],
        },
        {
            "name": "left-pad",
            "version": "1.3.0",
            "kind": "registry",
            "integrity": NPM_INTEGRITY,
            "license": "MIT",
            "dependencies": [],
        },
    ],
}


def cargo_document():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": subject.CYCLONEDX_SPEC_VERSION,
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
        "version": 1,
        "metadata": {
            "timestamp": "2026-10-29T00:00:00Z",
            "tools": [{"vendor": "example", "name": "cargo-cyclonedx", "version": "0.1.0"}],
            "component": {
                "type": "application",
                "bom-ref": "cargo-root",
                "name": "fixture-app",
                "version": "1.0.0",
                "purl": "pkg:cargo/fixture-app@1.0.0",
            },
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "serde-ref",
                "name": "serde",
                "version": "1.0.0",
                "purl": "pkg:cargo/serde@1.0.0",
                "hashes": [{"alg": "sha-256", "content": CARGO_HASH.upper()}],
                "licenses": [{"license": {"id": "MIT"}}],
            },
        ],
        "dependencies": [
            {"ref": "cargo-root", "dependsOn": ["serde-ref"]},
            {"ref": "serde-ref", "dependsOn": []},
        ],
    }


def npm_document():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": subject.CYCLONEDX_SPEC_VERSION,
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000002",
        "version": 1,
        "metadata": {
            "tools": [{"vendor": "example", "name": "cyclonedx-npm", "version": "1.0.0"}],
            "component": {
                "type": "application",
                "bom-ref": "npm-root",
                "name": "fixture-root",
                "version": "1.0.0",
                "purl": "pkg:npm/fixture-root@1.0.0",
            },
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "left-pad-ref",
                "name": "left-pad",
                "version": "1.3.0",
                "purl": "pkg:npm/left-pad@1.3.0",
                "hashes": [{"alg": "SHA-512", "content": NPM_HASH}],
                "licenses": [{"expression": "MIT"}],
            },
        ],
        "dependencies": [
            {"ref": "npm-root", "dependsOn": ["left-pad-ref"]},
            {"ref": "left-pad-ref", "dependsOn": []},
        ],
    }


def encode_document(document):
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def merge(cargo=None, npm=None, cargo_lock=CARGO_LOCK_BYTES,
          package_lock=PACKAGE_LOCK_BYTES, npm_inventory=NPM_LOCK_INVENTORY):
    return subject.normalize_and_merge(
        encode_document(cargo if cargo is not None else cargo_document()),
        encode_document(npm if npm is not None else npm_document()),
        cargo_lock,
        package_lock,
        npm_inventory,
    )


class SbomNormalizerTests(unittest.TestCase):
    def assert_refusal(self, code, operation):
        with self.assertRaises(subject.SbomRefusal) as raised:
            operation()
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)

    def test_healthy_merge_is_byte_identical_and_canonical(self):
        first = merge()
        second = merge()
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        document = json.loads(first.decode("ascii"))
        canonical = json.dumps(
            document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii") + b"\n"
        self.assertEqual(first, canonical)
        components = {item["purl"]: item for item in document["components"]}
        self.assertEqual(components["pkg:cargo/serde@1.0.0"]["hashes"][0]["content"], CARGO_HASH)
        self.assertEqual(components["pkg:npm/left-pad@1.3.0"]["hashes"][0]["content"], NPM_HASH)
        self.assertEqual(components["pkg:cargo/serde@1.0.0"]["licenses"], [{"expression": "MIT"}])
        self.assertEqual(components["pkg:npm/left-pad@1.3.0"]["licenses"], [{"expression": "MIT"}])
        normalizer = next(
            tool for tool in document["metadata"]["tools"]
            if tool["name"] == "KeelDock CycloneDX normalizer"
        )
        self.assertEqual(normalizer["version"], str(subject.NORMALIZER_VERSION))
        self.assertTrue(subject.validate_pinned_schema_subset(document))

    def test_rejects_oversize_invalid_json_and_duplicate_keys(self):
        self.assert_refusal(
            "sbom_input_oversize",
            lambda: subject.parse_generator_output(b" " * (subject.MAX_SBOM_BYTES + 1)),
        )
        self.assert_refusal("sbom_json_invalid", lambda: subject.parse_generator_output(b"bad json"))
        self.assert_refusal(
            "sbom_duplicate_key",
            lambda: subject.parse_generator_output(b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}'),
        )

    def test_rejects_unknown_unsupported_and_wrong_spec_fields(self):
        document = cargo_document()
        document["newTopField"] = True
        self.assert_refusal("sbom_unknown_field", lambda: merge(cargo=document))
        document = cargo_document()
        document["services"] = []
        self.assert_refusal("sbom_unsupported_field", lambda: merge(cargo=document))
        document = cargo_document()
        document["specVersion"] = "9.9"
        self.assert_refusal("sbom_spec_version", lambda: merge(cargo=document))
        document = cargo_document()
        document["bomFormat"] = "Other"
        self.assert_refusal("sbom_document_invalid", lambda: merge(cargo=document))

    def test_rejects_bad_component_purl_and_unsupported_component_data(self):
        document = cargo_document()
        document["components"][0]["name"] = ""
        self.assert_refusal("sbom_component_invalid", lambda: merge(cargo=document))
        document = cargo_document()
        document["components"][0]["purl"] = "pkg:cargo/other@1.0.0"
        self.assert_refusal("sbom_purl_invalid", lambda: merge(cargo=document))
        document = cargo_document()
        document["components"][0]["evidence"] = {}
        self.assert_refusal("sbom_unsupported_field", lambda: merge(cargo=document))

    def test_rejects_invalid_or_conflicting_hashes(self):
        document = cargo_document()
        document["components"][0]["hashes"][0]["alg"] = "SHA-1"
        self.assert_refusal("sbom_hash_invalid", lambda: merge(cargo=document))
        document = cargo_document()
        document["components"][0]["hashes"][0]["content"] = "b" * 64
        self.assert_refusal("sbom_hash_conflict", lambda: merge(cargo=document))

    def test_rejects_invalid_and_conflicting_licenses(self):
        document = cargo_document()
        document["components"][0]["licenses"] = [{"expression": 4}]
        self.assert_refusal("sbom_license_invalid", lambda: merge(cargo=document))
        document = npm_document()
        document["components"][0]["licenses"] = [{"expression": "Apache-2.0"}]
        self.assert_refusal("sbom_license_conflict", lambda: merge(npm=document))

    def test_rejects_duplicate_and_conflicting_component_identities(self):
        document = cargo_document()
        document["components"].append(dict(document["components"][0]))
        self.assert_refusal("sbom_duplicate_identity", lambda: merge(cargo=document))
        document = cargo_document()
        conflicting = dict(document["components"][0])
        conflicting["description"] = "different source data"
        document["components"].append(conflicting)
        self.assert_refusal("sbom_identity_conflict", lambda: merge(cargo=document))

    def test_proves_exact_component_coverage(self):
        document = cargo_document()
        document["components"] = []
        self.assert_refusal("sbom_coverage_missing", lambda: merge(cargo=document))
        document = cargo_document()
        extra = dict(document["components"][0])
        extra.update({"name": "other", "purl": "pkg:cargo/other@1.0.0"})
        document["components"].append(extra)
        self.assert_refusal("sbom_coverage_extra", lambda: merge(cargo=document))

    def test_rejects_dependency_edges_that_do_not_match_locks(self):
        document = cargo_document()
        document["dependencies"][0]["dependsOn"] = []
        self.assert_refusal("sbom_dependency_invalid", lambda: merge(cargo=document))
        document = cargo_document()
        document["dependencies"][0]["dependsOn"] = ["missing-ref"]
        self.assert_refusal("sbom_dependency_invalid", lambda: merge(cargo=document))

    def test_rejects_lock_and_inventory_mismatches(self):
        self.assert_refusal(
            "sbom_lock_invalid",
            lambda: merge(cargo_lock=b"version = 2\n"),
        )
        self.assert_refusal(
            "sbom_lock_hash_mismatch",
            lambda: merge(package_lock=PACKAGE_LOCK_BYTES + b" "),
        )
        self.assert_refusal(
            "sbom_inventory_invalid",
            lambda: merge(npm_inventory={}),
        )

    def test_rejects_malformed_pinned_schema_output(self):
        self.assert_refusal("sbom_schema_invalid", lambda: subject.validate_pinned_schema_subset({}))


if __name__ == "__main__":
    unittest.main()
