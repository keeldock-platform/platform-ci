"""Strict validation and first-use gate for the source-free release-tool ledger."""

import json
import math
import re
from types import MappingProxyType


SCHEMA_VERSION = 1
NOT_SET = "NOT SET"
MAX_LEDGER_BYTES = 524288
MAX_JSON_DEPTH = 32
MAX_ROWS = 128
MAX_TEXT = 2048

SUITES = (
    "release.vm-image",
    "release.build-vm",
    "release.sign-host",
    "release.build-verify",
    "release.sbom",
    "release.manifest",
    "release.latest-json",
    "release.dry-run",
    "release.provenance",
)

LOCATIONS = (
    "trusted host",
    "build VM",
    "image builder",
    "hosted outer runner",
)

ADMISSION_PATHS = ("crate", "npm", "release-tool", "os-supplied", "image")

KINDS = (
    "cli",
    "crate",
    "application_verifier",
    "public_verifier",
    "hardware_bridge",
    "sbom_generator",
    "npm_package",
    "source_tool",
    "source_code",
    "image_builder",
    "builder_plugin",
    "hypervisor_provider",
    "image_recipe",
    "hosted_route",
    "nested_provider",
    "package_manager",
    "toolchain",
    "runtime",
    "windows_sdk",
    "gradle_wrapper",
    "vendor_distribution",
    "android_sdk",
    "os_supplied",
    "standalone_binary",
    "apple_sdk",
    "signing_tool",
    "credential",
    "standalone_jar",
    "packaging_tool",
    "handoff",
    "cleanup",
    "workflow",
    "allow_list",
    "broker",
)

CREDENTIAL_CLASSES = (
    "none",
    "no-release-credentials",
    "test-release-role-key",
    "test-platform-signing-key",
    "owner-ios-identity",
    "production-hardware-token",
    "release-key-material",
)

PIN_FIELDS = (
    "exact_version",
    "platform_arch",
    "source_release_identity",
    "source_url",
    "artifact_sha256",
    "signature_provenance_result",
    "transitive_installed_closure_digest",
    "source_revision",
    "lock_vendor_digest",
    "executable_sha256",
    "recipe_sha256",
    "golden_image_digest",
    "lock_sha256",
    "archive_set_identity",
    "acquisition_method",
    "review_ids",
    "owner_acceptance_reference",
    "offline_input_proof_sha256",
    "platform_proof_sha256",
    "test_result_hashes",
    "outer_runner_image_revision",
    "installed_tool_inventory_digest",
    "provenance_profile_version",
    "provenance_generator_source_sha256",
    "provenance_generator_binary_sha256",
    "provenance_verifier_source_sha256",
    "provenance_verifier_binary_sha256",
    "provenance_positive_result_sha256",
    "provenance_altered_subject_sha256",
    "provenance_wrong_role_key_sha256",
    "provenance_stale_build_sha256",
    "provenance_missing_build_sha256",
    "provenance_wrong_edge_sha256",
)
BASE_PIN_FIELDS = (
    "exact_version",
    "platform_arch",
    "source_release_identity",
    "source_url",
    "artifact_sha256",
    "signature_provenance_result",
    "transitive_installed_closure_digest",
    "acquisition_method",
    "review_ids",
    "owner_acceptance_reference",
    "offline_input_proof_sha256",
    "platform_proof_sha256",
    "test_result_hashes",
)

REQUIRED_ROW_IDS = (
    "release-cli",
    "crate-serde",
    "crate-serde-json",
    "crate-sha2",
    "crate-time",
    "crate-p256",
    "crate-signature",
    "app-metadata-verifier",
    "public-verifier",
    "pkcs11-bridge",
    "cargo-cyclonedx",
    "cyclonedx-npm",
    "cargo-auditable",
    "sbom-merger-validator",
    "binary-metadata-inspector",
    "packer",
    "packer-plugin-virtualization-framework",
    "packer-plugin-hyper-v",
    "provider-virtualization-framework",
    "provider-hyper-v",
    "image-recipe-macos",
    "image-recipe-windows",
    "image-recipe-linux",
    "image-recipe-android",
    "image-recipe-ios-simulator",
    "hosted-runner-windows",
    "hosted-runner-linux",
    "hosted-nested-provider",
    "npm",
    "rustc-cargo",
    "node-runtime",
    "msbuild-windows-sdk",
    "gradle-wrapper",
    "gradle-distribution",
    "jdk-build-runtime",
    "android-sdk",
    "android-build-tools",
    "dpkg-deb",
    "appimagetool",
    "xcode-sdk",
    "codesign",
    "ios-signing-identity",
    "ios-provisioning-profile",
    "signtool",
    "jdk-host-signing-tools",
    "bundletool",
    "zipalign",
    "apksigner",
    "linux-detached-signer",
    "private-handoff",
    "cleanup-path",
    "release-workflow",
    "signer-allow-list",
    "host-signing-broker",
)

ROW_POLICY = MappingProxyType({
    "release-cli": ("source_tool", "release-tool", "trusted host", "test-release-role-key"),
    "crate-serde": ("crate", "crate", "trusted host", "none"),
    "crate-serde-json": ("crate", "crate", "trusted host", "none"),
    "crate-sha2": ("crate", "crate", "trusted host", "none"),
    "crate-time": ("crate", "crate", "trusted host", "none"),
    "crate-p256": ("crate", "crate", "trusted host", "none"),
    "crate-signature": ("crate", "crate", "trusted host", "none"),
    "app-metadata-verifier": ("source_tool", "release-tool", "build VM", "no-release-credentials"),
    "public-verifier": ("source_tool", "release-tool", "build VM", "no-release-credentials"),
    "pkcs11-bridge": ("hardware_bridge", "crate", "trusted host", "production-hardware-token"),
    "cargo-cyclonedx": ("source_tool", "crate", "build VM", "no-release-credentials"),
    "cyclonedx-npm": ("npm_package", "npm", "build VM", "no-release-credentials"),
    "cargo-auditable": ("source_tool", "crate", "build VM", "no-release-credentials"),
    "sbom-merger-validator": ("source_code", "release-tool", "trusted host", "no-release-credentials"),
    "binary-metadata-inspector": ("source_code", "release-tool", "trusted host", "no-release-credentials"),
    "packer": ("image_builder", "release-tool", "image builder", "no-release-credentials"),
    "packer-plugin-virtualization-framework": ("builder_plugin", "release-tool", "image builder", "no-release-credentials"),
    "packer-plugin-hyper-v": ("builder_plugin", "release-tool", "image builder", "no-release-credentials"),
    "provider-virtualization-framework": ("hypervisor_provider", "os-supplied", "image builder", "no-release-credentials"),
    "provider-hyper-v": ("hypervisor_provider", "os-supplied", "image builder", "no-release-credentials"),
    "image-recipe-macos": ("image_recipe", "image", "image builder", "no-release-credentials"),
    "image-recipe-windows": ("image_recipe", "image", "image builder", "no-release-credentials"),
    "image-recipe-linux": ("image_recipe", "image", "image builder", "no-release-credentials"),
    "image-recipe-android": ("image_recipe", "image", "image builder", "no-release-credentials"),
    "image-recipe-ios-simulator": ("image_recipe", "image", "image builder", "no-release-credentials"),
    "hosted-runner-windows": ("hosted_route", "image", "hosted outer runner", "no-release-credentials"),
    "hosted-runner-linux": ("hosted_route", "image", "hosted outer runner", "no-release-credentials"),
    "hosted-nested-provider": ("nested_provider", "image", "hosted outer runner", "no-release-credentials"),
    "npm": ("package_manager", "release-tool", "build VM", "no-release-credentials"),
    "rustc-cargo": ("toolchain", "release-tool", "build VM", "no-release-credentials"),
    "node-runtime": ("runtime", "release-tool", "build VM", "no-release-credentials"),
    "msbuild-windows-sdk": ("windows_sdk", "release-tool", "build VM", "no-release-credentials"),
    "gradle-wrapper": ("gradle_wrapper", "release-tool", "build VM", "no-release-credentials"),
    "gradle-distribution": ("vendor_distribution", "release-tool", "build VM", "no-release-credentials"),
    "jdk-build-runtime": ("runtime", "release-tool", "build VM", "no-release-credentials"),
    "android-sdk": ("android_sdk", "release-tool", "build VM", "no-release-credentials"),
    "android-build-tools": ("android_sdk", "release-tool", "build VM", "no-release-credentials"),
    "dpkg-deb": ("os_supplied", "os-supplied", "build VM", "no-release-credentials"),
    "appimagetool": ("standalone_binary", "release-tool", "build VM", "no-release-credentials"),
    "xcode-sdk": ("apple_sdk", "release-tool", "build VM", "no-release-credentials"),
    "codesign": ("signing_tool", "os-supplied", "trusted host", "test-platform-signing-key"),
    "ios-signing-identity": ("credential", "os-supplied", "trusted host", "owner-ios-identity"),
    "ios-provisioning-profile": ("credential", "os-supplied", "trusted host", "owner-ios-identity"),
    "signtool": ("signing_tool", "release-tool", "trusted host", "test-platform-signing-key"),
    "jdk-host-signing-tools": ("signing_tool", "release-tool", "trusted host", "test-platform-signing-key"),
    "bundletool": ("standalone_jar", "release-tool", "trusted host", "no-release-credentials"),
    "zipalign": ("packaging_tool", "release-tool", "trusted host", "no-release-credentials"),
    "apksigner": ("signing_tool", "release-tool", "trusted host", "test-platform-signing-key"),
    "linux-detached-signer": ("signing_tool", "release-tool", "trusted host", "test-release-role-key"),
    "private-handoff": ("handoff", "release-tool", "hosted outer runner", "no-release-credentials"),
    "cleanup-path": ("cleanup", "release-tool", "trusted host", "release-key-material"),
    "release-workflow": ("workflow", "release-tool", "hosted outer runner", "no-release-credentials"),
    "signer-allow-list": ("allow_list", "release-tool", "trusted host", "no-release-credentials"),
    "host-signing-broker": ("broker", "release-tool", "trusted host", "test-release-role-key"),
})

SOURCE_BUILT_ROW_IDS = frozenset((
    "release-cli",
    "app-metadata-verifier",
    "public-verifier",
    "cargo-cyclonedx",
    "cargo-auditable",
    "sbom-merger-validator",
    "binary-metadata-inspector",
))
PACKAGE_MANAGER_ROW_IDS = frozenset(("npm",))
EXECUTABLE_ROW_IDS = frozenset((
    "release-cli",
    "app-metadata-verifier",
    "public-verifier",
    "cargo-cyclonedx",
    "cyclonedx-npm",
    "cargo-auditable",
    "sbom-merger-validator",
    "binary-metadata-inspector",
    "packer",
    "packer-plugin-virtualization-framework",
    "packer-plugin-hyper-v",
    "provider-virtualization-framework",
    "provider-hyper-v",
    "hosted-nested-provider",
    "npm",
    "rustc-cargo",
    "node-runtime",
    "msbuild-windows-sdk",
    "gradle-wrapper",
    "gradle-distribution",
    "jdk-build-runtime",
    "android-sdk",
    "android-build-tools",
    "dpkg-deb",
    "appimagetool",
    "xcode-sdk",
    "codesign",
    "signtool",
    "jdk-host-signing-tools",
    "bundletool",
    "zipalign",
    "apksigner",
    "linux-detached-signer",
    "private-handoff",
    "cleanup-path",
    "host-signing-broker",
))

PARKED_ROW_ID = "pkcs11-bridge"
DEFERRED_ROW_IDS = frozenset(("ios-signing-identity", "ios-provisioning-profile"))
SIGNING_ROW_IDS = frozenset((
    "release-cli",
    "pkcs11-bridge",
    "codesign",
    "ios-signing-identity",
    "ios-provisioning-profile",
    "signtool",
    "jdk-host-signing-tools",
    "apksigner",
    "linux-detached-signer",
    "host-signing-broker",
))
PRIVATE_CREDENTIAL_CLASSES = frozenset((
    "test-release-role-key",
    "test-platform-signing-key",
    "owner-ios-identity",
    "production-hardware-token",
    "release-key-material",
))

HASH_FIELDS = frozenset((
    "artifact_sha256",
    "transitive_installed_closure_digest",
    "lock_vendor_digest",
    "executable_sha256",
    "recipe_sha256",
    "lock_sha256",
    "offline_input_proof_sha256",
    "platform_proof_sha256",
    "installed_tool_inventory_digest",
    "provenance_generator_source_sha256",
    "provenance_generator_binary_sha256",
    "provenance_verifier_source_sha256",
    "provenance_verifier_binary_sha256",
    "provenance_positive_result_sha256",
    "provenance_altered_subject_sha256",
    "provenance_wrong_role_key_sha256",
    "provenance_stale_build_sha256",
    "provenance_missing_build_sha256",
    "provenance_wrong_edge_sha256",
))
HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}\Z")


class LedgerRefusal(ValueError):
    """A stable, input-independent refusal code for ledger operations."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _refuse(code):
    raise LedgerRefusal(code)


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse("json_duplicate_key")
        result[key] = value
    return result


def _constant_refusal(value):
    _refuse("json_constant_forbidden")


def _check_ascii_tree(value, depth=0):
    if depth > MAX_JSON_DEPTH:
        _refuse("json_too_deep")
    if type(value) is str:
        if any(ord(char) > 127 for char in value):
            _refuse("json_non_ascii")
        return
    if type(value) is float and not math.isfinite(value):
        _refuse("json_constant_forbidden")
    if value is None or type(value) in (bool, int, float):
        return
    if type(value) is list:
        for item in value:
            _check_ascii_tree(item, depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            _check_ascii_tree(key, depth + 1)
            _check_ascii_tree(item, depth + 1)


def load_ledger_bytes(data):
    """Load bounded ASCII JSON, reject ambiguous values, and validate its schema."""
    if type(data) is not bytes:
        _refuse("ledger_shape_invalid")
    if len(data) > MAX_LEDGER_BYTES:
        _refuse("json_too_large")
    if any(byte > 127 for byte in data):
        _refuse("json_non_ascii")
    try:
        text = data.decode("ascii")
        ledger = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_constant_refusal,
        )
    except LedgerRefusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _refuse("json_invalid")
    _check_ascii_tree(ledger)
    validate_ledger(ledger)
    return ledger


def _safe_text(value, field):
    if type(value) is not str or not value.strip() or len(value) > MAX_TEXT:
        _refuse("field_invalid")
    if any(ord(char) < 32 or ord(char) > 126 for char in value):
        _refuse("field_invalid")
    if field == "source_url":
        separator = chr(58) + chr(47) + chr(47)
        if not value.startswith("https" + separator):
            _refuse("field_invalid")
        if not value.split(separator, 1)[1].split("/", 1)[0]:
            _refuse("field_invalid")
    elif chr(58) + chr(47) + chr(47) in value:
        _refuse("field_invalid")
    if field in ("exact_version", "platform_arch", "source_release_identity",
                 "source_url", "archive_set_identity", "outer_runner_image_revision",
                 "provenance_profile_version", "owner_acceptance_reference"):
        _reject_floating(value)
    return value


def _reject_floating(value):
    lowered = value.lower()
    if ("latest" in lowered or "stable" in lowered or "*" in value
            or "^" in value or "~" in value or ">=" in value or "<=" in value
            or re.search(r"(?:^|[.])x(?:$|[.])", lowered)
            or re.search(r"(?:^|\s)[<>]=?", lowered)
            or re.search(r"\|\|", lowered)
            or re.search(r"(?:^|\s)-\s", lowered)
            or lowered in ("main", "master", "head")):
        _refuse("floating_value")


def _valid_hash(value):
    return type(value) is str and HEX_256.fullmatch(value) is not None


def _valid_revision(value):
    return type(value) is str and REVISION.fullmatch(value) is not None


def _validate_pin_shape(row):
    pins = row["pins"]
    status = row["status"]
    fields = set(_pin_fields_for(row["id"]))
    if type(pins) is not dict or set(pins) != fields:
        _refuse("ledger_shape_invalid")
    if status != "admitted":
        if any(value != NOT_SET for value in pins.values()):
            _refuse("pin_partial")
        return
    for name, value in pins.items():
        if value == NOT_SET:
            continue
        if name in ("review_ids", "test_result_hashes"):
            if type(value) is not list or not value or len(value) > 128:
                _refuse("field_invalid")
        elif name == "signature_provenance_result":
            if (type(value) is not dict or set(value) != {"result", "identity", "evidence_sha256"}
                    or value.get("result") != "verified"
                    or type(value.get("identity")) is not str
                    or not value.get("identity")
                    or not _valid_hash(value.get("evidence_sha256"))):
                _refuse("field_invalid")
        elif type(value) is not str:
            _refuse("field_invalid")


def _metadata_valid(row):
    if type(row) is not dict:
        _refuse("ledger_shape_invalid")
    expected = {
        "id", "tool", "kind", "admission_path", "suites", "execution_location",
        "credential_class", "platforms", "targets", "status", "pins",
    }
    if set(row) != expected:
        _refuse("ledger_shape_invalid")
    for field in ("id", "tool"):
        _safe_text(row[field], field)
    if row["kind"] not in KINDS:
        _refuse("ledger_shape_invalid")
    if row["admission_path"] not in ADMISSION_PATHS:
        _refuse("ledger_shape_invalid")
    if row["execution_location"] not in LOCATIONS:
        _refuse("ledger_shape_invalid")
    if row["credential_class"] not in CREDENTIAL_CLASSES:
        _refuse("ledger_shape_invalid")
    for field in ("suites", "platforms", "targets"):
        values = row[field]
        if type(values) is not list or not values or len(values) > 32:
            _refuse("ledger_shape_invalid")
        for value in values:
            _safe_text(value, field)
        if len(values) != len(set(values)):
            _refuse("ledger_shape_invalid")
    if any(suite not in SUITES for suite in row["suites"]):
        _refuse("suite_invalid")


def validate_ledger(ledger):
    """Validate the complete inventory, pin-state rules, and location boundaries."""
    if type(ledger) is not dict or set(ledger) != {"schema_version", "suites", "rows"}:
        _refuse("ledger_shape_invalid")
    if type(ledger["schema_version"]) is not int or ledger["schema_version"] != SCHEMA_VERSION:
        _refuse("ledger_shape_invalid")
    if type(ledger["suites"]) is not list or tuple(ledger["suites"]) != SUITES:
        _refuse("suite_invalid")
    rows = ledger["rows"]
    if type(rows) is not list or len(rows) > MAX_ROWS:
        _refuse("ledger_shape_invalid")
    seen = set()
    for row in rows:
        _metadata_valid(row)
        row_id = row["id"]
        if row_id not in REQUIRED_ROW_IDS:
            _refuse("row_unknown")
        expected_policy = ROW_POLICY[row_id]
        submitted_policy = (
            row["kind"],
            row["admission_path"],
            row["execution_location"],
            row["credential_class"],
        )
        if row_id in SIGNING_ROW_IDS and row["execution_location"] != "trusted host":
            _refuse("signer_in_build_vm")
        if (row["credential_class"] in PRIVATE_CREDENTIAL_CLASSES
                and row["execution_location"] in ("build VM", "hosted outer runner")):
            _refuse("private_key_location")
        if submitted_policy != expected_policy:
            _refuse("row_policy_invalid")
        if row_id in seen:
            _refuse("row_duplicate")
        seen.add(row_id)
        if row["status"] not in ("not_set", "admitted", "parked", "deferred"):
            _refuse("status_invalid")
        if row_id == PARKED_ROW_ID and row["status"] != "parked":
            _refuse("pkcs11_not_parked")
        if row_id in DEFERRED_ROW_IDS and row["status"] != "deferred":
            _refuse("ios_not_deferred")
        if row_id not in DEFERRED_ROW_IDS and row_id != PARKED_ROW_ID:
            if row["status"] in ("parked", "deferred"):
                _refuse("status_invalid")
        _validate_pin_shape(row)
        if row_id == "release-cli" and "release.provenance" not in row["suites"]:
            _refuse("cli_provenance_missing")
        if row["status"] == "admitted":
            _validate_admitted_row(row)
    missing = set(REQUIRED_ROW_IDS) - seen
    if missing:
        _refuse("row_missing")
    return True


def _required_pin_fields(row):
    return set(_pin_fields_for(row["id"]))


def _pin_fields_for(row_id):
    if row_id not in ROW_POLICY:
        _refuse("row_unknown")
    kind, admission_path, execution_location, credential_class = ROW_POLICY[row_id]
    fields = list(BASE_PIN_FIELDS)
    if row_id in SOURCE_BUILT_ROW_IDS:
        fields.extend(("source_revision", "lock_vendor_digest", "executable_sha256"))
    if admission_path == "crate":
        fields.append("lock_vendor_digest")
    if execution_location == "build VM" or kind == "image_recipe":
        fields.extend(("recipe_sha256", "golden_image_digest"))
    if (admission_path in ("crate", "npm")
            or row_id == "dpkg-deb"
            or row_id in PACKAGE_MANAGER_ROW_IDS):
        fields.extend(("lock_sha256", "archive_set_identity"))
    if execution_location == "hosted outer runner":
        fields.extend((
            "outer_runner_image_revision",
            "installed_tool_inventory_digest",
            "recipe_sha256",
            "golden_image_digest",
        ))
    if row_id == "packer":
        fields.append("recipe_sha256")
    if row_id == "release-cli":
        fields.extend((
            "provenance_profile_version",
            "provenance_generator_source_sha256",
            "provenance_generator_binary_sha256",
            "provenance_verifier_source_sha256",
            "provenance_verifier_binary_sha256",
            "provenance_positive_result_sha256",
            "provenance_altered_subject_sha256",
            "provenance_wrong_role_key_sha256",
            "provenance_stale_build_sha256",
            "provenance_missing_build_sha256",
            "provenance_wrong_edge_sha256",
        ))
    if row_id in EXECUTABLE_ROW_IDS:
        fields.append("executable_sha256")
    return tuple(dict.fromkeys(fields))


MISSING_CODES = {
    "recipe_sha256": "image_pin_missing",
    "golden_image_digest": "image_pin_missing",
    "source_revision": "source_pin_missing",
    "lock_vendor_digest": "source_pin_missing",
    "executable_sha256": "executable_pin_missing",
    "lock_sha256": "package_pin_missing",
    "archive_set_identity": "package_pin_missing",
    "outer_runner_image_revision": "hosted_pin_missing",
    "installed_tool_inventory_digest": "hosted_pin_missing",
    "provenance_profile_version": "provenance_profile_missing",
    "provenance_generator_source_sha256": "provenance_generator_source_missing",
    "provenance_generator_binary_sha256": "provenance_generator_binary_missing",
    "provenance_verifier_source_sha256": "provenance_verifier_source_missing",
    "provenance_verifier_binary_sha256": "provenance_verifier_binary_missing",
    "provenance_positive_result_sha256": "provenance_positive_missing",
    "provenance_altered_subject_sha256": "provenance_altered_subject_missing",
    "provenance_wrong_role_key_sha256": "provenance_wrong_role_key_missing",
    "provenance_stale_build_sha256": "provenance_stale_build_missing",
    "provenance_missing_build_sha256": "provenance_missing_build_missing",
    "provenance_wrong_edge_sha256": "provenance_wrong_edge_missing",
}


def _missing(row, field, code="field_missing"):
    value = row["pins"].get(field, NOT_SET)
    if value == NOT_SET:
        _refuse(code)
    return value


def _validate_admitted_row(row):
    pins = row["pins"]
    required = _required_pin_fields(row)
    for field in required:
        code = MISSING_CODES.get(field, "field_missing")
        if field == "executable_sha256" and row["id"] in SOURCE_BUILT_ROW_IDS:
            code = "source_pin_missing"
        _missing(row, field, code)
    for field in (
        "exact_version", "platform_arch", "source_release_identity", "source_url",
        "archive_set_identity", "acquisition_method", "owner_acceptance_reference",
    ):
        if field in required:
            _safe_text(pins[field], field)
    for field in HASH_FIELDS.intersection(required):
        if not _valid_hash(pins[field]):
            _refuse("field_invalid")
    if "source_revision" in required and not _valid_revision(pins["source_revision"]):
        _refuse("field_invalid")
    if "golden_image_digest" in required and not _valid_hash(pins["golden_image_digest"]):
        _refuse("image_pin_missing")
    if "recipe_sha256" in required and not _valid_hash(pins["recipe_sha256"]):
        _refuse("image_pin_missing")
    if "source_revision" in required:
        if (not _valid_revision(pins["source_revision"])
                or not _valid_hash(pins["lock_vendor_digest"])
                or not _valid_hash(pins["executable_sha256"])):
            _refuse("source_pin_missing")
    if "lock_sha256" in required:
        if (not _valid_hash(pins["lock_sha256"])
                or not _safe_text(pins["archive_set_identity"], "archive_set_identity")):
            _refuse("package_pin_missing")
    if ROW_POLICY[row["id"]][2] == "hosted outer runner":
        if (not _safe_text(pins["outer_runner_image_revision"], "outer_runner_image_revision")
                or not _valid_hash(pins["installed_tool_inventory_digest"])):
            _refuse("hosted_pin_missing")
    signature = pins["signature_provenance_result"]
    if (type(signature) is not dict or set(signature) != {"result", "identity", "evidence_sha256"}
            or signature["result"] != "verified"
            or not _valid_hash(signature["evidence_sha256"])):
        _refuse("field_invalid")
    _safe_text(signature["identity"], "source_release_identity")
    for field in ("review_ids", "test_result_hashes"):
        values = pins[field]
        if type(values) is not list or not values or len(values) > 128:
            _refuse("field_invalid")
        for value in values:
            if field == "test_result_hashes":
                if not _valid_hash(value):
                    _refuse("field_invalid")
            elif type(value) is not str or IDENTIFIER.fullmatch(value) is None:
                _refuse("field_invalid")
    method = pins["acquisition_method"].lower().replace("_", " ").replace("-", " ")
    if ("cargo install" in method or re.search(r"\bnpx\b", method)
            or ("gradle" in method and "resolution" in method and "offline" not in method)
            or ("mutable" in method and ("package manager" in method or "install" in method))
            or ("apt" in method and ("moving" in method or "mutable" in method
                                      or ("update" in method and "snapshot" not in method)))
            or ("download" in method and "checkout" in method)):
        _refuse("forbidden_acquisition")
    if row["id"] == "release-cli":
        if "release.provenance" not in row["suites"]:
            _refuse("cli_provenance_missing")
        provenance_fields = (
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
        for field, code in provenance_fields:
            value = _missing(row, field, code)
            if field == "provenance_profile_version":
                _safe_text(value, field)
            elif not _valid_hash(value):
                _refuse(code)
    return True


def first_use_gate(ledger, row_id):
    """Return the admitted row only after complete-ledger and first-use checks."""
    if type(ledger) is bytes:
        ledger = load_ledger_bytes(ledger)
    validate_ledger(ledger)
    if type(row_id) is not str or row_id not in REQUIRED_ROW_IDS:
        _refuse("row_unknown")
    for row in ledger["rows"]:
        if row["id"] == row_id:
            if row["status"] != "admitted":
                _refuse("row_not_admitted")
            _validate_admitted_row(row)
            return row
    _refuse("row_missing")
