"""Bounded, deterministic CycloneDX inventory normalization and merge."""

import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import uuid
from pathlib import Path
from urllib.parse import quote, unquote

try:
    from . import cargo_lock_receipt as _cargo_lock_receipt
except ImportError:
    import cargo_lock_receipt as _cargo_lock_receipt


NORMALIZER_VERSION = 1
CYCLONEDX_SPEC_VERSION = "1.5"
CYCLONEDX_SPEC_VERSION_PRIMARY_SOURCE_RECHECK_REQUIRED = True
MAX_SBOM_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_LOCK_BYTES = (4 * 1024 * 1024) - (64 * 1024)
MAX_INVENTORY_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
MAX_INVENTORY_NODES = 1_000_000
MAX_JSON_STRING = 32_768
MAX_COMPONENTS = 50_000
MAX_TOOLS = 64
MAX_LICENSES = 32
MAX_DEPENDENCIES = 100_000
SAFE_INTEGER = 9_007_199_254_740_991
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
HEX128_RE = re.compile(r"[a-f0-9]{128}\Z")
NPM_NAME_RE = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*\Z")
VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
REFUSAL_CODES = frozenset((
    "sbom_input_oversize", "sbom_json_invalid", "sbom_duplicate_key",
    "sbom_unknown_field", "sbom_unsupported_field", "sbom_spec_version",
    "sbom_document_invalid", "sbom_component_invalid", "sbom_purl_invalid",
    "sbom_hash_invalid", "sbom_hash_conflict", "sbom_license_invalid",
    "sbom_license_conflict", "sbom_identity_conflict", "sbom_duplicate_identity",
    "sbom_coverage_missing", "sbom_coverage_extra", "sbom_dependency_invalid",
    "sbom_lock_invalid", "sbom_lock_hash_mismatch", "sbom_inventory_invalid",
    "sbom_schema_invalid",
))
TOP_LEVEL_FIELDS = frozenset((
    "bomFormat", "specVersion", "serialNumber", "version", "metadata",
    "components", "dependencies",
))
UNSUPPORTED_TOP_LEVEL_FIELDS = frozenset((
    "services", "externalReferences", "compositions", "vulnerabilities",
    "annotations", "formulation", "declarations", "definitions", "properties",
    "signature",
))
COMPONENT_FIELDS = frozenset((
    "type", "bom-ref", "name", "version", "purl", "hashes", "licenses",
    "scope", "description",
))
TOOL_FIELDS = frozenset(("vendor", "name", "version", "hashes"))
METADATA_FIELDS = frozenset(("timestamp", "tools", "component"))
IGNORED_VOLATILE_METADATA_FIELDS = frozenset(("timestamp",))


class SbomRefusal(Exception):
    """A refusal with a stable code and no caller-controlled message."""

    def __init__(self, code):
        if code not in REFUSAL_CODES:
            code = "sbom_document_invalid"
        self.code = code
        self.reason = code
        super().__init__(code)


def _refuse(code):
    raise SbomRefusal(code)


def _exact_dict(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _safe_text(value, maximum=4096, allow_empty=False):
    if type(value) is not str or len(value) > maximum or (not allow_empty and not value):
        return False
    return all(ord(character) >= 32 and not 55296 <= ord(character) <= 57343 for character in value)


def _valid_serial_number(value):
    if not _safe_text(value, 45) or not value.startswith("urn:uuid:"):
        return False
    try:
        identifier = uuid.UUID(value[len("urn:uuid:"):])
    except (ValueError, AttributeError):
        return False
    return value == "urn:uuid:" + str(identifier)


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse("sbom_duplicate_key")
        result[key] = value
    return result


def _json_integer(value):
    if len(value) > 16:
        _refuse("sbom_json_invalid")
    try:
        result = int(value)
    except ValueError:
        _refuse("sbom_json_invalid")
    if abs(result) > SAFE_INTEGER:
        _refuse("sbom_json_invalid")
    return result


def _json_float(value):
    _refuse("sbom_json_invalid")


def _json_constant(value):
    _refuse("sbom_json_invalid")


def _check_json_tree(value, max_nodes=MAX_JSON_NODES):
    pending = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > max_nodes or depth > MAX_JSON_DEPTH:
            _refuse("sbom_json_invalid")
        if type(current) is str:
            if not _safe_text(current, MAX_JSON_STRING, allow_empty=True):
                _refuse("sbom_json_invalid")
        elif type(current) is dict:
            for key, item in current.items():
                if not _safe_text(key, MAX_JSON_STRING, allow_empty=True):
                    _refuse("sbom_json_invalid")
                pending.append((item, depth + 1))
        elif type(current) is list:
            pending.extend((item, depth + 1) for item in current)
        elif current is None or type(current) in (bool, int):
            continue
        else:
            _refuse("sbom_json_invalid")


def parse_generator_output(data):
    """Parse one bounded generator document and reject unsupported top-level data."""
    if type(data) is not bytes:
        _refuse("sbom_json_invalid")
    if len(data) > MAX_SBOM_BYTES:
        _refuse("sbom_input_oversize")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeError:
        _refuse("sbom_json_invalid")
    if text.startswith("\ufeff"):
        _refuse("sbom_json_invalid")
    try:
        document = json.loads(
            text,
            object_pairs_hook=_json_object,
            parse_int=_json_integer,
            parse_float=_json_float,
            parse_constant=_json_constant,
        )
    except SbomRefusal:
        raise
    except (ValueError, TypeError, RecursionError):
        _refuse("sbom_json_invalid")
    _check_json_tree(document)
    if type(document) is not dict:
        _refuse("sbom_document_invalid")
    keys = set(document)
    if keys & UNSUPPORTED_TOP_LEVEL_FIELDS:
        _refuse("sbom_unsupported_field")
    if keys - TOP_LEVEL_FIELDS:
        _refuse("sbom_unknown_field")
    if document.get("bomFormat") != "CycloneDX":
        _refuse("sbom_document_invalid")
    if document.get("specVersion") != CYCLONEDX_SPEC_VERSION:
        _refuse("sbom_spec_version")
    if type(document.get("version")) is not int or document["version"] < 1:
        _refuse("sbom_document_invalid")
    serial_number = document.get("serialNumber")
    if serial_number is not None and not _valid_serial_number(serial_number):
        _refuse("sbom_document_invalid")
    return document


def _valid_name(ecosystem, name):
    if not _safe_text(name, 214):
        return False
    if ecosystem == "npm":
        return NPM_NAME_RE.fullmatch(name) is not None and ".." not in name
    return _cargo_lock_receipt.PACKAGE_NAME_RE.fullmatch(name) is not None


def _valid_version(version):
    if type(version) is not str or len(version) > 128 or VERSION_RE.fullmatch(version) is None:
        return False
    core = version.split("+", 1)[0]
    if "-" in core:
        for identifier in core.split("-", 1)[1].split("."):
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                return False
    return True


def _purl_for(ecosystem, name, version):
    if ecosystem not in ("cargo", "npm") or not _valid_name(ecosystem, name) or not _valid_version(version):
        _refuse("sbom_purl_invalid")
    safe_name = "/-._~" if ecosystem == "npm" else "-._~"
    return "pkg:" + ecosystem + "/" + quote(name, safe=safe_name) + "@" + quote(version, safe="-._~")


def _purl_identity(value, ecosystem):
    if not _safe_text(value, 4096):
        _refuse("sbom_purl_invalid")
    prefix = "pkg:" + ecosystem + "/"
    if not value.startswith(prefix) or "?" in value or chr(35) in value:
        _refuse("sbom_purl_invalid")
    body = value[len(prefix):]
    if "@" not in body:
        _refuse("sbom_purl_invalid")
    encoded_name, encoded_version = body.rsplit("@", 1)
    try:
        name = unquote(encoded_name, errors="strict")
        version = unquote(encoded_version, errors="strict")
    except (UnicodeError, ValueError):
        _refuse("sbom_purl_invalid")
    if not _valid_name(ecosystem, name) or not _valid_version(version):
        _refuse("sbom_purl_invalid")
    return name, version


def _normalise_hashes(value, source_hashes=None):
    result = {}
    if value is not None:
        if type(value) is not list or len(value) > 32:
            _refuse("sbom_hash_invalid")
        for item in value:
            if type(item) is not dict or set(item) != {"alg", "content"}:
                _refuse("sbom_hash_invalid")
            algorithm = item["alg"]
            content = item["content"]
            if type(algorithm) is not str:
                _refuse("sbom_hash_invalid")
            normalized_algorithm = algorithm.upper().replace("_", "-")
            if normalized_algorithm not in ("SHA-256", "SHA-512"):
                _refuse("sbom_hash_invalid")
            pattern = HEX64_RE if normalized_algorithm == "SHA-256" else HEX128_RE
            if type(content) is not str or pattern.fullmatch(content.lower()) is None:
                _refuse("sbom_hash_invalid")
            content = content.lower()
            if normalized_algorithm in result and result[normalized_algorithm] != content:
                _refuse("sbom_hash_conflict")
            result[normalized_algorithm] = content
    for algorithm, content in (source_hashes or {}).items():
        if algorithm in result and result[algorithm] != content:
            _refuse("sbom_hash_conflict")
        result[algorithm] = content
    return result


def _normalise_licenses(value, locked_license=None):
    expressions = []
    if value is not None:
        if type(value) is not list or len(value) > MAX_LICENSES:
            _refuse("sbom_license_invalid")
        if len(value) > 1:
            _refuse("sbom_unsupported_field")
        for choice in value:
            if type(choice) is not dict or len(choice) != 1:
                _refuse("sbom_license_invalid")
            if "expression" in choice:
                expression = choice["expression"]
            elif "license" in choice:
                license_value = choice["license"]
                if type(license_value) is not dict or set(license_value) != {"id"}:
                    _refuse("sbom_unsupported_field")
                expression = license_value["id"]
            else:
                _refuse("sbom_unsupported_field")
            if not _safe_text(expression, 4096):
                _refuse("sbom_license_invalid")
            expressions.append(expression)
    if locked_license is not None:
        if not _safe_text(locked_license, 4096):
            _refuse("sbom_license_invalid")
        if expressions and expressions != [locked_license]:
            _refuse("sbom_license_conflict")
        if not expressions:
            expressions = [locked_license]
    return expressions


def _normalise_tools(value):
    if value is None:
        return []
    if type(value) is not list or len(value) > MAX_TOOLS:
        _refuse("sbom_unsupported_field")
    tools = []
    for item in value:
        if type(item) is not dict or set(item) - TOOL_FIELDS:
            _refuse("sbom_unsupported_field")
        if not _safe_text(item.get("name"), 256):
            _refuse("sbom_document_invalid")
        tool = {"name": item["name"]}
        for field in ("vendor", "version"):
            if field in item:
                if not _safe_text(item[field], 4096):
                    _refuse("sbom_document_invalid")
                tool[field] = item[field]
        if "hashes" in item:
            hashes = _normalise_hashes(item["hashes"])
            tool["hashes"] = [
                {"alg": algorithm, "content": hashes[algorithm]}
                for algorithm in sorted(hashes)
            ]
        tools.append(tool)
    unique = {}
    for tool in tools:
        encoded = _canonical_bytes(tool)
        unique[encoded] = tool
    return [unique[key] for key in sorted(unique)]


def _cargo_inventory(lock_bytes):
    try:
        lock = _cargo_lock_receipt.parse_cargo_lock(lock_bytes)
    except _cargo_lock_receipt.Refusal:
        _refuse("sbom_lock_invalid")
    records = {}
    packages_by_name = {}
    for package in lock["packages"]:
        name = package["name"]
        version = package["version"]
        purl = _purl_for("cargo", name, version)
        source_hashes = {}
        checksum = package.get("checksum")
        if checksum is not None:
            if HEX64_RE.fullmatch(checksum) is None:
                _refuse("sbom_lock_invalid")
            source_hashes["SHA-256"] = checksum
        record = {
            "ecosystem": "cargo",
            "name": name,
            "version": version,
            "purl": purl,
            "kind": "registry" if package.get("source") else "workspace",
            "hashes": source_hashes,
            "license": None,
            "dependencies": set(),
        }
        if purl in records:
            _refuse("sbom_inventory_invalid")
        records[purl] = record
        packages_by_name.setdefault(name, []).append(package)
    for package in lock["packages"]:
        source_purl = _purl_for("cargo", package["name"], package["version"])
        for dependency_name, dependency_version, dependency_source in package.get("dependencies", []):
            candidates = packages_by_name.get(dependency_name, [])
            if dependency_version is not None:
                candidates = [item for item in candidates if item["version"] == dependency_version]
            if dependency_source is not None:
                candidates = [item for item in candidates if item.get("source") == dependency_source]
            if len(candidates) != 1:
                _refuse("sbom_lock_invalid")
            target = candidates[0]
            records[source_purl]["dependencies"].add(
                _purl_for("cargo", target["name"], target["version"])
            )
    return records


def _npm_source_hash(integrity):
    if not _safe_text(integrity, 128):
        _refuse("sbom_inventory_invalid")
    algorithm, separator, encoded = integrity.partition("-")
    if separator != "-" or algorithm != "sha512":
        _refuse("sbom_inventory_invalid")
    try:
        digest = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeError, binascii.Error):
        _refuse("sbom_inventory_invalid")
    if len(digest) != 64 or base64.b64encode(digest).decode("ascii") != encoded:
        _refuse("sbom_inventory_invalid")
    return digest.hex()


def _derive_npm_inventory(package_lock_bytes, expected_manifest, node_executable):
    if type(package_lock_bytes) is not bytes or len(package_lock_bytes) > MAX_PACKAGE_LOCK_BYTES:
        _refuse("sbom_lock_invalid")
    if (type(node_executable) is not str or not os.path.isabs(node_executable)
            or not _safe_text(node_executable, 4096)):
        _refuse("sbom_inventory_invalid")
    expectation_bytes = _canonical_bytes(expected_manifest)
    if len(expectation_bytes) > 262_144:
        _refuse("sbom_inventory_invalid")
    envelope = _canonical_bytes({
        "expected": expected_manifest,
        "lockBase64": base64.b64encode(package_lock_bytes).decode("ascii"),
    })
    helper = Path(__file__).with_name("node_lock_inventory.mjs")
    environment = {key: os.environ[key] for key in ("SystemRoot", "WINDIR") if key in os.environ}
    environment["NODE_OPTIONS"] = ""
    try:
        result = subprocess.run(
            [node_executable, str(helper)], input=envelope, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=environment, timeout=60, check=False,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        _refuse("sbom_inventory_invalid")
    if result.returncode != 0:
        _refuse("sbom_lock_invalid")
    if len(result.stdout) > MAX_INVENTORY_BYTES:
        _refuse("sbom_inventory_invalid")
    try:
        inventory = json.loads(
            result.stdout.decode("utf-8", "strict"), object_pairs_hook=_json_object,
            parse_int=_json_integer, parse_float=_json_float, parse_constant=_json_constant,
        )
        _check_json_tree(inventory, MAX_INVENTORY_NODES)
    except (UnicodeError, ValueError, TypeError, RecursionError, SbomRefusal):
        _refuse("sbom_inventory_invalid")
    return inventory


def _npm_inventory(package_lock_bytes, inventory):
    if type(package_lock_bytes) is not bytes or len(package_lock_bytes) > MAX_PACKAGE_LOCK_BYTES:
        _refuse("sbom_lock_invalid")
    if type(inventory) is not dict or set(inventory) != {
            "inventoryVersion", "packageCount", "lockfileVersion", "lockSha256", "packages"}:
        _refuse("sbom_inventory_invalid")
    if inventory["inventoryVersion"] != 1:
        _refuse("sbom_inventory_invalid")
    if type(inventory["packageCount"]) is not int or not 1 <= inventory["packageCount"] <= 50_000:
        _refuse("sbom_inventory_invalid")
    if inventory["lockfileVersion"] != 3:
        _refuse("sbom_inventory_invalid")
    if type(inventory["lockSha256"]) is not str or HEX64_RE.fullmatch(inventory["lockSha256"]) is None:
        _refuse("sbom_inventory_invalid")
    lock_sha256 = hashlib.sha256(package_lock_bytes).hexdigest()
    if inventory["lockSha256"] != lock_sha256:
        _refuse("sbom_lock_hash_mismatch")
    packages = inventory["packages"]
    if (type(packages) is not list or not packages or len(packages) > 50_000
            or len(packages) > inventory["packageCount"]):
        _refuse("sbom_inventory_invalid")
    records = {}
    for package in packages:
        if type(package) is not dict or set(package) != {
                "name", "version", "kind", "integrity", "license", "dependencies"}:
            _refuse("sbom_inventory_invalid")
        name = package["name"]
        version = package["version"]
        kind = package["kind"]
        if not _valid_name("npm", name) or not _valid_version(version):
            _refuse("sbom_inventory_invalid")
        if kind not in ("root", "workspace", "registry"):
            _refuse("sbom_inventory_invalid")
        if kind == "registry":
            if type(package["integrity"]) is not str:
                _refuse("sbom_inventory_invalid")
            hashes = {"SHA-512": _npm_source_hash(package["integrity"])}
        else:
            if package["integrity"] is not None:
                _refuse("sbom_inventory_invalid")
            hashes = {}
        locked_license = package["license"]
        if locked_license is not None and not _safe_text(locked_license, 4096):
            _refuse("sbom_inventory_invalid")
        dependencies = package["dependencies"]
        if type(dependencies) is not list or len(dependencies) > MAX_DEPENDENCIES:
            _refuse("sbom_inventory_invalid")
        purl = _purl_for("npm", name, version)
        dependency_purls = set()
        for dependency in dependencies:
            if type(dependency) is not dict or set(dependency) != {"name", "version"}:
                _refuse("sbom_inventory_invalid")
            dependency_name = dependency["name"]
            dependency_version = dependency["version"]
            if not _valid_name("npm", dependency_name) or not _valid_version(dependency_version):
                _refuse("sbom_inventory_invalid")
            dependency_purl = _purl_for("npm", dependency_name, dependency_version)
            if dependency_purl in dependency_purls:
                _refuse("sbom_inventory_invalid")
            dependency_purls.add(dependency_purl)
        record = records.get(purl)
        if record is None:
            record = {
                "ecosystem": "npm",
                "name": name,
                "version": version,
                "purl": purl,
                "kind": kind,
                "hashes": hashes,
                "license": locked_license,
                "dependencies": dependency_purls,
            }
            records[purl] = record
        elif (record["hashes"] != hashes
              or record["license"] != locked_license
              or record["kind"] != kind
              or record["dependencies"] != dependency_purls):
            _refuse("sbom_identity_conflict")
    record_keys = set(records)
    for record in records.values():
        if record["dependencies"] - record_keys:
            _refuse("sbom_inventory_invalid")
    return records


def _register_alias(aliases, reference, purl):
    if not _safe_text(reference, 4096):
        _refuse("sbom_component_invalid")
    prior = aliases.get(reference)
    if prior is not None and prior != purl:
        _refuse("sbom_identity_conflict")
    aliases[reference] = purl


def _normalise_component(component, ecosystem, expected, aliases, observed, is_root=False):
    if type(component) is not dict:
        _refuse("sbom_component_invalid")
    unsupported = set(component) - COMPONENT_FIELDS
    if unsupported:
        _refuse("sbom_unsupported_field")
    name = component.get("name")
    version = component.get("version")
    if not _valid_name(ecosystem, name) or not _valid_version(version):
        _refuse("sbom_component_invalid")
    purl = _purl_for(ecosystem, name, version)
    locked = expected.get(purl)
    if locked is None:
        _refuse("sbom_coverage_extra")
    raw_purl = component.get("purl")
    if raw_purl is not None and _purl_identity(raw_purl, ecosystem) != (name, version):
        _refuse("sbom_purl_invalid")
    component_type = component.get(
        "type", "application" if is_root or locked["kind"] == "root" else "library",
    )
    if component_type not in ("application", "library"):
        _refuse("sbom_component_invalid")
    licenses = _normalise_licenses(component.get("licenses"), locked["license"])
    output = {
        "type": component_type,
        "bom-ref": purl,
        "name": name,
        "version": version,
        "purl": purl,
    }
    if licenses:
        output["licenses"] = [{"expression": expression} for expression in licenses]
    hashes = _normalise_hashes(component.get("hashes"), locked["hashes"])
    if hashes:
        output["hashes"] = [
            {"alg": algorithm, "content": hashes[algorithm]}
            for algorithm in sorted(hashes)
        ]
    if "scope" in component:
        if component["scope"] not in ("required", "optional", "excluded"):
            _refuse("sbom_component_invalid")
        output["scope"] = component["scope"]
    if "description" in component:
        if not _safe_text(component["description"], 16_384, allow_empty=True):
            _refuse("sbom_component_invalid")
        output["description"] = component["description"]
    if purl in observed:
        if observed[purl] == output:
            _refuse("sbom_duplicate_identity")
        _refuse("sbom_identity_conflict")
    observed[purl] = output
    _register_alias(aliases, purl, purl)
    if "bom-ref" in component:
        _register_alias(aliases, component["bom-ref"], purl)
    if raw_purl is not None:
        _register_alias(aliases, raw_purl, purl)
    return purl


def _normalise_generator(document, ecosystem, expected):
    metadata = document.get("metadata", {})
    if type(metadata) is not dict:
        _refuse("sbom_document_invalid")
    if set(metadata) - METADATA_FIELDS:
        _refuse("sbom_unsupported_field")
    for field in IGNORED_VOLATILE_METADATA_FIELDS:
        if field in metadata and not _safe_text(metadata[field], 128):
            _refuse("sbom_document_invalid")
    tools = _normalise_tools(metadata.get("tools"))
    components = document.get("components", [])
    if type(components) is not list or len(components) > MAX_COMPONENTS:
        _refuse("sbom_document_invalid")
    observed = {}
    aliases = {}
    if "component" in metadata:
        _normalise_component(metadata["component"], ecosystem, expected, aliases, observed, is_root=True)
    for component in components:
        _normalise_component(component, ecosystem, expected, aliases, observed)
    missing = set(expected) - set(observed)
    if missing:
        _refuse("sbom_coverage_missing")
    dependencies = document.get("dependencies", [])
    if type(dependencies) is not list or len(dependencies) > MAX_DEPENDENCIES:
        _refuse("sbom_dependency_invalid")
    actual_edges = set()
    dependency_refs = set()
    for dependency in dependencies:
        if type(dependency) is not dict or set(dependency) - {"ref", "dependsOn"}:
            _refuse("sbom_dependency_invalid")
        reference = dependency.get("ref")
        if not _safe_text(reference, 4096):
            _refuse("sbom_dependency_invalid")
        source = aliases.get(reference)
        if source is None or source in dependency_refs:
            _refuse("sbom_dependency_invalid")
        dependency_refs.add(source)
        targets = dependency.get("dependsOn", [])
        if type(targets) is not list or len(targets) > MAX_COMPONENTS:
            _refuse("sbom_dependency_invalid")
        for target_reference in targets:
            if not _safe_text(target_reference, 4096):
                _refuse("sbom_dependency_invalid")
            target = aliases.get(target_reference)
            if target is None or (source, target) in actual_edges:
                _refuse("sbom_dependency_invalid")
            actual_edges.add((source, target))
    expected_edges = {
        (source, target)
        for source, record in expected.items()
        for target in record["dependencies"]
    }
    if actual_edges != expected_edges:
        _refuse("sbom_dependency_invalid")
    if set(dependency_refs) - set(expected):
        _refuse("sbom_dependency_invalid")
    return {"components": observed, "tools": tools}


def _canonical_bytes(value):
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _refuse("sbom_json_invalid")


def validate_pinned_schema_subset(document):
    """Validate the output shape implemented for the pinned CycloneDX subset."""
    top_fields = {"bomFormat", "specVersion", "serialNumber", "version", "metadata", "components", "dependencies"}
    if type(document) is not dict or set(document) != top_fields:
        _refuse("sbom_schema_invalid")
    if (document["bomFormat"] != "CycloneDX"
            or document["specVersion"] != CYCLONEDX_SPEC_VERSION
            or type(document["version"]) is not int or document["version"] != 1
            or not _valid_serial_number(document["serialNumber"])):
        _refuse("sbom_schema_invalid")
    metadata = document["metadata"]
    if type(metadata) is not dict or set(metadata) - {"component", "tools"}:
        _refuse("sbom_schema_invalid")
    root = metadata.get("component")
    if type(root) is not dict or set(root) != {"type", "bom-ref", "name", "version", "purl"}:
        _refuse("sbom_schema_invalid")
    if (root["type"] != "application" or root["bom-ref"] != root["purl"]
            or not _safe_text(root["name"], 256)
            or not _safe_text(root["version"], 128)
            or root["purl"] != "pkg:generic/release-inventory@1"):
        _refuse("sbom_schema_invalid")
    components = document["components"]
    if type(components) is not list or len(components) > MAX_COMPONENTS:
        _refuse("sbom_schema_invalid")
    refs = {root["bom-ref"]}
    previous_ref = ""
    for component in components:
        if type(component) is not dict:
            _refuse("sbom_schema_invalid")
        allowed = COMPONENT_FIELDS | {"hashes"}
        required = {"type", "bom-ref", "name", "version", "purl"}
        if set(component) - allowed or not required.issubset(component):
            _refuse("sbom_schema_invalid")
        if (component["type"] not in ("application", "library")
                or component["bom-ref"] != component["purl"]
                or not _safe_text(component["name"], 214)
                or not _safe_text(component["version"], 128)
                or not _safe_text(component["purl"], 4096)
                or component["purl"] in refs
                or component["purl"] < previous_ref):
            _refuse("sbom_schema_invalid")
        ecosystem = "cargo" if component["purl"].startswith("pkg:cargo/") else "npm"
        if not component["purl"].startswith(("pkg:cargo/", "pkg:npm/")):
            _refuse("sbom_schema_invalid")
        try:
            identity = _purl_identity(component["purl"], ecosystem)
        except SbomRefusal:
            _refuse("sbom_schema_invalid")
        if (identity != (component["name"], component["version"])
                or not _valid_name(ecosystem, component["name"])
                or not _valid_version(component["version"])):
            _refuse("sbom_schema_invalid")
        refs.add(component["purl"])
        previous_ref = component["purl"]
        if "scope" in component and component["scope"] not in ("required", "optional", "excluded"):
            _refuse("sbom_schema_invalid")
        if "description" in component and not _safe_text(component["description"], 16_384, allow_empty=True):
            _refuse("sbom_schema_invalid")
        if "licenses" in component:
            if type(component["licenses"]) is not list or len(component["licenses"]) != 1:
                _refuse("sbom_schema_invalid")
            for license_choice in component["licenses"]:
                if (type(license_choice) is not dict or set(license_choice) != {"expression"}
                        or not _safe_text(license_choice["expression"], 4096)):
                    _refuse("sbom_schema_invalid")
        if "hashes" in component:
            hashes = component["hashes"]
            if type(hashes) is not list:
                _refuse("sbom_schema_invalid")
            try:
                _normalise_hashes(hashes)
            except SbomRefusal:
                _refuse("sbom_schema_invalid")
    tools = metadata.get("tools", [])
    if type(tools) is not list or len(tools) > MAX_TOOLS:
        _refuse("sbom_schema_invalid")
    for tool in tools:
        if type(tool) is not dict or set(tool) - TOOL_FIELDS or not _safe_text(tool.get("name"), 256):
            _refuse("sbom_schema_invalid")
        for field in ("vendor", "version"):
            if field in tool and not _safe_text(tool[field], 4096):
                _refuse("sbom_schema_invalid")
        if "hashes" in tool:
            try:
                _normalise_hashes(tool["hashes"])
            except SbomRefusal:
                _refuse("sbom_schema_invalid")
    dependencies = document["dependencies"]
    if type(dependencies) is not list or len(dependencies) != len(refs):
        _refuse("sbom_schema_invalid")
    dependency_refs = set()
    previous_ref = ""
    for dependency in dependencies:
        if type(dependency) is not dict or set(dependency) != {"ref", "dependsOn"}:
            _refuse("sbom_schema_invalid")
        reference = dependency["ref"]
        targets = dependency["dependsOn"]
        if (not _safe_text(reference, 4096) or type(targets) is not list
                or any(not _safe_text(target, 4096) for target in targets)):
            _refuse("sbom_schema_invalid")
        if (reference not in refs or reference in dependency_refs or reference < previous_ref
                or targets != sorted(set(targets)) or any(target not in refs for target in targets)):
            _refuse("sbom_schema_invalid")
        dependency_refs.add(reference)
        previous_ref = reference
    if dependency_refs != refs:
        _refuse("sbom_schema_invalid")
    return True


def merge_normalized(cargo, npm):
    """Merge two already lock-checked inventories and return canonical JSON bytes."""
    components = {}
    edges = {}
    tools = {}
    normalizer_tool = {
        "vendor": "KeelDock",
        "name": "KeelDock CycloneDX normalizer",
        "version": str(NORMALIZER_VERSION),
    }
    tools[_canonical_bytes(normalizer_tool)] = normalizer_tool
    for normalized in (cargo, npm):
        if type(normalized) is not dict or set(normalized) != {"components", "tools"}:
            _refuse("sbom_document_invalid")
        if type(normalized["components"]) is not dict or type(normalized["tools"]) is not list:
            _refuse("sbom_document_invalid")
        for purl, component in normalized["components"].items():
            if purl in components:
                if components[purl] == component:
                    _refuse("sbom_duplicate_identity")
                _refuse("sbom_identity_conflict")
            components[purl] = component
        for tool in normalized["tools"]:
            encoded = _canonical_bytes(tool)
            tools[encoded] = tool
    for purl in components:
        edges[purl] = set()
    for normalized in (cargo, npm):
        for purl, component in normalized["components"].items():
            for dependency in component.get("_dependsOn", ()):
                edges[purl].add(dependency)
    all_package_refs = sorted(components)
    root_ref = "pkg:generic/release-inventory@1"
    root = {
        "type": "application",
        "bom-ref": root_ref,
        "name": "KeelDock release inventory",
        "version": "1",
        "purl": root_ref,
    }
    output_components = []
    for purl in all_package_refs:
        component = dict(components[purl])
        component.pop("_dependsOn", None)
        output_components.append(component)
    dependency_map = {purl: sorted(edges[purl]) for purl in all_package_refs}
    dependency_map[root_ref] = all_package_refs
    base = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": root,
            "tools": [tools[key] for key in sorted(tools)],
        } if tools else {"component": root},
        "components": output_components,
        "dependencies": [
            {"ref": reference, "dependsOn": dependency_map[reference]}
            for reference in sorted(dependency_map)
        ],
    }
    serial_digest = hashlib.sha256(_canonical_bytes(base)).hexdigest()
    base["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, serial_digest))
    validate_pinned_schema_subset(base)
    return _canonical_bytes(base) + b"\n"


def _attach_edges(normalized, expected):
    for purl, component in normalized["components"].items():
        component["_dependsOn"] = tuple(sorted(expected[purl]["dependencies"]))
    return normalized


def normalize_and_merge(
        cargo_sbom_bytes, npm_sbom_bytes, cargo_lock_bytes, package_lock_bytes,
        npm_lock_context):
    """Derive npm inventory from exact lock bytes and return the merged document."""
    if type(npm_lock_context) is not dict or set(npm_lock_context) != {"expected", "nodeExecutable"}:
        _refuse("sbom_inventory_invalid")
    cargo_document = parse_generator_output(cargo_sbom_bytes)
    npm_document = parse_generator_output(npm_sbom_bytes)
    cargo_expected = _cargo_inventory(cargo_lock_bytes)
    npm_lock_inventory = _derive_npm_inventory(
        package_lock_bytes, npm_lock_context["expected"], npm_lock_context["nodeExecutable"],
    )
    npm_expected = _npm_inventory(package_lock_bytes, npm_lock_inventory)
    cargo_normalized = _normalise_generator(cargo_document, "cargo", cargo_expected)
    npm_normalized = _normalise_generator(npm_document, "npm", npm_expected)
    _attach_edges(cargo_normalized, cargo_expected)
    _attach_edges(npm_normalized, npm_expected)
    return merge_normalized(cargo_normalized, npm_normalized)
