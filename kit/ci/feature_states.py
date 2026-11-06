"""Bounded strength-two feature-state coverage planning for CI manifests."""

import hashlib
import json
import re


SCHEMA_VERSION = 1
STATES = ("disabled", "free", "licensed")
ID_RE = re.compile(r"[a-z][a-z0-9._-]{0,95}\Z")
SHA40_RE = re.compile(r"[a-f0-9]{40}\Z")
SHA64_RE = re.compile(r"[a-f0-9]{64}\Z")
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_FEATURES = 96
MAX_ASSERTIONS = 100000
MAX_CASES = 50000
MAX_ARMS = 32
MAX_SHARDS = 128
INVENTORY_FIELDS = frozenset((
    "schema_version", "source_sha", "catalogue_sha256", "features", "matrix_arms",
    "shard_count", "max_cases", "max_assertions", "mcp_catalogue_keys",
))
FEATURE_FIELDS = frozenset((
    "id", "requires", "uses", "assertions", "suite_ids", "mcp_keys", "mcp_linked",
))
MANIFEST_FIELDS = frozenset((
    "schema_version", "source_sha", "catalogue_sha256", "feature_count", "features",
    "matrix_arms", "shard_count", "cases", "required_pairs", "covered_pairs",
    "suite_runs", "assertion_count", "unique_assertion_count", "mcp_catalogue_keys",
))


class FeatureStateError(ValueError):
    pass


def _fail(code):
    raise FeatureStateError(code)


def _string_list(value, maximum, pattern=ID_RE):
    if type(value) is not list or len(value) > maximum:
        _fail("inventory-invalid")
    if any(type(item) is not str or pattern.fullmatch(item) is None for item in value):
        _fail("inventory-invalid")
    if len(set(value)) != len(value):
        _fail("inventory-invalid")
    return tuple(value)


def validate_inventory(inventory):
    if type(inventory) is not dict or set(inventory) != INVENTORY_FIELDS:
        _fail("inventory-invalid")
    if (type(inventory["schema_version"]) is not int or inventory["schema_version"] != SCHEMA_VERSION
            or type(inventory["source_sha"]) is not str or SHA40_RE.fullmatch(inventory["source_sha"]) is None
            or type(inventory["catalogue_sha256"]) is not str
            or SHA64_RE.fullmatch(inventory["catalogue_sha256"]) is None):
        _fail("inventory-invalid")
    features = inventory["features"]
    if type(features) is not list or not 1 <= len(features) <= MAX_FEATURES:
        _fail("inventory-invalid")
    by_id = {}
    assertion_count = 0
    for feature in features:
        if type(feature) is not dict or set(feature) != FEATURE_FIELDS:
            _fail("inventory-invalid")
        identifier = feature["id"]
        if type(identifier) is not str or ID_RE.fullmatch(identifier) is None or identifier in by_id:
            _fail("inventory-invalid")
        requires = _string_list(feature["requires"], MAX_FEATURES)
        uses = _string_list(feature["uses"], MAX_FEATURES)
        assertions = _string_list(feature["assertions"], 2048)
        suites = _string_list(feature["suite_ids"], 128)
        mcp_keys = _string_list(feature["mcp_keys"], 128)
        if (type(feature["mcp_linked"]) is not bool or not suites or not assertions
                or identifier in requires or identifier in uses or set(requires) & set(uses)):
            _fail("inventory-invalid")
        by_id[identifier] = {
            "id": identifier, "requires": requires, "uses": uses, "assertions": assertions,
            "suite_ids": suites, "mcp_keys": mcp_keys, "mcp_linked": feature["mcp_linked"],
        }
        assertion_count += len(assertions)
    if assertion_count > MAX_ASSERTIONS:
        _fail("inventory-limit")
    if any(set(item["requires"] + item["uses"]) - set(by_id) for item in by_id.values()):
        _fail("inventory-invalid")
    arms = _string_list(inventory["matrix_arms"], MAX_ARMS)
    if not arms:
        _fail("inventory-invalid")
    if (type(inventory["shard_count"]) is not int or not 1 <= inventory["shard_count"] <= MAX_SHARDS
            or type(inventory["max_cases"]) is not int or not 1 <= inventory["max_cases"] <= MAX_CASES
            or type(inventory["max_assertions"]) is not int
            or not 1 <= inventory["max_assertions"] <= MAX_ASSERTIONS):
        _fail("inventory-limit")
    catalogue_keys = _string_list(inventory["mcp_catalogue_keys"], 8192)
    for item in by_id.values():
        if item["mcp_linked"] and set(item["mcp_keys"]) - set(catalogue_keys):
            _fail("mcp-link-unresolved")
    _validate_graph(by_id)
    return by_id, arms, catalogue_keys


def _validate_graph(features):
    active = set()
    visited = set()

    def visit(identifier):
        if identifier in active:
            _fail("dependency-cycle")
        if identifier in visited:
            return
        active.add(identifier)
        for target in features[identifier]["requires"] + features[identifier]["uses"]:
            visit(target)
        active.remove(identifier)
        visited.add(identifier)

    for identifier in features:
        visit(identifier)


def _close_states(features, values):
    closed = dict(values)
    for unused in range(len(features) + 1):
        changed = False
        for identifier, feature in features.items():
            if closed[identifier] == "disabled":
                continue
            for target in feature["requires"] + feature["uses"]:
                if closed[target] == "disabled":
                    closed[identifier] = "disabled"
                    changed = True
                    break
        if not changed:
            return closed
    _fail("dependency-closure-limit")


def _pair_key(left_id, left_state, right_id, right_state):
    return left_id + "=" + left_state + "&" + right_id + "=" + right_state


def _case_record(features, values, changed_ids, shard_count):
    closed = _close_states(features, values)
    state_bytes = json.dumps(closed, sort_keys=True, separators=(",", ":")).encode("ascii")
    case_id = hashlib.sha256(b"ci27-feature-state-v1\n" + state_bytes).hexdigest()[:24]
    assertions = sorted({
        assertion
        for identifier in set(changed_ids) | {
            key for key in closed if closed[key] != values[key]
        }
        for assertion in features[identifier]["assertions"]
    })
    mcp_visible = sorted({
        key for identifier, feature in features.items()
        if feature["mcp_linked"] and closed[identifier] != "disabled"
        for key in feature["mcp_keys"]
    })
    shard = int(hashlib.sha256(case_id.encode("ascii")).hexdigest()[:8], 16) % shard_count
    return {
        "id": case_id, "states": closed, "assertions": assertions,
        "mcp_visible": mcp_visible, "shard": shard,
    }


def generate_coverage(inventory):
    features, arms, catalogue_keys = validate_inventory(inventory)
    identifiers = tuple(sorted(features))
    cases = {}

    def add(values, changed_ids):
        case = _case_record(features, values, changed_ids, inventory["shard_count"])
        previous = cases.get(case["id"])
        if previous is not None:
            previous["assertions"] = sorted(set(previous["assertions"]) | set(case["assertions"]))
        else:
            cases[case["id"]] = case

    for state in STATES:
        add({identifier: state for identifier in identifiers}, identifiers)
    for identifier in identifiers:
        for state in STATES:
            values = {name: "licensed" for name in identifiers}
            values[identifier] = state
            add(values, (identifier,))
    required_pairs = set()
    for left_index, left_id in enumerate(identifiers):
        for right_id in identifiers[left_index + 1:]:
            for left_state in STATES:
                for right_state in STATES:
                    values = {identifier: "licensed" for identifier in identifiers}
                    values[left_id] = left_state
                    values[right_id] = right_state
                    closed = _close_states(features, values)
                    if closed[left_id] == left_state and closed[right_id] == right_state:
                        key = _pair_key(left_id, left_state, right_id, right_state)
                        required_pairs.add(key)
                        add(values, (left_id, right_id))
    if len(cases) > inventory["max_cases"]:
        _fail("case-limit")
    case_rows = [cases[key] for key in sorted(cases)]
    covered_pairs = set()
    for case in case_rows:
        identifiers_in_case = tuple(sorted(case["states"]))
        for index, left_id in enumerate(identifiers_in_case):
            for right_id in identifiers_in_case[index + 1:]:
                key = _pair_key(left_id, case["states"][left_id], right_id, case["states"][right_id])
                if key in required_pairs:
                    covered_pairs.add(key)
    if covered_pairs != required_pairs:
        _fail("pairwise-incomplete")
    expected_assertions = sum(len(feature["assertions"]) for feature in features.values())
    total_assertions = sum(len(case["assertions"]) for case in case_rows)
    if total_assertions > inventory["max_assertions"]:
        _fail("assertion-limit")
    suite_ids = sorted({suite for feature in features.values() for suite in feature["suite_ids"]})
    suite_runs = [
        {"suite_id": suite, "matrix_arm": arm}
        for suite in suite_ids for arm in arms
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "source_sha": inventory["source_sha"],
        "catalogue_sha256": inventory["catalogue_sha256"],
        "feature_count": len(features),
        "features": list(identifiers),
        "matrix_arms": list(arms),
        "shard_count": inventory["shard_count"],
        "cases": case_rows,
        "required_pairs": sorted(required_pairs),
        "covered_pairs": sorted(covered_pairs),
        "suite_runs": suite_runs,
        "assertion_count": total_assertions,
        "unique_assertion_count": expected_assertions,
        "mcp_catalogue_keys": list(catalogue_keys),
    }


def validate_coverage(inventory, manifest):
    expected = generate_coverage(inventory)
    if type(manifest) is not dict or manifest != expected:
        _fail("coverage-manifest-incomplete")
    return expected


def encode_manifest(inventory):
    return json.dumps(generate_coverage(inventory), ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")) + "\n"
