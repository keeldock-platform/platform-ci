"""Capture and validate reviewed qualification evidence for pinned cargo-deny."""

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time


SCHEMA_VERSION = 1
TOOL_VERSION = "0.20.2"
TOOLCHAIN_VERSION = "1.99.1"
RECORD_TYPES = ("r108", "issue_910", "affected_patched")
PLATFORMS = ("linux-x86_64", "darwin-arm64", "windows-x86_64")
PLATFORM_TOOLCHAIN_TARGETS = {
    "linux-x86_64": "x86_64-unknown-linux-gnu",
    "darwin-arm64": "aarch64-apple-darwin",
    "windows-x86_64": "x86_64-pc-windows-msvc",
}
FIXTURE_ROOT = Path(__file__).with_name("fixtures") / "cargo-deny"
FIXTURE_DIRECTORIES = {
    "issue_910": "issue-910-cycle",
    "affected": "rustsec-2020-0071-affected",
    "patched": "rustsec-2020-0071-patched",
}
SAFE_ENVIRONMENT_KEYS = frozenset((
    "CARGO_HOME", "CARGO_INCREMENTAL", "CARGO_NET_OFFLINE", "CARGO_TERM_COLOR",
    "HOME", "LANG", "LC_ALL", "PATH", "RUSTC", "RUSTDOC", "RUSTFLAGS", "RUSTDOCFLAGS",
))
GRAPH_TARGETS = (
    "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin", "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc",
)
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
HEX40_RE = re.compile(r"[a-f0-9]{40}\Z")
REVIEW_FIELDS = frozenset(("decision", "reviewer", "reference", "reviewed_at", "evidence_sha256"))
RUNTIME_CONTEXT_FIELDS = frozenset(("installed_platform", "installed_executable_sha256"))


class QualificationRefusal(Exception):
    """Fixed qualification refusal without evidence-derived text."""


def _refuse():
    raise QualificationRefusal("cargo_deny_qualification_invalid")


def _valid_hash(value):
    return type(value) is str and HEX64_RE.fullmatch(value) is not None


def _canonical_bytes(value):
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _refuse()


def _digest(value):
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def fixture_sha256(name):
    """Hash every regular file in a committed cargo-deny control fixture."""
    directory_name = FIXTURE_DIRECTORIES.get(name)
    if directory_name is None:
        _refuse()
    root = FIXTURE_ROOT / directory_name
    try:
        if root.is_symlink() or not root.is_dir():
            _refuse()
        entries = []
        for item in sorted(root.rglob("*"), key=lambda path: path.as_posix()):
            metadata = item.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                _refuse()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode):
                _refuse()
            relative = item.relative_to(root).as_posix()
            if any(ord(character) < 32 or ord(character) > 126 for character in relative):
                _refuse()
            payload = item.read_bytes()
            entries.append({
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        if not entries:
            _refuse()
        return _digest(entries)
    except (OSError, RuntimeError, TypeError, ValueError):
        _refuse()


def fixture_file_sha256(name, filename):
    directory_name = FIXTURE_DIRECTORIES.get(name)
    if directory_name is None or type(filename) is not str:
        _refuse()
    path = FIXTURE_ROOT / directory_name / filename
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            _refuse()
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, RuntimeError, TypeError, ValueError):
        _refuse()


def platform_key(system=None, machine=None):
    system = sys.platform if system is None else system
    machine = platform.machine() if machine is None else machine
    machine = machine.lower()
    if machine in ("amd64", "x86_64"):
        arch = "x86_64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        _refuse()
    if system == "linux" or system.startswith("linux"):
        name = "linux"
    elif system == "darwin":
        name = "darwin"
    elif system in ("win32", "windows"):
        name = "windows"
    else:
        _refuse()
    key = name + "-" + arch
    if key not in PLATFORMS:
        _refuse()
    return key


def review_record(record, reviewer, reference, reviewed_at=None):
    """Attach a review decision to immutable evidence; no qualification booleans are accepted."""
    if type(record) is not dict or "review" in record:
        _refuse()
    if (type(reviewer) is not str or not 1 <= len(reviewer) <= 128
            or type(reference) is not str or not 1 <= len(reference) <= 512):
        _refuse()
    timestamp = int(time.time()) if reviewed_at is None else reviewed_at
    if type(timestamp) is not int or timestamp <= 0:
        _refuse()
    result = dict(record)
    result["review"] = {
        "decision": "accepted",
        "reviewer": reviewer,
        "reference": reference,
        "reviewed_at": timestamp,
        "evidence_sha256": _digest(record),
    }
    return result


def _reviewed(record):
    review = record.get("review")
    if (type(review) is not dict or set(review) != REVIEW_FIELDS
            or review.get("decision") != "accepted"
            or type(review.get("reviewer")) is not str
            or not review["reviewer"] or len(review["reviewer"]) > 128
            or type(review.get("reference")) is not str
            or not review["reference"] or len(review["reference"]) > 512
            or type(review.get("reviewed_at")) is not int or review["reviewed_at"] <= 0
            or not _valid_hash(review.get("evidence_sha256"))):
        return False
    payload = dict(record)
    del payload["review"]
    return review["evidence_sha256"] == _digest(payload)


def _context_valid(context, expected_context):
    if type(context) is not dict or type(expected_context) is not dict:
        return False
    reviewed_context = {
        key: value for key, value in expected_context.items()
        if key not in RUNTIME_CONTEXT_FIELDS
    }
    return context == reviewed_context


def _argv_is_exact(observation, check_name):
    argv = observation.get("argv") if type(observation) is dict else None
    if type(argv) is not list or len(argv) != 10 or any(type(item) is not str for item in argv):
        return False
    manifest = argv[1].replace("\\", "/")
    policy = argv[3].replace("\\", "/")
    return (
        argv[0] == "--manifest-path" and manifest.endswith("/Cargo.toml")
        and argv[2] == "--config" and policy.rsplit("/", 1)[-1] == "cargo_deny_policy.toml"
        and argv[4:] == ["--workspace", "--all-features", "--locked", "--offline", "check", check_name]
    )


def _check_process_observation(value, *, expected_exit):
    fields = frozenset(("exit_code", "timed_out", "cancelled", "stdout_sha256",
                        "stderr_sha256", "argv_sha256", "argv", "stdout_b64", "stderr_b64",
                        "executable_sha256", "environment_sha256", "environment_keys",
                        "config_sha256", "manifest_sha256", "lock_sha256", "cwd_sha256",
                        "timeout_seconds", "output_limit"))
    if (type(value) is not dict or set(value) != fields
            or type(value.get("exit_code")) is not int
            or value.get("timed_out") is not False
            or value.get("cancelled") is not False
            or not _valid_hash(value.get("stdout_sha256"))
            or not _valid_hash(value.get("stderr_sha256"))
            or not _valid_hash(value.get("argv_sha256"))
            or not _valid_hash(value.get("executable_sha256"))
            or not _valid_hash(value.get("environment_sha256"))
            or not _valid_hash(value.get("config_sha256"))
            or not _valid_hash(value.get("manifest_sha256"))
            or not _valid_hash(value.get("lock_sha256"))
            or not _valid_hash(value.get("cwd_sha256"))
            or type(value.get("timeout_seconds")) is not int
            or value.get("timeout_seconds") != 120
            or type(value.get("output_limit")) is not int
            or value.get("output_limit") != 4096
            or type(value.get("environment_keys")) is not list
            or any(type(key) is not str or key not in SAFE_ENVIRONMENT_KEYS
                   for key in value["environment_keys"])
            or value["environment_keys"] != sorted(set(value["environment_keys"]))
            or type(value.get("argv")) is not list or not value["argv"]
            or any(type(item) is not str or not item or len(item) > 4096
                   or any(ord(character) < 32 or ord(character) > 126 for character in item)
                   for item in value["argv"])
            or value["argv_sha256"] != _digest(value["argv"])):
        return False
    try:
        stdout = base64.b64decode(value["stdout_b64"], validate=True)
        stderr = base64.b64decode(value["stderr_b64"], validate=True)
    except (ValueError, TypeError, binascii.Error):
        return False
    if (len(stdout) > 4096 or len(stderr) > 4096
            or hashlib.sha256(stdout).hexdigest() != value["stdout_sha256"]
            or hashlib.sha256(stderr).hexdigest() != value["stderr_sha256"]):
        return False
    if expected_exit == "zero":
        return value["exit_code"] == 0
    if expected_exit == "nonzero":
        return value["exit_code"] != 0
    return False


def _validate_r108(record, expected_context):
    fields = frozenset(("schema_version", "record_type", "context", "release_provenance_sha256",
                        "platform_artifacts", "target_triples", "toolchain", "checks",
                        "dependency_chain", "exceptions", "review"))
    if type(record) is not dict or set(record) != fields:
        return False
    if (record.get("schema_version") != SCHEMA_VERSION or record.get("record_type") != "r108"
            or not _context_valid(record.get("context"), expected_context)
            or not _valid_hash(record.get("release_provenance_sha256"))):
        return False
    targets = record.get("target_triples")
    if type(targets) is not list or tuple(targets) != GRAPH_TARGETS:
        return False
    artifacts = record.get("platform_artifacts")
    if type(artifacts) is not dict or set(artifacts) != set(PLATFORMS):
        return False
    for platform in PLATFORMS:
        item = artifacts[platform]
        if (type(item) is not dict or set(item) != {"asset_sha256", "binary_sha256"}
                or not _valid_hash(item.get("asset_sha256"))
                or not _valid_hash(item.get("binary_sha256"))):
            return False
    try:
        import cargo_deny_installer
        release_map = {
            "linux-x86_64": cargo_deny_installer.RELEASES[("linux", "x86_64")],
            "darwin-arm64": cargo_deny_installer.RELEASES[("darwin", "arm64")],
            "windows-x86_64": cargo_deny_installer.RELEASES[("windows", "amd64")],
        }
        for platform_name, (target, asset_sha256) in release_map.items():
            item = artifacts[platform_name]
            if item["asset_sha256"] != asset_sha256:
                return False
            del target
    except (ImportError, KeyError, TypeError):
        return False
    toolchain = record.get("toolchain")
    if type(toolchain) is not dict or set(toolchain) != set(PLATFORMS):
        return False
    for platform_name in PLATFORMS:
        item = toolchain[platform_name]
        if (type(item) is not dict or set(item) != {"version", "build_sha256", "target"}
                or item.get("version") != TOOLCHAIN_VERSION
                or not _valid_hash(item.get("build_sha256"))
                or item.get("target") != PLATFORM_TOOLCHAIN_TARGETS[platform_name]):
            return False
    checks = record.get("checks")
    if type(checks) is not dict or set(checks) != set(PLATFORMS):
        return False
    for platform_name in PLATFORMS:
        platform_checks = checks[platform_name]
        if type(platform_checks) is not dict or set(platform_checks) != {
                "advisories", "bans", "licenses", "sources"}:
            return False
        if any(not _check_process_observation(item, expected_exit="zero")
               for item in platform_checks.values()):
            return False
        if any(not _argv_is_exact(platform_checks[name], name)
               for name in platform_checks):
            return False
        if any(not _observation_matches_context(item, expected_context)
               for item in platform_checks.values()):
            return False
    dependency_chain = record.get("dependency_chain")
    if (type(dependency_chain) is not dict
            or set(dependency_chain) != {
                "lock_sha256", "manifest_sha256", "advisory_check", "packages",
                "unpatched_advisories",
            }
            or not _valid_hash(dependency_chain.get("lock_sha256"))
            or not _valid_hash(dependency_chain.get("manifest_sha256"))
            or not _check_process_observation(dependency_chain.get("advisory_check"), expected_exit="zero")
            or type(dependency_chain.get("packages")) is not list
            or not dependency_chain["packages"]
            or type(dependency_chain.get("unpatched_advisories")) is not list
            or dependency_chain["unpatched_advisories"]):
        return False
    if (not _check_process_observation(dependency_chain["advisory_check"], expected_exit="zero")
            or not _argv_is_exact(dependency_chain["advisory_check"], "advisories")):
        return False
    if (not _observation_matches_context(dependency_chain["advisory_check"], expected_context)
            or dependency_chain["advisory_check"]["manifest_sha256"]
            != dependency_chain["manifest_sha256"]
            or dependency_chain["advisory_check"]["lock_sha256"]
            != dependency_chain["lock_sha256"]):
        return False
    previous_package = None
    for package in dependency_chain["packages"]:
        if (type(package) is not dict or set(package) != {"name", "version", "checksum"}
                or type(package.get("name")) is not str or not package["name"]
                or type(package.get("version")) is not str or not package["version"]
                or not _valid_hash(package.get("checksum"))):
            return False
        key = (package["name"], package["version"])
        if previous_package is not None and key <= previous_package:
            return False
        previous_package = key
    exceptions = record.get("exceptions")
    if type(exceptions) is not list:
        return False
    for exception in exceptions:
        if (type(exception) is not dict
                or set(exception) != {"advisory", "owner", "removal_condition", "invalidating_check"}
                or any(type(exception.get(key)) is not str or not exception[key]
                       for key in ("advisory", "owner", "removal_condition", "invalidating_check"))
                or not re.fullmatch(r"RUSTSEC-[0-9]{4}-[0-9]{4}", exception["advisory"])
                or exception["invalidating_check"] not in checks):
            return False
    return _reviewed(record)


def _validate_platform_observations(record, expected_context, expected_exit):
    fields = frozenset(("schema_version", "record_type", "context", "platform_results", "review"))
    if type(record) is not dict or set(record) != fields:
        return False
    if (record.get("schema_version") != SCHEMA_VERSION
            or record.get("record_type") not in ("issue_910", "affected_patched")
            or not _context_valid(record.get("context"), expected_context)):
        return False
    results = record.get("platform_results")
    if type(results) is not dict or set(results) != set(PLATFORMS):
        return False
    for platform in PLATFORMS:
        result = results[platform]
        if record["record_type"] == "issue_910":
            if (type(result) is not dict
                    or set(result) != {"fixture_sha256", "coverage", "observation"}
                    or result.get("fixture_sha256") != fixture_sha256("issue_910")
                    or result.get("coverage") != {
                        "all_features": True, "all_targets": True,
                        "development_dependencies": True, "build_dependencies": True,
                    }
                    or not _check_process_observation(result.get("observation"), expected_exit="zero")
                    or not _argv_is_exact(result["observation"], "bans")
                    or b"stack overflow" in _observation_output(result["observation"]).lower()
                    or b"overflowed its stack" in _observation_output(result["observation"]).lower()):
                return False
            if not _manifest_ends_with(
                    result["observation"], "fixtures/cargo-deny/issue-910-cycle/Cargo.toml"):
                return False
            if (not _observation_matches_context(result["observation"], expected_context)
                    or result["observation"]["manifest_sha256"]
                    != fixture_file_sha256("issue_910", "Cargo.toml")
                    or result["observation"]["lock_sha256"]
                    != fixture_file_sha256("issue_910", "Cargo.lock")):
                return False
        else:
            if (type(result) is not dict
                    or set(result) != {"advisory", "affected", "patched"}
                    or result.get("advisory") != "RUSTSEC-2020-0071"
                    or type(result.get("affected")) is not dict
                    or set(result["affected"]) != {
                        "fixture_sha256", "coverage", "observation", "diagnostic_sha256",
                    }
                    or result["affected"].get("fixture_sha256") != fixture_sha256("affected")
                    or result["affected"].get("coverage") != {
                        "all_features": True, "all_targets": True,
                        "development_dependencies": True, "build_dependencies": True,
                    }
                    or not _valid_hash(result["affected"].get("diagnostic_sha256"))
                    or not _check_process_observation(result["affected"].get("observation"), expected_exit="nonzero")
                    or type(result.get("patched")) is not dict
                    or set(result["patched"]) != {"fixture_sha256", "coverage", "observation"}
                    or result["patched"].get("fixture_sha256") != fixture_sha256("patched")
                    or result["patched"].get("coverage") != {
                        "all_features": True, "all_targets": True,
                        "development_dependencies": True, "build_dependencies": True,
                    }
                    or not _check_process_observation(result["patched"].get("observation"), expected_exit="zero")
                    or not _argv_is_exact(result["affected"]["observation"], "advisories")
                    or not _argv_is_exact(result["patched"]["observation"], "advisories")):
                return False
            affected_output = _observation_output(result["affected"]["observation"])
            patched_output = _observation_output(result["patched"]["observation"])
            if (b"RUSTSEC-2020-0071" not in affected_output
                    or b"RUSTSEC-2020-0071" in patched_output
                    or hashlib.sha256(affected_output).hexdigest()
                    != result["affected"]["diagnostic_sha256"]):
                return False
            if (not _manifest_ends_with(
                    result["affected"]["observation"],
                    "fixtures/cargo-deny/rustsec-2020-0071-affected/Cargo.toml",
            ) or not _manifest_ends_with(
                    result["patched"]["observation"],
                    "fixtures/cargo-deny/rustsec-2020-0071-patched/Cargo.toml",
            )):
                return False
            for variant in ("affected", "patched"):
                observation = result[variant]["observation"]
                if (not _observation_matches_context(observation, expected_context)
                        or observation["manifest_sha256"]
                        != fixture_file_sha256(variant, "Cargo.toml")
                        or observation["lock_sha256"]
                        != fixture_file_sha256(variant, "Cargo.lock")):
                    return False
    return _reviewed(record)


def _manifest_ends_with(observation, suffix):
    argv = observation.get("argv") if type(observation) is dict else None
    try:
        positions = [index for index, item in enumerate(argv) if item == "--manifest-path"]
        if len(positions) != 1:
            return False
        index = positions[0]
        path = argv[index + 1].replace("\\", "/")
    except (AttributeError, IndexError, TypeError, ValueError):
        return False
    return path.endswith(suffix)


def _observation_matches_context(observation, expected_context):
    keys = observation.get("environment_keys") if type(observation) is dict else None
    required = {"CARGO_HOME", "HOME", "LANG", "LC_ALL", "PATH"}
    return (
        type(keys) is list and required.issubset(set(keys))
        and observation.get("config_sha256") == expected_context.get("policy_sha256")
    )


def _capture_relative_file(cwd, raw_path):
    if (type(raw_path) is not str or not raw_path or raw_path.startswith("/")
            or "\\" in raw_path or any(part in ("", ".", "..")
                                        for part in raw_path.split("/"))):
        _refuse()
    root = Path(cwd)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        _refuse()
    try:
        target = root.resolve(strict=True)
        for part in raw_path.split("/"):
            target = target / part
            metadata = target.lstat()
            if (stat.S_ISLNK(metadata.st_mode)
                    or getattr(metadata, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                _refuse()
        metadata = target.lstat()
        if not stat.S_ISREG(metadata.st_mode) or getattr(metadata, "st_nlink", 1) != 1:
            _refuse()
        return target, hashlib.sha256(target.read_bytes()).hexdigest()
    except (OSError, RuntimeError, TypeError, ValueError):
        _refuse()


def derive_flags(bundle_bytes, expected_context):
    """Derive qualification claims from canonical reviewed evidence, never stored booleans."""
    flags = {
        "cargo_deny_provenance_qualified": False,
        "cargo_deny_cli_qualified": False,
        "r108_qualified": False,
        "cargo_deny_issue_910_safe": False,
        "cargo_deny_affected_patched_controls_qualified": False,
    }
    if type(bundle_bytes) is not bytes or not bundle_bytes or len(bundle_bytes) > 4 * 1024 * 1024:
        return flags, hashlib.sha256(b"missing-qualification-evidence").hexdigest()
    try:
        payload = json.loads(bundle_bytes.decode("ascii"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError, RecursionError, QualificationRefusal):
        return flags, hashlib.sha256(b"invalid-qualification-evidence").hexdigest()
    if (type(payload) is not dict or set(payload) != {"schema_version", "records"}
            or payload.get("schema_version") != SCHEMA_VERSION or type(payload.get("records")) is not list):
        return flags, hashlib.sha256(b"invalid-qualification-evidence").hexdigest()
    if bundle_bytes not in (_canonical_bytes(payload), _canonical_bytes(payload) + b"\n"):
        return flags, hashlib.sha256(b"noncanonical-qualification-evidence").hexdigest()
    records = {}
    for record in payload["records"]:
        if type(record) is not dict or record.get("record_type") not in RECORD_TYPES:
            return flags, hashlib.sha256(b"invalid-qualification-evidence").hexdigest()
        kind = record["record_type"]
        if kind in records:
            return flags, hashlib.sha256(b"duplicate-qualification-evidence").hexdigest()
        records[kind] = record
    digest = hashlib.sha256(bundle_bytes).hexdigest()
    if set(records) != set(RECORD_TYPES):
        return flags, digest
    if type(expected_context) is not dict:
        return flags, digest
    installed_platform = expected_context.get("installed_platform")
    installed_executable_sha256 = expected_context.get("installed_executable_sha256")
    if (installed_platform not in PLATFORMS
            or not _valid_hash(installed_executable_sha256)):
        return flags, digest
    try:
        r108_ok = _validate_r108(records["r108"], expected_context)
        issue_ok = _validate_platform_observations(records["issue_910"], expected_context, "zero")
        controls_ok = _validate_platform_observations(records["affected_patched"], expected_context, "both")
        r108_binary_ok, issue_binary_ok, controls_binary_ok = _binary_bindings(
            records, installed_platform, installed_executable_sha256,
        )
        if not r108_ok or not r108_binary_ok:
            r108_ok = False
            issue_ok = False
            controls_ok = False
        else:
            issue_ok = issue_ok and issue_binary_ok
            controls_ok = controls_ok and controls_binary_ok
    except (QualificationRefusal, KeyError, TypeError, ValueError, IndexError, OSError):
        r108_ok = False
        issue_ok = False
        controls_ok = False
    flags["cargo_deny_provenance_qualified"] = r108_ok
    flags["cargo_deny_cli_qualified"] = r108_ok
    flags["r108_qualified"] = r108_ok
    flags["cargo_deny_issue_910_safe"] = issue_ok
    flags["cargo_deny_affected_patched_controls_qualified"] = controls_ok
    return flags, digest


def _binary_bindings(records, installed_platform, installed_executable_sha256):
    """Check each record's executable independently of its other validation failures."""
    r108_ok = True
    issue_ok = True
    controls_ok = True
    try:
        artifacts = records["r108"]["platform_artifacts"]
        for platform_name in PLATFORMS:
            binary_sha256 = artifacts[platform_name]["binary_sha256"]
            if not _valid_hash(binary_sha256):
                return False, False, False
            r108_observations = records["r108"]["checks"][platform_name].values()
            issue_observation = records["issue_910"]["platform_results"][platform_name]["observation"]
            control_result = records["affected_patched"]["platform_results"][platform_name]
            control_observations = (
                control_result["affected"]["observation"],
                control_result["patched"]["observation"],
            )
            r108_ok = r108_ok and all(
                type(item) is dict and item.get("executable_sha256") == binary_sha256
                for item in r108_observations
            )
            issue_ok = issue_ok and (
                type(issue_observation) is dict
                and issue_observation.get("executable_sha256") == binary_sha256
            )
            controls_ok = controls_ok and all(
                type(item) is dict and item.get("executable_sha256") == binary_sha256
                for item in control_observations
            )
        dependency_executable = records["r108"]["dependency_chain"]["advisory_check"].get(
            "executable_sha256",
        )
        known_executables = {artifacts[name]["binary_sha256"] for name in PLATFORMS}
        installed_matches = (
            artifacts[installed_platform]["binary_sha256"] == installed_executable_sha256
            and dependency_executable in known_executables
        )
        return (
            r108_ok and installed_matches,
            issue_ok and installed_matches,
            controls_ok and installed_matches,
        )
    except (AttributeError, KeyError, TypeError, ValueError, IndexError):
        return False, False, False


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse()
        result[key] = value
    return result


def capture_observation(executable, argv, cwd, environment, identity, policy_sha256,
                        qualification_sha256, advisory_commit, archive_sha256,
                        timeout_seconds=120):
    """Run cargo-deny through the production bounded subprocess adapter."""
    import rust_license_gate

    if (type(argv) not in (tuple, list) or not argv
            or any(type(item) is not str for item in argv)
            or type(environment) is not dict
            or any(type(key) is not str or key not in SAFE_ENVIRONMENT_KEYS
                   or type(value) is not str for key, value in environment.items())):
        _refuse()
    try:
        executable_sha256 = rust_license_gate._digest_file(executable)
        config_sha256 = hashlib.sha256(b"missing-cargo-deny-config").hexdigest()
        manifest_sha256 = hashlib.sha256(b"missing-cargo-deny-manifest").hexdigest()
        lock_sha256 = hashlib.sha256(b"missing-cargo-lock").hexdigest()
        if type(timeout_seconds) is not int or timeout_seconds != 120:
            _refuse()
        config_positions = [index for index, item in enumerate(argv) if item == "--config"]
        manifest_positions = [index for index, item in enumerate(argv) if item == "--manifest-path"]
        if config_positions:
            if len(config_positions) != 1 or config_positions[0] + 1 >= len(argv):
                _refuse()
            unused_config_path, config_sha256 = _capture_relative_file(
                cwd, argv[config_positions[0] + 1],
            )
            if config_sha256 != policy_sha256:
                _refuse()
        if manifest_positions:
            if len(manifest_positions) != 1 or manifest_positions[0] + 1 >= len(argv):
                _refuse()
            manifest_path, manifest_sha256 = _capture_relative_file(
                cwd, argv[manifest_positions[0] + 1],
            )
            unused_lock_path, lock_sha256 = _capture_relative_file(
                manifest_path.parent, "Cargo.lock",
            )
            if lock_sha256 != identity.lock_sha256:
                _refuse()
        request = rust_license_gate.ProcessRequest(
            str(executable), identity.source_sha, tuple(argv), str(cwd), b"",
            tuple(sorted(environment.items())), timeout_seconds, rust_license_gate.MAX_OUTPUT_BYTES,
            rust_license_gate._NeverCancelled(), executable_sha256, policy_sha256,
            qualification_sha256, advisory_commit, identity, archive_sha256,
        )
        result = rust_license_gate._PinnedProcessPort().run(request)
        if type(result) is not rust_license_gate.ProcessResult or result.seal is not rust_license_gate._SEAL:
            _refuse()
        return {
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "cancelled": result.cancelled,
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
            "argv_sha256": _digest(list(argv)),
            "argv": list(argv),
            "executable_sha256": executable_sha256,
            "environment_sha256": _digest(sorted(environment.items())),
            "environment_keys": sorted(environment),
            "config_sha256": config_sha256,
            "manifest_sha256": manifest_sha256,
            "lock_sha256": lock_sha256,
            "cwd_sha256": hashlib.sha256(
                str(Path(cwd).resolve(strict=True)).encode("utf-8"),
            ).hexdigest(),
            "timeout_seconds": timeout_seconds,
            "output_limit": rust_license_gate.MAX_OUTPUT_BYTES,
            "stdout_b64": base64.b64encode(result.stdout).decode("ascii"),
            "stderr_b64": base64.b64encode(result.stderr).decode("ascii"),
        }, result.stdout, result.stderr
    except QualificationRefusal:
        raise
    except BaseException:
        _refuse()


def _observation_output(observation):
    try:
        return (base64.b64decode(observation["stdout_b64"], validate=True)
                + base64.b64decode(observation["stderr_b64"], validate=True))
    except (KeyError, ValueError, TypeError, binascii.Error):
        return b""


def _safe_write_evidence(directory, name, payload):
    root = Path(directory)
    if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
            or not re.fullmatch(r"[a-f0-9]{64}\.(?:stdout|stderr|json)", name)
            or type(payload) is not bytes or len(payload) > 4 * 1024 * 1024):
        _refuse()
    target = root / name
    if target.exists() or target.is_symlink():
        _refuse()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(target), flags, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        _refuse()
    return target


def _main(argv=None):
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("--executable", required=True)
    capture.add_argument("--install-receipt", required=True)
    capture.add_argument("--cwd", required=True)
    capture.add_argument("--environment", required=True)
    capture.add_argument("--identity", required=True)
    capture.add_argument("--policy-sha256", required=True)
    capture.add_argument("--qualification-sha256", required=True)
    capture.add_argument("--advisory-commit", required=True)
    capture.add_argument("--archive-sha256", required=True)
    capture.add_argument("--evidence-directory", required=True)
    capture.add_argument("argv", nargs=argparse.REMAINDER)
    review = commands.add_parser("review")
    review.add_argument("--record", required=True)
    review.add_argument("--output", required=True)
    review.add_argument("--reviewer", required=True)
    review.add_argument("--reference", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--bundle", required=True)
    validate.add_argument("--context", required=True)
    validate.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            import rust_license_gate
            import cargo_deny_installer
            from dataclasses import asdict

            cargo_deny_installer.verify_installed(args.executable, args.install_receipt)

            environment = json.loads(Path(args.environment).read_text(encoding="ascii"))
            identity_value = json.loads(Path(args.identity).read_text(encoding="ascii"))
            if (type(identity_value) is not dict or set(identity_value) != {
                    "source_sha", "profile", "root", "lock_sha256"}):
                _refuse()
            identity = rust_license_gate.Identity(**identity_value)
            argv_items = list(args.argv)
            if argv_items and argv_items[0] == "--":
                argv_items = argv_items[1:]
            observation, stdout, stderr = capture_observation(
                args.executable, argv_items, args.cwd, environment, identity,
                args.policy_sha256, args.qualification_sha256, args.advisory_commit,
                args.archive_sha256,
            )
            key = _digest({"argv": argv_items, "identity": asdict(identity)})
            _safe_write_evidence(args.evidence_directory, key + ".stdout", stdout)
            _safe_write_evidence(args.evidence_directory, key + ".stderr", stderr)
            output = {"schema_version": 1, "observation": observation,
                      "stdout_artifact": key + ".stdout", "stderr_artifact": key + ".stderr"}
            _safe_write_evidence(args.evidence_directory, key + ".json", _canonical_bytes(output) + b"\n")
            sys.stdout.buffer.write(_canonical_bytes(output) + b"\n")
            return 0 if not observation["timed_out"] and not observation["cancelled"] else 2
        if args.command == "review":
            record = json.loads(Path(args.record).read_text(encoding="ascii"), object_pairs_hook=_unique_pairs)
            reviewed = review_record(record, args.reviewer, args.reference)
            Path(args.output).write_bytes(_canonical_bytes(reviewed) + b"\n")
            return 0
        bundle_bytes = Path(args.bundle).read_bytes()
        context_bytes = Path(args.context).read_bytes()
        context = json.loads(context_bytes.decode("ascii"), object_pairs_hook=_unique_pairs)
        flags, evidence_sha256 = derive_flags(bundle_bytes, context)
        output = {
            "schema_version": 1,
            "evidence_sha256": evidence_sha256,
            "flags": flags,
        }
        payload = _canonical_bytes(output) + b"\n"
        if args.output:
            Path(args.output).write_bytes(payload)
        else:
            sys.stdout.buffer.write(payload)
        return 0
    except (OSError, ValueError, UnicodeError, QualificationRefusal):
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
