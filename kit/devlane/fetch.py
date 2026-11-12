"""Bounded anonymous fetch and validation for public dev-lane inputs."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import tomllib
except ImportError:
    tomllib = None

import bundle
from bundle import Refusal, strict_json


REPOSITORY = "keeldock-platform/platform-ci"
REPOSITORY_ID = "1430960557"
WORKFLOW_PATH = ".github/workflows/devlane-encrypted.yml"
SOURCE_FREE_WAVE_CLASS = "source-free-synthetic"
MAX_PROJECTION = 16 * 1024 * 1024
MAX_CIPHERTEXT = 64 * 1024 * 1024
MAX_REDIRECTS = 5
ALLOWED_HOSTS = frozenset((
    "api.github.com", "github.com", "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
))
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
OPAQUE_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{7,63}\Z")
NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*\Z")
PACKAGE_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z")
CRATE_NAME = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


def _fail(code):
    raise Refusal(code)


def _id(value):
    if type(value) is not str or not OPAQUE_ID.fullmatch(value):
        _fail("input-id")
    return value


def validate_dispatch(identity, expected_profile=None, now=None):
    if type(identity) is not dict:
        _fail("dispatch-shape")
    required = {
        "repository", "repository_id", "server_url", "event", "ref", "control_sha",
        "workflow_path", "run_attempt", "control_run_id", "profile", "wave_id", "bundle_id",
        "bundle_asset_id", "bundle_sha256", "bundle_size", "projection_asset_id",
        "projection_sha256", "projection_size", "expires",
    }
    if set(identity) not in (required, required | {"wave_class"}):
        _fail("dispatch-shape")
    if "wave_class" in identity and identity["wave_class"] != SOURCE_FREE_WAVE_CLASS:
        _fail("dispatch-wave-class")
    if identity["repository"] != REPOSITORY or identity["repository_id"] != REPOSITORY_ID:
        _fail("repository-identity")
    if identity["server_url"] != "https://github.com" or identity["event"] != "workflow_dispatch":
        _fail("dispatch-origin")
    if identity["ref"] != "refs/heads/main" or identity["workflow_path"] != WORKFLOW_PATH:
        _fail("dispatch-control-ref")
    if type(identity["control_sha"]) is not str or not re.fullmatch(r"[a-f0-9]{40,64}", identity["control_sha"]):
        _fail("control-sha")
    if type(identity["run_attempt"]) is not int or identity["run_attempt"] != 1:
        _fail("run-attempt")
    if type(identity["control_run_id"]) is not str or not re.fullmatch(r"[1-9][0-9]{0,18}", identity["control_run_id"]):
        _fail("control-run-id")
    if identity["profile"] not in bundle.ENCRYPTED_PROFILES:
        _fail("profile")
    if expected_profile is not None and identity["profile"] != expected_profile:
        _fail("profile-binding")
    _id(identity["wave_id"])
    _id(identity["bundle_id"])
    for suffix in ("bundle", "projection"):
        asset = identity[suffix + "_asset_id"]
        size = identity[suffix + "_size"]
        digest = identity[suffix + "_sha256"]
        if type(asset) is not str or not re.fullmatch(r"[1-9][0-9]{0,18}", asset):
            _fail("asset-id")
        maximum = MAX_CIPHERTEXT if suffix == "bundle" else MAX_PROJECTION
        if type(size) is not int or size < 1 or size > maximum:
            _fail("asset-size")
        if type(digest) is not str or not SHA256.fullmatch(digest):
            _fail("asset-digest")
    now = int(time.time()) if now is None else now
    if type(identity["expires"]) is not int or identity["expires"] <= now:
        _fail("request-expired")
    if identity["expires"] > now + 60 * 60:
        _fail("request-expiry-range")
    return identity


def _validate_url(url, allowed_hosts):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
            or parsed.hostname not in allowed_hosts or parsed.port not in (None, 443)
            or parsed.fragment):
        _fail("download-redirect")
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_limited(url, maximum, allowed_hosts):
    handlers = [_NoRedirect()]
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/octet-stream", "User-Agent": "platform-devlane-fetch/1"},
        method="GET",
    )
    current = _validate_url(url, allowed_hosts)
    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308):
                _fail("download-http")
            location = error.headers.get("Location")
            if type(location) is not str:
                _fail("download-redirect")
            current = _validate_url(urllib.parse.urljoin(current, location), allowed_hosts)
            request = urllib.request.Request(
                current,
                headers={"Accept": "application/octet-stream", "User-Agent": "platform-devlane-fetch/1"},
                method="GET",
            )
            continue
        try:
            if response.status != 200 or urllib.parse.urlsplit(response.geturl()).hostname not in allowed_hosts:
                _fail("download-http")
            chunks = []
            size = 0
            while True:
                chunk = response.read(min(65536, maximum + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    _fail("download-size")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            response.close()
    _fail("download-redirect-limit")


def download_release_asset(asset_id, expected_size, expected_sha256, destination, maximum=MAX_CIPHERTEXT):
    if type(asset_id) is not str or not re.fullmatch(r"[1-9][0-9]{0,18}", asset_id):
        _fail("asset-id")
    if type(expected_size) is not int or expected_size < 1 or expected_size > maximum:
        _fail("asset-size")
    if type(expected_sha256) is not str or not SHA256.fullmatch(expected_sha256):
        _fail("asset-digest")
    url = "https://api.github.com/repos/" + REPOSITORY + "/releases/assets/" + asset_id
    payload = _open_limited(url, maximum, ALLOWED_HOSTS)
    if len(payload) != expected_size or hashlib.sha256(payload).hexdigest() != expected_sha256:
        _fail("asset-binding-mismatch")
    destination = Path(destination)
    descriptor = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    return len(payload)


def context_from_environment(environ):
    def required(name):
        value = environ.get(name)
        if type(value) is not str or not value:
            _fail("dispatch-input")
        return value

    def decimal(name, maximum):
        value = required(name)
        if not re.fullmatch(r"[1-9][0-9]{0,18}", value):
            _fail("dispatch-input")
        number = int(value)
        if number > maximum:
            _fail("dispatch-input")
        return number

    identity = {
        "repository": required("CI_REPOSITORY"),
        "repository_id": required("CI_REPOSITORY_ID"),
        "server_url": required("CI_SERVER_URL"),
        "event": required("CI_EVENT_NAME"),
        "ref": required("CI_REF"),
        "control_sha": required("CI_SHA"),
        "control_run_id": required("CI_CONTROL_RUN_ID"),
        "workflow_path": WORKFLOW_PATH,
        "run_attempt": decimal("CI_RUN_ATTEMPT", 1),
        "profile": required("DEVLANE_PROFILE"),
        "wave_id": required("DEVLANE_WAVE_ID"),
        "bundle_id": required("DEVLANE_BUNDLE_ID"),
        "bundle_asset_id": required("DEVLANE_BUNDLE_ASSET_ID"),
        "bundle_sha256": required("DEVLANE_BUNDLE_SHA256"),
        "bundle_size": decimal("DEVLANE_BUNDLE_SIZE", MAX_CIPHERTEXT),
        "projection_asset_id": required("DEVLANE_PROJECTION_ASSET_ID"),
        "projection_sha256": required("DEVLANE_PROJECTION_SHA256"),
        "projection_size": decimal("DEVLANE_PROJECTION_SIZE", MAX_PROJECTION),
        "expires": decimal("DEVLANE_EXPIRES", 9_999_999_999),
    }
    return validate_dispatch(identity)


def _write_private(path, payload):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def _valid_registry_url(url):
    if type(url) is not str:
        return False
    parsed = urllib.parse.urlsplit(url)
    return (
        parsed.scheme == "https" and parsed.hostname in ("registry.npmjs.org", "static.crates.io")
        and parsed.username is None and parsed.password is None and parsed.port in (None, 443)
        and not parsed.query and not parsed.fragment and ".." not in parsed.path.split("/")
    )


_NPM_COMPARATOR = r"(?:(?:\^|~|>=|<=|>|<|=) ?)?[0-9][0-9A-Za-z.+*-]*"
_NPM_RANGE = re.compile(
    r"(?:\*|" + _NPM_COMPARATOR + r"(?: " + _NPM_COMPARATOR + r")*"
    r"(?: \|\| " + _NPM_COMPARATOR + r"(?: " + _NPM_COMPARATOR + r")*)*)"
)


def _valid_npm_spec(value):
    """A semver range as real lockfiles print it, including `||` alternatives and spaced operators."""
    return type(value) is str and len(value) <= 128 and _NPM_RANGE.fullmatch(value) is not None


def _validate_npm_dependency_map(value, code):
    if type(value) is not dict or len(value) > 5000:
        _fail(code)
    for name, spec in value.items():
        if type(name) is not str or not NPM_NAME.fullmatch(name) or not _valid_npm_spec(spec):
            _fail(code)


def _validate_constraint_envelope(value, *, expected_source_sha, expected_control_sha,
                                  allow_empty=False):
    fields = {"schema", "profile", "source_commit", "control_sha", "manifest_projection_sha256",
              "toolchain", "target_set", "resolution_mode", "resolver_version", "constraints"}
    if type(value) is not dict or set(value) != fields:
        _fail("projection-constraint-shape")
    if (value["schema"] != 2 or value["profile"] != "core-rust"
            or value["source_commit"] != expected_source_sha
            or value["control_sha"] != expected_control_sha
            or value["toolchain"] != "1.99.1"
            or value["target_set"] != ["x86_64-unknown-linux-gnu"]
            or value["resolution_mode"] != "external-all-features-all-targets-v2"
            or value["resolver_version"] not in ("1", "2", "3")):
        _fail("projection-constraint-binding")
    if (type(value["manifest_projection_sha256"]) is not str
            or not SHA256.fullmatch(value["manifest_projection_sha256"])):
        _fail("projection-constraint-digest")
    rows = value["constraints"]
    if type(rows) is not list or (not rows and not allow_empty) or len(rows) > 20_000:
        _fail("projection-constraint-count")
    ids = set()
    pairs = set()
    ordered = []
    for row in rows:
        if type(row) is not dict or set(row) != {"id", "package", "version_req"}:
            _fail("projection-constraint-row")
        ident, package, requirement = row["id"], row["package"], row["version_req"]
        if (type(ident) is not str or not re.fullmatch(r"d[0-9]{6}", ident) or ident in ids
                or type(package) is not str or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", package)
                or package.startswith("keeldock" + "-")
                or type(requirement) is not str
                or not re.fullmatch(r"[=<>~^*0-9A-Za-z._,+| -]{1,128}", requirement)):
            _fail("projection-constraint-row")
        key = (package, requirement)
        if key in pairs or ordered and key < ordered[-1]:
            _fail("projection-constraint-order")
        ids.add(ident)
        pairs.add(key)
        ordered.append(key)
    digest_body = {
        "schema": value["schema"], "profile": value["profile"], "toolchain": value["toolchain"],
        "target_set": value["target_set"], "resolution_mode": value["resolution_mode"],
        "resolver_version": value["resolver_version"],
        "constraints": [{"package": row["package"], "version_req": row["version_req"]} for row in rows],
    }
    if hashlib.sha256(bundle.canonical_json(digest_body)).hexdigest() != value["manifest_projection_sha256"]:
        _fail("projection-constraint-digest")
    if len(bundle.canonical_json(value)) > 4 * 1024 * 1024:
        _fail("projection-constraint-size")
    return value


def _validate_core_rust_v2_projection(value, expected_control_sha):
    fields = {"schema", "profile", "tools", "source_sets", "manifest_constraints",
              "manifest_projection_sha256"}
    if type(value) is not dict or set(value) != fields:
        _fail("projection-shape")
    if (value.get("schema") != 2 or value.get("profile") != "core-rust"
            or type(expected_control_sha) is not str
            or not re.fullmatch(r"[a-f0-9]{40}", expected_control_sha)):
        _fail("projection-binding")
    if value["tools"] != {"cargo": "1.99.1", "rustc": "1.99.1"}:
        _fail("projection-tool-version")
    source_sets = value["source_sets"]
    if type(source_sets) is not dict or source_sets != bundle._expected_core_rust_source_sets():
        _fail("projection-source-identity")
    constraints = value["manifest_constraints"]
    if type(constraints) is not dict or set(constraints) != {"candidate", "baseline_runtime"}:
        _fail("projection-constraint-scopes")
    candidate = _validate_constraint_envelope(
        constraints["candidate"], expected_source_sha=bundle.CORE_RUST_SOURCE_REVISION,
        expected_control_sha=expected_control_sha,
    )
    baseline = _validate_constraint_envelope(
        constraints["baseline_runtime"], expected_source_sha=bundle.CORE_RUST_BASELINE_REVISION,
        expected_control_sha=expected_control_sha, allow_empty=True,
    )

    if baseline["constraints"] != [] or baseline["resolver_version"] != "3":
        _fail("projection-baseline-constraints")
    digest_input = {
        "schema": 2,
        "profile": "core-rust",
        "tools": value["tools"],
        "source_sets": source_sets,
        "manifest_constraints": {
            "candidate": candidate["manifest_projection_sha256"],
            "baseline_runtime": baseline["manifest_projection_sha256"],
        },
    }
    digest = hashlib.sha256(bundle.canonical_json(digest_input)).hexdigest()
    if value["manifest_projection_sha256"] != digest:
        _fail("projection-manifest-digest")
    return value


def validate_projection(payload, expected_profile, expected_control_sha=None):
    value = strict_json(payload, MAX_PROJECTION)
    if expected_profile == "core-rust" and type(value) is dict and value.get("schema") == 2:
        return _validate_core_rust_v2_projection(value, expected_control_sha)
    required = {"schema", "profile", "npm", "cargo", "playwright", "tools", "cargo_workspaces"}
    if expected_profile in ("core-node", "desktop"):
        required |= {"npm_package", "npm_lock"}
    if expected_profile in ("core-rust", "desktop") or expected_profile in bundle.RUST_PROFILES:
        required |= {"cargo_manifest", "cargo_lock"}
    if type(value) is not dict or set(value) != required:
        _fail("projection-shape")
    if value.get("schema") != 1 or value.get("profile") != expected_profile:
        _fail("projection-binding")
    npm = value.get("npm")
    if type(npm) is not list or len(npm) > 5000:
        _fail("projection-npm")
    seen = set()
    for item in npm:
        if type(item) is not dict or set(item) != {"name", "version", "integrity", "resolved"}:
            _fail("projection-npm-entry")
        if (type(item["name"]) is not str or not NPM_NAME.fullmatch(item["name"])
                or type(item["version"]) is not str or not PACKAGE_VERSION.fullmatch(item["version"])
                or type(item["integrity"]) is not str or not re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", item["integrity"])
                or not _valid_registry_url(item["resolved"])):
            _fail("projection-npm-coordinate")
        key = (item["name"], item["version"])
        if key in seen:
            _fail("projection-npm-duplicate")
        seen.add(key)
    cargo = value.get("cargo")
    if type(cargo) is not list or len(cargo) > 5000:
        _fail("projection-cargo")
    seen = set()
    for item in cargo:
        if type(item) is not dict or set(item) != {"name", "version", "checksum"}:
            _fail("projection-cargo-entry")
        if (type(item["name"]) is not str or not CRATE_NAME.fullmatch(item["name"])
                or type(item["version"]) is not str or not PACKAGE_VERSION.fullmatch(item["version"])
                or type(item["checksum"]) is not str or not SHA256.fullmatch(item["checksum"])):
            _fail("projection-cargo-coordinate")
        key = (item["name"], item["version"])
        if key in seen:
            _fail("projection-cargo-duplicate")
        seen.add(key)
    cargo_workspaces = value.get("cargo_workspaces")
    if type(cargo_workspaces) is not list or len(cargo_workspaces) > 64:
        _fail("projection-cargo-workspaces")
    for item in cargo_workspaces:
        if type(item) is not dict or set(item) != {"path", "manifest", "lock"}:
            _fail("projection-cargo-workspace")
        allowed_workspace_paths = ("fuzz/Cargo.lock", "runtime/Cargo.lock") if expected_profile == "core-rust" else ()
        if type(item["path"]) is not str or item["path"] not in allowed_workspace_paths:
            _fail("projection-cargo-workspace-path")
        if type(item["manifest"]) is not str or len(item["manifest"]) > 2 * 1024 * 1024:
            _fail("projection-cargo-manifest")
        if type(item["lock"]) is not str or len(item["lock"]) > 8 * 1024 * 1024:
            _fail("projection-cargo-lock")
        validate_cargo_lock(item["lock"].encode("utf-8"))
    browsers = value.get("playwright")
    if (type(browsers) is not list or len(browsers) > 3
            or len(set(browsers)) != len(browsers)
            or any(type(item) is not str or item not in ("chromium", "firefox", "webkit") for item in browsers)):
        _fail("projection-playwright")
    tools = value.get("tools")
    expected_tools = (
        {"node", "npm"} if expected_profile == "core-node" else
        {"node", "npm", "cargo", "rustc"} if expected_profile == "desktop" else
        {"cargo", "rustc"} if expected_profile in bundle.RUST_PROFILES else set()
    )
    if type(tools) is not dict or set(tools) != expected_tools:
        _fail("projection-tools")
    if expected_profile == "core-node" and tools != {"node": "24.22.1", "npm": "11.19.1"}:
        _fail("projection-tool-version")
    if expected_profile in bundle.RUST_PROFILES and tools != {"cargo": "1.99.1", "rustc": "1.99.1"}:
        _fail("projection-tool-version")
    if expected_profile == "desktop" and tools != {
            "node": "26.8.1", "npm": "11.19.0", "cargo": "1.99.1", "rustc": "1.99.1"}:
        _fail("projection-tool-version")
    for version in tools.values():
        if type(version) is not str or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", version):
            _fail("projection-tool-version")
    if expected_profile in ("core-node", "desktop"):
        package, lock = value["npm_package"], value["npm_lock"]
        if type(package) is not dict or set(package) - {"name", "version", "private", "dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}:
            _fail("projection-npm-package")
        if package.get("name") != "devlane-projection" or package.get("version") != "0.0.0" or package.get("private") is not True:
            _fail("projection-npm-package")
        if type(lock) is not dict or lock.get("lockfileVersion") != 3 or type(lock.get("packages")) is not dict:
            _fail("projection-npm-lock")
        validate_npm_package_lock(json.dumps(lock, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        if value["playwright"] and "node_modules/@playwright/test" not in lock["packages"]:
            _fail("projection-playwright-package")
        if cargo_workspaces:
            _fail("projection-node-workspaces")
    if expected_profile in ("core-rust", "desktop"):
        expected_workspaces = ["fuzz/Cargo.lock", "runtime/Cargo.lock"] if expected_profile == "core-rust" else []
        if [item["path"] for item in cargo_workspaces] != expected_workspaces:
            _fail("projection-cargo-workspace-set")
    elif expected_profile == "local-sync-rust" and cargo_workspaces:
        _fail("projection-cargo-workspace-set")
    if expected_profile in bundle.RUST_TOOL_PROFILES:
        if type(value["cargo_manifest"]) is not str or len(value["cargo_manifest"]) > 2 * 1024 * 1024:
            _fail("projection-cargo-manifest")
        if type(value["cargo_lock"]) is not str or len(value["cargo_lock"]) > 8 * 1024 * 1024:
            _fail("projection-cargo-lock")
        validate_cargo_lock(value["cargo_lock"].encode("utf-8"))
    return value


def project_npm_lock(payload):
    """Return npm's minimal synthetic package/lock projection from a v2/v3 lock."""
    original = validate_npm_package_lock(payload)
    packages = original["packages"]
    root = packages[""]
    groups = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    package = {"name": "devlane-projection", "version": "0.0.0", "private": True}
    root_entry = {"name": "devlane-projection", "version": "0.0.0"}
    for group in groups:
        if group in root:
            mapping = root[group]
            if type(mapping) is not dict or len(mapping) > 5000:
                _fail("npm-lock-root-dependencies")
            safe_mapping = {}
            for name, spec in mapping.items():
                if (type(name) is not str or not NPM_NAME.fullmatch(name) or type(spec) is not str
                        or not re.fullmatch(r"(?:\^|~|>=|<=|>|<|=)?[0-9][0-9A-Za-z.+*-]*", spec)):
                    _fail("npm-lock-root-dependencies")
                safe_mapping[name] = spec
            package[group] = dict(sorted(safe_mapping.items()))
            root_entry[group] = dict(sorted(safe_mapping.items()))
    projected_packages = {"": root_entry}
    coordinates = {}
    for path in sorted(packages):
        if path == "":
            continue
        item = packages[path]
        if "version" not in item or "integrity" not in item or "resolved" not in item:
            _fail("npm-lock-coordinate-missing")
        name = path.rsplit("node_modules/", 1)[-1]
        if not NPM_NAME.fullmatch(name):
            _fail("npm-lock-package-name")
        allowed = {
            "version", "resolved", "integrity", "dev", "optional", "devOptional", "peer", "inBundle",
            "os", "cpu", "libc", "engines", "dependencies", "optionalDependencies", "peerDependencies",
            "peerDependenciesMeta", "bin",
        }
        projected_packages[path] = {key: item[key] for key in allowed if key in item}
        coordinate = {"name": name, "version": item["version"], "integrity": item["integrity"], "resolved": item["resolved"]}
        key = (name, item["version"])
        if key in coordinates and coordinates[key] != coordinate:
            _fail("npm-lock-coordinate-ambiguous")
        coordinates[key] = coordinate
    lock = {"name": "devlane-projection", "version": "0.0.0", "lockfileVersion": 3,
            "requires": True, "packages": projected_packages}
    normalized = sorted(coordinates.values(), key=lambda row: (row["name"], row["version"], row["resolved"]))
    return package, lock, normalized


def validate_npm_manifest_binding(payload, projected_package):
    """Bind the encrypted package manifest's dependency graph to the public projection."""
    original = strict_json(payload, 1024 * 1024)
    if type(original) is not dict or type(projected_package) is not dict:
        _fail("npm-manifest-shape")
    if "workspaces" in original:
        _fail("npm-workspaces-unsupported")
    groups = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    for group in groups:
        actual = original.get(group, {})
        projected = projected_package.get(group, {})
        _validate_npm_dependency_map(actual, "npm-manifest-dependencies")
        _validate_npm_dependency_map(projected, "npm-projection-dependencies")
        if actual != projected:
            _fail("npm-manifest-projection-mismatch")
    return True


def validate_cargo_lock(payload):
    if tomllib is None:
        _fail("cargo-lock-parser-unavailable")
    if type(payload) is not bytes or len(payload) > 8 * 1024 * 1024:
        _fail("cargo-lock-size")
    try:
        value = tomllib.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        _fail("cargo-lock-invalid")
    if type(value) is not dict or value.get("version") not in (3, 4) or type(value.get("package")) is not list:
        _fail("cargo-lock-shape")
    packages, seen = [], set()
    for item in value["package"]:
        if type(item) is not dict or type(item.get("name")) is not str or not CRATE_NAME.fullmatch(item["name"]):
            _fail("cargo-lock-package")
        if type(item.get("version")) is not str or not PACKAGE_VERSION.fullmatch(item["version"]):
            _fail("cargo-lock-version")
        source = item.get("source")
        if source is None:
            continue
        github_registry = "registry+https:" + chr(47) * 2 + "github.com/" + "rust-lang/" + "crates.io-index"
        if source not in (github_registry, "registry+https://index.crates.io/"):
            _fail("cargo-lock-source")
        checksum = item.get("checksum")
        if type(checksum) is not str or not SHA256.fullmatch(checksum):
            _fail("cargo-lock-checksum")
        deps = item.get("dependencies", [])
        if type(deps) is not list or any(type(dep) is not str or len(dep) > 512 or not dep.isascii() for dep in deps):
            _fail("cargo-lock-dependencies")
        identity = (item["name"], item["version"], source)
        if identity in seen:
            _fail("cargo-lock-duplicate")
        seen.add(identity)
        packages.append({"name": item["name"], "version": item["version"], "source": source,
                         "checksum": checksum, "dependencies": sorted(deps)})
    if len(packages) > 5000:
        _fail("cargo-lock-package-count")
    return sorted(packages, key=lambda row: (row["name"], row["version"], row["source"]))


def project_cargo_lock(payload):
    packages = validate_cargo_lock(payload)
    aliases, root_dependencies, crate_rows = [], [], []
    for index, item in enumerate(packages, 1):
        alias = "devlane-dep-%05d" % index
        aliases.append('%s = { package = %s, version = %s, optional = true }' % (
            alias, json.dumps(item["name"]), json.dumps("=" + item["version"])))
        root_dependencies.append("%s %s" % (item["name"], item["version"]))
        crate_rows.extend(["[[package]]", "name = " + json.dumps(item["name"]),
                           "version = " + json.dumps(item["version"]),
                           "source = " + json.dumps(item["source"]),
                           "checksum = " + json.dumps(item["checksum"])])
        if item["dependencies"]:
            crate_rows.append("dependencies = " + json.dumps(item["dependencies"]))
        crate_rows.append("")
    feature_list = ", ".join(json.dumps("dep:devlane-dep-%05d" % i) for i in range(1, len(packages) + 1))
    manifest = "\n".join(["[package]", 'name = "devlane-projection"', 'version = "0.0.0"', 'edition = "2021"',
                          "", "[workspace]", 'resolver = "2"',
                          "", "[features]", "all = [" + feature_list + "]", "", "[dependencies]", *aliases, ""])
    lock = "\n".join(["version = 3", "", "[[package]]", 'name = "devlane-projection"',
                       'version = "0.0.0"', "dependencies = " + json.dumps(root_dependencies), "", *crate_rows])
    validate_cargo_lock(lock.encode("utf-8"))
    coordinates = [{"name": item["name"], "version": item["version"], "checksum": item["checksum"]}
                   for item in packages]
    return manifest, lock, coordinates


def validate_npm_package_lock(payload):
    """Reject unsafe full npm lock metadata before using a synthetic projection."""
    value = strict_json(payload, MAX_PROJECTION)
    if type(value) is not dict or value.get("lockfileVersion") not in (2, 3) or type(value.get("packages")) is not dict:
        _fail("npm-lock-shape")
    packages = value["packages"]
    if "" not in packages or len(packages) > 5001:
        _fail("npm-lock-packages")
    for path, item in packages.items():
        if type(path) is not str or type(item) is not dict:
            _fail("npm-lock-package")
        if path == "":
            allowed = {"name", "version", "dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "engines"}
            if set(item) - allowed:
                _fail("npm-lock-root-metadata")
            for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                if group in item:
                    _validate_npm_dependency_map(item[group], "npm-lock-root-dependencies")
            continue
        """Every segment must be node_modules/<package>; nested copies are ordinary in real locks."""
        if not re.fullmatch(r"(?:node_modules/(?:@[^/]+/)?[^/]+/)*node_modules/(?:@[^/]+/)?[^/]+", path):
            _fail("npm-lock-path")
        package_path = path.rsplit("node_modules/", 1)[1]
        if not NPM_NAME.fullmatch(package_path) or ".." in path.split("/"):
            _fail("npm-lock-path")
        """Real npm lockfiles carry license, libc, funding and deprecation metadata. They are accepted as input but, apart from libc (needed to pick platform packages), never projected: see project_npm_lock."""
        allowed = {
            "version", "resolved", "integrity", "dev", "optional", "devOptional", "peer", "inBundle",
            "hasInstallScript", "os", "cpu", "libc", "engines", "dependencies", "optionalDependencies",
            "peerDependencies", "peerDependenciesMeta", "bin", "license", "funding", "deprecated",
        }
        if set(item) - allowed:
            _fail("npm-lock-metadata")
        if "license" in item and (type(item["license"]) is not str or len(item["license"]) > 256):
            _fail("npm-lock-license")
        if "deprecated" in item and (type(item["deprecated"]) is not str or len(item["deprecated"]) > 4096):
            _fail("npm-lock-deprecated")
        if "funding" in item and len(json.dumps(item["funding"])) > 4096:
            _fail("npm-lock-funding")
        if (type(item.get("version")) is not str or not PACKAGE_VERSION.fullmatch(item["version"])
                or type(item.get("resolved")) is not str or not _valid_registry_url(item["resolved"])):
            _fail("npm-lock-url")
        if type(item.get("integrity")) is not str or not re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", item["integrity"]):
            _fail("npm-lock-integrity")
        for flag in ("dev", "optional", "devOptional", "peer", "inBundle", "hasInstallScript"):
            if flag in item and type(item[flag]) is not bool:
                _fail("npm-lock-flag")
        """hasInstallScript is only a registry marker: installation always runs with scripts suppressed, and the marker is dropped from the projection."""
        for group in ("dependencies", "optionalDependencies", "peerDependencies"):
            if group in item:
                _validate_npm_dependency_map(item[group], "npm-lock-dependencies")
        if "peerDependenciesMeta" in item:
            metadata = item["peerDependenciesMeta"]
            if type(metadata) is not dict or len(metadata) > 5000:
                _fail("npm-lock-peer-meta")
            for name, flags in metadata.items():
                if type(name) is not str or not NPM_NAME.fullmatch(name) or type(flags) is not dict or set(flags) - {"optional"}:
                    _fail("npm-lock-peer-meta")
                if "optional" in flags and type(flags["optional"]) is not bool:
                    _fail("npm-lock-peer-meta")
        for platform_field in ("os", "cpu", "libc"):
            if platform_field in item:
                values = item[platform_field]
                if type(values) is not list or len(values) > 64 or any(type(value) is not str or not re.fullmatch(r"!?[A-Za-z0-9_-]{1,64}", value) for value in values):
                    _fail("npm-lock-platform")
        if "engines" in item:
            engines = item["engines"]
            if type(engines) is not dict or set(engines) - {"node", "npm"} or any(not _valid_npm_spec(value) for value in engines.values()):
                _fail("npm-lock-engine")
        if "bin" in item:
            bins = item["bin"]
            if type(bins) is str:
                bins = {name.rsplit("/", 1)[-1]: bins}
            if type(bins) is not dict or len(bins) > 128:
                _fail("npm-lock-bin")
            for name, relative in bins.items():
                if (type(name) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
                        or type(relative) is not str or relative.startswith("/") or "\\" in relative
                        or any(part in ("", ".", "..") for part in relative.split("/"))):
                    _fail("npm-lock-bin")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="operation", required=True)
    download = sub.add_parser("download")
    download.add_argument("--asset-id", required=True)
    download.add_argument("--size", required=True, type=int)
    download.add_argument("--sha256", required=True)
    download.add_argument("--maximum", type=int, default=MAX_CIPHERTEXT)
    download.add_argument("--output", required=True)
    projection = sub.add_parser("check-projection")
    projection.add_argument("--file", required=True)
    projection.add_argument("--profile", required=True)
    projection.add_argument("--control-sha")
    npm_lock = sub.add_parser("check-npm-lock")
    npm_lock.add_argument("--file", required=True)
    context = sub.add_parser("context")
    context.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "download":
            size = download_release_asset(args.asset_id, args.size, args.sha256, args.output, args.maximum)
            print("public_asset_verified=true bytes=" + str(size))
        elif args.operation == "check-projection":
            validate_projection(Path(args.file).read_bytes(), args.profile, expected_control_sha=args.control_sha)
            print("fetch_projection_valid=true")
        elif args.operation == "check-npm-lock":
            validate_npm_package_lock(Path(args.file).read_bytes())
            print("npm_lock_projection_valid=true")
        else:
            identity = context_from_environment(os.environ)
            _write_private(args.output, json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
            run_id = os.environ.get("CI_RUN_ID", "")
            if not re.fullmatch(r"[1-9][0-9]{0,18}", run_id):
                _fail("dispatch-run-id")
            print("dispatch_context=validated")
        return 0
    except Refusal as error:
        print("devlane_refusal=" + str(error))
        return 2
    except Exception:
        print("devlane_refusal=fetch-failed")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
