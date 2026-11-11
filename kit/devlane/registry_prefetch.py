"""Build an exact, source-free crates.io local registry from a package projection.

The registry contains only the package coordinates in Cargo-generated lockfiles.
No Cargo cache, project source, manifests, or dependency edges cross the preparation
boundary. Cargo's official index metadata is filtered to those exact stable rows.
"""

from __future__ import annotations

import hashlib
import json
import argparse
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import cargo_projection


INDEX_HOST = "index.crates.io"
CRATE_HOST = "static.crates.io"
ALLOWED_HOSTS = frozenset((INDEX_HOST, CRATE_HOST))
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_TOTAL_INDEX_BYTES = 512 * 1024 * 1024
MAX_INDEX_LINE = 1024 * 1024
MAX_INDEX_ROWS = 200_000
MAX_CRATE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
MAX_PACKAGES = 5000
MAX_REDIRECTS = 3
HEX = re.compile(r"[a-f0-9]{64}\Z")
INDEX_FIELDS = frozenset(("name", "vers", "deps", "cksum", "features", "yanked",
                          "links", "v", "features2", "rust_version", "pubtime"))
DEP_FIELDS = frozenset(("name", "req", "features", "optional", "default_features",
                        "target", "kind", "registry", "package"))
PRINTABLE = re.compile(r"[ -~]{1,4096}\Z")
RUST_VERSION = re.compile(cargo_projection.STABLE_COMPONENT + r"\." + cargo_projection.STABLE_COMPONENT
                          + r"(?:\." + cargo_projection.STABLE_COMPONENT + r")?\Z")
PUBTIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
LOCAL_INDEX_CONFIG = (
    b'{"api":"https://crates.io","dl":"https://static.crates.io/crates/{crate}/{crate}-{version}.crate"}\n'
)


class Refusal(ValueError):
    """Safe policy code; never includes URLs, paths, or resolver output."""


def _refuse(code: str) -> None:
    raise Refusal(code)


def crate_index_path(name: str) -> str:
    if type(name) is not str or not name or name != name.lower() or not cargo_projection.CRATE.fullmatch(name):
        _refuse("package-name")
    if len(name) == 1:
        return "1/" + name
    if len(name) == 2:
        return "2/" + name
    if len(name) == 3:
        return "3/" + name[0] + "/" + name
    return name[:2] + "/" + name[2:4] + "/" + name


def _validate_packages(packages: object) -> list[dict[str, str]]:
    if type(packages) is not list or len(packages) > MAX_PACKAGES:
        _refuse("package-list")
    result = []
    previous = None
    for row in packages:
        name, version, checksum = cargo_projection._valid_package(row)
        if name != name.lower():
            _refuse("package-name")
        identity = (name, version)
        if previous is not None and identity <= previous:
            _refuse("package-order")
        previous = identity
        result.append({"name": name, "version": version, "checksum": checksum})
    return result


def _safe_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    return (parsed.scheme == "https" and parsed.hostname in ALLOWED_HOSTS
            and parsed.username is None and parsed.password is None
            and port in (None, 443) and not parsed.fragment)


class _RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirects = req.redirect_dict or {}
        if len(redirects) >= MAX_REDIRECTS or not _safe_url(newurl):
            _refuse("registry-redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _read_official(url: str, maximum: int) -> bytes:
    if not _safe_url(url):
        _refuse("registry-url")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _RestrictedRedirect(),
    )
    request = urllib.request.Request(url, headers={
        "Accept-Encoding": "identity",
        "User-Agent": "keeldock-platform-registry/1",
    })
    try:
        with opener.open(request, timeout=30) as response:
            if response.status != 200 or not _safe_url(response.geturl()):
                _refuse("registry-response")
            encoding = response.headers.get("Content-Encoding", "identity").lower()
            if encoding not in ("", "identity"):
                _refuse("registry-encoding")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isascii() or not length.isdecimal() or int(length) > maximum):
                _refuse("registry-response-size")
            payload = response.read(maximum + 1)
            if len(payload) > maximum:
                _refuse("registry-response-size")
            return payload
    except Refusal:
        raise
    except (OSError, TimeoutError, urllib.error.URLError, ValueError):
        _refuse("registry-fetch")


def _index_records(name: str, payload: bytes, wanted: dict[str, str]) -> bytes:
    if type(payload) is not bytes or not payload or len(payload) > MAX_INDEX_BYTES:
        _refuse("registry-index-size")
    selected: dict[str, dict[str, object]] = {}
    try:
        lines = payload.splitlines()
        if len(lines) > MAX_INDEX_ROWS:
            _refuse("registry-index-count")
        for line in lines:
            if not line or len(line) > MAX_INDEX_LINE:
                continue
            try:
                row = json.loads(line.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                continue
            if type(row) is not dict:
                continue
            version = row.get("vers")
            if row.get("name") != name or type(version) is not str or version not in wanted:
                continue
            checksum = row.get("cksum")
            if (set(row) - INDEX_FIELDS or not {"name", "vers", "deps", "cksum", "yanked"}.issubset(row)
                    or type(version) is not str or cargo_projection.STABLE_VERSION.fullmatch(version) is None
                    or type(checksum) is not str or HEX.fullmatch(checksum) is None
                    or checksum != wanted[version] or type(row.get("yanked")) is not bool
                    or row.get("yanked") or not _valid_index_fields(row)):
                _refuse("registry-index-record")
            if version in selected:
                _refuse("registry-index-duplicate")


            selected[version] = row
    except Refusal:
        raise
    if set(selected) != set(wanted):
        _refuse("registry-index-missing")
    def semver_key(version: str) -> tuple[int, int, int]:
        return tuple(int(part) for part in version.split("."))
    return b"".join(
        json.dumps(selected[version], ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        for version in sorted(selected, key=semver_key)
    )


def _valid_index_fields(row: dict[str, object]) -> bool:
    """Validate Cargo's public stable index fields before placing them offline."""
    schema = row.get("v", 1)
    if type(schema) is not int or schema not in (1, 2):
        return False
    if "features2" in row and schema < 2:
        return False

    if not _valid_feature_table(row.get("features", {})):
        return False
    if "features2" in row and not _valid_feature_table(row["features2"]):
        return False
    dependencies = row.get("deps")
    if type(dependencies) is not list or len(dependencies) > 10_000:
        return False
    for dependency in dependencies:
        if type(dependency) is not dict or set(dependency) - DEP_FIELDS or not {"name", "req"}.issubset(dependency):
            return False
        if not _safe_package_text(dependency["name"], 128) or cargo_projection.CRATE.fullmatch(dependency["name"]) is None:
            return False
        if not _safe_package_text(dependency["req"], 512):
            return False
        if "features" in dependency:
            features = dependency["features"]
            if type(features) is not list or len(features) > 4096 or any(not _safe_package_text(item, 256) for item in features):
                return False
        for key in ("optional", "default_features"):
            if key in dependency and type(dependency[key]) is not bool:
                return False
        if "target" in dependency and dependency["target"] is not None and not _safe_package_text(dependency["target"], 4096):
            return False
        if dependency.get("kind") not in (None, "normal", "build", "dev"):
            return False

        if dependency.get("registry") is not None:
            return False
        if dependency.get("package") is not None and (
                not _safe_package_text(dependency["package"], 128)
                or cargo_projection.CRATE.fullmatch(dependency["package"]) is None):
            return False
    if "links" in row and row["links"] is not None and not _safe_package_text(row["links"], 256):
        return False
    if "rust_version" in row and (type(row["rust_version"]) is not str
            or RUST_VERSION.fullmatch(row["rust_version"]) is None):
        return False
    if "pubtime" in row and (type(row["pubtime"]) is not str or PUBTIME.fullmatch(row["pubtime"]) is None):
        return False
    return True


def _safe_package_text(value: object, maximum: int) -> bool:
    return (type(value) is str and len(value) <= maximum and value.isascii()
            and PRINTABLE.fullmatch(value) is not None)


def _valid_feature_table(value: object) -> bool:
    if type(value) is not dict or len(value) > 10_000:
        return False
    for feature, members in value.items():
        if (not _safe_package_text(feature, 256) or type(members) is not list or len(members) > 10_000
                or any(not _safe_package_text(member, 256) for member in members)):
            return False
    return True


def _write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        _refuse("registry-output-exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


def _index_url(name: str) -> str:
    return "https://%s/%s" % (INDEX_HOST, crate_index_path(name))


def _crate_url(name: str, version: str) -> str:
    return "https://%s/crates/%s/%s-%s.crate" % (CRATE_HOST, name, name, version)


def build_registry(packages: object, destination: str | Path, fetcher=None) -> list[dict[str, str]]:
    """Fetch exact official index rows and crate archives into a new local registry."""
    rows = _validate_packages(packages)
    root = Path(destination)
    if root.exists() or root.is_symlink():
        _refuse("registry-root-exists")
    root.mkdir(mode=0o700, parents=True)
    (root / "index").mkdir(mode=0o700)
    fetch = fetcher or _read_official
    total = 0
    total_index = 0
    try:
        _write_new(root / "index" / "config.json", LOCAL_INDEX_CONFIG)
        by_name: dict[str, list[dict[str, str]]] = {}
        for row in rows:
            by_name.setdefault(row["name"], []).append(row)
        for name, entries in sorted(by_name.items()):
            wanted = {row["version"]: row["checksum"] for row in entries}
            index_payload = fetch(_index_url(name), MAX_INDEX_BYTES)
            if type(index_payload) is not bytes:
                _refuse("registry-index-size")
            total_index += len(index_payload)
            if total_index > MAX_TOTAL_INDEX_BYTES:
                _refuse("registry-index-total-size")
            filtered = _index_records(name, index_payload, wanted)
            _write_new(root / "index" / crate_index_path(name), filtered)
        for row in rows:
            url = _crate_url(row["name"], row["version"])
            archive = fetch(url, MAX_CRATE_BYTES)
            if type(archive) is not bytes or not archive or len(archive) > MAX_CRATE_BYTES:
                _refuse("registry-crate-size")
            if hashlib.sha256(archive).hexdigest() != row["checksum"]:
                _refuse("registry-crate-checksum")
            total += len(archive)
            if total > MAX_TOTAL_BYTES:
                _refuse("registry-total-size")
            _write_new(root / (row["name"] + "-" + row["version"] + ".crate"), archive)
        verify_registry_tree(root, rows)
        return rows
    except Exception:

        import shutil
        shutil.rmtree(root, ignore_errors=True)
        raise


def verify_registry_tree(directory: str | Path, expected_packages: object) -> None:
    """Rehash every package and require the exact local-registry file inventory."""
    rows = _validate_packages(expected_packages)
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        _refuse("registry-tree")
    expected_crates = {row["name"] + "-" + row["version"] + ".crate": row for row in rows}
    by_name: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_name.setdefault(row["name"], []).append(row)
    expected_indexes = {crate_index_path(name): items for name, items in by_name.items()}
    expected_directories = {"index"}
    for index_path in expected_indexes:
        parts = Path("index", index_path).parts
        for count in range(1, len(parts)):
            expected_directories.add(Path(*parts[:count]).as_posix())
    seen_crates = set()
    seen_indexes = set()
    seen_config = False
    seen_directories = set()
    total = 0
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        relative = base.relative_to(root)
        for name in directories:
            directory = base / name
            if directory.is_symlink():
                _refuse("registry-symlink")
            directory_relative = directory.relative_to(root).as_posix()
            if directory_relative not in expected_directories:
                _refuse("registry-directory-extra")
            seen_directories.add(directory_relative)
        for name in files:
            path = base / name
            if path.is_symlink() or not path.is_file():
                _refuse("registry-file")
            if relative.parts and relative.parts[0] == "index":
                index_path = path.relative_to(root / "index").as_posix()
                if index_path == "config.json":
                    if path.stat().st_size > 4096 or path.read_bytes() != LOCAL_INDEX_CONFIG:
                        _refuse("registry-config-drift")
                    seen_config = True
                    continue
                expected = expected_indexes.get(index_path)
                if expected is None:
                    _refuse("registry-index-extra")
                if path.stat().st_size > MAX_INDEX_BYTES:
                    _refuse("registry-index-size")
                payload = path.read_bytes()
                wanted = {row["version"]: row["checksum"] for row in expected}
                filtered = _index_records(expected[0]["name"], payload, wanted)
                if filtered != payload:
                    _refuse("registry-index-drift")
                seen_indexes.add(index_path)
            elif relative == Path("."):
                row = expected_crates.get(name)
                if row is None:
                    _refuse("registry-crate-extra")
                digest = hashlib.sha256()
                size = 0
                with path.open("rb") as stream:
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        total += len(chunk)
                        if size > MAX_CRATE_BYTES or total > MAX_TOTAL_BYTES:
                            _refuse("registry-crate-size")
                        digest.update(chunk)
                if digest.hexdigest() != row["checksum"]:
                    _refuse("registry-crate-checksum")
                seen_crates.add(name)
            else:
                _refuse("registry-path")
    if (not seen_config or seen_crates != set(expected_crates) or seen_indexes != set(expected_indexes)
            or seen_directories != expected_directories):
        _refuse("registry-incomplete")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse("package-list-duplicate-key")
        result[key] = value
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="operation", required=True)
    prefetch = commands.add_parser("prefetch")
    prefetch.add_argument("--packages", required=True)
    prefetch.add_argument("--destination", required=True)
    args = parser.parse_args(argv)
    try:
        payload = Path(args.packages).read_bytes()
        if not payload or len(payload) > 4 * 1024 * 1024:
            _refuse("package-list-size")
        try:
            value = json.loads(payload.decode("ascii", "strict"), object_pairs_hook=_unique_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            _refuse("package-list-parse")
        if (type(value) is not dict or set(value) != {"schema", "packages"}
                or type(value["schema"]) is not int or value["schema"] != 1):
            _refuse("package-list-shape")
        build_registry(value["packages"], args.destination)
        print("registry_prefetch=complete")
        return 0
    except Exception:
        print("registry_prefetch_refusal=invalid", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

