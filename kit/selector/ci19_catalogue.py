"""Build and validate the staged ci19 MCP feature-owner snapshot."""

import argparse
import hashlib
import json
import re
from pathlib import Path


SCHEMA_VERSION = 1
CANONICAL_SOURCE_SHA256 = "4b2e9a9eedbea850ef4e1c13dbdca9989e9d49fac7e61e3fc9999b23d110fe3a"
EXPECTED_OWNERS = (
    ("settings", "core.settings-schema"),
    ("ui", "core.shell-ui"),
    ("workspace", "core.workspace"),
    ("logs", "core.log"),
    ("search", "core.search"),
    ("diagnostics", "core.diagnostics"),
    ("windows", "core.windows"),
    ("ai", "core.ai"),
)
FEATURE_PATH_RE = re.compile(r"crates/host/mcp-host/([a-z][a-z0-9-]{0,31})/\*\*")
SUITE_RE = re.compile(r"`(core\.[a-z0-9.-]{1,96})`")


class CatalogueError(ValueError):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CatalogueError("snapshot-invalid")
        result[key] = value
    return result


def parse_catalogue(markdown):
    if type(markdown) is not str or len(markdown) > 2 * 1024 * 1024:
        raise CatalogueError("catalogue-invalid")
    observed = []
    for line in markdown.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        suite_match = SUITE_RE.fullmatch(cells[0])
        if suite_match is None:
            continue
        observed.extend((folder, suite_match.group(1)) for folder in FEATURE_PATH_RE.findall(cells[3]))
    if (len(observed) != len(EXPECTED_OWNERS)
            or len(set(observed)) != len(observed)
            or dict(observed) != dict(EXPECTED_OWNERS)):
        raise CatalogueError("catalogue-owners-invalid")
    return EXPECTED_OWNERS


def build_snapshot(source_bytes):
    if type(source_bytes) is not bytes or not 1 <= len(source_bytes) <= 2 * 1024 * 1024:
        raise CatalogueError("catalogue-invalid")
    try:
        markdown = source_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise CatalogueError("catalogue-invalid") from error
    owners = parse_catalogue(markdown)
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    if source_sha256 != CANONICAL_SOURCE_SHA256:
        raise CatalogueError("catalogue-digest-invalid")
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "catalogue_sha256": source_sha256,
        "owners": [{"folder": folder, "suite": suite} for folder, suite in owners],
    }
    return (json.dumps(snapshot, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("ascii")


def validate_snapshot(snapshot_bytes):
    if type(snapshot_bytes) is not bytes or not 1 <= len(snapshot_bytes) <= 8192:
        raise CatalogueError("snapshot-invalid")
    try:
        snapshot = json.loads(
            snapshot_bytes.decode("ascii", "strict"), object_pairs_hook=_unique_object
        )
    except (UnicodeDecodeError, ValueError):
        raise CatalogueError("snapshot-invalid")
    if (type(snapshot) is not dict
            or set(snapshot) != {"schema_version", "catalogue_sha256", "owners"}
            or type(snapshot["schema_version"]) is not int
            or snapshot["schema_version"] != SCHEMA_VERSION
            or snapshot["catalogue_sha256"] != CANONICAL_SOURCE_SHA256
            or snapshot["owners"] != [{"folder": folder, "suite": suite}
                                      for folder, suite in EXPECTED_OWNERS]):
        raise CatalogueError("snapshot-invalid")
    return tuple(EXPECTED_OWNERS)


def load_snapshot(path):
    try:
        return validate_snapshot(Path(path).read_bytes())
    except OSError as error:
        raise CatalogueError("snapshot-unavailable") from error


def generate(source, output):
    source_path = Path(source)
    output_path = Path(output)
    payload = build_snapshot(source_path.read_bytes())
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return payload


def _main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args(argv)
    try:
        generate(arguments.source, arguments.output)
    except (OSError, CatalogueError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
