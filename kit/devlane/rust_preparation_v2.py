"""Prepare public registry inputs without decrypting or staging product source."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


sys.path.insert(0, str(Path(__file__).resolve().parent))
import bounded_registry_io
import bundle
import constraint_resolver
import deadline
import fetch

CONFIG = ('[source.crates-io]\nreplace-with = "prepared-registry"\n'
          '[source.prepared-registry]\nlocal-registry = "/prepared/cargo-local-registry"\n'
          '[net]\noffline = true\nretry = 0\n')
MAX_INPUT = 4 * 1024 * 1024


def read_input(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_INPUT:
            raise bundle.Refusal("rust-preparation-input-type")
        with os.fdopen(fd, "rb", closefd=False) as source:
            payload = source.read(MAX_INPUT + 1)
        if len(payload) > MAX_INPUT:
            raise bundle.Refusal("rust-preparation-input-size")
        return payload
    finally:
        os.close(fd)


def prepare(projection_payload, *, control_sha, scratch, output, deadline_file):
    """Resolve sanitized public constraints and verify the resulting crate archives."""
    projection = fetch.validate_projection(
        projection_payload, "core-rust", expected_control_sha=control_sha)
    if projection["schema"] != 2:
        raise bundle.Refusal("rust-preparation-schema")
    outer = deadline._read(deadline_file)
    budget = bounded_registry_io.PhaseBudget.from_outer_deadlines(
        outer["work_deadline"], outer["work_deadline"] + outer["cleanup_reserve"])
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise bundle.Refusal("rust-preparation-output-exists")

    resolution = constraint_resolver.run_cargo_fixed_point(
        projection["manifest_constraints"]["candidate"],
        expected_source_sha=bundle.CORE_RUST_SOURCE_REVISION,
        expected_control_sha=control_sha, cargo="/tools/rust/bin/cargo",
        rustc="/tools/rust/bin/rustc", scratch_parent=scratch,
        deadline_file=deadline_file, phase_budget=budget)
    output.mkdir(mode=0o700)
    packages, inventory = bounded_registry_io.build_bounded_registry(
        resolution["packages"], output / "cargo-local-registry", budget)
    budget.remaining()
    record = {
        "schema": 2, "source_commit": bundle.CORE_RUST_SOURCE_REVISION,
        "control_sha": control_sha,
        "manifest_projection_sha256": projection["manifest_projection_sha256"],
        "resolver_lock_sha256": hashlib.sha256(resolution["resolver_lock"]).hexdigest(),
        "tool_hashes": resolution["tool_hashes"],
        "tool_provenance_status": resolution["tool_provenance_status"],
        "packages": packages, "inventory": inventory,
        "baseline_external_packages": [],
    }
    for name, payload in (
        ("projection.json", bundle.canonical_json(projection) + b"\n"),
        ("cargo-config.toml", CONFIG.encode("ascii")),
        ("registry-preparation.json", bundle.canonical_json(record) + b"\n"),
    ):
        budget.remaining()
        with (output / name).open("xb") as destination:
            destination.write(payload)
    budget.remaining()
    return record


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-sha", required=True)
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux") or os.geteuid() != 65534:
        raise bundle.Refusal("rust-preparation-worker-required")
    prepare(read_input("/control/input/projection.json"), control_sha=args.control_sha,
            scratch=Path("/work/resolver"), output=Path("/work/prepared"),
            deadline_file="/control/input/deadline.json")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:

        raise SystemExit(2)
