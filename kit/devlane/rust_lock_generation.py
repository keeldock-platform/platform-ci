"""Bind authenticated manifests and offline-generated locks inside the cut worker."""

import hashlib
import re

import bundle
import constraint_resolver
import registry_prefetch

LOCKS = (("Cargo.toml", "Cargo.lock"), ("runtime/Cargo.toml", "runtime/Cargo.lock"),
         ("fuzz/Cargo.toml", "fuzz/Cargo.lock"))


def verify_manifest_constraints(source_files, projection, control_sha):
    """Recompute the public projection from the already authenticated source bytes."""
    if any(".cargo" in name.split("/") for name in source_files):
        raise bundle.Refusal("source-constraint-projection-mismatch")
    prefix = bundle.BASELINE_NAMESPACE + "/"
    scopes = (
        ("candidate", {name: payload for name, payload in source_files.items()
                       if name.endswith("Cargo.toml") and not name.startswith(prefix)},
         bundle.CORE_RUST_SOURCE_REVISION, list(constraint_resolver.PRODUCTION_MANIFESTS), False),
        ("baseline_runtime", {name[len(prefix):]: payload for name, payload in source_files.items()
                              if name.startswith(prefix) and name.endswith("Cargo.toml")},
         bundle.CORE_RUST_BASELINE_REVISION, ["Cargo.toml"], True),
    )
    for scope, manifests, revision, selected, allow_empty in scopes:
        actual = constraint_resolver.build_manifest_constraint_envelope(
            manifests=manifests, source_commit=revision, control_sha=control_sha,
            selected_manifests=selected, allow_empty=allow_empty)
        expected = projection["manifest_constraints"][scope]
        if actual["manifest_projection_sha256"] != expected["manifest_projection_sha256"]:
            raise bundle.Refusal("source-constraint-projection-mismatch")


def command(manifest):
    if manifest not in {row[0] for row in LOCKS}:
        raise bundle.Refusal("generated-lock-manifest")
    return ["/tools/rust/bin/cargo", "generate-lockfile", "--offline", "--manifest-path",
            "/workspace/source/" + manifest,
            "--config", 'source.crates-io.replace-with="prepared-registry"',
            "--config", 'source.prepared-registry.local-registry="/prepared/cargo-local-registry"',
            "--config", "net.offline=true", "--config", "net.retry=0"]


def validate_preparation(preparation, projection, control_sha):
    if type(preparation) is not dict:
        raise bundle.Refusal("generated-lock-input-binding")
    if (preparation.get("schema") != 2
            or preparation.get("source_commit") != bundle.CORE_RUST_SOURCE_REVISION
            or preparation.get("control_sha") != control_sha
            or preparation.get("manifest_projection_sha256") != projection["manifest_projection_sha256"]):
        raise bundle.Refusal("generated-lock-input-binding")
    rows = registry_prefetch._validate_packages(preparation["packages"])
    if preparation.get("baseline_external_packages") != []:
        raise bundle.Refusal("generated-lock-input-binding")
    hashes = preparation.get("tool_hashes")
    expected = {"cargo_sha256", "rustc_sha256", "cargo_version_output_sha256",
                "rustc_version_output_sha256"}
    if (type(hashes) is not dict or set(hashes) != expected
            or any(type(value) is not str or not re.fullmatch(r"[a-f0-9]{64}", value)
                   for value in hashes.values())
            or preparation.get("tool_provenance_status") != "binary-hash-bound-origin-unverified"):
        raise bundle.Refusal("generated-lock-input-binding")
    return rows


def output_record(locks, preparation, projection, control_sha):
    if set(locks) != {row[1] for row in LOCKS}:
        raise bundle.Refusal("generated-lock-set")
    allowed = {tuple(row[key] for key in ("name", "version", "checksum"))
               for row in validate_preparation(preparation, projection, control_sha)}
    hashes = {}
    for name, payload in locks.items():
        rows = constraint_resolver.lock_package_rows(payload)
        if any(tuple(row[key] for key in ("name", "version", "checksum")) not in allowed for row in rows):
            raise bundle.Refusal("generated-lock-outside-registry")
        hashes[name] = hashlib.sha256(payload).hexdigest()
    return {"schema": 1, "source_commit": bundle.CORE_RUST_SOURCE_REVISION,
            "control_sha": control_sha, "status": "ephemeral-offline-generated-not-committed",
            "input_projection_sha256": projection["manifest_projection_sha256"],
            "tool_hashes": preparation["tool_hashes"],
            "tool_provenance_status": preparation["tool_provenance_status"],
            "generated_lock_sha256": hashes}
