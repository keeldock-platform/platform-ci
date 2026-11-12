"""Coordinator-only data projection builder; it never imports project modules."""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import bundle
import constraint_resolver
import fetch


def _source_manifests(repository, revision, *, baseline=False):
    repository = Path(repository).resolve(strict=True)
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "--verify", revision + "^{commit}"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=30)
    if result.returncode != 0 or result.stdout.strip() != revision.encode("ascii"):
        bundle._refuse("projection-source-revision")
    if not baseline:
        result = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "--verify", revision + "^{tree}"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=30)
        if result.returncode != 0 or result.stdout.strip() != bundle.CORE_RUST_SOURCE_TREE.encode("ascii"):
            bundle._refuse("projection-source-tree")
    result = subprocess.run(
        ["git", "-C", str(repository), "ls-tree", "-r", "-z", "--full-tree", revision],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=60)
    if result.returncode != 0 or len(result.stdout) > bundle.MAX_EXPANDED:
        bundle._refuse("projection-tree-unavailable")
    manifests, selected, all_paths = {}, set(), set()
    for row in result.stdout.split(b"\x00"):
        if not row:
            continue
        try:
            metadata, raw_name = row.split(b"\t", 1)
            mode, kind, oid = metadata.split(b" ", 2)
            name = raw_name.decode("utf-8", "strict")
        except (ValueError, UnicodeDecodeError):
            bundle._refuse("projection-tree-entry")
        if name in all_paths:
            bundle._refuse("projection-tree-entry")
        all_paths.add(name)
        if baseline:
            if not name.startswith("runtime/"):
                continue
            name = name[len("runtime/"):]
        elif name == ".npmrc":
            continue
        name = bundle._safe_member_name(name)
        if (mode not in (b"100644", b"100755") or kind != b"blob"
                or not re.fullmatch(rb"[a-f0-9]{40,64}", oid)):
            bundle._refuse("projection-source-type")
        selected.add(name)
        if name == "Cargo.toml" or name.endswith("/Cargo.toml"):
            if mode != b"100644":
                bundle._refuse("projection-source-type")
            manifests[name] = bundle._git_blob(repository, oid.decode("ascii"))
    expected_count = (bundle.CORE_RUST_BASELINE_FILE_COUNT if baseline
                      else bundle.CORE_RUST_SELECTED_FILE_COUNT)
    if len(selected) != expected_count or not manifests:
        bundle._refuse("projection-source-inventory")
    if not baseline and all_paths - selected != {".npmrc"}:
        bundle._refuse("projection-source-inventory")
    expected = ({"Cargo.toml": bundle.CORE_RUST_BASELINE_RUNTIME_MANIFEST_SHA256} if baseline
                else bundle.CORE_RUST_SELECTED_MANIFEST_SHA256)
    if any(name not in manifests or hashlib.sha256(manifests[name]).hexdigest() != digest
           for name, digest in expected.items()):
        bundle._refuse("projection-source-manifest")
    return manifests


def build_source_bound_rust_projection(repository, control_sha, *, baseline_repository=None):
    """Read immutable Git manifests locally and emit only sanitized public constraints."""
    if type(control_sha) is not str or not re.fullmatch(r"[a-f0-9]{40}", control_sha):
        bundle._refuse("projection-source-control")
    candidate = _source_manifests(repository, bundle.CORE_RUST_SOURCE_REVISION)
    baseline = _source_manifests(baseline_repository or repository,
                                 bundle.CORE_RUST_BASELINE_REVISION, baseline=True)
    constraints = {
        "candidate": constraint_resolver.build_manifest_constraint_envelope(
            manifests=candidate, source_commit=bundle.CORE_RUST_SOURCE_REVISION,
            control_sha=control_sha, selected_manifests=list(constraint_resolver.PRODUCTION_MANIFESTS)),
        "baseline_runtime": constraint_resolver.build_manifest_constraint_envelope(
            manifests=baseline, source_commit=bundle.CORE_RUST_BASELINE_REVISION,
            control_sha=control_sha, selected_manifests=["Cargo.toml"], allow_empty=True),
    }
    return build_projection({
        "schema": 2, "profile": "core-rust", "control_sha": control_sha,
        "tools": {"cargo": "1.99.1", "rustc": "1.99.1"},
        "source_sets": bundle._expected_core_rust_source_sets(), "manifest_constraints": constraints})


def build_projection(request):
    if type(request) is not dict:
        bundle._refuse("projection-request-shape")
    profile = request.get("profile")
    if profile not in bundle.ENCRYPTED_PROFILES:
        bundle._refuse("projection-profile")
    if profile == "core-rust" and type(request) is dict and request.get("schema") == 2:
        expected = {"schema", "profile", "control_sha", "tools", "source_sets", "manifest_constraints"}
        if set(request) != expected or type(request.get("control_sha")) is not str:
            bundle._refuse("projection-request-shape")
        if (type(request["source_sets"]) is not dict
                or request["source_sets"] != bundle._expected_core_rust_source_sets()):
            bundle._refuse("projection-source-identity")
        if request["tools"] != {"cargo": "1.99.1", "rustc": "1.99.1"}:
            bundle._refuse("projection-tool-versions")
        result = {
            "schema": 2,
            "profile": "core-rust",
            "tools": request["tools"],
            "source_sets": request["source_sets"],
            "manifest_constraints": request["manifest_constraints"],
        }
        constraints = result["manifest_constraints"]
        if type(constraints) is not dict or set(constraints) != {"candidate", "baseline_runtime"}:
            bundle._refuse("projection-constraint-scopes")
        try:
            candidate = constraints["candidate"]["manifest_projection_sha256"]
            baseline = constraints["baseline_runtime"]["manifest_projection_sha256"]
        except (KeyError, TypeError):
            bundle._refuse("projection-constraint-scopes")
        digest_input = {
            "schema": 2, "profile": "core-rust", "tools": request["tools"],
            "source_sets": request["source_sets"],
            "manifest_constraints": {"candidate": candidate, "baseline_runtime": baseline},
        }
        result["manifest_projection_sha256"] = hashlib.sha256(bundle.canonical_json(digest_input)).hexdigest()
        serialized = bundle.canonical_json(result)
        fetch.validate_projection(serialized, profile, expected_control_sha=request["control_sha"])
        return serialized
    common = {"schema", "repository", "source_revision", "profile", "tools", "playwright"}
    expected = common | ({"lockfile"} if profile == "core-node" else {"lockfiles"})
    if set(request) != expected or request.get("schema") != 1:
        bundle._refuse("projection-request-shape")
    repository = Path(request["repository"]).resolve(strict=True)
    revision = request["source_revision"]
    if type(revision) is not str or not bundle.GIT_SHA.fullmatch(revision):
        bundle._refuse("projection-source-revision")
    tools = request["tools"]
    if type(tools) is not dict:
        bundle._refuse("projection-tool-versions")
    expected_tools = (
        {"node", "npm"} if profile == "core-node" else
        {"node", "npm", "cargo", "rustc"} if profile == "desktop" else
        {"cargo", "rustc"}
    )
    if set(tools) != expected_tools:
        bundle._refuse("projection-tool-versions")
    lockfiles = [request["lockfile"]] if profile == "core-node" else request["lockfiles"]
    if (type(lockfiles) is not list or not lockfiles or len(lockfiles) > 65
            or any(type(item) is not str for item in lockfiles)):
        bundle._refuse("projection-lockfiles")
    lockfiles = [bundle._safe_member_name(item) for item in lockfiles]
    if len(lockfiles) != len(set(lockfiles)):
        bundle._refuse("projection-lockfile-duplicate")
    if profile == "core-rust" and lockfiles != ["Cargo.lock", "fuzz/Cargo.lock", "runtime/Cargo.lock"]:
        bundle._refuse("projection-rust-lockfile-set")
    if profile == "desktop" and lockfiles != ["package-lock.json", "Cargo.lock"]:
        bundle._refuse("projection-desktop-lockfile-set")
    if profile == "local-sync-rust" and lockfiles != ["local-sync/Cargo.lock"]:
        bundle._refuse("projection-rust-lockfile-set")
    tree = bundle.subprocess.run(
        ["git", "-C", str(repository), "ls-tree", "-r", "-z", "--full-tree", revision],
        check=False, stdout=bundle.subprocess.PIPE, stderr=bundle.subprocess.DEVNULL, timeout=60,
    )
    if tree.returncode != 0 or len(tree.stdout) > bundle.MAX_EXPANDED:
        bundle._refuse("projection-tree-unavailable")
    blob_ids = {}
    for row in tree.stdout.split(b"\x00"):
        if not row:
            continue
        try:
            metadata, raw_path = row.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ", 2)
            name = raw_path.decode("utf-8", "strict")
        except (ValueError, UnicodeDecodeError):
            bundle._refuse("projection-tree-entry")
        if name in lockfiles:
            if mode != b"100644" or kind != b"blob":
                bundle._refuse("projection-lockfile-type")
            blob_ids[name] = object_id.decode("ascii")
    if set(blob_ids) != set(lockfiles):
        bundle._refuse("projection-lockfile-missing")
    if profile == "desktop":
        tree_paths = {}
        for row in tree.stdout.split(b"\x00"):
            if not row:
                continue
            try:
                metadata, raw_path = row.split(b"\t", 1)
                mode, kind, _object_id = metadata.split(b" ", 2)
                tree_paths[raw_path.decode("utf-8", "strict")] = (mode, kind)
            except (ValueError, UnicodeDecodeError):
                bundle._refuse("projection-tree-entry")
        if any(tree_paths.get(name) != (b"100644", b"blob")
               for name in ("Cargo.toml", "src-tauri/Cargo.toml")):
            bundle._refuse("projection-desktop-manifest-missing")
    lock_payloads = [bundle._git_blob(repository, blob_ids[name]) for name in lockfiles]
    lock_bytes = lock_payloads[0]
    if profile == "core-node":
        package, lock, npm = fetch.project_npm_lock(lock_bytes)
        result = {
            "schema": 1, "profile": profile, "tools": tools,
            "npm": npm, "cargo": [], "playwright": request["playwright"],
            "npm_package": package, "npm_lock": lock, "cargo_workspaces": [],
        }
    elif profile in ("core-rust", "local-sync-rust"):
        manifest, lock, cargo = fetch.project_cargo_lock(lock_bytes)
        workspaces = []
        if profile == "core-rust":
            for path, payload in zip(lockfiles[1:], lock_payloads[1:]):
                workspace_manifest, workspace_lock, _ = fetch.project_cargo_lock(payload)
                workspaces.append({"path": path, "manifest": workspace_manifest, "lock": workspace_lock})
        result = {
            "schema": 1, "profile": profile, "tools": tools,
            "npm": [], "cargo": cargo, "playwright": [],
            "cargo_manifest": manifest, "cargo_lock": lock,
            "cargo_workspaces": workspaces,
        }
    else:
        npm_package, npm_lock, npm = fetch.project_npm_lock(lock_payloads[0])
        cargo_manifest, cargo_lock, cargo = fetch.project_cargo_lock(lock_payloads[1])
        result = {
            "schema": 1, "profile": profile, "tools": tools,
            "npm": npm, "cargo": cargo, "playwright": [],
            "npm_package": npm_package, "npm_lock": npm_lock,
            "cargo_manifest": cargo_manifest, "cargo_lock": cargo_lock,
            "cargo_workspaces": [],
        }
    serialized = bundle.canonical_json(result)
    fetch.validate_projection(serialized, profile)
    return serialized


def main(argv=None):
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--request", help="owner-only coordinator request file")
    source.add_argument("--source-repository", help="owner-only Git source repository")
    parser.add_argument("--baseline-repository")
    parser.add_argument("--control-sha")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.source_repository:
            output = build_source_bound_rust_projection(
                args.source_repository, args.control_sha, baseline_repository=args.baseline_repository)
        else:
            if args.control_sha or args.baseline_repository:
                bundle._refuse("projection-request-shape")
            request = bundle.strict_json(Path(args.request).read_bytes(), 1024 * 1024)
            output = build_projection(request)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(output)
            destination.flush()
            os.fsync(destination.fileno())
        print("projection_created=true bytes=%d sha256=%s" % (len(output), hashlib.sha256(output).hexdigest()))
        return 0
    except (bundle.Refusal, fetch.Refusal) as error:
        print("devlane_projection_refusal=" + str(error))
        return 2
    except Exception:
        print("devlane_projection_refusal=projection-failed")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
