"""Coordinator-only data projection builder; it never imports project modules."""

import argparse
import hashlib
import json
import os
from pathlib import Path

import bundle
import fetch


def build_projection(request):
    if type(request) is not dict:
        bundle._refuse("projection-request-shape")
    profile = request.get("profile")
    if profile not in ("core-node", "core-rust"):
        bundle._refuse("projection-profile")
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
    expected_tools = {"node", "npm"} if profile == "core-node" else {"cargo", "rustc"}
    if set(tools) != expected_tools:
        bundle._refuse("projection-tool-versions")
    lockfiles = [request["lockfile"]] if profile == "core-node" else request["lockfiles"]
    if (type(lockfiles) is not list or not lockfiles or len(lockfiles) > 65
            or any(type(item) is not str for item in lockfiles)):
        bundle._refuse("projection-lockfiles")
    lockfiles = [bundle._safe_member_name(item) for item in lockfiles]
    if len(lockfiles) != len(set(lockfiles)):
        bundle._refuse("projection-lockfile-duplicate")
    if profile == "core-rust" and lockfiles[0] != "Cargo.lock":
        bundle._refuse("projection-root-lockfile")
    if profile == "core-rust" and lockfiles[1:] != sorted(lockfiles[1:]):
        bundle._refuse("projection-lockfile-order")
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
    lock_payloads = [bundle._git_blob(repository, blob_ids[name]) for name in lockfiles]
    lock_bytes = lock_payloads[0]
    if profile == "core-node":
        package, lock, npm = fetch.project_npm_lock(lock_bytes)
        result = {
            "schema": 1, "profile": profile, "tools": tools,
            "npm": npm, "cargo": [], "playwright": request["playwright"],
            "npm_package": package, "npm_lock": lock, "cargo_workspaces": [],
        }
    else:
        manifest, lock, cargo = fetch.project_cargo_lock(lock_bytes)
        workspaces = []
        for payload in lock_payloads[1:]:
            workspace_manifest, workspace_lock, _ = fetch.project_cargo_lock(payload)
            workspaces.append({"manifest": workspace_manifest, "lock": workspace_lock})
        result = {
            "schema": 1, "profile": profile, "tools": tools,
            "npm": [], "cargo": cargo, "playwright": [],
            "cargo_manifest": manifest, "cargo_lock": lock,
            "cargo_workspaces": workspaces,
        }
    serialized = bundle.canonical_json(result)
    fetch.validate_projection(serialized, profile)
    return serialized


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, help="owner-only coordinator request file")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
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
