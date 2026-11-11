"""Linux-only public registry and offline Cargo compatibility proof."""

import argparse
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile

import bundle
import constraint_resolver
import deadline
import project


def run(argv, root, stage, deadline_file, environment):
    log = root / (stage + ".log")
    timeout = deadline.remaining(deadline_file)
    with log.open("xb") as output:
        def limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 256 * 1024 * 1024))
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                 env=environment, close_fds=True, start_new_session=True,
                                 preexec_fn=limits)
        try:
            result = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=min(5, deadline.cleanup_remaining(deadline_file)))
            raise bundle.Refusal("rust-preparation-smoke-timeout")
    if result != 0 or log.stat().st_size > 4 * 1024 * 1024:
        raise bundle.Refusal("rust-preparation-smoke-" + stage)


def smoke(args, root):
    envelope = constraint_resolver.build_constraint_envelope(
        source_commit=bundle.CORE_RUST_SOURCE_REVISION, control_sha=args.control_sha,
        constraints=[{"id": "d000001", "package": "serde", "version_req": "^1.0"}])
    baseline = constraint_resolver.build_constraint_envelope(
        source_commit=bundle.CORE_RUST_BASELINE_REVISION, control_sha=args.control_sha,
        constraints=[], resolver_version="3", allow_empty=True)
    projection = project.build_projection({
        "schema": 2, "profile": "core-rust", "control_sha": args.control_sha,
        "tools": {"cargo": "1.99.1", "rustc": "1.99.1"},
        "source_sets": bundle._expected_core_rust_source_sets(),
        "manifest_constraints": {"candidate": envelope, "baseline_runtime": baseline}})
    projection_path = root / "projection.json"
    projection_path.write_bytes(projection)
    prepared = root / "prepared"
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
    run([sys.executable, "-B", str(Path(__file__).with_name("prepare.py")),
         "--projection", str(projection_path), "--output", str(prepared), "--profile", "core-rust",
         "--control-sha", args.control_sha, "--deadline-file", args.deadline_file,
         "--owner-uid", str(args.owner_uid), "--owner-gid", str(args.owner_gid),
         "--cargo-path", args.cargo_path, "--rustc-path", args.rustc_path],
        root, "prepare", args.deadline_file, env)
    crate = root / "offline-project"
    crate.mkdir(mode=0o755)
    (crate / "src").mkdir(mode=0o755)
    (crate / "src/lib.rs").write_bytes(b"pub fn public_fixture() {}\n")
    (crate / "Cargo.toml").write_bytes(
        b'[package]\nname="public-registry-proof"\nversion="0.0.0"\nedition="2024"\n'
        b'[dependencies]\nserde="^1.0"\n')
    home = root / "cargo-home"
    home.mkdir(mode=0o755)
    for path in (crate, crate / "src", crate / "src/lib.rs", crate / "Cargo.toml", home):
        os.chown(path, 65534, 65534)
    tools = root / "toolchain"
    tools.mkdir(mode=0o755)
    original_tools = Path(args.cargo_path).resolve(strict=True).parent.parent
    if Path(args.rustc_path).resolve(strict=True).parent.parent != original_tools:
        raise bundle.Refusal("rust-preparation-smoke-tool-layout")
    run(["/usr/bin/mount", "--bind", str(original_tools), str(tools)],
        root, "tool-bind", args.deadline_file, env)
    run(["/usr/bin/mount", "-o", "remount,bind,ro,nosuid,nodev", str(tools)],
        root, "tool-seal", args.deadline_file, env)
    command = ["/usr/bin/unshare", "--net", "--fork", "/usr/bin/setpriv",
               "--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs",
               "--bounding-set=-all", "--", str(tools / "bin/cargo"), "generate-lockfile", "--offline",
               "--manifest-path", str(crate / "Cargo.toml"),
               "--config", 'source.crates-io.replace-with="prepared-registry"',
               "--config", 'source.prepared-registry.local-registry=' + json.dumps(
                   str(prepared / "cargo-local-registry")),
               "--config", "net.offline=true", "--config", "net.retry=0"]
    run(command, root, "offline", args.deadline_file,
        dict(env, CARGO_HOME=str(home), HOME=str(home), RUSTC=str(tools / "bin/rustc"),
             CARGO_NET_OFFLINE="true"))
    record = bundle.strict_json((prepared / "registry-preparation.json").read_bytes(), 4 * 1024 * 1024)
    available = {tuple(row[key] for key in ("name", "version", "checksum")) for row in record["packages"]}
    rows = constraint_resolver.lock_package_rows((crate / "Cargo.lock").read_bytes())
    if not rows or any(tuple(row[key] for key in ("name", "version", "checksum")) not in available for row in rows):
        raise bundle.Refusal("rust-preparation-smoke-lock-binding")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo-path", required=True)
    parser.add_argument("--rustc-path", required=True)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--deadline-file", required=True)
    parser.add_argument("--owner-uid", type=int, required=True)
    parser.add_argument("--owner-gid", type=int, required=True)
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise bundle.Refusal("linux-root-required")
    deadline.remaining(args.deadline_file)
    root = Path(tempfile.mkdtemp(prefix="public-registry-proof-", dir="/tmp"))
    os.chmod(root, 0o755)
    try:
        smoke(args, root)
    finally:
        if os.path.ismount(root / "toolchain"):
            result = subprocess.run(["/usr/bin/umount", str(root / "toolchain")], check=False,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=min(10, deadline.cleanup_remaining(args.deadline_file)))
            if result.returncode != 0:
                raise bundle.Refusal("rust-preparation-smoke-cleanup")
        shutil.rmtree(root)
    print("rust_preparation_v2_public_smoke=pass")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except bundle.Refusal as error:
        print("rust_preparation_v2_public_smoke=refused code=" + str(error))
        raise SystemExit(2)
    except Exception:
        print("rust_preparation_v2_public_smoke=refused code=unexpected")
        raise SystemExit(2)
