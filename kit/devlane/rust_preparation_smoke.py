"""Linux-only public registry and offline Cargo compatibility proof."""

import argparse
import json
import os
from pathlib import Path
import resource
import re
import shutil
import signal
import subprocess
import sys
import tempfile

import bundle
import constraint_resolver
import deadline
import project
import rust_preparation_v2


SMOKE_PHASES = frozenset((
    "smoke-argument-parse", "smoke-linux-check", "smoke-deadline-check",
    "smoke-temp-create", "smoke-projection-envelope", "smoke-projection-write",
    "smoke-prepare-run", "smoke-fixture-create", "smoke-tool-root",
    "smoke-tool-bind", "smoke-tool-seal", "smoke-offline-run",
    "smoke-registry-record", "smoke-lock-check", "smoke-cleanup-unmount",
    "smoke-cleanup-remove", "smoke-protocol",
))
SMOKE_PHASE = "smoke-argument-parse"
SMOKE_FAILURE_PHASE = None
SMOKE_CLEANUP_UNCONFIRMED = False


def set_smoke_phase(phase):
    global SMOKE_PHASE
    SMOKE_PHASE = phase if phase in SMOKE_PHASES else "smoke-protocol"


def failure_diagnostic(error):
    if isinstance(error, bundle.Refusal):
        code = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else "unclassified"
        code = code if re.fullmatch(r"[a-z][a-z0-9-]{0,79}", code) else "unclassified"
    elif isinstance(error, OSError):
        number = error.errno if type(error.errno) is int and error.errno >= 0 else 0
        code = "unexpected-filesystem-" + (SMOKE_FAILURE_PHASE or SMOKE_PHASE) + "-errno-" + str(number)
    else:
        code = "unexpected-" + rust_preparation_v2.failure_code(error)
    if SMOKE_CLEANUP_UNCONFIRMED:
        code += "-cleanup-unconfirmed"
    return code


def run(argv, root, stage, deadline_file, environment):
    run_phases = {
        "prepare": "smoke-prepare-run", "tool-bind": "smoke-tool-bind",
        "tool-seal": "smoke-tool-seal", "offline": "smoke-offline-run",
    }
    set_smoke_phase(run_phases.get(stage, "smoke-protocol"))
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
        with log.open("rb") as source:
            code = rust_preparation_v2.diagnostic_code(source.read(1024 * 1024 + 1))
        raise bundle.Refusal("rust-preparation-smoke-" + stage + ("-" + code if code else ""))


def smoke(args, root):
    set_smoke_phase("smoke-projection-envelope")
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
    set_smoke_phase("smoke-projection-write")
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
    set_smoke_phase("smoke-fixture-create")
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
    set_smoke_phase("smoke-tool-root")
    tools.mkdir(mode=0o755)
    original_tools = Path(args.cargo_path).resolve(strict=True).parent.parent
    if Path(args.rustc_path).resolve(strict=True).parent.parent != original_tools:
        raise bundle.Refusal("rust-preparation-smoke-tool-layout")
    set_smoke_phase("smoke-tool-bind")
    run(["/usr/bin/mount", "--bind", str(original_tools), str(tools)],
        root, "tool-bind", args.deadline_file, env)
    set_smoke_phase("smoke-tool-seal")
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
    set_smoke_phase("smoke-offline-run")
    run(command, root, "offline", args.deadline_file,
        dict(env, CARGO_HOME=str(home), HOME=str(home), RUSTC=str(tools / "bin/rustc"),
             LD_LIBRARY_PATH=str(tools / "lib"),
             CARGO_NET_OFFLINE="true"))
    set_smoke_phase("smoke-registry-record")
    record = bundle.strict_json((prepared / "registry-preparation.json").read_bytes(), 4 * 1024 * 1024)
    available = {tuple(row[key] for key in ("name", "version", "checksum")) for row in record["packages"]}
    set_smoke_phase("smoke-lock-check")
    rows = constraint_resolver.lock_package_rows((crate / "Cargo.lock").read_bytes())
    if not rows or any(tuple(row[key] for key in ("name", "version", "checksum")) not in available for row in rows):
        raise bundle.Refusal("rust-preparation-smoke-lock-binding")


def main(argv=None):
    global SMOKE_CLEANUP_UNCONFIRMED, SMOKE_FAILURE_PHASE
    SMOKE_CLEANUP_UNCONFIRMED = False
    SMOKE_FAILURE_PHASE = None
    set_smoke_phase("smoke-argument-parse")
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo-path", required=True)
    parser.add_argument("--rustc-path", required=True)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--deadline-file", required=True)
    parser.add_argument("--owner-uid", type=int, required=True)
    parser.add_argument("--owner-gid", type=int, required=True)
    args = parser.parse_args(argv)
    set_smoke_phase("smoke-linux-check")
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise bundle.Refusal("linux-root-required")
    set_smoke_phase("smoke-deadline-check")
    deadline.remaining(args.deadline_file)
    root = None
    primary_error = None
    cleanup_error = None
    try:
        set_smoke_phase("smoke-temp-create")
        root = Path(tempfile.mkdtemp(prefix="public-registry-proof-", dir="/tmp"))
        os.chmod(root, 0o755)
        smoke(args, root)
    except BaseException as error:
        primary_error = error
        SMOKE_FAILURE_PHASE = SMOKE_PHASE
    finally:
        if root is not None:
            try:
                set_smoke_phase("smoke-cleanup-unmount")
                if os.path.ismount(root / "toolchain"):
                    result = subprocess.run(
                        ["/usr/bin/umount", str(root / "toolchain")], check=False,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=min(10, deadline.cleanup_remaining(args.deadline_file)))
                    if result.returncode != 0:
                        cleanup_error = bundle.Refusal("rust-preparation-smoke-cleanup")
            except BaseException as error:
                cleanup_error = error
            try:
                set_smoke_phase("smoke-cleanup-remove")
                shutil.rmtree(root)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None:
            SMOKE_CLEANUP_UNCONFIRMED = True
        if primary_error is None and cleanup_error is not None:
            primary_error = bundle.Refusal("rust-preparation-smoke-cleanup")
            SMOKE_FAILURE_PHASE = SMOKE_PHASE
    if primary_error is not None:
        raise primary_error
    print("rust_preparation_v2_public_smoke=pass")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except bundle.Refusal as error:
        print("rust_preparation_v2_public_smoke=refused code=" + failure_diagnostic(error))
        raise SystemExit(2)
    except Exception as error:
        print("rust_preparation_v2_public_smoke=refused code=" + failure_diagnostic(error))
        raise SystemExit(2)
