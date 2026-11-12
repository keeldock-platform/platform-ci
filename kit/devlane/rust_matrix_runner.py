"""Fixed offline PR1 Rust matrix; never invokes a candidate-provided command.

The supervisor launches this file from the read-only /control/devlane bind mount
with -I -S. Isolated Python omits the script directory, so restore only this
runner's trusted control directory before importing its siblings. The caller
uses the literal /control/devlane path; candidate source never selects imports.
"""

import argparse
import json
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

if sys.flags.isolated:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import bundle
import diagnostic_contract
import rust_test_runner
import semver_stage


EXPECTED_MATRIX = {
    "schema": 1,
    "toolchain": "1.99.1",
    "tool_versions": {"cargo_deny": "0.20.2", "cargo_audit": "0.22.2", "cargo_vet": "0.10.3"},
    "workspaces": [
        {"id": "root", "manifest": "/workspace/source/Cargo.toml", "lock": "/workspace/source/Cargo.lock", "mode": "workspace"},
        {"id": "runtime", "manifest": "/workspace/source/runtime/Cargo.toml", "lock": "/workspace/source/runtime/Cargo.lock", "mode": "workspace"},
        {"id": "fuzz", "manifest": "/workspace/source/fuzz/Cargo.toml", "lock": "/workspace/source/fuzz/Cargo.lock", "mode": "package"},
    ],
    "listener": {"id": "listener", "manifest": "/workspace/source/runtime/crates/services/listener/Cargo.toml",
                 "lock": "/workspace/source/runtime/Cargo.lock", "mode": "package"},
    "feature_sets": ["default", "all"],
    "test_requirements": {"zero_ignored": True, "run_every_discovered_test": True},
    "coverage_ids": [
        "fmt-root", "fmt-runtime", "fmt-fuzz", "deny-root", "deny-runtime", "deny-fuzz",
        "audit-root", "audit-runtime", "audit-fuzz", "vet-root", "vet-runtime", "vet-fuzz",
        "root-default", "root-all-features", "runtime-default", "runtime-all-features",
        "fuzz-default", "fuzz-all-features", "listener-default", "listener-all-features",
        "fuzz-replay-default", "fuzz-replay-all-features", "semver-runtime",
    ],
}
MAX_CAPTURE = 256 * 1024 * 1024
TOOLS_ROOT = "/prepared/devlane-tools"
SOURCE_ROOT = "/workspace/source"
TARGET = "/scratch/target"
RAW = "/scratch/raw"
REPORTS = "/scratch/reports"
ADVISORY_DB_DIRECTORY = "advisory-db-3157b0e258782691"


class MatrixRefusal(ValueError):
    def __init__(self, code):
        self.code = (code if type(code) is str and code in diagnostic_contract.RUST_MATRIX_REFUSAL_CODES
                     else "matrix-runner-failed")
        super().__init__(self.code)


def _refusal_code(error):
    if type(error) is MatrixRefusal:
        code = error.code
    elif type(error) in (bundle.Refusal, rust_test_runner.Refusal):
        code = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else ""
    else:
        code = ""
    return code if code in diagnostic_contract.RUST_MATRIX_REFUSAL_CODES else "matrix-runner-failed"


TERM_GRACE_SECONDS = 2
KILL_REAP_SECONDS = 3


def _kill(process):
    started = time.monotonic()
    sent_term = False
    try:
        os.killpg(process.pid, signal.SIGTERM)
        sent_term = True
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=TERM_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    finally:
        if sent_term:
            left = TERM_GRACE_SECONDS - (time.monotonic() - started)
            if left > 0:
                time.sleep(left)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            process.wait(timeout=KILL_REAP_SECONDS)


def _limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_CAPTURE, MAX_CAPTURE))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
    os.umask(0o077)


def _remaining(deadline):
    return rust_test_runner._remaining(deadline)


def _run(label, argv, deadline, *, timeout=1800, cwd=SOURCE_ROOT, json_stdout=False):
    remaining = _remaining(deadline)
    stdout_path = Path(RAW) / (label + ".stdout")
    stderr_path = Path(RAW) / (label + ".stderr")
    stdout_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    stdout_fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    stderr_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    env = {
        "PATH": "/tools/rust/bin:/usr/bin:/bin",
        "CARGO": "/tools/rust/bin/cargo",
        "RUSTC": "/tools/rust/bin/rustc",
        "LD_LIBRARY_PATH": "/tools/rust/lib",
        "CC": "/usr/bin/cc",
        "CARGO_TARGET_" + "X" + "86_64_UNKNOWN_LINUX_GNU_LINKER": "/usr/bin/cc",
        "HOME": "/devlane-home",
        "TMPDIR": "/scratch/tmp",
        "CARGO_HOME": "/scratch/cargo-home",
        "CARGO_TARGET_DIR": TARGET,
        "CARGO_NET_OFFLINE": "true",
        "CARGO_BUILD_JOBS": "2",
        "RUSTUP_HOME": "/tools/rust",
        "RUST_TEST_THREADS": "1",
        "LC_ALL": "C",
        "LANG": "C",
        "CI": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        with os.fdopen(stdout_fd, "wb") as stdout, os.fdopen(stderr_fd, "wb") as stderr:
            try:
                process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr, close_fds=True,
                                           start_new_session=True, preexec_fn=_limits)
            except OSError:
                return 127, stdout_path
            try:
                code = process.wait(timeout=min(timeout, remaining))
            except subprocess.TimeoutExpired:
                _kill(process)
                raise MatrixRefusal("total-deadline-exhausted" if _remaining_safe(deadline) <= 0 else "matrix-phase-timeout") from None
            stdout.flush()
            stderr.flush()
            if os.fstat(stdout.fileno()).st_size > MAX_CAPTURE or os.fstat(stderr.fileno()).st_size > MAX_CAPTURE:
                raise MatrixRefusal("matrix-capture-size")
        if json_stdout:
            os.chmod(stdout_path, 0o400)
        return code, stdout_path
    except Exception:
        for descriptor in (stdout_fd, stderr_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _remaining_safe(deadline):
    try:
        return _remaining(deadline)
    except rust_test_runner.Refusal:
        return 0


def _coverage(suite, passed, failed):
    return {"kind": "coverage", "stage": _stage_for(suite), "suite": suite,
            "total": passed + failed, "passed": passed, "failed": failed, "ignored": 0}


def _stage_for(suite):
    if suite.startswith("fmt-"):
        return "format"
    if suite.startswith("deny-"):
        return "deny"
    if suite.startswith("audit-"):
        return "audit"
    if suite.startswith("vet-"):
        return "vet"
    if suite == semver_stage.SUITE:
        return semver_stage.STAGE
    return "unit"


def _emit_failure(records, stage):
    records.append({"kind": "control", "stage": stage, "status": "fail", "code": "DEVLANE_FAILURE"})


def _copy_advisory_database(deadline, cargo_home="/scratch/cargo-home"):
    _remaining(deadline)
    source = Path(TOOLS_ROOT) / "advisory-db"
    cargo_home = Path(cargo_home)
    if source.is_symlink() or not source.is_dir():
        raise MatrixRefusal("advisory-database-missing")
    database_root = cargo_home / "advisory-dbs"
    destination = database_root / ADVISORY_DB_DIRECTORY
    if database_root.exists() or database_root.is_symlink():
        raise MatrixRefusal("advisory-database-copy-exists")
    if destination.exists() or destination.is_symlink():
        raise MatrixRefusal("advisory-database-copy-exists")
    database_root.mkdir(mode=0o700)
    shutil.copytree(source, destination, symlinks=False)
    _remaining(deadline)
    for root, directories, files in os.walk(destination, followlinks=False):
        for name in directories + files:
            if (Path(root) / name).is_symlink():
                raise MatrixRefusal("advisory-database-link")


def _simple_check(records, suite, argv, deadline, *, timeout=1800):
    try:
        code, _ = _run(suite, argv, deadline, timeout=timeout)
        records.append(_coverage(suite, 1 if code == 0 else 0, 0 if code == 0 else 1))
        return code == 0
    except (MatrixRefusal, rust_test_runner.Refusal):
        _emit_failure(records, _stage_for(suite))
        return False


def _rust_test_arm(records, scope, manifest, workspace_mode, matrix_mode, config_path, deadline):
    if workspace_mode not in ("workspace", "package"):
        raise MatrixRefusal("matrix-workspace-mode")
    suffix = "all-features" if matrix_mode == "all" else "default"
    suite = scope + "-" + suffix
    label = "compile-" + suite
    argv = ["/tools/rust/bin/cargo", "test", "--manifest-path", manifest,
            "--all-targets", "--locked", "--offline", "--no-run", "--message-format=json"]
    if workspace_mode == "workspace":
        argv.append("--workspace")
    if matrix_mode == "all":
        argv.append("--all-features")
    try:
        code, log_path = _run(label, argv, deadline, timeout=2400, json_stdout=True)
        if code != 0:
            _emit_failure(records, "unit")
            return False
        output = Path(REPORTS) / ("tests-" + suite + ".jsonl")
        if output.exists() or output.is_symlink():
            raise MatrixRefusal("matrix-report-exists")
        result = rust_test_runner.collect(
            str(log_path), config_path, str(output), scope=scope, suite=suite, deadline=deadline)
        if result == 2:
            _emit_failure(records, "unit")
            return False
        payload = output.read_bytes()
        if not payload or not payload.endswith(b"\n") or len(payload) > 16 * 1024:
            _emit_failure(records, "unit")
            return False
        parsed = [bundle.strict_json(line, 512) for line in payload.splitlines()]
        if any(type(record) is not dict for record in parsed):
            _emit_failure(records, "unit")
            return False
        coverage = [record for record in parsed if record.get("kind") == "coverage"]
        if len(coverage) != 1 or coverage[0].get("suite") != suite:
            _emit_failure(records, "unit")
            return False
        records.extend(parsed)
        return result == 0
    except (MatrixRefusal, rust_test_runner.Refusal, OSError, bundle.Refusal):
        _emit_failure(records, "unit")
        return False


def _fuzz_replay(records, feature_set, deadline):
    suite = "fuzz-replay-" + ("all-features" if feature_set == "all" else "default")
    argv = ["/tools/rust/bin/cargo", "run", "--manifest-path", SOURCE_ROOT + "/fuzz/Cargo.toml",
            "--locked", "--offline"]
    if feature_set == "all":
        argv.append("--all-features")
    try:
        code, stdout_path = _run("replay-" + suite, argv, deadline, timeout=2400)
        payload = stdout_path.read_bytes()
        if code != 0 or len(payload) > 4096:
            raise MatrixRefusal("fuzz-replay-failed")
        lines = payload.decode("ascii", "strict").splitlines()
        if len(lines) != 1 or re.fullmatch(r"Replayed ([1-9][0-9]{0,6}) parser corpus seeds\.", lines[0]) is None:
            raise MatrixRefusal("fuzz-replay-report-invalid")
        count = int(lines[0].split()[1])
        records.append(_coverage(suite, count, 0))
        return True
    except (MatrixRefusal, OSError, UnicodeError, rust_test_runner.Refusal):
        _emit_failure(records, "unit")
        return False


def _semver_check(records, deadline):
    try:
        rows = semver_stage.request_stage(deadline)
        records.extend(rows)
        coverage = next(row for row in rows if row.get("kind") == "coverage")
        return coverage["passed"] == 1
    except Exception:
        records.extend(semver_stage.records_for_exit(101))
        return False


def run(matrix, config_path, report_path, deadline):
    if matrix != EXPECTED_MATRIX:
        raise MatrixRefusal("matrix-profile-mismatch")
    if type(deadline) not in (float, int):
        raise MatrixRefusal("total-deadline-invalid")
    records = []
    expected_ids = set(matrix["coverage_ids"])
    _copy_advisory_database(deadline)
    workspaces = matrix["workspaces"]
    for workspace in workspaces:
        suite = "fmt-" + workspace["id"]
        argv = ["/tools/rust/bin/cargo", "fmt", "--manifest-path", workspace["manifest"]]
        if workspace["mode"] == "workspace":
            argv.append("--all")
        argv.extend(["--", "--check"])
        _simple_check(records, suite, argv, deadline, timeout=900)
    deny = Path(TOOLS_ROOT) / "cargo-deny"
    audit = Path(TOOLS_ROOT) / "cargo-audit"
    vet = Path(TOOLS_ROOT) / "cargo-vet"
    for workspace in workspaces:
        identifier = workspace["id"]
        deny_args = [str(deny), "--manifest-path", workspace["manifest"], "--config",
                     SOURCE_ROOT + "/deny.toml", "--workspace", "--all-features", "--offline", "--locked", "check"]
        _simple_check(records, "deny-" + identifier, deny_args, deadline, timeout=1800)
    for workspace in workspaces:
        identifier = workspace["id"]
        audit_args = [str(audit), "audit", "--deny", "unsound", "--no-fetch", "--no-yanked", "--db",
                      "/scratch/cargo-home/advisory-dbs/" + ADVISORY_DB_DIRECTORY,
                      "--file", workspace["lock"]]
        _simple_check(records, "audit-" + identifier, audit_args, deadline, timeout=900)
    for workspace in workspaces:
        identifier = workspace["id"]
        store = SOURCE_ROOT + ("/runtime/supply-chain" if identifier == "runtime" else "/supply-chain")
        vet_args = [str(vet), "vet", "check", "--manifest-path", workspace["manifest"],
                    "--store-path", store, "--locked", "--frozen"]
        _simple_check(records, "vet-" + identifier, vet_args, deadline, timeout=900)
    arms = [(item["id"], item["manifest"], item["mode"]) for item in workspaces]
    arms.append((matrix["listener"]["id"], matrix["listener"]["manifest"], matrix["listener"]["mode"]))
    for scope, manifest, workspace_mode in arms:
        for feature_set in matrix["feature_sets"]:
            _rust_test_arm(records, scope, manifest, workspace_mode,
                           "all" if feature_set == "all" else "default", config_path, deadline)
    for feature_set in matrix["feature_sets"]:
        _fuzz_replay(records, "all" if feature_set == "all" else "default", deadline)
    _semver_check(records, deadline)
    coverage = [record for record in records if record.get("kind") == "coverage"]
    seen = [record.get("suite") for record in coverage]
    coverage_complete = (
        len(seen) == len(set(seen)) and set(seen) == expected_ids
        and all(
            type(row.get("total")) is int and row["total"] > 0
            and type(row.get("passed")) is int and type(row.get("failed")) is int
            and type(row.get("ignored")) is int
            and row["passed"] + row["failed"] == row["total"] and row["ignored"] == 0
            for row in coverage
        )
    )
    if not coverage_complete:
        _emit_failure(records, "unit")
    payload = b"".join(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
                     for record in records)
    if len(records) > 100 or len(payload) > 16 * 1024:
        payload = b'{"kind":"control","stage":"unit","status":"fail","code":"DEVLANE_FAILURE"}\n'
    descriptor = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    return 0 if coverage_complete and not any(record.get("failed", 0) > 0 or record.get("status") == "fail" for record in records) else 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("profile_file")
    parser.add_argument("config_path")
    parser.add_argument("report_path")
    parser.add_argument("--deadline", type=float, required=True)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        profile_value = bundle.strict_json(Path(args.profile_file).read_bytes(), 1024 * 1024)
        profile = profile_value["profiles"]["core-rust"]
        result = run(profile["rust_matrix"], args.config_path, args.report_path, args.deadline)
        print("rust_matrix=complete")
        return result
    except Exception as error:
        print("rust_matrix=refused code=" + _refusal_code(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
