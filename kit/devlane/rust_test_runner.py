"""Run every discovered test from one fixed Cargo matrix arm and report counts only."""

import json
import os
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath


MAX_LOG = 256 * 1024 * 1024
MAX_LIST = 4 * 1024 * 1024
MAX_TESTS = 100_000
TARGET_PREFIX = "/scratch/target/"
SOURCE_PREFIX = "/workspace/source/"
RESULT_LINE = re.compile(
    r"test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; "
    r"([0-9]+) measured; ([0-9]+) filtered out; finished in [0-9.]+s\Z"
)
TEST_ID = re.compile(r"case_[0-9]{4,6}\Z")
SCOPE_ID = re.compile(r"(?:root|runtime|fuzz|listener|local-sync)\Z")
FIXED_FAILURE = b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit","status":"fail"}\n'


class Refusal(ValueError):
    pass


def _test_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LIST + 1, MAX_LIST + 1))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_NPROC, (128, 128))
    os.umask(0o077)


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise Refusal("duplicate-json-key")
        result[key] = value
    return result


def _read(path, maximum):
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise Refusal("input-file-invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise Refusal("input-file-invalid")
        output = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > maximum:
                raise Refusal("input-file-size")
        if len(output) != metadata.st_size:
            raise Refusal("input-file-changed")
        return bytes(output)
    finally:
        os.close(descriptor)


def _strict_json(payload, maximum):
    if type(payload) is not bytes or len(payload) > maximum:
        raise Refusal("json-size")
    try:
        return json.loads(payload.decode("utf-8", "strict"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refusal("json-invalid") from None


def _manifest_relative(value):
    if type(value) is not str or not value.startswith(SOURCE_PREFIX):
        raise Refusal("cargo-manifest-path-invalid")
    relative = value[len(SOURCE_PREFIX):]
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts or path.name != "Cargo.toml":
        raise Refusal("cargo-manifest-path-invalid")
    return path.as_posix()


def _cargo_test_executables(log_path):
    payload = _read(log_path, MAX_LOG)
    executables = {}
    build_finished = []
    for line in payload.splitlines():
        if not line or len(line) > 1024 * 1024:
            raise Refusal("cargo-message-invalid")
        message = _strict_json(line, 1024 * 1024)
        if type(message) is not dict or type(message.get("reason")) is not str:
            raise Refusal("cargo-message-invalid")
        reason = message["reason"]
        if reason == "compiler-artifact":
            profile = message.get("profile")
            if type(profile) is not dict or type(profile.get("test")) is not bool:
                raise Refusal("cargo-artifact-invalid")
            if profile["test"] is True:
                path = message.get("executable")
                if type(path) is not str or not path.startswith(TARGET_PREFIX):
                    raise Refusal("cargo-test-path-invalid")
                target_path = Path(path)
                try:
                    metadata = target_path.lstat()
                except OSError:
                    raise Refusal("cargo-test-unavailable") from None
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0 or target_path.is_symlink():
                    raise Refusal("cargo-test-unavailable")
                manifest = _manifest_relative(message.get("manifest_path"))
                existing = executables.get(str(target_path))
                if existing is not None and existing != manifest:
                    raise Refusal("cargo-artifact-identity-conflict")
                executables[str(target_path)] = manifest
        elif reason == "build-finished":
            if type(message.get("success")) is not bool:
                raise Refusal("cargo-finish-invalid")
            build_finished.append(message["success"])
        elif reason not in ("compiler-message", "build-script-executed", "future-incompat-report"):
            raise Refusal("cargo-reason-invalid")
    if build_finished != [True] or len(executables) > 2048:
        raise Refusal("cargo-build-incomplete")
    return sorted(executables.items())


def _test_map(config_path, scope):
    if not SCOPE_ID.fullmatch(scope):
        raise Refusal("rust-test-scope-invalid")
    config = _strict_json(_read(config_path, 4 * 1024 * 1024), 4 * 1024 * 1024)
    rows = config.get("tests") if type(config) is dict else None
    if type(rows) is not list or len(rows) > MAX_TESTS:
        raise Refusal("rust-test-map-invalid")
    mapping = {}
    ids = set()
    prefix = scope + "::"
    for row in rows:
        if (type(row) is not list or len(row) != 2 or type(row[0]) is not str or not row[0]
                or len(row[0]) > 2048 or any(ord(char) < 0x20 for char in row[0])
                or type(row[1]) is not str or not TEST_ID.fullmatch(row[1]) or row[1] in ids):
            raise Refusal("rust-test-map-invalid")
        if row[0].startswith(prefix):
            name = row[0][len(prefix):]
            if name.count("::") < 2 or name in mapping:
                raise Refusal("rust-test-map-invalid")
            mapping[name] = row[1]
            ids.add(row[1])
    return mapping


def _remaining(deadline):
    if type(deadline) not in (float, int):
        raise Refusal("total-deadline-invalid")
    value = deadline - time.monotonic()
    if value <= 0:
        raise Refusal("total-deadline-exhausted")
    return value


def _run_bounded(argv, *, list_output, deadline, timeout=120):
    limit = min(float(timeout), _remaining(deadline))
    temporary_directory = os.environ.get("TMPDIR") or tempfile.gettempdir()
    output = tempfile.TemporaryFile(mode="w+b", dir=temporary_directory) if list_output else open(os.devnull, "wb")
    process = None
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/devlane-home",
                 "TMPDIR": "/scratch/tmp", "LC_ALL": "C", "LANG": "C", "RUST_TEST_THREADS": "1"},
            close_fds=True, start_new_session=True, preexec_fn=_test_limits,
        )
        try:
            code = process.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            _kill_process(process)
            if _remaining_safe(deadline) <= 0:
                raise Refusal("total-deadline-exhausted") from None
            raise Refusal("rust-test-timeout") from None
        if not list_output:
            return code, b""
        output.flush()
        size = os.fstat(output.fileno()).st_size
        if size > MAX_LIST:
            raise Refusal("rust-test-list-size")
        output.seek(0)
        payload = output.read(MAX_LIST + 1)
        if len(payload) != size or size > MAX_LIST:
            raise Refusal("rust-test-list-size")
        return code, payload
    finally:
        output.close()


def _remaining_safe(deadline):
    try:
        return _remaining(deadline)
    except Refusal:
        return 0


TERM_GRACE_SECONDS = 2
KILL_REAP_SECONDS = 3


def _kill_process(process):
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


def _listed_tests(executable, deadline):
    code, payload = _run_bounded([executable, "--list", "--format", "terse"], list_output=True, deadline=deadline, timeout=30)
    if code != 0:
        raise Refusal("rust-test-list-failed")
    try:
        lines = payload.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        raise Refusal("rust-test-list-invalid") from None
    names = []
    for line in lines:
        if line.endswith(": benchmark"):
            raise Refusal("rust-test-list-invalid")
        if line.endswith(": test"):
            name = line[:-6]
            if not name or len(name) > 2048 or name in names:
                raise Refusal("rust-test-list-invalid")
            names.append(name)
        elif line.strip():
            raise Refusal("rust-test-list-invalid")
    return names


def _ignored_tests(executable, deadline):
    code, payload = _run_bounded([executable, "--list", "--ignored", "--format", "terse"],
                                 list_output=True, deadline=deadline, timeout=30)
    if code != 0:
        raise Refusal("rust-ignored-list-failed")
    try:
        lines = payload.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        raise Refusal("rust-ignored-list-invalid") from None
    ignored = []
    for line in lines:
        if line.endswith(": test"):
            name = line[:-6]
            if not name or name in ignored:
                raise Refusal("rust-ignored-list-invalid")
            ignored.append(name)
        elif line.strip():
            raise Refusal("rust-ignored-list-invalid")
    return ignored


def _classify(code, payload):
    """Return a result only for one exact test with no ignored/skipped outcome."""
    try:
        lines = payload.decode("utf-8", "strict").split("\n")
    except UnicodeDecodeError:
        raise Refusal("rust-test-result-invalid") from None
    rows = [line for line in lines if line.startswith("test result: ")]
    match = RESULT_LINE.fullmatch(rows[0]) if len(rows) == 1 else None
    if match is None:
        raise Refusal("rust-test-result-invalid")
    status, passed, failed, ignored = match.group(1), int(match.group(2)), int(match.group(3)), int(match.group(4))
    if ignored != 0:
        raise Refusal("rust-test-ignored")
    if code == 0 and status == "ok" and failed == 0 and passed == 1:
        return True
    if code == 101 and status == "FAILED" and failed == 1 and passed == 0:
        return False
    raise Refusal("rust-test-result-invalid")


def _run_one(executable, name, deadline):
    timeout = min(120, _remaining(deadline))
    temporary_directory = os.environ.get("TMPDIR") or tempfile.gettempdir()
    output = tempfile.TemporaryFile(mode="w+b", dir=temporary_directory)
    process = None
    completed = False
    try:
        process = subprocess.Popen(
            [executable, "--exact", "--format", "terse", name],
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/devlane-home",
                 "TMPDIR": "/scratch/tmp", "LC_ALL": "C", "LANG": "C", "RUST_TEST_THREADS": "1"},
            close_fds=True, start_new_session=True, preexec_fn=_test_limits,
        )
        try:
            timeout = min(timeout, _remaining(deadline))
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_process(process)
            completed = True
            if _remaining_safe(deadline) <= 0:
                raise Refusal("total-deadline-exhausted") from None
            raise Refusal("rust-test-timeout") from None
        output.flush()
        size = os.fstat(output.fileno()).st_size
        if size > MAX_LIST:
            raise Refusal("rust-test-output-size")
        output.seek(0)
        payload = output.read(MAX_LIST + 1)
        if len(payload) != size:
            raise Refusal("rust-test-output-size")
        result = _classify(code, payload)
        completed = True
        return result
    except BaseException:
        if process is not None and not completed:
            try:
                _kill_process(process)
            finally:
                completed = True
        raise
    finally:
        output.close()


def _write(path, records):
    payload = b"".join(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
                     for record in records)
    if len(records) > MAX_TESTS + 1 or len(payload) > 16 * 1024:
        payload = FIXED_FAILURE
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


def collect(log_path, config_path, output_path, scope="root", suite="root-default", deadline=None):
    records = []
    passed = 0
    failed = 0
    ignored = 0
    try:
        end = time.monotonic() + 1200 if deadline is None else deadline
        expected = _test_map(config_path, scope)
        if not expected:
            raise Refusal("rust-test-coverage")
        executables = _cargo_test_executables(log_path)
        actual = []
        by_name = {}
        for executable, manifest in executables:
            for name in _listed_tests(executable, end):
                scoped_name = manifest + "::" + name
                if scoped_name in by_name:
                    raise Refusal("rust-test-duplicate")
                by_name[scoped_name] = (executable, name)
                actual.append(scoped_name)
            ignored_names = _ignored_tests(executable, end)
            ignored += len(ignored_names)
            if ignored_names:
                raise Refusal("rust-test-ignored")
        if not actual or set(actual) != set(expected) or len(actual) > MAX_TESTS:
            raise Refusal("rust-test-coverage")
        for scoped_name in sorted(expected):
            executable, name = by_name[scoped_name]
            if _run_one(executable, name, end):
                passed += 1
            else:
                failed += 1
                records.append({"kind": "test", "stage": "unit", "test": expected[scoped_name]})
        records.append({"kind": "coverage", "stage": "unit", "suite": suite,
                        "total": len(actual), "passed": passed, "failed": failed, "ignored": ignored})
        _write(output_path, records)
        return 1 if failed else 0
    except Exception:
        try:
            _write(output_path, [{"kind": "control", "stage": "unit", "status": "fail",
                                  "code": "DEVLANE_FAILURE"}])
        except Exception:
            pass
        return 2


def main(argv=None):
    parser = __import__("argparse").ArgumentParser()
    parser.add_argument("log_path")
    parser.add_argument("config_path")
    parser.add_argument("output_path")
    parser.add_argument("--scope", choices=("root", "runtime", "fuzz", "listener", "local-sync"), required=True)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--deadline", type=float, required=True)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    code = collect(args.log_path, args.config_path, args.output_path,
                   args.scope, args.suite, args.deadline)
    if code == 2:
        print("rust_test_adapter=refused", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
