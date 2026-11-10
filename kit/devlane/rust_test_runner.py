"""Run exact Rust tests and expose only mapped opaque failure identities."""

import json
import os
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


MAX_LOG = 256 * 1024 * 1024
MAX_LIST = 4 * 1024 * 1024
MAX_TESTS = 10_000
TARGET_PREFIX = "/scratch/target/"
RESULT_LINE = re.compile(
    r"test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; "
    r"([0-9]+) measured; ([0-9]+) filtered out; finished in [0-9.]+s\Z"
)
TEST_ID = re.compile(r"case_[0-9]{4,6}\Z")
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


def _cargo_test_executables(log_path):
    payload = _read(log_path, MAX_LOG)
    executables = set()
    build_finished = []
    for line in payload.splitlines():
        if not line or len(line) > 1024 * 1024:
            raise Refusal("cargo-message-invalid")
        message = _strict_json(line, 1024 * 1024)
        if type(message) is not dict or type(message.get("reason")) is not str:
            raise Refusal("cargo-message-invalid")
        reason = message["reason"]
        if reason == "compiler-artifact":
            target = message.get("target")
            if type(target) is not dict:
                raise Refusal("cargo-artifact-invalid")
            profile = message.get("profile")
            if type(profile) is not dict or type(profile.get("test")) is not bool:
                raise Refusal("cargo-artifact-invalid")
            """Only artifacts compiled with the test profile carry a test executable; a library built for dependants (target.test true, profile.test false) has executable null."""
            if profile["test"] is True:
                path = message.get("executable")
                if type(path) is not str or not path.startswith(TARGET_PREFIX):
                    raise Refusal("cargo-test-path-invalid")
                target_path = Path(path)
                try:
                    metadata = target_path.lstat()
                except OSError:
                    raise Refusal("cargo-test-unavailable") from None
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0
                        or target_path.is_symlink()):
                    raise Refusal("cargo-test-unavailable")
                executables.add(str(target_path))
        elif reason == "build-finished":
            if type(message.get("success")) is not bool:
                raise Refusal("cargo-finish-invalid")
            build_finished.append(message["success"])
        elif reason not in ("compiler-message", "build-script-executed", "future-incompat-report"):
            raise Refusal("cargo-reason-invalid")
    if build_finished != [True] or not executables or len(executables) > 512:
        raise Refusal("cargo-build-incomplete")
    return sorted(executables)


def _test_map(config_path):
    config = _strict_json(_read(config_path, 4 * 1024 * 1024), 4 * 1024 * 1024)
    rows = config.get("tests") if type(config) is dict else None
    if type(rows) is not list or not 1 <= len(rows) <= MAX_TESTS:
        raise Refusal("rust-test-map-invalid")
    mapping = {}
    ids = set()
    for row in rows:
        if (type(row) is not list or len(row) != 2 or type(row[0]) is not str
                or not row[0] or len(row[0]) > 2048 or any(ord(char) < 0x20 for char in row[0])
                or type(row[1]) is not str or not TEST_ID.fullmatch(row[1])
                or row[0] in mapping or row[1] in ids):
            raise Refusal("rust-test-map-invalid")
        mapping[row[0]] = row[1]
        ids.add(row[1])
    return mapping


def _run_bounded(argv, *, list_output):
    temporary_directory = os.environ.get("TMPDIR") or tempfile.gettempdir()
    output = tempfile.TemporaryFile(mode="w+b", dir=temporary_directory) if list_output else open(os.devnull, "wb")
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/devlane-home",
                 "TMPDIR": "/scratch/tmp", "LC_ALL": "C", "LANG": "C", "RUST_TEST_THREADS": "1"},
            close_fds=True, start_new_session=True, preexec_fn=_test_limits,
        )
        try:
            code = process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
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


def _listed_tests(executable):
    code, payload = _run_bounded([executable, "--list", "--format", "terse"], list_output=True)
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


def _classify(code, payload):
    """True for a pass, False for a failure; anything ambiguous is a refusal.

    libtest's terse output for one exact test is a progress character and exactly one
    summary line. The exit code must agree with that summary.
    """
    try:
        lines = payload.decode("utf-8", "strict").split("\n")
    except UnicodeDecodeError:
        raise Refusal("rust-test-result-invalid") from None
    rows = [line for line in lines if line.startswith("test result: ")]
    match = RESULT_LINE.fullmatch(rows[0]) if len(rows) == 1 else None
    if match is None:
        raise Refusal("rust-test-result-invalid")
    status, passed, failed, ignored = match.group(1), int(match.group(2)), int(match.group(3)), int(match.group(4))
    if code == 0 and status == "ok" and failed == 0 and passed + ignored == 1:
        return True
    if code == 101 and status == "FAILED" and failed == 1 and passed == 0 and ignored == 0:
        return False
    raise Refusal("rust-test-result-invalid")


def _run_one(executable, name):
    temporary_directory = os.environ.get("TMPDIR") or tempfile.gettempdir()
    output = tempfile.TemporaryFile(mode="w+b", dir=temporary_directory)
    try:
        process = subprocess.Popen(
            [executable, "--exact", "--format", "terse", name],
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/devlane-home",
                 "TMPDIR": "/scratch/tmp", "LC_ALL": "C", "LANG": "C", "RUST_TEST_THREADS": "1"},
            close_fds=True, start_new_session=True, preexec_fn=_test_limits,
        )
        try:
            code = process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
            raise Refusal("rust-test-timeout") from None
        output.flush()
        size = os.fstat(output.fileno()).st_size
        if size > MAX_LIST:
            raise Refusal("rust-test-output-size")
        output.seek(0)
        payload = output.read(MAX_LIST + 1)
        if len(payload) != size:
            raise Refusal("rust-test-output-size")
        return _classify(code, payload)
    finally:
        output.close()


def _write(path, records):
    payload = b"".join(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
                     for record in records)
    if len(records) > MAX_TESTS or len(payload) > 16 * 1024:
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


def collect(log_path, config_path, output_path):
    records = []
    try:
        expected = _test_map(config_path)
        executables = _cargo_test_executables(log_path)
        actual = []
        by_name = {}
        for executable in executables:
            for name in _listed_tests(executable):
                if name in by_name:
                    raise Refusal("rust-test-duplicate")
                by_name[name] = executable
                actual.append(name)
        if set(actual) != set(expected):
            raise Refusal("rust-test-coverage")
        for name in sorted(expected):
            if not _run_one(by_name[name], name):
                records.append({"kind": "test", "stage": "unit", "test": expected[name]})
        _write(output_path, records)
        return 1 if records else 0
    except Exception:
        try:
            _write(output_path, [{"kind": "control", "stage": "unit", "status": "fail",
                                  "code": "DEVLANE_FAILURE"}])
        except Exception:
            pass
        return 2


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        return 2
    code = collect(*arguments)
    if code == 2:
        print("rust_test_adapter=refused", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
