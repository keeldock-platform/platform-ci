"""Linux/root source-free acceptance of the production encrypted lane path.

Run only from the ubuntu devlane-synthetic workflow.  Fixtures use planted
canaries and fake source code; this test never reads project source or a real
decryption secret.

Scenarios (each runs the production preparation, supervisor, decryptor, profile
commands, adapters, filter and cleanup; nothing is stubbed):

* synthetic-node: fixed-shape fixture with hostile behaviour (descendants that
  outlive their parent, planted workflow-command text on every output channel,
  inspection of the workload's environment, descriptors and files for key bytes),
  a wrong-key refusal, a failing test mapped to its opaque identity, and a
  cancellation while a profile command is running.
* synthetic-rust-v1-refusal: committed root, fuzz and runtime workspaces, a
  listener package, replay corpus and the fixed matrix;
  the legacy schema-1 envelope must fail the SemVer v2 gate explicitly.
* real-node: the pinned Vitest, Vite and TypeScript packages (native bindings
  included) installed online from the reviewed lock, run offline, with a passing
  test and an intentionally failing negative-control test. Its execute status 1
  is expected and its public summary must contain case_0002 plus vitest-failed.
* real-browser: the pinned Playwright test runner with an installed Chromium,
  run offline.
* install-script-canary: a public package whose lock entry declares an install script
  (esbuild) is installed through the production preparation; its placeholder launcher
  must remain unreplaced, proving lifecycle scripts never run.
"""

import gzip
import base64
import binascii
import hashlib
import io
import json
import os
import re
import signal
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib import error as urllib_error
from urllib.parse import quote

import bundle
import fetch
import network_probe
import host_cleanup
import owned_tree_cleanup
import rust_matrix_runner
import rust_tooling
import rust_rehearsal_fixture
import semver_stage
import deadline as deadline_budget
import diagnostic_contract
import filter as output_filter
import supervisor


ROOT = Path(__file__).resolve().parents[2]
DEVLANE_ROOT = (ROOT / "kit/devlane").resolve()
RUNNER_TEMP = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())).resolve()
DEADLINE_FILE = ""
DIAGNOSTIC_FILE = ""
RUN_ID = os.environ.get("GITHUB_RUN_ID", "")
RUN_ATTEMPT = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
CONTROL_SHA = os.environ.get("CI_SHA", "")
CONTROL_RUN_ID = RUN_ID
SOURCE_CANARY = "SYNTHETIC_SOURCE_CANARY_7f8c"
KEY_CANARY = b"KEYCANARY-73A10X"
KEY_BYTES = KEY_CANARY + bytes(range(16))
COMMAND_CANARIES = ("::add-mask::SYNTHETIC_SOURCE_CANARY_7f8c", "::error::SYNTHETIC_SOURCE_CANARY_7f8c",
                    chr(35) * 2 + "[group]SYNTHETIC_SOURCE_CANARY_7f8c", "::set-output name=x::SYNTHETIC_SOURCE_CANARY_7f8c")
BACKGROUND_MARKER = "DEVLANE_E2E_BACKGROUND_MARKER"
RUST_VERSION = "1.99.1"
RUST_LOCKFILES = rust_rehearsal_fixture.LOCKFILES
PLAYWRIGHT_VERSION = "1.54.2"
TYPESCRIPT_VERSION = "6.0.3"
SYNTHETIC_LOCK = ROOT / "kit/confinement/synthetic_project/package-lock.json"

DIAGNOSTIC_PHASES = diagnostic_contract.E2E_PROGRESS_PHASES
PROGRESS_ENABLED = False
MAX_E2E_RAW_DIAGNOSTIC_LOGS = 48
MAX_E2E_RAW_DIAGNOSTIC_TAIL_LINES = 120
MAX_E2E_RAW_DIAGNOSTIC_TAIL_BYTES = 128 * 1024
MAX_E2E_RAW_DIAGNOSTIC_LINE_BYTES = 128
MAX_E2E_REPORT_ENTRIES = 64
_DIAGNOSTIC_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

EXECUTE_EXIT_EXPECTATIONS = {
    ("synthetic-node", "accept"): 0,
    ("synthetic-node", "failing-test"): 1,
    ("real-node", "accept-with-failure"): 1,
    ("synthetic-rust-v1-refusal", "accept"): 1,
    ("install-script-canary", "accept"): 0,
    ("real-browser", "accept"): 0,
}


def _progress(line):
    if PROGRESS_ENABLED:
        print("devlane_e2e_progress=" + line, flush=True)


def _innermost_devlane_frame(error):
    """Return only the innermost trusted frame as basename, line, and function."""
    frames = []
    current = error.__traceback__
    while current is not None:
        frame = current.tb_frame
        try:
            relative = Path(frame.f_code.co_filename).resolve().relative_to(DEVLANE_ROOT)
        except (OSError, RuntimeError, ValueError):
            current = current.tb_next
            continue
        basename = relative.name
        function = frame.f_code.co_name
        line = current.tb_lineno
        if (re.fullmatch(r"[A-Za-z0-9_-]{1,48}\.py", basename)
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", function)
                and type(line) is int and line > 0):
            frames.append((basename, line, function))
        current = current.tb_next
    return frames[-1] if frames else None


_EXCEPTION_CATEGORIES = {
    AssertionError: "assertion-error",
    AttributeError: "attribute-error",
    FileExistsError: "file-exists",
    FileNotFoundError: "file-not-found",
    IsADirectoryError: "is-directory",
    KeyError: "key-error",
    NameError: "name-error",
    NotADirectoryError: "not-directory",
    OSError: "os-error",
    PermissionError: "permission-denied",
    RuntimeError: "runtime-error",
    TimeoutError: "timeout-error",
    TypeError: "type-error",
    ValueError: "value-error",
    UnicodeError: "unicode-error",
    UnicodeDecodeError: "unicode-decode-error",
    json.JSONDecodeError: "json-decode-error",
    subprocess.CalledProcessError: "process-exit-error",
    subprocess.SubprocessError: "process-error",
    subprocess.TimeoutExpired: "process-timeout",
    tarfile.TarError: "archive-error",
    urllib_error.HTTPError: "http-error",
    urllib_error.URLError: "url-error",
    bundle.Refusal: "bundle-refusal",
    deadline_budget.DeadlineRefusal: "deadline-refusal",
    fetch.Refusal: "fetch-refusal",
    network_probe.ProbeRefusal: "network-probe-refusal",
    output_filter.FilterRefusal: "filter-refusal",
    rust_matrix_runner.MatrixRefusal: "matrix-refusal",
    rust_tooling.ToolingRefusal: "tooling-refusal",
}

STARTUP_REFUSAL_CODES = supervisor.STARTUP_REFUSAL_CODES
SUPERVISOR_OPERATION_REFUSAL_CODES = supervisor.REFUSAL_CODES - STARTUP_REFUSAL_CODES
SUPERVISOR_REFUSAL_CODES = (STARTUP_REFUSAL_CODES | supervisor.REFUSAL_CODES
                            | supervisor.STARTUP_DIAGNOSTIC_CODES)
_STARTUP_DIAGNOSTIC_CATEGORIES = STARTUP_REFUSAL_CODES | frozenset((
    "startup-exit-one", "startup-exit-signal", "startup-exit-unexpected",
    "startup-import-failure", "startup-output-canary", "startup-parser-refusal",
    "startup-refusal-unlisted", "startup-stderr-empty", "startup-stderr-invalid",
    "startup-success-output-invalid", "startup-success-output-missing", "startup-success-stderr",
    "startup-traceback", "startup-unexpected-success", "startup-stdout-unexpected",
))
_STARTUP_DIAGNOSTIC_CATEGORIES |= SUPERVISOR_OPERATION_REFUSAL_CODES
_STARTUP_DIAGNOSTIC_CATEGORIES |= supervisor.STARTUP_DIAGNOSTIC_CODES
_REFUSAL_CATEGORY_ALIASES = {
    "cargo-workspace-projection-invalid": "cargo-ws-projection-invalid",
    "cargo-workspace-projection-mismatch": "cargo-ws-projection-mismatch",
}
_STARTUP_DIAGNOSTIC_CATEGORIES |= frozenset(_REFUSAL_CATEGORY_ALIASES.values())


class StartupRefusalMismatch(RuntimeError):
    """A startup result that differs from the one exact expected refusal."""

    def __init__(self, category):
        route_detail = None
        route_code = "network-probe-refusal:network-route-unexpected"
        if category.startswith(route_code + " "):
            candidate = category[len(route_code) + 1:]
            if network_probe.valid_route_diagnostic(candidate):
                route_detail = candidate
        self.refusal_code = (
            route_code if route_detail is not None else
            category if category in SUPERVISOR_REFUSAL_CODES else ""
        )
        if route_detail is not None:
            self.category = route_code + " " + route_detail
        elif category in _STARTUP_DIAGNOSTIC_CATEGORIES:
            self.category = _REFUSAL_CATEGORY_ALIASES.get(category, category)
        else:
            self.category = "startup-refusal-unlisted"
        super().__init__("startup-refusal-contract-mismatch")


class PreparationRefusalMismatch(RuntimeError):
    """A preparation CLI result outside its exact finite success/refusal contract."""

    def __init__(self, phase, category, cleanup_state="not-needed", cleanup_reason=""):
        self.phase = phase if phase in DIAGNOSTIC_PHASES else "prepare-protocol"
        if category not in diagnostic_contract.PREPARATION_E2E_CATEGORIES:
            category = "preparation-output-invalid"
        self.category = category
        self.cleanup_state = cleanup_state if cleanup_state == "unconfirmed" else ""
        self.cleanup_reason = cleanup_reason if cleanup_reason in diagnostic_contract.CLEANUP_SUBREASONS else ""
        super().__init__("preparation-result-contract-mismatch")


class _DiagnosticState:
    """Keep one bounded trusted phase and exception category for the first failure."""

    def __init__(self):
        self.first_failure = None
        self.cleanup_state = ""
        self.tooling_reason = ""
        self.tooling_version = ""
        self.cleanup_reason = ""
        self.runtime_frame = None
        self.runtime_code = ""

    def reset(self):
        self.first_failure = None
        self.cleanup_state = ""
        self.tooling_reason = ""
        self.tooling_version = ""
        self.cleanup_reason = ""
        self.runtime_frame = None
        self.runtime_code = ""

    def capture(self, phase, error):
        cleanup_reason = getattr(error, "cleanup_reason", "")
        if cleanup_reason in diagnostic_contract.CLEANUP_SUBREASONS:
            self.cleanup_state = "unconfirmed"
            self.cleanup_reason = cleanup_reason
        if self.first_failure is None:
            if type(error) is PreparationRefusalMismatch:
                phase, category = error.phase, error.category
                self.cleanup_state = error.cleanup_state
                self.cleanup_reason = error.cleanup_reason or self.cleanup_reason
            elif cleanup_reason in diagnostic_contract.CLEANUP_SUBREASONS:
                category = "cleanup-incomplete"
            else:
                category = (error.category if type(error) is StartupRefusalMismatch
                            else _EXCEPTION_CATEGORIES.get(type(error), "unclassified"))
                if type(error) is rust_tooling.ToolingRefusal:
                    self.tooling_reason = (
                        error.code if error.code in diagnostic_contract.TOOLING_REFUSAL_CODES
                        else "tooling-refusal-unlisted"
                    )
                    if self.tooling_reason == "tool-version-mismatch":
                        self.tooling_version = _public_tool_version_line(error.version_output)
                if phase in ("variant-execute", "variant-summary-validate") and type(error) is RuntimeError:
                    self.runtime_frame = _innermost_devlane_frame(error)
                    if (len(error.args) == 1 and type(error.args[0]) is str
                            and error.args[0] in diagnostic_contract.E2E_REQUIRE_CODES):
                        self.runtime_code = error.args[0]
            self.first_failure = (phase, category)

    @contextmanager
    def phase(self, name):
        if name not in DIAGNOSTIC_PHASES:
            raise RuntimeError("diagnostic-phase-invalid")
        try:
            yield
        except Exception as error:
            self.capture(name, error)
            raise
        else:
            _progress("phase=" + name)

    def refusal_line(self, error):
        if self.first_failure is None:
            self.capture("harness-startup", error)
        phase, category = self.first_failure
        line = "devlane_production_e2e=refused stage=" + phase + " exception=" + category
        if (phase in ("variant-execute", "variant-summary-validate")
                and category == "runtime-error" and self.runtime_frame is not None):
            basename, line_number, function = self.runtime_frame
            line += (" class=RuntimeError frame=" + basename + ":" + str(line_number)
                     + ":" + function)
            if self.runtime_code:
                line += " code=" + self.runtime_code
        elif category == "tooling-refusal":
            reason = self.tooling_reason or "tooling-refusal-unlisted"
            line += " reason=" + reason
            if reason == "tool-version-mismatch" and self.tooling_version:
                line += ' version="' + self.tooling_version + '"'
        elif self.cleanup_reason:
            line += " reason=" + self.cleanup_reason
        if self.cleanup_state == "unconfirmed":
            line += " cleanup=unconfirmed"
        return line


def _public_tool_version_line(output):
    """Keep one short, path-free public version line from a pinned tool probe."""
    if type(output) is not bytes:
        return ""
    first_line = output.partition(b"\n")[0].partition(b"\r")[0][:256]
    text = first_line.decode("ascii", "replace").strip()
    if any(marker in text for marker in (
        "SYNTHETIC_SOURCE_CANARY", "PRIVATE_SOURCE_CANARY", "SYNTHETIC_KEY_CANARY",
        "PRIVATE_KEY_CANARY", "KEYCANARY",
    )):
        return "redacted"
    sanitized = "".join(character if character in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._+-"
                        else "_" for character in text)
    sanitized = " ".join(sanitized.split())[:32].strip()
    if not sanitized:
        return ""
    if not sanitized[0].isalnum() and sanitized[0] not in "._+-":
        return ""
    return sanitized


DIAGNOSTICS = _DiagnosticState()


def _phase_call(name, callback, *args, **kwargs):
    with DIAGNOSTICS.phase(name):
        return callback(*args, **kwargs)


def _run_preparation(argv, timeout=60 * 60):
    try:
        result = _process_run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise PreparationRefusalMismatch("prepare-launch", "preparation-process-timeout") from None
    except subprocess.SubprocessError:
        raise PreparationRefusalMismatch("prepare-launch", "preparation-process-error") from None
    except deadline_budget.DeadlineRefusal:
        raise PreparationRefusalMismatch("prepare-deadline-check", "total-deadline-exhausted") from None
    except OSError as error:
        category = ("preparation-process-start-error" if type(error) in (FileNotFoundError, PermissionError)
                    else "preparation-process-error")
        raise PreparationRefusalMismatch("prepare-launch", category) from None
    if _contains_output_canary(result.stdout + result.stderr):
        raise PreparationRefusalMismatch("prepare-protocol", "preparation-output-canary")
    failure = diagnostic_contract.parse_preparation_result(
        result.returncode, result.stdout, result.stderr,
    )
    if failure is not None:
        raise PreparationRefusalMismatch(*failure)
    return result


def _write_diagnostic_file(path, line):
    if not path:
        return False
    payload = (line + "\n").encode("ascii", "strict")
    if len(payload) > diagnostic_contract.MAX_PUBLIC_DIAGNOSTIC_BYTES + 1:
        return False
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        return True
    except OSError:
        return False


def _read_reportable_diagnostic_file(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or metadata.st_nlink != 1
                or metadata.st_size > diagnostic_contract.MAX_PUBLIC_DIAGNOSTIC_BYTES + 1):
            return None
        payload = os.read(descriptor, diagnostic_contract.MAX_PUBLIC_DIAGNOSTIC_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) != metadata.st_size or not payload.endswith(b"\n"):
        return None
    try:
        line = payload[:-1].decode("ascii", "strict")
    except UnicodeDecodeError:
        return None
    return line if (diagnostic_contract.public_preparation_diagnostic(line)
                    or diagnostic_contract.public_e2e_runtime_diagnostic(line)) else None


def _require(condition, code):
    if not condition:
        raise RuntimeError(code)


def _summary_has_valid_terminator(payload):
    """A filtered success may contain no records; nonempty summaries end on a line boundary."""
    return type(payload) is bytes and (not payload or payload.endswith(b"\n"))


def _bounded_timeout(timeout):
    if DEADLINE_FILE:
        return min(float(timeout), deadline_budget.remaining(DEADLINE_FILE))
    return timeout


def _process_run(argv, **kwargs):
    if "timeout" in kwargs:
        kwargs["timeout"] = _bounded_timeout(kwargs["timeout"])
    return subprocess.run(argv, **kwargs)


def _scan_output(data, code):
    _require(not _contains_output_canary(data), code)


def _contains_output_canary(data):
    return any(canary in data for canary in (
        SOURCE_CANARY.encode("ascii"), KEY_CANARY, KEY_BYTES.hex().encode("ascii"),
        *(item.encode("ascii") for item in COMMAND_CANARIES),
    ))


def _expected_execute_status(scenario, variant):
    key = (scenario["name"], variant)
    if key not in EXECUTE_EXIT_EXPECTATIONS:
        raise RuntimeError("execute-expectation-unlisted")
    if (scenario["name"] == "synthetic-rust-v1-refusal") != (
            scenario.get("expect_semver_execution_refusal") is True):
        raise RuntimeError("execute-expectation-profile-mismatch")
    return EXECUTE_EXIT_EXPECTATIONS[key]


def _run(argv, *, env=None, timeout=900, expected=0, scan=True, cwd=None, diagnostic_callsite=None,
         on_result=None):
    result = _process_run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, timeout=timeout,
                            close_fds=True, check=False, cwd=cwd)
    if on_result is not None:
        on_result(result)
    if result.returncode != 0 and diagnostic_callsite is not None:
        _report_command_failure(diagnostic_callsite, result)
    _require(result.returncode == expected, "production-path-command-failed")
    if scan:
        _scan_output(result.stdout + result.stderr, "canary-in-command-output")
    return result


def _report_command_failure(callsite, result):
    """Emit the fixed callsite, bounded public summary records, and refusal lines."""
    if (callsite not in diagnostic_contract.E2E_COMMAND_CALL_SITES
            or type(result.returncode) is not int):
        return
    print("devlane_e2e_command=failed call=" + callsite
          + " returncode=" + str(result.returncode), flush=True)
    stdout = result.stdout if type(result.stdout) is bytes else b""
    stderr = result.stderr if type(result.stderr) is bytes else b""
    emitted = set()
    count = 0
    for payload, is_stdout in ((stdout, True), (stderr, False)):
        if (len(payload) > diagnostic_contract.MAX_E2E_COMMAND_OUTPUT_BYTES
                or _contains_output_canary(payload)):
            continue
        for raw_line in payload.splitlines(keepends=True):
            if not raw_line.endswith(b"\n"):
                continue
            try:
                line = raw_line[:-1].decode("ascii", "strict")
            except UnicodeDecodeError:
                continue
            is_summary_record = (is_stdout
                                 and output_filter.is_public_summary_record(raw_line[:-1]))
            is_refusal = diagnostic_contract.public_e2e_command_refusal(line)
            if line not in emitted and (is_summary_record or is_refusal):
                print(line, flush=True)
                emitted.add(line)
                count += 1
                if count >= diagnostic_contract.MAX_E2E_COMMAND_DIAGNOSTIC_LINES:
                    break
        if count >= diagnostic_contract.MAX_E2E_COMMAND_DIAGNOSTIC_LINES:
            break


def _synthetic_failure_subreason(summary, profile="core-node", *, execution_failed=False):
    if profile not in ("core-node", "core-rust"):
        return ""
    if type(summary) is bytes and not _contains_output_canary(summary):
        for line in summary.splitlines():
            try:
                record = output_filter._parse_record(line)
            except output_filter.FilterRefusal:
                continue
            if (record.get("kind") == "control" and record.get("status") == "fail"
                    and record.get("code") == "DEVLANE_FAILURE"):
                subreason = record.get("subreason")
                if (profile == "core-node" and record.get("stage") == "unit"
                        and subreason in ("vitest-failed", "report-missing", "adapter-failed")):
                    return subreason
                if (profile == "core-rust" and record.get("stage") != "semver"
                        and subreason in ("report-missing", "adapter-failed")):
                    return "rust-matrix-" + subreason
            if profile == "core-rust":
                if record.get("kind") == "test" and record.get("stage") == "unit":
                    return "rust-matrix-failed"
                if (record.get("kind") == "control" and record.get("stage") == "semver"
                        and record.get("status") == "fail"):
                    return "rust-matrix-failed"
                if (record.get("kind") == "coverage"
                        and type(record.get("failed")) is int and record["failed"] > 0):
                    return "rust-matrix-failed"
                if (record.get("kind") == "diagnostic"
                        and record.get("level") == "error"):
                    return "rust-matrix-failed"
    return "execute-failed" if execution_failed else ""


def _safe_diagnostic_name(value, fallback):
    if (type(value) is str and _DIAGNOSTIC_NAME.fullmatch(value)
            and not _contains_output_canary(value.encode("ascii", "ignore"))):
        return value
    return fallback


def _read_synthetic_failure_diagnostics(path, expected_subreason):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size > supervisor.MAX_SYNTHETIC_DIAGNOSTIC_FILE_BYTES):
                return None
            payload = source.read(supervisor.MAX_SYNTHETIC_DIAGNOSTIC_FILE_BYTES + 1)
    except OSError:
        return None
    if len(payload) > supervisor.MAX_SYNTHETIC_DIAGNOSTIC_FILE_BYTES:
        return None
    try:
        document = bundle.strict_json(payload, supervisor.MAX_SYNTHETIC_DIAGNOSTIC_FILE_BYTES)
    except bundle.Refusal:
        return None
    if (type(document) is not dict or set(document) != {"schema", "wave_class", "subreason", "logs", "reports"}
            or document["schema"] != 1 or document["wave_class"] != fetch.SOURCE_FREE_WAVE_CLASS
            or document["subreason"] != expected_subreason
            or type(document["logs"]) is not list or len(document["logs"]) > MAX_E2E_RAW_DIAGNOSTIC_LOGS
            or type(document["reports"]) is not list
            or len(document["reports"]) > MAX_E2E_REPORT_ENTRIES + 1):
        return None
    return document


def _print_synthetic_failure_diagnostics(document):
    for log in document["logs"]:
        if type(log) is not dict or set(log) != {"name", "lines"}:
            continue
        name = _safe_diagnostic_name(log["name"], "raw-log")
        if type(log["lines"]) is not list or len(log["lines"]) > MAX_E2E_RAW_DIAGNOSTIC_TAIL_LINES:
            continue
        for index, encoded_line in enumerate(log["lines"], 1):
            if type(encoded_line) is not str:
                continue
            try:
                raw_line = base64.b64decode(encoded_line, validate=True)
            except (ValueError, binascii.Error):
                continue
            if len(raw_line) > MAX_E2E_RAW_DIAGNOSTIC_TAIL_BYTES or _contains_output_canary(raw_line):
                continue
            text = raw_line.decode("utf-8", "replace").rstrip("\r\n")
            hash_marker = chr(35) * 2
            text = text.replace("::", ": :").replace(hash_marker + "[", hash_marker + " [")
            text = "".join(character if ord(character) >= 32 and ord(character) != 127 else " "
                           for character in text)
            text = text.encode("utf-8")[:MAX_E2E_RAW_DIAGNOSTIC_LINE_BYTES].decode("utf-8", "ignore")
            encoded = quote(text, safe="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~:/,=@+!?(){} -")
            line = "devlane_e2e_failure_diag=log name=%s line=%d text=%s" % (name, index, encoded)
            if diagnostic_contract.public_e2e_failure_diagnostic(line):
                print(line, flush=True)

    for index, report in enumerate(document["reports"], 1):
        if (type(report) is not dict or set(report) != {"name", "kind", "bytes"}
                or report["kind"] not in ("directory", "file", "symlink", "other", "missing")
                or type(report["bytes"]) is not int or not 0 <= report["bytes"] <= 999_999_999_999):
            continue
        name = _safe_diagnostic_name(report["name"], "entry-%02d" % index)
        line = "devlane_e2e_failure_diag=report name=%s kind=%s bytes=%d" % (
            name, report["kind"], report["bytes"],
        )
        if diagnostic_contract.public_e2e_failure_diagnostic(line):
            print(line, flush=True)


def _emit_synthetic_failure_diagnostics(path, summary, profile="core-node", *, execution_failed=False):
    """Print sanitized tails copied by the supervisor for one source-free profile failure."""
    try:
        subreason = _synthetic_failure_subreason(
            summary, profile, execution_failed=execution_failed,
        )
        if not subreason:
            return
        document = _read_synthetic_failure_diagnostics(path, subreason)
        if document is not None:
            _print_synthetic_failure_diagnostics(document)
    finally:
        try:
            Path(path).unlink()
        except OSError:
            pass


def _processes_matching(marker):
    result = _process_run(["pgrep", "-f", marker], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          check=False, timeout=5)
    own = {os.getpid(), os.getppid()}
    return [int(item) for item in result.stdout.split() if int(item) not in own]


"""---------------------------------------------------------------- metadata"""

def _node_lock_from_reviewed(dev_dependencies):
    """A non-workspace lock holding exactly the reachable closure of the requested dev packages,
    taken from the reviewed synthetic lock (real integrity hashes, native optional bindings)."""
    original = json.loads(SYNTHETIC_LOCK.read_text(encoding="utf-8"))["packages"]

    def resolve(owner, name):
        """npm's lookup: nested node_modules of the requester first, then each ancestor."""
        base = owner
        while True:
            candidate = (base + "/" if base else "") + "node_modules/" + name
            if candidate in original:
                return candidate
            if "/node_modules/" not in base and not base.startswith("node_modules/"):
                return None
            base = base.rsplit("/node_modules/", 1)[0] if "/node_modules/" in base else ""
            if base == "" and (("node_modules/" + name) not in original):
                return None

    chosen, queue = {}, []
    for name, version in dev_dependencies.items():
        path = "node_modules/" + name
        _require(path in original and original[path].get("version") == version, "reviewed-lock-package-missing")
        queue.append(path)
    while queue:
        path = queue.pop()
        if path in chosen:
            continue
        chosen[path] = dict(original[path])
        entry = original[path]
        for group in ("dependencies", "optionalDependencies", "peerDependencies"):
            for name in entry.get(group, {}):
                found = resolve(path, name)
                if found is not None:
                    queue.append(found)
    return {
        "name": "synthetic-private-canary", "version": "0.0.0", "lockfileVersion": 3, "requires": True,
        "packages": {"": {"name": "synthetic-private-canary", "version": "0.0.0", "devDependencies": dict(dev_dependencies)},
                     **dict(sorted(chosen.items()))},
    }


def _node_projection(source_lock, playwright=()):
    npm_package, npm_lock, npm_rows = fetch.project_npm_lock(bundle.canonical_json(source_lock))
    projection = {
        "schema": 1, "profile": "core-node", "tools": {"node": "24.22.1", "npm": "11.19.1"},
        "npm": npm_rows, "cargo": [], "playwright": list(playwright), "npm_package": npm_package,
        "npm_lock": npm_lock, "cargo_workspaces": [],
    }
    payload = bundle.canonical_json(projection)
    fetch.validate_projection(payload, "core-node")
    return projection, payload


def _generated_npm_lock(manifest_text):
    """Resolve a package lock on the networked hosted runner for packages the reviewed lock lacks."""
    with tempfile.TemporaryDirectory(prefix="devlane-lock-", dir=str(RUNNER_TEMP)) as temporary:
        directory = Path(temporary)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": temporary, "LC_ALL": "C"}
        (directory / "package.json").write_text(manifest_text, encoding="utf-8")
        _run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
             env=env, cwd=temporary, timeout=600, scan=False)
        return json.loads((directory / "package-lock.json").read_text(encoding="utf-8"))


def _rust_projection(lock_bytes, fuzz_lock_bytes, runtime_lock_bytes):
    cargo_manifest, cargo_lock, cargo_rows = fetch.project_cargo_lock(lock_bytes)
    fuzz_manifest, fuzz_lock, _ = fetch.project_cargo_lock(fuzz_lock_bytes)
    runtime_manifest, runtime_lock, _ = fetch.project_cargo_lock(runtime_lock_bytes)
    projection = {
        "schema": 1, "profile": "core-rust", "tools": {"cargo": RUST_VERSION, "rustc": RUST_VERSION},
        "npm": [], "cargo": cargo_rows, "playwright": [], "cargo_manifest": cargo_manifest,
        "cargo_lock": cargo_lock,
        "cargo_workspaces": [
            {"path": "fuzz/Cargo.lock", "manifest": fuzz_manifest, "lock": fuzz_lock},
            {"path": "runtime/Cargo.lock", "manifest": runtime_manifest, "lock": runtime_lock},
        ],
    }
    payload = bundle.canonical_json(projection)
    fetch.validate_projection(payload, "core-rust")
    return projection, payload


RUST_FIXTURE_SOURCES = rust_rehearsal_fixture.source_files()
RUST_FIXTURE_TESTS = rust_rehearsal_fixture.TESTS

def _write_rust_fixture(root, cargo_path):
    if not sys.platform.startswith("linux") or os.geteuid() == 0:
        raise RuntimeError("rust-fixture-linux-runner-required")
    _verify_rust_toolchain({"cargo": cargo_path, "rustc": _tool_paths("core-rust")["rustc"]})
    root = Path(root)
    _require(not root.exists() and not root.is_symlink(), "rust-fixture-output-exists")
    root.mkdir(mode=0o700, parents=True)
    files = rust_rehearsal_fixture.source_files()
    for relative, payload in files.items():
        path = root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(payload)
    for manifest in ("Cargo.toml", "fuzz/Cargo.toml", "runtime/Cargo.toml"):
        _run([cargo_path, "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1",
              "--manifest-path", str(root / manifest)], cwd=root, timeout=120, scan=False)
    lock_hashes = {}
    for relative in RUST_LOCKFILES:
        payload = files.get(relative)
        _require(type(payload) is bytes and bool(payload), "rust-fixture-lock-missing")
        lock_hashes[relative] = hashlib.sha256(payload).hexdigest()
    projection, projection_bytes = _rust_projection(
        files["Cargo.lock"], files["fuzz/Cargo.lock"], files["runtime/Cargo.lock"])
    snapshot = {
        "schema": 1,
        "toolchain": RUST_VERSION,
        "lockfiles": {path: {"sha256": lock_hashes[path], "size": len(files[path])}
                      for path in RUST_LOCKFILES},
        "projection_sha256": hashlib.sha256(projection_bytes).hexdigest(),
    }
    (root / ".devlane-projection.json").write_bytes(projection_bytes)
    (root / ".devlane-lock-snapshot.json").write_bytes(bundle.canonical_json(snapshot) + b"\n")
    _validate_rust_fixture(root, files, projection, projection_bytes, snapshot)
    print("rust_matrix_fixture=loaded committed_locks=3 matrix_coverage_ids=23")


def _validate_rust_fixture(root, files, projection, projection_bytes, snapshot):
    root = Path(root)
    _require(rust_matrix_runner.EXPECTED_MATRIX["toolchain"] == RUST_VERSION, "rust-matrix-toolchain-mismatch")
    _require(len(rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]) == 23, "rust-matrix-suite-count")
    _require([item["path"] for item in projection["cargo_workspaces"]]
             == ["fuzz/Cargo.lock", "runtime/Cargo.lock"], "rust-matrix-projection-paths")
    validated = fetch.validate_projection(projection_bytes, "core-rust")
    _require(validated == projection, "rust-matrix-projection-invalid")
    _require(set(snapshot["lockfiles"]) == set(RUST_LOCKFILES), "rust-matrix-lock-snapshot-set")
    for path in RUST_LOCKFILES:
        payload = files.get(path)
        _require(type(payload) is bytes and hashlib.sha256(payload).hexdigest() == snapshot["lockfiles"][path]["sha256"],
                 "rust-matrix-lock-snapshot-mismatch")
        _require(snapshot["lockfiles"][path]["size"] == len(payload), "rust-matrix-lock-snapshot-size")
        manifest, lock, dependencies = fetch.project_cargo_lock(payload)
        row = projection["cargo_workspaces"][0 if path.startswith("fuzz/") else 1] if path != "Cargo.lock" else None
        if path == "Cargo.lock":
            _require(manifest == projection["cargo_manifest"] and lock == projection["cargo_lock"],
                     "rust-matrix-root-projection")
            _require({item["name"] for item in dependencies} >= {"itoa", "fastrand"},
                     "rust-matrix-root-dependency-projection")
        else:
            _require(manifest == row["manifest"] and lock == row["lock"], "rust-matrix-workspace-projection")
            _require(not dependencies, "rust-matrix-workspace-dependencies")
    _require(snapshot["projection_sha256"] == hashlib.sha256(projection_bytes).hexdigest(),
             "rust-matrix-projection-snapshot")
    expected_lock_hashes = {path: value["sha256"] for path, value in snapshot["lockfiles"].items()}
    archive = _archive(files, "core-rust", snapshot["projection_sha256"], {}, RUST_FIXTURE_TESTS, {},
                      original_lockfiles=expected_lock_hashes)
    manifest, archive_files, _ = bundle.inspect_archive(archive, {
        "profile": "core-rust", "fetch_sha256": snapshot["projection_sha256"],
    })
    _require(set(manifest["original_lockfiles"]) == set(RUST_LOCKFILES), "rust-matrix-archive-lock-set")
    _require(all(archive_files[path] == files[path] for path in RUST_LOCKFILES), "rust-matrix-archive-lock-bytes")
    _require(set(RUST_FIXTURE_TESTS) == {
        "root::Cargo.toml::tests::child_has_no_control_secrets_or_sockets",
        "runtime::runtime/crates/services/listener/Cargo.toml::tests::listener_fixture_is_reachable",
        "fuzz::fuzz/Cargo.toml::tests::corpus_fixture_is_present",
        "listener::runtime/crates/services/listener/Cargo.toml::tests::listener_fixture_is_reachable",
    }, "rust-matrix-test-map")
    required_files = set(RUST_FIXTURE_SOURCES)
    _require(required_files == set(files) and all(bool(files[path]) for path in required_files),
             "rust-matrix-fixture-files")
    for relative in required_files:
        path = root / relative
        _require(path.is_file() and not path.is_symlink() and path.read_bytes() == files[relative],
                 "rust-matrix-fixture-source-binding")
    _require((root / ".devlane-projection.json").read_bytes() == projection_bytes,
             "rust-matrix-projection-file-binding")
    _require(bundle.strict_json((root / ".devlane-lock-snapshot.json").read_bytes(), 64 * 1024) == snapshot,
             "rust-matrix-lock-snapshot-file-binding")
    matrix = rust_matrix_runner.EXPECTED_MATRIX
    _require(matrix["workspaces"] == [
        {"id": "root", "manifest": "/workspace/source/Cargo.toml", "lock": "/workspace/source/Cargo.lock", "mode": "workspace"},
        {"id": "runtime", "manifest": "/workspace/source/runtime/Cargo.toml", "lock": "/workspace/source/runtime/Cargo.lock", "mode": "workspace"},
        {"id": "fuzz", "manifest": "/workspace/source/fuzz/Cargo.toml", "lock": "/workspace/source/fuzz/Cargo.lock", "mode": "package"},
    ], "rust-matrix-workspace-set")
    _require(matrix["listener"] == {
        "id": "listener", "manifest": "/workspace/source/runtime/crates/services/listener/Cargo.toml",
        "lock": "/workspace/source/runtime/Cargo.lock", "mode": "package",
    }, "rust-matrix-listener-package")
    _require(matrix["coverage_ids"] == [
        "fmt-root", "fmt-runtime", "fmt-fuzz", "deny-root", "deny-runtime", "deny-fuzz",
        "audit-root", "audit-runtime", "audit-fuzz", "vet-root", "vet-runtime", "vet-fuzz",
        "root-default", "root-all-features", "runtime-default", "runtime-all-features",
        "fuzz-default", "fuzz-all-features", "listener-default", "listener-all-features",
        "fuzz-replay-default", "fuzz-replay-all-features", "semver-runtime",
    ], "rust-matrix-suite-set")
    for path in ("deny.toml", "supply-chain/config.toml", "supply-chain/audits.toml",
                 "supply-chain/imports.lock", "runtime/supply-chain/config.toml",
                 "runtime/supply-chain/audits.toml", "runtime/supply-chain/imports.lock",
                 "fuzz/corpus/valid-object.json", "fuzz/corpus/valid-array.json"):
        _require(path in files and bool(files[path]), "rust-matrix-policy-or-replay-fixture")
    _require(b'[[exemptions.fastrand]]\nversion = "2.5.0"' in files["supply-chain/config.toml"]
             and b'[[exemptions.itoa]]\nversion = "1.0.19"' in files["supply-chain/config.toml"],
             "rust-matrix-fixture-vet-policy")
    return archive


def _load_rust_fixture(root):
    root = Path(root)
    projection_bytes = (root / ".devlane-projection.json").read_bytes()
    snapshot = bundle.strict_json((root / ".devlane-lock-snapshot.json").read_bytes(), 64 * 1024)
    _require(type(snapshot) is dict and set(snapshot) == {
        "schema", "toolchain", "lockfiles", "projection_sha256",
    } and snapshot["schema"] == 1 and snapshot["toolchain"] == RUST_VERSION,
        "rust-matrix-lock-snapshot-shape")
    _require(type(snapshot["projection_sha256"]) is str
             and re.fullmatch(r"[a-f0-9]{64}", snapshot["projection_sha256"]) is not None,
             "rust-matrix-projection-snapshot-shape")
    files = {}
    for relative in set(RUST_FIXTURE_SOURCES):
        path = root / relative
        _require(path.is_file() and not path.is_symlink(), "rust-fixture-source-missing")
        files[relative] = path.read_bytes()
    projection = fetch.validate_projection(projection_bytes, "core-rust")
    _validate_rust_fixture(root, files, projection, projection_bytes, snapshot)
    return projection, projection_bytes, snapshot, files


def _verify_rust_toolchain(paths):
    for name in ("cargo", "rustc"):
        result = _process_run([paths[name], "--version"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=10, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        words = result.stdout.decode("ascii", "strict").split()
        _require(result.returncode == 0 and len(words) >= 2 and words[1] == RUST_VERSION,
                 "rust-fixture-toolchain-version")
    rustup = shutil.which("rustup")
    _require(bool(rustup), "rustup-unavailable")
    rustup_env = {
        "PATH": os.pathsep.join((str(Path(rustup).parent), "/usr/bin", "/bin")),
        "HOME": os.environ.get("HOME", ""),
        "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", ""),
        "CARGO_HOME": os.environ.get("CARGO_HOME", ""),
        "LC_ALL": "C",
    }
    result = _process_run([rustup, "run", RUST_VERSION, "rustfmt", "--version"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=10, check=False, env=rustup_env)
    version = result.stdout.decode("ascii", "strict").strip()
    _require(result.returncode == 0 and version.startswith("rustfmt "),
             "rust-fixture-rustfmt-unavailable")
    result = _process_run([rustup, "show", "home"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=10, check=False, env=rustup_env)
    _require(result.returncode == 0, "rust-fixture-rustup-home")
    rustup_home = Path(result.stdout.decode("ascii", "strict").strip()).resolve(strict=True)
    result = _process_run([rustup, "which", "--toolchain", RUST_VERSION, "rustfmt"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=10, check=False, env=rustup_env)
    _require(result.returncode == 0, "rust-fixture-rustfmt-toolchain")
    rustfmt_path = Path(result.stdout.decode("ascii", "strict").strip()).resolve(strict=True)
    try:
        relative = rustfmt_path.relative_to(rustup_home / "toolchains")
    except ValueError:
        relative = Path()
    _require(rustfmt_path.name == "rustfmt" and len(relative.parts) >= 2
             and (relative.parts[0] == RUST_VERSION or relative.parts[0].startswith(RUST_VERSION + "-"))
             and relative.parts[1:] == ("bin", "rustfmt"), "rust-fixture-rustfmt-toolchain")


def _verify_prepared_rust_tools(prepared, source):
    tools = Path(prepared) / "devlane-tools"
    source = Path(source)
    _require(tools.is_dir() and not tools.is_symlink(), "rust-matrix-tools-missing")
    for current, directories, _files in os.walk(tools, followlinks=False):
        for directory in (".", *directories):
            path = Path(current) if directory == "." else Path(current) / directory
            _require(stat.S_IMODE(path.stat().st_mode) & 0o005 == 0o005,
                     "rust-matrix-tool-directory-access")
    expected_entries = set(rust_tooling.TOOLS) | {
        "advisory-db", "advisory-db-revision", rust_tooling.SEMVER_RECEIPT,
    }
    _require({path.name for path in tools.iterdir()} == expected_entries, "rust-matrix-tools-layout")
    semver_stage.verify_tool(source)
    semver_stage.verify_tool(tools)
    for name, (_, _, _, version, _) in rust_tooling.TOOLS.items():
        path = tools / name
        _require(path.is_file() and not path.is_symlink() and os.access(path, os.X_OK),
                 "rust-matrix-tool-layout")
        source_path = source / name
        _require(source_path.is_file() and not source_path.is_symlink()
                 and rust_tooling._hash_prepared_binary(path)
                 == rust_tooling._hash_prepared_binary(source_path), "rust-matrix-tool-copy-binding")
        result = _process_run([str(path), "--version"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=10, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        _require(result.returncode == 0 and result.stdout.decode("ascii", "strict").strip() == version,
                 "rust-matrix-tool-version")
    database = tools / "advisory-db"
    revision_path = tools / "advisory-db-revision"
    _require(database.is_dir() and not database.is_symlink() and revision_path.is_file()
             and not revision_path.is_symlink(), "rust-matrix-advisory-database-missing")
    revision = revision_path.read_text(encoding="ascii").strip()
    _require(re.fullmatch(r"[a-f0-9]{40}", revision) is not None, "rust-matrix-advisory-database-revision")
    _require((database / "crates").is_dir() and any((database / "crates").rglob("*.md")),
             "rust-matrix-advisory-database-layout")
    result = _process_run(["git", "-C", str(database), "rev-parse", "--verify", "HEAD"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=10, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    _require(result.returncode == 0 and result.stdout.decode("ascii", "strict").strip() == revision,
             "rust-matrix-advisory-database-binding")
    source_database = source / "advisory-db"
    source_revision = (source / "advisory-db-revision").read_text(encoding="ascii").strip()
    _require(source_database.is_dir() and not source_database.is_symlink()
             and source_revision == revision, "rust-matrix-advisory-database-copy-binding")
    for database_path in (database, source_database):
        head = _process_run(["git", "-C", str(database_path), "rev-parse", "--verify", "HEAD"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=10, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        _require(head.returncode == 0 and head.stdout.decode("ascii", "strict").strip() == revision,
                 "rust-matrix-advisory-database-binding")
        status = _process_run(
            ["git", "-C", str(database_path), "status", "--porcelain", "--untracked-files=all"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10, check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0"},
        )
        _require(status.returncode == 0 and not status.stdout, "rust-matrix-advisory-database-dirty")
    for current, directories, filenames in os.walk(tools, followlinks=False):
        _require(not Path(current).is_symlink(), "rust-matrix-tools-link")
        _require(all(not (Path(current) / name).is_symlink() for name in directories + filenames),
                 "rust-matrix-tools-link")


"""---------------------------------------------------------------- fixtures"""

def _probe_script():
    """Workload-side inspection shared by the Node fixtures: it throws if any boundary is open.

    The key hex string is built at run time from its bytes, so no file in the workspace spells it.
    """
    return r'''import fs from 'node:fs';
import path from 'node:path';
const KEY_TEXT = __KEY_CANARY__;
const KEY_HEX = Buffer.from(__KEY_BYTES__).toString('hex');
const names = Object.keys(process.env);
if (names.includes('DEVLANE_DECRYPT_KEY') || names.some((name) => name.startsWith('GITHUB_') || name.startsWith('RUNNER_') || name === 'SYNTHETIC_KEY_CANARY' || name.startsWith('ACTIONS_'))) throw new Error('environment-boundary');
if (Object.values(process.env).some((value) => String(value).includes(KEY_HEX) || String(value).includes(KEY_TEXT))) throw new Error('environment-value-boundary');
if (process.argv.some((argument) => argument.includes(KEY_TEXT) || argument.includes(KEY_HEX))) throw new Error('argument-boundary');
if (process.platform === 'linux') {
  for (const name of fs.readdirSync('/proc/self/fd')) {
    const fd = Number(name);
    if (fd <= 2) continue;
    try { if (fs.readlinkSync(`/proc/self/fd/${fd}`).startsWith('socket:[')) throw new Error('descriptor'); }
    catch (error) { if (error?.message === 'descriptor') throw error; }
  }
  const runnerHome = '/proc/1/root/ho' + 'me/runner';
  if (fs.existsSync(runnerHome)) throw new Error('host-path-boundary');
  const environ = fs.readFileSync('/proc/self/environ', 'utf8');
  if (environ.includes(KEY_HEX) || environ.includes('DEVLANE_DECRYPT_KEY')) throw new Error('environ-boundary');
  const visible = fs.readdirSync('/proc').filter((name) => /^[0-9]+$/.test(name));
  if (visible.length > 64) throw new Error('process-visibility-boundary');
}
for (const forbidden of ['/ho' + 'me/runner', '/run/docker.sock', '/var/run/docker.sock']) {
  if (fs.existsSync(forbidden)) throw new Error('host-path-boundary');
}
function walk(directory, depth) {
  if (depth > 6) return;
  let entries = [];
  try { entries = fs.readdirSync(directory, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    const full = path.join(directory, entry.name);
    if (entry.name === 'node_modules' || entry.name === 'cargo-home' || entry.name === 'npm-cache') continue;
    if (entry.isDirectory()) walk(full, depth + 1);
    else if (entry.isFile()) {
      try { if (fs.statSync(full).size < 1048576 && fs.readFileSync(full, 'latin1').includes(KEY_HEX)) throw new Error('key-file-boundary'); }
      catch (error) { if (error?.message === 'key-file-boundary') throw error; }
    }
  }
}
for (const root of ['/trusted', '/workspace/source', '/tmp', '/devlane-home', '/scratch/tmp', '/scratch/reports']) walk(root, 0);
'''.replace("__KEY_CANARY__", json.dumps(KEY_CANARY.decode("ascii"))).replace("__KEY_BYTES__", json.dumps(list(KEY_BYTES)))


def _canary_emitters():
    lines = []
    for canary in COMMAND_CANARIES:
        lines.append("console.log(" + json.dumps(canary) + ");")
        lines.append("console.error(" + json.dumps(canary) + ");")
    lines.append("console.log(" + json.dumps(KEY_CANARY.decode("ascii")) + ");")
    return "\n".join(lines) + "\n"


def _node_source(lock, *, failing_test=False, hang=False):
    package = {
        "name": "synthetic-private-canary", "version": "0.0.0", "private": True,
        "type": "module", "devDependencies": dict(lock["packages"][""]["devDependencies"]),
    }
    ui_package = {
        "name": "@keeldock/kernel-ui-kit-fixture", "version": "0.0.0", "private": True,
        "type": "module", "scripts": {
            "typecheck": "node -e \"process.exit(0)\"",
            "test": "node tests/write-report.mjs",
        },
    }
    tokens_package = {
        "name": "@keeldock/kernel-tokens-fixture", "version": "0.0.0", "private": True,
        "type": "module", "scripts": {"check:generated": "node -e \"process.exit(0)\""},
    }
    tsconfig = {"compilerOptions": {"strict": True, "noEmit": True, "target": "ES2020", "module": "ESNext",
                                    "moduleResolution": "bundler", "skipLibCheck": True}}
    source = ("export const planted = '" + SOURCE_CANARY + "';\n"
              "export const value: number = 41;\n")
    status = "failed" if failing_test else "passed"
    background = ""
    if hang:
        background = ("setInterval(() => {}, 1000);\n"
                      "await new Promise((resolve) => setTimeout(resolve, 600000));\n")
    script = _probe_script() + r'''import { spawn } from 'node:child_process';
const output = process.argv.find((item) => item.startsWith('--outputFile='))?.slice('--outputFile='.length) ?? '/scratch/reports/vitest.json';
spawn(process.execPath, ['-e', 'setTimeout(() => {}, 900000) /* __BACKGROUND_MARKER__ */'], { detached: true, stdio: 'ignore' }).unref();
''' + _canary_emitters() + background + r'''fs.writeFileSync(output, JSON.stringify({ testResults: [{ assertionResults: [{ fullName: 'synthetic canary suite accepted test', status: __TEST_STATUS__, failureMessages: [__SOURCE_CANARY__, __KEY_CANARY__] }] }] }));
'''
    script = (script.replace("__TEST_STATUS__", json.dumps(status))
              .replace("__SOURCE_CANARY__", json.dumps(SOURCE_CANARY))
              .replace("__KEY_CANARY__", json.dumps(KEY_CANARY.decode("ascii")))
              .replace("__BACKGROUND_MARKER__", BACKGROUND_MARKER))
    return {
        "package.json": bundle.canonical_json(package) + b"\n",
        "package-lock.json": bundle.canonical_json(lock) + b"\n",
        "tsconfig.json": bundle.canonical_json(tsconfig) + b"\n",
        "packages/kernel-ui-kit/package.json": bundle.canonical_json(ui_package) + b"\n",
        "packages/kernel-tokens/package.json": bundle.canonical_json(tokens_package) + b"\n",
        "packages/kernel-ui-kit/src/example.ts": source.encode("ascii"),
        "packages/kernel-ui-kit/tests/write-report.mjs": script.encode("ascii"),
    }


def _real_node_source(lock):
    dev = lock["packages"][""]["devDependencies"]
    package = {
        "name": "synthetic-private-canary", "version": "0.0.0", "private": True, "type": "module",
        "devDependencies": dev,
    }
    ui_package = {
        "name": "@keeldock/kernel-ui-kit-fixture", "version": "0.0.0", "private": True,
        "type": "module", "scripts": {
            "typecheck": "tsc --noEmit -p /workspace/source/tsconfig.json",
            "test": "vitest",
        },
    }
    tokens_package = {
        "name": "@keeldock/kernel-tokens-fixture", "version": "0.0.0", "private": True,
        "type": "module", "scripts": {"check:generated": "node -e \"process.exit(0)\""},
    }
    tsconfig = {"compilerOptions": {"strict": True, "noEmit": True, "target": "ES2022", "module": "ESNext",
                                    "moduleResolution": "bundler", "skipLibCheck": True}}
    vitest_config = (
        "import { defineConfig } from 'vitest/config';\n"
        "export default defineConfig({\n"
        "  cacheDir: '/scratch/tmp/vitest-cache',\n"
        "  test: { pool: 'threads', include: ['tests/**/*.test.ts'] },\n"
        "});\n"
    )
    source = ("export const planted = '" + SOURCE_CANARY + "';\n"
              "export function add(left: number, right: number): number { return left + right; }\n")
    tests = (
        "import { expect, test } from 'vitest';\n"
        "import { add, planted } from '../src/example';\n"
        "test('real vitest accepted test', () => {\n"
        + _canary_emitters() +
        "  expect(add(1, 2)).toBe(3);\n});\n"
        "test('real vitest failing test', () => {\n"
        "  expect(planted).toBe('not-the-planted-value');\n});\n"
    )
    return {
        "package.json": bundle.canonical_json(package) + b"\n",
        "package-lock.json": bundle.canonical_json(lock) + b"\n",
        "tsconfig.json": bundle.canonical_json(tsconfig) + b"\n",
        "packages/kernel-ui-kit/package.json": bundle.canonical_json(ui_package) + b"\n",
        "packages/kernel-tokens/package.json": bundle.canonical_json(tokens_package) + b"\n",
        "packages/kernel-ui-kit/vitest.config.ts": vitest_config.encode("ascii"),
        "packages/kernel-ui-kit/src/example.ts": source.encode("ascii"),
        "packages/kernel-ui-kit/tests/example.test.ts": tests.encode("ascii"),
    }


def _browser_source(lock):
    package = {
        "name": "synthetic-private-canary", "version": "0.0.0", "private": True, "type": "module",
        "devDependencies": lock["packages"][""]["devDependencies"],
    }
    ui_package = {
        "name": "@keeldock/kernel-ui-kit-fixture", "version": "0.0.0", "private": True,
        "type": "module", "scripts": {
            "typecheck": "node -e \"process.exit(0)\"",
            "test": "node tests/write-report.mjs",
        },
    }
    tokens_package = {
        "name": "@keeldock/kernel-tokens-fixture", "version": "0.0.0", "private": True,
        "type": "module", "scripts": {"check:generated": "node -e \"process.exit(0)\""},
    }
    config = "export default { testDir: '.', reporter: 'json', workers: 1 };\n"
    spec = (
        "import { test, expect } from '@playwright/test';\n"
        "test('browser frame accepted', async ({ page }) => {\n"
        "  await page.setContent('<h1 id=\"x\">" + SOURCE_CANARY + "</h1>');\n"
        + _canary_emitters() +
        "  await expect(page.locator('h1')).toBeVisible();\n});\n"
    )
    report = (
        "import fs from 'node:fs';\n"
        "fs.mkdirSync('/scratch/reports', { recursive: true });\n"
        "fs.writeFileSync('/scratch/reports/vitest.json', JSON.stringify({ testResults: [{ assertionResults: "
        "[{ fullName: 'browser lane unit placeholder', status: 'passed', failureMessages: [] }] }] }));\n"
    )
    return {
        "package.json": bundle.canonical_json(package) + b"\n",
        "package-lock.json": bundle.canonical_json(lock) + b"\n",
        "tsconfig.json": bundle.canonical_json({"compilerOptions": {"noEmit": True, "skipLibCheck": True,
                                                                     "target": "ES2022", "module": "ESNext",
                                                                     "moduleResolution": "bundler"}}) + b"\n",
        "packages/kernel-ui-kit/package.json": bundle.canonical_json(ui_package) + b"\n",
        "packages/kernel-tokens/package.json": bundle.canonical_json(tokens_package) + b"\n",
        "packages/kernel-ui-kit/src/example.ts": ("export const planted = '" + SOURCE_CANARY + "';\n").encode("ascii"),
        "packages/kernel-ui-kit/browser/playwright.config.ts": config.encode("ascii"),
        "packages/kernel-ui-kit/browser/frame.spec.mjs": spec.encode("ascii"),
        "packages/kernel-ui-kit/tests/write-report.mjs": report.encode("ascii"),
    }


def _rust_build_script():
    return (
        "fn main() {\n"
        "    println!(\"cargo:warning=" + SOURCE_CANARY + "\");\n"
        "    println!(\"cargo:warning=" + KEY_CANARY.decode("ascii") + "\");\n"
        "    println!(\"cargo:warning=::add-mask::" + SOURCE_CANARY + "\");\n"
        "}\n"
    )


def _archive(files, profile, projection_sha, allowed_files, allowed_tests, frames, *, original_lockfiles=None):
    inventory = [{"path": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
                 for name, payload in sorted(files.items())]
    lock_name = "package-lock.json" if profile == "core-node" else "Cargo.lock"
    if original_lockfiles is None:
        original_lockfiles = {lock_name: hashlib.sha256(files[lock_name]).hexdigest()}
    manifest = {
        "schema": 1, "profile": profile, "profile_revision": 1, "source_revision": CONTROL_SHA,
        "tree_sha256": hashlib.sha256(bundle.canonical_json(inventory)).hexdigest(),
        "files": inventory,
        "original_lockfiles": original_lockfiles,
        "fetch_sha256": projection_sha,
        "allowed_files": allowed_files, "allowed_tests": allowed_tests, "frames": frames,
        "limits": {"ciphertext_bytes": bundle.MAX_CIPHERTEXT, "expanded_bytes": bundle.MAX_EXPANDED,
                   "files": bundle.MAX_FILES, "file_bytes": bundle.MAX_FILE},
    }
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o600
            info.uid = info.gid = info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
        payload = bundle.canonical_json(manifest)
        info = tarfile.TarInfo(".devlane/manifest.json")
        info.size = len(payload)
        info.mode = 0o600
        info.uid = info.gid = info.mtime = 0
        archive.addfile(info, io.BytesIO(payload))
    return gzip.compress(stream.getvalue(), mtime=0)


def scenarios():
    """The scenario table; building it needs the network only for the generated-lock scenarios."""
    result = []
    node_lock = _node_lock_from_reviewed({"typescript": TYPESCRIPT_VERSION})
    projection, payload = _node_projection(node_lock)
    result.append({
        "name": "synthetic-node", "profile": "core-node", "projection": projection, "payload": payload,
        "files": lambda **kw: _node_source(node_lock, **kw),
        "allowed_files": {"packages/kernel-ui-kit/src/example.ts": "file_0001"},
        "allowed_tests": {"synthetic canary suite accepted test": "case_0001"}, "frames": {},
        "variants": ("startup-refusal", "accept", "wrong-key", "failing-test", "cancel"),
    })
    real_lock = _node_lock_from_reviewed({
        "typescript": TYPESCRIPT_VERSION, "vite": "8.3.5", "vitest": "5.0.5",
        "esbuild": "0.27.0", "rollup": ROLLUP_VERSION,
    })
    projection, payload = _node_projection(real_lock)
    result.append({
        "name": "real-node", "profile": "core-node", "projection": projection, "payload": payload,
        "files": lambda **kw: _real_node_source(real_lock),
        "allowed_files": {"packages/kernel-ui-kit/src/example.ts": "file_0001"},
        "allowed_tests": {"real vitest accepted test": "case_0001", "real vitest failing test": "case_0002"},
        "frames": {}, "variants": ("accept-with-failure",), "after_prepare": _install_script_canary_check,
    })
    return result


INSTALL_SCRIPT_PACKAGE = "esbuild"
INSTALL_SCRIPT_VERSION = "0.25.9"
ROLLUP_VERSION = "4.44.2"
INSTALL_SCRIPT_PLACEHOLDER_LIMIT = 64 * 1024


def _install_script_canary_manifest():
    return json.dumps({
        "name": "synthetic-private-canary", "version": "0.0.0", "private": True,
        "devDependencies": {
            INSTALL_SCRIPT_PACKAGE: INSTALL_SCRIPT_VERSION,
            "rollup": ROLLUP_VERSION,
            "typescript": TYPESCRIPT_VERSION,
        },
    })


def _browser_manifest():
    return json.dumps({
        "name": "synthetic-private-canary", "version": "0.0.0", "private": True,
        "devDependencies": {
            "@playwright/test": PLAYWRIGHT_VERSION,
            "typescript": TYPESCRIPT_VERSION,
        },
    })


def _install_script_canary_check(prepared_path):
    """esbuild's public install script replaces its placeholder launcher with the native binary.

    With scripts suppressed the launcher must still be the small placeholder, while the platform
    package that carries the binary is present: the package installed, its script did not run.
    """
    launcher = Path(prepared_path) / "node_modules" / INSTALL_SCRIPT_PACKAGE / "bin" / INSTALL_SCRIPT_PACKAGE
    _require(launcher.is_file() and not launcher.is_symlink(), "install-script-canary-missing")
    _require(launcher.stat().st_size < INSTALL_SCRIPT_PLACEHOLDER_LIMIT, "install-script-ran")
    _require((Path(prepared_path) / "node_modules" / "@esbuild").is_dir(), "install-script-canary-platform-package-missing")
    if sys.platform.startswith("linux") and os.uname().machine == "x86_64":
        modules = Path(prepared_path) / "node_modules"
        esbuild_native = modules / "@esbuild/linux-x64/bin/esbuild"
        rollup_native = modules / "@rollup/rollup-linux-x64-gnu/rollup.linux-x64-gnu.node"
        _require(esbuild_native.is_file() and not esbuild_native.is_symlink()
                 and bool(esbuild_native.stat().st_mode & 0o111), "linux-esbuild-native-package-missing")
        _require(rollup_native.is_file() and not rollup_native.is_symlink()
                 and bool(rollup_native.stat().st_mode & 0o444), "linux-rollup-native-package-missing")


def _validate_linux_native_lock(lock):
    packages = lock.get("packages") if type(lock) is dict else None
    for package_path in (
            "node_modules/@esbuild/linux-x64",
            "node_modules/@rollup/rollup-linux-x64-gnu"):
        entry = packages.get(package_path) if type(packages) is dict else None
        _require(type(entry) is dict and entry.get("optional") is True
                 and entry.get("os") == ["linux"] and entry.get("cpu") == ["x64"],
                 "linux-native-lock-entry-missing")
    return True


def late_scenarios():
    """Scenarios that resolve packages from the public registries on the hosted runner."""
    result = []
    canary_lock = _generated_npm_lock(_install_script_canary_manifest())
    _require(bool(canary_lock["packages"]["node_modules/" + INSTALL_SCRIPT_PACKAGE].get("hasInstallScript")),
             "install-script-canary-lacks-marker")
    _validate_linux_native_lock(canary_lock)
    projection, payload = _node_projection(canary_lock)
    result.append({
        "name": "install-script-canary", "profile": "core-node", "projection": projection, "payload": payload,
        "files": lambda **kw: _node_source(canary_lock, **kw),
        "allowed_files": {"packages/kernel-ui-kit/src/example.ts": "file_0001"},
        "allowed_tests": {"synthetic canary suite accepted test": "case_0001"}, "frames": {},
        "variants": ("accept",), "after_prepare": _install_script_canary_check,
    })
    browser_lock = _generated_npm_lock(_browser_manifest())
    projection, payload = _node_projection(browser_lock, playwright=("chromium",))
    result.append({
        "name": "real-browser", "profile": "core-node", "projection": projection, "payload": payload,
        "files": lambda **kw: _browser_source(browser_lock),
        "allowed_files": {"packages/kernel-ui-kit/src/example.ts": "file_0001"},
        "allowed_tests": {"browser lane unit placeholder": "case_0001"},
        "frames": {"browser frame accepted": "frame_0001"}, "variants": ("accept",),
    })
    return result


"""---------------------------------------------------------------- production path"""

def _tool_paths(profile):
    paths = _phase_call("tool-path-discovery", lambda: {
        name: shutil.which(name) or "" for name in ("cargo", "rustc")
    })
    if profile == "core-rust":
        rustup = _phase_call("rust-tool-path-resolution", shutil.which, "rustup")
        _require(bool(rustup), "rustup-unavailable")
        for name in ("cargo", "rustc"):
            result = _phase_call("rust-tool-path-resolution", _run,
                                 [rustup, "which", "--toolchain", RUST_VERSION, name], timeout=15)
            paths[name] = result.stdout.decode("ascii", "strict").strip()
    return paths


def _prepare(profile, projection_path, prepared_path):
    try:
        paths = _tool_paths(profile)
    except Exception as error:
        category = _EXCEPTION_CATEGORIES.get(type(error), "unclassified")
        category = "prepare-" + category if category in diagnostic_contract.PREPARATION_EXCEPTION_LABELS else "preparation-exception-unlisted"
        raise PreparationRefusalMismatch("prepare-toolchain-selection", category) from None
    command = [
        "sudo", "-n", "unshare", "--mount", "--pid", "--ipc", "--fork", "--mount-proc", "--kill-child", "--",
        sys.executable, "-B", str(ROOT / "kit/devlane/prepare.py"),
        "--projection", str(projection_path), "--output", str(prepared_path), "--profile", profile,
        "--control-sha", CONTROL_SHA,
        "--owner-uid", str(os.getuid()), "--owner-gid", str(os.getgid()),
        "--deadline-file", DEADLINE_FILE,
    ]
    snapshot_id = ""
    if profile == "core-node":
        if RUN_ID.isdecimal() and RUN_ATTEMPT.isdecimal() and RUN_ATTEMPT != "0":
            snapshot_id = "devlane-" + RUN_ID + "-" + RUN_ATTEMPT
        else:
            snapshot_id = "test-" + hashlib.sha256(
                (str(Path(prepared_path).absolute()) + str(os.getpid())).encode("utf-8")
            ).hexdigest()[:24]
        command.extend(("--node-snapshot-id", snapshot_id))
    for name in ("cargo", "rustc"):
        path = paths[name]
        command.extend(("--" + name + "-path", path))
    try:
        _run_preparation(command)
        if not prepared_path.is_dir() or prepared_path.is_symlink():
            raise PreparationRefusalMismatch("prepare-prepared-output-copy", "prepared-tree-missing")
    except Exception as error:
        if snapshot_id:
            try:
                host_cleanup.clean_node_snapshot(snapshot_id, DEADLINE_FILE)
            except Exception:
                DIAGNOSTICS.cleanup_state = "unconfirmed"
                if type(error) is PreparationRefusalMismatch:
                    error.cleanup_state = "unconfirmed"
                print("node_snapshot_cleanup=unconfirmed", file=sys.stderr)
        raise
    if snapshot_id:
        paths["node_snapshot_id"] = snapshot_id
    return paths


def _summary_records(summary, scenario):
    profile_root = bundle.strict_json((ROOT / "ci/devlane-profiles.json").read_bytes())
    profile = profile_root["profiles"][scenario["profile"]]
    matrix = profile.get("rust_matrix", {})
    suites = sorted(matrix.get("coverage_ids", []))
    _require(scenario["profile"] != "core-rust" or matrix == rust_matrix_runner.EXPECTED_MATRIX,
             "rust-matrix-summary-profile")
    files = sorted(set(scenario["allowed_files"].values()))
    tests = sorted(set(scenario["allowed_tests"].values()))
    frames = sorted(set(scenario["frames"].values()))
    stages = list(profile["stages"]) + (["browser"] if frames else [])
    allowlists = {
        "files": {identifier: identifier for identifier in files},
        "tests": {identifier: identifier for identifier in tests},
        "frames": {identifier: identifier for identifier in frames},
        "stages": stages,
        "codes": sorted(set(profile.get("diagnostic_codes", []) + ["DEVLANE_FAILURE"])),
        "max_lines": {identifier: 10_000_000 for identifier in files},
        "suites": suites,
    }
    output_filter.validate_public_summary(summary, allowlists, frames)
    records = [bundle.strict_json(line, output_filter.MAX_RECORD_BYTES)
               for line in summary.splitlines()]
    if scenario["profile"] == "core-rust":
        expected_semver_refusal = scenario.get("expect_semver_execution_refusal") is True
        expected = set(rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"])
        coverage = [record for record in records if record.get("kind") == "coverage"]
        seen = [record.get("suite") for record in coverage]
        _require(len(seen) == len(expected) and len(seen) == len(set(seen)) and set(seen) == expected,
                 "rust-matrix-summary-coverage-set")
        controls = [record for record in records if record.get("kind") == "control"]
        if expected_semver_refusal:
            _require(controls == [{
                "kind": "control", "stage": "semver", "status": "fail",
                "code": "DEVLANE_SEMVER_EXECUTION",
            }], "rust-matrix-v1-semver-refusal")
            _require(not any(record.get("kind") == "test"
                             or (record.get("kind") == "frame" and record.get("status") != "pass")
                             or (record.get("kind") == "diagnostic" and record.get("level") == "error")
                             for record in records), "rust-matrix-v1-semver-refusal")
        else:
            _require(not any(record.get("kind") == "test"
                             or (record.get("kind") == "frame" and record.get("status") != "pass")
                             or (record.get("kind") == "control" and record.get("status") != "pass")
                             or (record.get("kind") == "diagnostic" and record.get("level") == "error")
                             for record in records), "rust-matrix-summary-not-all-pass")
        for row in coverage:
            counts = [row.get(name) for name in ("total", "passed", "failed", "ignored")]
            _require(all(type(value) is int and value >= 0 for value in counts)
                     and counts[0] > 0 and counts[1] + counts[2] + counts[3] == counts[0]
                     and counts[3] == 0
                     and ((expected_semver_refusal and row.get("suite") == "semver-runtime"
                           and counts == [1, 0, 1, 0])
                          or (row.get("suite") != "semver-runtime" and counts[2] == 0)
                          or (not expected_semver_refusal and counts[2] == 0)),
                     "rust-matrix-summary-counts")
    return records


def _remove_owned_prepared_tree(path):
    """Restore directory write permission only through owned, no-follow descriptors."""
    owned_tree_cleanup.remove_owned_tree(path, RUNNER_TEMP, prefix="prepared-cleanup-")


def _positive_control(path):
    value = network_probe.positive_control(timeout=_bounded_timeout(5))
    _require(value == {"connected": True, "target": "public-tls-control"}, "positive-control-failed")
    path.write_bytes(bundle.canonical_json(value) + b"\n")


def _supervisor(*arguments):
    return [sys.executable, "-B", str(ROOT / "kit/devlane/supervisor.py"), *arguments]


def _assert_supervisor_result(result, expected_returncode, expected_stdout, expected_stderr):
    stdout = result.stdout if type(result.stdout) is bytes else b""
    stderr = result.stderr if type(result.stderr) is bytes else b""
    if _contains_output_canary(stdout + stderr):
        raise StartupRefusalMismatch("startup-output-canary")
    if b"ModuleNotFoundError:" in stderr or b"ImportError:" in stderr:
        raise StartupRefusalMismatch("startup-import-failure")
    if b"Traceback (most recent call last):" in stderr:
        raise StartupRefusalMismatch("startup-traceback")
    if (type(result.stdout) is not bytes or type(result.stderr) is not bytes
            or type(result.returncode) is not int):
        raise StartupRefusalMismatch("startup-stderr-invalid")
    if not expected_stdout and stdout:
        raise StartupRefusalMismatch("startup-stdout-unexpected")
    if result.returncode != expected_returncode and stdout and stdout != expected_stdout:
        raise StartupRefusalMismatch("startup-stdout-unexpected")
    if (result.returncode == expected_returncode and stdout == expected_stdout
            and stderr == expected_stderr):
        return

    if result.returncode == 2 and not stdout:
        if stderr.startswith(b"usage: ") or b"error: the following arguments are required" in stderr:
            raise StartupRefusalMismatch("startup-parser-refusal")
        refusal = re.fullmatch(
            rb"devlane_supervisor_refusal=([a-z][a-z0-9-]{0,63}(?::[a-z0-9-]{1,48}){0,2})"
            rb"(?: (route\[[^\n]{1,320}\]))?\n",
            stderr,
        )
        if refusal is not None:
            code = refusal.group(1).decode("ascii")
            route_detail = refusal.group(2)
            if route_detail is not None:
                detail = route_detail.decode("ascii", "strict")
                if (code != "network-probe-refusal:network-route-unexpected"
                        or not network_probe.valid_route_diagnostic(detail)):
                    raise StartupRefusalMismatch("startup-refusal-unlisted")
                code += " " + detail
                raise StartupRefusalMismatch(code)
            raise StartupRefusalMismatch(code if code in SUPERVISOR_REFUSAL_CODES else "startup-refusal-unlisted")
        if not stderr:
            raise StartupRefusalMismatch("startup-stderr-empty")
        if b"usage:" in stderr or b"error:" in stderr:
            raise StartupRefusalMismatch("startup-parser-refusal")
        raise StartupRefusalMismatch("startup-stderr-invalid")

    if result.returncode != expected_returncode:
        if result.returncode == 0:
            category = "startup-unexpected-success"
        elif result.returncode == 1:
            category = "startup-exit-one"
        elif result.returncode < 0:
            category = "startup-exit-signal"
        else:
            category = "startup-exit-unexpected"
        raise StartupRefusalMismatch(category)
    if stdout != expected_stdout:
        if expected_stdout and not stdout:
            raise StartupRefusalMismatch("startup-success-output-missing")
        if expected_stdout:
            raise StartupRefusalMismatch("startup-success-output-invalid")
        raise StartupRefusalMismatch("startup-stdout-unexpected")
    if result.returncode == 0 and stderr:
        raise StartupRefusalMismatch("startup-success-stderr")
    raise StartupRefusalMismatch("startup-stderr-invalid")


def _assert_startup_projection_refusal(result):
    return _assert_supervisor_result(
        result, 2, b"", b"devlane_supervisor_refusal=projection-binding-mismatch\n",
    )


def _assert_supervisor_start_ready(result):
    return _assert_supervisor_result(result, 0, b"offline_supervisor=ready\n", b"")


def _assert_supervisor_probe_pass(result):
    return _assert_supervisor_result(result, 0, b"network_cut_probe=pass\n", b"")


def _assert_supervisor_decrypt_pass(result):
    return _assert_supervisor_result(result, 0, b"authenticated_decryption=pass\n", b"")


def _assert_supervisor_refusal(result, code):
    if code not in SUPERVISOR_REFUSAL_CODES:
        raise RuntimeError("startup-refusal-code-invalid")
    return _assert_supervisor_result(result, 2, b"", ("devlane_supervisor_refusal=" + code + "\n").encode("ascii"))


class _SupervisorLifecycle:
    """Prepared data stays immutable until this run's supervisor is absent."""

    def __init__(self, root):
        self.root = root
        self.start_attempted = False
        self.cleanup_confirmed = False

    def begin_variant(self, root):
        self.root = root
        self.start_attempted = False
        self.cleanup_confirmed = False

    def note_start_attempt(self):
        self.start_attempted = True
        self.cleanup_confirmed = False

    def confirm_teardown(self):
        _require(not self.root.exists() and not self.root.is_symlink(), "host-cleanup-root-remains")
        _require(not _processes_matching("supervisor.py"), "supervisor-survived-cleanup")
        _require(not _processes_matching(BACKGROUND_MARKER), "background-process-survived-cleanup")
        self.cleanup_confirmed = True

    def permits_prepared_cleanup(self):
        if self.start_attempted and not self.cleanup_confirmed:
            return False
        try:
            return (not self.root.exists() and not self.root.is_symlink()
                    and not _processes_matching("supervisor.py")
                    and not _processes_matching(BACKGROUND_MARKER))
        except Exception:
            return False


def _run_variant(scenario, projection_bytes, prepared_path, tool_paths, key_bytes, variant, lifecycle):
    with DIAGNOSTICS.phase("variant-root-setup"):
        profile = scenario["profile"]
        root = RUNNER_TEMP / ("devlane-" + RUN_ID)
        lifecycle.begin_variant(root)
        _require(not root.exists() and not root.is_symlink(), "runner-root-already-exists")
        root.mkdir(mode=0o700)
    diagnostic_kind = "vitest" if profile == "core-node" else "rust-matrix"
    diagnostic_name = "devlane-%s-%s-%s-%s.json" % (
        diagnostic_kind,
        RUN_ID or "local", scenario["name"], variant,
    )
    diagnostic_path = RUNNER_TEMP / diagnostic_name
    try:
        projection_path = root / "projection.json"
        _phase_call("variant-projection-write", projection_path.write_bytes, projection_bytes)
        expires = int(time.time()) + 3600
        label = scenario["name"].replace("-", "")
        wave_id = "e2e-wave-" + label
        bundle_id = "e2e-bundle-" + label + variant.replace("-", "")
        projection_sha = hashlib.sha256(projection_bytes).hexdigest()
        files = _phase_call("variant-source-build", scenario["files"], **(
            {"failing_test": True} if variant == "failing-test" else
            {"hang": True} if variant == "cancel" else {}
        ))
        archive = _phase_call(
            "variant-archive-build", _archive, files, profile, projection_sha, scenario["allowed_files"],
            scenario["allowed_tests"], scenario["frames"],
            original_lockfiles=scenario.get("original_lockfiles"),
        )
        if profile == "core-rust":
            with DIAGNOSTICS.phase("variant-rust-archive-verify"):
                rust_manifest, rust_files, _ = bundle.inspect_archive(archive, {
                    "profile": "core-rust", "fetch_sha256": projection_sha,
                })
                _require(set(rust_manifest["original_lockfiles"]) == set(RUST_LOCKFILES),
                         "rust-matrix-envelope-lock-set")
                _require(all(rust_files[path] == files[path] for path in RUST_LOCKFILES),
                         "rust-matrix-envelope-lock-binding")
        with DIAGNOSTICS.phase("variant-envelope-build"):
            bindings = {
                "format": "kd-public-devlane-aesgcm-v1", "repository_id": fetch.REPOSITORY_ID,
                "control_sha": CONTROL_SHA, "workflow_path": fetch.WORKFLOW_PATH, "profile": profile,
                "wave_id": wave_id, "bundle_id": bundle_id, "fetch_sha256": projection_sha, "expires": expires,
            }
            envelope = bundle.build_envelope(archive, key_bytes, bindings)
        bundle_path = root / "bundle.enc"
        _phase_call("variant-envelope-build", bundle_path.write_bytes, envelope)
        with DIAGNOSTICS.phase("variant-context-build"):
            context = {
                "repository": fetch.REPOSITORY, "repository_id": fetch.REPOSITORY_ID,
                "server_url": "https://github.com", "event": "workflow_dispatch", "ref": "refs/heads/main",
                "control_sha": CONTROL_SHA, "control_run_id": CONTROL_RUN_ID,
                "workflow_path": fetch.WORKFLOW_PATH, "run_attempt": 1, "profile": profile,
                "wave_id": wave_id, "bundle_id": bundle_id, "bundle_asset_id": "123456",
                "bundle_sha256": hashlib.sha256(envelope).hexdigest(), "bundle_size": len(envelope),
                "projection_asset_id": "123457", "projection_sha256": projection_sha,
                "projection_size": len(projection_bytes), "expires": expires,
                "wave_class": fetch.SOURCE_FREE_WAVE_CLASS,
            }
        _phase_call("variant-context-validate", fetch.validate_dispatch, context)
        context_path = root / "context.json"
        _phase_call("variant-context-write", context_path.write_bytes,
                    bundle.canonical_json(context) + b"\n")
        positive_path = root / "positive-control.json"
        _phase_call("variant-positive-control", _positive_control, positive_path)
        state_path = root / "state"
        if variant == "startup-refusal":
            """A tampered projection must be rejected before namespace or mount setup."""
            _phase_call("variant-startup-tamper", projection_path.write_bytes, projection_bytes + b" ")
        with DIAGNOSTICS.phase("variant-supervisor-start"):
            start = _supervisor("start", "--state-dir", str(state_path), "--context", str(context_path),
                                "--workspace", str(ROOT), "--prepared", str(prepared_path),
                                "--bundle", str(bundle_path), "--projection", str(projection_path),
                                "--positive-control", str(positive_path), "--deadline-file", DEADLINE_FILE)
            start.extend(("--node-snapshot-id", tool_paths.get("node_snapshot_id", "")))
            start.extend(("--failure-diagnostics-file", str(diagnostic_path)))
            for name in ("cargo", "rustc"):
                start.extend(("--" + name + "-path", tool_paths[name]))
            lifecycle.note_start_attempt()
        if variant == "startup-refusal":
            refused = _phase_call(
                "variant-startup-command", _process_run, start, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, close_fds=True, check=False,
            )
            _phase_call("variant-startup-refusal-check", _assert_startup_projection_refusal, refused)
            _phase_call("variant-host-cleanup", host_cleanup.clean, str(root), str(RUNNER_TEMP),
                        deadline_file=DEADLINE_FILE)
            _phase_call("variant-teardown-confirm", lifecycle.confirm_teardown)
            return
        start_result = _phase_call(
            "variant-supervisor-start-command", _process_run, start, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, close_fds=True, check=False,
        )
        _phase_call("variant-supervisor-start-check", _assert_supervisor_start_ready, start_result)
        probe = _phase_call("variant-supervisor-probe-command", _supervisor,
                            "probe", "--state-dir", str(state_path))
        probe_result = _phase_call(
            "variant-supervisor-probe-command", _process_run, probe, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, close_fds=True, check=False,
        )
        _phase_call("variant-supervisor-probe-check", _assert_supervisor_probe_pass, probe_result)

        key_path = root / "synthetic-key.hex"
        _phase_call("variant-key-create", bundle.write_private_key, key_path, key_bytes)
        supplied_key = _phase_call("variant-key-create", bundle.read_key_file, key_path).hex()
        if variant == "wrong-key":
            supplied_key = bytes(reversed(key_bytes)).hex()
        decrypt_env = os.environ.copy()
        decrypt_env["DEVLANE_DECRYPT_KEY"] = supplied_key
        try:
            decrypt = _phase_call("variant-decrypt", _supervisor, "decrypt", "--state-dir", str(state_path))
            decrypt_result = _phase_call(
                "variant-decrypt", _process_run, decrypt, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=decrypt_env,
                timeout=180, close_fds=True, check=False,
            )
            if variant == "wrong-key":
                _phase_call("variant-decrypt-check", _assert_supervisor_refusal,
                            decrypt_result, "decrypt-rejected")
            else:
                _phase_call("variant-decrypt-check", _assert_supervisor_decrypt_pass, decrypt_result)
        finally:
            decrypt_error = sys.exc_info()[1]
            decrypt_env.pop("DEVLANE_DECRYPT_KEY", None)
            supplied_key = ""
            try:
                _phase_call("variant-key-cleanup", key_path.unlink, missing_ok=True)
            except OSError:
                if decrypt_error is None:
                    raise
                print("key_cleanup=unconfirmed", file=sys.stderr)
        execute = _phase_call("variant-execute", _supervisor, "execute", "--state-dir", str(state_path),
                              "--context", str(context_path))
        with DIAGNOSTICS.phase("variant-execute"):
            if variant == "wrong-key":
                """A refused decryption must leave execution refused: exit 2 and no summary at all."""
                refused = _run(
                    execute, expected=2, diagnostic_callsite="supervisor-client:execute",
                    on_result=lambda completed: _emit_synthetic_failure_diagnostics(
                        diagnostic_path, completed.stdout, profile,
                        execution_failed=(completed.returncode != 0)),
                )
                _require(refused.stdout == b"", "summary-after-decrypt-refusal")
            elif variant == "cancel":
                wait_budget = _bounded_timeout(180)
                process = subprocess.Popen(execute, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
                wait_until = time.monotonic() + wait_budget
                while (time.monotonic() < wait_until and process.poll() is None
                       and not _processes_matching(BACKGROUND_MARKER)):
                    time.sleep(min(1, wait_until - time.monotonic()))
                _require(process.poll() is None and bool(_processes_matching(BACKGROUND_MARKER)),
                         "cancel-target-did-not-start")
                _phase_call("variant-host-cleanup", host_cleanup.clean, str(root), str(RUNNER_TEMP),
                            deadline_file=DEADLINE_FILE)
                try:
                    output, errors = process.communicate(timeout=_bounded_timeout(180))
                except subprocess.TimeoutExpired:
                    process.kill()
                    raise RuntimeError("cancelled-execute-did-not-end") from None
                _require(process.returncode != 0, "cancelled-execute-reported-success")
                _scan_output(output + errors, "canary-after-cancel")
                _report_command_failure(
                    "supervisor-client:execute",
                    subprocess.CompletedProcess(execute, process.returncode, output, errors),
                )
                _emit_synthetic_failure_diagnostics(
                    diagnostic_path, output, profile, execution_failed=True,
                )
            else:
                expected = _expected_execute_status(scenario, variant)
                result = _run(execute, timeout=60 * 40, expected=expected,
                              diagnostic_callsite="supervisor-client:execute",
                              on_result=lambda completed: _emit_synthetic_failure_diagnostics(
                                  diagnostic_path, completed.stdout, profile,
                                  execution_failed=(completed.returncode != 0)))
                with DIAGNOSTICS.phase("variant-summary-validate"):
                    _require(_summary_has_valid_terminator(result.stdout), "summary-schema-invalid")
                    records = _summary_records(result.stdout, scenario)
                    if scenario.get("expect_semver_execution_refusal") is True and variant == "accept":
                        _require(any(record.get("kind") == "coverage"
                                     and record.get("suite") == "semver-runtime"
                                     and record.get("failed") == 1 for record in records),
                                 "rust-matrix-v1-semver-refusal")
                        _require(all(record.get("passed") == record.get("total")
                                     and record.get("failed") == 0
                                     and record.get("ignored") == 0
                                     for record in records if record.get("kind") == "coverage"
                                     and record.get("suite") != "semver-runtime"),
                                 "rust-matrix-v1-non-semver-failure")
                    summary = result.stdout.splitlines()
                    _require(len(summary) <= 100 and len(result.stdout) <= 16 * 1024, "summary-limits")
                    if variant in ("failing-test", "accept-with-failure"):
                        wanted = "case_0001" if variant == "failing-test" else "case_0002"
                        _require(any(record.get("kind") == "test" and record.get("test") == wanted
                                     for record in records), "test-failure-not-mapped")
                    if scenario["name"] == "real-node" and variant == "accept-with-failure":
                        expected_records = [
                            {"code": "DEVLANE_FAILURE", "kind": "control", "stage": "unit",
                             "status": "fail", "subreason": "vitest-failed"},
                            {"kind": "test", "stage": "unit", "test": "case_0002"},
                        ]
                        _require(records == expected_records, "vitest-negative-control-summary")
                        _require(not _contains_output_canary(result.stdout), "canary-in-summary")
                    if scenario["frames"]:
                        _require(any(b'"frame":"frame_0001"' in line and b'"status":"pass"' in line
                                     for line in summary), "browser-frame-not-reported")
                    if variant == "accept" and scenario["name"] == "synthetic-node":
                        _require(not any(b'"kind":"control"' in line for line in summary),
                                 "unexpected-control-failure")
        os.environ.setdefault("GITHUB_RUN_ID", RUN_ID)
        _phase_call("variant-host-cleanup", host_cleanup.clean, str(root), str(RUNNER_TEMP),
                    deadline_file=DEADLINE_FILE)
        """Descendants that outlived their parent must not outlive cleanup."""
        _phase_call("variant-teardown-confirm", lifecycle.confirm_teardown)
    finally:
        previous_error = sys.exc_info()[1]
        cleanup_error = None
        try:
            diagnostic_path.unlink(missing_ok=True)
        except OSError as error:
            cleanup_error = error
        try:
            _phase_call("variant-key-cleanup", (root / "synthetic-key.hex").unlink, missing_ok=True)
        except OSError as error:
            cleanup_error = error
        try:
            with DIAGNOSTICS.phase("variant-host-cleanup-finally"):
                if root.exists() or root.is_symlink():
                    if not root.is_symlink():
                        os.environ.setdefault("GITHUB_RUN_ID", RUN_ID)
                        host_cleanup.clean(str(root), str(RUNNER_TEMP), deadline_file=DEADLINE_FILE)
            _phase_call("variant-teardown-confirm-finally", lifecycle.confirm_teardown)
        except Exception as error:
            cleanup_error = cleanup_error or error
        if cleanup_error is not None:
            lifecycle.cleanup_confirmed = False
            if previous_error is None:
                raise cleanup_error
            print("host_cleanup=unconfirmed", file=sys.stderr)


def _run_scenario(scenario, rust_tool_cache=None):
    _progress("scenario=" + scenario["name"])
    prepared = RUNNER_TEMP / ("devlane-e2e-" + RUN_ID + "-" + scenario["name"])
    projection_path = RUNNER_TEMP / ("devlane-e2e-projection-" + RUN_ID + "-" + scenario["name"])
    lifecycle = _SupervisorLifecycle(RUNNER_TEMP / ("devlane-" + RUN_ID))
    tool_paths = {}
    try:
        _phase_call("scenario-projection-write", projection_path.write_bytes, scenario["payload"])
        tool_paths = _phase_call("scenario-dependency-prepare", _prepare,
                                 scenario["profile"], projection_path, prepared)
        if scenario["profile"] == "core-rust":
            _require(rust_tool_cache is not None, "rust-matrix-tool-preparation-missing")
            _phase_call("scenario-tool-install", rust_tooling.install,
                        str(rust_tool_cache), str(prepared), deadline_file=DEADLINE_FILE)
            _phase_call("scenario-tool-verify", _verify_prepared_rust_tools, prepared, rust_tool_cache)
        if "after_prepare" in scenario:
            _phase_call("scenario-after-prepare-hook", scenario["after_prepare"], prepared)
        key_bytes = KEY_CANARY + bytes(range(16))
        for variant in scenario["variants"]:
            _phase_call("scenario-variant-run", _run_variant, scenario, scenario["payload"],
                        prepared, tool_paths, key_bytes, variant, lifecycle)
    finally:
        previous_error = sys.exc_info()[1]
        cleanup_unconfirmed = False
        try:
            try:
                with DIAGNOSTICS.phase("scenario-prepared-tree-cleanup"):
                    if prepared.exists() or prepared.is_symlink():
                        _require(lifecycle.permits_prepared_cleanup(), "prepared-cleanup-supervisor-unconfirmed")
                        _remove_owned_prepared_tree(prepared)
                    _require(not prepared.exists() and not prepared.is_symlink(), "prepared-cleanup-tree-remains")
            except Exception:
                cleanup_unconfirmed = True
            if prepared.exists() or prepared.is_symlink():
                cleanup_unconfirmed = True
        finally:
            snapshot_id = tool_paths.get("node_snapshot_id", "")
            if snapshot_id:
                try:
                    with DIAGNOSTICS.phase("scenario-node-snapshot-cleanup"):
                        _require(lifecycle.permits_prepared_cleanup(), "node-snapshot-supervisor-unconfirmed")
                        host_cleanup.clean_node_snapshot(snapshot_id, DEADLINE_FILE)
                except Exception:
                    cleanup_unconfirmed = True
            try:
                with DIAGNOSTICS.phase("scenario-projection-cleanup"):
                    projection_path.unlink(missing_ok=True)
                    if projection_path.exists() or projection_path.is_symlink():
                        raise RuntimeError("projection-cleanup-remains")
            except Exception:
                cleanup_unconfirmed = True
        if cleanup_unconfirmed:
            DIAGNOSTICS.cleanup_state = "unconfirmed"
            if previous_error is None:
                raise RuntimeError("scenario-cleanup-unconfirmed")
            print("scenario_cleanup=unconfirmed", file=sys.stderr)


def _deadline_termination(signum, _frame):
    raise RuntimeError("harness-work-deadline")


def main(argv=None):
    global PROGRESS_ENABLED
    PROGRESS_ENABLED = False
    DIAGNOSTICS.reset()
    with DIAGNOSTICS.phase("argument-parse"):
        parser = __import__("argparse").ArgumentParser()
        parser.add_argument("--generate-rust-fixture", default="")
        parser.add_argument("--rust-fixture", default="")
        parser.add_argument("--deadline-file", required=True)
        parser.add_argument("--diagnostic-file", default="")
        parser.add_argument("--report-diagnostic-file", default="")
        args = parser.parse_args(argv)
    if args.report_diagnostic_file:
        try:
            with DIAGNOSTICS.phase("production-e2e-diagnostic-file"):
                line = _read_reportable_diagnostic_file(args.report_diagnostic_file)
        except Exception:
            line = None
        if line is None:
            print("devlane_acceptance=refused stage=production-path-e2e")
        else:
            print(line)
        return 0
    if argv is None and not args.generate_rust_fixture:
        PROGRESS_ENABLED = True
        _progress("phase=argument-parse")
    global DEADLINE_FILE
    global DIAGNOSTIC_FILE
    DEADLINE_FILE = args.deadline_file
    DIAGNOSTIC_FILE = args.diagnostic_file
    _phase_call("deadline-validate", deadline_budget.remaining, DEADLINE_FILE)
    if args.generate_rust_fixture:
        with DIAGNOSTICS.phase("fixture-toolchain-discovery"):
            _require(bool(DEADLINE_FILE), "deadline-file-required")
            paths = _tool_paths("core-rust")
        _phase_call("fixture-toolchain-verify", _verify_rust_toolchain, paths)
        _phase_call("fixture-generation", _write_rust_fixture, args.generate_rust_fixture, paths["cargo"])
        return 0
    with DIAGNOSTICS.phase("runner-preflight"):
        _require(sys.platform.startswith("linux") and os.geteuid() != 0, "linux-runner-user-required")
        _require(bool(DEADLINE_FILE), "deadline-file-required")
        signal.signal(signal.SIGTERM, _deadline_termination)
        _require(bool(RUN_ID and RUN_ID.isdecimal() and CONTROL_SHA and len(CONTROL_SHA) == 40),
                 "workflow-identity-required")
        _require(shutil.which("sudo") and shutil.which("unshare") and shutil.which("pgrep"),
                 "linux-tools-required")
        fixture_root = args.rust_fixture or os.environ.get("DEVLANE_RUST_FIXTURE", "")
        _require(bool(fixture_root), "rust-fixture-path-required")
    projection, projection_bytes, snapshot, rust_files = _phase_call(
        "fixture-load", _load_rust_fixture, fixture_root,
    )
    with DIAGNOSTICS.phase("tooling-root-create"):
        tooling_root = RUNNER_TEMP / ("devlane-rust-tools-" + RUN_ID)
        rust_scenario = {
            "name": "synthetic-rust-v1-refusal", "profile": "core-rust", "projection": projection,
            "payload": projection_bytes, "files": lambda **kw: rust_files,
            "allowed_files": {}, "allowed_tests": RUST_FIXTURE_TESTS, "frames": {},
            "expect_semver_execution_refusal": True,
            "original_lockfiles": {path: value["sha256"] for path, value in snapshot["lockfiles"].items()},
            "variants": ("accept", "wrong-key"),
        }
    done = []
    try:
        _phase_call("tooling-root-fetch", rust_tooling.fetch_tools, str(tooling_root),
                    deadline_file=DEADLINE_FILE, phase_context=DIAGNOSTICS.phase)
        scenario_list = _phase_call("scenario-construction", scenarios)
        for scenario in scenario_list:
            _phase_call("scenario-run", _run_scenario, scenario)
            done.append(scenario["name"])
        _phase_call("scenario-run", _run_scenario, rust_scenario, tooling_root)
        done.append(rust_scenario["name"])
        late_scenario_list = _phase_call("late-scenario-construction", late_scenarios)
        for scenario in late_scenario_list:
            _phase_call("late-scenario-run", _run_scenario, scenario)
            done.append(scenario["name"])
    finally:
        previous_error = sys.exc_info()[1]
        try:
            with DIAGNOSTICS.phase("tooling-root-cleanup"):
                if tooling_root.exists() and not tooling_root.is_symlink():
                    shutil.rmtree(tooling_root)
                _require(not tooling_root.exists() and not tooling_root.is_symlink(), "rust-tool-cleanup-remains")
        except Exception:
            if previous_error is None:
                raise
    print("devlane_production_e2e=pass scenarios=" + ",".join(done))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        line = DIAGNOSTICS.refusal_line(error)
        _write_diagnostic_file(DIAGNOSTIC_FILE, line)
        print(line, file=sys.stderr)
        raise SystemExit(1)
