import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from collections.abc import Mapping


SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
TOKEN_READER_RE = re.compile(r"[!-~]{1,4096}\Z")
READER_REASONS = frozenset((
    "token_unavailable", "arguments_invalid", "token_invalid", "configuration_invalid",
    "repository_list_unavailable", "repository_scope_invalid", "metadata_unavailable",
    "ok", "revocation_unconfirmed", "internal_error",
))
READER_FIELDS = frozenset((
    "schema_version", "status", "reason", "repository_scope", "metadata", "revocation",
))
READER_FAILURE = {
    "schema_version": 1,
    "status": "refused",
    "reason": "internal_error",
    "repository_scope": "unverified",
    "metadata": "unverified",
    "revocation": "unconfirmed",
}
TOKEN_REFUSAL_STATES = frozenset(("not-read", "confirmed", "unconfirmed"))
TAG_RE = re.compile(r"v[0-9]+(?:\.[0-9]+){0,3}(?:[-+][A-Za-z0-9.-]+)?\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_.+@/-]{1,256}\Z")
SETTING_RE = re.compile(r"[A-Za-z][A-Za-z0-9.]{0,127}\Z")
FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
PHASES = frozenset(("preflight", "bootstrap"))
REASONS = frozenset((
    "invalid_input", "bootstrap_gate_refused", "context_unavailable", "control_import_unavailable",
    "revocation_policy_invalid", "runner_controls_unavailable", "probe_identity_unavailable",
    "summary_write_allowed", "summary_changed", "lock_invalid", "manifest_mismatch",
    "source_lease_unavailable", "configuration_unavailable", "source_reader_unavailable",
    "repository_scope_invalid", "source_fetch_unavailable", "revocation_unconfirmed",
    "base_invalid", "signature_invalid", "bootstrap_snapshot_invalid", "bootstrap_not_approved",
    "cleanup_incomplete", "internal_error",
))
SOURCE_VALIDATION_REASONS = frozenset((
    "invalid_input", "context_unavailable", "configuration_unavailable", "source_reader_unavailable",
    "repository_scope_invalid", "source_fetch_unavailable", "revocation_unconfirmed", "base_invalid",
    "signature_invalid", "revocation_policy_invalid", "bootstrap_snapshot_invalid",
    "bootstrap_not_approved", "cleanup_incomplete", "internal_error",
))
STAGES = frozenset((
    "input", "gate", "context", "import", "inventory", "toolchain", "controls", "identity",
    "summary", "source_lease", "lock", "manifest", "cleanup",
))
SOURCE_DIAGNOSTIC_OPERATIONS = frozenset((
    "git_init", "remote_add", "base_fetch", "base_ref", "candidate_fetch",
    "source_ref", "shallow_check", "remote_remove", "source_snapshot",
))
SOURCE_DIAGNOSTIC_CLASSES = frozenset((
    "exit_nonzero", "stderr_present", "process_failure", "unexpected_exception",
))
CORE_SOURCE_GATE_ENV = "CORE_BOOTSTRAP_ALLOWED_SHA"
CORE_CONTROL_GATE_ENV = "CORE_BOOTSTRAP_ALLOWED_CONTROL_SHA"
MAX_LOCK_BYTES = 262144
MAX_LOCK_LINES = 4096
MAX_LOCK_LINE_BYTES = 2048
MAX_MANIFEST_FILES = 1024
MAX_MANIFEST_FILE_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_TOTAL_BYTES = 32 * 1024 * 1024
RULES_DIRECTORY = chr(46) + "claude"
STANDIN_GUARD_MARKER = b"summary-standin=write-denied\n"
STANDIN_GUARD_SCRIPT = r'''
import errno, os, sys
try:
    descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_NOFOLLOW)
except OSError as error:
    if error.errno not in (errno.EACCES, errno.EPERM):
        raise SystemExit(81)
else:
    os.close(descriptor)
    raise SystemExit(82)
marker = b"summary-standin=write-denied\n"
if os.write(1, marker) != len(marker):
    raise SystemExit(83)
'''


class Refusal(Exception):
    def __init__(self, reason, stage, source_diagnostic=None):
        self.reason = reason if type(reason) is str and reason in REASONS else "internal_error"
        self.stage = stage if type(stage) is str and stage in STAGES else "input"
        self.source_diagnostic = None
        if (
            self.reason == "source_fetch_unavailable" and self.stage == "source_lease"
            and type(source_diagnostic) is tuple and len(source_diagnostic) == 2
            and type(source_diagnostic[0]) is str
            and source_diagnostic[0] in SOURCE_DIAGNOSTIC_OPERATIONS
            and type(source_diagnostic[1]) is str
            and source_diagnostic[1] in SOURCE_DIAGNOSTIC_CLASSES
        ):
            self.source_diagnostic = source_diagnostic
        super().__init__(self.reason)


def _valid_sha(value):
    return type(value) is str and SHA_RE.fullmatch(value) is not None


def _parse_arguments(arguments):
    if type(arguments) not in (tuple, list) or len(arguments) not in (4, 5):
        raise Refusal("invalid_input", "input")
    if (
        type(arguments[0]) is not str or arguments[0] != "--phase"
        or type(arguments[1]) is not str or arguments[1] not in PHASES
    ):
        raise Refusal("invalid_input", "input")
    if type(arguments[2]) is not str or arguments[2] != "--source-sha" or not _valid_sha(arguments[3]):
        raise Refusal("invalid_input", "input")
    token_stdin = len(arguments) == 5 and arguments[4] == "--token-stdin"
    if len(arguments) == 5 and (not token_stdin or arguments[1] != "bootstrap"):
        raise Refusal("invalid_input", "input")
    if arguments[1] == "bootstrap" and not token_stdin:
        raise Refusal("invalid_input", "input")
    return arguments[1], arguments[3], token_stdin


def _phase_hint(arguments):
    if (
        type(arguments) in (tuple, list) and len(arguments) >= 2
        and type(arguments[0]) is str and arguments[0] == "--phase"
        and type(arguments[1]) is str and arguments[1] in {"preflight", "bootstrap"}
    ):
        return arguments[1]
    return None


def _read_token_stdin(stream):
    try:
        payload = stream.read(4097)
        if (
            type(payload) is not bytes or TOKEN_READER_RE.fullmatch(payload.decode("ascii", "strict")) is None
        ):
            raise ValueError
        return payload.decode("ascii", "strict")
    except BaseException:
        raise Refusal("bootstrap_gate_refused", "gate") from None


def _check_gates(source_sha, environ):
    control_sha = environ.get("CI_SHA", "")
    if (
        not _valid_sha(control_sha)
        or environ.get(CORE_SOURCE_GATE_ENV) != source_sha
        or environ.get(CORE_CONTROL_GATE_ENV) != control_sha
    ):
        raise Refusal("bootstrap_gate_refused", "gate")
    return control_sha


def _revoke_pending_token(environ):
    try:
        token = environ.get("SOURCE_READER_TOKEN")
    except BaseException:
        return None
    if token is None:
        return None
    if type(token) is not str or TOKEN_READER_RE.fullmatch(token) is None:
        return False
    result = None
    try:
        reader = _load_control_sibling("macos_source_reader")
        run_reader = getattr(reader, "run", None)
        if callable(run_reader):
            result = run_reader(environ)
    except BaseException:
        result = None
    confirmed = (
        type(result) is dict
        and set(result) == {
            "schema_version", "status", "reason", "repository_scope", "metadata", "revocation",
        }
        and type(result.get("schema_version")) is int
        and result.get("schema_version") == 1
        and result.get("status") == "passed"
        and result.get("reason") == "ok"
        and result.get("repository_scope") == "verified"
        and result.get("metadata") == "verified"
        and result.get("revocation") == "confirmed"
    )
    if not confirmed:
        return False
    try:
        environ.pop("SOURCE_READER_TOKEN", None)
        return "SOURCE_READER_TOKEN" not in environ
    except BaseException:
        return False


def _cleanup_after_refusal(environ, token_read, token_value, token_confirmed):
    if token_confirmed:
        return None
    if token_read and type(token_value) is str:
        try:
            if "SOURCE_READER_TOKEN" not in environ:
                environ["SOURCE_READER_TOKEN"] = token_value
        except BaseException:
            return False
    return _revoke_pending_token(environ)


def _runtime_revocation_confirmed(runtime, state, token, repository_id, request, binding):
    if runtime is None or state is None or type(token) is not str:
        return False
    verifier = getattr(runtime, "revocation_confirmed", None)
    if not callable(verifier):
        return False
    try:
        result = verifier(state, token, repository_id, request, binding)
    except BaseException:
        return False
    return type(result) is bool and result


def _clean_reader_record(result):
    if (
        type(result) is not dict or set(result) != READER_FIELDS
        or type(result.get("schema_version")) is not int or result.get("schema_version") != 1
        or result.get("status") not in {"passed", "refused"}
        or result.get("reason") not in READER_REASONS
        or result.get("repository_scope") not in {"verified", "unverified"}
        or result.get("metadata") not in {"verified", "unverified"}
        or result.get("revocation") not in {"confirmed", "unconfirmed"}
    ):
        return dict(READER_FAILURE)
    record = dict(result)
    passed = (
        record["status"] == "passed" and record["reason"] == "ok"
        and record["repository_scope"] == "verified"
        and record["metadata"] == "verified" and record["revocation"] == "confirmed"
    )
    refused = record["status"] == "refused" and record["reason"] != "ok"
    return record if passed or refused else dict(READER_FAILURE)


def _run_revoke_cli(arguments, environ=None, token_reader=None):
    environment = os.environ if environ is None else environ
    if (
        type(arguments) not in (tuple, list) or len(arguments) != 3
        or type(arguments[0]) is not str or arguments[0] != "--phase"
        or type(arguments[1]) is not str or arguments[1] != "revoke"
        or type(arguments[2]) is not str or arguments[2] != "--token-stdin"
    ):
        record = dict(READER_FAILURE)
        record["reason"] = "arguments_invalid"
    else:
        try:
            token = _read_token_stdin(sys.stdin.buffer if token_reader is None else token_reader)
            environment["SOURCE_READER_TOKEN"] = token
        except BaseException:
            record = dict(READER_FAILURE)
            record["reason"] = "token_invalid"
        else:
            try:
                reader = _load_control_sibling("macos_source_reader")
                run_reader = getattr(reader, "run", None)
                result = run_reader(environment) if callable(run_reader) else None
                record = _clean_reader_record(result)
            except BaseException:
                record = dict(READER_FAILURE)
            if (
                record.get("status") == "passed"
                and record.get("reason") == "ok"
                and record.get("repository_scope") == "verified"
                and record.get("metadata") == "verified"
                and record.get("revocation") == "confirmed"
            ):
                try:
                    environment.pop("SOURCE_READER_TOKEN", None)
                except BaseException:
                    record = dict(READER_FAILURE)
    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return line, 0 if record.get("status") == "passed" else 1


def _load_control_sibling(name):
    if type(name) is not str or name not in {
        "macos_capability", "macos_reviewed_build", "macos_private_validation", "macos_source_reader",
    }:
        raise ImportError("control module unavailable")
    directory = Path(__file__).resolve(strict=True).parent
    candidate = directory / (name + ".py")
    info = candidate.lstat()
    path = candidate.resolve(strict=True)
    if path.parent != directory or stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ImportError("control module unavailable")
    loaded = sys.modules.get(name)
    if loaded is not None and type(getattr(loaded, "__file__", None)) is str:
        try:
            if Path(loaded.__file__).resolve(strict=True) == path:
                return loaded
        except OSError:
            pass
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError("control module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise ImportError("control module unavailable") from None
    return module


def _load_control():
    try:
        capability = _load_control_sibling("macos_capability")
        reviewed_build = _load_control_sibling("macos_reviewed_build")
        runtime = _load_control_sibling("macos_private_validation")
        if reviewed_build.capability is None or runtime.capability is None or runtime.reviewed_build is None:
            raise ImportError("control module unavailable")
        return capability, reviewed_build, runtime
    except BaseException:
        raise Refusal("control_import_unavailable", "import") from None


def _safe_context(control_sha, environ, reviewed_build, capability):
    try:
        binding = reviewed_build._binding(control_sha, environ)
        root = capability._check_context(control_sha, environ.get("CI_WORKSPACE", ""))
        return binding, Path(root).resolve(strict=True)
    except BaseException:
        raise Refusal("context_unavailable", "context") from None


def _verify_control_inventory(root, control_sha, runtime, capability):
    temporary = None
    try:
        git = capability._resolve_trusted_path("/usr/bin/git").as_posix()
        temporary = runtime._safe_temp_root()
        runtime._control_inventory(root, control_sha, git, temporary)
    except BaseException as error:
        if getattr(error, "cleanup_complete", True) is False or getattr(error, "stage", None) == "cleanup":
            raise Refusal("cleanup_incomplete", "cleanup") from None
        raise Refusal("revocation_policy_invalid", "inventory") from None
    finally:
        if temporary is not None:
            try:
                runtime._remove_tree(temporary)
            except BaseException:
                raise Refusal("cleanup_incomplete", "cleanup") from None


def _run_summary_probe(root, binding, capability, reviewed_build):
    toolchain = None
    uid = None
    home_parent = None
    scratch = None
    guard = None
    summary_identity = None
    primary_error = None
    try:
        try:
            toolchain = capability._resolve_trusted_toolchain()
        except BaseException:
            raise Refusal("context_unavailable", "toolchain") from None
        try:
            uid, home_parent, home = capability._create_probe_identity(root)
        except BaseException as error:
            if getattr(error, "cleanup_complete", True) is False:
                raise Refusal("cleanup_incomplete", "cleanup") from None
            raise Refusal("probe_identity_unavailable", "identity") from None
        try:
            scratch, standin = reviewed_build._make_control_scratch()
            child_env = reviewed_build._child_environment(home, home_parent, toolchain)
            standin_result = capability._run_as_probe_user(
                reviewed_build._probe_argv(toolchain["python"], STANDIN_GUARD_SCRIPT, standin),
                uid,
                env=child_env,
                timeout=15,
                failure_reason="native_preflight_unavailable",
                python_executable=toolchain["python"],
            )
            if (
                standin_result.returncode != 0
                or standin_result.stdout != STANDIN_GUARD_MARKER
                or standin_result.stderr
            ):
                raise Refusal("summary_write_allowed", "summary")
            reviewed_build._assert_standin_unchanged(standin)
            guard = reviewed_build._prepare_runner_summary(uid)
            original = guard["original_info"]
            summary_identity = {
                "summary_path": guard["path"],
                "summary_device": original.st_dev,
                "summary_inode": original.st_ino,
                "summary_uid": original.st_uid,
                "summary_gid": original.st_gid,
                "summary_mode": stat.S_IMODE(original.st_mode),
            }
            reviewed_build._run_real_summary_probe(
                guard,
                uid,
                env=child_env,
                python_executable=toolchain["python"],
                binding=binding,
            )
        except capability.ProbeFailure as error:
            if not error.cleanup_complete:
                raise Refusal("cleanup_incomplete", "cleanup") from None
            raise Refusal("summary_write_allowed", "summary") from None
        except Refusal:
            raise
        except BaseException as error:
            if getattr(error, "reason", None) == "cleanup_incomplete" or getattr(error, "stage", None) == "cleanup":
                raise Refusal("cleanup_incomplete", "cleanup") from None
            raise Refusal("summary_write_allowed", "summary") from None
    except Refusal as error:
        primary_error = error
    except BaseException:
        primary_error = Refusal("internal_error", "summary")
    if uid is not None and toolchain is not None:
        try:
            reviewed_build._cleanup((home_parent, scratch), uid, toolchain)
        except BaseException:
            primary_error = Refusal("cleanup_incomplete", "cleanup")
    if guard is not None:
        try:
            reviewed_build._close_runner_summary(guard)
        except BaseException:
            primary_error = Refusal("cleanup_incomplete", "cleanup")
    if primary_error is not None:
        raise primary_error
    if summary_identity is None:
        raise Refusal("summary_changed", "summary")
    return summary_identity


def _safe_relative_path(value):
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        return None
    try:
        value.encode("ascii", "strict")
    except UnicodeEncodeError:
        return None
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        return None
    return parts


def _read_source_file(root, relative, maximum):
    parts = _safe_relative_path(relative)
    if parts is None:
        raise Refusal("lock_invalid", "manifest")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory_flag or not hasattr(os, "open"):
        raise Refusal("lock_invalid", "manifest")
    current = None
    descriptor = None
    try:
        current = os.open(root, os.O_RDONLY | nofollow | directory_flag)
        root_info = os.fstat(current)
        if (
            not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
            or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        ):
            raise ValueError
        for component in parts[:-1]:
            following = os.open(component, os.O_RDONLY | nofollow | directory_flag, dir_fd=current)
            os.close(current)
            current = following
            info = os.fstat(current)
            if (
                not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            ):
                raise ValueError
        named = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        descriptor = os.open(parts[-1], os.O_RDONLY | nofollow, dir_fd=current)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode)
            or opened.st_uid != 0 or opened.st_nlink != 1
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or opened.st_size > maximum
        ):
            raise ValueError
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise ValueError
            chunks.append(chunk)
        current_named = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        final = os.fstat(descriptor)
        if (
            (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
            or (current_named.st_dev, current_named.st_ino) != (opened.st_dev, opened.st_ino)
            or final.st_size != opened.st_size or size != opened.st_size
        ):
            raise ValueError
        return b"".join(chunks)
    except Refusal:
        raise
    except BaseException:
        raise Refusal("lock_invalid", "manifest") from None
    finally:
        for value in (descriptor, current):
            if value is not None:
                try:
                    os.close(value)
                except OSError:
                    raise Refusal("cleanup_incomplete", "cleanup") from None


def _parse_lock(payload):
    if (
        type(payload) is not bytes or not payload or len(payload) > MAX_LOCK_BYTES
        or not payload.endswith(b"\n") or b"\r" in payload or b"\x00" in payload
    ):
        raise Refusal("lock_invalid", "lock")
    try:
        lines = payload[:-1].decode("ascii", "strict").split("\n")
    except BaseException:
        raise Refusal("lock_invalid", "lock") from None
    if not lines or len(lines) > MAX_LOCK_LINES:
        raise Refusal("lock_invalid", "lock")
    if lines[0].startswith(chr(35)):
        lines = lines[1:]
    fields = {}
    files = {}
    hooks = []
    settings = {}
    anchors = []
    downgrade_count = 0
    for line in lines:
        if not line or len(line.encode("ascii")) > MAX_LOCK_LINE_BYTES:
            raise Refusal("lock_invalid", "lock")
        values = line.split(" ")
        if any(not value for value in values):
            raise Refusal("lock_invalid", "lock")
        key = values[0]
        if key == "file" and len(values) == 3:
            path, digest = values[1:]
            if path in files or _safe_relative_path(path) is None or SHA256_RE.fullmatch(digest) is None:
                raise Refusal("lock_invalid", "lock")
            files[path] = digest
        elif key == "hook" and len(values) == 4:
            event, matcher, path = values[1:]
            if TOKEN_RE.fullmatch(event) is None or re.fullmatch(r"[A-Za-z0-9_.+@|/-]{1,256}", matcher) is None:
                raise Refusal("lock_invalid", "lock")
            if _safe_relative_path(path) is None:
                raise Refusal("lock_invalid", "lock")
            hooks.append(path)
        elif key == "anchor" and len(values) == 4:
            tag, object_id, fingerprint = values[1:]
            if not TAG_RE.fullmatch(tag) or not SHA_RE.fullmatch(object_id) or not FINGERPRINT_RE.fullmatch(fingerprint):
                raise Refusal("lock_invalid", "lock")
            anchors.append((tag, object_id, fingerprint))
        elif key == "setting" and len(values) == 3:
            name, value = values[1:]
            if not SETTING_RE.fullmatch(name) or TOKEN_RE.fullmatch(value) is None or name in settings:
                raise Refusal("lock_invalid", "lock")
            settings[name] = value
        elif key == "downgrade" and values == ["downgrade", "allowed"]:
            downgrade_count += 1
        else:
            if key not in {
                "format", "source", "profile", "tag", "tag-object", "commit", "signature",
                "signer", "signers-sha256", "fragment",
            } or key in fields or len(values) != 2:
                raise Refusal("lock_invalid", "lock")
            fields[key] = values[1]
    required = {
        "format", "source", "profile", "tag", "tag-object", "commit", "signature",
        "signer", "signers-sha256", "fragment",
    }
    if (
        set(fields) != required or fields["format"] != "3" or fields["profile"] != "full"
        or TOKEN_RE.fullmatch(fields["source"]) is None or not TAG_RE.fullmatch(fields["tag"])
        or not SHA_RE.fullmatch(fields["tag-object"]) or not SHA_RE.fullmatch(fields["commit"])
        or fields["signature"] != "verified" or TOKEN_RE.fullmatch(fields["signer"]) is None
        or not SHA256_RE.fullmatch(fields["signers-sha256"])
        or not SHA256_RE.fullmatch(fields["fragment"])
        or not anchors or not files or not hooks or downgrade_count > 1
        or set(settings) != {"includeCoAuthoredBy"}
        or settings.get("includeCoAuthoredBy") != "false"
        or any(path not in files for path in hooks)
        or len(set(hooks)) != len(hooks)
        or len(set(anchors)) != len(anchors)
    ):
        raise Refusal("lock_invalid", "lock")
    return {"files": files, "fields": fields}


def _verify_lock_manifest(source_root):
    lock_path = RULES_DIRECTORY + "/shared.lock"
    payload = _read_source_file(source_root, lock_path, MAX_LOCK_BYTES)
    parsed = _parse_lock(payload)
    files = parsed["files"]
    if len(files) > MAX_MANIFEST_FILES:
        raise Refusal("lock_invalid", "manifest")
    total = 0
    for relative, expected_digest in files.items():
        content = _read_source_file(source_root, relative, MAX_MANIFEST_FILE_BYTES)
        total += len(content)
        if total > MAX_MANIFEST_TOTAL_BYTES:
            raise Refusal("lock_invalid", "manifest")
        actual_digest = hashlib.sha256(content).hexdigest()
        if actual_digest != expected_digest:
            raise Refusal("manifest_mismatch", "manifest")
    return {
        "format": "3",
        "manifest": "matched",
        "signers_hash": "well-formed",
        "fragment_hash": "well-formed",
    }


def _validate_lease_record(runtime, record, binding, source_sha):
    if not isinstance(record, Mapping):
        raise Refusal("source_lease_unavailable", "source_lease")
    copy = dict(record)
    expected = {
        "source_sha": source_sha,
        "base_sha": source_sha,
        "base_branch": "main",
        "concern": "core-bootstrap",
        "candidate_class": "permanent-tip",
        "signature": "verified",
        "rules_lock": "present",
        "tree": "core_administrative",
        "source_execution": "not_run_at_yield",
        "app_build": "not_run",
        "cleanup": "lease_open",
        "control_sha": binding["control_sha"],
        "run_id": binding["run_id"],
        "run_attempt": binding["run_attempt"],
        "image_os": binding["image_os"],
        "image_version": binding["image_version"],
        "repository_scope": "verified",
        "metadata": "verified",
        "token_revocation": "confirmed_before_yield",
        "signer_authority": "bound_base",
        "signatures": "all_new_commits_verified",
        "ancestry": "base_ancestor",
        "revocation_policy": "current_control_fingerprints",
        "worker_access": "not_applicable",
    }
    if set(copy) != set(expected) | {"repository_id"} or any(copy.get(key) != value for key, value in expected.items()):
        raise Refusal("source_lease_unavailable", "source_lease")
    if re.fullmatch(r"[1-9][0-9]{0,18}", copy.get("repository_id", "")) is None:
        raise Refusal("source_lease_unavailable", "source_lease")
    copy["cleanup"] = "complete"
    try:
        runtime._format_success(copy, binding)
    except BaseException:
        raise Refusal("source_lease_unavailable", "source_lease") from None
    return copy


def _success_line(record, binding, manifest):
    return " ".join((
        "macos-core-bootstrap=verified",
        "schema=1",
        "control-sha=" + binding["control_sha"],
        "run-id=" + binding["run_id"],
        "run-attempt=" + binding["run_attempt"],
        "image-os=" + binding["image_os"],
        "image-version=" + binding["image_version"],
        "source-repository-id=" + record["repository_id"],
        "source-sha=" + record["source_sha"],
        "base-branch=main",
        "base-sha=" + record["base_sha"],
        "concern=core-bootstrap",
        "source-signature=verified",
        "token-revocation=confirmed-before-execution",
        "rules-lock=present",
        "rules-lock-signature=declared-verified",
        "lock-format=" + manifest["format"],
        "manifest=" + manifest["manifest"],
        "signers-hash=" + manifest["signers_hash"],
        "fragment-hash=" + manifest["fragment_hash"],
        "source-execution=not-run",
        "app-build=not-run",
        "worker-access=not-applicable",
        "cleanup=complete",
        "summary-control=append-denied",
        "summary-sibling=create-denied",
        "summary-standin=write-denied",
        "summary-sentinel=written",
    ))


def _append_summary(summary_identity, line):
    path = summary_identity["summary_path"]
    descriptor = None
    try:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if not nofollow:
            raise ValueError
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | nofollow)
        opened = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode)
            or opened.st_nlink != 1 or opened.st_uid != summary_identity["summary_uid"]
            or opened.st_gid != summary_identity["summary_gid"]
            or stat.S_IMODE(opened.st_mode) != summary_identity["summary_mode"]
            or (opened.st_dev, opened.st_ino) != (
                summary_identity["summary_device"], summary_identity["summary_inode"],
            )
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size != 0 or named.st_size != 0
        ):
            raise ValueError
        payload = (line + "\n").encode("ascii")
        position = 0
        while position < len(payload):
            amount = os.write(descriptor, payload[position:])
            if amount <= 0:
                raise OSError
            position += amount
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        current = path.lstat()
        if (
            (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or final.st_size != len(payload) or current.st_size != len(payload)
        ):
            raise ValueError
    except BaseException:
        raise Refusal("summary_changed", "summary") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise Refusal("cleanup_incomplete", "cleanup") from None


def _safe_identity(control_sha, environ, source_sha):
    run_id = environ.get("GITHUB_RUN_ID", "")
    attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    if DECIMAL_RE.fullmatch(run_id) is None:
        run_id = "unknown"
    if DECIMAL_RE.fullmatch(attempt) is None:
        attempt = "unknown"
    safe_control = control_sha if _valid_sha(control_sha) else "unknown"
    safe_source = source_sha if _valid_sha(source_sha) else "unknown"
    return safe_control, run_id, attempt, safe_source


def _format_refusal(error, control_sha, environ, source_sha, token_state=None):
    if type(error) is not Refusal:
        error = Refusal("internal_error", "input")
    safe_control, run_id, attempt, safe_source = _safe_identity(control_sha, environ, source_sha)
    line = (
        "macos-core-bootstrap=refused schema=1 reason=" + error.reason
        + " stage=" + error.stage + " control-sha=" + safe_control
        + " run-id=" + run_id + " run-attempt=" + attempt + " source-sha=" + safe_source
    )
    source_diagnostic = error.source_diagnostic
    if (
        error.reason == "source_fetch_unavailable" and error.stage == "source_lease"
        and type(source_diagnostic) is tuple and len(source_diagnostic) == 2
        and type(source_diagnostic[0]) is str
        and source_diagnostic[0] in SOURCE_DIAGNOSTIC_OPERATIONS
        and type(source_diagnostic[1]) is str
        and source_diagnostic[1] in SOURCE_DIAGNOSTIC_CLASSES
    ):
        operation, failure_class = source_diagnostic
        line += " source-diagnostic=" + operation + "." + failure_class
    if token_state in TOKEN_REFUSAL_STATES:
        line += " token-revocation=" + token_state
    return line


def run(arguments=None, environ=None, token_reader=None):
    actual_arguments = sys.argv[1:] if arguments is None else arguments
    environment = os.environ if environ is None else environ
    control_sha = environment.get("CI_SHA", "")
    source_sha = ""
    phase_hint = _phase_hint(actual_arguments)
    token_read = False
    token_value = None
    token_confirmed = False
    runtime = None
    request = None
    binding = None
    revocation_state = None
    expected_repository_id = environment.get("SOURCE_REPOSITORY_ID", "")
    try:
        phase, source_sha, token_stdin = _parse_arguments(actual_arguments)
        phase_hint = phase
        control_sha = _check_gates(source_sha, environment)
        if phase == "bootstrap":
            token_value = _read_token_stdin(
                sys.stdin.buffer if token_reader is None else token_reader,
            )
            environment["SOURCE_READER_TOKEN"] = token_value
            token_read = True
        capability, reviewed_build, runtime = _load_control()
        binding, root = _safe_context(control_sha, environment, reviewed_build, capability)
        _verify_control_inventory(root, control_sha, runtime, capability)
        summary_identity = _run_summary_probe(root, binding, capability, reviewed_build)
        if phase == "preflight":
            return " ".join((
                "macos-core-bootstrap=preflight-passed",
                "schema=1",
                "control-sha=" + control_sha,
                "run-id=" + binding["run_id"],
                "run-attempt=" + binding["run_attempt"],
                "source-sha=" + source_sha,
                "runner-summary=append-denied",
                "summary-sibling=create-denied",
                "summary-standin=write-denied",
                "cleanup=complete",
            )), None
        request = {
            "source_sha": source_sha,
            "base_sha": source_sha,
            "base_branch": "main",
            "concern": "core-bootstrap",
        }
        revocation_state = runtime.RevocationState()
        try:
            with runtime.validated_source(
                request,
                binding,
                root,
                environment,
                revocation_state=revocation_state,
            ) as lease:
                token_confirmed = _runtime_revocation_confirmed(
                    runtime,
                    revocation_state,
                    token_value,
                    expected_repository_id,
                    request,
                    binding,
                )
                if not token_confirmed:
                    raise Refusal("source_lease_unavailable", "source_lease")
                record = _validate_lease_record(runtime, lease.record, binding, source_sha)
                manifest = _verify_lock_manifest(lease.source_path)
        except runtime.Refusal as error:
            token_confirmed = token_confirmed or _runtime_revocation_confirmed(
                runtime,
                revocation_state,
                token_value,
                expected_repository_id,
                request,
                binding,
            )
            if error.stage == "cleanup" or error.reason == "cleanup_incomplete":
                raise Refusal("cleanup_incomplete", "cleanup") from None
            reason = (
                error.reason
                if type(error.reason) is str and error.reason in SOURCE_VALIDATION_REASONS
                else "source_lease_unavailable"
            )
            source_diagnostic = None
            if reason == "source_fetch_unavailable" and error.stage == "fetch":
                candidate = getattr(error, "source_diagnostic", None)
                if (
                    type(candidate) is tuple and len(candidate) == 2
                    and type(candidate[0]) is str
                    and candidate[0] in SOURCE_DIAGNOSTIC_OPERATIONS
                    and type(candidate[1]) is str
                    and candidate[1] in SOURCE_DIAGNOSTIC_CLASSES
                ):
                    source_diagnostic = candidate
            raise Refusal(reason, "source_lease", source_diagnostic) from None
        except Refusal:
            raise
        except BaseException:
            raise Refusal("source_lease_unavailable", "source_lease") from None
        record["cleanup"] = "complete"
        line = _success_line(record, binding, manifest)
        _append_summary(summary_identity, line)
        return line, None
    except Refusal as error:
        if phase_hint == "bootstrap":
            token_confirmed = token_confirmed or _runtime_revocation_confirmed(
                runtime,
                revocation_state,
                token_value,
                expected_repository_id,
                request,
                binding,
            )
        cleanup = _cleanup_after_refusal(environment, token_read, token_value, token_confirmed)
        token_state = None
        if phase_hint == "bootstrap":
            token_state = (
                "confirmed" if token_confirmed or cleanup is True
                else "unconfirmed" if token_read
                else "not-read"
            )
        if cleanup is True:
            token_state = "confirmed"
        elif cleanup is False:
            error = Refusal("cleanup_incomplete", "cleanup")
            token_state = "unconfirmed" if phase_hint == "bootstrap" else None
        elif phase_hint == "bootstrap" and token_read and not token_confirmed:
            error = Refusal("cleanup_incomplete", "cleanup")
        return _format_refusal(error, control_sha, environment, source_sha, token_state), 1
    except BaseException:
        error = Refusal("internal_error", "input")
        if phase_hint == "bootstrap":
            token_confirmed = token_confirmed or _runtime_revocation_confirmed(
                runtime,
                revocation_state,
                token_value,
                expected_repository_id,
                request,
                binding,
            )
        cleanup = _cleanup_after_refusal(environment, token_read, token_value, token_confirmed)
        token_state = None
        if phase_hint == "bootstrap":
            token_state = (
                "confirmed" if token_confirmed or cleanup is True
                else "unconfirmed" if token_read
                else "not-read"
            )
        if cleanup is True:
            token_state = "confirmed"
        elif cleanup is False:
            error = Refusal("cleanup_incomplete", "cleanup")
            token_state = "unconfirmed" if phase_hint == "bootstrap" else None
        elif phase_hint == "bootstrap" and token_read and not token_confirmed:
            error = Refusal("cleanup_incomplete", "cleanup")
        return _format_refusal(error, control_sha, environment, source_sha, token_state), 1


def main(arguments=None):
    actual_arguments = sys.argv[1:] if arguments is None else arguments
    if (
        type(actual_arguments) in (tuple, list) and len(actual_arguments) >= 2
        and type(actual_arguments[0]) is str and actual_arguments[0] == "--phase"
        and type(actual_arguments[1]) is str and actual_arguments[1] == "revoke"
    ):
        line, status = _run_revoke_cli(actual_arguments)
        sys.stdout.write(line + "\n")
        return status
    line, status = run(actual_arguments)
    sys.stdout.write(line + "\n")
    return 1 if status else 0


if __name__ == "__main__":
    raise SystemExit(main())
