from decimal import Decimal, InvalidOperation
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zlib


SCHEMA_VERSION = 1
SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
BASE_BRANCHES = frozenset(("main", "develop", "uat"))
CONCERN = "rules-bootstrap"
SUITES = ("rules.hooks", "rules.sync", "rules.static", "rules.public")
GATES = SUITES + ("plan-ids",)
CONTROL_SIBLINGS = frozenset((
    "macos_reviewed_build", "macos_capability", "macos_boundary_guard",
    "macos_private_validation", "macos_source_reader", "macos_network_observer",
))
REQUIRED_SOURCE_FILES = (
    "ci/run-suite.sh",
    "tests/run-hook-tests.sh",
    "tests/run-sync-tests.sh",
    "tests/run-chain-tests.sh",
    "tests/run-signature-tests.sh",
    "tests/run-signature-merge-tests.sh",
    "tests/check-static.sh",
    "tests/check-no-public.sh",
    "tests/check-plan-ids.sh",
    "docs/commit-signers",
    "allowed-signers",
)
MAX_CAPTURE_BYTES = 65536
MAX_PLAN_BYTES = 48 * 1024
MAX_PLAN_LINES = 20000
PLAN_ROW_RE = re.compile(rb"\|[ \t]*(?:MC|CI|CR|[DRHKXCM])[0-9]+[ \t]*\|\Z")
TOKEN_RE = re.compile(r"[!-~]{1,4096}\Z")

DASH_FORMULA = "homebrew/core/dash-shell"
DASH_VERSION = "0.5.13.5"
DASH_FORMULA_SHA256 = "7a414fa6d299c0697053cb3f796b94d13682cd43c20e8ba62ce515cb3a1c3d14"
DASH_BOTTLE_SHA256 = "0e104457d0d188129596ee04e4f88ab6039baf9a03e183820caf0aa333d581d0"
DASH_BOTTLE_URL = (
    "https://ghcr.io/v2/homebrew/core/dash-shell/blobs/sha256:" + DASH_BOTTLE_SHA256
)
DASH_TOKEN_URL = "https://ghcr.io/token?" + urllib.parse.urlencode(
    {"scope": "repository:homebrew/core/dash-shell:pull"}
)
DASH_BINARY_MEMBER = "dash-shell/0.5.13.5/bin/dash"
DASH_FORMULA_MEMBER = "dash-shell/0.5.13.5/.brew/dash-shell.rb"
MAX_BOTTLE_BYTES = 32 * 1024 * 1024
MAX_BOTTLE_MEMBERS = 4096
MAX_BOTTLE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_BOTTLE_TOTAL_BYTES = 32 * 1024 * 1024
MAX_DASH_BYTES = 16 * 1024 * 1024
MAX_PAX_HEADERS = 7
MAX_PAX_VALUE_BYTES = 32
PAX_TIMESTAMP_RE = re.compile(r"-?(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,9})?\Z")
PAX_TIMESTAMP_MIN = Decimal("-62135596800")
PAX_TIMESTAMP_MAX = Decimal("253402300799.999999999")
PAX_TIMESTAMP_KEYS = frozenset(("mtime", "atime", "ctime", "LIBARCHIVE.creationtime"))
PREP_ROOT = Path("/") / "private" / "tmp"
PREP_PREFIX = "macos-ci-dash-"
RUN_PREFIX = "macos-ci-check-"
GHCR_HOST = "ghcr.io"
GHCR_REDIRECT_HOST = "pkg-containers.githubusercontent.com"

REASONS = frozenset((
    "invalid_input", "control_identity_invalid", "bootstrap_gate_refused", "developer_mode_unavailable",
    "plan_snapshot_refused", "dash_bottle_unavailable", "dash_bottle_invalid",
    "dash_identity_invalid", "context_unavailable", "toolchain_unavailable",
    "runner_controls_unavailable", "probe_identity_unavailable", "storage_unavailable",
    "source_lease_unavailable", "source_identity_invalid", "source_tree_invalid",
    "summary_guard_failed", "suite_failed", "plan_ids_failed",
    "cleanup_incomplete", "internal_error",
))
STAGES = frozenset((
    "arguments", "context", "bootstrap_gate", "developer_mode", "plan_snapshot", "dash_download",
    "dash_archive", "dash_archive_structure", "dash_archive_pax_metadata",
    "dash_archive_member", "dash_archive_content", "dash_archive_binary_missing",
    "dash_archive_formula_missing", "dash_archive_formula_digest_mismatch",
    "dash_verify", "toolchain", "runner_controls", "identity",
    "storage", "source_lease", "source_identity", "source_tree", "summary_guard",
    *GATES, "cleanup",
))

SUMMARY_GUARD_SCRIPT = r'''
import errno, os, sys
for path in sys.argv[1:-1]:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM):
            raise SystemExit(81)
    else:
        os.close(fd)
        raise SystemExit(82)
standin = sys.argv[-1]
for flags in (os.O_WRONLY | os.O_NOFOLLOW, os.O_RDONLY | os.O_NOFOLLOW):
    try:
        fd = os.open(standin, flags)
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM):
            raise SystemExit(83)
    else:
        os.close(fd)
        raise SystemExit(84)
os.write(1, b"runner-controls=write-denied summary-standin=write-denied\n")
'''

TREE_PROBE = r'''
import os, stat, sys
root = sys.argv[1]
if not os.path.isabs(root) or os.path.realpath(root) != root:
    raise SystemExit(81)
count = 0
for current, directories, files in os.walk(root, topdown=True, followlinks=False):
    info = os.stat(current, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o077
            or not os.access(current, os.R_OK | os.X_OK) or os.access(current, os.W_OK)):
        raise SystemExit(82)
    for name in directories + files:
        path = os.path.join(current, name)
        info = os.stat(path, follow_symlinks=False)
        count += 1
        if count > 20000 or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
            raise SystemExit(83)
        if name in directories:
            if (not stat.S_ISDIR(info.st_mode) or not os.access(path, os.R_OK | os.X_OK)
                    or os.access(path, os.W_OK)):
                raise SystemExit(84)
        elif (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not os.access(path, os.R_OK) or os.access(path, os.W_OK)):
            raise SystemExit(85)
os.write(1, b"source-tree=uid-read-only\n")
'''

SNAPSHOT_PROBE = r'''
import errno, hashlib, os, stat, sys
directory, filename, expected = sys.argv[1:]
info = os.stat(directory, follow_symlinks=False)
if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
    raise SystemExit(81)
if not os.access(directory, os.R_OK | os.X_OK) or os.access(directory, os.W_OK):
    raise SystemExit(82)
info = os.stat(filename, follow_symlinks=False)
if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o400:
    raise SystemExit(83)
try:
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW)
except OSError:
    raise SystemExit(84)
try:
    chunks, size = [], 0
    while True:
        data = os.read(fd, 65536)
        if not data:
            break
        size += len(data)
        if size > 49152:
            raise SystemExit(85)
        chunks.append(data)
finally:
    os.close(fd)
if hashlib.sha256(b"".join(chunks)).hexdigest() != expected:
    raise SystemExit(86)
try:
    fd = os.open(filename, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
except OSError as error:
    if error.errno not in (errno.EACCES, errno.EPERM):
        raise SystemExit(87)
else:
    os.close(fd)
    raise SystemExit(88)
os.write(1, b"plan-id-snapshot=read-only\n")
'''


class Refusal(Exception):
    def __init__(self, reason, stage, *, embedded_formula_sha256=None, verified_bottle_sha256=None):
        self.reason = reason if type(reason) is str and reason in REASONS else "internal_error"
        self.stage = stage if type(stage) is str and stage in STAGES else "context"
        self.embedded_formula_sha256 = (
            embedded_formula_sha256
            if type(embedded_formula_sha256) is str and SHA256_RE.fullmatch(embedded_formula_sha256)
            else None
        )
        self.verified_bottle_sha256 = (
            verified_bottle_sha256
            if type(verified_bottle_sha256) is str and SHA256_RE.fullmatch(verified_bottle_sha256)
            else None
        )
        super().__init__(self.reason)


class _PinnedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, message, headers, newurl):
        try:
            old = urllib.parse.urlsplit(req.full_url)
            new = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, newurl))
        except BaseException:
            return None
        if (new.scheme != "https" or new.username is not None or new.password is not None
                or new.port not in (None, 443) or new.fragment):
            return None
        old_host = (old.hostname or "").lower()
        new_host = (new.hostname or "").lower()
        same_host = old_host == new_host and new_host in (GHCR_HOST, GHCR_REDIRECT_HOST)
        blob_redirect = old_host == GHCR_HOST and new_host == GHCR_REDIRECT_HOST
        if not (same_host or blob_redirect):
            return None
        forwarded = {}
        for key, value in req.header_items():
            if key.lower() in ("host", "content-length", "content-type"):
                continue
            if key.lower() == "authorization" and not same_host:
                continue
            forwarded[key] = value
        return urllib.request.Request(new.geturl(), headers=forwarded, method="GET")


def _load_control_sibling(name):
    if type(name) is not str or name not in CONTROL_SIBLINGS:
        raise ImportError("control module unavailable")
    directory = Path(__file__).resolve(strict=True).parent
    path = (directory / (name + ".py")).resolve(strict=True)
    if path.parent != directory or not path.is_file():
        raise ImportError("control module unavailable")
    module = sys.modules.get(name)
    if module is not None and getattr(module, "__file__", None):
        try:
            if Path(module.__file__).resolve(strict=True) == path:
                return module
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
        raise
    return module


def _load_control():
    try:
        reviewed = _load_control_sibling("macos_reviewed_build")
        capability = _load_control_sibling("macos_capability")
        boundary = _load_control_sibling("macos_boundary_guard")
    except BaseException:
        raise Refusal("context_unavailable", "context") from None
    if reviewed.capability is None:
        raise Refusal("context_unavailable", "context")
    return reviewed, capability, boundary


def _revoke_pending_token(environ, token_reference=None):
    token = token_reference
    if token is None:
        token = environ.get("SOURCE_READER_TOKEN", "")
    if type(token) is not str or TOKEN_RE.fullmatch(token) is None:
        return False
    try:
        reader = _load_control_sibling("macos_source_reader")
        reader_environment = dict(environ)
        reader_environment["SOURCE_READER_TOKEN"] = token
        result = reader.run(environ=reader_environment)
        required = {"schema_version", "status", "reason", "repository_scope", "metadata", "revocation"}
        if (type(result) is not dict or set(result) != required
                or type(result.get("schema_version")) is not int or result.get("schema_version") != 1
                or type(result.get("status")) is not str or result.get("status") != "passed"
                or type(result.get("reason")) is not str or result.get("reason") != "ok"
                or type(result.get("repository_scope")) is not str
                or result.get("repository_scope") != "verified"
                or type(result.get("metadata")) is not str or result.get("metadata") != "verified"
                or type(result.get("revocation")) is not str or result.get("revocation") != "confirmed"):
            raise ValueError
        try:
            environ.pop("SOURCE_READER_TOKEN", None)
        except BaseException:
            pass
        return True
    except BaseException:
        raise Refusal("cleanup_incomplete", "cleanup") from None


def _valid_sha(value):
    return type(value) is str and SHA_RE.fullmatch(value) is not None


def _safe_id(value):
    return type(value) is str and DECIMAL_RE.fullmatch(value) is not None


def _parse_request(argv):
    if type(argv) not in (tuple, list) or len(argv) != 8:
        raise Refusal("invalid_input", "arguments")
    if tuple(argv[::2]) != ("--source-sha", "--base-sha", "--base-branch", "--concern"):
        raise Refusal("invalid_input", "arguments")
    source_sha, base_sha, branch, concern = argv[1::2]
    if (not _valid_sha(source_sha) or not _valid_sha(base_sha)
            or branch not in BASE_BRANCHES or concern != CONCERN):
        raise Refusal("invalid_input", "arguments")
    return {"source_sha": source_sha, "base_sha": base_sha, "base_branch": branch, "concern": concern}


def _public_context(environ, reviewed, capability, boundary):
    control = environ.get("CI_SHA", "")
    if (not _valid_sha(control) or environ.get("CI_EVENT_NAME") != "workflow_dispatch"
            or environ.get("CI_REF") != "refs/heads/main"
            or environ.get("CI_REPOSITORY") != "keeldock-platform/platform-ci"
            or environ.get("CI_SERVER_URL") != "https://github.com"):
        raise Refusal("control_identity_invalid", "context")
    try:
        binding = reviewed._binding(control, environ)
        root = capability._check_context(control, environ.get("CI_WORKSPACE", ""))
        identity = boundary.check_platform()
    except BaseException:
        raise Refusal("context_unavailable", "context") from None
    if (not _safe_id(binding.get("run_id")) or not _safe_id(binding.get("run_attempt"))
            or identity.architecture != "arm64"):
        raise Refusal("control_identity_invalid", "context")
    return binding, root


def _validate_plan_definitions(environ):
    text = environ.get("RULES_ID_DEFINITIONS", "")
    expected = environ.get("RULES_ID_DEFINITIONS_SHA256", "")
    if (type(text) is not str or not text or not SHA256_RE.fullmatch(expected)
            or "\x00" in text):
        raise Refusal("plan_snapshot_refused", "plan_snapshot")
    try:
        raw = text.encode("ascii", "strict")
    except UnicodeEncodeError:
        raise Refusal("plan_snapshot_refused", "plan_snapshot") from None
    if len(raw) > MAX_PLAN_BYTES or not raw.endswith(b"\n") or b"\r" in raw:
        raise Refusal("plan_snapshot_refused", "plan_snapshot")
    lines = raw[:-1].split(b"\n")
    if not lines or len(lines) > MAX_PLAN_LINES:
        raise Refusal("plan_snapshot_refused", "plan_snapshot")
    seen = set()
    for line in lines:
        if len(line) > 128 or PLAN_ROW_RE.fullmatch(line) is None or line in seen:
            raise Refusal("plan_snapshot_refused", "plan_snapshot")
        seen.add(line)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected:
        raise Refusal("plan_snapshot_refused", "plan_snapshot")
    return raw, digest


def _validate_bootstrap_gate(request, binding, environ):
    if (environ.get("RULES_BOOTSTRAP_ALLOWED_SHA") != request["source_sha"]
            or environ.get("RULES_BOOTSTRAP_ALLOWED_CONTROL_SHA") != binding["control_sha"]
            or binding["control_sha"] != environ.get("CI_SHA")):
        raise Refusal("bootstrap_gate_refused", "bootstrap_gate")
    if request.get("concern") != CONCERN or request.get("base_branch") not in BASE_BRANCHES:
        raise Refusal("bootstrap_gate_refused", "bootstrap_gate")
    candidate_ref = environ.get("SOURCE_CANDIDATE_REF", "")
    reviewed_diff_sha256 = environ.get("SOURCE_REVIEWED_DIFF_SHA256", "")
    if (environ.get("SOURCE_REVIEWED_SHA") != request["source_sha"]
            or environ.get("SOURCE_REVIEWED_BASE") != request["base_sha"]
            or environ.get("SOURCE_REVIEWED_BASE_BRANCH") != request["base_branch"]
            or not _safe_candidate_ref(candidate_ref, request)
            or type(reviewed_diff_sha256) is not str
            or SHA256_RE.fullmatch(reviewed_diff_sha256) is None):
        raise Refusal("bootstrap_gate_refused", "bootstrap_gate")
    definitions, definitions_sha256 = _validate_plan_definitions(environ)
    return definitions, definitions_sha256, reviewed_diff_sha256


def _record_runtime_revocation(runtime, state, token, request, binding, environ, lifecycle):
    repository_id = environ.get("SOURCE_REPOSITORY_ID", "")
    if (state is None or not _safe_id(repository_id)
            or type(token) is not str or TOKEN_RE.fullmatch(token) is None):
        return False
    try:
        confirmed = runtime.revocation_confirmed(
            state, token, repository_id, request, binding,
        )
    except BaseException:
        return False
    if confirmed is not True:
        return False
    lifecycle["token_revocation"] = "confirmed"
    lifecycle["token_reference"] = None
    return True


def _safe_candidate_ref(candidate_ref, request):
    if type(candidate_ref) is not str or len(candidate_ref) > 160:
        return False
    if request["source_sha"] == request["base_sha"]:
        return candidate_ref == "refs/heads/" + request["base_branch"]
    if re.fullmatch(r"refs/heads/(?:feat|fix|chore|plan)/[A-Za-z0-9][A-Za-z0-9._/-]{0,126}", candidate_ref) is None:
        return False
    branch = candidate_ref[len("refs/heads/"):]
    components = branch.split("/")
    return not (
        any(not part or part in (".", "..") or part.startswith(".")
            or part.endswith(".") or part.endswith(".lock") for part in components)
        or ".." in branch or "@{" in branch or branch.endswith("/")
    )


def _binding_digest(request, binding, plan_sha, reviewed_diff_sha256):
    record = {
        "schema_version": SCHEMA_VERSION,
        "concern": CONCERN,
        "control_sha": binding["control_sha"],
        "run_id": binding["run_id"],
        "run_attempt": binding["run_attempt"],
        "source_sha": request["source_sha"],
        "base_sha": request["base_sha"],
        "base_branch": request["base_branch"],
        "definitions_sha256": plan_sha,
        "reviewed_diff_sha256": reviewed_diff_sha256,
    }
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs)


def _open_bounded(opener, url, headers, limit):
    with opener.open(urllib.request.Request(url, headers=headers, method="GET"), timeout=20) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if (final.scheme != "https" or (final.hostname or "").lower() not in (GHCR_HOST, GHCR_REDIRECT_HOST)
                or final.port not in (None, 443)):
            raise Refusal("dash_bottle_unavailable", "dash_download")
        length = response.headers.get("Content-Length")
        if length is not None and (re.fullmatch(r"[0-9]{1,10}", length) is None or int(length) > limit):
            raise Refusal("dash_bottle_invalid", "dash_download")
        body = response.read(limit + 1)
        if len(body) > limit:
            raise Refusal("dash_bottle_invalid", "dash_download")
        return body


def _fetch_bottle():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _PinnedRedirect())
    try:
        token_data = _strict_json(_open_bounded(opener, DASH_TOKEN_URL, {"Accept": "application/json"}, 65536))
        if type(token_data) is not dict or set(token_data) - {"token", "expires_in", "issued_at"}:
            raise ValueError("unexpected token schema")
        token = token_data.get("token")
        if type(token) is not str or re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,8192}", token) is None:
            raise ValueError("invalid public token")
        bottle = _open_bounded(
            opener, DASH_BOTTLE_URL,
            {"Accept": "application/octet-stream", "Authorization": "Bearer " + token},
            MAX_BOTTLE_BYTES,
        )
    except Refusal:
        raise
    except BaseException:
        raise Refusal("dash_bottle_unavailable", "dash_download") from None
    if hashlib.sha256(bottle).hexdigest() != DASH_BOTTLE_SHA256:
        raise Refusal("dash_bottle_invalid", "dash_download")
    return bottle


def _safe_tar_name(name):
    if type(name) is not str or not name or "\x00" in name or "\\" in name:
        return None
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name.rstrip("/"):
        return None
    if any(part in ("", ".", "..") for part in path.parts):
        return None
    return path.as_posix()


def _safe_pax_headers(headers):
    if type(headers) is not dict or len(headers) > MAX_PAX_HEADERS:
        return False
    for key, value in headers.items():
        if (type(key) is not str or type(value) is not str or not key.isascii()
                or not value.isascii() or len(value) > MAX_PAX_VALUE_BYTES):
            return False
        if key in PAX_TIMESTAMP_KEYS:
            if PAX_TIMESTAMP_RE.fullmatch(value) is None:
                return False
            try:
                timestamp = Decimal(value)
            except InvalidOperation:
                return False
            if not timestamp.is_finite() or not PAX_TIMESTAMP_MIN <= timestamp <= PAX_TIMESTAMP_MAX:
                return False
        elif key in ("uid", "gid"):
            if value != "0":
                return False
        elif key == "hdrcharset":
            if value not in ("BINARY", "UTF-8"):
                return False
        else:
            return False
    return True


def _safe_archive_member_type(member):
    return (member.type in (tarfile.DIRTYPE, tarfile.REGTYPE, tarfile.AREGTYPE)
            and member.sparse is None)


def _extract_dash_member(bottle):
    binary = None
    formula = None
    seen = set()
    total = 0
    try:
        if type(bottle) is not bytes or len(bottle) > MAX_BOTTLE_BYTES:
            raise Refusal("dash_bottle_invalid", "dash_archive_structure")
        actual_bottle_sha256 = hashlib.sha256(bottle).hexdigest()
        if actual_bottle_sha256 != DASH_BOTTLE_SHA256:
            raise Refusal("dash_bottle_invalid", "dash_download")
        try:
            inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
            unpacked = inflater.decompress(bottle, MAX_BOTTLE_TOTAL_BYTES + 1)
            if (len(unpacked) > MAX_BOTTLE_TOTAL_BYTES or inflater.unconsumed_tail
                    or inflater.unused_data or not inflater.eof):
                raise Refusal("dash_bottle_invalid", "dash_archive_structure")
            tail = inflater.flush(MAX_BOTTLE_TOTAL_BYTES + 1 - len(unpacked))
            if len(unpacked) + len(tail) > MAX_BOTTLE_TOTAL_BYTES:
                raise Refusal("dash_bottle_invalid", "dash_archive_structure")
            unpacked += tail
        except Refusal:
            raise
        except BaseException:
            raise Refusal("dash_bottle_invalid", "dash_archive_structure") from None
        try:
            archive = tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:")
        except BaseException:
            raise Refusal("dash_bottle_invalid", "dash_archive_structure") from None
        try:
            with archive:
                count = 0
                for member in archive:
                    count += 1
                    if count > MAX_BOTTLE_MEMBERS:
                        raise Refusal("dash_bottle_invalid", "dash_archive_member")
                    if not _safe_pax_headers(member.pax_headers):
                        raise Refusal("dash_bottle_invalid", "dash_archive_pax_metadata")
                    name = _safe_tar_name(member.name)
                    if (name is None or name in seen
                            or (name not in ("dash-shell", "dash-shell/" + DASH_VERSION)
                                and not name.startswith("dash-shell/" + DASH_VERSION + "/"))):
                        raise Refusal("dash_bottle_invalid", "dash_archive_member")
                    seen.add(name)
                    if (not _safe_archive_member_type(member)
                            or member.issym() or member.islnk() or member.isdev() or member.isfifo()
                            or not (member.isdir() or member.isreg())
                            or member.mode & (stat.S_ISUID | stat.S_ISGID)):
                        raise Refusal("dash_bottle_invalid", "dash_archive_member")
                    if member.size < 0 or member.size > MAX_BOTTLE_MEMBER_BYTES:
                        raise Refusal("dash_bottle_invalid", "dash_archive_member")
                    total += member.size
                    if total > MAX_BOTTLE_TOTAL_BYTES or (member.isdir() and member.size != 0):
                        raise Refusal("dash_bottle_invalid", "dash_archive_member")
                    if member.isdir() or name not in (DASH_BINARY_MEMBER, DASH_FORMULA_MEMBER):
                        continue
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise Refusal("dash_bottle_invalid", "dash_archive_structure")
                    with stream:
                        data = stream.read(member.size + 1)
                    if len(data) != member.size:
                        raise Refusal("dash_bottle_invalid", "dash_archive_structure")
                    if name == DASH_BINARY_MEMBER:
                        if binary is not None or not member.mode & 0o111 or len(data) > MAX_DASH_BYTES:
                            raise Refusal("dash_bottle_invalid", "dash_archive_member")
                        binary = data
                    else:
                        if formula is not None or len(data) > 65536:
                            raise Refusal("dash_bottle_invalid", "dash_archive_member")
                        formula = data
        except Refusal:
            raise
        except BaseException:
            raise Refusal("dash_bottle_invalid", "dash_archive_structure") from None
    except Refusal:
        raise
    except BaseException:
        raise Refusal("dash_bottle_invalid", "dash_archive") from None
    if binary is None:
        raise Refusal("dash_bottle_invalid", "dash_archive_binary_missing")
    if not binary:
        raise Refusal("dash_bottle_invalid", "dash_archive_content")
    if formula is None:
        raise Refusal("dash_bottle_invalid", "dash_archive_formula_missing")
    embedded_formula_sha256 = hashlib.sha256(formula).hexdigest()
    if embedded_formula_sha256 != DASH_FORMULA_SHA256:
        raise Refusal(
            "dash_bottle_invalid", "dash_archive_formula_digest_mismatch",
            embedded_formula_sha256=embedded_formula_sha256,
            verified_bottle_sha256=actual_bottle_sha256,
        )
    return binary


def _write_new_file(path, payload, mode):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise Refusal("storage_unavailable", "storage")
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(payload):
            count = os.write(fd, payload[offset:])
            if count <= 0:
                raise OSError("short write")
            offset += count
        os.fsync(fd)
    except BaseException:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            Path(path).unlink()
        except OSError:
            pass
        raise Refusal("storage_unavailable", "storage") from None
    os.close(fd)


def _prep_directory(binding):
    return PREP_ROOT / (PREP_PREFIX + binding["run_id"] + "-" + binding["run_attempt"] + "-" + binding["control_sha"])


def _run_directory(binding):
    return PREP_ROOT / (RUN_PREFIX + binding["run_id"] + "-" + binding["run_attempt"] + "-" + binding["control_sha"])


def _check_temp_root():
    try:
        info = PREP_ROOT.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o1777):
            raise ValueError
    except BaseException:
        raise Refusal("storage_unavailable", "context") from None


def _file_sha(path, expected=None):
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_size <= 0 or info.st_size > MAX_DASH_BYTES
                or stat.S_IMODE(info.st_mode) != 0o555):
            raise ValueError
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if expected is not None and digest != expected:
            raise ValueError
        return digest
    except BaseException:
        raise Refusal("dash_identity_invalid", "dash_verify") from None


def _verify_prepared_dash(binding):
    directory = _prep_directory(binding)
    try:
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o755):
            raise ValueError
        evidence_info = (directory / "evidence.json").lstat()
        if (not stat.S_ISREG(evidence_info.st_mode) or evidence_info.st_uid != 0
                or stat.S_IMODE(evidence_info.st_mode) != 0o444 or evidence_info.st_nlink != 1
                or evidence_info.st_size > 4096):
            raise ValueError
        record = _strict_json((directory / "evidence.json").read_bytes().rstrip(b"\n"))
        expected = {
            "schema_version": SCHEMA_VERSION,
            "formula": DASH_FORMULA,
            "version": DASH_VERSION,
            "formula_sha256": DASH_FORMULA_SHA256,
            "bottle_sha256": DASH_BOTTLE_SHA256,
            "control_sha": binding["control_sha"],
            "run_id": binding["run_id"],
            "run_attempt": binding["run_attempt"],
        }
        if (type(record) is not dict or set(record) != set(expected) | {"binary_sha256"}
                or any(record.get(key) != value for key, value in expected.items())
                or not SHA256_RE.fullmatch(record.get("binary_sha256", ""))):
            raise ValueError
        binary = directory / "dash"
        digest = _file_sha(binary, record["binary_sha256"])
        if digest != record["binary_sha256"]:
            raise ValueError
        return directory, record
    except Refusal:
        raise
    except BaseException:
        raise Refusal("dash_identity_invalid", "dash_verify") from None


def _probe_dash(directory, binary_sha, uid, home, toolchain, capability):
    script = r'''
import hashlib, os, stat, sys
path, expected = sys.argv[1:]
info = os.stat(path, follow_symlinks=False)
if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o555:
    raise SystemExit(81)
digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
if digest != expected:
    raise SystemExit(82)
os.write(1, ("dash-binary-sha256=" + digest + "\n").encode("ascii"))
'''
    env = {
        "PATH": directory.as_posix() + ":/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home), "TMPDIR": "/tmp", "LANG": "C", "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        checked = capability._run_as_probe_user(
            (toolchain["python"], "-I", "-S", "-B", "-c", script, str(directory / "dash"), binary_sha),
            uid, env=env, timeout=15, failure_reason="native_preflight_unavailable",
            python_executable=toolchain["python"],
        )
        if checked.stdout != ("dash-binary-sha256=" + binary_sha + "\n").encode("ascii") or checked.stderr:
            raise ValueError
        smoke = capability._run_as_probe_user(
            (str(directory / "dash"), "-c",
             "set -eu; value=$(printf '%s' rules); [ \"$value\" = rules ]; printf '%s\\n' 'dash-posix-smoke=passed'"),
            uid, env=env, timeout=15, failure_reason="native_preflight_unavailable",
            python_executable=toolchain["python"],
        )
        if smoke.stdout != b"dash-posix-smoke=passed\n" or smoke.stderr:
            raise ValueError
    except BaseException:
        raise Refusal("dash_identity_invalid", "dash_verify") from None


def prepare_dash(environ=None):
    env = os.environ if environ is None else environ
    reviewed, capability, boundary = _load_control()
    binding, root = _public_context(env, reviewed, capability, boundary)
    _check_temp_root()
    if os.geteuid() != 0:
        raise Refusal("context_unavailable", "context")
    directory = _prep_directory(binding)
    created = False
    toolchain = None
    uid = None
    home_parent = None
    failure = None
    digest = None
    try:
        try:
            os.mkdir(directory, 0o755)
            created = True
            os.chown(directory, 0, 0)
            os.chmod(directory, 0o755)
        except BaseException:
            raise Refusal("storage_unavailable", "storage") from None
        binary = _extract_dash_member(_fetch_bottle())
        _write_new_file(directory / "dash", binary, 0o555)
        digest = _file_sha(directory / "dash")
        try:
            toolchain = capability._resolve_trusted_toolchain()
            uid, home_parent, home = capability._create_probe_identity(root)
            _probe_dash(directory, digest, uid, home, toolchain, capability)
        except Refusal:
            raise
        except BaseException:
            raise Refusal("toolchain_unavailable", "toolchain") from None
        evidence = {
            "schema_version": SCHEMA_VERSION,
            "formula": DASH_FORMULA,
            "version": DASH_VERSION,
            "formula_sha256": DASH_FORMULA_SHA256,
            "bottle_sha256": DASH_BOTTLE_SHA256,
            "binary_sha256": digest,
            "control_sha": binding["control_sha"],
            "run_id": binding["run_id"],
            "run_attempt": binding["run_attempt"],
        }
        raw = (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        _write_new_file(directory / "evidence.json", raw, 0o444)
        _verify_prepared_dash(binding)
    except Refusal as error:
        failure = error
    except BaseException:
        failure = Refusal("internal_error", "dash_archive")
    finally:
        if toolchain is not None and (uid is not None or home_parent is not None):
            try:
                reviewed._cleanup((home_parent,), uid, toolchain)
            except BaseException:
                failure = Refusal("cleanup_incomplete", "cleanup")
        elif uid is not None or home_parent is not None:
            failure = Refusal("cleanup_incomplete", "cleanup")
        if failure is not None and created:
            try:
                shutil.rmtree(directory)
                if directory.exists() or directory.is_symlink():
                    raise OSError("not removed")
            except BaseException:
                failure = Refusal("cleanup_incomplete", "cleanup")
    if failure is not None:
        raise failure
    return {
        "control_sha": binding["control_sha"], "run_id": binding["run_id"],
        "run_attempt": binding["run_attempt"], "version": DASH_VERSION,
        "bottle_sha256": DASH_BOTTLE_SHA256, "binary_sha256": digest,
    }


def _validate_lease_record(record, request, binding, worker_uid, current_uid=None):
    from collections.abc import Mapping

    keys = {
        "repository_id", "source_sha", "base_sha", "base_branch", "concern", "candidate_class",
        "signature", "rules_lock", "tree", "source_execution", "app_build", "cleanup",
        "control_sha", "run_id", "run_attempt", "image_os", "image_version", "repository_scope",
        "metadata", "token_revocation", "signer_authority", "signatures", "ancestry",
        "revocation_policy", "worker_access",
    }
    if not isinstance(record, Mapping) or set(record) != keys:
        raise Refusal("source_lease_unavailable", "source_lease")
    repository_id = record["repository_id"]
    if type(repository_id) not in (int, str) or str(repository_id) in ("", "0"):
        raise Refusal("source_lease_unavailable", "source_lease")
    expected = {
        "source_sha": request["source_sha"],
        "base_sha": request["base_sha"],
        "base_branch": request["base_branch"],
        "concern": CONCERN,
        "signature": "verified",
        "rules_lock": "not-applicable",
        "tree": "rules_regular_files",
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
        "worker_access": "uid_read_only",
    }
    if current_uid is None:
        current_uid = os.getuid() if hasattr(os, "getuid") else 0
    if (any(record[key] != value for key, value in expected.items())
            or record["candidate_class"] not in ("permanent-tip", "signed-descendant")
            or worker_uid <= 0 or worker_uid == current_uid):
        raise Refusal("source_lease_unavailable", "source_lease")


def _validate_source_path(source_path, request, storage_root, reviewed):
    try:
        source = Path(source_path)
        if source.resolve(strict=True) != source or source.is_symlink() or not source.is_dir():
            raise ValueError
        source.relative_to(storage_root)
        info = source.lstat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError
        for relative in REQUIRED_SOURCE_FILES:
            target = source / relative
            target_info = target.lstat()
            if (not stat.S_ISREG(target_info.st_mode) or target_info.st_uid != 0
                    or stat.S_IMODE(target_info.st_mode) & 0o077 or target_info.st_nlink != 1):
                raise ValueError
        git_metadata = source / ".git"
        git_info = git_metadata.lstat()
        if not (stat.S_ISDIR(git_info.st_mode) or stat.S_ISREG(git_info.st_mode)):
            raise ValueError
        git_env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/empty",
            "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        }
        original_cwd = Path.cwd()
        try:
            os.chdir(source)
            git_result = reviewed._run_command(
                ("/usr/bin/git", "-c", "safe.directory=" + str(source), "rev-parse", "--verify", "HEAD"),
                env=git_env, timeout=10, max_output=256, failure_stage="source_identity",
            )
            status = reviewed._run_command(
                ("/usr/bin/git", "-c", "safe.directory=" + str(source), "status", "--porcelain=v1",
                 "--untracked-files=all"),
                env=git_env, timeout=10, max_output=8192, failure_stage="source_identity",
            )
        finally:
            os.chdir(original_cwd)
        if (git_result.returncode != 0 or git_result.stderr
                or git_result.stdout != (request["source_sha"] + "\n").encode("ascii")
                or status.returncode != 0 or status.stderr or status.stdout):
            raise ValueError
        return source
    except Refusal:
        raise
    except BaseException:
        raise Refusal("source_identity_invalid", "source_identity") from None


def _run_tree_probe(source, uid, home, toolchain, capability):
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "TMPDIR": "/tmp",
        "LANG": "C", "LC_ALL": "C",
    }
    try:
        result = capability._run_as_probe_user(
            (toolchain["python"], "-I", "-S", "-B", "-c", TREE_PROBE, str(source)),
            uid, env=env, timeout=60, failure_reason="native_preflight_unavailable",
            python_executable=toolchain["python"],
        )
        if result.stdout != b"source-tree=uid-read-only\n" or result.stderr:
            raise ValueError
    except BaseException:
        raise Refusal("source_tree_invalid", "source_tree") from None


def _summary_guard(uid, home, toolchain, reviewed, capability, root, binding, environ, guard_state):
    try:
        if (not environ.get("GITHUB_STEP_SUMMARY")
                or environ.get("CI_STEP_SUMMARY") != environ.get("GITHUB_STEP_SUMMARY")
                or not environ.get("RUNNER_HOME")):
            raise ValueError
        runner_uid, directories, files = capability._protect_runner_controls(root)
        if runner_uid <= 0 or runner_uid == uid:
            raise ValueError
        guard = reviewed._prepare_runner_summary(uid)
        guard_state["guard"] = guard
        reviewed._run_real_summary_probe(
            guard, uid,
            env=reviewed._child_environment(home, Path("/tmp"), toolchain),
            python_executable=toolchain["python"], binding=binding,
        )
        capability._verify_runner_controls_are_private(
            directories + files, uid, python_executable=toolchain["python"]
        )
        scratch, standin = reviewed._make_control_scratch()
        try:
            expected = b"runner-controls=write-denied summary-standin=write-denied\n"
            reviewed._run_probe_step(
                reviewed._probe_argv(toolchain["python"], SUMMARY_GUARD_SCRIPT, *files, standin),
                uid, env=reviewed._child_environment(home, Path("/tmp"), toolchain),
                python_executable=toolchain["python"], stage="capture", expected_stdout=expected,
            )
            reviewed._assert_standin_unchanged(standin)
        finally:
            capability._remove_probe_tree(scratch)
    except BaseException as error:
        if getattr(error, "reason", None) == "cleanup_incomplete":
            raise Refusal("cleanup_incomplete", "cleanup") from None
        raise Refusal("summary_guard_failed", "summary_guard") from None


def _finish_summary_guard(guard, reviewed, *, worker_cleanup_confirmed):
    if guard is None:
        return
    failed = not worker_cleanup_confirmed
    if worker_cleanup_confirmed:
        try:
            probe_name = guard.get("parent_probe_name")
            if type(probe_name) is str and probe_name:
                reviewed._remove_summary_parent_probe(guard, probe_name)
            reviewed._restore_runner_summary(guard)
        except BaseException:
            failed = True
    try:
        reviewed._close_runner_summary(guard)
    except BaseException:
        failed = True
    if failed:
        raise Refusal("cleanup_incomplete", "cleanup") from None


def _probe_summary_after_commands(guard, uid, home, toolchain, reviewed, capability, binding):
    env = reviewed._child_environment(home, Path("/tmp"), toolchain)
    try:
        presence = capability._probe_uid_processes_present(
            uid, include_survivor_classes=True, python_executable=toolchain["python"]
        )
        present, _ = capability._presence_result(presence)
        if present:
            raise Refusal("cleanup_incomplete", "cleanup")
        reviewed._run_real_summary_probe(
            guard, uid, env=env, python_executable=toolchain["python"], binding=binding
        )
    except Refusal:
        raise
    except BaseException as error:
        if getattr(error, "reason", None) == "cleanup_incomplete":
            raise Refusal("cleanup_incomplete", "cleanup") from None
        raise Refusal("summary_guard_failed", "summary_guard") from None


def _grant_read_acl(path, *, directory):
    rights = (
        "list,search,read,readattr,readextattr,readsecurity"
        if directory else "read,readattr,readextattr,readsecurity"
    )
    result = subprocess.run(
        ("/bin/chmod", "+a", "user:ci-sandbox-probe allow " + rights, str(path)),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10, close_fds=True, check=False,
    )
    if result.returncode != 0 or result.stdout or result.stderr:
        raise Refusal("plan_snapshot_refused", "plan_snapshot")


def _create_plan_snapshot(binding, request, definitions, definitions_sha256, reviewed_diff_sha256, worker_uid, home,
                          toolchain, capability):
    directory = _run_directory(binding).with_name(_run_directory(binding).name + "-ids")
    created = False
    try:
        os.mkdir(directory, 0o700)
        created = True
        os.chown(directory, 0, 0)
        os.chmod(directory, 0o700)
        target = directory / "definitions.md"
        _write_new_file(target, definitions, 0o400)
        _grant_read_acl(directory, directory=True)
        _grant_read_acl(target, directory=False)
        binding_record = {
            "schema_version": SCHEMA_VERSION,
            "control_sha": binding["control_sha"],
            "run_id": binding["run_id"],
            "run_attempt": binding["run_attempt"],
            "source_sha": request["source_sha"],
            "base_sha": request["base_sha"],
            "base_branch": request["base_branch"],
            "definitions_sha256": definitions_sha256,
            "reviewed_diff_sha256": reviewed_diff_sha256,
            "binding_sha256": _binding_digest(request, binding, definitions_sha256, reviewed_diff_sha256),
        }
        raw = (json.dumps(binding_record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        _write_new_file(directory / "binding.json", raw, 0o400)
        _grant_read_acl(directory / "binding.json", directory=False)
        _verify_plan_snapshot(directory, request, binding, definitions_sha256, reviewed_diff_sha256)
        result = capability._run_as_probe_user(
            (toolchain["python"], "-I", "-S", "-B", "-c", SNAPSHOT_PROBE,
             str(directory), str(target), definitions_sha256),
            worker_uid,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "TMPDIR": "/tmp",
                 "LANG": "C", "LC_ALL": "C"},
            timeout=15, failure_reason="native_preflight_unavailable",
            python_executable=toolchain["python"],
        )
        if result.stdout != b"plan-id-snapshot=read-only\n" or result.stderr:
            raise ValueError
        return directory
    except Refusal as error:
        failure = error
    except BaseException:
        failure = Refusal("plan_snapshot_refused", "plan_snapshot")
    if created:
        try:
            shutil.rmtree(directory)
            if directory.exists() or directory.is_symlink():
                raise OSError("not removed")
        except BaseException:
            raise Refusal("cleanup_incomplete", "cleanup") from None
    raise failure


def _verify_plan_snapshot(directory, request, binding, definitions_sha256, reviewed_diff_sha256):
    try:
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError
        definitions_path = directory / "definitions.md"
        definitions_info = definitions_path.lstat()
        if (not stat.S_ISREG(definitions_info.st_mode) or definitions_info.st_uid != 0
                or stat.S_IMODE(definitions_info.st_mode) != 0o400
                or definitions_info.st_nlink != 1 or definitions_info.st_size > MAX_PLAN_BYTES):
            raise ValueError
        if hashlib.sha256(definitions_path.read_bytes()).hexdigest() != definitions_sha256:
            raise ValueError
        binding_record = _strict_json((directory / "binding.json").read_bytes().rstrip(b"\n"))
        expected = {
            "schema_version": SCHEMA_VERSION,
            "control_sha": binding["control_sha"],
            "run_id": binding["run_id"],
            "run_attempt": binding["run_attempt"],
            "source_sha": request["source_sha"],
            "base_sha": request["base_sha"],
            "base_branch": request["base_branch"],
            "definitions_sha256": definitions_sha256,
            "reviewed_diff_sha256": reviewed_diff_sha256,
            "binding_sha256": _binding_digest(request, binding, definitions_sha256, reviewed_diff_sha256),
        }
        if type(binding_record) is not dict or binding_record != expected:
            raise ValueError
    except BaseException:
        raise Refusal("plan_snapshot_refused", "plan_snapshot") from None


def _worker_environment(source, dash_directory, home, storage):
    return {
        "PATH": dash_directory.as_posix() + ":/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home),
        "TMPDIR": str(storage),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": str(source),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _probe_worker_privilege(worker_uid, home, storage, toolchain, reviewed):
    try:
        environment = reviewed._child_environment(home, storage, toolchain)
        reviewed._run_probe_step(
            reviewed._probe_argv(toolchain["python"], reviewed.PRIVILEGE_SCRIPT),
            worker_uid,
            env=environment,
            python_executable=toolchain["python"],
            stage="privilege",
            expected_stdout=reviewed.PRIVILEGE_MARKER,
        )
    except BaseException as error:
        if getattr(error, "reason", None) == "cleanup_incomplete":
            raise Refusal("cleanup_incomplete", "cleanup") from None
        raise Refusal("probe_identity_unavailable", "identity") from None
    return "sudo-denied"


def _observer_refusal(error):
    if getattr(error, "reason", None) == "cleanup_incomplete":
        return Refusal("cleanup_incomplete", "cleanup")
    return Refusal("runner_controls_unavailable", "runner_controls")


def _validate_network_record(record, binding, source_sha):
    keys = {
        "schema_version", "status", "mode", "control_sha", "run_id", "run_attempt", "source_sha",
        "interface_count", "dns_query_count", "tcp_syn_count", "dns_name_hashes",
        "tcp_destination_hashes", "hashes_truncated", "capture_limited", "capture", "cleanup",
        "worker_attribution", "completeness", "network_blocking",
    }
    if type(record) is not dict or set(record) != keys:
        raise Refusal("runner_controls_unavailable", "runner_controls")
    if (type(record["schema_version"]) is not int or record["schema_version"] != 1
            or record["status"] != "observed" or record["mode"] != "host-level"
            or record["control_sha"] != binding["control_sha"]
            or record["run_id"] != binding["run_id"]
            or record["run_attempt"] != binding["run_attempt"]
            or record["source_sha"] != source_sha
            or not _valid_sha(record["control_sha"]) or not _valid_sha(record["source_sha"])
            or not _safe_id(record["run_id"]) or not _safe_id(record["run_attempt"])
            or type(record["status"]) is not str or type(record["mode"]) is not str
            or type(record["interface_count"]) is not int or not 1 <= record["interface_count"] <= 4
            or type(record["dns_query_count"]) is not int
            or not 0 <= record["dns_query_count"] <= 65535
            or type(record["tcp_syn_count"]) is not int or not 0 <= record["tcp_syn_count"] <= 65535
            or type(record["hashes_truncated"]) is not bool
            or type(record["capture_limited"]) is not bool
            or any(type(record[key]) is not str for key in (
                "capture", "cleanup", "worker_attribution", "completeness", "network_blocking",
            ))
            or record["capture"] != "private" or record["cleanup"] != "complete"
            or record["worker_attribution"] != "not-claimed"
            or record["completeness"] != "not-claimed"
            or record["network_blocking"] != "not-claimed"):
        raise Refusal("runner_controls_unavailable", "runner_controls")
    for key in ("dns_name_hashes", "tcp_destination_hashes"):
        values = record[key]
        if (type(values) is not list or len(values) > 16
                or any(type(value) is not str or SHA256_RE.fullmatch(value) is None for value in values)
                or values != sorted(set(values))):
            raise Refusal("runner_controls_unavailable", "runner_controls")
    return record


def _start_network_observation(binding, source_sha):
    try:
        observer = _load_control_sibling("macos_network_observer")
        return observer.start_observation(
            binding["control_sha"], binding["run_id"], binding["run_attempt"], source_sha,
        )
    except BaseException as error:
        raise _observer_refusal(error) from None


def _finish_network_observation(session, binding, source_sha):
    try:
        record = session.finish()
        return _validate_network_record(record, binding, source_sha)
    except Refusal:
        raise
    except BaseException as error:
        raise _observer_refusal(error) from None


def _format_network_observed(record):
    def hashes(key):
        return ",".join(record[key]) or "none"

    return (
        "macos-rules-network=observed schema=1 mode=host-level"
        + " control-sha=" + record["control_sha"]
        + " run-id=" + record["run_id"] + " run-attempt=" + record["run_attempt"]
        + " source-sha=" + record["source_sha"]
        + " interface-count=" + str(record["interface_count"])
        + " dns-query-count=" + str(record["dns_query_count"])
        + " tcp-syn-count=" + str(record["tcp_syn_count"])
        + " dns-name-hashes=" + hashes("dns_name_hashes")
        + " tcp-destination-hashes=" + hashes("tcp_destination_hashes")
        + " hashes-truncated=" + str(record["hashes_truncated"]).lower()
        + " capture-limited=" + str(record["capture_limited"]).lower()
        + " capture=private cleanup=complete worker-attribution=not-claimed"
        + " completeness=not-claimed network-blocking=not-claimed"
    )


def _execute(command, stage, worker_uid, toolchain, environment, capability):
    reason = "plan_ids_failed" if stage == "plan-ids" else "suite_failed"
    try:
        result = capability._run_as_probe_user(
            command, worker_uid, env=environment, timeout=600,
            failure_reason="native_preflight_unavailable", failure_check="probe_process_exit",
            python_executable=toolchain["python"],
        )
        if type(result.returncode) is not int or result.returncode != 0:
            raise ValueError
    except BaseException:
        raise Refusal(reason, stage) from None


def _cleanup_prepared_dash(directory):
    try:
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o755
                or not directory.name.startswith(PREP_PREFIX)):
            raise ValueError
        shutil.rmtree(directory)
        if directory.exists() or directory.is_symlink():
            raise OSError("not removed")
    except BaseException:
        raise Refusal("cleanup_incomplete", "cleanup") from None


def cleanup_dash(environ=None):
    env = os.environ if environ is None else environ
    reviewed, capability, boundary = _load_control()
    binding, _ = _public_context(env, reviewed, capability, boundary)
    _check_temp_root()
    directory = _prep_directory(binding)
    if directory.exists() or directory.is_symlink():
        _cleanup_prepared_dash(directory)
    return {
        "control_sha": binding["control_sha"],
        "run_id": binding["run_id"],
        "run_attempt": binding["run_attempt"],
        "status": "cleaned_or_absent",
    }


def _run_private(request, binding, root, definitions, definitions_sha256, reviewed_diff_sha256,
                 dash_directory, dash_record, reviewed, capability, environ, lifecycle):
    toolchain = None
    worker_uid = None
    home_parent = None
    home = None
    worker_storage = None
    storage_identity = None
    storage_root = _run_directory(binding)
    storage_root_created = False
    snapshot_directory = None
    summary_guard_state = {"guard": None}
    lease_record = None
    runtime = None
    revocation_state = None
    retained_token = lifecycle.get("token_reference")
    privilege_check = None
    completed = []
    failure = None
    worker_cleanup_confirmed = False
    try:
        if os.geteuid() != 0:
            raise Refusal("context_unavailable", "context")
        if getattr(capability, "MAX_CAPTURE_BYTES", None) != MAX_CAPTURE_BYTES:
            raise Refusal("context_unavailable", "context")
        try:
            capability._disable_developer_mode()
        except BaseException:
            raise Refusal("developer_mode_unavailable", "developer_mode") from None
        try:
            toolchain = capability._resolve_trusted_toolchain()
            worker_uid, home_parent, home = capability._create_probe_identity(root)
            os.mkdir(storage_root, 0o700)
            storage_root_created = True
            os.chown(storage_root, 0, 0)
            os.chmod(storage_root, 0o700)
            root_info = storage_root.lstat()
            if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
                    or stat.S_IMODE(root_info.st_mode) != 0o700 or any(storage_root.iterdir())):
                raise ValueError
            worker_storage = Path(tempfile.mkdtemp(prefix="rules-worker-", dir=str(PREP_ROOT)))
            storage_identity = capability._prepare_storage_directory(worker_storage, worker_uid)
            worker_storage = Path(storage_identity[0])
        except BaseException:
            raise Refusal("probe_identity_unavailable", "identity") from None

        _summary_guard(
            worker_uid, home, toolchain, reviewed, capability, root, binding, environ,
            summary_guard_state,
        )

        try:
            runtime = _load_control_sibling("macos_private_validation")
            revocation_state = runtime.RevocationState()
            runtime_request = runtime.parse_request((
                "--source-sha", request["source_sha"],
                "--base-sha", request["base_sha"],
                "--base-branch", request["base_branch"],
                "--concern", CONCERN,
            ))
            if runtime_request != request:
                raise ValueError
            lease_context = runtime.validated_source(
                request, binding, root, environ, worker_uid=worker_uid, storage_root=storage_root,
                revocation_state=revocation_state,
            )
        except Refusal:
            _record_runtime_revocation(
                runtime, revocation_state, retained_token, request, binding, environ, lifecycle,
            )
            raise
        except BaseException as error:
            _record_runtime_revocation(
                runtime, revocation_state, retained_token, request, binding, environ, lifecycle,
            )
            runtime_refusal = getattr(runtime, "Refusal", None)
            if (isinstance(runtime_refusal, type) and isinstance(error, runtime_refusal)
                    and getattr(error, "reason", None) == "cleanup_incomplete"):
                raise Refusal("cleanup_incomplete", "cleanup") from None
            raise Refusal("source_lease_unavailable", "source_lease") from None

        try:
            with lease_context as lease:
                if not _record_runtime_revocation(
                    runtime, revocation_state, retained_token, request, binding, environ, lifecycle,
                ):
                    raise Refusal("source_lease_unavailable", "source_lease")
                _validate_lease_record(lease.record, request, binding, worker_uid)
                source = _validate_source_path(lease.source_path, request, storage_root, reviewed)
                _run_tree_probe(source, worker_uid, home, toolchain, capability)
                privilege_check = _probe_worker_privilege(
                    worker_uid, home, worker_storage, toolchain, reviewed,
                )
                environment = _worker_environment(source, dash_directory, home, worker_storage)
                original_cwd = Path.cwd()
                network_session = _start_network_observation(binding, request["source_sha"])
                commands_started = False
                command_failure = None
                observation_failure = None
                summary_failure = None
                try:
                    os.chdir(source)
                    for suite in SUITES:
                        commands_started = True
                        _execute(("/bin/sh", "ci/run-suite.sh", suite), suite,
                                 worker_uid, toolchain, environment, capability)
                        completed.append(suite)
                    snapshot_directory = _create_plan_snapshot(
                        binding, request, definitions, definitions_sha256, reviewed_diff_sha256,
                        worker_uid, home, toolchain, capability,
                    )
                    commands_started = True
                    _execute(("/bin/sh", "tests/check-plan-ids.sh", str(snapshot_directory)),
                             "plan-ids", worker_uid, toolchain, environment, capability)
                    completed.append("plan-ids")
                except BaseException as error:
                    command_failure = error
                finally:
                    try:
                        os.chdir(original_cwd)
                    except BaseException:
                        command_failure = Refusal("cleanup_incomplete", "cleanup")
                    try:
                        observation = _finish_network_observation(
                            network_session, binding, request["source_sha"],
                        )
                        lifecycle["network_observation_marker"] = _format_network_observed(observation)
                    except BaseException as error:
                        observation_failure = error
                    finally:
                        try:
                            if commands_started:
                                _probe_summary_after_commands(
                                    summary_guard_state["guard"], worker_uid, home, toolchain,
                                    reviewed, capability, binding,
                                )
                        except BaseException as error:
                            summary_failure = error

                if any(getattr(error, "reason", None) == "cleanup_incomplete"
                       for error in (command_failure, observation_failure, summary_failure)
                       if error is not None):
                    raise Refusal("cleanup_incomplete", "cleanup")
                if command_failure is not None:
                    raise command_failure
                if summary_failure is not None:
                    raise summary_failure
                if observation_failure is not None:
                    raise observation_failure
                lease_record = dict(lease.record)
        except Refusal:
            _record_runtime_revocation(
                runtime, revocation_state, retained_token, request, binding, environ, lifecycle,
            )
            raise
        except BaseException as error:
            _record_runtime_revocation(
                runtime, revocation_state, retained_token, request, binding, environ, lifecycle,
            )
            runtime_refusal = getattr(runtime, "Refusal", None)
            if isinstance(runtime_refusal, type) and isinstance(error, runtime_refusal):
                if getattr(error, "reason", None) == "cleanup_incomplete":
                    raise Refusal("cleanup_incomplete", "cleanup") from None
                raise Refusal("source_lease_unavailable", "source_lease") from None
            raise Refusal("cleanup_incomplete", "cleanup") from None

        if completed != list(GATES) or lease_record is None or privilege_check != "sudo-denied":
            raise Refusal("source_lease_unavailable", "source_lease")
        if storage_root.exists() and any(storage_root.iterdir()):
            raise Refusal("cleanup_incomplete", "cleanup")
        capability._verify_storage_directory(worker_storage, storage_identity, worker_uid)
    except Refusal as error:
        failure = error
    except BaseException:
        failure = Refusal("internal_error", "context")
    finally:
        if storage_root_created:
            try:
                if storage_root.exists() and any(storage_root.iterdir()):
                    failure = Refusal("cleanup_incomplete", "cleanup")
            except BaseException:
                failure = Refusal("cleanup_incomplete", "cleanup")
        if toolchain is not None:
            try:
                paths = tuple(path for path in (
                    worker_storage, home_parent, snapshot_directory,
                    storage_root if storage_root_created else None,
                )
                              if path is not None and path.exists())
                reviewed._cleanup(paths, worker_uid, toolchain)
                worker_cleanup_confirmed = True
            except BaseException:
                failure = Refusal("cleanup_incomplete", "cleanup")
        else:
            try:
                for path in (
                    worker_storage, home_parent, snapshot_directory,
                    storage_root if storage_root_created else None,
                ):
                    if path is not None and (path.exists() or path.is_symlink()):
                        capability._remove_probe_tree(path)
                if worker_uid is not None or home_parent is not None:
                    failure = Refusal("cleanup_incomplete", "cleanup")
            except BaseException:
                failure = Refusal("cleanup_incomplete", "cleanup")
        try:
            _finish_summary_guard(
                summary_guard_state["guard"], reviewed,
                worker_cleanup_confirmed=worker_cleanup_confirmed,
            )
        except BaseException:
            failure = Refusal("cleanup_incomplete", "cleanup")
        try:
            _cleanup_prepared_dash(dash_directory)
        except BaseException:
            failure = Refusal("cleanup_incomplete", "cleanup")
    if failure is not None:
        raise failure
    if lease_record is None or completed != list(GATES):
        raise Refusal("cleanup_incomplete", "cleanup")
    return {
        "schema_version": SCHEMA_VERSION,
        "control_sha": binding["control_sha"],
        "run_id": binding["run_id"],
        "run_attempt": binding["run_attempt"],
        "source_sha": request["source_sha"],
        "base_sha": request["base_sha"],
        "base_branch": request["base_branch"],
        "candidate_class": lease_record["candidate_class"],
        "suites": tuple(completed),
        "token_revocation": "confirmed_before_execution",
        "lease_cleanup": "complete",
        "process_cleanup": "complete",
        "identity_cleanup": "complete",
        "summary_guard": "append_sibling_create_readback_restore",
        "source_tree": "uid_read_only",
        "dash_version": DASH_VERSION,
        "dash_bottle_sha256": DASH_BOTTLE_SHA256,
        "dash_binary_sha256": dash_record["binary_sha256"],
        "definitions_sha256": definitions_sha256,
        "reviewed_diff_sha256": reviewed_diff_sha256,
        "definitions_binding_sha256": _binding_digest(
            request, binding, definitions_sha256, reviewed_diff_sha256
        ),
        "same_job_memory": "not_verified",
    }


def _format_success(record):
    required = {
        "schema_version", "control_sha", "run_id", "run_attempt", "source_sha", "base_sha",
        "base_branch", "candidate_class", "suites", "token_revocation", "lease_cleanup",
        "process_cleanup", "identity_cleanup", "summary_guard", "source_tree", "dash_version",
        "dash_bottle_sha256", "dash_binary_sha256", "definitions_sha256",
        "reviewed_diff_sha256", "definitions_binding_sha256", "same_job_memory",
    }
    if type(record) is not dict or set(record) != required or record["schema_version"] != SCHEMA_VERSION:
        raise Refusal("internal_error", "cleanup")
    if (not _valid_sha(record["control_sha"]) or not _valid_sha(record["source_sha"])
            or not _valid_sha(record["base_sha"]) or not _safe_id(record["run_id"])
            or not _safe_id(record["run_attempt"]) or record["base_branch"] not in BASE_BRANCHES
            or record["candidate_class"] not in ("permanent-tip", "signed-descendant")
            or tuple(record["suites"]) != GATES
            or record["token_revocation"] != "confirmed_before_execution"
            or record["lease_cleanup"] != "complete" or record["process_cleanup"] != "complete"
            or record["identity_cleanup"] != "complete"
            or record["summary_guard"] != "append_sibling_create_readback_restore"
            or record["source_tree"] != "uid_read_only" or record["dash_version"] != DASH_VERSION
            or record["dash_bottle_sha256"] != DASH_BOTTLE_SHA256
            or not SHA256_RE.fullmatch(record["dash_binary_sha256"])
            or not SHA256_RE.fullmatch(record["definitions_sha256"])
            or not SHA256_RE.fullmatch(record["reviewed_diff_sha256"])
            or not SHA256_RE.fullmatch(record["definitions_binding_sha256"])
            or record["same_job_memory"] != "not_verified"):
        raise Refusal("internal_error", "cleanup")
    return (
        "macos-rules-bootstrap=passed schema=1"
        + " control-sha=" + record["control_sha"]
        + " run-id=" + record["run_id"] + " run-attempt=" + record["run_attempt"]
        + " source-sha=" + record["source_sha"] + " base-sha=" + record["base_sha"]
        + " base-branch=" + record["base_branch"] + " candidate-class=" + record["candidate_class"]
        + " suites=rules.hooks,rules.sync,rules.static,rules.public,plan-ids"
        + " token-revocation=confirmed-before-execution lease-cleanup=complete"
        + " process-cleanup=complete identity-cleanup=complete"
        + " summary-guard=append-sibling-create-readback-restore"
        + " source-tree=uid-read-only dash-version=" + DASH_VERSION
        + " dash-bottle-sha256=" + record["dash_bottle_sha256"]
        + " dash-binary-sha256=" + record["dash_binary_sha256"]
        + " reviewed-diff-sha256=" + record["reviewed_diff_sha256"]
        + " same-job-memory=not-verified"
    )


def _format_refusal(error, environ, lifecycle=None):
    reason = error.reason if type(error) is Refusal else "internal_error"
    stage = error.stage if type(error) is Refusal else "context"
    control = environ.get("CI_SHA", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    if not _valid_sha(control):
        control = "unknown"
    if not _safe_id(run_id):
        run_id = "unknown"
    if not _safe_id(attempt):
        attempt = "unknown"
    token_revocation = "not-read"
    if type(lifecycle) is dict:
        value = lifecycle.get("token_revocation", "not-read")
        if value in ("not-read", "confirmed", "unconfirmed"):
            token_revocation = value
        else:
            token_revocation = "unconfirmed"
    line = (
        "macos-rules-bootstrap=refused schema=1 reason=" + reason + " stage=" + stage
        + " control-sha=" + control + " run-id=" + run_id + " run-attempt=" + attempt
        + " token-revocation=" + token_revocation
    )
    if (type(error) is Refusal and reason == "dash_bottle_invalid"
            and stage == "dash_archive_formula_digest_mismatch"
            and error.verified_bottle_sha256 == DASH_BOTTLE_SHA256
            and type(error.embedded_formula_sha256) is str
            and SHA256_RE.fullmatch(error.embedded_formula_sha256)):
        line += " embedded-formula-sha256=" + error.embedded_formula_sha256
    return line


def _validate_cli(argv):
    if type(argv) not in (tuple, list) or not argv:
        raise Refusal("invalid_input", "arguments")
    if argv[0] == "prepare-dash" and len(argv) == 1:
        return "prepare-dash", None, False
    if argv[0] == "cleanup-dash" and len(argv) == 1:
        return "cleanup-dash", None, False
    if argv[0] == "preflight":
        return "preflight", _parse_request(argv[1:]), False
    if argv[0] == "run" and len(argv) >= 2 and argv[1] == "--token-stdin":
        return "run", _parse_request(argv[2:]), True
    raise Refusal("invalid_input", "arguments")


def _read_token_stdin(lifecycle):
    lifecycle["token_revocation"] = "unconfirmed"
    try:
        raw = sys.stdin.buffer.read(4097)
    except BaseException:
        raise Refusal("invalid_input", "arguments") from None
    candidate = raw
    for delimiter in (b"\n", b"\r"):
        if delimiter in candidate:
            candidate = candidate.split(delimiter, 1)[0]
    if type(candidate) is bytes and 1 <= len(candidate) <= 4096 and all(33 <= item <= 126 for item in candidate):
        lifecycle["token_reference"] = candidate.decode("ascii")
    if type(raw) is not bytes or not 1 <= len(raw) <= 4096:
        raise Refusal("invalid_input", "arguments")
    try:
        token = raw.decode("ascii")
    except UnicodeDecodeError:
        raise Refusal("invalid_input", "arguments") from None
    if TOKEN_RE.fullmatch(token) is None:
        raise Refusal("invalid_input", "arguments")
    lifecycle["token_reference"] = token
    return token


def _run(mode, request, token_stdin, environ, lifecycle):
    if mode != "run" and environ.get("SOURCE_READER_TOKEN", ""):
        raise Refusal("control_identity_invalid", "context")
    if mode == "run" and environ.get("SOURCE_READER_TOKEN", ""):
        raise Refusal("control_identity_invalid", "context")
    if mode == "prepare-dash":
        return prepare_dash(environ)
    if mode == "cleanup-dash":
        return cleanup_dash(environ)
    reviewed, capability, boundary = _load_control()
    binding, root = _public_context(environ, reviewed, capability, boundary)
    definitions, definitions_sha256, reviewed_diff_sha256 = _validate_bootstrap_gate(request, binding, environ)
    dash_directory, dash_record = _verify_prepared_dash(binding)
    if mode == "preflight":
        return {
            "control_sha": binding["control_sha"], "run_id": binding["run_id"],
            "run_attempt": binding["run_attempt"], "source_sha": request["source_sha"],
            "base_sha": request["base_sha"], "base_branch": request["base_branch"],
            "dash_version": DASH_VERSION, "dash_bottle_sha256": DASH_BOTTLE_SHA256,
            "dash_binary_sha256": dash_record["binary_sha256"], "definitions_sha256": definitions_sha256,
            "reviewed_diff_sha256": reviewed_diff_sha256,
        }
    if not token_stdin:
        raise Refusal("invalid_input", "arguments")
    if not _safe_id(environ.get("SOURCE_REPOSITORY_ID", "")):
        raise Refusal("bootstrap_gate_refused", "bootstrap_gate")
    token = _read_token_stdin(lifecycle)
    runtime_environment = dict(environ)
    runtime_environment["SOURCE_READER_TOKEN"] = token
    return _run_private(
        request, binding, root, definitions, definitions_sha256, reviewed_diff_sha256,
        dash_directory, dash_record, reviewed, capability, runtime_environment, lifecycle,
    )


def main(argv=None, environ=None):
    args = sys.argv[1:] if argv is None else argv
    env = os.environ if environ is None else environ
    lifecycle = {
        "token_revocation": "not-read",
        "token_reference": None,
        "network_observation_marker": None,
    }
    legacy_token_present = "SOURCE_READER_TOKEN" in env
    legacy_token = env.pop("SOURCE_READER_TOKEN", None) if legacy_token_present else None
    if legacy_token_present:
        lifecycle["token_revocation"] = "unconfirmed"
        if type(legacy_token) is str and TOKEN_RE.fullmatch(legacy_token) is not None:
            lifecycle["token_reference"] = legacy_token
    try:
        if legacy_token_present:
            raise Refusal("control_identity_invalid", "context")
        mode, request, token_stdin = _validate_cli(args)
        result = _run(mode, request, token_stdin, env, lifecycle)
        if mode == "run" and lifecycle["token_revocation"] != "confirmed":
            raise Refusal("source_lease_unavailable", "source_lease")
        if mode == "prepare-dash":
            line = (
                "macos-rules-dash=prepared version=" + result["version"]
                + " bottle-sha256=" + result["bottle_sha256"]
                + " binary-sha256=" + result["binary_sha256"]
                + " control-sha=" + result["control_sha"]
                + " run-id=" + result["run_id"] + " run-attempt=" + result["run_attempt"]
            )
        elif mode == "cleanup-dash":
            line = (
                "macos-rules-dash=cleanup-complete"
                + " control-sha=" + result["control_sha"]
                + " run-id=" + result["run_id"] + " run-attempt=" + result["run_attempt"]
            )
        elif mode == "preflight":
            line = (
                "macos-rules-bootstrap=preflight-passed schema=1"
                + " control-sha=" + result["control_sha"]
                + " run-id=" + result["run_id"] + " run-attempt=" + result["run_attempt"]
                + " source-sha=" + result["source_sha"] + " base-sha=" + result["base_sha"]
                + " base-branch=" + result["base_branch"] + " dash-version=" + result["dash_version"]
                + " dash-bottle-sha256=" + result["dash_bottle_sha256"]
                + " dash-binary-sha256=" + result["dash_binary_sha256"]
                + " reviewed-diff-sha256=" + result["reviewed_diff_sha256"]
            )
        else:
            line = _format_success(result)
        if mode == "run":
            observed = lifecycle["network_observation_marker"]
            if type(observed) is not str or not observed.startswith("macos-rules-network=observed "):
                raise Refusal("runner_controls_unavailable", "runner_controls")
            line = observed + "\n" + line
        print(line)
        return 0
    except Refusal as error:
        if lifecycle["token_revocation"] == "unconfirmed" and lifecycle["token_reference"] is not None:
            try:
                if _revoke_pending_token(env, lifecycle["token_reference"]):
                    lifecycle["token_revocation"] = "confirmed"
                    lifecycle["token_reference"] = None
            except Refusal:
                pass
        refusal = _format_refusal(error, env, lifecycle)
        observed = lifecycle["network_observation_marker"]
        if type(observed) is str and observed.startswith("macos-rules-network=observed "):
            refusal = observed + "\n" + refusal
        print(refusal)
        return 1
    except BaseException:
        if lifecycle["token_revocation"] == "unconfirmed" and lifecycle["token_reference"] is not None:
            try:
                if _revoke_pending_token(env, lifecycle["token_reference"]):
                    lifecycle["token_revocation"] = "confirmed"
                    lifecycle["token_reference"] = None
            except Refusal:
                pass
        refusal = _format_refusal(Refusal("internal_error", "context"), env, lifecycle)
        observed = lifecycle["network_observation_marker"]
        if type(observed) is str and observed.startswith("macos-rules-network=observed "):
            refusal = observed + "\n" + refusal
        print(refusal)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

