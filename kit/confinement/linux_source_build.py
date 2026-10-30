import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import linux_harness
import linux_channels
import linux_probes
import linux_session
import rust_license_gate


REPOSITORY = "keeldock-platform/platform-ci"
WORKFLOW_PATH = ".github/workflows/linux-source-admission.yml"
API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
TOOLCHAIN_ROOT = Path("/tmp/kd-toolchains")
PROJECT_ROOT = Path("/tmp/kd-project-worker")
NODE_VERSION = "24.22.1"
NPM_VERSION = "11.19.1"
NODE_LINUX_TARBALL_SHA256 = "COORDINATOR_FILL_NODE_LINUX_TARBALL_24_22_1_SHA256"
SYNTHETIC_LOG_CANARY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SOURCE_SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
IMAGE_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
OWNER_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
GATES = (
    "format", "clippy", "workspace_tests", "api_tests", "mock_tests", "conformance_tests",
    "parser_format", "parser_clippy", "parser_replay", "node_dependency_prepare",
    "node_dependency_audit", "typescript_typecheck", "typescript_tests",
)
RUNTIME_GATE_NAMES = ("runtime_format", "runtime_clippy", "runtime_tests")
RUNTIME_ROOT_FILES = ("runtime/Cargo.toml", "runtime/Cargo.lock")
MAX_LOCK_DIRECTORIES = 100000
MAX_DIRECTORY_ENTRIES = 8192
MAX_TREE_ENTRIES = 1000000
MAX_PENDING_DIRECTORIES = 8192
RUST_COMPONENTS = (
    ("rust-std", "https://static.rust-lang.org/dist/2026-10-15/rust-std-1.99.1-x86_64-unknown-linux-gnu.tar.gz", "d1290c05994a59c029e562cb75be1bddc6fb11a4c501e1b7b0f61d119c6cbb12"),
    ("rustc", "https://static.rust-lang.org/dist/2026-10-15/rustc-1.99.1-x86_64-unknown-linux-gnu.tar.gz", "85e7c0e6f21636f714e2a42966011364a6cc56b6548126d32144d6ba90904966"),
    ("cargo", "https://static.rust-lang.org/dist/2026-10-15/cargo-1.99.1-x86_64-unknown-linux-gnu.tar.gz", "47babc028247e26577f8a1bf390b11f447ad9b7ab93f5c9a0dda078935fc149b"),
    ("rustfmt-preview", "https://static.rust-lang.org/dist/2026-10-15/rustfmt-1.99.1-x86_64-unknown-linux-gnu.tar.gz", "e3a88008061f485126fe24569c4d3e5a0f49462a06ee6339920f8f202124b13a"),
    ("clippy-preview", "https://static.rust-lang.org/dist/2026-10-15/clippy-1.99.1-x86_64-unknown-linux-gnu.tar.gz", "3c6d008544b6e456cc785c86f8ce3713f0d845b94be3a6c8a34662b8504561b5"),
)
PROVENANCE_FIELDS = frozenset((
    "schema_version", "status", "generation_identity", "accepted_source_identity", "lock_sha256",
    "manifest_sha256", "node_version", "npm_version", "release_age_days", "policy_epoch_ms",
    "cutoff_epoch_ms", "age_status", "generation_attempts", "audit_endpoint", "audit_status",
    "accepted_at_ms",
))
IDENTITY_FIELDS = ("source_sha", "base_sha", "control_sha", "reviewed_diff_sha256")
MANIFEST_GROUPS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
MANIFEST_PACKAGE_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$")
MANIFEST_VERSION_RE = re.compile(r"^[0-9A-Za-z.*^~<>=|+ -]{1,128}$")
MANIFEST_WORKSPACE_VERSION_RE = re.compile(r"workspace:(?:\*|\^|~|[0-9][0-9A-Za-z.+-]*)")
MAX_PACKAGE_JSON_BYTES = 256 * 1024
SOURCE_STEP_NAMES = (
    "Fetch exact public control",
    "Repeat preflight in source-read",
    "Record image and fetch pinned Rust and Node toolchains",
    "Harden runner paths before the proof",
    "Boundary self-test before source-reader mint",
    "Mint scoped source-reader token",
    "Verify selected installation identity",
    "Fetch exact source and verify binding, tree, signatures and lock provenance",
    "Revoke source-reader token and verify rejection",
    "Require trusted Rust licence admission",
    "Fetch npm tarballs by committed lock integrity",
    "Run trusted dependency audit",
    "Prepare offline project inputs",
    "Re-run positive controls immediately before the first project command",
    "Run all thirteen offline project gates",
    "Merge confinement phase records",
    "Forced faults must fail closed",
)
VERDICT_STEP_NAMES = (
    "Fetch exact public control",
    "Repeat independent preflight",
    "Record verifier image and fetch pinned toolchains",
    "Harden verifier runner paths",
    "Run independent boundary self-test",
    "Mint verifier scoped source-reader token",
    "Verify source independently against binding, tree, signatures and lock",
    "Revoke verifier token and verify rejection",
    "Require trusted Rust licence admission independently",
    "Fetch independent npm tarballs by lock integrity",
    "Run independent trusted dependency audit",
    "Prepare independent offline project inputs",
    "Re-run independent positive controls before project execution",
    "Run independent thirteen offline project gates",
    "Merge independent confinement records",
    "Verify unprivileged proof handoff",
    "Publish confinement verdict",
)
OPTIONAL_VERDICT_SYNTHETIC_STEPS = (
    "Mint verifier scoped source-reader token",
    "Verify source independently against binding, tree, signatures and lock",
    "Revoke verifier token and verify rejection",
    "Require trusted Rust licence admission independently",
    "Fetch independent npm tarballs by lock integrity",
    "Run independent trusted dependency audit",
    "Prepare independent offline project inputs",
    "Run independent thirteen offline project gates",
)
SETTINGS_STEP_NAMES = (
    "Fetch exact public control",
    "Prepare audit identity",
    "Snapshot cache inventory and validate preflight",
)
UNIT_STEP_NAMES = (
    "Fetch exact public control",
    "Run unprivileged source-free checks",
)
OPTIONAL_SOURCE_STEPS = frozenset((
    "Mint scoped source-reader token",
    "Verify selected installation identity",
    "Fetch exact source and verify binding, tree, signatures and lock provenance",
    "Revoke source-reader token and verify rejection",
    "Require trusted Rust licence admission",
    "Fetch npm tarballs by committed lock integrity",
    "Run trusted dependency audit",
    "Prepare offline project inputs",
    "Run all thirteen offline project gates",
    "Forced faults must fail closed",
))


class SourceBuildRefusal(Exception):
    def __init__(self, reason="invalid"):
        self.reason = reason if reason in {
            "identity", "freshness", "untrusted", "source", "binding", "duplicate",
            "cache", "toolchain", "hash_mismatch", "token", "checkout", "signature",
            "revocation", "lock", "registry", "network", "gate", "boundary", "audit",
        } else "invalid"
        super().__init__(self.reason)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _api_request(path, token, method="GET", payload=None, expected=(200,)):
    if type(path) is not str or not path.startswith("/") or ".." in path:
        raise SourceBuildRefusal("network")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "User-Agent": "kd-linux-source-read",
        "X-GitHub-Api-Version": API_VERSION,
    }
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(API_ROOT + path, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=20) as response:
            status = response.status
            body = response.read(8 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        body = b""
    except (OSError, urllib.error.URLError):
        raise SourceBuildRefusal("network") from None
    if status not in expected or len(body) > 8 * 1024 * 1024:
        raise SourceBuildRefusal("network")
    if status in (204, 401, 403):
        return status, None
    try:
        value = json.loads(body.decode("utf-8")) if body else None
    except (UnicodeError, ValueError):
        raise SourceBuildRefusal("network") from None
    return status, value


def _reference_sha(token, repository, branch):
    status, payload = _api_request(
        "/repos/" + repository + "/git/ref/heads/" + urllib.parse.quote(branch, safe="/"), token,
        expected=(200, 404),
    )
    if status == 404:
        return None
    target = payload.get("object") if type(payload) is dict else None
    sha = target.get("sha") if type(target) is dict else None
    if type(sha) is not str or SOURCE_SHA_RE.fullmatch(sha) is None:
        raise SourceBuildRefusal("network")
    return sha


def _comparison(token, repository, base, head):
    status, payload = _api_request(
        "/repos/" + repository + "/compare/" + base + "..." + head, token,
        expected=(200, 404),
    )
    if status == 404 or type(payload) is not dict:
        return "unavailable"
    state = payload.get("status")
    return state if state in ("ahead", "behind", "identical", "diverged") else "unavailable"


def _source_inputs(environ):
    source_sha = environ.get("REQUESTED_SOURCE_SHA", "")
    base_sha = environ.get("REQUESTED_BASE_SHA", "")
    base_branch = environ.get("REQUESTED_BASE_BRANCH", "")
    fingerprint = environ.get("REQUESTED_FINGERPRINT", "")
    control_sha = environ.get("CI_SHA", "")
    if (SOURCE_SHA_RE.fullmatch(source_sha) is None or SOURCE_SHA_RE.fullmatch(base_sha) is None
            or base_branch not in ("main", "develop", "uat")
            or HEX64_RE.fullmatch(fingerprint) is None or SOURCE_SHA_RE.fullmatch(control_sha) is None):
        raise SourceBuildRefusal("binding")
    values = {
        "LINUX_SOURCE_ALLOWED_SHA": source_sha,
        "LINUX_SOURCE_ALLOWED_BASE_SHA": base_sha,
        "LINUX_SOURCE_ALLOWED_BASE_BRANCH": base_branch,
        "LINUX_SOURCE_ALLOWED_FINGERPRINT": fingerprint,
        "LINUX_SOURCE_ALLOWED_CONTROL_SHA": control_sha,
    }
    if any(environ.get(name) != value for name, value in values.items()):
        raise SourceBuildRefusal("binding")
    for name in (
        "SOURCE_REPOSITORY_ID", "SOURCE_REPOSITORY_OWNER", "SOURCE_REPOSITORY_NAME",
        "SOURCE_READER_INSTALLATION_ID", "SOURCE_READER_CLIENT_ID",
        "LINUX_SOURCE_ACCEPTED_NODE_LOCK_SHA256", "LINUX_SOURCE_ACCEPTED_MANIFEST_SHA256",
        "LINUX_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON", "LINUX_SOURCE_ENVIRONMENT_NAME",
    ):
        if not environ.get(name):
            raise SourceBuildRefusal("binding")
    if (DECIMAL_RE.fullmatch(environ["SOURCE_REPOSITORY_ID"]) is None
            or DECIMAL_RE.fullmatch(environ["SOURCE_READER_INSTALLATION_ID"]) is None
            or not OWNER_RE.fullmatch(environ["SOURCE_REPOSITORY_OWNER"])
            or not OWNER_RE.fullmatch(environ["SOURCE_REPOSITORY_NAME"])
            or HEX64_RE.fullmatch(environ["LINUX_SOURCE_ACCEPTED_NODE_LOCK_SHA256"]) is None
            or HEX64_RE.fullmatch(environ["LINUX_SOURCE_ACCEPTED_MANIFEST_SHA256"]) is None):
        raise SourceBuildRefusal("binding")
    if (environ.get("REQUESTED_ENVIRONMENT_NAME") != environ["LINUX_SOURCE_ENVIRONMENT_NAME"]
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", environ["LINUX_SOURCE_ENVIRONMENT_NAME"]) is None):
        raise SourceBuildRefusal("binding")
    identity = {
        "source_sha": source_sha,
        "base_sha": base_sha,
        "base_branch": base_branch,
        "reviewed_diff_sha256": fingerprint,
        "control_sha": control_sha,
        "repository_id": environ["SOURCE_REPOSITORY_ID"],
        "owner": environ["SOURCE_REPOSITORY_OWNER"],
        "name": environ["SOURCE_REPOSITORY_NAME"],
    }
    _validate_provenance_binding(identity, environ)
    return identity


def validate_dispatch(environ, api_token=None):
    if (environ.get("CI_EVENT_NAME") != "workflow_dispatch"
            or environ.get("CI_REPOSITORY") != REPOSITORY
            or environ.get("CI_SERVER_URL") != "https://github.com"
            or environ.get("CACHE_MODE") != "none"
            or environ.get("CI_SHA") != environ.get("GITHUB_SHA")):
        raise SourceBuildRefusal("identity")
    ref = environ.get("CI_REF", "")
    if ref not in ("refs/heads/main", "refs/heads/untrusted"):
        raise SourceBuildRefusal("identity")
    if api_token is None:
        api_token = environ.get("GITHUB_TOKEN", "")
    if not api_token:
        raise SourceBuildRefusal("identity")
    live_main = _reference_sha(api_token, REPOSITORY, "main")
    live_untrusted = _reference_sha(api_token, REPOSITORY, "untrusted")
    if live_main is None:
        raise SourceBuildRefusal("freshness")
    if ref == "refs/heads/main" and live_main != environ.get("CI_SHA"):
        raise SourceBuildRefusal("freshness")
    if live_untrusted is None or _comparison(api_token, REPOSITORY, live_untrusted, live_main) not in ("ahead", "identical"):
        raise SourceBuildRefusal("untrusted")
    if ref == "refs/heads/untrusted" and live_untrusted != environ.get("CI_SHA"):
        raise SourceBuildRefusal("freshness")
    mode = environ.get("CI_MODE", "")
    if mode == "synthetic":
        if ref != "refs/heads/main":
            raise SourceBuildRefusal("identity")
        return "synthetic"
    if mode != "source":
        raise SourceBuildRefusal("identity")
    identity = _source_inputs(environ)
    _require_no_duplicate(api_token, environ)
    return "source"


def _require_no_duplicate(token, environ):
    run_id = environ.get("GITHUB_RUN_ID", "")
    source_sha = environ.get("REQUESTED_SOURCE_SHA", "")
    title = "Linux admission source " + source_sha
    base = "/repos/" + REPOSITORY + "/actions/workflows/linux-source-admission.yml/runs?per_page=100&status="
    for active_status in ("queued", "in_progress"):
        status, payload = _api_request(base + active_status, token)
        runs = payload.get("workflow_runs") if type(payload) is dict else None
        if (type(runs) is not list or len(runs) > 100
                or type(payload.get("total_count")) is not int or payload["total_count"] > len(runs)):
            raise SourceBuildRefusal("duplicate")
        for run in runs:
            if type(run) is not dict:
                raise SourceBuildRefusal("duplicate")
            if (str(run.get("id")) != run_id and run.get("display_title") == title
                    and run.get("status") == active_status
                    and run.get("event") == "workflow_dispatch"):
                raise SourceBuildRefusal("duplicate")


def _audit_modules():
    try:
        import confinement_public_audit
        import confinement_verdict
        import log_canary
        from confinement_verdict import CHANNELS
    except ImportError:
        from . import confinement_public_audit, confinement_verdict, log_canary
        from .confinement_verdict import CHANNELS
    if tuple(linux_channels.CHANNELS) != tuple(CHANNELS):
        raise SourceBuildRefusal("boundary")
    return confinement_public_audit, confinement_verdict, log_canary


def _expected_run(environ, cache_digest):
    audit, unused_verdict, unused_canary = _audit_modules()
    mode = environ.get("CI_MODE", "")
    if mode not in ("source", "synthetic"):
        mode = "source"
    source_sha = environ.get("REQUESTED_SOURCE_SHA", "")
    title = "Linux admission source " + (source_sha or "synthetic") if mode == "source" else "Linux admission synthetic synthetic"
    ci_ref = environ.get("CI_REF", "refs/heads/main").removeprefix("refs/heads/")
    if ci_ref not in ("main", "untrusted"):
        ci_ref = "main"
    all_steps = list(SOURCE_STEP_NAMES)
    if mode == "source":
        all_steps.append("Post Mint scoped source-reader token")
        optional = ("Forced faults must fail closed",)
    else:
        optional = tuple(sorted(OPTIONAL_SOURCE_STEPS - {"Forced faults must fail closed"}))
    expected = {
        "repository": REPOSITORY,
        "os": "linux",
        "mode": "candidate" if mode == "source" else "synthetic",
        "control_sha": environ.get("CI_SHA", "0" * 40),
        "run_id": int(environ.get("GITHUB_RUN_ID", "1")) if DECIMAL_RE.fullmatch(environ.get("GITHUB_RUN_ID", "")) else 1,
        "run_attempt": int(environ.get("GITHUB_RUN_ATTEMPT", "1")) if DECIMAL_RE.fullmatch(environ.get("GITHUB_RUN_ATTEMPT", "")) else 1,
        "workflow_path": WORKFLOW_PATH,
        "ci_ref": ci_ref,
        "display_title": title,
        "jobs": {
            "linux-source-admission-settings": {"steps": SETTINGS_STEP_NAMES, "optional_steps": ()},
            "linux-source-admission-unit": {"steps": UNIT_STEP_NAMES, "optional_steps": ()},
            "linux-source-admission-source-read": {"steps": tuple(all_steps), "optional_steps": tuple(optional)},
            "linux-source-admission-verdict": {
                "steps": VERDICT_STEP_NAMES,
                "optional_steps": OPTIONAL_VERDICT_SYNTHETIC_STEPS if mode == "synthetic" else (),
            },
        },
        "verdict_job": "linux-source-admission-verdict",
        "verdict_step": "Publish confinement verdict",
        "auditor_job": "linux-source-admission-audit",
        "artifact_names": (),
        "cache_digest": cache_digest if HEX64_RE.fullmatch(cache_digest or "") else "0" * 64,
    }
    audit.validate_expected(expected)
    return expected


def _write_output(environ, values):
    path = environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "at", encoding="ascii") as sink:
        for key, value in values.items():
            sink.write(key + "=" + value + "\n")


def mint_verifier_token(environ=None):
    env = os.environ if environ is None else environ
    identity = _source_inputs(env)
    client_id = env.get("SOURCE_READER_CLIENT_ID", "")
    installation_id = env.get("SOURCE_READER_INSTALLATION_ID", "")
    private_key = env.get("SOURCE_READER_PRIVATE_KEY", "")
    if (re.fullmatch(r"[A-Za-z0-9_.-]{3,100}", client_id) is None
            or DECIMAL_RE.fullmatch(installation_id) is None
            or not private_key.startswith("-----BEGIN ")
            or len(private_key) > 16384):
        raise SourceBuildRefusal("token")
    now = int(time.time())
    header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=")
    claims = json.dumps({"iat": now - 60, "exp": now + 540, "iss": client_id}, separators=(",", ":")).encode("ascii")
    payload = base64.urlsafe_b64encode(claims).rstrip(b"=")
    signing_input = header + b"." + payload
    descriptor = -1
    try:
        descriptor = os.memfd_create("kd-app-key", os.MFD_CLOEXEC)
        key_bytes = private_key.encode("ascii")
        if os.write(descriptor, key_bytes) != len(key_bytes):
            raise SourceBuildRefusal("token")
        os.lseek(descriptor, 0, os.SEEK_SET)
        signed = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-sign", "/proc/self/fd/" + str(descriptor)],
            input=signing_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, check=False, pass_fds=(descriptor,),
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise SourceBuildRefusal("token") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if signed.returncode != 0 or len(signed.stdout) < 64 or len(signed.stdout) > 1024:
        raise SourceBuildRefusal("token")
    jwt = signing_input.decode("ascii") + "." + base64.urlsafe_b64encode(signed.stdout).rstrip(b"=").decode("ascii")
    unused, installation = _api_request("/app/installations/" + installation_id, jwt)
    account = installation.get("account") if type(installation) is dict else None
    if (type(installation) is not dict or installation.get("id") != int(installation_id)
            or type(account) is not dict or type(account.get("login")) is not str
            or account["login"].lower() != identity["owner"].lower()):
        raise SourceBuildRefusal("token")
    unused, issued = _api_request(
        "/app/installations/" + installation_id + "/access_tokens", jwt, method="POST",
        payload={"repositories": [identity["name"]], "permissions": {"contents": "read"}}, expected=(201,),
    )
    token = issued.get("token") if type(issued) is dict else None
    if type(token) is not str or re.fullmatch(r"[A-Za-z0-9_]{20,1024}", token) is None:
        raise SourceBuildRefusal("token")
    permissions = issued.get("permissions")
    if (type(permissions) is not dict or permissions.get("contents") != "read"
            or set(permissions) - {"contents", "metadata"}
            or any(value != "read" for value in permissions.values())):
        raise SourceBuildRefusal("token")
    unused, repositories = _api_request("/installation/repositories?per_page=100", token)
    entries = repositories.get("repositories") if type(repositories) is dict else None
    if (type(entries) is not list or len(entries) != 1 or repositories.get("total_count") != 1
            or type(entries[0]) is not dict or entries[0].get("id") != int(identity["repository_id"])
            or entries[0].get("name") != identity["name"]):
        raise SourceBuildRefusal("token")
    sys.stdout.write("::add-mask::" + token + "\n")
    sys.stdout.flush()
    _write_output(env, {"token": token, "installation_id": installation_id})
    sys.stdout.write("linux-verifier-token=issued installation=verified scope=one-repository\n")
    return 0


def snapshot_and_preflight(environ=None):
    env = os.environ if environ is None else environ
    try:
        audit, unused_verdict, unused_canary = _audit_modules()
        expected = _expected_run(env, "0" * 64)
        _write_output(env, {"expected": json.dumps(expected, sort_keys=True, separators=(",", ":"))})
        token = env.get("GITHUB_TOKEN", "")
        api = audit._default_api_factory(token, REPOSITORY)
        caches = audit._collect_caches(api, REPOSITORY)
        digest = audit.cache_inventory_digest(caches)
        expected = _expected_run(env, digest)
        _write_output(env, {
            "cache_digest": digest,
            "expected": json.dumps(expected, sort_keys=True, separators=(",", ":")),
        })
        state = validate_dispatch(env, token)
        sys.stdout.write("linux-source-settings=verified mode=" + state + " cache=snapped\n")
        return 0
    except SourceBuildRefusal as error:
        sys.stdout.write("linux-source-settings=refused reason=" + error.reason + "\n")
        return 1
    except Exception:
        sys.stdout.write("linux-source-settings=refused reason=invalid\n")
        return 1


def write_audit_identity(environ=None):
    env = os.environ if environ is None else environ
    try:
        expected = _expected_run(env, "0" * 64)
        _write_output(env, {"expected": json.dumps(expected, sort_keys=True, separators=(",", ":"))})
        sys.stdout.write("linux-source-audit-identity=prepared\n")
        return 0
    except BaseException:
        sys.stdout.write("linux-source-audit-identity=unavailable\n")
        return 1


def repeat_preflight(environ=None):
    env = os.environ if environ is None else environ
    try:
        mode = validate_dispatch(env)
        sys.stdout.write("linux-source-preflight=verified mode=" + mode + " cache-mode=none\n")
        return 0
    except SourceBuildRefusal as error:
        sys.stdout.write("linux-source-preflight=refused reason=" + error.reason + "\n")
        return 1
    except Exception:
        sys.stdout.write("linux-source-preflight=refused reason=invalid\n")
        return 1


def _download(url, expected_sha, destination, maximum):
    if HEX64_RE.fullmatch(expected_sha or "") is None:
        raise SourceBuildRefusal("toolchain")
    request = urllib.request.Request(url, headers={"User-Agent": "kd-linux-source-build"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    digest = hashlib.sha256()
    size = 0
    try:
        with opener.open(request, timeout=60) as response, open(destination, "wb") as target:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > maximum:
                    raise SourceBuildRefusal("network")
                digest.update(block)
                target.write(block)
    except SourceBuildRefusal:
        raise
    except (OSError, urllib.error.URLError):
        raise SourceBuildRefusal("network") from None
    if not size or digest.hexdigest() != expected_sha:
        try:
            os.unlink(destination)
        except OSError:
            pass
        raise SourceBuildRefusal("hash_mismatch")
    os.chmod(destination, 0o400)
    return digest.hexdigest()


def _safe_tar_member(name):
    if type(name) is not str or not name or name.startswith("/") or "\\" in name or "\x00" in name:
        return False
    if name.endswith("/"):
        name = name[:-1]
        if not name or name.endswith("/"):
            return False
    parts = name.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def _safe_tar_link(name):
    return (type(name) is str and bool(name) and not name.startswith("/")
            and "\\" not in name and "\x00" not in name)


def _extract_tar(archive_path, destination, mode):
    root = Path(destination).resolve()
    os.makedirs(root, mode=0o755, exist_ok=True)
    try:
        archive = tarfile.open(archive_path, mode)
    except (OSError, tarfile.TarError):
        raise SourceBuildRefusal("toolchain") from None
    with archive:
        members = archive.getmembers()
        if not members or len(members) > 200000:
            raise SourceBuildRefusal("toolchain")
        pending_links = []
        for member in members:
            if not _safe_tar_member(member.name):
                raise SourceBuildRefusal("toolchain")
            target = root.joinpath(*member.name.split("/"))
            if os.path.commonpath((str(root), str(target.resolve(strict=False)))) != str(root):
                raise SourceBuildRefusal("toolchain")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, member.mode & 0o755)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    raise SourceBuildRefusal("toolchain")
                with stream, open(target, "wb") as sink:
                    shutil.copyfileobj(stream, sink, 1024 * 1024)
                os.chmod(target, member.mode & 0o755)
            elif member.issym() or member.islnk():
                pending_links.append((member, target))
            else:
                raise SourceBuildRefusal("toolchain")
        for member, target in pending_links:
            linkname = member.linkname
            if not _safe_tar_link(linkname):
                raise SourceBuildRefusal("toolchain")
            link_base = target.parent if member.issym() else root
            resolved = (link_base / linkname).resolve(strict=False)
            if os.path.commonpath((str(root), str(resolved))) != str(root):
                raise SourceBuildRefusal("toolchain")
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                os.symlink(linkname, target)
            else:
                if not resolved.is_file():
                    raise SourceBuildRefusal("toolchain")
                os.link(resolved, target)
    return root


def prepare_toolchains(environ=None):
    env = os.environ if environ is None else environ
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-records"
    root = TOOLCHAIN_ROOT
    if root.is_symlink():
        raise SourceBuildRefusal("toolchain")
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (IMAGE_RE.fullmatch(env.get("ImageOS", "")) is None
            or IMAGE_RE.fullmatch(env.get("ImageVersion", "")) is None):
        raise SourceBuildRefusal("toolchain")
    image_line = "linux-source-image schema=1 image-os=" + env["ImageOS"] + " image-version=" + env["ImageVersion"]
    (records / "image.txt").write_text(image_line + "\n", encoding="ascii")
    component_root = root / "rust-components"
    component_root.mkdir(mode=0o755, exist_ok=True)
    for name, url, digest in RUST_COMPONENTS:
        archive = root / (name + ".tar.gz")
        _download(url, digest, str(archive), 512 * 1024 * 1024)
        extracted = component_root / name
        _extract_tar(str(archive), str(extracted), "r:gz")
        installer = next(extracted.rglob("install.sh"), None)
        if installer is None:
            raise SourceBuildRefusal("toolchain")
        try:
            subprocess.run(
                ["/bin/sh", str(installer), "--prefix=" + str(root / "rust"), "--disable-ldconfig"],
                cwd=str(installer.parent),
                env={"PATH": "/usr/bin:/bin", "HOME": str(root), "LANG": "C", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=180, check=True, close_fds=True,
            )
        except (OSError, subprocess.SubprocessError):
            raise SourceBuildRefusal("toolchain") from None
    if NODE_LINUX_TARBALL_SHA256.startswith("COORDINATOR_FILL_"):
        raise SourceBuildRefusal("toolchain")
    node_archive = root / "node-linux-x64.tar.xz"
    _download(
        "https://nodejs.org/dist/v" + NODE_VERSION + "/node-v" + NODE_VERSION + "-linux-x64.tar.xz",
        NODE_LINUX_TARBALL_SHA256,
        str(node_archive),
        128 * 1024 * 1024,
    )
    node_root = _extract_tar(str(node_archive), str(root / "node"), "r:xz")
    node_binary = next(node_root.rglob("bin/node"), None)
    if node_binary is None:
        raise SourceBuildRefusal("toolchain")
    npm_manifest = node_binary.parent.parent / "lib" / "node_modules" / "npm" / "package.json"
    rustc = root / "rust" / "bin" / "rustc"
    cargo = root / "rust" / "bin" / "cargo"
    try:
        npm_record = json.loads(npm_manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise SourceBuildRefusal("toolchain") from None
    if (not rustc.is_file() or not cargo.is_file()
            or type(npm_record) is not dict or npm_record.get("version") != NPM_VERSION):
        raise SourceBuildRefusal("toolchain")
    os.chmod(root, 0o755)
    for current, directories, files in os.walk(root, followlinks=False):
        os.chmod(current, 0o755)
        for name in files:
            path = Path(current) / name
            if path.is_symlink():
                continue
            mode = path.stat().st_mode
            os.chmod(path, 0o555 if mode & stat.S_IXUSR else 0o444)
    output = env.get("GITHUB_OUTPUT")
    if output:
        with open(output, "at", encoding="ascii") as sink:
            sink.write("rust_root=" + str(root / "rust") + "\n")
            sink.write("rust_sysroot=" + str(root / "rust") + "\n")
            sink.write("node_root=" + str(node_root) + "\n")
            sink.write("node_bin=" + str(node_binary.parent) + "\n")
    sys.stdout.write(image_line + " toolchains=hash-verified\n")
    return 0


def _run(argv, cwd, environ=None, timeout=120, maximum=16 * 1024 * 1024):
    try:
        result = subprocess.run(
            [str(item) for item in argv], cwd=str(cwd), env=environ or {
                "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
            },
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False, close_fds=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise SourceBuildRefusal("checkout") from None
    if len(result.stdout) > maximum or len(result.stderr) > maximum:
        raise SourceBuildRefusal("checkout")
    return result


def _git(repo, *args, token=None, timeout=300, maximum=32 * 1024 * 1024):
    env = {
        "PATH": "/usr/bin:/bin", "HOME": str(repo.parent), "TMPDIR": str(repo.parent),
        "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_ATTR_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "3",
        "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": "/dev/null",
        "GIT_CONFIG_KEY_1": "protocol.file.allow", "GIT_CONFIG_VALUE_1": "never",
        "GIT_CONFIG_KEY_2": "http.followRedirects", "GIT_CONFIG_VALUE_2": "false",
    }
    if token:
        authorization = "AUTHORIZATION: basic " + base64.b64encode(("x-access-token:" + token).encode("ascii")).decode("ascii")
        env["GIT_CONFIG_COUNT"] = "4"
        env["GIT_CONFIG_KEY_3"] = "http.https://github.com/.extraheader"
        env["GIT_CONFIG_VALUE_3"] = authorization
    return _run(("/usr/bin/git", "-c", "safe.directory=" + str(repo), *args), repo, env, timeout, maximum)


def _sha_output(result):
    if result.returncode != 0 or result.stderr:
        raise SourceBuildRefusal("checkout")
    try:
        value = result.stdout.decode("ascii").strip()
    except UnicodeError:
        raise SourceBuildRefusal("checkout") from None
    if SOURCE_SHA_RE.fullmatch(value) is None:
        raise SourceBuildRefusal("checkout")
    return value


def _signer_keys(payload):
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError:
        raise SourceBuildRefusal("signature") from None
    accepted = []
    fingerprints = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(chr(35)):
            continue
        try:
            fields = shlex.split(stripped, comments=False, posix=True)
            key_positions = [index for index in (1, 2) if index < len(fields) and fields[index] == "ssh-ed25519"]
            if len(key_positions) != 1:
                raise ValueError
            position = key_positions[0]
            encoded = fields[position + 1]
            blob = base64.b64decode(encoded.encode("ascii"), validate=True)
            first_size = int.from_bytes(blob[:4], "big")
            second_offset = 4 + first_size
            second_size = int.from_bytes(blob[second_offset:second_offset + 4], "big")
            if (blob[4:second_offset] != b"ssh-ed25519" or second_size != 32
                    or second_offset + 4 + second_size != len(blob)):
                raise ValueError
            fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
            accepted.append((stripped + "\n").encode("ascii"))
            fingerprints[fingerprint] = b"ssh-ed25519 " + encoded.encode("ascii") + b"\n"
        except BaseException:
            raise SourceBuildRefusal("signature") from None
    if not accepted:
        raise SourceBuildRefusal("signature")
    return b"".join(accepted), fingerprints


def _validate_provenance_binding(identity, environ):
    try:
        def unique_pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        record = json.loads(
            environ.get("LINUX_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON", ""),
            object_pairs_hook=unique_pairs,
            parse_constant=lambda unused: (_ for _ in ()).throw(ValueError()),
        )
    except (ValueError, TypeError):
        raise SourceBuildRefusal("lock") from None
    if type(record) is not dict or set(record) != PROVENANCE_FIELDS:
        raise SourceBuildRefusal("lock")
    accepted_identity = record.get("accepted_source_identity")
    if type(accepted_identity) is not dict or set(accepted_identity) != set(IDENTITY_FIELDS):
        raise SourceBuildRefusal("lock")
    for name in IDENTITY_FIELDS:
        value = identity[name]
        if accepted_identity.get(name) != value:
            raise SourceBuildRefusal("lock")
    if (type(record.get("schema_version")) is not int or record.get("schema_version") != 1
            or record.get("status") != "accepted"
            or record.get("lock_sha256") != environ.get("LINUX_SOURCE_ACCEPTED_NODE_LOCK_SHA256")
            or record.get("manifest_sha256") != environ.get("LINUX_SOURCE_ACCEPTED_MANIFEST_SHA256")
            or record.get("node_version") != NODE_VERSION or record.get("npm_version") != NPM_VERSION
            or type(record.get("release_age_days")) is not int or record.get("release_age_days") != 7
            or record.get("age_status") != "passed"
            or type(record.get("generation_attempts")) is not int or record.get("generation_attempts") != 1
            or record.get("audit_endpoint") != "npm-bulk-advisory-v1"
            or record.get("audit_status") != "passed"):
        raise SourceBuildRefusal("lock")
    for key in ("generation_identity", "accepted_source_identity"):
        entry = record.get(key)
        if type(entry) is not dict or set(entry) != set(IDENTITY_FIELDS):
            raise SourceBuildRefusal("lock")
        if (SOURCE_SHA_RE.fullmatch(entry.get("source_sha", "")) is None
                or SOURCE_SHA_RE.fullmatch(entry.get("base_sha", "")) is None
                or SOURCE_SHA_RE.fullmatch(entry.get("control_sha", "")) is None
                or HEX64_RE.fullmatch(entry.get("reviewed_diff_sha256", "")) is None):
            raise SourceBuildRefusal("lock")
    policy_epoch = record.get("policy_epoch_ms")
    accepted_at = record.get("accepted_at_ms")
    if (type(policy_epoch) is not int or type(accepted_at) is not int
            or record.get("cutoff_epoch_ms") != policy_epoch - 7 * 24 * 60 * 60 * 1000
            or not policy_epoch <= accepted_at <= int(time.time() * 1000)):
        raise SourceBuildRefusal("lock")
    return record


def _check_lock_provenance(lock_bytes, identity, environ, source_root):
    if len(lock_bytes) > 4 * 1024 * 1024 - 64 * 1024:
        raise SourceBuildRefusal("lock")
    lock_sha = hashlib.sha256(lock_bytes).hexdigest()
    record = _validate_provenance_binding(identity, environ)
    manifest_digest = _manifest_digest(source_root)
    if (lock_sha != environ.get("LINUX_SOURCE_ACCEPTED_NODE_LOCK_SHA256")
            or record.get("lock_sha256") != lock_sha
            or manifest_digest != environ.get("LINUX_SOURCE_ACCEPTED_MANIFEST_SHA256")
            or record.get("manifest_sha256") != manifest_digest):
        raise SourceBuildRefusal("lock")
    return lock_sha, manifest_digest


def _verify_signatures(repo, source, identity, control_root):
    signer_path = "docs/commit-signers"
    signers_result = _git(repo, "show", identity["base_sha"] + ":" + signer_path)
    if signers_result.returncode != 0 or signers_result.stderr:
        raise SourceBuildRefusal("signature")
    allowed_payload, key_map = _signer_keys(signers_result.stdout)
    revoked_path = control_root / "ci" / "revoked-signer-fingerprints"
    try:
        revoked_payload = revoked_path.read_bytes()
        committed = _git(control_root, "show", identity["control_sha"] + ":ci/revoked-signer-fingerprints")
    except OSError:
        raise SourceBuildRefusal("signature") from None
    if committed.returncode != 0 or committed.stderr or committed.stdout != revoked_payload:
        raise SourceBuildRefusal("signature")
    revoked = []
    if revoked_payload:
        if not revoked_payload.endswith(b"\n") or b"\r" in revoked_payload:
            raise SourceBuildRefusal("signature")
        for line in revoked_payload[:-1].decode("ascii", "strict").split("\n"):
            if FINGERPRINT_RE.fullmatch(line) is None or line in revoked:
                raise SourceBuildRefusal("signature")
            revoked.append(line)
    revocation_data = b"".join(key_map[name] for name in revoked if name in key_map)
    if any(name not in key_map for name in revoked):
        raise SourceBuildRefusal("signature")
    temporary = Path(tempfile.mkdtemp(prefix="linux-signatures-", dir=str(repo.parent)))
    try:
        allowed_path = temporary / "base-allowed-signers"
        revoked_file = temporary / "revoked-signers"
        allowed_path.write_bytes(allowed_payload)
        revoked_file.write_bytes(revocation_data)
        changed = _git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", identity["base_sha"], identity["source_sha"])
        if changed.returncode != 0 or changed.stderr:
            raise SourceBuildRefusal("signature")
        if signer_path.encode("ascii") in changed.stdout.split(b"\x00"):
            raise SourceBuildRefusal("signature")
        commits = _git(repo, "rev-list", "--topo-order", "--reverse", identity["base_sha"] + ".." + identity["source_sha"])
        if commits.returncode != 0 or commits.stderr or len(commits.stdout) > 4 * 1024 * 1024:
            raise SourceBuildRefusal("signature")
        commit_ids = commits.stdout.decode("ascii").splitlines()
        for commit in commit_ids:
            if SOURCE_SHA_RE.fullmatch(commit) is None:
                raise SourceBuildRefusal("signature")
            result = _git(
                repo, "-c", "gpg.format=ssh", "-c", "gpg.ssh.program=/usr/bin/ssh-keygen",
                "-c", "gpg.program=false", "-c", "gpg.x509.program=false",
                "-c", "gpg.ssh.allowedSignersFile=" + str(allowed_path),
                "-c", "gpg.ssh.revocationFile=" + str(revoked_file),
                "-c", "gpg.minTrustLevel=fully", "verify-commit", commit,
            )
            if result.returncode != 0:
                raise SourceBuildRefusal("signature")
    except UnicodeError:
        raise SourceBuildRefusal("signature") from None
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def checkout_source(environ=None):
    env = os.environ if environ is None else environ
    identity = _source_inputs(env)
    token = env.get("SOURCE_READER_TOKEN", "")
    if not token or len(token) > 4096:
        raise SourceBuildRefusal("token")
    source_root = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-source-checkout"
    shutil.rmtree(source_root, ignore_errors=True)
    source_root.mkdir(mode=0o700, parents=True)
    repo = source_root / "repository"
    repo.mkdir(mode=0o700)
    init = _git(repo, "init", "--quiet")
    if init.returncode != 0 or init.stderr:
        raise SourceBuildRefusal("checkout")
    owner = identity["owner"]
    name = identity["name"]
    repository = owner + "/" + name
    repository_path = "/repos/" + urllib.parse.quote(owner, safe="") + "/" + urllib.parse.quote(name, safe="")
    status, repository_info = _api_request(repository_path, token)
    if (status != 200 or type(repository_info) is not dict
            or type(repository_info.get("id")) is not int
            or str(repository_info["id"]) != identity["repository_id"]
            or repository_info.get("private") is not True
            or repository_info.get("full_name") != repository):
        raise SourceBuildRefusal("source")
    eligible = env.get("CI_REF") == "refs/heads/untrusted"
    if env.get("CI_REF") == "refs/heads/main":
        for branch in ("develop", "uat", "main"):
            tip = _reference_sha(token, repository, branch)
            if tip is not None and _comparison(token, repository, identity["source_sha"], tip) in ("ahead", "identical"):
                eligible = True
                break
    if not eligible:
        raise SourceBuildRefusal("source")
    remote = "https://github.com/" + owner + "/" + name + ".git"
    added = _git(repo, "remote", "add", "source", remote)
    if added.returncode != 0:
        raise SourceBuildRefusal("checkout")
    base_ref = "refs/heads/" + identity["base_branch"]
    fetched_base = _git(
        repo, "fetch", "--quiet", "--no-tags", "source",
        base_ref + ":refs/remotes/source/base", token=token,
    )
    fetched_source = _git(repo, "fetch", "--quiet", "--no-tags", "source", identity["source_sha"], token=token)
    if fetched_base.returncode != 0 or fetched_source.returncode != 0:
        raise SourceBuildRefusal("checkout")
    base = _sha_output(_git(repo, "rev-parse", "--verify", "refs/remotes/source/base^{commit}"))
    if base != identity["base_sha"]:
        raise SourceBuildRefusal("binding")
    source_sha = _sha_output(_git(repo, "rev-parse", "--verify", identity["source_sha"] + "^{commit}"))
    if source_sha != identity["source_sha"]:
        raise SourceBuildRefusal("checkout")
    ancestor = _git(repo, "merge-base", "--is-ancestor", identity["base_sha"], identity["source_sha"])
    if ancestor.returncode != 0 or ancestor.stdout or ancestor.stderr:
        raise SourceBuildRefusal("binding")
    checked = _git(repo, "checkout", "--quiet", "--detach", identity["source_sha"])
    if checked.returncode != 0 or checked.stderr:
        raise SourceBuildRefusal("checkout")
    head = _sha_output(_git(repo, "rev-parse", "--verify", "HEAD"))
    tree = _sha_output(_git(repo, "rev-parse", "--verify", "HEAD^{tree}"))
    status = _git(repo, "status", "--porcelain", "--untracked-files=all")
    if head != identity["source_sha"] or status.returncode != 0 or status.stdout or status.stderr:
        raise SourceBuildRefusal("checkout")
    diff = _git(repo, "diff", "--binary", "--no-ext-diff", "--no-renames", identity["base_sha"], identity["source_sha"], maximum=64 * 1024 * 1024)
    if diff.returncode != 0 or diff.stderr or hashlib.sha256(diff.stdout).hexdigest() != identity["reviewed_diff_sha256"]:
        raise SourceBuildRefusal("binding")
    _verify_signatures(repo, source_root, identity, Path(env["CI_WORKSPACE"]))
    lock_path = repo / "package-lock.json"
    try:
        lock_bytes = lock_path.read_bytes()
    except OSError:
        raise SourceBuildRefusal("lock") from None
    lock_sha, manifest_sha = _check_lock_provenance(lock_bytes, identity, env, repo)
    _validate_cargo_lock_sources(repo)
    _neutralize_config_files(repo)
    write_out = env.get("GITHUB_OUTPUT")
    if write_out:
        with open(write_out, "at", encoding="ascii") as sink:
            sink.write("source_path=" + str(repo) + "\n")
            sink.write("source_tree=" + tree + "\n")
            sink.write("lock_sha256=" + lock_sha + "\n")
            sink.write("manifest_sha256=" + manifest_sha + "\n")
    sys.stdout.write("linux-source-checkout=verified source-sha=" + head + " tree=" + tree + " signatures=verified lock=accepted\n")
    return 0


def revoke_token(environ=None):
    env = os.environ if environ is None else environ
    token = env.get("SOURCE_READER_TOKEN", "")
    if not token:
        raise SourceBuildRefusal("revocation")
    status, unused = _api_request("/installation/token", token, method="DELETE", expected=(204,))
    if status != 204:
        raise SourceBuildRefusal("revocation")
    status, unused = _api_request("/installation/repositories?per_page=1", token, expected=(401,))
    if status != 401:
        raise SourceBuildRefusal("revocation")
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-records"
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipt = {
        "schema_version": 1,
        "status": "confirmed",
        "control_sha": env.get("CI_SHA", ""),
        "run_id": env.get("GITHUB_RUN_ID", ""),
        "run_attempt": env.get("GITHUB_RUN_ATTEMPT", ""),
        "installation_id": env.get("SOURCE_READER_INSTALLATION_ID", ""),
        "rejected_after_revoke": True,
    }
    (records / "revocation.json").write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    sys.stdout.write("linux-source-token=revoked rejection=verified receipt=positive\n")
    return 0


def _npm_integrity(value):
    if type(value) is not str or not value.startswith("sha512-"):
        raise SourceBuildRefusal("lock")
    try:
        digest = base64.b64decode(value[7:].encode("ascii"), validate=True)
    except (ValueError, UnicodeError):
        raise SourceBuildRefusal("lock") from None
    if len(digest) != 64:
        raise SourceBuildRefusal("lock")
    return digest


def _locked_packages(lock_bytes):
    try:
        lock = json.loads(lock_bytes.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise SourceBuildRefusal("lock") from None
    if (type(lock) is not dict or lock.get("lockfileVersion") != 3
            or type(lock.get("packages")) is not dict or len(lock["packages"]) > 50000):
        raise SourceBuildRefusal("lock")
    packages = {}
    for key, entry in lock["packages"].items():
        if not key or type(entry) is not dict or entry.get("link") is True:
            continue
        resolved = entry.get("resolved")
        if resolved is None:
            continue
        parsed = urllib.parse.urlsplit(resolved)
        if parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org" or parsed.port:
            raise SourceBuildRefusal("lock")
        integrity = _npm_integrity(entry.get("integrity"))
        packages[resolved] = integrity
    if not packages:
        raise SourceBuildRefusal("lock")
    return lock, packages


def _manifest_json(path):
    try:
        payload = Path(path).read_bytes()
    except OSError:
        raise SourceBuildRefusal("lock") from None
    if not payload or len(payload) > MAX_PACKAGE_JSON_BYTES:
        raise SourceBuildRefusal("lock")

    def unique_pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        return json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=unique_pairs,
            parse_constant=lambda unused: (_ for _ in ()).throw(ValueError()),
        )
    except BaseException:
        raise SourceBuildRefusal("lock") from None


MANIFEST_ROOT_OVERRIDES = {"lightningcss": "1.33.0"}


def _manifest_root_overrides(root):
    if "overrides" not in root:
        return None
    value = root["overrides"]
    if (type(value) is not dict or set(value) != set(MANIFEST_ROOT_OVERRIDES)
            or any(type(item) is not str or item != MANIFEST_ROOT_OVERRIDES[name] for name, item in value.items())):
        raise SourceBuildRefusal("lock")
    return dict(value)


def _manifest_digest(source_root):
    root = _manifest_json(Path(source_root) / "package.json")
    if (type(root) is not dict or type(root.get("name")) is not str
            or type(root.get("version")) is not str
            or any(key in root for key in ("resolutions", "bundleDependencies", "bundledDependencies"))):
        raise SourceBuildRefusal("lock")
    workspaces = root.get("workspaces")
    if type(workspaces) is dict:
        if set(workspaces) != {"packages"}:
            raise SourceBuildRefusal("lock")
        workspaces = workspaces.get("packages")
    if (type(workspaces) is not list or len(workspaces) != 1
            or workspaces[0] not in ("packages/*", "packages/host-api")):
        raise SourceBuildRefusal("lock")
    root_expected = {"name": root["name"], "version": root["version"], "workspaces": workspaces}
    for group in MANIFEST_GROUPS:
        if group in root:
            root_expected[group] = root[group]
    overrides = _manifest_root_overrides(root)
    if overrides is not None:
        root_expected["overrides"] = overrides
    workspace_path = "packages/host-api"
    if not any(pattern == workspace_path or pattern == "packages/*" and workspace_path.startswith("packages/")
               for pattern in workspaces):
        raise SourceBuildRefusal("lock")
    package = _manifest_json(Path(source_root) / workspace_path / "package.json")
    if (type(package) is not dict or type(package.get("name")) is not str
            or type(package.get("version")) is not str
            or any(key in package for key in ("overrides", "resolutions", "bundleDependencies", "bundledDependencies"))):
        raise SourceBuildRefusal("lock")
    workspace_expected = {"path": workspace_path, "name": package["name"], "version": package["version"]}
    for group in MANIFEST_GROUPS:
        if group in package:
            workspace_expected[group] = package[group]
    workspace_names = {workspace_expected["name"]}
    for manifest in (root_expected, workspace_expected):
        for group in MANIFEST_GROUPS:
            dependencies = manifest.get(group, {})
            if type(dependencies) is not dict or len(dependencies) > 512:
                raise SourceBuildRefusal("lock")
            for name, spec in dependencies.items():
                if (type(name) is not str or len(name) > 214 or not MANIFEST_PACKAGE_RE.fullmatch(name)
                        or ".." in name or type(spec) is not str or len(spec) > 128):
                    raise SourceBuildRefusal("lock")
                if name in workspace_names and spec.startswith("workspace:"):
                    if MANIFEST_WORKSPACE_VERSION_RE.fullmatch(spec) is None:
                        raise SourceBuildRefusal("lock")
                elif not MANIFEST_VERSION_RE.fullmatch(spec):
                    raise SourceBuildRefusal("lock")
    expected = {"root": root_expected, "workspaces": [workspace_expected]}
    try:
        encoded = json.dumps(
            expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
    except BaseException:
        raise SourceBuildRefusal("lock") from None
    if len(encoded) > 256 * 1024:
        raise SourceBuildRefusal("lock")
    return hashlib.sha256(encoded).hexdigest()


def _cargo_config_files(root):
    found = []
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if not os.path.islink(os.path.join(current, name))]
        if Path(current).name == ".cargo":
            for name in files:
                if name.startswith("config"):
                    found.append(Path(current) / name)
    return found


def _neutralize_config_files(source_root):
    for current, directories, files in os.walk(source_root, followlinks=False):
        for name in list(directories):
            path = Path(current) / name
            if name == ".cargo" and path.is_symlink():
                path.unlink()
                directories.remove(name)
    for path in _cargo_config_files(source_root):
        if path.is_symlink():
            path.unlink()
            continue
        try:
            payload = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise SourceBuildRefusal("registry") from None
        if re.search(r"(?im)^\s*\[(?:source\.|registries\.)|^\s*(?:replace-with|registry)\s*=", payload):
            raise SourceBuildRefusal("registry")
        path.unlink()
    for current, directories, files in os.walk(source_root, followlinks=False):
        directories[:] = [name for name in directories if not os.path.islink(os.path.join(current, name))]
        for name in files:
            if name == ".npmrc":
                (Path(current) / name).unlink()


def fetch_npm_tarballs(environ=None):
    env = os.environ if environ is None else environ
    source = Path(env.get("SOURCE_PATH", ""))
    if not source.is_dir():
        raise SourceBuildRefusal("checkout")
    lock_bytes = (source / "package-lock.json").read_bytes()
    identity = _source_inputs(env)
    lock_sha, manifest_sha = _check_lock_provenance(lock_bytes, identity, env, source)
    lock, packages = _locked_packages(lock_bytes)
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-records"
    cache = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-npm-tarballs"
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    mapping = {}
    for index, (url, expected) in enumerate(sorted(packages.items())):
        path = cache / (str(index) + ".tgz")
        _download_integrity(url, expected, str(path))
        mapping[url] = str(path)
    index_path = records / "npm-tarballs.json"
    index_path.write_text(json.dumps(mapping, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    env_out = env.get("GITHUB_OUTPUT")
    if env_out:
        with open(env_out, "at", encoding="ascii") as sink:
            sink.write("tarball_index=" + str(index_path) + "\n")
            sink.write("lock_sha256=" + lock_sha + "\n")
            sink.write("manifest_sha256=" + manifest_sha + "\n")
    sys.stdout.write("linux-npm-tarballs=verified count=" + str(len(mapping)) + " integrity=sha512\n")
    return 0


def _download_integrity(url, expected, destination):
    request = urllib.request.Request(url, headers={"User-Agent": "kd-linux-source-build"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    digest = hashlib.sha512()
    count = 0
    try:
        with opener.open(request, timeout=45) as response, open(destination, "wb") as target:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                count += len(block)
                if count > 256 * 1024 * 1024:
                    raise SourceBuildRefusal("network")
                digest.update(block)
                target.write(block)
    except SourceBuildRefusal:
        raise
    except (OSError, urllib.error.URLError):
        raise SourceBuildRefusal("network") from None
    if count == 0 or digest.digest() != expected:
        try:
            os.unlink(destination)
        except OSError:
            pass
        raise SourceBuildRefusal("hash_mismatch")
    os.chmod(destination, 0o400)


def _open_project_root():
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        parent = os.open("/tmp", flags)
    except OSError:
        raise SourceBuildRefusal("gate") from None
    parent_details = os.fstat(parent)
    if parent_details.st_uid != 0 or parent_details.st_mode & 0o022 and not parent_details.st_mode & stat.S_ISVTX:
        os.close(parent)
        raise SourceBuildRefusal("gate")
    try:
        try:
            os.mkdir(PROJECT_ROOT.name, 0o755, dir_fd=parent)
        except FileExistsError:
            pass
        root = os.open(PROJECT_ROOT.name, flags, dir_fd=parent)
    except OSError:
        raise SourceBuildRefusal("gate") from None
    finally:
        os.close(parent)
    try:
        details = os.fstat(root)
    except OSError:
        os.close(root)
        raise SourceBuildRefusal("gate") from None
    if details.st_uid != 0 or details.st_mode & 0o022:
        os.close(root)
        raise SourceBuildRefusal("gate")
    return root


def _project_gate_directories(worker, create=False):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root = _open_project_root()
    try:
        if Path(worker) != PROJECT_ROOT / "source":
            raise SourceBuildRefusal("gate")
        project = os.open("source", flags, dir_fd=root)
        try:
            details = os.fstat(project)
            if details.st_uid != linux_harness.CHILD_UID or details.st_gid != linux_harness.CHILD_GID:
                raise SourceBuildRefusal("gate")
            for name in (".home", ".tmp", "target", ".npm-cache", ".kd-cargo-home"):
                made = False
                if create and name != ".kd-cargo-home":
                    try:
                        os.mkdir(name, 0o700, dir_fd=project)
                        made = True
                    except FileExistsError:
                        pass
                child = os.open(name, flags, dir_fd=project)
                try:
                    if made:
                        os.fchown(child, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
                        os.fchmod(child, 0o700)
                    details = os.fstat(child)
                    if details.st_uid != linux_harness.CHILD_UID or details.st_gid != linux_harness.CHILD_GID:
                        raise SourceBuildRefusal("gate")
                finally:
                    os.close(child)
        finally:
            os.close(project)
    except OSError:
        raise SourceBuildRefusal("gate") from None
    finally:
        os.close(root)


def _prepare_worker_tree(source, tarball_index, environ):
    root = _open_project_root()
    os.close(root)
    worker = PROJECT_ROOT / "source"
    if worker.is_symlink():
        raise SourceBuildRefusal("gate")
    shutil.rmtree(worker, ignore_errors=True)
    _neutralize_config_files(source)
    shutil.copytree(source, worker, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    for current, directories, files in os.walk(worker, followlinks=False):
        for name in directories + files:
            path = Path(current) / name
            if path.is_symlink():
                link = os.readlink(path)
                resolved = (path.parent / link).resolve(strict=False)
                if os.path.isabs(link) or os.path.commonpath((str(worker.resolve()), str(resolved))) != str(worker.resolve()):
                    raise SourceBuildRefusal("gate")
    for current, directories, files in os.walk(worker, followlinks=False):
        directories[:] = [name for name in directories if not os.path.islink(os.path.join(current, name))]
        for name in list(files):
            path = Path(current) / name
            if name == ".npmrc":
                path.unlink()
            elif path.parent.name == ".cargo" and name.startswith("config"):
                path.unlink()
    lock_path = worker / "package-lock.json"
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        mapping = json.loads(Path(tarball_index).read_text(encoding="ascii"))
    except (OSError, UnicodeError, ValueError):
        raise SourceBuildRefusal("lock") from None
    if type(mapping) is not dict or any(type(key) is not str or type(value) is not str for key, value in mapping.items()):
        raise SourceBuildRefusal("lock")
    tarball_root = worker / ".kd-npm-tarballs"
    try:
        tarball_root.mkdir(mode=0o755)
    except OSError:
        raise SourceBuildRefusal("gate") from None
    copied = {}
    package_integrities = {}
    for entry in lock.get("packages", {}).values():
        if type(entry) is not dict:
            continue
        url = entry.get("resolved")
        if url not in mapping:
            continue
        integrity = _npm_integrity(entry.get("integrity"))
        if url not in copied:
            source_tarball = Path(mapping[url])
            if source_tarball.is_symlink() or not source_tarball.is_file():
                raise SourceBuildRefusal("lock")
            destination = tarball_root / (str(len(copied)) + ".tgz")
            shutil.copyfile(source_tarball, destination)
            digest = hashlib.sha512()
            with open(destination, "rb") as copied_file:
                while True:
                    block = copied_file.read(1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
            if digest.digest() != integrity:
                destination.unlink()
                raise SourceBuildRefusal("hash_mismatch")
            os.chown(destination, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
            os.chmod(destination, 0o444)
            copied[url] = destination.resolve().as_uri()
        elif package_integrities[url] != integrity:
            raise SourceBuildRefusal("lock")
        package_integrities[url] = integrity
        entry["resolved"] = copied[url]
    if set(copied) != set(mapping):
        raise SourceBuildRefusal("lock")
    lock_path.write_text(json.dumps(lock, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    for current, directories, files in os.walk(worker, followlinks=False):
        os.chown(current, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
        os.chmod(current, 0o755)
        for name in files:
            path = Path(current) / name
            if path.is_symlink():
                continue
            os.chown(path, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
            mode = path.stat().st_mode
            os.chmod(path, 0o755 if mode & stat.S_IXUSR else 0o644)
    return worker


def _validate_cargo_lock_sources(project):
    found = False
    for current, directories, files in os.walk(project, followlinks=False):
        directories[:] = [
            name for name in directories
            if name != ".git" and not os.path.islink(os.path.join(current, name))
        ]
        if "Cargo.lock" not in files:
            continue
        found = True
        try:
            payload = (Path(current) / "Cargo.lock").read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise SourceBuildRefusal("lock") from None
        if len(payload) > 4 * 1024 * 1024:
            raise SourceBuildRefusal("lock")
        for line in payload.splitlines():
            if re.match(r"^\s*source\s*=", line):
                raise SourceBuildRefusal("registry")
    if not found:
        raise SourceBuildRefusal("lock")


def _directory_identity(metadata):
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink


def _open_source_root(source):
    source = Path(source)
    if not source.is_absolute() or ".." in source.parts:
        raise SourceBuildRefusal("binding")
    if (not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW")
            or os.stat not in os.supports_dir_fd):
        raise SourceBuildRefusal("binding")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = None
    try:
        descriptor = os.open("/", flags)
        for component in source.parts[1:]:
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise SourceBuildRefusal("binding")
            child = os.open(component, flags, dir_fd=descriptor)
            opened = os.fstat(child)
            if _directory_identity(opened) != _directory_identity(before):
                os.close(child)
                raise SourceBuildRefusal("binding")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except SourceBuildRefusal:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except (OSError, TypeError, ValueError):
        if descriptor is not None:
            os.close(descriptor)
        raise SourceBuildRefusal("binding") from None


def _open_verified_directory(root_fd, relative_parts, identities):
    if len(identities) != len(relative_parts) + 1:
        raise SourceBuildRefusal("lock")
    descriptors = []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        current = os.dup(root_fd)
        descriptors.append(current)
        if _directory_identity(os.fstat(current)) != identities[0]:
            raise SourceBuildRefusal("lock")
        for index, component in enumerate(relative_parts, 1):
            before = os.stat(component, dir_fd=current, follow_symlinks=False)
            if (stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode)
                    or _directory_identity(before) != identities[index]):
                raise SourceBuildRefusal("lock")
            child = os.open(component, flags, dir_fd=current)
            opened = os.fstat(child)
            if _directory_identity(opened) != identities[index]:
                os.close(child)
                raise SourceBuildRefusal("lock")
            descriptors.append(child)
            current = child
        return descriptors
    except BaseException:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _rust_lock_paths(root_fd):
    ignored = {".git", "target", "node_modules", ".kd-cargo-home", ".npm-cache"}
    paths = []
    root_identity = _directory_identity(os.fstat(root_fd))
    pending = [((), (root_identity,))]
    visited = 0
    total_entries = 0
    while pending:
        relative_parts, identities = pending.pop()
        visited += 1
        if visited > MAX_LOCK_DIRECTORIES:
            raise SourceBuildRefusal("lock")
        descriptors = _open_verified_directory(root_fd, relative_parts, identities)
        current = descriptors[-1]
        entries_seen = 0
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    entries_seen += 1
                    total_entries += 1
                    if (entries_seen > MAX_DIRECTORY_ENTRIES
                            or total_entries > MAX_TREE_ENTRIES):
                        raise SourceBuildRefusal("lock")
                    name = entry.name
                    if name in ignored:
                        continue
                    metadata = os.stat(name, dir_fd=current, follow_symlinks=False)
                    if stat.S_ISLNK(metadata.st_mode):
                        if name == "Cargo.lock":
                            raise SourceBuildRefusal("lock")
                        continue
                    child_parts = relative_parts + (name,)
                    if stat.S_ISDIR(metadata.st_mode):
                        if len(pending) >= MAX_PENDING_DIRECTORIES:
                            raise SourceBuildRefusal("lock")
                        pending.append((child_parts, identities + (_directory_identity(metadata),)))
                        continue
                    if name != "Cargo.lock":
                        continue
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                        raise SourceBuildRefusal("lock")
                    paths.append((child_parts, identities, _stat_identity(metadata)))
                    if len(paths) > 32:
                        raise SourceBuildRefusal("lock")
        except SourceBuildRefusal:
            raise
        except OSError:
            raise SourceBuildRefusal("lock") from None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
    if not paths:
        raise SourceBuildRefusal("lock")
    return tuple(sorted(paths, key=lambda item: "/".join(item[0])))


def _stat_identity(metadata):
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
        metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _read_bounded_cargo_lock(root_fd, candidate):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None or type(candidate) is not tuple or len(candidate) != 3:
        raise SourceBuildRefusal("lock")
    descriptor = None
    parent_descriptors = []
    try:
        relative_parts, ancestry, discovered_identity = candidate
        if (type(relative_parts) is not tuple or not relative_parts
                or type(ancestry) is not tuple):
            raise SourceBuildRefusal("lock")
        parent_parts = relative_parts[:-1]
        parent_descriptors = _open_verified_directory(root_fd, parent_parts, ancestry)
        parent_fd = parent_descriptors[-1]
        lock_name = relative_parts[-1]
        before = os.stat(lock_name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > rust_license_gate.MAX_LOCK_BYTES):
            raise SourceBuildRefusal("lock")
        if discovered_identity != _stat_identity(before):
            raise SourceBuildRefusal("lock")
        descriptor = os.open(
            lock_name, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
        if (_stat_identity(before) != _stat_identity(opened)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1):
            raise SourceBuildRefusal("lock")
        content = bytearray()
        while len(content) <= rust_license_gate.MAX_LOCK_BYTES:
            chunk = os.read(
                descriptor,
                min(65536, rust_license_gate.MAX_LOCK_BYTES + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > rust_license_gate.MAX_LOCK_BYTES:
            raise SourceBuildRefusal("lock")
        after = os.fstat(descriptor)
        path_after = os.stat(lock_name, dir_fd=parent_fd, follow_symlinks=False)
        if (_stat_identity(opened) != _stat_identity(after)
                or _stat_identity(after) != _stat_identity(path_after)
                or len(content) != after.st_size):
            raise SourceBuildRefusal("lock")
        current_ancestors = _open_verified_directory(root_fd, parent_parts, ancestry)
        try:
            for current_fd, expected_identity in zip(current_ancestors, ancestry):
                if _directory_identity(os.fstat(current_fd)) != expected_identity:
                    raise SourceBuildRefusal("lock")
        finally:
            for current_fd in reversed(current_ancestors):
                os.close(current_fd)
        return bytes(content)
    except SourceBuildRefusal:
        raise
    except (OSError, ValueError):
        raise SourceBuildRefusal("lock") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for parent_fd in reversed(parent_descriptors):
            os.close(parent_fd)


def _require_source_root_identity(source, expected_identity):
    descriptor = _open_source_root(source)
    try:
        if _directory_identity(os.fstat(descriptor)) != expected_identity:
            raise SourceBuildRefusal("binding")
    finally:
        os.close(descriptor)


def run_rust_license_gate(environ=None):
    env = os.environ if environ is None else environ
    source = Path(env.get("SOURCE_PATH", ""))
    source_sha = env.get("REQUESTED_SOURCE_SHA", "")
    if SOURCE_SHA_RE.fullmatch(source_sha) is None:
        raise SourceBuildRefusal("binding")
    try:
        root_fd = _open_source_root(source)
    except SourceBuildRefusal:
        raise SourceBuildRefusal("binding") from None
    root_identity = _directory_identity(os.fstat(root_fd))
    try:
        _require_source_root_identity(source, root_identity)
        for candidate in _rust_lock_paths(root_fd):
            try:
                lock_bytes = _read_bounded_cargo_lock(root_fd, candidate)
                relative_parts = candidate[0][:-1]
                relative = "/".join(relative_parts) or "."
                if len(relative) > 64:
                    raise SourceBuildRefusal("lock")
                _require_source_root_identity(source, root_identity)
            except (OSError, ValueError):
                raise SourceBuildRefusal("lock") from None
            if not lock_bytes or len(lock_bytes) > rust_license_gate.MAX_LOCK_BYTES:
                raise SourceBuildRefusal("lock")
            identity = rust_license_gate.Identity(
                source_sha, relative, str(source.joinpath(*relative_parts)),
                hashlib.sha256(lock_bytes).hexdigest(),
            )
            rust_license_gate.require_configured_control(
                lock_bytes, identity, rust_license_gate.TRUSTED_PORTS,
            )
    finally:
        os.close(root_fd)
    return 0


def prepare_project(environ=None):
    env = os.environ if environ is None else environ
    source = Path(env.get("SOURCE_PATH", ""))
    rust_root = Path(env.get("RUST_ROOT", ""))
    tarball_index = env.get("NPM_TARBALL_INDEX", "")
    cargo = rust_root / "bin" / "cargo"
    if not source.is_dir() or not cargo.is_file() or not tarball_index:
        raise SourceBuildRefusal("toolchain")
    lock_bytes = (source / "package-lock.json").read_bytes()
    if (hashlib.sha256(lock_bytes).hexdigest() != env.get("EXPECTED_NODE_LOCK_SHA256")
            or _manifest_digest(source) != env.get("EXPECTED_MANIFEST_SHA256")):
        raise SourceBuildRefusal("lock")
    _validate_cargo_lock_sources(source)
    worker = _prepare_worker_tree(source, tarball_index, env)
    cargo_home = worker / ".kd-cargo-home"
    try:
        cargo_home.mkdir(mode=0o755)
    except OSError:
        raise SourceBuildRefusal("gate") from None
    config = cargo_home / "config.toml"
    config.write_text("\n", encoding="ascii")
    os.chown(config, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
    os.chmod(config, 0o444)
    os.chown(cargo_home, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
    os.chmod(cargo_home, 0o755)
    _project_gate_directories(worker, create=True)
    output = env.get("GITHUB_OUTPUT")
    if output:
        with open(output, "at", encoding="ascii") as sink:
            sink.write("worker_path=" + str(worker) + "\n")
            sink.write("cargo_home=" + str(cargo_home) + "\n")
    sys.stdout.write("linux-project-inputs=prepared cargo=registry-free npm=integrity\n")
    return 0


def run_trusted_audit(environ=None):
    env = os.environ if environ is None else environ
    source = Path(env.get("SOURCE_PATH", ""))
    node = Path(env.get("NODE_BIN", "")) / "node"
    npm = Path(env.get("NODE_BIN", "")) / "npm"
    if not source.is_dir() or not node.is_file() or not npm.exists():
        raise SourceBuildRefusal("toolchain")
    _neutralize_config_files(source)
    identity = _source_inputs(env)
    lock_bytes = (source / "package-lock.json").read_bytes()
    _check_lock_provenance(lock_bytes, identity, env, source)
    private = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-audit"
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = _run(
        (str(node), str(npm), "audit", "--package-lock-only", "--json"), source,
        {"PATH": str(node.parent) + ":/usr/bin:/bin", "HOME": str(private), "TMPDIR": str(private),
         "LANG": "C", "LC_ALL": "C", "NPM_CONFIG_USERCONFIG": "/dev/null",
         "NPM_CONFIG_GLOBALCONFIG": "/dev/null", "NPM_CONFIG_CACHE": str(private / "cache")},
        timeout=120, maximum=4 * 1024 * 1024,
    )
    if result.returncode != 0:
        (private / "audit.stdout").write_bytes(result.stdout)
        (private / "audit.stderr").write_bytes(result.stderr)
        raise SourceBuildRefusal("lock")
    lock_after = (source / "package-lock.json").read_bytes()
    _check_lock_provenance(lock_after, identity, env, source)
    (private / "audit.json").write_bytes(result.stdout)
    sys.stdout.write("linux-node-audit=verified phase=trusted\n")
    return 0


def _runtime_workspace_present(project):
    try:
        runtime_info = (project / "runtime").lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise SourceBuildRefusal("gate") from None
    if not stat.S_ISDIR(runtime_info.st_mode):
        raise SourceBuildRefusal("gate")
    present = []
    for relative_path in RUNTIME_ROOT_FILES:
        try:
            info = (project / relative_path).lstat()
        except FileNotFoundError:
            present.append(False)
            continue
        except OSError:
            raise SourceBuildRefusal("gate") from None
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SourceBuildRefusal("gate")
        present.append(True)
    if any(present) and not all(present):
        raise SourceBuildRefusal("gate")
    return all(present)


def _gate_commands(project, rust_root, node_bin):
    cargo = str(Path(rust_root) / "bin" / "cargo")
    npm = str(Path(node_bin) / "npm")
    commands = (
        ("format", (cargo, "--locked", "--offline", "fmt", "--manifest-path", str(project / "Cargo.toml"), "--all", "--", "--check")),
        ("clippy", (cargo, "clippy", "--offline", "--manifest-path", str(project / "Cargo.toml"), "--workspace", "--all-targets", "--locked", "--", "-D", "warnings")),
        ("workspace_tests", (cargo, "test", "--offline", "--manifest-path", str(project / "Cargo.toml"), "--workspace", "--all-targets", "--locked")),
        ("api_tests", (cargo, "test", "--offline", "--manifest-path", str(project / "crates/host/api/Cargo.toml"), "--all-targets", "--locked")),
        ("mock_tests", (cargo, "test", "--offline", "--manifest-path", str(project / "crates/host/mock/Cargo.toml"), "--all-targets", "--locked")),
        ("conformance_tests", (cargo, "test", "--offline", "--manifest-path", str(project / "crates/host/conformance/Cargo.toml"), "--all-targets", "--locked")),
        ("parser_format", (cargo, "--locked", "--offline", "fmt", "--manifest-path", str(project / "fuzz/Cargo.toml"), "--all", "--", "--check")),
        ("parser_clippy", (cargo, "clippy", "--offline", "--manifest-path", str(project / "fuzz/Cargo.toml"), "--all-targets", "--locked", "--", "-D", "warnings")),
        ("parser_replay", (cargo, "run", "--locked", "--offline", "--manifest-path", str(project / "fuzz/Cargo.toml"))),
        ("node_dependency_prepare", (str(Path(node_bin) / "node"), npm, "--offline", "--ignore-scripts", "--audit=false", "--fund=false", "ci", "--workspaces=true", "--include-workspace-root")),
        ("node_dependency_audit", (str(Path(node_bin) / "node"), npm, "--offline", "ls", "--all", "--workspaces=true", "--include-workspace-root")),
        ("typescript_typecheck", (str(Path(node_bin) / "node"), npm, "--offline", "run", "typecheck", "--workspaces", "--ignore-scripts")),
        ("typescript_tests", (str(Path(node_bin) / "node"), npm, "--offline", "run", "test", "--workspaces", "--ignore-scripts")),
    )
    if not _runtime_workspace_present(project):
        return commands
    runtime_manifest = str(project / "runtime/Cargo.toml")
    return commands + (
        ("runtime_format", (cargo, "--locked", "--offline", "fmt", "--manifest-path", runtime_manifest, "--all", "--", "--check")),
        ("runtime_clippy", (cargo, "clippy", "--offline", "--manifest-path", runtime_manifest, "--workspace", "--all-targets", "--locked", "--", "-D", "warnings")),
        ("runtime_tests", (cargo, "test", "--offline", "--manifest-path", runtime_manifest, "--workspace", "--all-targets", "--locked")),
    )


def run_project_gates(environ=None):
    env = os.environ if environ is None else environ
    worker = Path(env.get("WORKER_PATH", ""))
    cargo_home = Path(env.get("CARGO_HOME", ""))
    rust_root = env.get("RUST_ROOT", "")
    node_bin = env.get("NODE_BIN", "")
    if not rust_root or not node_bin or cargo_home != worker / ".kd-cargo-home":
        raise SourceBuildRefusal("gate")
    license_environment = dict(env)
    license_environment["SOURCE_PATH"] = str(worker)
    run_rust_license_gate(license_environment)
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-records"
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    commands = _gate_commands(worker, rust_root, node_bin)
    selected_gates = tuple(name for name, unused_argv in commands)
    expected_gates = GATES + (RUNTIME_GATE_NAMES if _runtime_workspace_present(worker) else ())
    if selected_gates != expected_gates:
        raise SourceBuildRefusal("gate")
    outcomes = {name: "not-run" for name in selected_gates}
    for index, (name, argv) in enumerate(commands):
        project_env = {
            "PATH": str(Path(node_bin)) + ":" + str(Path(rust_root) / "bin") + ":/usr/bin:/bin",
            "LANG": "C", "LC_ALL": "C", "HOME": str(worker / ".home"),
            "TMPDIR": str(worker / ".tmp"), "CARGO_HOME": str(cargo_home),
            "RUSTUP_HOME": str(Path(rust_root) / "rustup"),
            "CARGO_TARGET_DIR": str(worker / "target"), "CARGO_NET_OFFLINE": "true",
            "CARGO_INCREMENTAL": "0", "NPM_CONFIG_OFFLINE": "true",
            "NPM_CONFIG_CACHE": str(worker / ".npm-cache"),
            "NPM_CONFIG_USERCONFIG": "/dev/null", "NPM_CONFIG_GLOBALCONFIG": "/dev/null",
            "npm_config_offline": "true",
            "npm_config_cache": str(worker / ".npm-cache"), "npm_config_userconfig": "/dev/null",
            "npm_config_globalconfig": "/dev/null",
            "PYTHONDONTWRITEBYTECODE": "1", "CI": "true",
        }
        nonce = os.urandom(12).hex()
        try:
            _project_gate_directories(worker)
            launch = ("/usr/bin/python3", "-B", "-c", linux_probes.LAUNCHER_SOURCE, *argv)
            result = linux_session.run_host(
                str(env.get("RUNNER_TEMP", "/tmp")), nonce, launch, project_env, {},
                limits="fixture", timeout=600, cwd=str(worker),
            )
        except BaseException:
            outcomes[name] = "failed"
            break
        (records / ("gate-" + str(index) + ".stdout")).write_bytes(result.stdout)
        (records / ("gate-" + str(index) + ".stderr")).write_bytes(result.stderr)
        if result.exit_code == 0 and not result.timed_out:
            outcomes[name] = "passed"
        else:
            outcomes[name] = "failed"
            break
    completed_gates = [name for name in selected_gates if outcomes[name] == "passed"]
    result = {
        "schema_version": 1, "selected_gates": list(selected_gates),
        "completed_gates": completed_gates, "gates": outcomes,
        "gate_count": sum(value != "not-run" for value in outcomes.values()),
        "failed": sum(value == "failed" for value in outcomes.values()),
    }
    (records / "gates.json").write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    if result["failed"] or result["gate_count"] != len(selected_gates):
        sys.stdout.write("linux-project-gates=refused completed=" + str(result["gate_count"]) + " failed=" + str(result["failed"]) + "\n")
        return 1
    sys.stdout.write("linux-project-gates=passed gates=" + str(len(selected_gates)) + " failed=0 offline=true\n")
    return 0


def _load_json(path):
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            return None
        with os.fdopen(descriptor, "rt", encoding="ascii") as source:
            descriptor = -1
            value = json.loads(source.read(65537))
    except (OSError, UnicodeError, ValueError):
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return value if type(value) is dict else None


def _handoff_record(records):
    path = records / "merged.json"
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600):
        return None
    return _load_json(path)


def verify_proof_handoff(environ=None):
    env = os.environ if environ is None else environ
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-records"
    record = _handoff_record(records)
    if record is None or type(record.get("channels")) is not dict:
        raise SourceBuildRefusal("boundary")
    sys.stdout.write("linux-verifier-proof-handoff=readable owner=runner mode=0600\n")
    return 0


def _verified_source_receipts(records, env):
    gates = _load_json(records / "gates.json")
    revoke = _load_json(records / "revocation.json")
    if type(gates) is not dict or type(gates.get("selected_gates")) is not list:
        return False
    selected_gates = tuple(gates["selected_gates"])
    expected_gate_sets = (GATES, GATES + RUNTIME_GATE_NAMES)
    if (set(gates) != {
                "schema_version", "selected_gates", "completed_gates", "gates", "gate_count", "failed",
            }
            or selected_gates not in expected_gate_sets
            or gates.get("completed_gates") != list(selected_gates)
            or revoke is None or gates.get("schema_version") != 1
            or type(gates.get("gates")) is not dict
            or set(gates["gates"]) != set(selected_gates)
            or any(gates["gates"][name] != "passed" for name in selected_gates)
            or type(gates.get("gate_count")) is not int
            or gates.get("gate_count") != len(selected_gates)
            or type(gates.get("failed")) is not int or gates.get("failed") != 0
            or revoke.get("schema_version") != 1 or revoke.get("status") != "confirmed"
            or revoke.get("control_sha") != env.get("CI_SHA")
            or revoke.get("run_id") != env.get("GITHUB_RUN_ID")
            or revoke.get("run_attempt") != env.get("GITHUB_RUN_ATTEMPT")
            or revoke.get("installation_id") != env.get("SOURCE_READER_INSTALLATION_ID")
            or revoke.get("rejected_after_revoke") is not True):
        return False
    return True


def _verdict_record(environ):
    env = environ
    unused_audit, verdict, unused_canary = _audit_modules()
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-records"
    merged = _handoff_record(records)
    try:
        mode = env.get("CI_MODE")
        if mode not in ("source", "synthetic"):
            raise ValueError
        if merged is None or type(merged.get("channels")) is not dict:
            raise ValueError
        channels = {
            name: {
                "status": merged["channels"][name]["status"],
                "before": merged["channels"][name]["before"],
                "after": merged["channels"][name]["after"],
            }
            for name in verdict.CHANNELS
        }
        memory = merged.get("memory_canary", "not-run")
        readable = merged.get("readable_file_canary", "not-run")
        accepted_source = mode == "source" and _verified_source_receipts(records, env)
        project = "completed" if accepted_source else "not_started"
        gate_count = 13 if accepted_source else 0
        failed = 0
        token_state = "confirmed" if accepted_source else "not-applicable" if mode == "synthetic" else "unconfirmed"
        record = {
            "os": "linux", "boundary": "linux-ns-seccomp-uid",
            "control_sha": env.get("CI_SHA", ""),
            "run_id": int(env.get("GITHUB_RUN_ID", "0")),
            "run_attempt": int(env.get("GITHUB_RUN_ATTEMPT", "0")),
            "channels": channels,
            "memory_canary": memory,
            "readable_file_canary": readable,
            "handoff": "not-applicable",
            "project_execution": project,
            "gates": gate_count,
            "failed": failed,
            "token_revocation": token_state,
        }
    except BaseException:
        record = {
            "os": "linux", "boundary": "linux-ns-seccomp-uid",
            "control_sha": env.get("CI_SHA", "0" * 40),
            "run_id": int(env.get("GITHUB_RUN_ID", "1")) if DECIMAL_RE.fullmatch(env.get("GITHUB_RUN_ID", "")) else 1,
            "run_attempt": int(env.get("GITHUB_RUN_ATTEMPT", "1")) if DECIMAL_RE.fullmatch(env.get("GITHUB_RUN_ATTEMPT", "")) else 1,
            "channels": {name: {"status": "not-run", "before": False, "after": False} for name in verdict.CHANNELS},
            "memory_canary": "not-run", "readable_file_canary": "not-run",
            "handoff": "not-applicable", "project_execution": "not_started",
            "gates": 0, "failed": 0, "token_revocation": "not-applicable" if env.get("CI_MODE") == "synthetic" else "unconfirmed",
        }
    return record


def emit_verdict(environ=None):
    env = os.environ if environ is None else environ
    unused_audit, verdict, unused_canary = _audit_modules()
    record = _verdict_record(env)
    line = verdict.encode_line(record)
    sys.stdout.write(line + "\n")
    accepted = verdict.run_accepted(record) if env.get("CI_MODE") == "source" else verdict.confinement_accepted(record)
    return 0 if accepted and env.get("PRODUCER_RESULT") == "success" else 1


def run_audit(environ=None):
    env = os.environ if environ is None else environ
    try:
        audit, unused_verdict, log_canary = _audit_modules()
        value = env.get("KD_LINUX_LOG_CANARY", "")
        if env.get("CI_MODE") == "synthetic":
            value = SYNTHETIC_LOG_CANARY
        config = log_canary.compute_config(value)
        log_canary.PINNED_CONFIG = config
        code = audit.main(arguments=[], environ=env)
        return code
    except BaseException:
        sys.stdout.write("KD-CONFINEMENT-AUDIT schema=1 status=refused phase=log_canary reason=confinement_audit_invalid\n")
        return 1


def _dispatch(command):
    actions = {
        "snapshot": snapshot_and_preflight,
        "audit-expected": write_audit_identity,
        "preflight": repeat_preflight,
        "toolchains": prepare_toolchains,
        "mint-verifier-token": mint_verifier_token,
        "checkout": checkout_source,
        "revoke": revoke_token,
        "npm-tarballs": fetch_npm_tarballs,
        "trusted-audit": run_trusted_audit,
        "rust-license-gate": run_rust_license_gate,
        "prepare-project": prepare_project,
        "gates": run_project_gates,
        "verify-handoff": verify_proof_handoff,
        "verdict": emit_verdict,
        "audit": run_audit,
    }
    action = actions.get(command)
    if action is None:
        return 2
    try:
        return action()
    except SourceBuildRefusal as error:
        sys.stdout.write("linux-source-build=refused phase=" + command + " reason=" + error.reason + "\n")
        return 1
    except rust_license_gate.LicenseGateRefusal as error:
        refusal = "linux-source-build=refused phase=" + command
        refusal += " reason=license_" + error.reason + "\n"
        sys.stdout.write(refusal)
        return 1
    except BaseException:
        sys.stdout.write("linux-source-build=refused phase=" + command + " reason=invalid\n")
        return 1


def main(arguments=None):
    actual = sys.argv[1:] if arguments is None else arguments
    if len(actual) != 1:
        return 2
    return _dispatch(actual[0])


if __name__ == "__main__":
    raise SystemExit(main())
