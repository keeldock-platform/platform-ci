"""Coordinator ledger and terminal cleanup; never dispatches or creates secrets."""

import argparse
import datetime
import fcntl
import io
import json
import os
import re
import subprocess
import sys
import time
import zipfile
import stat
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "confinement"))
from macos_public_audit import cache_inventory_digest

import bundle
import fetch
import control_audit
import permit
import public_audit


LEDGER_FIELDS = {
    "schema", "wave_id", "bundle_id", "control_run_id", "control_sha", "profile",
    "release_id", "bundle_asset_name", "projection_asset_name", "bundle_asset_id",
    "bundle_sha256", "bundle_size", "projection_asset_id", "projection_sha256",
    "projection_size", "expires", "cache_baseline_sha256", "state", "created_at", "updated_at",
    "run_id", "authorized_run_id", "run_attempt", "cleanup_attempts", "cleanup_obligations",
    "dispatch_requested_at",
}
SECRET_NAME = "DEVLANE_DECRYPT_KEY"
DECRYPT_STEP = "Decrypt authenticated bundle"
RUN_JOB_NAME = "devlane-encrypted-run"
MAX_REVOKE_LATENCY_SECONDS = 120
DECRYPT_ENVIRONMENT = "devlane-decrypt"
TERMINAL = {"success", "failure", "cancelled", "skipped", "timed_out", "action_required", "neutral", "stale"}


class Refusal(ValueError):
    pass


def _fail(code):
    raise Refusal(code)


def _timestamp():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ledger_root(path):
    root = Path(path)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or os.name == "nt" or os.stat(root).st_uid != os.getuid() or os.stat(root).st_mode & 0o077:
        _fail("ledger-permissions")
    return root


def _read(path):
    descriptor = None
    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64 * 1024:
            _fail("ledger-record-invalid")
        data = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, 64 * 1024 + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 64 * 1024:
                _fail("ledger-record-invalid")
        record = bundle.strict_json(bytes(data), 64 * 1024)
    except (OSError, bundle.Refusal):
        _fail("ledger-unavailable")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if type(record) is not dict or set(record) != LEDGER_FIELDS or record.get("schema") != 2:
        _fail("ledger-record-invalid")
    return record


def _write_atomic(path, record):
    target = Path(path)
    temporary = target.with_name(target.name + ".tmp-" + str(os.getpid()) + "-" + str(time.time_ns()))
    payload = bundle.canonical_json(record) + b"\n"
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        directory = os.open(str(target.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _wave_record(root, wave_id):
    _validate_wave_id(wave_id, "wave-id")
    record = _read(Path(root) / (wave_id + ".json"))
    if record["wave_id"] != wave_id:
        _fail("ledger-wave-mismatch")
    return record


def _acquire_lock(path):
    try:
        descriptor = os.open(str(path), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            os.close(descriptor)
            _fail("ledger-lock-invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError:
        _fail("ledger-busy")
    except FileExistsError:
        _fail("ledger-busy")
    except OSError:
        _fail("ledger-lock-unavailable")


def _release_lock(descriptor):
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _cache_records():
    endpoint = "repos/%s/actions/caches?per_page=100" % fetch.REPOSITORY
    result = subprocess.run(["gh", "api", "--paginate", "--slurp", endpoint],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=60, check=False, env=os.environ.copy())
    if result.returncode != 0:
        _fail("cache-inventory-unavailable")
    pages = bundle.strict_json(result.stdout, 16 * 1024 * 1024)
    if type(pages) is not list or not pages:
        _fail("cache-inventory-invalid")
    caches = []
    total_count = None
    for page in pages:
        if type(page) is not dict or type(page.get("actions_caches")) is not list:
            _fail("cache-inventory-invalid")
        count = page.get("total_count")
        if type(count) is not int or count < 0 or (total_count is not None and count != total_count):
            _fail("cache-inventory-invalid")
        total_count = count
        caches.extend(page["actions_caches"])
        if len(caches) > 10_000:
            _fail("cache-inventory-size")
    if total_count != len(caches):
        _fail("cache-inventory-incomplete")
    return caches


def _control_record(root, control_sha, control_run_id):
    path = root / ("control-evidence-" + control_sha + "-" + control_run_id + ".json")
    try:
        record = bundle.strict_json(path.read_bytes(), 4096)
    except (OSError, bundle.Refusal):
        _fail("control-evidence-required")
    if (type(record) is not dict or set(record) != {"schema", "control_sha", "control_run_id", "status", "verified_at"}
            or record.get("schema") != 1 or record.get("control_sha") != control_sha
            or record.get("control_run_id") != control_run_id or record.get("status") != "passed"):
        _fail("control-evidence-invalid")
    return record


def record_control_evidence(ledger, control_run_id, control_sha):
    root = _ledger_root(ledger)
    if not re.fullmatch(r"[1-9][0-9]{0,18}", str(control_run_id)) or not bundle.GIT_SHA.fullmatch(control_sha):
        _fail("control-evidence-input")
    run_id = str(control_run_id)
    run = _gh_json("repos/%s/actions/runs/%s" % (fetch.REPOSITORY, run_id))
    jobs_record = _gh_json("repos/%s/actions/runs/%s/jobs?filter=all&per_page=100&page=1" % (fetch.REPOSITORY, run_id))
    if (type(jobs_record) is not dict or jobs_record.get("total_count") != 18
            or type(jobs_record.get("jobs")) is not list or len(jobs_record["jobs"]) != 18):
        _fail("control-evidence-jobs")
    control_audit.validate_terminal_control_run(run, jobs_record["jobs"], run_id, control_sha, require_main=True)
    key = "devlane-control-v1-" + run_id
    matches = [cache for cache in _cache_records() if type(cache) is dict and cache.get("key") == key]
    if len(matches) != 1 or type(matches[0].get("size_in_bytes")) is not int or matches[0]["size_in_bytes"] > 16 * 1024:
        _fail("control-evidence-cache")
    record = {
        "schema": 1, "control_sha": control_sha, "control_run_id": run_id,
        "status": "passed", "verified_at": _timestamp(),
    }
    _write_atomic(root / ("control-evidence-" + control_sha + "-" + run_id + ".json"), record)
    print("control_evidence=passed sha=" + control_sha + " run-id=" + run_id)


def _validate_wave_id(value, code):
    if type(value) is not str or not bundle.OPAQUE_ID.fullmatch(value):
        _fail(code)


def reserve_wave(ledger, request):
    root = _ledger_root(ledger)
    required = {"schema", "wave_id", "bundle_id", "control_run_id", "control_sha", "profile", "expires", "release_id"}
    if type(request) is not dict or set(request) != required or request["schema"] != 2:
        _fail("reservation-shape")
    for name in ("wave_id", "bundle_id"):
        _validate_wave_id(request[name], "reservation-id")
    if (request["profile"] not in ("core-node", "core-rust")
            or not re.fullmatch(r"[1-9][0-9]{0,18}", str(request["control_run_id"]))
            or type(request["control_sha"]) is not str or not bundle.GIT_SHA.fullmatch(request["control_sha"])
            or type(request["expires"]) is not int or not int(time.time()) < request["expires"] <= int(time.time()) + 3600):
        _fail("reservation-bounds")
    control_run_id = str(request["control_run_id"])
    _control_record(root, request["control_sha"], control_run_id)
    _verify_secret_absent()
    if type(request["release_id"]) is not str or not re.fullmatch(r"[1-9][0-9]{0,18}", request["release_id"]):
        _fail("reservation-release")
    global_lock = root / ".dispatch.lock"
    lock_descriptor = _acquire_lock(global_lock)
    try:
        for current in root.glob("*.json"):
            if current.name.startswith("control-evidence-"):
                continue
            record = _read(current)
            if record["wave_id"] != current.stem:
                _fail("ledger-wave-mismatch")
            if record["state"] != "deleted":
                _fail("wave-already-open")
            if record["bundle_id"] == request["bundle_id"]:
                _fail("bundle-replay")
        target = root / (request["wave_id"] + ".json")
        record = {
            "schema": 2, "wave_id": request["wave_id"], "bundle_id": request["bundle_id"],
            "control_run_id": control_run_id, "control_sha": request["control_sha"],
            "profile": request["profile"], "release_id": request["release_id"],
            "bundle_asset_name": "devlane-" + request["wave_id"] + "-" + request["bundle_id"] + ".enc",
            "projection_asset_name": "devlane-" + request["wave_id"] + "-" + request["bundle_id"] + ".projection.json",
            "bundle_asset_id": None, "bundle_sha256": None, "bundle_size": None,
            "projection_asset_id": None, "projection_sha256": None, "projection_size": None,
            "expires": request["expires"], "cache_baseline_sha256": None,
            "state": "reserved", "created_at": _timestamp(), "updated_at": None,
            "run_id": None, "authorized_run_id": None, "run_attempt": None,
            "dispatch_requested_at": None, "cleanup_attempts": [],
            "cleanup_obligations": {
                "secret": {"state": "not-installed"},
                "bundle_asset": {"state": "not-uploaded"},
                "projection_asset": {"state": "not-uploaded"},
                "logs": {"state": "not-created"}, "artifacts": {"state": "not-created"},
                "run": {"state": "not-dispatched"},
                "replay_guard": {"state": "not-created", "retain_until": request["expires"]},
            },
        }
        try:
            record_descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            _fail("wave-replay")
        try:
            with os.fdopen(record_descriptor, "wb") as output:
                output.write(bundle.canonical_json(record) + b"\n")
                output.flush()
                os.fsync(output.fileno())
            directory = os.open(str(root), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception:
            try:
                target.unlink()
            except OSError:
                pass
            raise
    finally:
        _release_lock(lock_descriptor)
    print("wave_reserved=true")


def stage_bundle(ledger, wave_id, request):
    root = _ledger_root(ledger)
    _validate_wave_id(wave_id, "wave-id")
    required = {"schema", "bundle_sha256", "bundle_size", "projection_sha256", "projection_size"}
    if type(request) is not dict or set(request) != required or request["schema"] != 1:
        _fail("staged-assets-shape")
    record = _wave_record(root, wave_id)
    if record["state"] != "reserved":
        _fail("staged-assets-state")
    for name in ("bundle_sha256", "projection_sha256"):
        if type(request[name]) is not str or not bundle.SHA256.fullmatch(request[name]):
            _fail("staged-assets-digest")
    if (type(request["bundle_size"]) is not int or not 1 <= request["bundle_size"] <= bundle.MAX_CIPHERTEXT
            or type(request["projection_size"]) is not int or not 1 <= request["projection_size"] <= fetch.MAX_PROJECTION):
        _fail("staged-assets-size")
    existing = _release_assets(record["release_id"])
    expected_names = {record["bundle_asset_name"], record["projection_asset_name"]}
    if any(asset.get("name") in expected_names for asset in existing):
        _fail("staged-asset-name-exists")
    record.update({
        "bundle_sha256": request["bundle_sha256"], "bundle_size": request["bundle_size"],
        "projection_sha256": request["projection_sha256"], "projection_size": request["projection_size"],
        "state": "assets-staged", "updated_at": _timestamp(),
    })
    record["cleanup_obligations"]["bundle_asset"] = {"state": "upload-pending", "name": record["bundle_asset_name"]}
    record["cleanup_obligations"]["projection_asset"] = {"state": "upload-pending", "name": record["projection_asset_name"]}
    _write_atomic(root / (wave_id + ".json"), record)
    print("assets_staged=true")


def record_intent(ledger, request):
    root = _ledger_root(ledger)
    required = {"schema", "wave_id", "bundle_asset_id", "projection_asset_id", "cache_baseline_sha256"}
    if type(request) is not dict or set(request) != required or request["schema"] != 2:
        _fail("intent-shape")
    wave_id = request["wave_id"]
    _validate_wave_id(wave_id, "intent-id")
    path = root / (wave_id + ".json")
    record = _wave_record(root, wave_id)
    if record["state"] != "assets-staged":
        _fail("intent-state")
    for asset_name in ("bundle_asset_id", "projection_asset_id"):
        if type(request[asset_name]) is not str or not re.fullmatch(r"[1-9][0-9]{0,18}", request[asset_name]):
            _fail("intent-asset")
    if type(request["cache_baseline_sha256"]) is not str or not bundle.SHA256.fullmatch(request["cache_baseline_sha256"]):
        _fail("intent-cache-baseline")
    caches = _cache_records()
    if cache_inventory_digest(caches) != request["cache_baseline_sha256"]:
        _fail("cache-baseline-changed")
    if any(type(item) is dict and item.get("key") == "devlane-permit-v1-" + record["bundle_id"] for item in caches):
        _fail("bundle-replay")
    record.update({
        "bundle_asset_id": request["bundle_asset_id"],
        "projection_asset_id": request["projection_asset_id"],
        "cache_baseline_sha256": request["cache_baseline_sha256"],
        "state": "assets-attached", "updated_at": _timestamp(),
    })
    for key, asset_id in (("bundle_asset", record["bundle_asset_id"]), ("projection_asset", record["projection_asset_id"])):
        _verify_asset(record, key, asset_id)
        record["cleanup_obligations"][key] = {"state": "pending", "asset_id": asset_id}
    _write_atomic(path, record)
    print("wave_assets_attached=true")


def transition(ledger, wave_id, action, run_id=None):
    root = _ledger_root(ledger)
    if not bundle.OPAQUE_ID.fullmatch(wave_id):
        _fail("wave-id")
    path = root / (wave_id + ".json")
    lock = root / (wave_id + ".lock")
    descriptor = _acquire_lock(lock)
    try:
        record = _wave_record(root, wave_id)
        allowed = {
            "mark-secret-installing": ("assets-attached", "secret-installing"),
            "mark-secret-installed": ("secret-installing", "secret-installed"),
            "mark-dispatch-requested": ("secret-installed", "dispatch-requested"),
            "attach-run": ("dispatch-requested", "run-attached"),
            "mark-terminal": ("run-attached", "terminal"),
        }
        """A run that surfaces only during cleanup recovery is attached without leaving cleanup."""
        recovering = action == "attach-run" and record["state"] in ("cleanup-failed", "cleanup-in-progress")
        if action not in allowed or (record["state"] != allowed[action][0] and not recovering):
            _fail("ledger-transition")
        if recovering and record["authorized_run_id"] is not None:
            _fail("ledger-transition")
        if action == "mark-secret-installing":
            _verify_environment()
        if action == "mark-secret-installed":
            _verify_environment()
            _verify_secret_present()
            record["cleanup_obligations"]["secret"] = {"state": "installed", "verified_at": _timestamp()}
        if action == "mark-dispatch-requested":
            record["dispatch_requested_at"] = _timestamp()
            record["cleanup_obligations"]["run"] = {"state": "dispatch-ambiguous"}
        if action == "attach-run":
            if type(run_id) is not str or not re.fullmatch(r"[1-9][0-9]{0,18}", run_id):
                _fail("run-id")
            attached_run = _verify_run_identity(run_id, record, terminal=False)
            _verify_run_binding(run_id, record, attached_run)
            record["run_id"] = run_id
            record["authorized_run_id"] = run_id
            record["run_attempt"] = 1
            record["cleanup_obligations"].update({
                "run": {"state": "present", "run_id": run_id},
                "logs": {"state": "present", "run_id": run_id},
                "artifacts": {"state": "inventory-pending", "run_id": run_id},
                "replay_guard": {"state": "consumed", "retain_until": record["expires"]},
            })
        if action == "mark-terminal":
            if record["run_id"] is None or record["authorized_run_id"] != record["run_id"]:
                _fail("run-id-missing")
            """Revoke before any public surface is collected or audited."""
            record["cleanup_obligations"]["secret"] = {"state": "secret-delete-pending", "attempted_at": _timestamp()}
            _write_atomic(path, record)
            _revoke_secret()
            record["cleanup_obligations"]["secret"] = {"state": "absent", "verified_at": _timestamp()}
            _write_atomic(path, record)
            run = _verify_terminal(record["run_id"], record)
            _verify_wave_marker(record["run_id"], record, run)
            disposition = _terminal_audit_disposition(record["run_id"], record, run, root)
            record["cleanup_obligations"]["logs"] = {"state": "present", "run_id": record["run_id"]}
            record["cleanup_obligations"]["artifacts"] = {"state": "inventory-pending", "run_id": record["run_id"]}
        record["state"] = record["state"] if recovering else allowed[action][1]
        record["updated_at"] = _timestamp()
        if action == "mark-terminal":
            record["cleanup_attempts"].append({
                "at": _timestamp(), "result": "terminal-confirmed", "audit_disposition": disposition,
            })
        _write_atomic(path, record)
    finally:
        _release_lock(descriptor)
    print("wave_state=" + record["state"])


def _gh_json(endpoint):
    result = subprocess.run(["gh", "api", endpoint], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=30, check=False, env=os.environ.copy())
    if result.returncode != 0:
        _fail("github-api-unavailable")
    return bundle.strict_json(result.stdout, 2 * 1024 * 1024)


def _cli_token():
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    try:
        result = subprocess.run(["gh", "auth", "token", "--hostname", "github.com"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=10, check=False, env=os.environ.copy())
    except (OSError, subprocess.SubprocessError):
        _fail("github-auth-unavailable")
    token = result.stdout.decode("ascii", "strict").strip()
    if result.returncode != 0 or not token or len(token) > 256:
        _fail("github-auth-unavailable")
    return token


def _verify_asset(record, key, asset_id):
    if key == "bundle_asset":
        expected_name, expected_size, expected_digest = (
            record["bundle_asset_name"], record["bundle_size"], record["bundle_sha256"]
        )
    elif key == "projection_asset":
        expected_name, expected_size, expected_digest = (
            record["projection_asset_name"], record["projection_size"], record["projection_sha256"]
        )
    else:
        _fail("asset-kind-invalid")
    asset = _gh_json("repos/%s/releases/assets/%s" % (fetch.REPOSITORY, asset_id))
    if (type(asset) is not dict or str(asset.get("id")) != asset_id
            or asset.get("name") != expected_name or asset.get("size") != expected_size
            or asset.get("state") != "uploaded"
            or asset.get("digest") != "sha256:" + expected_digest):
        _fail("asset-identity-mismatch")
    release_assets = _release_assets(record["release_id"])
    matches = [item for item in release_assets if item.get("id") == int(asset_id)]
    if (len(matches) != 1 or matches[0].get("name") != expected_name
            or matches[0].get("size") != expected_size
            or matches[0].get("digest") != "sha256:" + expected_digest):
        _fail("asset-release-mismatch")
    return asset


def _release_assets(release_id):
    endpoint = "repos/%s/releases/%s/assets?per_page=100" % (fetch.REPOSITORY, release_id)
    result = subprocess.run(["gh", "api", "--paginate", "--slurp", endpoint],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=60, check=False, env=os.environ.copy())
    if result.returncode != 0:
        _fail("release-asset-inventory-unavailable")
    pages = bundle.strict_json(result.stdout, 16 * 1024 * 1024)
    if type(pages) is not list or not pages or any(type(page) is not list for page in pages):
        _fail("release-asset-inventory-invalid")
    assets = [asset for page in pages for asset in page]
    if len(assets) > 10_000 or any(type(asset) is not dict for asset in assets):
        _fail("release-asset-inventory-invalid")
    ids = [asset.get("id") for asset in assets]
    if any(type(item) is not int or item < 1 for item in ids) or len(ids) != len(set(ids)):
        _fail("release-asset-inventory-invalid")
    return assets


def _environment_secret_endpoint():
    return "repos/%s/environments/%s/secrets/%s" % (fetch.REPOSITORY, DECRYPT_ENVIRONMENT, SECRET_NAME)


def _repository_secret_endpoint():
    """Never used for installation: a repository-wide copy of the key is readable by any workflow on any branch."""
    return "repos/%s/actions/secrets/%s" % (fetch.REPOSITORY, SECRET_NAME)


def _verify_environment():
    """The decryption environment must exist, admit only main and give administrators no bypass of that rule."""
    base = "repos/%s/environments/%s" % (fetch.REPOSITORY, DECRYPT_ENVIRONMENT)
    environment = _gh_json(base)
    policy = environment.get("deployment_branch_policy") if type(environment) is dict else None
    if (type(environment) is not dict or environment.get("name") != DECRYPT_ENVIRONMENT
            or type(policy) is not dict
            or environment.get("can_admins_bypass") is not False
            or policy.get("protected_branches") is not False or policy.get("custom_branch_policies") is not True):
        _fail("environment-unrestricted")
    policies = _gh_json(base + "/deployment-branch-policies")
    entries = policies.get("branch_policies") if type(policies) is dict else None
    if (type(entries) is not list or policies.get("total_count") != 1 or len(entries) != 1
            or type(entries[0]) is not dict or entries[0].get("name") != "main"
            or entries[0].get("type", "branch") != "branch"):
        _fail("environment-unrestricted")


def _verify_secret_present():
    """Environment-secret metadata is name and timestamps; a repository-wide copy must not also exist."""
    secret = _gh_json(_environment_secret_endpoint())
    if (type(secret) is not dict or secret.get("name") != SECRET_NAME
            or type(secret.get("created_at")) is not str or type(secret.get("updated_at")) is not str):
        _fail("secret-install-unverified")
    if _gh_status(_repository_secret_endpoint()) not in (404, 410):
        _fail("secret-repository-scope")
    return _environment_secret_endpoint()


def _revoke_secret():
    """Delete the decryption secret (and any repository-wide copy) and prove both gone; raise on anything ambiguous."""
    for endpoint in (_environment_secret_endpoint(), _repository_secret_endpoint()):
        status = _gh_status(endpoint)
        if status in (404, 410):
            continue
        if status != 200:
            _fail("secret-state-ambiguous")
        _delete_and_verify(endpoint)


def revoke_secret(ledger, wave_id):
    root = _ledger_root(ledger)
    _validate_wave_id(wave_id, "wave-id")
    path = root / (wave_id + ".json")
    lock = root / (wave_id + ".lock")
    descriptor = _acquire_lock(lock)
    try:
        record = _wave_record(root, wave_id)
        if record["state"] not in (
            "secret-installing", "secret-installed", "dispatch-requested", "run-attached", "terminal",
            "cleanup-in-progress", "cleanup-failed", "run-delete-pending",
        ):
            _fail("revoke-state")
        record["cleanup_obligations"]["secret"] = {"state": "secret-delete-pending", "attempted_at": _timestamp()}
        record["updated_at"] = _timestamp()
        _write_atomic(path, record)
        _revoke_secret()
        record["cleanup_obligations"]["secret"] = {"state": "absent", "verified_at": _timestamp()}
        record["updated_at"] = _timestamp()
        _write_atomic(path, record)
    finally:
        _release_lock(descriptor)
    print("secret_revoked=true")


def _verify_secret_absent():
    for endpoint in (_environment_secret_endpoint(), _repository_secret_endpoint()):
        if _gh_status(endpoint) not in (404, 410):
            _fail("secret-already-installed")


def _verify_run_identity(run_id, record, *, terminal=False):
    run = _gh_json("repos/%s/actions/runs/%s" % (fetch.REPOSITORY, run_id))
    repository = run.get("repository") if type(run) is dict else None
    valid_status = (run.get("status") == "completed" if terminal else run.get("status") in ("queued", "in_progress", "completed")) if type(run) is dict else False
    if (type(run) is not dict or str(run.get("id")) != run_id or run.get("path") != fetch.WORKFLOW_PATH
            or run.get("event") != "workflow_dispatch" or run.get("run_attempt") != 1
            or run.get("head_branch") != "main" or run.get("head_sha") != record["control_sha"]
            or not valid_status or type(repository) is not dict
            or repository.get("full_name") != fetch.REPOSITORY
            or str(repository.get("id")) != fetch.REPOSITORY_ID):
        _fail("run-identity-mismatch")
    return run


def expected_run_title(record):
    return "devlane wave=%s bundle=%s" % (record["wave_id"], record["bundle_id"])


def _verify_run_binding(run_id, record, run):
    """Bind a run to its wave: dispatch-time run title, else the in-run marker.

    The title is fixed from the dispatch inputs, so a run that failed before it
    could print the marker (setup, fetch, permit failure) is still attributable.
    """
    if type(run) is dict and run.get("display_title") == expected_run_title(record):
        return "title"
    _verify_dispatch_log(run_id, record)
    return "marker"


def _verify_dispatch_log(run_id, record):
    archive = _run_log_bundle(run_id)
    marker = ("KD-DEVLANE-DISPATCH schema=1 wave-id=%s bundle-id=%s control-sha=%s "
              "run-id=%s run-attempt=1" % (
                  record["wave_id"], record["bundle_id"], record["control_sha"], run_id,
              )).encode("ascii")
    permit_marker = ("devlane_permit=consumed run-id=%s run-attempt=1" % run_id).encode("ascii")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as log_archive:
            if len(log_archive.infolist()) > 100:
                _fail("run-log-contract")
            total = marker_count = permit_count = 0
            for entry in log_archive.infolist():
                if entry.is_dir() or entry.file_size > 8 * 1024 * 1024:
                    continue
                total += entry.file_size
                if total > 32 * 1024 * 1024:
                    _fail("run-log-size")
                payload = log_archive.read(entry)
                marker_count += payload.count(marker)
                permit_count += payload.count(permit_marker)
    except (OSError, zipfile.BadZipFile, RuntimeError):
        _fail("run-log-invalid")
    if marker_count != 1 or permit_count != 1:
        _fail("run-wave-binding")


def cache_baseline():
    endpoint = "repos/%s/actions/caches?per_page=100" % fetch.REPOSITORY
    result = subprocess.run(["gh", "api", "--paginate", "--slurp", endpoint],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=60, check=False, env=os.environ.copy())
    if result.returncode != 0:
        _fail("cache-inventory-unavailable")
    pages = bundle.strict_json(result.stdout, 16 * 1024 * 1024)
    if type(pages) is not list or not pages:
        _fail("cache-inventory-invalid")
    caches = []
    total_count = None
    for page in pages:
        if type(page) is not dict or type(page.get("actions_caches")) is not list:
            _fail("cache-inventory-invalid")
        count = page.get("total_count")
        if type(count) is not int or count < 0 or (total_count is not None and count != total_count):
            _fail("cache-inventory-invalid")
        total_count = count
        caches.extend(page["actions_caches"])
        if len(caches) > 10_000:
            _fail("cache-inventory-size")
    if total_count != len(caches):
        _fail("cache-inventory-incomplete")
    print("cache_baseline_sha256=" + cache_inventory_digest(caches))


def _run_log_bundle(run_id, maximum=8 * 1024 * 1024):
    command = ["gh", "api", "repos/%s/actions/runs/%s/logs" % (fetch.REPOSITORY, run_id)]
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, close_fds=True, env=os.environ.copy())
        output = bytearray()
        while True:
            chunk = process.stdout.read(min(65536, maximum + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > maximum:
                process.kill()
                process.wait(timeout=5)
                _fail("run-log-bundle-size")
        if process.wait(timeout=30) != 0:
            _fail("run-logs-unavailable")
        return bytes(output)
    except (OSError, subprocess.SubprocessError):
        _fail("run-logs-unavailable")


def _verify_wave_marker(run_id, record, run=None):
    if run is None:
        run = _gh_json("repos/%s/actions/runs/%s" % (fetch.REPOSITORY, run_id))
    _verify_run_binding(run_id, record, run)


def _gh_delete(endpoint):
    result = subprocess.run(["gh", "api", "--include", "--method", "DELETE", endpoint],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=30, check=False, env=os.environ.copy())
    match = re.search(rb"(?m)^HTTP/[^ \r\n]+[ \t]+([0-9]{3})(?:[ \t]|\r?$)", result.stdout)
    if match is None or int(match.group(1)) not in (204, 404):
        _fail("github-delete-failed")


def _gh_status(endpoint):
    try:
        process = subprocess.Popen(["gh", "api", "--include", endpoint], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   close_fds=True, env=os.environ.copy())
        line = process.stdout.readline(256)
        process.kill()
        process.wait(timeout=5)
    except (OSError, subprocess.SubprocessError):
        _fail("github-verify-unavailable")
    match = re.match(rb"^HTTP/[^ \r\n]+[ \t]+([0-9]{3})(?:[ \t]|\r?$)", line)
    if match is None:
        _fail("github-verify-unavailable")
    return int(match.group(1))


def _expect_absent(endpoint):
    if _gh_status(endpoint) not in (404, 410):
        _fail("deletion-not-verified")


def _artifact_ids(run_id):
    endpoint = "repos/%s/actions/runs/%s/artifacts?per_page=100" % (fetch.REPOSITORY, run_id)
    result = subprocess.run(["gh", "api", "--paginate", "--slurp", endpoint],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=60, check=False, env=os.environ.copy())
    if result.returncode != 0:
        _fail("artifact-inventory-unavailable")
    pages = bundle.strict_json(result.stdout, 16 * 1024 * 1024)
    if type(pages) is not list or not pages:
        _fail("artifact-inventory-invalid")
    records = []
    total_count = None
    for page in pages:
        if type(page) is not dict or type(page.get("artifacts")) is not list:
            _fail("artifact-inventory-invalid")
        count = page.get("total_count")
        if type(count) is not int or count < 0 or (total_count is not None and total_count != count):
            _fail("artifact-inventory-invalid")
        total_count = count
        records.extend(page["artifacts"])
        if len(records) > 10_000:
            _fail("artifact-inventory-size")
    if total_count != len(records):
        _fail("artifact-inventory-incomplete")
    identifiers = []
    for artifact in records:
        if type(artifact) is not dict or type(artifact.get("id")) is not int or artifact["id"] < 1:
            _fail("artifact-inventory-invalid")
        identifiers.append(artifact["id"])
    if len(identifiers) != len(set(identifiers)):
        _fail("artifact-inventory-invalid")
    return identifiers


def _workflow_run_pages(endpoint):
    """Return a complete, bounded run inventory or refuse ambiguity."""
    try:
        result = subprocess.run(
            ["gh", "api", "--paginate", "--slurp", endpoint],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=60, check=False, env=os.environ.copy(),
        )
    except (OSError, subprocess.SubprocessError):
        _fail("dispatch-run-inventory-unavailable")
    if result.returncode != 0:
        _fail("dispatch-run-inventory-unavailable")
    pages = bundle.strict_json(result.stdout, 16 * 1024 * 1024)
    if type(pages) is not list or not pages:
        _fail("dispatch-run-inventory")
    runs, total_count = [], None
    for page in pages:
        if type(page) is not dict or type(page.get("workflow_runs")) is not list:
            _fail("dispatch-run-inventory")
        count = page.get("total_count")
        if type(count) is not int or count < 0 or (total_count is not None and count != total_count):
            _fail("dispatch-run-inventory")
        total_count = count
        runs.extend(page["workflow_runs"])
        if len(runs) > 10_000:
            _fail("dispatch-run-inventory-size")
    if total_count != len(runs):
        _fail("dispatch-run-inventory-incomplete")
    return runs


def _preserve_diagnostics(root, record, records):
    """Keep the validated public records in the private ledger before the logs are deleted."""
    if root is None:
        return None
    target = Path(root) / ("diagnostics-" + record["wave_id"] + ".jsonl")
    payload = b"".join(line + b"\n" for line in records)
    if len(payload) > 64 * 1024:
        _fail("diagnostics-size")
    temporary = target.with_name(target.name + ".tmp-" + str(os.getpid()))
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, target)
    return target.name


def _terminal_audit_disposition(run_id, record, run, root=None):
    if (str(run.get("id")) != run_id or run.get("path") != fetch.WORKFLOW_PATH
            or run.get("head_branch") != "main" or run.get("head_sha") != record["control_sha"]
            or run.get("event") != "workflow_dispatch" or run.get("run_attempt") != 1):
        _fail("run-identity-mismatch")
    endpoint = "repos/%s/actions/runs/%s/jobs?filter=all&per_page=100&page=1" % (fetch.REPOSITORY, run_id)
    try:
        response = _gh_json(endpoint)
        jobs = response.get("jobs") if type(response) is dict else None
        if type(jobs) is not list or len(jobs) > 100:
            return "refused"
        identity = {"run_id": run_id, "control_sha": record["control_sha"],
                    "control_run_id": record["control_run_id"],
                    "profile": record["profile"], "wave_id": record["wave_id"],
                    "bundle_id": record["bundle_id"], "cache_baseline_sha256": record["cache_baseline_sha256"]}
        public = public_audit.validate_final_public_surfaces(GitHubAPI(_cli_token()), jobs, identity, record["profile"])
        if response.get("total_count") != 2:
            return "refused"
        _verify_wave_marker(run_id, record, run)
    except Exception:
        return "refused"
    try:
        _preserve_diagnostics(root, record, public["records"])
        return "accepted"
    except Exception:
        return "preserve-failed"


def _verify_terminal(run_id, record):
    run = _verify_run_identity(run_id, record, terminal=True)
    if run.get("conclusion") not in TERMINAL:
        _fail("run-not-terminal")
    return run


def _delete_and_verify(endpoint):
    try:
        _gh_delete(endpoint)
    except Refusal:
        if _gh_status(endpoint) in (404, 410):
            return
        raise
    _expect_absent(endpoint)


def _cleanup_asset(record, obligation_name):
    obligation = record["cleanup_obligations"][obligation_name]
    if obligation.get("state") in ("not-uploaded", "absent"):
        return
    assets = _release_assets(record["release_id"])
    name = record["bundle_asset_name"] if obligation_name == "bundle_asset" else record["projection_asset_name"]
    expected_size = record["bundle_size"] if obligation_name == "bundle_asset" else record["projection_size"]
    matches = [asset for asset in assets if asset.get("name") == name]
    if not matches:
        obligation.update({"state": "absent", "verified_at": _timestamp()})
        return
    if len(matches) != 1:
        obligation.update({"state": "ambiguous", "matches": len(matches)})
        _fail("asset-name-ambiguous")
    asset = matches[0]
    asset_id = str(asset.get("id"))
    expected_id = record.get("bundle_asset_id" if obligation_name == "bundle_asset" else "projection_asset_id")
    expected_digest = record["bundle_sha256"] if obligation_name == "bundle_asset" else record["projection_sha256"]
    if ((expected_id is not None and asset_id != expected_id) or asset.get("size") != expected_size
            or asset.get("state") != "uploaded" or asset.get("digest") != "sha256:" + expected_digest):
        obligation.update({"state": "identity-mismatch", "asset_id": asset_id})
        _fail("asset-identity-mismatch")
    obligation.update({"state": "delete-pending", "asset_id": asset_id})
    endpoint = "repos/%s/releases/assets/%s" % (fetch.REPOSITORY, asset_id)
    _delete_and_verify(endpoint)
    obligation.update({"state": "absent", "asset_id": asset_id, "verified_at": _timestamp()})


def cleanup_terminal(ledger, wave_id):
    root = _ledger_root(ledger)
    _validate_wave_id(wave_id, "wave-id")
    path = root / (wave_id + ".json")
    record = _wave_record(root, wave_id)
    allowed_states = {
        "reserved", "assets-staged", "assets-attached", "secret-installing", "secret-installed",
        "dispatch-requested", "run-attached", "terminal", "cleanup-in-progress", "cleanup-failed",
        "run-delete-pending",
    }
    if record["state"] not in allowed_states:
        _fail("cleanup-state")
    lock = root / (wave_id + ".lock")
    descriptor = _acquire_lock(lock)
    attempt = {"at": _timestamp(), "result": "started", "obligations": {}}
    record["cleanup_attempts"].append(attempt)
    if len(record["cleanup_attempts"]) > 50:
        _release_lock(descriptor)
        _fail("cleanup-attempt-limit")
    record["state"] = "cleanup-in-progress"
    record["updated_at"] = _timestamp()
    try:
        _write_atomic(path, record)
    except Exception:
        _release_lock(descriptor)
        raise

    def persist():
        record["updated_at"] = _timestamp()
        _write_atomic(path, record)

    def attempt_obligation(name, operation, *, ambiguous="pending", pending_state="delete-pending"):
        obligation = record["cleanup_obligations"][name]
        if obligation.get("state") not in ("absent", "not-created", "not-dispatched", "not-uploaded"):
            obligation.update({"state": pending_state, "attempted_at": _timestamp()})
        attempt["obligations"][name] = "pending"
        persist()
        try:
            operation()
            if obligation.get("state") not in ("absent", "retained"):
                obligation.update({"state": "absent", "verified_at": _timestamp()})
            attempt["obligations"][name] = "absent"
        except Exception as error:
            code = str(error) if isinstance(error, Refusal) else "cleanup-operation-failed"
            obligation.update({"state": ambiguous, "last_error": code, "attempted_at": _timestamp()})
            attempt["obligations"][name] = "pending"
        persist()

    try:
        attempt_obligation(
            "secret", _revoke_secret, ambiguous="secret-delete-pending",
            pending_state="secret-delete-pending",
        )

        cleanup_identity_valid = False
        run_already_absent = False
        hold_for_preservation = False
        if record["run_id"] is not None:
            run_obligation = record["cleanup_obligations"]["run"]
            expected_receipt = {
                "run_id": record["run_id"], "run_attempt": 1,
                "wave_id": record["wave_id"], "bundle_id": record["bundle_id"],
                "control_sha": record["control_sha"],
            }
            if (record["authorized_run_id"] != record["run_id"] or record["run_attempt"] != 1):
                attempt["audit_disposition"] = "refused"
                attempt["audit_error"] = "run-identity-mismatch"
                run_obligation.update({"state": "identity-mismatch"})
                persist()
            elif _gh_status("repos/%s/actions/runs/%s" % (fetch.REPOSITORY, record["run_id"])) in (404, 410):
                """The run was already deleted (a previous DELETE succeeded but its response or ledger write was lost). The attached identity was bound at attach time; only absence remains to be recorded, so run, logs and artifacts close below."""
                run_already_absent = True
                attempt["audit_disposition"] = "not-collected"
                persist()
            else:
                try:
                    run = _verify_terminal(record["run_id"], record)
                    if run_obligation.get("identity_verified") != expected_receipt:
                        _verify_wave_marker(record["run_id"], record, run)
                        run_obligation["identity_verified"] = expected_receipt
                        persist()
                    cleanup_identity_valid = True
                    attempt["audit_disposition"] = _terminal_audit_disposition(
                        record["run_id"], record, run, root)
                    if attempt["audit_disposition"] != "accepted":
                        run_obligation.update({"state": "audit-refused"})
                    if attempt["audit_disposition"] == "preserve-failed" and len(record["cleanup_attempts"]) <= 3:
                        hold_for_preservation = True
                except Exception as error:
                    attempt["audit_disposition"] = "refused"
                    attempt["audit_error"] = str(error) if isinstance(error, Refusal) else "audit-unavailable"
                    run_obligation.update({"state": "identity-unverified"})
                persist()

        for name in ("bundle_asset", "projection_asset"):
            attempt_obligation(
                name, lambda name=name: _cleanup_asset(record, name),
                ambiguous="delete-pending", pending_state="delete-pending",
            )

        run_id = record.get("authorized_run_id")
        if run_id is None:
            if record.get("dispatch_requested_at"):
                def unresolved_dispatch():
                    _fail("dispatch-unreconciled")
                attempt_obligation(
                    "run", unresolved_dispatch, ambiguous="dispatch-ambiguous",
                    pending_state="dispatch-ambiguous",
                )
                record["cleanup_obligations"]["logs"].update({"state": "dispatch-ambiguous"})
                record["cleanup_obligations"]["artifacts"].update({"state": "dispatch-ambiguous"})
                attempt["obligations"]["logs"] = "dispatch-ambiguous"
                attempt["obligations"]["artifacts"] = "dispatch-ambiguous"
            else:
                record["cleanup_obligations"]["run"] = {"state": "not-dispatched"}
                record["cleanup_obligations"]["logs"] = {"state": "not-created"}
                record["cleanup_obligations"]["artifacts"] = {"state": "not-created"}
                attempt["obligations"].update({"run": "absent", "logs": "absent", "artifacts": "absent"})
                persist()
        else:
            identity = {"control_sha": record["control_sha"]}
            run_endpoint = "repos/%s/actions/runs/%s" % (fetch.REPOSITORY, run_id)

            def delete_logs():
                if run_already_absent or _gh_status(run_endpoint) in (404, 410):
                    return
                if not cleanup_identity_valid:
                    _fail("run-identity-unverified")
                if hold_for_preservation:
                    _fail("diagnostics-preservation-pending")
                if _gh_status(run_endpoint + "/logs") in (404, 410):
                    return
                _verify_run_identity(run_id, record, terminal=True)
                _delete_and_verify(run_endpoint + "/logs")

            attempt_obligation(
                "logs", delete_logs, ambiguous="delete-pending", pending_state="delete-pending",
            )

            def delete_artifacts():
                if run_already_absent or _gh_status(run_endpoint) in (404, 410):
                    return
                if not cleanup_identity_valid:
                    _fail("run-identity-unverified")
                if hold_for_preservation:
                    _fail("diagnostics-preservation-pending")
                _verify_run_identity(run_id, record, terminal=True)
                identifiers = _artifact_ids(run_id)
                items = record["cleanup_obligations"]["artifacts"].setdefault("items", {})
                live = {str(item) for item in identifiers}
                for prior_id, prior in items.items():
                    if prior_id not in live:
                        prior.update({"state": "absent", "verified_at": _timestamp()})
                for artifact_id in identifiers:
                    item_key = str(artifact_id)
                    item = items.setdefault(item_key, {"state": "delete-pending"})
                    item.update({"state": "delete-pending", "attempted_at": _timestamp()})
                    persist()
                    try:
                        _delete_and_verify("repos/%s/actions/artifacts/%s" % (fetch.REPOSITORY, artifact_id))
                        item.update({"state": "absent", "verified_at": _timestamp()})
                    except Exception:
                        item.update({"state": "delete-pending", "attempted_at": _timestamp()})
                        persist()
                persist()
                if any(item.get("state") != "absent" for item in items.values()):
                    _fail("artifact-deletion-unverified")
                if _artifact_ids(run_id):
                    _fail("artifact-deletion-unverified")

            attempt_obligation(
                "artifacts", delete_artifacts, ambiguous="delete-pending", pending_state="delete-pending",
            )

            def delete_authorized_run():
                status = _gh_status(run_endpoint)
                if status in (404, 410):
                    return
                if not cleanup_identity_valid:
                    _fail("run-identity-unverified")
                if hold_for_preservation:
                    _fail("diagnostics-preservation-pending")
                """Deleting the run removes its logs and artifacts, so an unresolved log or artifact obligation never blocks this independent attempt."""
                _verify_run_identity(run_id, record, terminal=True)
                record["cleanup_obligations"]["run"].update({
                    "state": "delete-pending", "run_id": run_id,
                    "identity_verified": expected_receipt,
                })
                record["state"] = "run-delete-pending"
                persist()
                _delete_and_verify(run_endpoint)

            attempt_obligation(
                "run", delete_authorized_run, ambiguous="delete-pending", pending_state="delete-pending",
            )
            if record["cleanup_obligations"]["run"].get("state") == "absent":
                """The run is verified absent, so its logs and artifacts are necessarily absent too."""
                for dependent in ("logs", "artifacts"):
                    if record["cleanup_obligations"][dependent].get("state") != "absent":
                        record["cleanup_obligations"][dependent].update(
                            {"state": "absent", "verified_at": _timestamp()})
                        attempt["obligations"][dependent] = "absent"
                persist()

        record["cleanup_obligations"]["replay_guard"] = {
            "state": "retained", "retain_until": record["expires"],
        }
        obligations = record["cleanup_obligations"]
        required_absent = ("secret", "bundle_asset", "projection_asset", "logs", "artifacts", "run")
        closed = all(obligations[name].get("state") in ("absent", "not-created", "not-dispatched", "not-uploaded")
                     for name in required_absent)
        if obligations["secret"].get("state") not in ("absent", "not-installed"):
            closed = False
        attempt["result"] = "complete" if closed else "incomplete"
        record["state"] = "deleted" if closed else (
            "run-delete-pending" if obligations["run"].get("state") == "delete-pending" else "cleanup-failed"
        )
        persist()
    finally:
        _release_lock(descriptor)
    if record["state"] != "deleted":
        _fail("cleanup-incomplete")
    print("terminal_cleanup=complete")


def reconcile_dispatch(ledger, wave_id):
    root = _ledger_root(ledger)
    _validate_wave_id(wave_id, "wave-id")
    record = _wave_record(root, wave_id)
    if record["state"] not in ("dispatch-requested", "cleanup-failed", "cleanup-in-progress"):
        _fail("reconcile-state")
    endpoint = ("repos/%s/actions/workflows/%s/runs?event=workflow_dispatch&branch=main&per_page=100"
                % (fetch.REPOSITORY, fetch.WORKFLOW_PATH.rsplit("/", 1)[-1]))
    runs = _workflow_run_pages(endpoint)
    candidates = []
    for run in runs:
        if type(run) is not dict:
            _fail("dispatch-run-inventory")
        run_id = str(run.get("id", ""))
        if not re.fullmatch(r"[1-9][0-9]{0,18}", run_id):
            continue
        if (run.get("path") != fetch.WORKFLOW_PATH or run.get("head_branch") != "main"
                or run.get("head_sha") != record["control_sha"] or run.get("event") != "workflow_dispatch"
                or run.get("run_attempt") != 1):
            continue
        try:
            _verify_run_binding(run_id, record, run)
        except Refusal:
            continue
        candidates.append(run_id)
    if len(candidates) > 1:
        _fail("dispatch-multiple-matches")
    if not candidates:
        print("dispatch_reconciliation=pending")
        return False
    transition(ledger, wave_id, "attach-run", candidates[0])
    print("dispatch_reconciliation=attached run-id=" + candidates[0])
    return True


def _epoch(value):
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def _decrypt_conclusion(run_id):
    """(concluded, concluded_at_epoch): the decrypt step finished, or nothing can still decrypt.

    Nothing can still decrypt once the run job or the whole run has completed, so a run that failed
    before the decrypt step is treated as concluded too.
    """
    jobs = _gh_json("repos/%s/actions/runs/%s/jobs?filter=latest&per_page=100" % (fetch.REPOSITORY, run_id))
    entries = jobs.get("jobs") if type(jobs) is dict else None
    if type(entries) is not list:
        _fail("decrypt-progress-unavailable")
    job = next((item for item in entries if type(item) is dict and item.get("name") == RUN_JOB_NAME), None)
    if job is None:
        return False, None
    step = next((item for item in (job.get("steps") or []) if type(item) is dict and item.get("name") == DECRYPT_STEP), None)
    if type(step) is dict and step.get("status") == "completed":
        return True, _epoch(step.get("completed_at"))
    if job.get("status") == "completed":
        return True, _epoch(job.get("completed_at"))
    return False, None


def await_decrypt_and_revoke(ledger, wave_id, poll_seconds=2, timeout_seconds=7200,
                             sleep=time.sleep, clock=time.time):
    """Mandatory timed step: revoke the key as soon as Decrypt authenticated bundle concludes.

    The key is revoked in every outcome (concluded, timeout, persistent poll failure, interruption);
    a failing poll is retried until the timeout, then reported as within_limit=false (exit 3). Only a
    failed revocation raises (exit 2). The return value says whether the
    revocation landed within MAX_REVOKE_LATENCY_SECONDS of the step's conclusion; a late revocation
    is reported, not hidden, and must be recorded by the owner for that wave.
    """
    root = _ledger_root(ledger)
    _validate_wave_id(wave_id, "wave-id")
    record = _wave_record(root, wave_id)
    if record["state"] != "run-attached" or record["run_id"] is None or record["authorized_run_id"] != record["run_id"]:
        _fail("revoke-await-state")
    run_id = record["run_id"]
    started = clock()
    concluded_at = None
    timed_out = False
    poll_failed = False
    try:
        while True:
            try:
                concluded, concluded_at = _decrypt_conclusion(run_id)
                poll_failed = False
            except Exception:
                """A transient API or parse error is retried until the timeout; it never skips the revocation."""
                concluded, concluded_at = False, None
                poll_failed = True
            if concluded:
                break
            if clock() - started >= timeout_seconds:
                timed_out = True
                break
            sleep(poll_seconds)
    finally:
        revoke_secret(ledger, wave_id)
    now = clock()
    latency = max(0, int(now - concluded_at)) if concluded_at is not None else None
    within = (not timed_out) and latency is not None and latency <= MAX_REVOKE_LATENCY_SECONDS
    print("revoke_latency_seconds=%s limit=%d within_limit=%s timed_out=%s poll_failed=%s" % (
        "unknown" if latency is None else latency, MAX_REVOKE_LATENCY_SECONDS,
        "true" if within else "false", "true" if timed_out else "false", "true" if poll_failed else "false"))
    return within


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="operation", required=True)
    evidence = sub.add_parser("record-control-evidence")
    evidence.add_argument("--ledger", required=True)
    evidence.add_argument("--control-run-id", required=True)
    evidence.add_argument("--control-sha", required=True)
    reserve = sub.add_parser("reserve-wave")
    reserve.add_argument("--ledger", required=True)
    reserve.add_argument("--request", required=True)
    staged = sub.add_parser("stage-bundle")
    staged.add_argument("--ledger", required=True)
    staged.add_argument("--wave-id", required=True)
    staged.add_argument("--request", required=True)
    intent = sub.add_parser("record-intent")
    intent.add_argument("--ledger", required=True)
    intent.add_argument("--request", required=True)
    for action in ("mark-secret-installing", "mark-secret-installed", "mark-dispatch-requested", "attach-run", "mark-terminal"):
        command = sub.add_parser(action)
        command.add_argument("--ledger", required=True)
        command.add_argument("--wave-id", required=True)
        if action == "attach-run":
            command.add_argument("--run-id", required=True)
    revoke = sub.add_parser("revoke-secret")
    revoke.add_argument("--ledger", required=True)
    revoke.add_argument("--wave-id", required=True)
    awaiting = sub.add_parser("await-decrypt-and-revoke")
    awaiting.add_argument("--ledger", required=True)
    awaiting.add_argument("--wave-id", required=True)
    awaiting.add_argument("--poll-seconds", type=int, default=2)
    awaiting.add_argument("--timeout-seconds", type=int, default=7200)
    reconcile = sub.add_parser("reconcile-dispatch")
    reconcile.add_argument("--ledger", required=True)
    reconcile.add_argument("--wave-id", required=True)
    cleanup = sub.add_parser("cleanup-terminal")
    cleanup.add_argument("--ledger", required=True)
    cleanup.add_argument("--wave-id", required=True)
    sub.add_parser("cache-baseline")
    args = parser.parse_args(argv)
    try:
        if args.operation == "record-control-evidence":
            record_control_evidence(args.ledger, args.control_run_id, args.control_sha)
        elif args.operation == "reserve-wave":
            reserve_wave(args.ledger, bundle.strict_json(Path(args.request).read_bytes(), 64 * 1024))
        elif args.operation == "stage-bundle":
            stage_bundle(args.ledger, args.wave_id, bundle.strict_json(Path(args.request).read_bytes(), 64 * 1024))
        elif args.operation == "record-intent":
            record_intent(args.ledger, bundle.strict_json(Path(args.request).read_bytes(), 64 * 1024))
        elif args.operation == "cache-baseline":
            cache_baseline()
        elif args.operation == "cleanup-terminal":
            cleanup_terminal(args.ledger, args.wave_id)
        elif args.operation == "revoke-secret":
            revoke_secret(args.ledger, args.wave_id)
        elif args.operation == "await-decrypt-and-revoke":
            """Exit 0 only when revoked within the limit; 3 means revoked but late or after a timeout."""
            if not 1 <= args.poll_seconds <= 30 or not 60 <= args.timeout_seconds <= 14400:
                _fail("revoke-await-bounds")
            return 0 if await_decrypt_and_revoke(args.ledger, args.wave_id, args.poll_seconds, args.timeout_seconds) else 3
        elif args.operation == "reconcile-dispatch":
            """Exit 0 only when a run was attached; 3 means still pending (not an error, not done)."""
            return 0 if reconcile_dispatch(args.ledger, args.wave_id) else 3
        else:
            transition(args.ledger, args.wave_id, args.operation, getattr(args, "run_id", None))
        return 0
    except (Refusal, bundle.Refusal) as error:
        print("devlane_coordinator_refusal=" + str(error), file=sys.stderr)
        return 2
    except Exception:
        print("devlane_coordinator_refusal=operation-failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
