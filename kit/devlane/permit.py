"""Source-free control evidence and one-run bundle permit records."""

import argparse
import os
import re
import stat
import sys
import time
from pathlib import Path

import bundle


CONTROL_FIELDS = {"schema", "kind", "control_ref", "control_sha", "control_run_id", "run_attempt", "status"}
CLAIM_FIELDS = {
    "schema", "kind", "control_sha", "control_run_id", "profile", "wave_id", "bundle_id",
    "run_id", "run_attempt", "expires", "status",
}
DECIMAL = re.compile(r"[1-9][0-9]{0,18}\Z")


class PermitRefusal(ValueError):
    pass


def _refuse(code):
    raise PermitRefusal(code)


def _read(path, maximum=64 * 1024):
    descriptor = None
    try:
        if not stat.S_ISREG(os.lstat(str(path)).st_mode):
            _refuse("permit-file-invalid")
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not os.path.isfile(path) or metadata.st_size > maximum:
            _refuse("permit-file-invalid")
        data = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > maximum:
                _refuse("permit-file-size")
        return bundle.strict_json(bytes(data), maximum)
    except (OSError, bundle.Refusal):
        _refuse("permit-file-unavailable")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write(path, record):
    target = Path(path)
    if target.exists() or target.is_symlink():
        _refuse("permit-file-exists")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.parent.is_symlink():
        _refuse("permit-directory-invalid")
    try:
        descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(bundle.canonical_json(record) + b"\n")
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        _refuse("permit-file-write")


def _valid_control(record):
    if (type(record) is not dict or set(record) != CONTROL_FIELDS or record.get("schema") != 1
            or record.get("kind") != "source-free-control-success" or record.get("status") != "passed"
            or record.get("control_ref") != "refs/heads/main"
            or record.get("run_attempt") != 1 or type(record.get("control_sha")) is not str
            or not re.fullmatch(r"[a-f0-9]{40}", record["control_sha"])
            or type(record.get("control_run_id")) is not str
            or not DECIMAL.fullmatch(record["control_run_id"])):
        _refuse("control-evidence-invalid")


def _identity(env):
    required = ("CI_SHA", "CI_CONTROL_RUN_ID", "DEVLANE_PROFILE", "DEVLANE_WAVE_ID",
                "DEVLANE_BUNDLE_ID", "CI_RUN_ID", "CI_RUN_ATTEMPT", "DEVLANE_EXPIRES")
    if any(type(env.get(name)) is not str or not env[name] for name in required):
        _refuse("permit-identity-invalid")
    if (not re.fullmatch(r"[a-f0-9]{40}", env["CI_SHA"])
            or not DECIMAL.fullmatch(env["CI_CONTROL_RUN_ID"])
            or env["DEVLANE_PROFILE"] not in ("core-node", "core-rust", "desktop")
            or not bundle.OPAQUE_ID.fullmatch(env["DEVLANE_WAVE_ID"])
            or not bundle.OPAQUE_ID.fullmatch(env["DEVLANE_BUNDLE_ID"])
            or not DECIMAL.fullmatch(env["CI_RUN_ID"]) or env["CI_RUN_ATTEMPT"] != "1"
            or not env["DEVLANE_EXPIRES"].isdecimal()):
        _refuse("permit-identity-invalid")
    expires = int(env["DEVLANE_EXPIRES"])
    now = int(time.time())
    if not now < expires <= now + 3600:
        _refuse("permit-expiry-invalid")
    return {
        "control_sha": env["CI_SHA"], "control_run_id": env["CI_CONTROL_RUN_ID"],
        "profile": env["DEVLANE_PROFILE"], "wave_id": env["DEVLANE_WAVE_ID"],
        "bundle_id": env["DEVLANE_BUNDLE_ID"], "run_id": env["CI_RUN_ID"],
        "run_attempt": 1, "expires": expires,
    }


def create_control(path, control_sha, run_id, control_ref="refs/heads/main"):
    record = {
        "schema": 1, "kind": "source-free-control-success", "control_ref": control_ref, "control_sha": control_sha,
        "control_run_id": run_id, "run_attempt": 1, "status": "passed",
    }
    _valid_control(record)
    _write(path, record)


def verify_control(path, control_sha, run_id):
    record = _read(path)
    _valid_control(record)
    if record["control_sha"] != control_sha or record["control_run_id"] != run_id:
        _refuse("control-evidence-binding")
    return record


def claim(path, env):
    identity = _identity(env)
    if Path(path).exists() or Path(path).is_symlink():
        _refuse("bundle-run-already-claimed")
    record = {"schema": 1, "kind": "one-run-bundle-permit", **identity, "status": "consumed"}
    _write(path, record)
    return record


def verify_claim(path, env):
    expected = {"schema": 1, "kind": "one-run-bundle-permit", **_identity(env), "status": "consumed"}
    record = _read(path)
    if type(record) is not dict or set(record) != CLAIM_FIELDS or record != expected:
        _refuse("bundle-run-permit-binding")
    return record


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="operation", required=True)
    control = sub.add_parser("create-control")
    control.add_argument("--file", required=True)
    control.add_argument("--control-sha", required=True)
    control.add_argument("--run-id", required=True)
    control.add_argument("--ref", default="refs/heads/main")
    check = sub.add_parser("verify-control")
    check.add_argument("--file", required=True)
    check.add_argument("--control-sha", required=True)
    check.add_argument("--run-id", required=True)
    for operation in ("claim", "verify-claim"):
        command = sub.add_parser(operation)
        command.add_argument("--file", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "create-control":
            create_control(args.file, args.control_sha, args.run_id, args.ref)
        elif args.operation == "verify-control":
            verify_control(args.file, args.control_sha, args.run_id)
        elif args.operation == "claim":
            claim(args.file, os.environ)
        else:
            verify_claim(args.file, os.environ)
        if args.operation == "verify-claim":
            print("devlane_permit=consumed run-id=" + os.environ["CI_RUN_ID"] + " run-attempt=1")
        else:
            print("devlane_permit=" + args.operation.replace("-", "_") + "=pass")
        return 0
    except Exception:
        print("devlane_permit=refused", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
