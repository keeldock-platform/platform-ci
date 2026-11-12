"""Short-lived, offline decryptor. Key bytes arrive only through stdin."""

import importlib
import json
import os
import stat
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
bundle = None


DECRYPT_REFUSAL_CODES = frozenset((
    "archive-invalid", "auth-tag", "binding-mismatch", "crypto-unavailable",
    "child-import-failed", "child-no-output", "child-output-invalid", "child-panic",
    "child-spawn-failed", "child-signal-SIGKILL", "child-signal-SIGSEGV",
    "child-signal-SIGABRT", "child-signal-SIGSYS", "child-signal-SIGXCPU",
    "child-signal-SIGXFSZ", "child-signal-SIGBUS", "child-signal-SIGILL",
    "child-signal-other", "child-exit-1", "child-exit-2", "child-exit-120",
    "child-exit-126", "child-exit-127", "child-exit-other", "decrypt-failed",
    "decrypt-timeout", "expired",
    "invalid-envelope", "key-format", "request-invalid", "truncated",
))


def _load_bundle():
    """Load the decrypt implementation only after main can turn failures into receipts."""
    global bundle
    bundle = None
    try:
        bundle = importlib.import_module("bundle")
    except BaseException as error:
        reason = "crypto-unavailable" if type(error).__name__ == "PanicException" else "child-import-failed"
        return None, reason
    if getattr(bundle, "AESGCM", None) is None:
        return bundle, "crypto-unavailable"
    return bundle, None


def _write_refusal(reason):
    payload = json.dumps(
        {"status": "refused", "reason": reason},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def _public_refusal(error):
    """Map internal parser failures to a small fixed vocabulary safe for public logs."""
    code = str(error) if isinstance(error, bundle.Refusal) else ""
    if code == "authentication-failed":
        return "auth-tag"
    if code in ("key-invalid",):
        return "key-format"
    if code == "request-expired":
        return "expired"
    if code in ("envelope-truncated", "decrypt-input"):
        return "truncated"
    if code == "crypto-unavailable":
        return "crypto-unavailable"
    if code in ("binding-mismatch", "inner-binding-mismatch") or code.startswith("binding-"):
        return "binding-mismatch"
    if code == "ciphertext-size":
        return "invalid-envelope"
    if code == "decrypt-request" or code.startswith("json-"):
        return "request-invalid"
    return "archive-invalid"


def _read_envelope(path):
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > bundle.MAX_CIPHERTEXT:
            raise bundle.Refusal("decrypt-input")
        output = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, bundle.MAX_CIPHERTEXT + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > bundle.MAX_CIPHERTEXT:
                raise bundle.Refusal("decrypt-input")
        if len(output) != metadata.st_size:
            raise bundle.Refusal("decrypt-input")
        return bytes(output)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def main():
    _, import_refusal = _load_bundle()
    if import_refusal is not None:
        _write_refusal(import_refusal)
        return 2
    key_buffer = bytearray()
    try:
        request_bytes = sys.stdin.buffer.read(64 * 1024 + 1)
        if len(request_bytes) > 64 * 1024:
            raise bundle.Refusal("decrypt-request")
        request = bundle.strict_json(request_bytes, 64 * 1024)
        if type(request) is not dict or set(request) != {"key", "expected"}:
            raise bundle.Refusal("decrypt-request")
        key_hex = request["key"]
        if type(key_hex) is not str or len(key_hex) != 64 or any(
                character not in "0123456789abcdef" for character in key_hex):
            raise bundle.Refusal("key-invalid")
        key_buffer = bytearray.fromhex(key_hex)
        key_hex = ""
        envelope = _read_envelope("/control/bundle.enc")
        try:
            archive_bytes = bundle.parse_envelope(envelope, bytes(key_buffer), request["expected"])
        finally:
            for index in range(len(key_buffer)):
                key_buffer[index] = 0
            envelope = b""
        try:
            manifest = bundle.extract_authenticated_archive(
                archive_bytes, "/workspace/source", request["expected"],
            )
        finally:
            archive_bytes = b""
        sys.stdout.buffer.write(bundle.canonical_json({"status": "accepted", "manifest": manifest}))
        sys.stdout.buffer.flush()
        return 0
    except Exception as error:
        _write_refusal(_public_refusal(error))
        print("decrypt_once=refused", file=sys.stderr)
        return 2
    except BaseException:
        _write_refusal("child-panic")
        print("decrypt_once=refused", file=sys.stderr)
        return 2
    finally:
        for index in range(len(key_buffer)):
            key_buffer[index] = 0


if __name__ == "__main__":
    raise SystemExit(main())
