"""Short-lived, offline decryptor. Key bytes arrive only through stdin."""

import json
import os
import stat
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import bundle


DECRYPT_REFUSAL_CODES = frozenset((
    "archive-invalid", "auth-tag", "binding-mismatch", "crypto-unavailable",
    "expired", "invalid-envelope", "key-format", "request-invalid", "truncated",
))


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
    reason = "archive-invalid"
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
        reason = _public_refusal(error)
        sys.stdout.buffer.write(bundle.canonical_json({"status": "refused", "reason": reason}))
        sys.stdout.buffer.flush()
        print("decrypt_once=refused", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
