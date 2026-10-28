"""Verify a receipt-bound Cargo vendor tree before an offline source build."""

import hashlib
import hmac
import json
import os
from pathlib import Path
import stat

import cargo_lock_receipt as cargo


VENDOR_RECEIPT_FIELDS = frozenset((
    "schema_version", "lock_receipt_sha256", "lock_sha256", "vendor_sha256",
))
MAX_VENDOR_RECEIPT_BYTES = 4096


def _refuse():
    cargo._refuse("cargo_vendor_invalid")


def _decode_vendor_receipt(data, trusted_sha256):
    if (type(data) is not bytes or len(data) > MAX_VENDOR_RECEIPT_BYTES
            or not cargo._valid_hex(trusted_sha256, cargo.HEX64_RE)):
        _refuse()
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), trusted_sha256):
        _refuse()
    try:
        text = cargo._decode_ascii(data, MAX_VENDOR_RECEIPT_BYTES, "cargo_vendor_invalid")
        record = json.loads(
            text, object_pairs_hook=cargo._unique_json_pairs,
            parse_constant=cargo._reject_json_constant,
        )
        canonical = cargo._canonical_json(record)
    except (cargo.Refusal, ValueError, TypeError, json.JSONDecodeError, RecursionError):
        _refuse()
    if canonical != data or type(record) is not dict:
        _refuse()
    if set(record) != set(VENDOR_RECEIPT_FIELDS):
        _refuse()
    if (type(record["schema_version"]) is not int or record["schema_version"] != 1
            or not cargo._valid_hex(record["lock_receipt_sha256"], cargo.HEX64_RE)
            or not cargo._valid_hex(record["lock_sha256"], cargo.HEX64_RE)
            or not cargo._valid_hex(record["vendor_sha256"], cargo.HEX64_RE)):
        _refuse()
    return record


def _require_read_only(path, expected_mode, directory):
    try:
        metadata = path.lstat()
    except OSError:
        _refuse()
    if cargo._is_link_or_reparse(path):
        _refuse()
    if directory:
        valid_type = stat.S_ISDIR(metadata.st_mode)
    else:
        valid_type = stat.S_ISREG(metadata.st_mode)
    if not valid_type or stat.S_IMODE(metadata.st_mode) != expected_mode:
        _refuse()


def _hash_read_only_file(path):
    _require_read_only(path, 0o444, False)
    try:
        before = path.lstat()
        if getattr(before, "st_nlink", 1) != 1 or before.st_size > cargo.MAX_FILE_BYTES:
            _refuse()
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > cargo.MAX_FILE_BYTES:
                    _refuse()
                digest.update(block)
        after = path.lstat()
    except cargo.Refusal:
        raise
    except OSError:
        _refuse()
    if (size != before.st_size or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_mode != after.st_mode):
        _refuse()
    return digest.hexdigest()


def _walk_error(unused_error):
    _refuse()


def _verify_package(package_root, expected_checksum):
    _require_read_only(package_root, 0o555, True)
    file_hashes = {}
    checksum_path = None
    try:
        for current, directories, files in os.walk(
                package_root, topdown=True, followlinks=False, onerror=_walk_error):
            current_path = Path(current)
            _require_read_only(current_path, 0o555, True)
            directories.sort()
            files.sort()
            for name in directories:
                if name == ".cargo-checksum.json":
                    _refuse()
                _require_read_only(current_path / name, 0o555, True)
            for name in files:
                path = current_path / name
                relative = path.relative_to(package_root).as_posix()
                if name == ".cargo-checksum.json":
                    if relative != ".cargo-checksum.json" or checksum_path is not None:
                        _refuse()
                    checksum_path = path
                    continue
                file_hashes[relative] = _hash_read_only_file(path)
    except cargo.Refusal:
        raise
    except (OSError, ValueError, RuntimeError):
        _refuse()
    if checksum_path is None or "Cargo.toml" not in file_hashes:
        _refuse()
    try:
        metadata = checksum_path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or cargo._is_link_or_reparse(checksum_path)
                or stat.S_IMODE(metadata.st_mode) != 0o444
                or metadata.st_size > 2 * 1024 * 1024):
            _refuse()
        with checksum_path.open("rb") as stream:
            manifest_bytes = stream.read(2 * 1024 * 1024 + 1)
    except cargo.Refusal:
        raise
    except OSError:
        _refuse()
    if len(manifest_bytes) > 2 * 1024 * 1024:
        _refuse()
    try:
        cargo._parse_checksum_manifest(manifest_bytes, expected_checksum, file_hashes)
    except cargo.Refusal:
        _refuse()


def verify_vendor_tree(
        lock_bytes, lock_receipt, expected_lock_context, authorized_audits,
        vendor_directory, vendor_receipt_bytes, trusted_vendor_receipt_sha256):
    """Check lock, vendor receipt, package files and offline Cargo settings.

    The trusted vendor receipt digest must come from the protected preparation
    handoff. The lock receipt context and audit mapping must also be independently
    authenticated. The handoff must also enforce platform ACLs and prevent
    same-user writers because mode bits alone do not provide that isolation.
    This function does not run Cargo or project code.
    """
    if type(lock_receipt) is bytes:
        lock_record = cargo.decode_receipt(lock_receipt)
    else:
        lock_record = lock_receipt
    cargo.verify_lock_against_receipt(
        lock_bytes, lock_record, expected_lock_context, authorized_audits,
    )
    lock_receipt_digest = hashlib.sha256(cargo.encode_receipt(lock_record)).hexdigest()
    vendor_receipt = _decode_vendor_receipt(
        vendor_receipt_bytes, trusted_vendor_receipt_sha256,
    )
    if (not hmac.compare_digest(vendor_receipt["lock_receipt_sha256"], lock_receipt_digest)
            or not hmac.compare_digest(
                vendor_receipt["lock_sha256"], lock_record["lock_sha256"],
            )):
        _refuse()

    try:
        vendor_root = Path(vendor_directory)
    except (TypeError, ValueError):
        _refuse()
    if cargo._is_link_or_reparse(vendor_root):
        _refuse()
    _require_read_only(vendor_root, 0o555, True)
    packages = lock_record["packages"]
    expected_roots = {
        package["name"] + "-" + package["version"]: package
        for package in packages
    }
    try:
        entries = list(vendor_root.iterdir())
    except OSError:
        _refuse()
    if {entry.name for entry in entries} != set(expected_roots):
        _refuse()
    try:
        vendor_digest = cargo.vendor_tree_digest(vendor_root)
    except (cargo.Refusal, OSError, TypeError, ValueError):
        _refuse()
    if not hmac.compare_digest(vendor_digest, vendor_receipt["vendor_sha256"]):
        _refuse()

    for root_name, package in expected_roots.items():
        _verify_package(vendor_root / root_name, package["checksum"])

    try:
        final_digest = cargo.vendor_tree_digest(vendor_root)
    except (cargo.Refusal, OSError, TypeError, ValueError):
        _refuse()
    if not hmac.compare_digest(final_digest, vendor_digest):
        _refuse()
    cargo_arguments, environment = cargo.cargo_config_for_vendor(vendor_root)
    return {
        "vendor_sha256": final_digest,
        "cargo_arguments": cargo_arguments,
        "environment": environment,
    }
