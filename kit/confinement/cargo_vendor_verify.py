"""Verify a receipt-bound Cargo vendor tree before an offline source build."""

import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys

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


def _require_protected_ancestor(descriptor):
    metadata = os.fstat(descriptor)
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022):
        _refuse()
    try:
        cargo._require_no_extended_acl(descriptor)
    except cargo.Refusal:
        _refuse()


def _read_only_superblocks():
    if sys.platform == "darwin":
        return None
    if sys.platform != "linux":
        _refuse()
    try:
        with open("/proc/self/mountinfo", "r", encoding="ascii") as stream:
            lines = stream.readlines()
        read_only = set()
        for line in lines:
            sections = line.rstrip("\n").split(" - ", 1)
            if len(sections) != 2:
                _refuse()
            mount_fields = sections[0].split()
            filesystem_fields = sections[1].split(" ", 2)
            if len(mount_fields) < 6 or len(filesystem_fields) != 3:
                _refuse()
            if "ro" in filesystem_fields[2].split(","):
                read_only.add(int(mount_fields[0]))
        return read_only
    except (OSError, UnicodeError, ValueError):
        _refuse()


def _require_read_only_mount(descriptor, read_only_superblocks):
    """Reject writable mounts and Linux bind mounts backed by writable storage."""
    read_only_flag = getattr(os, "ST_RDONLY", None)
    if (read_only_flag is None or not hasattr(os, "fstatvfs")
            or not os.fstatvfs(descriptor).f_flag & read_only_flag):
        _refuse()
    if sys.platform == "linux":
        try:
            with open(
                    "/proc/self/fdinfo/" + str(descriptor), "r", encoding="ascii",
            ) as stream:
                mount_ids = [
                    int(line.split(":", 1)[1].strip())
                    for line in stream if line.startswith("mnt_id:")
                ]
        except (OSError, UnicodeError, ValueError):
            _refuse()
        if len(mount_ids) != 1 or mount_ids[0] not in read_only_superblocks:
            _refuse()


def _open_physical_root(physical_root, read_only_superblocks):
    if (os.name == "nt" or not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid")
            or os.geteuid() == 0):
        _refuse()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open("/", flags)
        for component in physical_root.parts[1:]:
            _require_protected_ancestor(descriptor)
            entry = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if (not stat.S_ISDIR(entry.st_mode) or stat.S_ISLNK(entry.st_mode)
                    or getattr(entry, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                _refuse()
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            try:
                opened = os.fstat(next_descriptor)
                if opened.st_dev != entry.st_dev or opened.st_ino != entry.st_ino:
                    _refuse()
            except BaseException:
                os.close(next_descriptor)
                raise
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if (not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o555):
            _refuse()
        _require_read_only_mount(descriptor, read_only_superblocks)
        return descriptor
    except cargo.Refusal:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except (OSError, TypeError, ValueError):
        if descriptor is not None:
            os.close(descriptor)
        _refuse()


def _resolve_vendor_root(vendor_directory):
    if os.name == "nt":
        _refuse()
    try:
        raw = Path(vendor_directory)
        if not raw.is_absolute() or ".." in raw.parts:
            _refuse()
        return raw.resolve(strict=True)
    except cargo.Refusal:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        _refuse()


def _read_manifest(root_fd, relative, expected_digest, require_read_only):
    parts = relative.split("/")
    parent_fd = None
    file_fd = None
    try:
        parent_fd = cargo._open_relative_directory(root_fd, parts[:-1])
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        require_read_only(file_fd)
        metadata = os.fstat(file_fd)
        if (not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o444
                or getattr(metadata, "st_nlink", 1) != 1
                or metadata.st_size > 2 * 1024 * 1024):
            _refuse()
        content = bytearray()
        while len(content) <= 2 * 1024 * 1024:
            chunk = os.read(file_fd, 2 * 1024 * 1024 + 1 - len(content))
            if not chunk:
                break
            content.extend(chunk)
        if (len(content) != metadata.st_size
                or not hmac.compare_digest(
                    hashlib.sha256(content).hexdigest(), expected_digest,
                )):
            _refuse()
        return bytes(content)
    except cargo.Refusal:
        raise
    except (OSError, TypeError, ValueError):
        _refuse()
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _verify_inventory(root_fd, items, file_hashes, packages, require_read_only):
    expected_roots = {
        package["name"] + "-" + package["version"]: package
        for package in packages
    }
    top_level = {relative for relative in items if "/" not in relative}
    if top_level != set(expected_roots):
        _refuse()
    children = {root_name: [] for root_name in expected_roots}
    for relative, item in items.items():
        root_name = relative.split("/", 1)[0]
        if root_name not in children:
            _refuse()
        if "/" in relative:
            children[root_name].append((relative, item))
    for root_name, package in expected_roots.items():
        root_item = items[root_name]
        if not root_item[0] or stat.S_IMODE(root_item[1].st_mode) != 0o555:
            _refuse()
        expected_hashes = {}
        manifest_name = root_name + "/.cargo-checksum.json"
        for relative, (is_directory, metadata) in children[root_name]:
            short_name = relative[len(root_name) + 1:]
            if is_directory:
                if (stat.S_IMODE(metadata.st_mode) != 0o555
                        or short_name.split("/")[-1] == ".cargo-checksum.json"):
                    _refuse()
            else:
                if stat.S_IMODE(metadata.st_mode) != 0o444:
                    _refuse()
                if short_name.split("/")[-1] == ".cargo-checksum.json":
                    if relative != manifest_name:
                        _refuse()
                else:
                    expected_hashes[short_name] = file_hashes[relative]
        if "Cargo.toml" not in expected_hashes or manifest_name not in file_hashes:
            _refuse()
        manifest = _read_manifest(
            root_fd, manifest_name, file_hashes[manifest_name], require_read_only,
        )
        try:
            cargo._parse_checksum_manifest(
                manifest, package["checksum"], expected_hashes,
            )
        except cargo.Refusal:
            _refuse()


def verify_vendor_tree(
        lock_bytes, lock_receipt, expected_lock_context, authorized_audits,
        vendor_directory, vendor_receipt_bytes, trusted_vendor_receipt_sha256):
    """Check lock, vendor receipt, package files and offline Cargo settings.

    The trusted vendor receipt digest must come from the protected preparation
    handoff. The lock receipt context and audit mapping must also be independently
    authenticated. The physical vendor path has root-owned, non-writable
    ancestors, no extended macOS ACLs, and read-only storage for every member.
    Linux also requires a read-only superblock. The trusted handoff must keep
    that mount and namespace through Cargo consumption. Windows refuses until
    its native handle and ACL handoff is implemented.
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

    physical_root = _resolve_vendor_root(vendor_directory)
    read_only_superblocks = _read_only_superblocks()
    root_fd = _open_physical_root(physical_root, read_only_superblocks)
    require_read_only = lambda descriptor: _require_read_only_mount(
        descriptor, read_only_superblocks,
    )
    try:
        try:
            vendor_digest, items, file_hashes = cargo.vendor_tree_inventory_fd(
                root_fd, require_read_only,
            )
        except cargo.Refusal:
            _refuse()
        if not hmac.compare_digest(vendor_digest, vendor_receipt["vendor_sha256"]):
            _refuse()
        _verify_inventory(
            root_fd, items, file_hashes, lock_record["packages"], require_read_only,
        )
        try:
            final_digest = cargo.vendor_tree_inventory_fd(root_fd, require_read_only)[0]
        except cargo.Refusal:
            _refuse()
        if not hmac.compare_digest(final_digest, vendor_digest):
            _refuse()
        _require_same_path(root_fd, physical_root, read_only_superblocks)
        cargo_arguments, environment = cargo.cargo_config_for_vendor(physical_root)
        try:
            expected_setting = (
                "source.verified-vendor.directory="
                + json.dumps(str(physical_root), ensure_ascii=True)
            )
            if expected_setting not in cargo_arguments:
                _refuse()
            _require_same_path(root_fd, physical_root, read_only_superblocks)
        except cargo.Refusal:
            for key in ("HOME", "CARGO_HOME", "RUSTUP_HOME"):
                try:
                    os.rmdir(environment[key])
                except (KeyError, OSError):
                    pass
            raise
        return {
            "vendor_sha256": final_digest,
            "cargo_arguments": cargo_arguments,
            "environment": environment,
        }
    finally:
        os.close(root_fd)


def _require_same_path(root_fd, physical_root, read_only_superblocks):
    comparison_fd = _open_physical_root(physical_root, read_only_superblocks)
    try:
        original = os.fstat(root_fd)
        current = os.fstat(comparison_fd)
        if (original.st_dev != current.st_dev or original.st_ino != current.st_ino):
            _refuse()
    except OSError:
        _refuse()
    finally:
        os.close(comparison_fd)
