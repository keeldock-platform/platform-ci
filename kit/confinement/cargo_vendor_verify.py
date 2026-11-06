"""Verify a receipt-bound Cargo vendor tree before an offline source build."""

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import sys

import cargo_lock_receipt as cargo
import rust_license_gate


VENDOR_RECEIPT_FIELDS = frozenset((
    "schema_version", "lock_receipt_sha256", "lock_sha256", "source_sha", "profile",
    "vendor_sha256", "license_gate_receipt_sha256", "archive_spdx_sha256",
    "policy_sha256", "checker_sha256", "cargo_deny_sha256",
    "cargo_deny_qualification_sha256", "advisory_database_commit",
    "advisory_database_generated_at_epoch",
))
MAX_VENDOR_RECEIPT_BYTES = 8192


@dataclass(frozen=True)
class VendorVerificationRequest:
    lock_bytes: bytes
    lock_receipt: object
    expected_lock_context: dict
    authorized_audits: dict
    vendor_directory: object
    vendor_receipt_bytes: bytes
    trusted_vendor_receipt_sha256: str
    trusted_staging_root: object
    rust_license_gate_receipt: object


def _refuse():
    cargo._refuse("cargo_vendor_invalid")


def _is_windows():
    return os.name == "nt"


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
    hashes = (
        "lock_receipt_sha256", "lock_sha256", "vendor_sha256",
        "license_gate_receipt_sha256", "archive_spdx_sha256", "policy_sha256",
        "checker_sha256", "cargo_deny_sha256", "cargo_deny_qualification_sha256",
    )
    if (type(record["schema_version"]) is not int or record["schema_version"] != 2
            or any(not cargo._valid_hex(record[field], cargo.HEX64_RE) for field in hashes)
            or cargo.HEX40_RE.fullmatch(record.get("source_sha", "")) is None
            or type(record.get("profile")) is not str or not 1 <= len(record["profile"]) <= 64
            or cargo.HEX40_RE.fullmatch(record.get("advisory_database_commit", "")) is None
            or type(record.get("advisory_database_generated_at_epoch")) is not int
            or record["advisory_database_generated_at_epoch"] <= 0):
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
    if (_is_windows() or not hasattr(os, "O_DIRECTORY")
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
    try:
        raw = Path(vendor_directory)
        if not raw.is_absolute() or ".." in raw.parts:
            _refuse()
        physical = raw.resolve(strict=True)
        if _is_windows():
            current = Path(physical.anchor)
            for component in physical.parts[1:]:
                current = current / component
                metadata = current.lstat()
                attributes = getattr(metadata, "st_file_attributes", 0)
                if (stat.S_ISLNK(metadata.st_mode)
                        or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                    _refuse()
        return physical
    except cargo.Refusal:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        _refuse()


def _windows_readonly(metadata):
    if not stat.S_ISREG(metadata.st_mode) and not stat.S_ISDIR(metadata.st_mode):
        return False
    if stat.S_IMODE(metadata.st_mode) & 0o222:
        return False
    attributes = getattr(metadata, "st_file_attributes", None)
    if attributes is not None:
        if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            return False
        if not attributes & getattr(stat, "FILE_ATTRIBUTE_READONLY", 0x1):
            return False
    return True


def _windows_inventory(root):
    items = {}
    file_hashes = {}
    folded = {}
    total = 0
    try:
        root_metadata = root.lstat()
        if not stat.S_ISDIR(root_metadata.st_mode) or not _windows_readonly(root_metadata):
            _refuse()
        for current, directories, files in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            directories.sort()
            files.sort()
            selected = list(directories) + files
            for name in selected:
                item = current_path / name
                relative = item.relative_to(root).as_posix()
                if not cargo._safe_relative_path(relative):
                    _refuse()
                previous = folded.get(relative.casefold())
                if previous is not None and previous != relative:
                    _refuse()
                folded[relative.casefold()] = relative
                metadata = item.lstat()
                if not _windows_readonly(metadata):
                    _refuse()
                if stat.S_ISDIR(metadata.st_mode):
                    items[relative] = (True, metadata)
                    if getattr(metadata, "st_file_attributes", 0) & getattr(
                            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                        _refuse()
                elif stat.S_ISREG(metadata.st_mode):
                    if getattr(metadata, "st_nlink", 1) != 1:
                        _refuse()
                    total += metadata.st_size
                    if metadata.st_size > cargo.MAX_FILE_BYTES or total > cargo.MAX_TOTAL_BYTES:
                        _refuse()
                    with item.open("rb") as stream:
                        content_digest = hashlib.sha256()
                        read_total = 0
                        while True:
                            block = stream.read(1024 * 1024)
                            if not block:
                                break
                            content_digest.update(block)
                            read_total += len(block)
                    after = item.lstat()
                    if ((after.st_dev, after.st_ino, after.st_size)
                            != (metadata.st_dev, metadata.st_ino, metadata.st_size)
                            or read_total != metadata.st_size
                            or not _windows_readonly(after)):
                        _refuse()
                    items[relative] = (False, metadata)
                    file_hashes[relative] = content_digest.hexdigest()
                else:
                    _refuse()
                if len(items) > cargo.MAX_ARCHIVE_MEMBERS:
                    _refuse()
            directories[:] = [
                name for name in directories
                if stat.S_ISDIR((current_path / name).lstat().st_mode)
            ]
        final_root = root.lstat()
        if ((final_root.st_dev, final_root.st_ino) != (root_metadata.st_dev, root_metadata.st_ino)
                or not _windows_readonly(final_root)):
            _refuse()
        return items, file_hashes
    except cargo.Refusal:
        raise
    except (OSError, TypeError, ValueError, UnicodeError):
        _refuse()


def _verify_windows_inventory(root, items, file_hashes, packages):
    expected_roots = {
        package["name"] + "-" + package["version"]: package for package in packages
    }
    top_level = {relative for relative in items if "/" not in relative}
    if top_level != set(expected_roots):
        _refuse()
    children = {name: [] for name in expected_roots}
    for relative, item in items.items():
        root_name = relative.split("/", 1)[0]
        if root_name not in children:
            _refuse()
        if "/" in relative:
            children[root_name].append((relative, item))
    for root_name, package in expected_roots.items():
        if not items[root_name][0]:
            _refuse()
        expected_hashes = {}
        checksum_path = root / root_name / ".cargo-checksum.json"
        checksum_relative = root_name + "/.cargo-checksum.json"
        for relative, (is_directory, metadata) in children[root_name]:
            short_name = relative[len(root_name) + 1:]
            if is_directory:
                if short_name.split("/")[-1] == ".cargo-checksum.json":
                    _refuse()
            elif short_name.split("/")[-1] == ".cargo-checksum.json":
                if relative != checksum_relative:
                    _refuse()
            else:
                expected_hashes[short_name] = file_hashes[relative]
        if "Cargo.toml" not in expected_hashes or checksum_relative not in file_hashes:
            _refuse()
        try:
            manifest_bytes = checksum_path.read_bytes()
            if hashlib.sha256(manifest_bytes).hexdigest() != file_hashes[checksum_relative]:
                _refuse()
            cargo._parse_checksum_manifest(
                manifest_bytes, package["checksum"], expected_hashes,
            )
        except (OSError, cargo.Refusal):
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


def _materialize_vendor(root_fd, items, expected_digest, require_read_only, staging_root):
    parent_fd = None
    stage_fd = None
    stage_name = None
    stage_identity = None
    stage_created = False
    final_name = ".cargo-vendor-" + secrets.token_hex(16)
    try:
        parent_fd, target = cargo._open_target_directory(staging_root)
        stage_name = ".cargo-stage-" + secrets.token_hex(16)
        os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
        stage_created = True
        stage_fd = os.open(
            stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        stage_identity = cargo._file_identity(os.fstat(stage_fd))
        directories = sorted(
            (relative for relative, item in items.items() if item[0]),
            key=lambda relative: (relative.count("/"), relative),
        )
        for relative in directories:
            parts = relative.split("/")
            directory_fd = cargo._open_relative_directory(stage_fd, parts[:-1])
            try:
                os.mkdir(parts[-1], 0o700, dir_fd=directory_fd)
            finally:
                os.close(directory_fd)

        def open_copy(relative):
            parts = relative.split("/")
            directory_fd = cargo._open_relative_directory(stage_fd, parts[:-1])
            try:
                return os.open(
                    parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=directory_fd,
                )
            finally:
                os.close(directory_fd)

        copied_digest = cargo.vendor_tree_inventory_fd(
            root_fd, require_read_only, open_copy,
        )[0]
        if not hmac.compare_digest(copied_digest, expected_digest):
            _refuse()
        for relative in reversed(directories):
            directory_fd = cargo._open_relative_directory(stage_fd, relative.split("/"))
            try:
                os.fchmod(directory_fd, 0o555)
            finally:
                os.close(directory_fd)
        materialized_digest = cargo.vendor_tree_inventory_fd(stage_fd)[0]
        if not hmac.compare_digest(materialized_digest, expected_digest):
            _refuse()
        cargo._publish_stage(parent_fd, stage_name, final_name, stage_identity)
        stage_name = None
        os.fchmod(stage_fd, 0o555)
        published = os.fstat(stage_fd)
        if (cargo._file_identity(published) != stage_identity
                or stat.S_IMODE(published.st_mode) != 0o555
                or cargo._entry_identity(parent_fd, final_name) != stage_identity):
            _refuse()
        return target / final_name, parent_fd, stage_fd, final_name, stage_identity
    except BaseException:
        if stage_created and parent_fd is not None:
            for name in (stage_name, final_name):
                if name is not None:
                    try:
                        cargo._remove_stage(parent_fd, name, stage_identity)
                    except (OSError, cargo.Refusal):
                        pass
        if stage_fd is not None:
            os.close(stage_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        raise


def _require_materialized_path(parent_fd, stage_fd, target, final_name):
    comparison_fd = None
    try:
        comparison_fd, unused_target = cargo._open_target_directory(target)
        if (cargo._file_identity(os.fstat(comparison_fd))
                != cargo._file_identity(os.fstat(parent_fd))
                or cargo._entry_identity(comparison_fd, final_name)
                != cargo._file_identity(os.fstat(stage_fd))):
            _refuse()
    finally:
        if comparison_fd is not None:
            os.close(comparison_fd)


def _verified_request_inputs(request):
    if type(request) is not VendorVerificationRequest:
        _refuse()
    lock_bytes = request.lock_bytes
    lock_receipt = request.lock_receipt
    expected_lock_context = request.expected_lock_context
    authorized_audits = request.authorized_audits
    vendor_directory = request.vendor_directory
    vendor_receipt_bytes = request.vendor_receipt_bytes
    trusted_vendor_receipt_sha256 = request.trusted_vendor_receipt_sha256
    trusted_staging_root = request.trusted_staging_root
    rust_license_gate_receipt = request.rust_license_gate_receipt
    if type(lock_receipt) is bytes:
        lock_record = cargo.decode_receipt(lock_receipt)
    else:
        lock_record = lock_receipt
    cargo.verify_lock_against_receipt(
        lock_bytes, lock_record, expected_lock_context, authorized_audits,
    )
    try:
        gate_receipt = rust_license_gate.require_vendor_gate_receipt(
            rust_license_gate_receipt, lock_record["source_sha"],
            lock_record["workspace_path"], lock_record["lock_sha256"],
            tuple(rust_license_gate.Package(
                item["name"], item["version"], item["checksum"],
            ) for item in lock_record["packages"]),
        )
    except rust_license_gate.LicenseGateRefusal:
        _refuse()
    lock_receipt_digest = hashlib.sha256(cargo.encode_receipt(lock_record)).hexdigest()
    gate_receipt_digest = rust_license_gate.gate_receipt_sha256(gate_receipt)
    vendor_receipt = _decode_vendor_receipt(
        vendor_receipt_bytes, trusted_vendor_receipt_sha256,
    )
    if (not hmac.compare_digest(vendor_receipt["lock_receipt_sha256"], lock_receipt_digest)
            or vendor_receipt["lock_sha256"] != lock_record["lock_sha256"]
            or vendor_receipt["source_sha"] != lock_record["source_sha"]
            or vendor_receipt["profile"] != lock_record["workspace_path"]
            or not hmac.compare_digest(
                vendor_receipt["license_gate_receipt_sha256"], gate_receipt_digest,
            )
            or vendor_receipt["archive_spdx_sha256"] != gate_receipt.archive_spdx_sha256
            or vendor_receipt["policy_sha256"] != gate_receipt.policy_sha256
            or vendor_receipt["checker_sha256"] != gate_receipt.checker_sha256
            or vendor_receipt["cargo_deny_sha256"] != gate_receipt.cargo_deny_sha256
            or vendor_receipt["cargo_deny_qualification_sha256"]
            != gate_receipt.cargo_deny_qualification_sha256
            or vendor_receipt["advisory_database_commit"] != gate_receipt.advisory_database_commit
            or vendor_receipt["advisory_database_generated_at_epoch"]
            != gate_receipt.advisory_database_generated_at_epoch):
        _refuse()
    return (
        lock_record, vendor_receipt, vendor_directory, trusted_staging_root,
    )


def _cleanup_vendor_state(materialized, environment):
    if materialized is not None:
        unused_path, parent_fd, unused_stage_fd, final_name, stage_identity = materialized
        try:
            cargo._remove_stage(parent_fd, final_name, stage_identity)
        except (OSError, cargo.Refusal):
            pass
    if environment is not None:
        for key in ("HOME", "CARGO_HOME", "RUSTUP_HOME"):
            try:
                os.rmdir(environment[key])
            except (KeyError, OSError):
                pass


def _verify_windows_vendor_tree(lock_record, vendor_receipt, vendor_directory, staging_root):
    environment = None
    try:
        physical_root = _resolve_vendor_root(vendor_directory)
        physical_staging = _resolve_vendor_root(staging_root)
        try:
            common = os.path.normcase(os.path.commonpath((str(physical_root), str(physical_staging))))
            staging_text = os.path.normcase(str(physical_staging))
        except (OSError, ValueError):
            _refuse()
        if common != staging_text or physical_root == physical_staging:
            _refuse()
        items, file_hashes = _windows_inventory(physical_root)
        _verify_windows_inventory(physical_root, items, file_hashes, lock_record["packages"])
        vendor_digest = cargo.vendor_tree_digest(physical_root)
        if not hmac.compare_digest(vendor_digest, vendor_receipt["vendor_sha256"]):
            _refuse()
        cargo_arguments, environment = cargo.cargo_config_for_vendor(physical_root)
        required_settings = (
            "source.crates-io.replace-with=\"verified-vendor\"",
            "source.verified-vendor.directory=" + json.dumps(str(physical_root), ensure_ascii=True),
            "net.offline=true", "registry.global-credential-providers=[]", "patch.crates-io={}",
        )
        if any(
                not any(argument == "--config" and index + 1 < len(cargo_arguments)
                        and cargo_arguments[index + 1] == setting
                        for index, argument in enumerate(cargo_arguments))
                for setting in required_settings):
            _refuse()
        final_digest = cargo.vendor_tree_digest(physical_root)
        if not hmac.compare_digest(final_digest, vendor_digest):
            _refuse()
        return {
            "vendor_sha256": vendor_digest,
            "materialized_vendor_directory": physical_root,
            "cargo_arguments": cargo_arguments,
            "environment": environment,
            "required_flags": ("--locked", "--offline"),
        }
    except BaseException:
        _cleanup_vendor_state(None, environment)
        raise


def _close_vendor_descriptors(materialized, root_fd):
    if materialized is not None:
        unused_path, parent_fd, stage_fd, unused_name, unused_identity = materialized
        os.close(stage_fd)
        os.close(parent_fd)
    os.close(root_fd)


def verify_vendor_tree(request):
    """Verify receipts before exposing a frozen, read-only vendor tree."""
    lock_record, vendor_receipt, vendor_directory, trusted_staging_root = (
        _verified_request_inputs(request)
    )

    physical_root = _resolve_vendor_root(vendor_directory)
    if _is_windows():
        return _verify_windows_vendor_tree(
            lock_record, vendor_receipt, physical_root, trusted_staging_root,
        )
    read_only_superblocks = _read_only_superblocks()
    root_fd = _open_physical_root(physical_root, read_only_superblocks)
    require_read_only = lambda descriptor: _require_read_only_mount(
        descriptor, read_only_superblocks,
    )
    materialized = None
    environment = None
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
        _require_same_path(root_fd, physical_root, read_only_superblocks)
        try:
            materialized = _materialize_vendor(
                root_fd, items, vendor_digest, require_read_only, trusted_staging_root,
            )
        except (cargo.Refusal, OSError, TypeError, ValueError):
            _refuse()
        materialized_path, parent_fd, stage_fd, final_name, stage_identity = materialized
        cargo_arguments, environment = cargo.cargo_config_for_vendor(materialized_path)
        expected_setting = (
            "source.verified-vendor.directory="
            + json.dumps(str(materialized_path), ensure_ascii=True)
        )
        if expected_setting not in cargo_arguments:
            _refuse()
        try:
            _require_materialized_path(
                parent_fd, stage_fd, materialized_path.parent, final_name,
            )
        except (cargo.Refusal, OSError, TypeError, ValueError):
            _refuse()
        return {
            "vendor_sha256": vendor_digest,
            "materialized_vendor_directory": materialized_path,
            "cargo_arguments": cargo_arguments,
            "environment": environment,
        }
    except BaseException:
        _cleanup_vendor_state(materialized, environment)
        raise
    finally:
        _close_vendor_descriptors(materialized, root_fd)


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
