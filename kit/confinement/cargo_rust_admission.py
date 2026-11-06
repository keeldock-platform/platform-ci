"""Authenticate a protected Cargo lock, run the production gate, and verify vendor bytes."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

import cargo_lock_bootstrap as cargo_bootstrap
import cargo_lock_receipt as cargo
import cargo_vendor_producer
import cargo_vendor_verify
import rust_license_gate


MAX_BINDING_BYTES = 1024 * 1024


class RustAdmissionRefusal(Exception):
    """Fixed refusal without source-derived details."""


def _refuse():
    raise RustAdmissionRefusal("cargo_admission_refused")


def _read_trusted_file(path, source_root, maximum):
    try:
        raw = Path(path)
        if not raw.is_absolute() or raw.is_symlink():
            _refuse()
        current = Path(raw.anchor)
        for component in raw.parts[1:]:
            current = current / component
            details = current.lstat()
            if (stat.S_ISLNK(details.st_mode)
                    or getattr(details, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                _refuse()
        resolved = raw.resolve(strict=True)
        source = Path(source_root).resolve(strict=True)
        if os.path.commonpath((str(source), str(resolved))) == str(source):
            _refuse()
        metadata = resolved.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_size <= 0 or metadata.st_size > maximum
                or getattr(metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            _refuse()
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o022:
            _refuse()
        with resolved.open("rb") as stream:
            payload = stream.read(maximum + 1)
        after = resolved.lstat()
        if ((after.st_dev, after.st_ino, after.st_size)
                != (metadata.st_dev, metadata.st_ino, metadata.st_size)
                or len(payload) != metadata.st_size or len(payload) > maximum):
            _refuse()
        return payload
    except RustAdmissionRefusal:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        _refuse()


def _json_bytes(payload, maximum):
    try:
        value = json.loads(
            cargo._decode_ascii(payload, maximum, "cargo_lock_receipt_invalid"),
            object_pairs_hook=cargo._unique_json_pairs,
            parse_constant=cargo._reject_json_constant,
        )
        if cargo._canonical_json(value) != payload:
            _refuse()
        return value
    except (cargo.Refusal, ValueError, TypeError, json.JSONDecodeError, RecursionError):
        _refuse()


def _authorized_audits(value):
    if type(value) is not list or not value:
        _refuse()
    result = {}
    for item in value:
        if (type(item) is not dict
                or set(item) != {"name", "version", "checksum", "audit_record_id"}):
            _refuse()
        identity = (item["name"], item["version"], item["checksum"])
        if identity in result or type(item["audit_record_id"]) is not str:
            _refuse()
        result[identity] = item["audit_record_id"]
    return result


def _workspace_identity_root(source_root, profile):
    """Resolve the fixed manifest root selected by the Cargo lock profile."""
    if profile == ".":
        workspace = cargo_bootstrap.CONTRACT_WORKSPACE
    elif profile == cargo_bootstrap.RUNTIME_WORKSPACE:
        workspace = cargo_bootstrap.RUNTIME_WORKSPACE
    else:
        _refuse()
    try:
        source = Path(source_root)
        if not source.is_absolute():
            _refuse()
        source_metadata = source.lstat()
        if (not stat.S_ISDIR(source_metadata.st_mode)
                or getattr(source_metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            _refuse()
        source = source.resolve(strict=True)
        directory = cargo_bootstrap.workspace_directory(workspace)
        root = source if directory == "." else source / directory
        metadata = root.lstat()
        if (not stat.S_ISDIR(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            _refuse()
        resolved_root = root.resolve(strict=True)
        if directory != "." and resolved_root.parent != source:
            _refuse()
        manifest = source / cargo_bootstrap.workspace_root_manifest(workspace)
        manifest_metadata = manifest.lstat()
        if (not stat.S_ISREG(manifest_metadata.st_mode)
                or getattr(manifest_metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            _refuse()
        return str(resolved_root)
    except (OSError, RuntimeError, TypeError, ValueError, cargo_bootstrap.BootstrapRefusal):
        _refuse()


def control_files_for_lock(evidence_root, source_root, lock_relative):
    """Read protected receipt files named by the canonical source-relative lock path."""
    try:
        root = Path(evidence_root)
        source = Path(source_root).resolve(strict=True)
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            _refuse()
        root = root.resolve(strict=True)
        if os.path.commonpath((str(source), str(root))) == str(source):
            _refuse()
        relative = Path(lock_relative).as_posix()
        if (not relative or relative.startswith("/") or "\\" in relative
                or any(part in ("", ".", "..") for part in relative.split("/"))):
            _refuse()
        key = hashlib.sha256(relative.encode("ascii", "strict")).hexdigest()
        return (
            _read_trusted_file(root / (key + ".receipt.json"), source, cargo.MAX_RECEIPT_BYTES),
            _read_trusted_file(root / (key + ".binding.json"), source, MAX_BINDING_BYTES),
        )
    except RustAdmissionRefusal:
        raise
    except (OSError, UnicodeError, TypeError, ValueError):
        _refuse()


def admit_lock(lock_bytes, source_root, source_sha, profile, lock_receipt_bytes=None,
               binding_bytes=None, vendor_parent=None, rust_root="", trusted_ports=None):
    """Return a registry-free proof or a verified vendor configuration for this lock."""
    if (type(lock_bytes) is not bytes or not lock_bytes
            or rust_license_gate.SOURCE_RE.fullmatch(source_sha or "") is None
            or type(profile) is not str or not 1 <= len(profile) <= 64):
        _refuse()
    try:
        parsed = cargo.parse_cargo_lock(lock_bytes)
    except cargo.Refusal:
        _refuse()
    workspace_root = _workspace_identity_root(source_root, profile)
    identity = rust_license_gate.Identity(
        source_sha, profile, workspace_root, hashlib.sha256(lock_bytes).hexdigest(),
    )
    registry_packages = tuple(
        item for item in parsed["packages"] if item.get("source") == cargo.REGISTRY_SOURCE
    )
    if not registry_packages:
        return rust_license_gate.require_lock_admission(lock_bytes, identity, trusted_ports)
    if type(lock_receipt_bytes) is not bytes or type(binding_bytes) is not bytes:
        _refuse()
    try:
        lock_record = cargo.decode_receipt(lock_receipt_bytes)
        binding = _json_bytes(binding_bytes, MAX_BINDING_BYTES)
        if (type(binding) is not dict or set(binding) != {"expected_context", "authorized_audits"}
                or type(binding["expected_context"]) is not dict):
            _refuse()
        authorized = _authorized_audits(binding["authorized_audits"])
        cargo.verify_lock_against_receipt(
            lock_bytes, lock_record, binding["expected_context"], authorized,
        )
        trusted_control = os.environ.get("CI_SHA", "")
        if (rust_license_gate.SOURCE_RE.fullmatch(trusted_control) is None
                or binding["expected_context"].get("control_sha") != trusted_control
                or lock_record["source_sha"] != source_sha
                or lock_record["workspace_path"] != profile
                or lock_record["lock_sha256"] != identity.lock_sha256
                or binding["expected_context"].get("source_sha") != source_sha
                or binding["expected_context"].get("workspace_path") != profile):
            _refuse()
    except (cargo.Refusal, RustAdmissionRefusal):
        _refuse()
    gate_receipt = rust_license_gate.require_lock_admission(
        lock_bytes, identity, trusted_ports,
    )
    if type(gate_receipt) is not rust_license_gate.GateReceipt:
        _refuse()
    try:
        parent = Path(vendor_parent) if vendor_parent else Path(tempfile.gettempdir())
        if not parent.is_absolute() or parent.is_symlink() or not parent.is_dir():
            _refuse()
        parent = parent.resolve(strict=True)
        staging = Path(tempfile.mkdtemp(prefix="kd-cargo-stage-", dir=str(parent)))
        vendor_root = staging / "vendor"
        vendor_root.mkdir(mode=0o700)
    except (OSError, TypeError, ValueError):
        _refuse()
    try:
        produced = cargo_vendor_producer.produce_vendor_evidence(
            lock_bytes, lock_record, binding["expected_context"], authorized,
            gate_receipt, vendor_root,
        )
        request = cargo_vendor_verify.VendorVerificationRequest(
            lock_bytes, lock_record, binding["expected_context"], authorized,
            produced.vendor_directory, produced.vendor_receipt_bytes,
            produced.trusted_vendor_receipt_sha256, staging, gate_receipt,
        )
        verified = cargo_vendor_verify.verify_vendor_tree(request)
        verified["vendor_receipt_sha256"] = produced.trusted_vendor_receipt_sha256
        verified["license_gate_receipt_sha256"] = rust_license_gate.gate_receipt_sha256(
            gate_receipt,
        )
        verified["license_gate_receipt"] = gate_receipt
        verified["registry_lock"] = True
        verified["rust_root"] = str(Path(rust_root)) if rust_root else ""
        verified["required_flags"] = ("--locked", "--offline")
        return verified
    except (cargo.Refusal, rust_license_gate.LicenseGateRefusal,
            cargo_vendor_producer.VendorProductionRefusal,
            OSError, TypeError, ValueError):
        shutil.rmtree(staging, ignore_errors=True)
        _refuse()


def admit_authenticated_lock(lock_bytes, source_root, source_sha, profile, lock_relative,
                             evidence_root, vendor_parent, rust_root="", trusted_ports=None):
    receipt_bytes, binding_bytes = control_files_for_lock(
        evidence_root, source_root, lock_relative,
    )
    result = admit_lock(
        lock_bytes, source_root, source_sha, profile, receipt_bytes, binding_bytes,
        vendor_parent, rust_root, trusted_ports,
    )
    if type(result) is rust_license_gate.RegistryFreeReceipt:
        _refuse()
    return result


def _main(argv=None):
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    inspection = commands.add_parser("inspect-lock")
    inspection.add_argument("--lock-path", required=True)
    admission = commands.add_parser("admit-lock")
    admission.add_argument("--source-root", required=True)
    admission.add_argument("--source-sha", required=True)
    admission.add_argument("--profile", required=True)
    admission.add_argument("--lock-path", required=True)
    admission.add_argument("--receipt-path", required=True)
    admission.add_argument("--binding-path", required=True)
    admission.add_argument("--vendor-parent", required=True)
    admission.add_argument("--rust-root", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect-lock":
            lock_bytes = Path(args.lock_path).read_bytes()
            parsed = cargo.parse_cargo_lock(lock_bytes)
            output = {
                "schema_version": 1,
                "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
                "registry_packages": sum(
                    item.get("source") == cargo.REGISTRY_SOURCE
                    for item in parsed["packages"]
                ),
                "package_count": len(parsed["packages"]),
            }
            sys.stdout.buffer.write(
                json.dumps(output, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
            )
            return 0
        source_root = Path(args.source_root).resolve(strict=True)
        lock_path = Path(args.lock_path).resolve(strict=True)
        try:
            relative = lock_path.relative_to(source_root).as_posix()
        except ValueError:
            _refuse()
        lock_bytes = lock_path.read_bytes()
        receipt_bytes = _read_trusted_file(args.receipt_path, source_root, cargo.MAX_RECEIPT_BYTES)
        binding_bytes = _read_trusted_file(args.binding_path, source_root, MAX_BINDING_BYTES)
        result = admit_lock(
            lock_bytes, source_root, args.source_sha, args.profile,
            receipt_bytes, binding_bytes, args.vendor_parent, args.rust_root,
        )
        if type(result) is rust_license_gate.RegistryFreeReceipt:
            sys.stdout.buffer.write(b"cargo-admission=registry-free\n")
            return 0
        output = {
            "vendor_directory": str(result["materialized_vendor_directory"]),
            "vendor_sha256": result["vendor_sha256"],
            "vendor_receipt_sha256": result["vendor_receipt_sha256"],
            "license_gate_receipt_sha256": result["license_gate_receipt_sha256"],
            "lock_path": relative,
            "source_sha": args.source_sha,
            "cargo_arguments": list(result["cargo_arguments"]),
            "required_flags": list(result["required_flags"]),
        }
        sys.stdout.buffer.write(
            json.dumps(output, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
            + b"\n"
        )
        return 0
    except (OSError, ValueError, RustAdmissionRefusal,
            rust_license_gate.LicenseGateRefusal, cargo.Refusal):
        sys.stdout.buffer.write(b"cargo-admission=refused\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
