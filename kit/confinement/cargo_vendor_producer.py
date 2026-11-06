"""Create trusted offline vendor evidence from authenticated crates.io archives."""

from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path

import cargo_archive_producer
import cargo_lock_receipt as cargo
import rust_license_gate


VENDOR_RECEIPT_SCHEMA_VERSION = 2
VENDOR_RECEIPT_FIELDS = frozenset((
    "schema_version", "lock_receipt_sha256", "lock_sha256", "source_sha", "profile",
    "vendor_sha256", "license_gate_receipt_sha256", "archive_spdx_sha256",
    "policy_sha256", "checker_sha256", "cargo_deny_sha256",
    "cargo_deny_qualification_sha256", "advisory_database_commit",
    "advisory_database_generated_at_epoch",
))


class VendorProductionRefusal(Exception):
    """Fixed source-free vendor production refusal."""


@dataclass(frozen=True)
class VendorProductionResult:
    vendor_directory: Path
    vendor_receipt_bytes: bytes
    trusted_vendor_receipt_sha256: str
    vendor_sha256: str


def _refuse():
    raise VendorProductionRefusal("cargo_vendor_production_invalid")


def _canonical_bytes(value):
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _refuse()


def _read_lock_record(lock_receipt):
    try:
        if type(lock_receipt) is bytes:
            return cargo.decode_receipt(lock_receipt)
        if type(lock_receipt) is dict:
            return cargo.decode_receipt(cargo.encode_receipt(lock_receipt))
    except cargo.Refusal:
        _refuse()
    _refuse()


def _require_empty_vendor_root(vendor_root):
    try:
        root = Path(vendor_root)
        if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
                or any(root.iterdir()) or cargo._is_link_or_reparse(root)):
            _refuse()
        return root.resolve(strict=True)
    except VendorProductionRefusal:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        _refuse()


def produce_vendor_evidence(lock_bytes, lock_receipt, expected_lock_context,
                            authorized_audits, license_gate_receipt, vendor_root,
                            archive_port=None):
    """Materialize archives and issue a receipt bound to lock, gate, source and policy."""
    try:
        record = _read_lock_record(lock_receipt)
        cargo.verify_lock_against_receipt(
            lock_bytes, record, expected_lock_context, authorized_audits,
        )
        packages = tuple(rust_license_gate.Package(
            item["name"], item["version"], item["checksum"],
        ) for item in record["packages"])
        if not packages:
            _refuse()
        rust_license_gate.require_vendor_gate_receipt(
            license_gate_receipt, record["source_sha"], record["workspace_path"],
            record["lock_sha256"], packages,
        )
        root = _require_empty_vendor_root(vendor_root)
        parsed = cargo.parse_cargo_lock(lock_bytes)
        lock_packages = tuple(sorted((rust_license_gate.Package(
            item["name"], item["version"], item["checksum"],
        ) for item in parsed["packages"] if item.get("source") == cargo.REGISTRY_SOURCE),
            key=lambda item: (item.name, item.version, item.checksum)))
        if lock_packages != tuple(sorted(packages, key=lambda item: (item.name, item.version, item.checksum))):
            _refuse()
        port = archive_port or cargo_archive_producer.TrustedArchivePort()
        if type(port) is not cargo_archive_producer.TrustedArchivePort:
            _refuse()

        def materialize(package, payload):
            cargo.extract_archive(
                package.name, package.version, payload, package.checksum, root,
            )

        archives = port.verify_complete(
            lock_bytes, license_gate_receipt.identity, packages,
            archive_consumer=materialize,
        )
        archives = rust_license_gate._validate_archives(
            license_gate_receipt.identity, packages, archives,
        )
        if not hmac.compare_digest(
                archives.archive_spdx_sha256, license_gate_receipt.archive_spdx_sha256):
            _refuse()
        vendor_sha256 = cargo.make_vendor_read_only(root)
        gate_sha256 = rust_license_gate.gate_receipt_sha256(license_gate_receipt)
        receipt = {
            "schema_version": VENDOR_RECEIPT_SCHEMA_VERSION,
            "lock_receipt_sha256": hashlib.sha256(cargo.encode_receipt(record)).hexdigest(),
            "lock_sha256": record["lock_sha256"],
            "source_sha": record["source_sha"],
            "profile": record["workspace_path"],
            "vendor_sha256": vendor_sha256,
            "license_gate_receipt_sha256": gate_sha256,
            "archive_spdx_sha256": archives.archive_spdx_sha256,
            "policy_sha256": license_gate_receipt.policy_sha256,
            "checker_sha256": license_gate_receipt.checker_sha256,
            "cargo_deny_sha256": license_gate_receipt.cargo_deny_sha256,
            "cargo_deny_qualification_sha256":
                license_gate_receipt.cargo_deny_qualification_sha256,
            "advisory_database_commit": license_gate_receipt.advisory_database_commit,
            "advisory_database_generated_at_epoch":
                license_gate_receipt.advisory_database_generated_at_epoch,
        }
        if set(receipt) != VENDOR_RECEIPT_FIELDS:
            _refuse()
        receipt_bytes = _canonical_bytes(receipt)
        return VendorProductionResult(
            root, receipt_bytes, hashlib.sha256(receipt_bytes).hexdigest(), vendor_sha256,
        )
    except VendorProductionRefusal:
        raise
    except (cargo.Refusal, rust_license_gate.LicenseGateRefusal,
            cargo_archive_producer.ArchiveProducerRefusal, OSError, TypeError, ValueError):
        _refuse()
