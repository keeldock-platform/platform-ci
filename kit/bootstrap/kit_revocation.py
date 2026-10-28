import hashlib
import re
from pathlib import Path

from public_tree import MAX_FILE_BYTES, PINNED_FILE_SHA256


REVOCATION_PATH = "ci/revoked-kit-versions"
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
KIT_SHA = re.compile(r"[a-f0-9]{40}\Z")
KIT_VERSION = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


class RevocationError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def parse_revocations(payload, expected_sha256):
    if type(payload) is not bytes or len(payload) > MAX_FILE_BYTES:
        raise RevocationError("revocation-size")
    if type(expected_sha256) is not str or SHA256.fullmatch(expected_sha256) is None:
        raise RevocationError("revocation-pin-invalid")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise RevocationError("revocation-pin-mismatch")
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        raise RevocationError("revocation-encoding")
    if not text:
        return {"versions": frozenset(), "shas": frozenset()}
    if "\r" in text or not text.endswith("\n"):
        raise RevocationError("revocation-line-ending")
    lines = text[:-1].split("\n")
    if not lines or lines[0] != "kit-revocations-v1" or any(not line for line in lines):
        raise RevocationError("revocation-format")
    entries = lines[1:]
    if entries != sorted(entries) or len(entries) != len(set(entries)):
        raise RevocationError("revocation-order")
    versions = set()
    shas = set()
    for line in entries:
        fields = line.split("\t")
        if len(fields) != 2:
            raise RevocationError("revocation-entry")
        kind, value = fields
        if kind == "version" and KIT_VERSION.fullmatch(value) is not None:
            versions.add(value)
        elif kind == "sha" and KIT_SHA.fullmatch(value) is not None:
            shas.add(value)
        else:
            raise RevocationError("revocation-entry")
    if len(versions) != sum(1 for line in entries if line.startswith("version\t")):
        raise RevocationError("revocation-duplicate")
    if len(shas) != sum(1 for line in entries if line.startswith("sha\t")):
        raise RevocationError("revocation-duplicate")
    return {"versions": frozenset(versions), "shas": frozenset(shas)}


def load_revocations(root):
    expected_sha256 = PINNED_FILE_SHA256.get(REVOCATION_PATH)
    if expected_sha256 is None:
        raise RevocationError("revocation-pin-missing")
    try:
        with (Path(root) / REVOCATION_PATH).open("rb") as source:
            payload = source.read(MAX_FILE_BYTES + 1)
    except OSError:
        raise RevocationError("revocation-unavailable")
    return parse_revocations(payload, expected_sha256)


def check_kit_not_revoked(root, kit_sha, version=None):
    if type(kit_sha) is not str or KIT_SHA.fullmatch(kit_sha) is None:
        raise RevocationError("kit-sha-invalid")
    if version is not None and (type(version) is not str or KIT_VERSION.fullmatch(version) is None):
        raise RevocationError("kit-version-invalid")
    revoked = load_revocations(root)
    if kit_sha in revoked["shas"] or (version is not None and version in revoked["versions"]):
        raise RevocationError("kit-revoked")
    return True
