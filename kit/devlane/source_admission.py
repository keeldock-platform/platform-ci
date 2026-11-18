"""Portable Git signature checks for the coordinator's pinned Core source."""

import base64
import hashlib
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


SOURCE_SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
SIGNER_PATH = "docs/commit-signers"
REVOCATION_PATH = "ci/revoked-signer-fingerprints"
CORE_SOURCE_REPOSITORY = "keeldock" + "-core"
SOURCE_REPOSITORY_URLS = frozenset((
    "git@github.com:Moh-Bakr/" + CORE_SOURCE_REPOSITORY + ".git",
    "https://github.com/Moh-Bakr/" + CORE_SOURCE_REPOSITORY + ".git",
    "ssh://git@github.com/Moh-Bakr/" + CORE_SOURCE_REPOSITORY + ".git",
))


class AdmissionRefusal(ValueError):
    pass


def _git(repo, *arguments, timeout=30, maximum=8 * 1024 * 1024):
    executable = shutil.which("git")
    if not executable:
        raise AdmissionRefusal("git-unavailable")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(Path(tempfile.gettempdir()).resolve()),
        "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_ATTR_NOSYSTEM": "1",
    }
    try:
        result = subprocess.run(
            [executable, "-c", "core.hooksPath=" + os.devnull,
             "-c", "protocol.file.allow=never", "-c", "http.followRedirects=false",
             "-C", str(repo), *arguments],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False, env=env,
        )
    except (OSError, subprocess.SubprocessError):
        raise AdmissionRefusal("git-unavailable") from None
    if len(result.stdout) > maximum or len(result.stderr) > maximum:
        raise AdmissionRefusal("git-output-limit")
    return result


def _expect_git(repo, *arguments, maximum=8 * 1024 * 1024):
    result = _git(repo, *arguments, maximum=maximum)
    if result.returncode != 0 or result.stderr:
        raise AdmissionRefusal("git-check-failed")
    return result.stdout


def _signer_keys(payload):
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError:
        raise AdmissionRefusal("signer-file-invalid") from None
    accepted = []
    fingerprints = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(chr(35)):
            continue
        try:
            fields = shlex.split(stripped, comments=False, posix=True)
            positions = [index for index in (1, 2) if index < len(fields) and fields[index] == "ssh-ed25519"]
            if len(positions) != 1:
                raise ValueError
            key_position = positions[0]
            encoded = fields[key_position + 1]
            blob = base64.b64decode(encoded.encode("ascii"), validate=True)
            first_size = int.from_bytes(blob[:4], "big")
            second_offset = 4 + first_size
            second_size = int.from_bytes(blob[second_offset:second_offset + 4], "big")
            if (blob[4:second_offset] != b"ssh-ed25519" or second_size != 32
                    or second_offset + 4 + second_size != len(blob)):
                raise ValueError
            fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
            accepted.append((stripped + "\n").encode("ascii"))
            fingerprints[fingerprint] = b"ssh-ed25519 " + encoded.encode("ascii") + b"\n"
        except BaseException:
            raise AdmissionRefusal("signer-file-invalid") from None
    if not accepted:
        raise AdmissionRefusal("signer-file-invalid")
    return b"".join(accepted), fingerprints


def _revoked_keys(payload, signer_map):
    if not payload:
        return b""
    if not payload.endswith(b"\n") or b"\r" in payload or len(payload) > 64 * 1024:
        raise AdmissionRefusal("revocation-file-invalid")
    try:
        lines = payload[:-1].decode("ascii").split("\n")
    except UnicodeError:
        raise AdmissionRefusal("revocation-file-invalid") from None
    revoked = []
    for line in lines:
        if FINGERPRINT_RE.fullmatch(line) is None or line in revoked or line not in signer_map:
            raise AdmissionRefusal("revocation-file-invalid")
        revoked.append(line)
    return b"".join(signer_map[line] for line in revoked)


def _read_revocations(path):
    descriptor = None
    try:
        path = Path(path)
        if path.is_symlink():
            raise AdmissionRefusal("revocation-file-invalid")
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64 * 1024:
            raise AdmissionRefusal("revocation-file-invalid")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, min(8192, 64 * 1024 + 1 - len(payload)))
            if not chunk:
                return bytes(payload)
            payload.extend(chunk)
            if len(payload) > 64 * 1024:
                raise AdmissionRefusal("revocation-file-invalid")
    except AdmissionRefusal:
        raise
    except OSError:
        raise AdmissionRefusal("revocation-file-unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def verify_core_source(*, source_repository, control_repository, source_sha, base_sha,
                       admitted_main_sha, control_sha):
    """Verify exact pinned source ancestry and signatures against base and kit policy."""
    if (SOURCE_SHA_RE.fullmatch(source_sha or "") is None
            or SOURCE_SHA_RE.fullmatch(base_sha or "") is None
            or SOURCE_SHA_RE.fullmatch(admitted_main_sha or "") is None
            or SOURCE_SHA_RE.fullmatch(control_sha or "") is None
            or admitted_main_sha != source_sha):
        raise AdmissionRefusal("source-binding-mismatch")
    source_repository = Path(source_repository).resolve(strict=True)
    control_repository = Path(control_repository).resolve(strict=True)
    root = _expect_git(source_repository, "rev-parse", "--show-toplevel", maximum=4096).decode("ascii").strip()
    if Path(root).resolve() != source_repository:
        raise AdmissionRefusal("source-repository-mismatch")
    remote = _expect_git(source_repository, "remote", "get-url", "origin", maximum=4096).decode("utf-8").strip()
    if remote not in SOURCE_REPOSITORY_URLS:
        raise AdmissionRefusal("source-repository-mismatch")
    _expect_git(source_repository, "cat-file", "-e", base_sha + "^{commit}", maximum=1024)
    _expect_git(source_repository, "cat-file", "-e", source_sha + "^{commit}", maximum=1024)
    _expect_git(source_repository, "merge-base", "--is-ancestor", base_sha, source_sha, maximum=1024)
    parents = _expect_git(source_repository, "show", "-s", "--format=%P", source_sha, maximum=1024).decode("ascii").split()
    if parents != [base_sha]:
        raise AdmissionRefusal("source-base-mismatch")

    signer_payload = _expect_git(source_repository, "show", base_sha + ":" + SIGNER_PATH)
    allowed_payload, signer_map = _signer_keys(signer_payload)
    revocation_path = control_repository / REVOCATION_PATH
    current_payload = _read_revocations(revocation_path)
    admitted_payload = _expect_git(control_repository, "show", control_sha + ":" + REVOCATION_PATH,
                                   maximum=64 * 1024)
    if admitted_payload != current_payload:
        raise AdmissionRefusal("revocation-file-mismatch")
    revoked_payload = _revoked_keys(current_payload, signer_map)

    changed = _expect_git(source_repository, "diff-tree", "--no-commit-id", "--name-only", "-r", "-m", "-z",
                          base_sha, source_sha, maximum=4 * 1024 * 1024)
    if SIGNER_PATH.encode("ascii") in changed.split(b"\x00"):
        raise AdmissionRefusal("signer-authority-changed")
    commits = _expect_git(source_repository, "rev-list", "--topo-order", "--reverse",
                          base_sha + ".." + source_sha, maximum=4 * 1024 * 1024)
    commit_ids = commits.decode("ascii").splitlines()
    if commit_ids != [source_sha]:
        raise AdmissionRefusal("source-range-mismatch")
    ssh_keygen = shutil.which("ssh-keygen")
    if not ssh_keygen:
        raise AdmissionRefusal("ssh-keygen-unavailable")
    with tempfile.TemporaryDirectory(prefix="devlane-source-signature-") as temporary:
        allowed_path = Path(temporary) / "base-allowed-signers"
        revoked_path = Path(temporary) / "revoked-signers"
        allowed_path.write_bytes(allowed_payload)
        revoked_path.write_bytes(revoked_payload)
        result = _git(
            source_repository, "-c", "gpg.format=ssh", "-c", "gpg.ssh.program=" + ssh_keygen,
            "-c", "gpg.program=false", "-c", "gpg.x509.program=false",
            "-c", "gpg.ssh.allowedSignersFile=" + str(allowed_path),
            "-c", "gpg.ssh.revocationFile=" + str(revoked_path),
            "-c", "gpg.minTrustLevel=fully", "verify-commit", source_sha,
            maximum=64 * 1024,
        )
        if result.returncode != 0:
            raise AdmissionRefusal("signature-invalid")
    return {
        "source_sha": source_sha, "base_sha": base_sha, "control_sha": control_sha,
        "signer_authority": "base:" + base_sha + ":" + SIGNER_PATH,
        "revocation_authority": "control:" + control_sha + ":" + REVOCATION_PATH,
        "ancestry": "single-parent-descendant", "admission": "github-main-exact",
    }
