import hashlib
import os
import re
from pathlib import Path


PLATFORM_FILES = frozenset(
    (
        ".github/workflows/public-policy.yml",
        ".github/workflows/linux-confinement.yml",
        ".github/workflows/windows-attestation-permission-probe.yml",
        ".github/workflows/macos-capability.yml",
        ".github/workflows/macos-reviewed-build.yml",
        ".github/workflows/macos-rust-toolchain-smoke.yml",
        ".github/workflows/macos-cache-proof.yml",
        ".github/workflows/macos-source-reader-preflight.yml",
        ".github/workflows/macos-rules-reader-preflight.yml",
        ".github/workflows/macos-rules-bootstrap.yml",
        ".github/workflows/macos-core-bootstrap.yml",
        ".github/workflows/windows-native-preflight.yml",
        "ci/policy.json",
        "ci/revoked-signer-fingerprints",
        "kit/bootstrap/action.yml",
        "kit/bootstrap/check_candidate.py",
        "kit/bootstrap/policy.py",
        "kit/bootstrap/public_tree.py",
        "kit/bootstrap/test_policy.py",
        "kit/bootstrap/test_public_tree.py",
        "kit/confinement/macos_boundary_guard.py",
        "kit/confinement/test_macos_boundary_guard.py",
        "kit/confinement/macos_canary_scan.py",
        "kit/confinement/macos_deny_default.py",
        "kit/confinement/test_macos_deny_default.py",
        "kit/confinement/macos_public_audit.py",
        "kit/confinement/test_macos_public_audit.py",
        "kit/confinement/macos_cache_client/action.yml",
        "kit/confinement/macos_cache_client/index.js",
        "kit/confinement/macos_reviewed_build.py",
        "kit/confinement/test_macos_reviewed_build.py",
        "kit/confinement/macos_rust_toolchain.py",
        "kit/confinement/test_macos_rust_toolchain.py",
        "kit/confinement/macos_network_observer.py",
        "kit/confinement/test_macos_network_observer.py",
        'kit/confinement/macos_rules_bootstrap.py',
        'kit/confinement/test_macos_rules_bootstrap.py',
        'kit/confinement/macos_core_bootstrap.py',
        'kit/confinement/test_macos_core_bootstrap.py',
        "kit/confinement/macos_private_validation.py",
        "kit/confinement/test_macos_private_validation.py",
        "kit/confinement/macos_source_reader.py",
        "kit/confinement/test_macos_source_reader.py",
        "kit/confinement/macos_harness.py",
        "kit/confinement/test_macos_harness.py",
        "kit/confinement/macos_capability.py",
        "kit/confinement/macos_capability.swift",
        "kit/confinement/test_macos_capability.py",
        "kit/confinement/test_macos_descriptors.py",
        "kit/confinement/linux_harness.py",
        "kit/confinement/test_linux_harness.py",
        "kit/confinement/windows_native_preflight.cs",
        "kit/confinement/windows_native_preflight.ps1",
        "kit/confinement/test_windows_native_preflight.py",
    )
)
CONSUMER_FILES = frozenset((".github/workflows/public-policy.yml", "ci/policy.json"))
ALLOWED_FILES = {
    "platform": PLATFORM_FILES,
    "connect": CONSUMER_FILES,
    "workspace": CONSUMER_FILES,
    "data": CONSUMER_FILES,
}
MAX_FILE_BYTES = 262144
PINNED_FILE_SHA256 = {
    '.github/workflows/macos-rust-toolchain-smoke.yml': 'cdf7068f8887c22958d74f3c2cc0a73c5c8c4c41f4eff0b43e16e47f61e58bb7',
    'kit/confinement/macos_rust_toolchain.py': 'a27c103b1d6c4fbf9fef24469ade69668e01c949e3108dc89dc3dbd63ac14b49',
    'kit/confinement/test_macos_rust_toolchain.py': '27c40bc8d42a3df6e88209d6cb8ea99cd9e80107310f1eb639dbfb2f6638727a',
    '.github/workflows/macos-rules-bootstrap.yml': 'a91387440f8caceadf8f19f7c87feb3d82377eb3c9e1813de48b518992d48807',
    '.github/workflows/macos-core-bootstrap.yml': '08cf50d62e18e52661befe3153294c2d188b8a980f914437dab7cbd899744b81',
    'kit/confinement/macos_rules_bootstrap.py': '9e86a0e5f100614f6a845723994760e186536b40abb6109701537e3e231b4308',
    'kit/confinement/test_macos_rules_bootstrap.py': '51dc1cb1539eefa8ebc891f71c30eb278b43bd145b6988b391a2b8734fcb6c0e',
    'kit/confinement/macos_core_bootstrap.py': '0b03235d000b1504848d49215a2bed9c4dec5ee3dd47d26b4177c7fa44c16836',
    'kit/confinement/test_macos_core_bootstrap.py': 'f8e56bde25e64fc691adc25c3288924179797b83c8d6da66ef21c5fad256c38e',
    'kit/confinement/macos_network_observer.py': 'a7cf6cb16e68f00513e9f8ee08d52511619b18bb8edd37205faf907dcf0a98d9',
    'kit/confinement/test_macos_network_observer.py': '0187ffbe5a7b7395b2edc2025a4dd3e4c0adf5a48c881f8878578010d76307a3',
    'kit/confinement/macos_private_validation.py': 'c50dc22b6a0024ac387724771665fd1396bd64abe85a772e07cf852b56ec7464',
    'kit/confinement/test_macos_private_validation.py': 'da59832cb3de5388779d8d6f3a2a0e3ea339fd3b9a1bb892fbfee4bf70d9d02d',
    'ci/revoked-signer-fingerprints': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    ".github/workflows/windows-native-preflight.yml": "da294aadfc0e99cbe109aba90f9fb86df65867cd32d3325d26a9e9a5b035e5bb",
    "kit/confinement/windows_native_preflight.cs": "ba0f8859db9d8bcc1e4c8274520bcb67a3292cb311f553127e1f29fe13838543",
    "kit/confinement/windows_native_preflight.ps1": "8dbaaaad105c2fe0439dedb1b7c9572b8e7ec74a8db29f8edcab91169b06c58b",
    "kit/confinement/test_windows_native_preflight.py": "02d6bcf6d52d4c5f26589b6da8e224b5f0b3f8f57255e00c135f666caed613fe",
    "kit/confinement/macos_source_reader.py": "d3fbda5c68ac7d21761e946b0f546607b19c23ccb725e453f3fffef3321c0d70",
    "kit/confinement/test_macos_source_reader.py": "ed8e9b850f7d3a80346ad4a6efc182b28ff9c22fa669eda241f2c5feb3ccf806",
}
PLAN_ID_PATTERN = re.compile(r"(?<![A-Za-z0-9])(?:D|R|H|X|CI|PF|K)[0-9]{1,3}(?![0-9])")
ACTION_VERSION_COMMENT_PATTERN = re.compile(
    r"^\s*uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}\s+"
    + re.escape(chr(35))
    + r"\s+v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$"
)
PRIVATE_PATH_PATTERN = re.compile(chr(47) + r"(?:Users|home|private)/[A-Za-z0-9._-]+")
WINDOWS_PRIVATE_PATH_PATTERN = re.compile(
    r"[A-Za-z]:[\\/]" + r"(?:Users|Documents and Settings)[\\/]" + r"[A-Za-z0-9._ -]+",
    re.IGNORECASE,
)
WINDOWS_UNC_PRIVATE_PATH_PATTERN = re.compile(
    r"(?:\\\\\?\\UNC\\|//\?/UNC/|\\\\|//)"
    + r"[^\\/\s]+"
    + r"(?:[\\/][^\\/\s]+)?"
    + r"[\\/](?:Users|Documents and Settings)[\\/][A-Za-z0-9._ -]+",
    re.IGNORECASE,
)
REPOSITORY_URL_PATTERN = re.compile(
    re.escape("https:" + chr(47) * 2 + "github.com" + chr(47))
    + r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
)
PRIVATE_REPOSITORY_PREFIX = "keeldock" + "-"
PUBLIC_REPOSITORY_PREFIX = "keeldock" + "-" + "platform"
PRIVATE_PATH_MARKERS = (
    "agents" + "-work",
    "Plans" + chr(47) + "PluginSystem",
    "." + "claude",
)


class PublicTreeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def inspect_text(text, pool):
    lowered = text.lower()
    if any(
        chr(35) in line and not ACTION_VERSION_COMMENT_PATTERN.fullmatch(line)
        for line in text.splitlines()
    ):
        raise PublicTreeError("comment-present")
    if PLAN_ID_PATTERN.search(text):
        raise PublicTreeError("plan-id-present")
    if PRIVATE_PATH_PATTERN.search(text):
        raise PublicTreeError("absolute-path-present")
    if WINDOWS_PRIVATE_PATH_PATTERN.search(text):
        raise PublicTreeError("absolute-path-present")
    if WINDOWS_UNC_PRIVATE_PATH_PATTERN.search(text):
        raise PublicTreeError("absolute-path-present")
    if REPOSITORY_URL_PATTERN.search(text):
        raise PublicTreeError("repository-url-present")
    allowed_prefixes = ("keeldock" + "-" + pool, PUBLIC_REPOSITORY_PREFIX)
    without_public_names = lowered
    for public_prefix in allowed_prefixes:
        without_public_names = without_public_names.replace(public_prefix, "")
    if PRIVATE_REPOSITORY_PREFIX in without_public_names:
        raise PublicTreeError("private-name-present")
    if any(marker.lower() in lowered for marker in PRIVATE_PATH_MARKERS):
        raise PublicTreeError("private-path-present")


def _expected_directories(files):
    result = set()
    for name in files:
        parent = Path(name).parent
        while str(parent) != ".":
            result.add(parent.as_posix())
            parent = parent.parent
    return result


def scan_tree(root, pool):
    if type(pool) is not str or pool not in ALLOWED_FILES:
        raise PublicTreeError("pool-unknown")
    root = Path(root)
    if not root.is_dir():
        raise PublicTreeError("tree-unavailable")
    actual_files = set()
    actual_directories = set()
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        relative_current = current_path.relative_to(root)
        if relative_current.parts and relative_current.parts[0] == ".git":
            directories[:] = []
            continue
        retained = []
        for directory in directories:
            item = current_path / directory
            if item.is_symlink():
                raise PublicTreeError("symlink-present")
            if directory == ".git" and relative_current == Path("."):
                continue
            retained.append(directory)
            actual_directories.add((relative_current / directory).as_posix())
        directories[:] = retained
        for filename in files:
            item = current_path / filename
            relative = item.relative_to(root).as_posix()
            if relative == ".git" and item.is_file() and not item.is_symlink():
                continue
            if relative.startswith(".git/"):
                continue
            if item.is_symlink() or not item.is_file():
                raise PublicTreeError("non-regular-file")
            actual_files.add(relative)
    expected_files = ALLOWED_FILES[pool]
    if actual_files != expected_files or actual_directories != _expected_directories(expected_files):
        raise PublicTreeError("tree-shape")
    for relative in sorted(actual_files):
        item = root / relative
        try:
            with item.open("rb") as source:
                payload = source.read(MAX_FILE_BYTES + 1)
        except OSError:
            raise PublicTreeError("file-unreadable")
        if len(payload) > MAX_FILE_BYTES:
            raise PublicTreeError("file-too-large")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            raise PublicTreeError("file-not-utf8")
        expected_hash = PINNED_FILE_SHA256.get(relative)
        if expected_hash is not None and hashlib.sha256(payload).hexdigest() != expected_hash:
            raise PublicTreeError("file-hash-mismatch")
        inspect_text(text, pool)
    return tuple(sorted(actual_files))
