import hashlib
import os
import re
from pathlib import Path


PLATFORM_FILES = frozenset(
    (
        ".github/workflows/public-policy.yml",
        '.github/workflows/node-lock-return.yml',
        '.github/workflows/core-rust-format-return.yml',
        '.github/workflows/core-build-diagnostic-return.yml',
        'kit/confinement/macos_feedback_producer.py',
        'kit/confinement/test_macos_feedback_producer.py',
        'kit/confinement/feedback_producer_crypto.mjs',
        'kit/confinement/test_feedback_producer_crypto.mjs',
        'kit/confinement/feedback_admin.py',
        'kit/confinement/test_feedback_admin.py',
        'kit/confinement/feedback_admin_crypto.mjs',
        'kit/confinement/test_feedback_admin_crypto.mjs',
        'kit/confinement/test_feedback_admin_integration.py',
        'kit/confinement/feedback_api.py',
        'kit/confinement/test_feedback_api.py',
        'kit/confinement/feedback_public_audit.py',
        'kit/confinement/test_feedback_public_audit.py',

        '.github/workflows/node-lock-smoke.yml',
        '.github/workflows/development-feedback-smoke.yml',
        'kit/confinement/development_feedback.mjs',
        'kit/confinement/test_development_feedback.mjs',
        'kit/confinement/feedback_request.py',
        'kit/confinement/test_feedback_request.py',
        'kit/confinement/feedback_smoke.mjs',
        'kit/confinement/test_feedback_smoke.mjs',
        'kit/confinement/feedback_smoke_audit.py',
        'kit/confinement/test_feedback_smoke_audit.py',
        'kit/confinement/node_lock_envelope.mjs',
        'kit/confinement/test_node_lock_envelope.mjs',
        'kit/confinement/node_lock_manifest.mjs',
        'kit/confinement/test_node_lock_manifest.mjs',
        'kit/confinement/node_lock_receipt.py',
        'kit/confinement/test_node_lock_receipt.py',
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
        ".github/workflows/macos-core-contract.yml",
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
        'kit/confinement/macos_core_contract.py',
        'kit/confinement/test_macos_core_contract.py',
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
    '.github/workflows/development-feedback-smoke.yml': '1212e019a19c85d5cb4ef4524cae6c8aedcab4c3998c2ca46f0ee8f10ca6ce8a',
    'kit/confinement/development_feedback.mjs': '12a914f638ff0ecf9ef471b93cda4ce010db32b2a0cfd3820d532687062e117e',
    'kit/confinement/test_development_feedback.mjs': 'a29941208549298f285757ce4d8bb54be10127b498fad644b9f6497a4e47c38a',
    'kit/confinement/feedback_request.py': '13e96cf6642fa7949ff7407c0f67711b3aa8dc3a71095c9b50dc86a84a05c6b4',
    'kit/confinement/test_feedback_request.py': 'af60e475084a71f6b650564f598ef7152688a25dbee4c3ced4aacd1507cf6b8a',
    'kit/confinement/feedback_smoke.mjs': 'de814d03e2202d91312879b1a3ef1e280026d8d8dc53836f35c7f4d1bae59bf6',
    'kit/confinement/test_feedback_smoke.mjs': '2498a04a338a01b1e3f510ebd9b66eca970baa1acac7a78286ebcd5b391dbd0d',
    'kit/confinement/feedback_smoke_audit.py': 'fefaae55c52b676951efc567b304bbbb07bb2488659c6c3803ac192e31fcde7c',
    'kit/confinement/test_feedback_smoke_audit.py': '4b03a8f9c9d04d247377aab7fa9ca2ef80c759527f3d931798e676c858415793',
    '.github/workflows/node-lock-smoke.yml': 'fc9287e22cc03d19679ca0bf505fc9576e155f29460fb96939b5c150788d8c32',
    'kit/confinement/node_lock_envelope.mjs': '17b636e798669b740ae54630082d55c21b0584305cb556770dfc9c9ba593642f',
    'kit/confinement/test_node_lock_envelope.mjs': '255b00fb4e47dff6e825ce52919af04f7f08e21ea49af336f1f52cca23a6f381',
    'kit/confinement/node_lock_manifest.mjs': 'd64ff3d3d6fee05e8e75e8461301a0fd95cc01e9f4ffcfb323483ee7d2fa23ad',
    'kit/confinement/test_node_lock_manifest.mjs': 'b90d9c5564c5f13231924a91d0a4ac7a79403ae25ad42ca42ebb28330bd35666',
    'kit/confinement/node_lock_receipt.py': 'ade987d617a6cfe8a8b9f937ea6c17510a639a9ea671437625afeecd0c7e1a63',
    'kit/confinement/test_node_lock_receipt.py': '76163ace7dc4e239c16c993de84da44deaf402e42ba4fccb1a28fd8c28fae6b6',
    '.github/workflows/macos-core-contract.yml': '38c33a1b30bc18378359910af0da73e493026e8105511062f96f6f80fafbe096',
    'kit/confinement/macos_core_contract.py': '2baaaca63fd39e7686bc1285b88d4ee2548e30be99389d9a7cb73ded4af2f0a9',
    'kit/confinement/test_macos_core_contract.py': 'bc8467c53082bffbf075a3624d0178f10b4325e23f7d167d894df1ff4086b56d',
    '.github/workflows/macos-rust-toolchain-smoke.yml': 'cdf7068f8887c22958d74f3c2cc0a73c5c8c4c41f4eff0b43e16e47f61e58bb7',
    'kit/confinement/macos_rust_toolchain.py': '917e27d7fef4b7481074ea44ee731e02c95f79a378c3a69662d3338a7fb666f5',
    'kit/confinement/test_macos_rust_toolchain.py': '49f93552ee9b4dbbc557d9f01238aee53589ac581c54b5ede964e948e694b153',
    '.github/workflows/macos-rules-bootstrap.yml': 'a91387440f8caceadf8f19f7c87feb3d82377eb3c9e1813de48b518992d48807',
    '.github/workflows/macos-core-bootstrap.yml': '08cf50d62e18e52661befe3153294c2d188b8a980f914437dab7cbd899744b81',
    'kit/confinement/macos_rules_bootstrap.py': '9e86a0e5f100614f6a845723994760e186536b40abb6109701537e3e231b4308',
    'kit/confinement/test_macos_rules_bootstrap.py': '51dc1cb1539eefa8ebc891f71c30eb278b43bd145b6988b391a2b8734fcb6c0e',
    'kit/confinement/macos_core_bootstrap.py': '0b03235d000b1504848d49215a2bed9c4dec5ee3dd47d26b4177c7fa44c16836',
    'kit/confinement/test_macos_core_bootstrap.py': 'f8e56bde25e64fc691adc25c3288924179797b83c8d6da66ef21c5fad256c38e',
    'kit/confinement/macos_network_observer.py': 'a7cf6cb16e68f00513e9f8ee08d52511619b18bb8edd37205faf907dcf0a98d9',
    'kit/confinement/test_macos_network_observer.py': '0187ffbe5a7b7395b2edc2025a4dd3e4c0adf5a48c881f8878578010d76307a3',
    'kit/confinement/macos_private_validation.py': 'aaa86eee51b2063e3d3f437e99eecd0ed4aae7a70a0724714b3fd4f19be966c6',
    'kit/confinement/test_macos_private_validation.py': 'b7db7145673e9f2f1607076d739ba6d6b32194ef13aea2cda11506c4b3239f05',
    'ci/revoked-signer-fingerprints': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    '.github/workflows/windows-native-preflight.yml': 'da294aadfc0e99cbe109aba90f9fb86df65867cd32d3325d26a9e9a5b035e5bb',
    'kit/confinement/windows_native_preflight.cs': 'ba0f8859db9d8bcc1e4c8274520bcb67a3292cb311f553127e1f29fe13838543',
    'kit/confinement/windows_native_preflight.ps1': '8dbaaaad105c2fe0439dedb1b7c9572b8e7ec74a8db29f8edcab91169b06c58b',
    'kit/confinement/test_windows_native_preflight.py': '02d6bcf6d52d4c5f26589b6da8e224b5f0b3f8f57255e00c135f666caed613fe',
    'kit/confinement/macos_source_reader.py': 'd3fbda5c68ac7d21761e946b0f546607b19c23ccb725e453f3fffef3321c0d70',
    'kit/confinement/test_macos_source_reader.py': 'ed8e9b850f7d3a80346ad4a6efc182b28ff9c22fa669eda241f2c5feb3ccf806',
    '.github/workflows/node-lock-return.yml': 'a174d16844493ec95aad32bab573536799c3ea9d8185fcc4d5e9976d1bd28180',
    '.github/workflows/core-rust-format-return.yml': '6e654caeee7385eaf0ba205edf6459a628304270659449f6218ce152c34a1adf',
    '.github/workflows/core-build-diagnostic-return.yml': '7f661e8f2fe8493e15ee14e69030b979f1022e52d2be826c507d23b66de2ef92',
    'kit/confinement/macos_feedback_producer.py': '4474457a1af8a4122aebe90901d4eb11e536a80da2ae5a7cc1f89731342e11b5',
    'kit/confinement/test_macos_feedback_producer.py': 'b97041a243241423bd34f8ef59eba1bc9c1fef2b08aca74566c4a6d2387ff7ac',
    'kit/confinement/feedback_producer_crypto.mjs': 'e621131afec27d78b170e207843e76e20d4f9682cf2323c3a787ac53b6db60da',
    'kit/confinement/test_feedback_producer_crypto.mjs': '1f70ec5fd25a02257f9bf857afcd244383aec71906e45fd4ed67809c279a9c10',
    'kit/confinement/feedback_admin.py': 'be8d497598b11dbe665261d7791a5136e0f0ebde6bba74b825986e4c229eaacc',
    'kit/confinement/test_feedback_admin.py': '065bdd930e4cc6ac698fe577d9055459fb78390b677fb45840ba9c605cf8c3af',
    'kit/confinement/feedback_admin_crypto.mjs': '181e1b986916de1bd146368254589b5d69e34f50e3e8e7111f0f8ea5ca7b4e8e',
    'kit/confinement/test_feedback_admin_crypto.mjs': 'f327b2b12055909db88e1ce2ad65a27bfd9835b83234da81357ef6b7411344a8',
    'kit/confinement/test_feedback_admin_integration.py': '490867f9b8e922af1f960cca82b6e0612f8859c456cfabc63c038a330ad4e7dc',
    'kit/confinement/feedback_api.py': 'da61979310f4d021c98377095b92c54c87679731cbbc41d73001dc4a1e198108',
    'kit/confinement/test_feedback_api.py': 'c680ecc82df70834d0e7a870407567f8fa064b909c24300404a4b56cc8a2e030',
    'kit/confinement/feedback_public_audit.py': '33a9aa0b39f8cdbd367ab144efab3b1da2a31800316f8c7ae8184a3ac0c803a1',
    'kit/confinement/test_feedback_public_audit.py': '9a639b042cfbf494e14321eeedcd652cffb0ff9bbe62c3626874ab221e8a94a2',
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
