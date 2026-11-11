"""Pinned, source-map-bound SemVer stage for the encrypted offline Rust matrix."""

import hashlib
import json
import os
import re
import stat
import tomllib
import time
from pathlib import Path


SOURCE_ROOT = "/workspace/source"
BASELINE_ROOT = "/workspace/semver-baseline/runtime"
LEGACY_BASELINE_ROOT = "/prepared/semver-baseline/runtime"
TOOLS_ROOT = "/prepared/devlane-tools"
SUITE = "semver-runtime"
STAGE = "semver"
CHECK_SECONDS = 1800
PIN_FILE = Path(__file__).with_name("semver-pins.json")
PIN_FILE_SHA256 = "9c08ce2957c3561f93ffb2e19507abcc02a959d67f660000b0c27ac133269449"
MAX_PIN_BYTES = 16 * 1024
MAX_SOURCE_FILE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_TREE_BYTES = 512 * 1024 * 1024
SEMVER_TOOL = "cargo-semver-checks"
SEMVER_VERSION = "0.51.0"
SEMVER_ASSET_SHA256 = "cacadafaa5cd27ae6d05a74a103266917ebab4c5e43c898360e177d4fbf06a65"
SEMVER_RELEASE_COMMIT = "260fad71517e8b320c5c1ad1f367900ab37362a1"
TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
SOURCE_REVISION = "9d6cc9e68694e17857d7702e83654131804a1bda"
SOURCE_TREE = "958e13e531d1b2601f241a91a9f80a44ac04d889"
FULL_GIT_TREE_MAP_SHA256 = "d6ef344e2129babea26ac39c04bacf7eb4cbd3d770acb8416b2fe11a1c334eab"
FULL_GIT_FILE_COUNT = 2637
SELECTED_TRANSFER_MAP_SHA256 = "ca99e9c82c8ea07bc4a1d73d881da673dc5f71194c0db4c61c179da5d248b6b3"
SELECTED_TRANSFER_FILE_COUNT = 2636
SELECTED_TRANSFER_BYTES = 16619832
EXCLUDED_SOURCE_PATHS = (".npmrc",)
OFFLINE_CACHE_PIN = {
    "schema": "keeldock.rust-v2-semver-execution-inputs.v1",
    "helper_sha256": "d2eccd210ef2f466e927daa3b5b9b1fccddb23c1a5b2387714464cbe58389b14",
    "wrapper_sha256": "63ba0974db2388b3462f7dddded28fa7f89e5a60575a88ae68d8de9b17712336",
    "support_modules": {
        "bounded_registry_io.py": "4ba0d03215642857306056f8a52e051a67056642fca1b42c15921abddba584d5",
        "cargo_projection.py": "ea0557e6a1d72dacbaa2449449d8ce994f579d8b42bb6263e25643a6da447328",
        "constraint_resolver.py": "d66ea2eef15d91aa4eb4e97d443efaed3c760f4820c0877e554f349e87452e73",
        "registry_prefetch.py": "585c02674ca6532b09a4ad426217c34f7a8279412d947b28fb33ebfe8525a45a",
        "rust_lock_generation.py": "86b999e05b6c24e320591f9a1e2853dcdd7e68615936b42707669c866fa9d3b5",
        "rust_preparation_v2.py": "f38b3049d0cfbf852406a3dc807341a8bba482e3a2f25530fa390a6182e86422",
        "temp_project_checkpoints.py": "93e47b3867f6c5e4c7051f5705fc4acea765438c88c73ba272941f6ea11db299",
    },
    "replay_mode": "verified-final-payload-only",
}
OFFLINE_DEPENDENCY_CONTRACT = {
    "owner": "trusted-supervisor",
    "prepared_baseline": BASELINE_ROOT,
    "candidate_lock_inputs": "generated root, runtime, and fuzz locks are bound by the generation record and remain ephemeral",
    "offline_cargo_inputs": "the prepared local registry is shared by candidate, baseline, and tool-created projects",
    "temporary_cargo_update": "tool-created projects are observed by fixed callbacks after creation",
    "network": "CARGO_NET_OFFLINE=true; the network cut is verified before execution",
    "failure": "missing baseline, lock record, or registry input refuses without a network retry",
}
BASELINE_MAP_SHA256 = "e0a6b6b1c822658b2d55555c2e790193d0fff402632d7df8c22e2d031e5cb1f3"
BASELINE_REVISION = "bb1258247ebbbcfec7f112c67dd15902a0f4d4d1"
BASELINE_FILE_COUNT = 59
BASELINE_TOTAL_BYTES = 253657
CANDIDATE_SOURCE_MAP_SHA256 = "6242bb393a8b4b70c76efd9eaae4ad3f7b1ba831b380868a3dd5da3b79ad6f73"
BASELINE_VERSION = "0.1.0"
CANDIDATE_VERSION = "0.2.0"
BASELINE_RUNTIME_MANIFEST_SHA256 = "7bbd52ff34a5db106b792b6764e0a032d99e935723227970514568fba48778dc"
CANDIDATE_RUNTIME_MANIFEST_SHA256 = "6696df8536d6b4c3ea8ae8ccf7e812cf516833f10302bcf277f3ff4e69aa7d20"
CANDIDATE_MANIFEST_SHA256 = {
    "Cargo.toml": "98202cdbb1ce4a75cba138acaf6911de65430ba183640b0a45155ab7f8d5530a",
    "fuzz/Cargo.toml": "053fb43372e34b20cfeb9bdc9f7f63e2c8fadfd5f8dbd10af9f0f76e75d797d0",
    "runtime/Cargo.toml": CANDIDATE_RUNTIME_MANIFEST_SHA256,
}
BASELINE_RUNTIME_LOCK_SHA256 = "d2196578c97f4fd7435bdc6b581f8b59f6020025e003bab91b697aa3a74a3cf7"
SOURCE_SET_DOMAIN = "keeldock" + "-core/core-rust-candidate-baseline/v1"
BASELINE_NAMESPACE = ".devlane/baseline-runtime"
SOURCE_EXCLUSIONS = [{"path": ".npmrc", "status": "untransferred-unscanned"}]
OFFLINE_CACHE_MATRIX_CONTRACT = {
    "schema": OFFLINE_CACHE_PIN["schema"],
    "source_maps": {
        "baseline_source_map_sha256": BASELINE_MAP_SHA256,
        "candidate_source_map_sha256": CANDIDATE_SOURCE_MAP_SHA256,
        "candidate_full_source_map_sha256": SELECTED_TRANSFER_MAP_SHA256,
    },
    "source_transfer": {
        "source_revision": SOURCE_REVISION,
        "source_tree": SOURCE_TREE,
        "full_git_tree_map_sha256": FULL_GIT_TREE_MAP_SHA256,
        "full_git_file_count": FULL_GIT_FILE_COUNT,
        "selected_transfer_map_sha256": SELECTED_TRANSFER_MAP_SHA256,
        "selected_file_count": SELECTED_TRANSFER_FILE_COUNT,
        "selected_source_bytes": SELECTED_TRANSFER_BYTES,
        "excluded_paths": list(EXCLUDED_SOURCE_PATHS),
    },
    "temporary_project_checkpoint_protocol": {
        "local": ["before-update", "after-update", "after-metadata", "after-doc"],
        "registry": ["before-metadata", "after-metadata", "after-doc"],
        "root": "/scratch/semver-target/semver-checks",
    },
    "prepared_inputs": {
        "registry": "/prepared/cargo-local-registry",
        "registry_record": "/prepared/registry-preparation.json",
        "generated_locks_record": "/trusted/generated-locks.json",
        "generated_lock_status": "ephemeral-offline-generated-not-committed",
        "generated_lock_paths": ["Cargo.lock", "fuzz/Cargo.lock", "runtime/Cargo.lock"],
        "baseline_root": BASELINE_ROOT,
        "baseline_external_packages": [],
        "rust_tool_provenance_status": "binary-hash-bound-origin-unverified",
    },
    "runtime_status": "pending-public-linux-offline-semver-execution",
}
MATRIX_CONTRACT = {
    "suite": SUITE,
    "stage": STAGE,
    "tool": SEMVER_TOOL,
    "version": SEMVER_VERSION,
    "asset_sha256": SEMVER_ASSET_SHA256,
    "release_commit": SEMVER_RELEASE_COMMIT,
    "baseline_root": BASELINE_ROOT,
    "baseline_version": BASELINE_VERSION,
    "baseline_runtime_map_sha256": BASELINE_MAP_SHA256,
    "candidate_runtime_root": SOURCE_ROOT + "/runtime",
    "candidate_version": CANDIDATE_VERSION,
    "candidate_source_map_sha256_excluding_runtime_Cargo_lock": CANDIDATE_SOURCE_MAP_SHA256,
    "source_revision": SOURCE_REVISION,
    "source_tree": SOURCE_TREE,
    "source_transfer": OFFLINE_CACHE_MATRIX_CONTRACT["source_transfer"],
    "argv": [
        "<prepared>/cargo-semver-checks", "check-release",
        "--manifest-path", SOURCE_ROOT + "/runtime/Cargo.toml",
        "--baseline-root", BASELINE_ROOT, "--workspace", "--all-features",
        "--target", TARGET_TRIPLE,
    ],
    "offline_environment": {"CARGO_NET_OFFLINE": "true"},
    "offline_cache": {
        "schema": OFFLINE_CACHE_PIN["schema"],
        "helper_sha256": OFFLINE_CACHE_PIN["helper_sha256"],
        "wrapper_sha256": OFFLINE_CACHE_PIN["wrapper_sha256"],
        "prepared_root": "/prepared",
        "prepared_registry": "/prepared/cargo-local-registry",
        "generated_locks_record": "/trusted/generated-locks.json",
        "cargo_home": "/scratch/semver-cargo-home",
        "cargo_wrapper": "/scratch/semver-cargo-bin/cargo",
        "worker_uid": 65534,
        "temporary_project_checkpoints": [
            "before-update", "after-update", "after-metadata", "after-doc",
        ],
        "registry_project_checkpoints": [
            "before-metadata", "after-metadata", "after-doc",
        ],
        "target_root": "/scratch/semver-target",
        "runtime_status": "pending-public-linux-offline-semver-execution",
    },
    "offline_dependency_contract": OFFLINE_DEPENDENCY_CONTRACT,
    "timeout_seconds": CHECK_SECONDS,
    "release_type_override": None,
    "exit_semantics": {"0": "clean", "100": "deny-findings", "101": "could-not-complete", "other_nonzero": "execution-or-cli-error"},
    "pre_1_0_policy": "allow-breaking-api-changes-for-0.1.0-to-0.2.0-by-cargo-major-equivalent-convention",
    "clean_result_limit": "No deny-level findings beyond the declared version bump; not a complete compatibility or release approval.",
}


class SemverRefusal(ValueError):
    def __init__(self, code="semver-input-invalid"):
        super().__init__(code)
        self.code = code


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _read_fixed_file(path, maximum):
    descriptor = None
    try:
        path = Path(path)
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > maximum):
            raise SemverRefusal("semver-input-invalid")
        nofollow = getattr(os, "O_NOFOLLOW", None)
        nonblock = getattr(os, "O_NONBLOCK", None)
        if nofollow is None or nonblock is None:
            raise SemverRefusal("semver-input-invalid")
        descriptor = os.open(str(path), os.O_RDONLY | nofollow | nonblock
                             | getattr(os, "O_CLOEXEC", 0))
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_dev != before.st_dev or opened.st_ino != before.st_ino
                or opened.st_size != before.st_size
                or opened.st_size > maximum):
            raise SemverRefusal("semver-input-invalid")
        result = bytearray()
        deadline = time.monotonic() + 5.0
        while True:
            if time.monotonic() >= deadline:
                raise SemverRefusal("semver-input-invalid")
            chunk = os.read(descriptor, min(16_384, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            if len(result) > maximum:
                raise SemverRefusal("semver-input-invalid")
        after = os.fstat(descriptor)
        try:
            after_path = path.lstat()
        except OSError:
            raise SemverRefusal("semver-input-invalid") from None
        if (len(result) != opened.st_size or not stat.S_ISREG(after_path.st_mode)
                or after_path.st_nlink != 1 or after.st_dev != opened.st_dev
                or after.st_ino != opened.st_ino or after.st_size != opened.st_size
                or after.st_nlink != 1 or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
                or after_path.st_dev != opened.st_dev or after_path.st_ino != opened.st_ino):
            raise SemverRefusal("semver-input-invalid")
        return bytes(result)
    except SemverRefusal:
        raise
    except OSError:
        raise SemverRefusal("semver-input-invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _pins():
    raw = _read_fixed_file(PIN_FILE, MAX_PIN_BYTES)
    if _sha(raw) != PIN_FILE_SHA256:
        raise SemverRefusal("semver-pins-invalid")
    try:
        pins = json.loads(raw.decode("ascii", "strict"))
    except (UnicodeError, ValueError, RecursionError):
        raise SemverRefusal("semver-pins-invalid") from None
    if type(pins) is not dict or pins.get("schema") != "keeldock.pr1-semver-stage-pins.v1":
        raise SemverRefusal("semver-pins-invalid")
    if (pins.get("tool", {}).get("version") != SEMVER_VERSION
            or pins.get("tool", {}).get("asset_sha256") != SEMVER_ASSET_SHA256
            or pins.get("tool", {}).get("release_commit") != SEMVER_RELEASE_COMMIT
            or pins.get("baseline", {}).get("source_revision") != BASELINE_REVISION
            or pins.get("baseline", {}).get("runtime_root") != BASELINE_ROOT
            or pins.get("baseline", {}).get("runtime_file_count") != BASELINE_FILE_COUNT
            or pins.get("baseline", {}).get("runtime_bytes") != BASELINE_TOTAL_BYTES
            or pins.get("baseline", {}).get("runtime_map_sha256") != BASELINE_MAP_SHA256
            or pins.get("baseline", {}).get("runtime_manifest_sha256") != BASELINE_RUNTIME_MANIFEST_SHA256
            or pins.get("baseline", {}).get("runtime_lock_sha256") != BASELINE_RUNTIME_LOCK_SHA256
            or pins.get("candidate", {}).get("runtime_semantic_map_sha256_excluding_cargo_lock")
            != CANDIDATE_SOURCE_MAP_SHA256
            or pins.get("candidate", {}).get("source_revision") != SOURCE_REVISION
            or pins.get("candidate", {}).get("source_tree") != SOURCE_TREE
            or pins.get("candidate", {}).get("full_git_tree_map_sha256_before_transfer")
            != FULL_GIT_TREE_MAP_SHA256
            or pins.get("candidate", {}).get("full_git_file_count_before_transfer")
            != FULL_GIT_FILE_COUNT
            or pins.get("candidate", {}).get("selected_transfer_map_sha256_before_offline_lock_generation")
            != SELECTED_TRANSFER_MAP_SHA256
            or pins.get("candidate", {}).get("selected_transfer_file_count_before_offline_lock_generation")
            != SELECTED_TRANSFER_FILE_COUNT
            or pins.get("candidate", {}).get("selected_transfer_bytes_before_offline_lock_generation")
            != SELECTED_TRANSFER_BYTES
            or pins.get("candidate", {}).get("selected_manifest_sha256") != CANDIDATE_MANIFEST_SHA256
            or pins.get("candidate", {}).get("excluded_paths") != list(EXCLUDED_SOURCE_PATHS)
            or pins.get("offline_cache") != OFFLINE_CACHE_PIN):
        raise SemverRefusal("semver-pins-invalid")
    return pins


def offline_cache_source_maps():
    """Return independently pinned source-map identities for the cache preflight."""
    pins = _pins()
    try:
        baseline = pins["baseline"]["runtime_map_sha256"]
        candidate_runtime = pins["candidate"]["runtime_semantic_map_sha256_excluding_cargo_lock"]
        candidate_full = pins["candidate"]["selected_transfer_map_sha256_before_offline_lock_generation"]
    except (KeyError, TypeError):
        raise SemverRefusal("semver-pins-invalid") from None
    if any(type(value) is not str or re.fullmatch(r"[a-f0-9]{64}", value) is None
           for value in (baseline, candidate_runtime, candidate_full)):
        raise SemverRefusal("semver-pins-invalid")
    return {
        "baseline_source_map_sha256": baseline,
        "candidate_source_map_sha256": candidate_runtime,
        "candidate_full_source_map_sha256": candidate_full,
    }


def offline_cache_source_sets():
    """Return the exact candidate/baseline identities carried by Rust manifest v2."""
    _pins()
    return {
        "domain": SOURCE_SET_DOMAIN,
        "candidate": {
            "source_revision": SOURCE_REVISION,
            "tree_oid": SOURCE_TREE,
            "full_map_sha256": FULL_GIT_TREE_MAP_SHA256,
            "selected_map_sha256": SELECTED_TRANSFER_MAP_SHA256,
            "selected_file_count": SELECTED_TRANSFER_FILE_COUNT,
            "selected_bytes": SELECTED_TRANSFER_BYTES,
            "selected_manifest_sha256": dict(CANDIDATE_MANIFEST_SHA256),
        },
        "baseline_runtime": {
            "source_revision": BASELINE_REVISION,
            "map_sha256": BASELINE_MAP_SHA256,
            "file_count": BASELINE_FILE_COUNT,
            "bytes": BASELINE_TOTAL_BYTES,
            "namespace": BASELINE_NAMESPACE,
            "runtime_manifest_sha256": BASELINE_RUNTIME_MANIFEST_SHA256,
            "runtime_lock_sha256": BASELINE_RUNTIME_LOCK_SHA256,
        },
        "exclusions": [dict(row) for row in SOURCE_EXCLUSIONS],
    }


def offline_cache_input_identity(control_sha, projection_sha256, semver_tool_binary_sha256):
    """Build the trusted cache binding from exact v2 source pins and observed tool bytes."""
    import semver_offline_cache

    return semver_offline_cache._validate_input_identity({
        "source_commit": SOURCE_REVISION,
        "control_sha": control_sha,
        "manifest_projection_sha256": projection_sha256,
        "baseline_source_map_sha256": BASELINE_MAP_SHA256,
        "candidate_source_map_sha256": CANDIDATE_SOURCE_MAP_SHA256,
        "candidate_full_source_map_sha256": SELECTED_TRANSFER_MAP_SHA256,
        "candidate_root_manifest_sha256": CANDIDATE_MANIFEST_SHA256["Cargo.toml"],
        "candidate_fuzz_manifest_sha256": CANDIDATE_MANIFEST_SHA256["fuzz/Cargo.toml"],
        "baseline_runtime_manifest_sha256": BASELINE_RUNTIME_MANIFEST_SHA256,
        "candidate_runtime_manifest_sha256": CANDIDATE_RUNTIME_MANIFEST_SHA256,
        "baseline_runtime_version": BASELINE_VERSION,
        "candidate_runtime_version": CANDIDATE_VERSION,
        "semver_tool_binary_sha256": semver_tool_binary_sha256,
    })


def _hash_file(path):
    descriptor = None
    try:
        path = Path(path)
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > MAX_SOURCE_FILE_BYTES):
            raise SemverRefusal("semver-source-invalid")
        nofollow = getattr(os, "O_NOFOLLOW", None)
        nonblock = getattr(os, "O_NONBLOCK", None)
        if nofollow is None or nonblock is None:
            raise SemverRefusal("semver-source-invalid")
        descriptor = os.open(str(path), os.O_RDONLY | nofollow | nonblock
                             | getattr(os, "O_CLOEXEC", 0))
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino or opened.st_size != before.st_size
                or opened.st_size > MAX_SOURCE_FILE_BYTES):
            raise SemverRefusal("semver-source-invalid")
        digest = hashlib.sha256()
        size = 0
        deadline = time.monotonic() + 10.0
        while True:
            if time.monotonic() >= deadline:
                raise SemverRefusal("semver-source-invalid")
            chunk = os.read(descriptor, min(65_536, MAX_SOURCE_FILE_BYTES + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_SOURCE_FILE_BYTES:
                raise SemverRefusal("semver-source-invalid")
            digest.update(chunk)
        after = os.fstat(descriptor)
        try:
            after_path = path.lstat()
        except OSError:
            raise SemverRefusal("semver-source-invalid") from None
        if (size != opened.st_size or not stat.S_ISREG(after_path.st_mode)
                or after_path.st_nlink != 1 or after.st_dev != opened.st_dev
                or after.st_ino != opened.st_ino or after.st_size != opened.st_size
                or after.st_nlink != 1 or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
                or after_path.st_dev != opened.st_dev or after_path.st_ino != opened.st_ino):
            raise SemverRefusal("semver-source-invalid")
        return digest.hexdigest(), size
    except SemverRefusal:
        raise
    except OSError:
        raise SemverRefusal("semver-source-invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validated_directory_chain(root):
    root = Path(os.path.abspath(root))
    boundary = next((item for item in (Path("/workspace"), Path("/prepared"))
                     if root == item or item in root.parents), None)
    chain = [root]
    if boundary is not None:
        chain = [boundary]
        for part in root.relative_to(boundary).parts:
            chain.append(chain[-1] / part)
    for component in chain:
        try:
            metadata = component.lstat()
        except OSError:
            raise SemverRefusal("semver-source-invalid") from None
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise SemverRefusal("semver-source-invalid")
    return root


def _tree_map(root, *, omit_runtime_lock=False):
    root = _validated_directory_chain(root)
    result = {}
    total_bytes = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        here = Path(current)
        for name in list(directories):
            child = here / name
            try:
                metadata = child.lstat()
            except OSError:
                raise SemverRefusal("semver-source-invalid") from None
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise SemverRefusal("semver-source-invalid")
        for name in filenames:
            path = here / name
            relative = path.relative_to(root).as_posix()
            if omit_runtime_lock and relative == "Cargo.lock":
                try:
                    metadata = path.lstat()
                except OSError:
                    raise SemverRefusal("semver-lock-missing") from None
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                        or metadata.st_size > MAX_SOURCE_FILE_BYTES):
                    raise SemverRefusal("semver-lock-invalid")
                continue
            digest, size = _hash_file(path)
            total_bytes += size
            if total_bytes > MAX_SOURCE_TREE_BYTES:
                raise SemverRefusal("semver-source-size")
            key = "runtime/" + relative if omit_runtime_lock else relative
            result[key] = digest
    ordered = dict(sorted(result.items()))
    encoded = (json.dumps(ordered, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    return ordered, _sha(encoded)


def _workspace_version(root):
    manifest = Path(root) / "Cargo.toml"
    raw = _read_fixed_file(manifest, MAX_SOURCE_FILE_BYTES)
    try:
        document = tomllib.loads(raw.decode("utf-8", "strict"))
        version = document["workspace"]["package"]["version"]
    except (UnicodeError, ValueError, KeyError, TypeError):
        raise SemverRefusal("semver-version-invalid") from None
    if type(version) is not str:
        raise SemverRefusal("semver-version-invalid")
    return _sha(raw), version


def verify_source_maps(source_root=SOURCE_ROOT, baseline_root=BASELINE_ROOT):
    """Verify the frozen baseline and candidate semantic source bytes before launch.

    The candidate map deliberately omits only runtime/Cargo.lock: c706 owns its
    offline regeneration. The full candidate input map and generated lock proofs
    remain separate generated input requirements.
    """
    pins = _pins()
    source_root = Path(source_root)
    baseline_root = Path(baseline_root)
    baseline_map, baseline_digest = _tree_map(baseline_root)
    candidate_map, candidate_digest = _tree_map(source_root, omit_runtime_lock=True)
    baseline_manifest_digest, baseline_version = _workspace_version(baseline_root)
    candidate_manifest_digest, candidate_version = _workspace_version(source_root)
    expected_baseline = pins["baseline"]
    expected_candidate = pins["candidate"]
    if (len(baseline_map) != expected_baseline["runtime_file_count"]
            or baseline_digest != expected_baseline["runtime_map_sha256"]
            or baseline_manifest_digest != expected_baseline["runtime_manifest_sha256"]
            or baseline_version != expected_baseline["version"]
            or len(candidate_map) != expected_candidate["runtime_semantic_file_count_excluding_cargo_lock"]
            or candidate_digest != expected_candidate["runtime_semantic_map_sha256_excluding_cargo_lock"]
            or candidate_manifest_digest != expected_candidate["runtime_manifest_sha256"]
            or candidate_version != expected_candidate["version"]):
        raise SemverRefusal("semver-source-binding")
    return True


def verify_tool(tools_root=TOOLS_ROOT):
    try:
        if not Path(tools_root).is_dir() or Path(tools_root).is_symlink():
            raise SemverRefusal("semver-tool-binding")
        tool = Path(tools_root) / SEMVER_TOOL
        receipt = Path(tools_root) / "semver-tool-receipt.json"
        for path in (tool, receipt):
            metadata = path.lstat()
            if (not stat.S_ISREG(metadata.st_mode) or path.is_symlink()
                    or metadata.st_nlink != 1 or metadata.st_mode & 0o222):
                raise SemverRefusal("semver-tool-binding")
        if not os.access(tool, os.X_OK) or not 0 < tool.stat().st_size <= 128 * 1024 * 1024:
            raise SemverRefusal("semver-tool-binding")
        raw = _read_fixed_file(receipt, 4096)
        value = json.loads(raw.decode("ascii", "strict"))
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True).encode("ascii") + b"\n"
        binary_sha, binary_size = _hash_file(tool)
        expected = {
            "schema": "keeldock.prepared-semver-tool.v1",
            "tool": SEMVER_TOOL,
            "version": SEMVER_VERSION,
            "release_tag": "v" + SEMVER_VERSION,
            "release_commit": SEMVER_RELEASE_COMMIT,
            "asset_sha256": SEMVER_ASSET_SHA256,
            "asset_name": SEMVER_TOOL + "-x86_64-unknown-linux-gnu.tar.gz",
            "target": TARGET_TRIPLE,
            "version_output": "cargo " + SEMVER_VERSION,
            "binary_sha256": binary_sha,
            "binary_size_bytes": binary_size,
            "verification": "published release-asset digest matched; executable version matched pinned output",
        }
        if type(value) is not dict or raw != canonical or value != expected:
            raise SemverRefusal("semver-tool-binding")
    except SemverRefusal:
        raise
    except Exception:
        raise SemverRefusal("semver-tool-binding") from None
    return tool


def fixed_argv(tools_root=TOOLS_ROOT, baseline_root=BASELINE_ROOT):
    if baseline_root not in (BASELINE_ROOT, LEGACY_BASELINE_ROOT):
        raise SemverRefusal("semver-baseline-path-invalid")
    return [
        str(Path(tools_root) / SEMVER_TOOL),
        "check-release",
        "--manifest-path", SOURCE_ROOT + "/runtime/Cargo.toml",
        "--baseline-root", baseline_root,
        "--workspace", "--all-features", "--target", TARGET_TRIPLE,
    ]


def verify_run_inputs(source_root=SOURCE_ROOT, baseline_root=BASELINE_ROOT, tools_root=TOOLS_ROOT):
    verify_source_maps(source_root, baseline_root)
    verify_tool(tools_root)
    return True


def records_for_exit(exit_code):
    """Return only bounded identity/status rows; never include the tool's text output."""
    if type(exit_code) is not int:
        outcome = "execution"
    elif exit_code == 0:
        outcome = "pass"
    elif exit_code == 100:
        outcome = "findings"
    else:
        outcome = "execution"
    passed = 1 if outcome == "pass" else 0
    records = [{
        "kind": "coverage", "stage": STAGE, "suite": SUITE,
        "total": 1, "passed": passed, "failed": 1 - passed, "ignored": 0,
    }]
    if outcome != "pass":
        code = "DEVLANE_SEMVER_FINDINGS" if outcome == "findings" else "DEVLANE_SEMVER_EXECUTION"
        records.append({"kind": "control", "stage": STAGE, "status": "fail", "code": code})
    return records
