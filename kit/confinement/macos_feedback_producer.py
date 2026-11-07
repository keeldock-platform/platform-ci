import base64
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

try:
    from . import feedback_request
except ImportError:
    _request_path = Path(__file__).resolve(strict=True).parent / "feedback_request.py"
    _request_spec = importlib.util.spec_from_file_location("feedback_request", str(_request_path))
    if _request_spec is None or _request_spec.loader is None:
        raise ImportError("feedback request unavailable")
    feedback_request = importlib.util.module_from_spec(_request_spec)
    sys.modules["feedback_request"] = feedback_request
    try:
        _request_spec.loader.exec_module(feedback_request)
    except BaseException:
        raise ImportError("feedback request unavailable") from None


SCHEMA_VERSION = 1
REQUEST_ENV = "KD_FEEDBACK_REQUEST_B64"
RECIPIENT_ENV = "KD_FEEDBACK_RECIPIENT_SPKI_B64"
NODE_ENV = "KD_NODE_EXECUTABLE"
NODE_VERSION = "24.22.1"
OUTPUT_DIRECTORY = "core-feedback"
FEEDBACK_TEMP_DIRECTORY = "feedback-tmp"
OUTPUT_OWNER_UID = 0
OUTPUT_OWNER_GID = 0
MAX_REQUEST_BYTES = 2048
MAX_KEY_BYTES = 4096
MAX_PACKAGE_JSON_BYTES = 256 * 1024
MAX_FEEDBACK_PAYLOAD_BYTES = 4 * 1024 * 1024 - 64 * 1024
MAX_RUST_FILE_BYTES = 1024 * 1024
MAX_RUST_PATHS = 512
MAX_PATCH_BYTES = 4 * 1024 * 1024 - 64 * 1024
MAX_NODE_INPUT_BYTES = 6 * 1024 * 1024
MAX_CIPHERTEXT_BYTES = 4 * 1024 * 1024
SHA1_RE = re.compile(r"[a-f0-9]{40}\Z")
SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
PACKAGE_ROOTS = (
    Path("crates/host/api"), Path("crates/host/mock"), Path("crates/host/conformance"),
    Path("crates/kernel/i18n"),
)
RUNTIME_PACKAGE_ROOTS = (
    Path("runtime/crates/services/sync-publication"),
    *(Path("runtime/crates/test-fixtures") / name for name in (
        "host-router", "fixture-data", "tool-a", "tool-b",
        "tool-bad-no-handler", "tool-bad-no-manifest",
    )),
    Path("runtime/crates/host/registry"), Path("runtime/crates/host/core"),
    Path("runtime/crates/host/settings-schema"), Path("runtime/crates/services/palette"),
    Path("runtime/crates/services/notifications"),
)
RUNTIME_BATCH_SEVEN_CRATE_ROOTS = (
    Path("runtime/crates/host/registry"), Path("runtime/crates/host/core"),
    Path("runtime/crates/host/settings-schema"), Path("runtime/crates/services/palette"),
    Path("runtime/crates/services/notifications"),
)
RUNTIME_WAVE_70_CRATE_ROOTS = (
    Path("runtime/crates/host/entitlements"), Path("runtime/crates/services/log"),
    Path("runtime/crates/services/fs"), Path("runtime/crates/services/store"),
    Path("runtime/crates/services/vault"),
)
RUNTIME_WAVE_70_APP_ROOTS = (
    Path("runtime/apps/test-shell-desktop/src-tauri"),
    Path("runtime/apps/test-shell-mobile/src-tauri"),
)
RUNTIME_BATCH_SEVEN_DOC_FILES = frozenset(("README.md", "CONTRACT.md", "CHANGELOG.md"))
RUNTIME_EXISTING_SERVICE_DOC_ROOT = Path("runtime/crates/services/sync-publication")
RUNTIME_EXISTING_SERVICE_DOC_FILES = frozenset(("README.md", "CONTRACT.md", "CHANGELOG.md"))
OPTIONAL_RUNTIME_PACKAGE_ROOTS = (Path("runtime/crates/services/sync-format"),)
RUNTIME_MEMBER_LIST_RE = re.compile(r"(?m)^members\s*=\s*\[(.*?)\]\s*$", re.DOTALL)
RUNTIME_MEMBER_ITEM_RE = re.compile(r'\s*"([A-Za-z0-9][A-Za-z0-9/_-]{0,127})"\s*,?')
CARGO_WORKSPACE_ROOTS = {"contract": PACKAGE_ROOTS, "runtime": RUNTIME_PACKAGE_ROOTS}
FOUNDATION_FUZZ_RUST_PATHS = (
    "fuzz/src/main.rs",
    "fuzz/fuzz_targets/identifiers.rs",
    "fuzz/fuzz_targets/tool_error_codes.rs",
    "fuzz/fuzz_targets/versions.rs",
)
FOUNDATION_FUZZ_TARGETS = frozenset(
    Path(path).stem for path in FOUNDATION_FUZZ_RUST_PATHS[1:]
)
FOUNDATION_FUZZ_TARGET_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\.rs\Z")
MAX_FOUNDATION_FUZZ_TARGETS = 16
FOUNDATION_FUZZ_MANIFESTS = ("fuzz/Cargo.toml", "fuzz/Cargo.lock")
RUST_ROOT_FILES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rustfmt.toml", "clippy.toml")
DIAGNOSTIC_BASE_GATES = (
    "format", "clippy", "workspace_tests", "api_tests", "api_feature_clippy", "api_feature_tests",
    "mock_tests", "conformance_tests",
)
DIAGNOSTIC_PARSER_GATES = ("parser_format", "parser_clippy", "parser_replay")
DIAGNOSTIC_NODE_GATES = ("node_dependency_prepare", "typescript_typecheck", "typescript_tests")
DIAGNOSTIC_GATE_SELECTIONS = tuple(
    selection + DIAGNOSTIC_NODE_GATES
    for selection in (DIAGNOSTIC_BASE_GATES, DIAGNOSTIC_BASE_GATES + DIAGNOSTIC_PARSER_GATES)
)
UNSAFE_DIAGNOSTIC_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
DISPLAY_UNSAFE_DIAGNOSTIC_RE = re.compile(r"[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
DIAGNOSTIC_MAX_LINES = 8192
DIAGNOSTIC_MAX_LINE_UNITS = 8192
DIAGNOSTIC_STREAM_MAX_LINES = 4000
PROFILE_BY_KIND = feedback_request.PROFILE_BY_KIND
PROFILE_BY_CONCERN = feedback_request.PROFILES


ENCRYPT_DETAILS = frozenset((
    "payload_missing", "tool_path", "input_size", "spawn", "node_exit", "output_size",
    "output_shape", "output_directory", "output_write", "output_member",
    "reviewed_paths_invalid", "encryptor_unavailable",
))
NODE_REFUSAL_CODES = frozenset((
    "credential_like_content", "envelope_rejected", "exception_expired",
    "invalid_context", "invalid_expectation", "invalid_input",
    "invalid_payload", "invalid_payload_bom", "invalid_payload_c0", "invalid_payload_c1",
    "invalid_payload_cr", "invalid_payload_nul", "invalid_payload_utf8",
    "invalid_recipient", "invalid_rust_patch", "limit_exceeded",
    "payload_too_large", "unreviewed_rust_path", "unsupported_kind", "input_too_large",
    "encryption_failed",
))
NODE_DETAILS = frozenset("node_" + code for code in NODE_REFUSAL_CODES)
NODE_STDERR_RE = re.compile(r"KD-FEEDBACK-ENCRYPTION-REFUSAL(?: ([a-z0-9_]{1,40}))?\n\Z")


class FeedbackRefusal(Exception):
    def __init__(self, reason="feedback_invalid", detail=None):
        self.reason = reason if reason in {
            "feedback_invalid", "request_invalid", "recipient_invalid", "manifest_invalid",
            "tool_unavailable", "command_failed", "capture_invalid", "payload_invalid",
            "output_unavailable", "cleanup_incomplete",
        } else "feedback_invalid"
        self.detail = detail if type(detail) is str and (detail in ENCRYPT_DETAILS or detail in NODE_DETAILS) else None
        super().__init__(self.reason)


def _refuse(reason="feedback_invalid", detail=None):
    raise FeedbackRefusal(reason, detail)


def _node_detail(stderr):
    try:
        match = NODE_STDERR_RE.fullmatch(bytes(stderr[:256]).decode("ascii", "strict"))
    except BaseException:
        return "node_exit"
    if match is not None and match.group(1) in NODE_REFUSAL_CODES:
        return "node_" + match.group(1)
    return "node_exit"


def _valid_decimal(value):
    return type(value) is str and DECIMAL_RE.fullmatch(value) is not None


def _decode_b64(value, maximum):
    if type(value) is not str or not value or len(value) > ((maximum + 2) // 3) * 4:
        _refuse("request_invalid")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except BaseException:
        _refuse("request_invalid")
    if not decoded or len(decoded) > maximum or base64.b64encode(decoded).decode("ascii") != value:
        _refuse("request_invalid")
    return decoded


def _strict_json(raw, maximum):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        _refuse("manifest_invalid")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                          parse_constant=lambda unused: (_ for _ in ()).throw(ValueError()))
    except BaseException:
        _refuse("manifest_invalid")


def _read_file(path, *, maximum, owner=0):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _refuse("manifest_invalid")
    descriptor = None
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_nlink != 1
                or before.st_size <= 0 or before.st_size > maximum
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | nofollow)
        opened = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != owner
                or opened.st_nlink != 1 or opened.st_size > maximum):
            raise ValueError
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(8192, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (total != opened.st_size or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or after.st_uid != owner or after.st_nlink != 1
                or after.st_size > maximum or after.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise ValueError
        return b"".join(chunks)
    except BaseException:
        _refuse("manifest_invalid")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _validated_fuzz_rust_paths(source):
    directory = source / "fuzz/fuzz_targets"
    try:
        directory_info = directory.lstat()
        if (not stat.S_ISDIR(directory_info.st_mode) or stat.S_ISLNK(directory_info.st_mode)
                or directory_info.st_uid != 0
                or directory_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            _refuse("manifest_invalid")
        with os.scandir(directory) as iterator:
            names = sorted(entry.name for entry in iterator)
    except OSError:
        _refuse("manifest_invalid")
    fixed_targets = {Path(path).name for path in FOUNDATION_FUZZ_RUST_PATHS[1:]}
    if (not 1 <= len(names) <= MAX_FOUNDATION_FUZZ_TARGETS
            or not fixed_targets.issubset(set(names))
            or not FOUNDATION_FUZZ_TARGETS.issubset({name[:-3] for name in names})
            or any(len(name[:-3]) > 64 or FOUNDATION_FUZZ_TARGET_RE.fullmatch(name) is None
                   for name in names)):
        _refuse("manifest_invalid")
    paths = []
    for relative in FOUNDATION_FUZZ_RUST_PATHS[:1] + tuple(
            "fuzz/fuzz_targets/" + name for name in names):
        target = source / relative
        try:
            info = target.lstat()
        except OSError:
            _refuse("manifest_invalid")
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
            _refuse("manifest_invalid")
        paths.append(relative)
    return tuple(paths)


def _runtime_batch_seven_file_allowed(relative):
    if relative in ("Cargo.toml", "README.md", "CONTRACT.md", "CHANGELOG.md"):
        return True
    parts = relative.split("/")
    if (len(parts) >= 2 and parts[0] == "src" and relative.endswith(".rs")
            and parts[-1] != "build.rs"):
        return True
    return (
        len(parts) == 2 and parts[0] == "tests" and relative.endswith(".rs")
        and parts[-1] != "build.rs"
    )


def _runtime_batch_seven_directory_allowed(relative):
    return relative == "src" or relative.startswith("src/") or relative == "tests"


def _validate_runtime_batch_seven_trees(source):
    crates_root = source / "runtime/crates"
    try:
        root_info = crates_root.lstat()
    except OSError:
        _refuse("manifest_invalid")
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        _refuse("manifest_invalid")
    prefixes = tuple(root.as_posix() for root in RUNTIME_BATCH_SEVEN_CRATE_ROOTS)
    required = {prefix: {"Cargo.toml", "README.md", "CONTRACT.md", "CHANGELOG.md", "src/lib.rs"}
                for prefix in prefixes}
    found = {prefix: set() for prefix in prefixes}
    present = set()
    stack = [(crates_root, "runtime/crates")]
    count = 0
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    doc_names = {"README.md", "CONTRACT.md", "CHANGELOG.md"}
    while stack:
        directory, parent_relative = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError:
            _refuse("manifest_invalid")
        for entry in entries:
            count += 1
            if count > MAX_RUST_PATHS * 128:
                _refuse("manifest_invalid")
            relative = parent_relative + "/" + entry.name
            target = Path(entry.path)
            try:
                info = target.lstat()
            except OSError:
                _refuse("manifest_invalid")
            prefix = next((item for item in prefixes
                           if relative == item or relative.startswith(item + "/")), None)
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & reparse):
                if prefix is not None or entry.name in doc_names:
                    _refuse("manifest_invalid")
                continue
            if entry.name in doc_names:
                previous_service_path = (
                    relative in {
                        RUNTIME_EXISTING_SERVICE_DOC_ROOT.as_posix() + "/" + name
                        for name in RUNTIME_EXISTING_SERVICE_DOC_FILES
                    }
                )
                batch_document_path = (
                    prefix is not None
                    and relative[len(prefix) + 1:] in RUNTIME_BATCH_SEVEN_DOC_FILES
                )
                if (not previous_service_path and not batch_document_path
                        or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != 0
                        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
                    _refuse("manifest_invalid")
            if stat.S_ISDIR(info.st_mode):
                if relative in prefixes:
                    present.add(relative)
                if prefix is not None and relative != prefix:
                    within = relative[len(prefix) + 1:]
                    if not _runtime_batch_seven_directory_allowed(within):
                        _refuse("manifest_invalid")
                if (info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                    if prefix is not None:
                        _refuse("manifest_invalid")
                stack.append((target, relative))
                continue
            if prefix is not None:
                within = relative[len(prefix) + 1:]
                if (not _runtime_batch_seven_file_allowed(within)
                        or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != 0
                        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
                    _refuse("manifest_invalid")
                found[prefix].add(within)
    for prefix in present:
        if not required[prefix].issubset(found[prefix]):
            _refuse("manifest_invalid")


def _runtime_wave70_directory_allowed(relative, root_name, inventory_paths):
    if _runtime_batch_seven_directory_allowed(relative):
        return True
    absolute = root_name + "/" + relative
    return any(path.startswith(absolute + "/") for path in inventory_paths)


def _validate_runtime_wave70_trees(source, inventory_paths=frozenset()):
    crates_root = source / "runtime/crates"
    try:
        root_info = crates_root.lstat()
    except OSError:
        _refuse("manifest_invalid")
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        _refuse("manifest_invalid")
    prefixes = tuple(root.as_posix() for root in RUNTIME_WAVE_70_CRATE_ROOTS)
    required = {prefix: {"Cargo.toml", "README.md", "CONTRACT.md", "CHANGELOG.md", "src/lib.rs"}
                for prefix in prefixes}
    found = {prefix: set() for prefix in prefixes}
    stack = [(crates_root, "runtime/crates")]
    count = 0
    while stack:
        directory, parent_relative = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError:
            _refuse("manifest_invalid")
        for entry in entries:
            count += 1
            if count > MAX_RUST_PATHS * 128:
                _refuse("manifest_invalid")
            relative = parent_relative + "/" + entry.name
            target = Path(entry.path)
            try:
                info = target.lstat()
            except OSError:
                _refuse("manifest_invalid")
            prefix = next((item for item in prefixes
                           if relative == item or relative.startswith(item + "/")), None)
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                if prefix is not None:
                    _refuse("manifest_invalid")
                continue
            if stat.S_ISDIR(info.st_mode):
                if prefix is not None and relative != prefix:
                    within = relative[len(prefix) + 1:]
                    if not _runtime_wave70_directory_allowed(within, prefix, inventory_paths):
                        _refuse("manifest_invalid")
                stack.append((target, relative))
                continue
            if prefix is not None:
                within = relative[len(prefix) + 1:]
                if (not _runtime_batch_seven_file_allowed(within)
                        and relative not in inventory_paths
                        or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                    _refuse("manifest_invalid")
                found[prefix].add(within)
    for prefix, required_files in required.items():
        if not required_files.issubset(found[prefix]):
            _refuse("manifest_invalid")


def _reviewed_rust_paths(source, *, include_fuzz=False, roots=None, inventory_paths=frozenset()):
    if type(include_fuzz) is not bool:
        _refuse("manifest_invalid")
    selected_roots = PACKAGE_ROOTS if roots is None else roots
    if all(root in selected_roots for root in RUNTIME_BATCH_SEVEN_CRATE_ROOTS):
        _validate_runtime_batch_seven_trees(source)
    if all(root in selected_roots for root in RUNTIME_WAVE_70_CRATE_ROOTS):
        _validate_runtime_wave70_trees(source, inventory_paths)
    paths = []
    for package_root in selected_roots:
        source_directory = source / package_root / "src"
        try:
            source_info = source_directory.lstat()
        except OSError:
            _refuse("manifest_invalid")
        if (not stat.S_ISDIR(source_info.st_mode) or stat.S_ISLNK(source_info.st_mode)
                or source_info.st_uid != 0 or source_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            _refuse("manifest_invalid")
        for folder in ("src", "tests"):
            directory = source / package_root / folder
            try:
                with os.scandir(directory) as iterator:
                    entries = sorted(iterator, key=lambda item: item.name)
            except FileNotFoundError:
                continue
            except OSError:
                _refuse("manifest_invalid")
            stack = [(directory, entries)]
            while stack:
                current, values = stack.pop()
                for entry in values:
                    target = Path(entry.path)
                    try:
                        info = target.lstat()
                    except OSError:
                        _refuse("manifest_invalid")
                    if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0
                            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
                        _refuse("manifest_invalid")
                    if stat.S_ISDIR(info.st_mode):
                        try:
                            with os.scandir(target) as iterator:
                                child_entries = sorted(iterator, key=lambda item: item.name)
                        except OSError:
                            _refuse("manifest_invalid")
                        stack.append((target, child_entries))
                    elif target.suffix == ".rs" and target.name != "build.rs":
                        relative = target.relative_to(source).as_posix()
                        if (not stat.S_ISREG(info.st_mode) or len(relative) > 256
                                or relative in paths or info.st_nlink != 1):
                            _refuse("manifest_invalid")
                        paths.append(relative)
                        if len(paths) > MAX_RUST_PATHS:
                            _refuse("manifest_invalid")
                    elif not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
                        _refuse("manifest_invalid")
    if include_fuzz:
        fuzz_paths = _validated_fuzz_rust_paths(source)
        if set(paths) & set(fuzz_paths):
            _refuse("manifest_invalid")
        paths.extend(fuzz_paths)
    if not paths or len(paths) > MAX_RUST_PATHS:
        _refuse("manifest_invalid")
    return tuple(sorted(paths))


def _runtime_package_roots(source, selector):
    if selector == "contract":
        payload = _read_file(source / "Cargo.toml", maximum=MAX_PACKAGE_JSON_BYTES)
        try:
            text = payload.decode("utf-8", "strict")
        except UnicodeError:
            _refuse("manifest_invalid")
        matches = tuple(RUNTIME_MEMBER_LIST_RE.finditer(text))
        if len(matches) != 1:
            _refuse("manifest_invalid")
        roots = []
        body = matches[0].group(1)
        position = 0
        while position < len(body):
            match = RUNTIME_MEMBER_ITEM_RE.match(body, position)
            if match is None:
                if body[position:].strip():
                    _refuse("manifest_invalid")
                break
            roots.append(Path(match.group(1)))
            position = match.end()
        from cargo_lock_bootstrap import (
            CONTRACT_BASE_MEMBERS, CONTRACT_WAVE_70A_MEMBERS, CONTRACT_WAVE_70B_MEMBERS,
        )
        selected = frozenset(path.as_posix() for path in roots)
        if selected not in (CONTRACT_BASE_MEMBERS, CONTRACT_WAVE_70A_MEMBERS,
                            CONTRACT_WAVE_70B_MEMBERS):
            _refuse("manifest_invalid")
        if len(set(roots)) != len(roots):
            _refuse("manifest_invalid")
        return tuple(roots)
    if selector != "runtime":
        _refuse("manifest_invalid")
    root_path = source / "runtime" / "Cargo.toml"
    payload = _read_file(root_path, maximum=MAX_PACKAGE_JSON_BYTES)
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeError:
        _refuse("manifest_invalid")
    matches = tuple(RUNTIME_MEMBER_LIST_RE.finditer(text))
    if len(matches) != 1:
        _refuse("manifest_invalid")
    body = matches[0].group(1)
    roots = []
    position = 0
    while position < len(body):
        match = RUNTIME_MEMBER_ITEM_RE.match(body, position)
        if match is None:
            if body[position:].strip():
                _refuse("manifest_invalid")
            break
        roots.append(Path("runtime") / match.group(1))
        position = match.end()
    base = frozenset(RUNTIME_PACKAGE_ROOTS)
    wave70a = base | frozenset(RUNTIME_WAVE_70_APP_ROOTS)
    wave70b = wave70a | frozenset(RUNTIME_WAVE_70_CRATE_ROOTS)
    optional = frozenset(OPTIONAL_RUNTIME_PACKAGE_ROOTS)
    root_set = frozenset(roots)
    if (len(root_set) != len(roots)
            or root_set not in (base, base | optional, wave70a, wave70a | optional,
                                wave70b, wave70b | optional)):
        _refuse("manifest_invalid")
    return tuple(roots)


def _reviewed_api_source_paths(source):
    root = source / "crates" / "host" / "api" / "src"
    try:
        root_info = root.lstat()
    except OSError:
        _refuse("manifest_invalid")
    if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != 0 or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        _refuse("manifest_invalid")
    paths = []
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError:
            _refuse("manifest_invalid")
        for entry in entries:
            path = Path(entry.path)
            try:
                info = path.lstat()
            except OSError:
                _refuse("manifest_invalid")
            if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0
                    or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
                _refuse("manifest_invalid")
            if stat.S_ISDIR(info.st_mode):
                stack.append(path)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    _refuse("manifest_invalid")
                relative = path.relative_to(source).as_posix()
                if len(relative) > 256 or relative in paths:
                    _refuse("manifest_invalid")
                paths.append(relative)
                if len(paths) > MAX_RUST_PATHS:
                    _refuse("manifest_invalid")
            else:
                _refuse("manifest_invalid")
    if not paths or "crates/host/api/src/lib.rs" not in paths:
        _refuse("manifest_invalid")
    return tuple(sorted(paths))


def _authenticated_candidate_files(source, source_sha):
    if type(source_sha) is not str or re.fullmatch(r"[a-f0-9]{40}", source_sha) is None:
        _refuse("manifest_invalid")
    environment = {
        "PATH": "/usr/bin:/bin", "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_ATTR_NOSYSTEM": "1",
    }
    prefix = ("/usr/bin/git", "-C", str(source))
    try:
        head = subprocess.run(
            prefix + ("rev-parse", "--verify", "HEAD"), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
            timeout=10, check=False,
        )
        if (head.returncode != 0 or head.stderr
                or head.stdout.decode("ascii", "strict").strip() != source_sha):
            _refuse("manifest_invalid")
        tree = subprocess.run(
            prefix + ("ls-tree", "-r", "-z", "--full-tree", source_sha, "--",
                      "Cargo.toml", "package.json", "package-lock.json", ".node-version",
                      ".npmrc", "dependency-policy.json", "docs/dependencies", "packages",
                      "crates/host/api", "runtime"),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, timeout=30, check=False,
        )
        if tree.returncode != 0 or tree.stderr or len(tree.stdout) > 8 * 1024 * 1024:
            _refuse("manifest_invalid")
        entries = {}
        for record in tree.stdout.split(b"\x00"):
            if not record:
                continue
            metadata, path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ", 2)
            try:
                relative = path.decode("ascii", "strict")
                mode_text = mode.decode("ascii", "strict")
                kind_text = kind.decode("ascii", "strict")
                oid = object_id.decode("ascii", "strict")
            except UnicodeError:
                continue
            if kind_text == "blob" and re.fullmatch(r"[a-f0-9]{40}", oid) is not None:
                entries[relative] = (mode_text, oid)
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        _refuse("manifest_invalid")
    return entries


def validate_dispatch(kind, environ, *, now=None):
    if type(kind) is not str or kind not in PROFILE_BY_KIND:
        _refuse("request_invalid")
    current = int(time.time()) if now is None else now
    try:
        request_bytes = _decode_b64(environ.get(REQUEST_ENV), MAX_REQUEST_BYTES)
        spki_der = _decode_b64(environ.get(RECIPIENT_ENV), MAX_KEY_BYTES)
        request = feedback_request.parse_request(request_bytes, now=current)
    except FeedbackRefusal:
        raise
    except BaseException:
        _refuse("request_invalid")
    profile = PROFILE_BY_KIND[kind]
    workflow_ref = environ.get("GITHUB_WORKFLOW_REF", "")
    repository_slug = environ.get("GITHUB_REPOSITORY", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    if (request.get("kind") != profile["kind"] or request.get("concern") != profile["concern"]
            or request.get("workflow_path") != profile["workflow_path"]
            or request.get("workflow_ref") != feedback_request.WORKFLOW_REF
            or request.get("ci_repository_id") != environ.get("GITHUB_REPOSITORY_ID")
            or request.get("repository_id") != environ.get("SOURCE_REPOSITORY_ID")
            or request.get("source_sha") != environ.get("CORE_CONTRACT_REVIEWED_SOURCE_SHA")
            or request.get("base_sha") != environ.get("CORE_CONTRACT_REVIEWED_BASE_SHA")
            or request.get("base_branch") != environ.get("CORE_CONTRACT_REVIEWED_BASE_BRANCH")
            or request.get("reviewed_diff_sha256") != environ.get("CORE_CONTRACT_REVIEWED_DIFF_SHA256")
            or request.get("control_sha") != environ.get("CI_SHA")
            or environ.get("GITHUB_SHA") != environ.get("CI_SHA")
            or environ.get("GITHUB_REF") != "refs/heads/main"
            or environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or workflow_ref != repository_slug + "/" + profile["workflow_path"] + "@refs/heads/main"
            or environ.get("GITHUB_JOB") != profile["producer_job"]
            or not _valid_decimal(run_id)
            or environ.get("GITHUB_RUN_ATTEMPT") != "1"
            or len(spki_der) > MAX_KEY_BYTES
            or hashlib.sha256(spki_der).hexdigest() != request.get("recipient_fingerprint")):
        _refuse("request_invalid")
    context = {
        "request_id": request["request_id"],
        "nonce": request["nonce"],
        "recipient_fingerprint": request["recipient_fingerprint"],
        "concern": profile["concern"],
        "repository_id": request["repository_id"],
        "source_sha": request["source_sha"],
        "base_sha": request["base_sha"],
        "control_sha": request["control_sha"],
        "base_branch": request["base_branch"],
        "reviewed_diff_sha256": request["reviewed_diff_sha256"],
        "workflow_ref": request["workflow_ref"],
        "run_id": run_id,
        "producer_job": profile["producer_job"],
        "run_attempt": 1,
        "expiry": request["expiry"],
    }
    context["kind"] = profile["kind"]
    context = {
        "request_id": context["request_id"], "nonce": context["nonce"],
        "recipient_fingerprint": context["recipient_fingerprint"],
        "concern": context["concern"], "kind": context["kind"],
        **{name: value for name, value in context.items()
           if name not in ("request_id", "nonce", "recipient_fingerprint", "concern", "kind")},
    }
    return {"profile": dict(profile), "request": request, "context": context, "spki_der": spki_der}


def resolve_node(environ):
    candidate = environ.get(NODE_ENV, "")
    cache = environ.get("RUNNER_TOOL_CACHE", "")
    try:
        node = Path(candidate)
        root = Path(cache).resolve(strict=True) / "node" / NODE_VERSION
        resolved = node.resolve(strict=True)
        info = resolved.lstat()
    except BaseException:
        _refuse("tool_unavailable")
    if (not node.is_absolute() or node != resolved or root not in resolved.parents
            or not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IXUSR
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        _refuse("tool_unavailable")
    environment = {"PATH": str(resolved.parent), "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C"}
    try:
        result = subprocess.run((str(resolved), "--version"), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                                timeout=10, close_fds=True, check=False)
    except BaseException:
        _refuse("tool_unavailable")
    if result.returncode != 0 or result.stdout != b"v" + NODE_VERSION.encode("ascii") + b"\n" or result.stderr:
        _refuse("tool_unavailable")
    return resolved


def _encrypt_payload(encryptor, input_record, node):
    raw = json.dumps(input_record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw) > MAX_NODE_INPUT_BYTES:
        _refuse("payload_invalid", "input_size")
    try:
        result = subprocess.run((str(node), str(encryptor)), input=raw, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                env={"PATH": str(node.parent), "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C"},
                                timeout=60, close_fds=True, check=False)
    except BaseException:
        _refuse("payload_invalid", "spawn")
    if result.returncode != 0 or result.stderr:
        _refuse("payload_invalid", _node_detail(result.stderr))
    if not result.stdout or result.stdout[:4] != b"KDLE":
        _refuse("payload_invalid", "output_shape")
    if len(result.stdout) > MAX_CIPHERTEXT_BYTES:
        _refuse("payload_invalid", "output_size")
    return bytes(result.stdout)


def _write_ciphertext(runner_temp, member_name, payload):
    if (member_name not in {profile["member_name"] for profile in PROFILE_BY_KIND.values()}
            or type(payload) is not bytes or not 1 <= len(payload) <= MAX_CIPHERTEXT_BYTES):
        _refuse("output_unavailable", "output_member")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        _refuse("output_unavailable", "output_directory")
    parent_fd = directory_fd = file_fd = None
    directory_created = False
    file_created = False
    try:
        parent_fd = os.open(runner_temp, os.O_RDONLY | directory_flag | nofollow)
        parent = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid == 0:
            raise ValueError
        os.mkdir(OUTPUT_DIRECTORY, 0o700, dir_fd=parent_fd)
        directory_created = True
        directory_fd = os.open(OUTPUT_DIRECTORY, os.O_RDONLY | directory_flag | nofollow, dir_fd=parent_fd)
        os.fchown(directory_fd, OUTPUT_OWNER_UID, OUTPUT_OWNER_GID)
        os.fchmod(directory_fd, 0o700)
        directory = os.fstat(directory_fd)
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != OUTPUT_OWNER_UID
                or stat.S_IMODE(directory.st_mode) != 0o700):
            raise ValueError
        file_fd = os.open(member_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                          0o600, dir_fd=directory_fd)
        file_created = True
        os.fchown(file_fd, OUTPUT_OWNER_UID, OUTPUT_OWNER_GID)
        os.fchmod(file_fd, 0o400)
        offset = 0
        while offset < len(payload):
            count = os.write(file_fd, payload[offset:])
            if count <= 0:
                raise OSError
            offset += count
        os.fsync(file_fd)
        opened = os.fstat(file_fd)
        named = os.stat(member_name, dir_fd=directory_fd, follow_symlinks=False)
        if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != OUTPUT_OWNER_UID or opened.st_nlink != 1
                or opened.st_size != len(payload) or stat.S_IMODE(opened.st_mode) != 0o400):
            raise ValueError
        os.fsync(directory_fd)
        return {
            "member_name": member_name,
            "ciphertext_digest": hashlib.sha256(payload).hexdigest(),
            "member_size": len(payload),
        }
    except BaseException:
        if file_created and directory_fd is not None:
            try:
                os.unlink(member_name, dir_fd=directory_fd)
            except OSError:
                pass
        if directory_created and parent_fd is not None:
            try:
                os.rmdir(OUTPUT_DIRECTORY, dir_fd=parent_fd)
            except OSError:
                pass
        _refuse("output_unavailable", "output_write")
    finally:
        for descriptor in (file_fd, directory_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def producer_receipt(dispatch, ciphertext_info):
    profile = dispatch["profile"]
    context_fields = (
        ("request_id", "nonce", "recipient_fingerprint", "concern", "repository_id", "source_sha",
         "base_sha", "control_sha", "base_branch", "reviewed_diff_sha256", "workflow_ref", "run_id",
         "producer_job", "run_attempt", "expiry")
        if profile["profile_id"] == 1 else
        ("request_id", "nonce", "recipient_fingerprint", "concern", "kind", "repository_id", "source_sha",
         "base_sha", "control_sha", "base_branch", "reviewed_diff_sha256", "workflow_ref", "run_id",
         "producer_job", "run_attempt", "expiry")
    )
    record = {name: dispatch["context"][name] for name in context_fields}
    record.update({
        "schema_version": SCHEMA_VERSION,
        "status": "encrypted",
        "job_name": profile["producer_job"],
        **ciphertext_info,
    })
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _make_worker_directory(path, worker_uid, primary_gid):
    try:
        os.mkdir(path, 0o700)
        os.chown(path, worker_uid, primary_gid)
        os.chmod(path, 0o700)
        info = path.lstat()
    except BaseException:
        _refuse("output_unavailable")
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != worker_uid or info.st_gid != primary_gid
            or stat.S_IMODE(info.st_mode) != 0o700):
        _refuse("output_unavailable")


def _write_worker_file(path, payload, worker_uid, primary_gid, mode=0o600):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None or mode not in (0o600, 0o644):
        _refuse("output_unavailable")
    descriptor = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, mode)
        os.fchown(descriptor, worker_uid, primary_gid)
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(payload):
            count = os.write(descriptor, payload[offset:])
            if count <= 0:
                raise OSError
            offset += count
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        named = path.lstat()
        if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != worker_uid
                or opened.st_gid != primary_gid or opened.st_nlink != 1
                or opened.st_size != len(payload) or stat.S_IMODE(opened.st_mode) != mode):
            raise ValueError
    except BaseException:
        _refuse("output_unavailable")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _copy_reviewed_files(source, destination, relative_paths, worker_uid, primary_gid,
                         file_mode=0o600, candidate_files=None, inventoried_paths=frozenset(),
                         inventory_file_max_bytes=MAX_RUST_FILE_BYTES):
    if file_mode not in (0o600, 0o644):
        _refuse("output_unavailable")
    _make_worker_directory(destination, worker_uid, primary_gid)
    for relative in relative_paths:
        rel = Path(relative)
        if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
            _refuse("manifest_invalid")
        current = destination
        for part in rel.parts[:-1]:
            current = current / part
            try:
                current.lstat()
            except FileNotFoundError:
                _make_worker_directory(current, worker_uid, primary_gid)
            except OSError:
                _refuse("output_unavailable")
        source_path = source / rel
        if relative in inventoried_paths:
            maximum = inventory_file_max_bytes
        else:
            maximum = (MAX_RUST_FILE_BYTES if rel.suffix in (".rs", ".ts")
                       else MAX_PACKAGE_JSON_BYTES)
        payload = _read_file(source_path, maximum=maximum)
        try:
            source_info = source_path.lstat()
        except OSError:
            _refuse("manifest_invalid")
        if (not stat.S_ISREG(source_info.st_mode) or source_info.st_nlink != 1
                or stat.S_IMODE(source_info.st_mode) not in (0o600, 0o644)
                or source_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
            _refuse("manifest_invalid")
        if candidate_files is not None:
            candidate = candidate_files.get(rel.as_posix())
            git_blob = hashlib.sha1(
                b"blob " + str(len(payload)).encode("ascii") + b"\x00" + payload,
            ).hexdigest()
            if candidate != ("100644", git_blob):
                _refuse("manifest_invalid")
        _write_worker_file(current / rel.name, payload, worker_uid, primary_gid, file_mode)


def _read_worker_file(path, worker_uid, maximum):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _refuse("capture_invalid")
    descriptor = None
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != worker_uid or before.st_nlink != 1
                or before.st_size <= 0 or before.st_size > maximum
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | nofollow)
        opened = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != worker_uid
                or opened.st_nlink != 1 or opened.st_size > maximum):
            raise ValueError
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(8192, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (total != opened.st_size or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or after.st_uid != worker_uid or after.st_nlink != 1):
            raise ValueError
        return b"".join(chunks)
    except BaseException:
        _refuse("capture_invalid")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _node_environment(environment, node, worker_storage):
    home = environment.get("HOME", "")
    if type(home) is not str or not Path(home).is_absolute():
        _refuse("tool_unavailable")
    return {
        "PATH": str(node.parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": home,
        "TMPDIR": str(worker_storage / FEEDBACK_TEMP_DIRECTORY),
        "LANG": "C",
        "LC_ALL": "C",
        "npm_config_cache": str(worker_storage / "npm-cache"),
        "npm_config_registry": "https://registry.npmjs.org/",
        "npm_config_userconfig": "/dev/null",
        "npm_config_globalconfig": "/dev/null",
        "npm_config_ignore_scripts": "true",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_fetch_retries": "0",
        "npm_config_fetch_timeout": "30000",
        "npm_config_update_notifier": "false",
    }


def _run_worker(rust, argv, worker_uid, environment, python_executable, capability, stage, deadline,
                *, allow_nonzero_capture=False, timeout=120):
    command = tuple(str(part) for part in argv)
    if any(not part or "\x00" in part for part in command):
        _refuse("capture_invalid")
    try:
        result = rust._run_worker_command(
            command, worker_uid, environment, python_executable, capability,
            stage=stage, deadline=deadline, timeout=timeout,
            allow_nonzero_capture=allow_nonzero_capture,
        )
    except BaseException as error:
        if getattr(error, "reason", None) == "cleanup_incomplete":
            _refuse("cleanup_incomplete")
        if getattr(error, "reason", None) == "capture_invalid":
            _refuse("capture_invalid")
        refusal = FeedbackRefusal("command_failed")
        check = getattr(error, "command_check", None)
        if type(check) is str and check in ("timeout", "spawn_failure"):
            refusal.command_check = check
        raise refusal
    stdout_limit = rust.MAX_CAPTURE_BYTES if allow_nonzero_capture else 32_768
    if (type(result.returncode) is not int or type(result.stdout) is not bytes
            or type(result.stderr) is not bytes or len(result.stdout) > stdout_limit
            or len(result.stderr) > 32_768):
        _refuse("capture_invalid")
    return result


def _source_root_files(*, include_fuzz=False):
    if type(include_fuzz) is not bool:
        _refuse("manifest_invalid")
    paths = list(RUST_ROOT_FILES)
    for package_root in PACKAGE_ROOTS:
        paths.append((package_root / "Cargo.toml").as_posix())
    if include_fuzz:
        paths.extend(FOUNDATION_FUZZ_MANIFESTS)
    return tuple(paths)


def _rust_format_patch(source, formatted, reviewed_paths, worker_uid, deadline, original_sources=None):
    chunks = []
    total = 0
    for relative in reviewed_paths:
        if type(deadline) not in (int, float) or deadline <= time.monotonic():
            _refuse("command_failed")
        before = _read_file(source / relative, maximum=MAX_RUST_FILE_BYTES)
        after = _read_worker_file(formatted / relative, worker_uid, MAX_RUST_FILE_BYTES)
        if before == after:
            continue
        if original_sources is not None:
            if type(original_sources) is not dict:
                _refuse("manifest_invalid")
            original_sources[relative] = before
        try:
            before_text = before.decode("utf-8", "strict").splitlines(keepends=True)
            after_text = after.decode("utf-8", "strict").splitlines(keepends=True)
        except UnicodeError:
            _refuse("payload_invalid")
        body = "".join(difflib.unified_diff(
            before_text, after_text, fromfile="a/" + relative, tofile="b/" + relative,
            lineterm="\n",
        ))
        if not body.endswith("\n"):
            body += "\n"
        chunk = ("diff --git a/" + relative + " b/" + relative + "\n" + body).encode("utf-8")
        total += len(chunk)
        if total > MAX_PATCH_BYTES:
            _refuse("payload_invalid")
        chunks.append(chunk)
    payload = b"".join(chunks)
    if not payload:
        _refuse("payload_invalid")
    return payload


def run_source_profile(dispatch, source, worker_storage, worker_uid, environment, tools,
                       host_toolchain, capability, rust, reviewed, deadline, node,
                       *, validated_fuzz_workspace=False):
    kind = dispatch["profile"]["kind"]
    if (type(validated_fuzz_workspace) is not bool
            or validated_fuzz_workspace and kind not in ("rust_patch", "build_diagnostics")):
        _refuse("manifest_invalid")
    if kind == "rust_patch":
        reviewed_paths = _reviewed_rust_paths(source, include_fuzz=validated_fuzz_workspace)
        copy_paths = _source_root_files(include_fuzz=validated_fuzz_workspace) + reviewed_paths
        formatted = worker_storage / "feedback-rust-format"
        _copy_reviewed_files(source, formatted, copy_paths, worker_uid, capability.PROBE_PRIMARY_GID)
        commands = [("feedback_format", (
            tools["cargo"], "--offline", "fmt", "--manifest-path", str(formatted / "Cargo.toml"), "--all",
        ))]
        if validated_fuzz_workspace:
            commands.append(("feedback_parser_format", (
                tools["cargo"], "--locked", "--offline", "fmt", "--manifest-path",
                str(formatted / "fuzz/Cargo.toml"), "--all",
            )))
        try:
            os.chdir(formatted)
            for stage, argv in commands:
                result = _run_worker(
                    rust, argv, worker_uid, environment, host_toolchain["python"], capability,
                    stage, deadline, allow_nonzero_capture=True,
                )
                if result.returncode != 0:
                    _refuse("command_failed")
        finally:
            try:
                os.chdir(source)
            except OSError:
                _refuse("cleanup_incomplete")
        original_sources = {}
        patch = _rust_format_patch(
            source, formatted, reviewed_paths, worker_uid, deadline, original_sources=original_sources,
        )
        return {"payload_bytes": patch,
                "reviewed_rust_paths": list(reviewed_paths), "original_rust_sources": original_sources,
                "source_result": "command_completed"}

    _refuse("request_invalid")


def build_diagnostic_payload(outcome):
    if type(outcome) is not dict:
        _refuse("capture_invalid")
    failed = outcome.get("failed_stage")
    selected = outcome.get("selected_gates")
    completed = outcome.get("completed")
    if (type(selected) is not tuple or selected not in DIAGNOSTIC_GATE_SELECTIONS
            or type(completed) is not tuple or any(type(stage) is not str for stage in completed)):
        _refuse("capture_invalid")
    if failed is None:
        if (completed != selected or type(outcome.get("returncode")) is not int
                or outcome.get("returncode") != 0 or outcome.get("stdout") != b""
                or outcome.get("stderr") != b""
                or outcome.get("stdout_truncated") is not False
                or outcome.get("stderr_truncated") is not False):
            _refuse("capture_invalid")
        reviewed_evidence = ""
        return (
            "KD-BUILD-DIAGNOSTICS schema=1 selected_gates=" + ",".join(selected)
            + " completed_gates=" + ",".join(completed)
            + " result=all-gates-completed" + reviewed_evidence + "\n"
        ).encode("ascii")
    if (type(failed) is not str or failed not in selected
            or completed != selected[:selected.index(failed)]):
        _refuse("capture_invalid")
    if (type(outcome.get("returncode")) is not int
            or not 1 <= outcome["returncode"] <= 255
            or type(outcome.get("stdout")) is not bytes or type(outcome.get("stderr")) is not bytes):
        _refuse("capture_invalid")
    if (len(outcome["stdout"]) > 32_768 or len(outcome["stderr"]) > 32_768):
        _refuse("capture_invalid")
    if (type(outcome.get("stdout_truncated")) is not bool
            or type(outcome.get("stderr_truncated")) is not bool):
        _refuse("capture_invalid")
    stdout, stdout_truncated = sanitize_diagnostic_stream(outcome["stdout"], outcome["stdout_truncated"])
    stderr, stderr_truncated = sanitize_diagnostic_stream(outcome["stderr"], outcome["stderr_truncated"])
    prefix = ("KD-BUILD-DIAGNOSTICS schema=1 stage=" + failed
              + " stdout_truncated=" + ("true" if stdout_truncated else "false")
              + " stderr_truncated=" + ("true" if stderr_truncated else "false")
              + " exit=" + str(outcome["returncode"])
              + " selected_gates=" + ",".join(selected)
              + " completed_gates=" + (",".join(completed) if completed else "none")
              + "\nstdout:\n").encode("ascii")
    payload = prefix + stdout + b"\nstderr:\n" + stderr
    if len(payload) > 512 * 1024:
        _refuse("payload_invalid")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeError:
        _refuse("payload_invalid")
    if (UNSAFE_DIAGNOSTIC_RE.search(text) is not None
            or text.count("\n") + 1 > DIAGNOSTIC_MAX_LINES
            or any(_utf16_units(line) > DIAGNOSTIC_MAX_LINE_UNITS for line in text.split("\n"))):
        _refuse("payload_invalid")
    return payload


def _trim_incomplete_utf8(data):
    """Drop an incomplete trailing UTF-8 sequence left behind by a byte cut."""
    size = len(data)
    for back in range(1, min(4, size) + 1):
        byte = data[size - back]
        if byte & 0xC0 == 0x80:
            continue
        if byte >= 0xC0:
            needed = 2 if byte < 0xE0 else 3 if byte < 0xF0 else 4
            if needed > back:
                return data[:size - back]
        return data
    return data


def _utf16_units(text):
    return sum(2 if ord(character) > 0xFFFF else 1 for character in text)


def _clip_line_units(line, limit=DIAGNOSTIC_MAX_LINE_UNITS):
    units = 0
    end = 0
    for character in line:
        step = 2 if ord(character) > 0xFFFF else 1
        if units + step > limit:
            break
        units += step
        end += 1
    return line[:end]


def _escape_unsafe_character(match):
    return "\\u{%02x}" % ord(match.group(0))


def sanitize_diagnostic_stream(raw, truncated):
    """Make one captured gate stream safe for the build-diagnostics payload.

    Escape form (documented, deterministic, ASCII only): an incomplete trailing UTF-8 sequence from
    a byte cut is dropped; any other invalid UTF-8 byte becomes \\xNN; NUL, CR, C0 controls other
    than tab and newline, DEL and C1 controls become \\u{h...h} (lowercase hex, at least two digits).
    The bidirectional controls U+061C, U+200E, U+200F, U+202A to U+202E and U+2066 to U+2069 get the
    same form, so project text cannot visually reorder the body in a terminal or editor. Literal
    backslashes are not escaped, so the form is not injective: project text that already reads
    \\u{1b} gives the same bytes as an escaped ESC. No consumer may ever un-escape it.
    The result is then bounded to DIAGNOSTIC_STREAM_MAX_LINES lines of DIAGNOSTIC_MAX_LINE_UNITS
    UTF-16 units, so escaping growth can never push the payload past the encryptor's line limits.
    Returns (bytes, truncated) where truncated also covers any cut made here."""
    if type(raw) is not bytes or type(truncated) is not bool:
        _refuse("capture_invalid")
    data = _trim_incomplete_utf8(raw) if truncated else raw
    text = UNSAFE_DIAGNOSTIC_RE.sub(_escape_unsafe_character, data.decode("utf-8", "backslashreplace"))
    text = DISPLAY_UNSAFE_DIAGNOSTIC_RE.sub(_escape_unsafe_character, text)
    lines = text.split("\n")
    cut = False
    if len(lines) > DIAGNOSTIC_STREAM_MAX_LINES:
        lines = lines[:DIAGNOSTIC_STREAM_MAX_LINES]
        cut = True
    for index, line in enumerate(lines):
        if _utf16_units(line) > DIAGNOSTIC_MAX_LINE_UNITS:
            lines[index] = _clip_line_units(line)
            cut = True
    return "\n".join(lines).encode("utf-8"), truncated or cut


def encrypt_after_cleanup(dispatch, result, node):
    profile = dispatch["profile"]
    payload = result.get("payload_bytes")
    if type(payload) is not bytes or not payload:
        _refuse("payload_invalid", "payload_missing")
    record = {
        "schema_version": 1,
        "kind": profile["kind"],
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "context": dispatch["context"],
        "recipient_spki_b64": base64.b64encode(dispatch["spki_der"]).decode("ascii"),
        "now": int(time.time()),
    }
    if profile["kind"] == "rust_patch":
        paths = result.get("reviewed_rust_paths")
        if type(paths) is not list or not paths:
            _refuse("manifest_invalid", "reviewed_paths_invalid")
        record["reviewed_rust_paths"] = paths
    try:
        control_directory = Path(__file__).resolve(strict=True).parent
        encryptor = control_directory / "feedback_producer_crypto.mjs"
        info = encryptor.lstat()
        resolved_encryptor = encryptor.resolve(strict=True)
    except (OSError, RuntimeError):
        _refuse("tool_unavailable", "encryptor_unavailable")
    if (resolved_encryptor.parent != control_directory or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1 or stat.S_ISLNK(info.st_mode)
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        _refuse("tool_unavailable", "tool_path")
    try:
        return _encrypt_payload(encryptor, record, node)
    except FeedbackRefusal as error:
        if profile["kind"] != "rust_patch" or error.detail != "node_credential_like_content":
            raise
        original_sources = result.get("original_rust_sources")
        if (type(original_sources) is not dict or not original_sources
                or not set(original_sources).issubset(paths)
                or any(type(original_sources[path]) is not bytes for path in original_sources)):
            _refuse("manifest_invalid", "reviewed_paths_invalid")
        record["original_rust_files_b64"] = [
            {"path": path, "content_b64": base64.b64encode(original_sources[path]).decode("ascii")}
            for path in sorted(original_sources)
        ]
        return _encrypt_payload(encryptor, record, node)


def write_output(runner_temp, dispatch, ciphertext):
    info = _write_ciphertext(runner_temp, dispatch["profile"]["member_name"], ciphertext)
    return producer_receipt(dispatch, info)


def _parse_producer_line(raw, kind, environ):
    if (type(raw) is not bytes or len(raw) > 8192 or not raw.endswith(b"\n")
            or raw.count(b"\n") != 1 or not raw.startswith(b"KD-FEEDBACK-PRODUCER ")):
        _refuse("request_invalid")
    try:
        payload = raw[len(b"KD-FEEDBACK-PRODUCER "):-1].decode("ascii", "strict")
        record = _strict_json(payload.encode("ascii"), 8192)
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if canonical != payload:
            raise ValueError
        dispatch = validate_dispatch(kind, environ)
        profile = dispatch["profile"]
        expected = producer_receipt(dispatch, {
            "member_name": profile["member_name"],
            "ciphertext_digest": record.get("ciphertext_digest"),
            "member_size": record.get("member_size"),
        })
        if payload != expected:
            raise ValueError
        if (type(record.get("ciphertext_digest")) is not str
                or SHA256_RE.fullmatch(record["ciphertext_digest"]) is None
                or type(record.get("member_size")) is not int
                or not 1 <= record["member_size"] <= MAX_CIPHERTEXT_BYTES):
            raise ValueError
    except FeedbackRefusal:
        raise
    except BaseException:
        _refuse("request_invalid")
    return dispatch, record, payload


def _read_root_spool(runner_temp, member_name, expected_size, expected_digest):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        _refuse("output_unavailable")
    parent_fd = directory_fd = file_fd = None
    try:
        parent_path = Path(runner_temp)
        if parent_path.resolve(strict=True) != parent_path:
            raise ValueError
        parent_fd = os.open(parent_path, os.O_RDONLY | directory_flag | nofollow)
        parent = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid == 0:
            raise ValueError
        directory_fd = os.open(OUTPUT_DIRECTORY, os.O_RDONLY | directory_flag | nofollow, dir_fd=parent_fd)
        directory = os.fstat(directory_fd)
        named_directory = os.stat(OUTPUT_DIRECTORY, dir_fd=parent_fd, follow_symlinks=False)
        if ((directory.st_dev, directory.st_ino) != (named_directory.st_dev, named_directory.st_ino)
                or not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
                or stat.S_IMODE(directory.st_mode) != 0o700):
            raise ValueError
        file_fd = os.open(member_name, os.O_RDONLY | nofollow, dir_fd=directory_fd)
        opened = os.fstat(file_fd)
        named = os.stat(member_name, dir_fd=directory_fd, follow_symlinks=False)
        if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0
                or opened.st_nlink != 1 or opened.st_size != expected_size
                or stat.S_IMODE(opened.st_mode) != 0o400):
            raise ValueError
        chunks = []
        total = 0
        while True:
            chunk = os.read(file_fd, min(65_536, expected_size + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > expected_size:
                raise ValueError
            chunks.append(chunk)
        after = os.fstat(file_fd)
        named_after = os.stat(member_name, dir_fd=directory_fd, follow_symlinks=False)
        if ((after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or (named_after.st_dev, named_after.st_ino) != (opened.st_dev, opened.st_ino)
                or after.st_uid != 0 or after.st_nlink != 1 or after.st_size != expected_size):
            raise ValueError
        payload = b"".join(chunks)
        if hashlib.sha256(payload).hexdigest() != expected_digest:
            raise ValueError
        return payload
    except BaseException:
        _refuse("output_unavailable")
    finally:
        for descriptor in (file_fd, directory_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _stage_ciphertext(runner_temp, member_name, payload):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        _refuse("output_unavailable")
    parent_fd = directory_fd = file_fd = None
    created_directory = False
    temporary_name = "." + member_name + ".tmp"
    file_installed = False
    try:
        parent_fd = os.open(runner_temp, os.O_RDONLY | directory_flag | nofollow)
        parent = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid == 0:
            raise ValueError
        os.mkdir("core-feedback-upload", 0o700, dir_fd=parent_fd)
        created_directory = True
        directory_fd = os.open("core-feedback-upload", os.O_RDONLY | directory_flag | nofollow,
                               dir_fd=parent_fd)
        directory = os.fstat(directory_fd)
        os.fchown(directory_fd, 0, 0)
        os.fchmod(directory_fd, 0o700)
        directory = os.fstat(directory_fd)
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
                or stat.S_IMODE(directory.st_mode) != 0o700):
            raise ValueError
        file_fd = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                          0o600, dir_fd=directory_fd)
        os.fchown(file_fd, 0, 0)
        os.fchmod(file_fd, 0o600)
        offset = 0
        while offset < len(payload):
            count = os.write(file_fd, payload[offset:])
            if count <= 0:
                raise OSError
            offset += count
        os.fsync(file_fd)
        created = os.fstat(file_fd)
        os.rename(temporary_name, member_name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        file_installed = True
        named = os.stat(member_name, dir_fd=directory_fd, follow_symlinks=False)
        if ((created.st_dev, created.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISREG(named.st_mode) or named.st_uid != 0
                or named.st_nlink != 1 or named.st_size != len(payload)):
            raise ValueError
        os.fchown(file_fd, parent.st_uid, parent.st_gid)
        os.fchmod(file_fd, 0o600)
        os.fsync(file_fd)
        copied = os.fstat(file_fd)
        named = os.stat(member_name, dir_fd=directory_fd, follow_symlinks=False)
        if ((copied.st_dev, copied.st_ino) != (named.st_dev, named.st_ino)
                or copied.st_uid != parent.st_uid or copied.st_gid != parent.st_gid
                or stat.S_IMODE(copied.st_mode) != 0o600 or copied.st_size != len(payload)):
            raise ValueError
        os.fchown(directory_fd, parent.st_uid, parent.st_gid)
        os.fchmod(directory_fd, 0o700)
        os.fsync(directory_fd)
        named_directory = os.stat("core-feedback-upload", dir_fd=parent_fd, follow_symlinks=False)
        if ((named_directory.st_dev, named_directory.st_ino) != (directory.st_dev, directory.st_ino)
                or named_directory.st_uid != parent.st_uid
                or stat.S_IMODE(named_directory.st_mode) != 0o700):
            raise ValueError
    except BaseException:
        if directory_fd is not None:
            try:
                if file_installed:
                    os.unlink(member_name, dir_fd=directory_fd)
                else:
                    os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
        if created_directory and parent_fd is not None:
            try:
                os.rmdir("core-feedback-upload", dir_fd=parent_fd)
            except OSError:
                pass
        _refuse("output_unavailable")
    finally:
        for descriptor in (file_fd, directory_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _append_github_output(path, runner_uid, runner_gid, values):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _refuse("output_unavailable")
    descriptor = None
    try:
        target = Path(path)
        before = target.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != runner_uid
                or before.st_gid != runner_gid or before.st_nlink != 1 or before.st_size > 1024 * 1024
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise ValueError
        descriptor = os.open(target, os.O_WRONLY | os.O_APPEND | nofollow)
        opened = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_uid != runner_uid or opened.st_gid != runner_gid or opened.st_nlink != 1):
            raise ValueError
        payload = "".join(name + "=" + value + "\n" for name, value in values.items()).encode("ascii")
        if len(payload) > 16 * 1024:
            raise ValueError
        offset = 0
        while offset < len(payload):
            count = os.write(descriptor, payload[offset:])
            if count <= 0:
                raise OSError
            offset += count
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        named = target.lstat()
        if ((after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
                or after.st_uid != runner_uid or after.st_gid != runner_gid):
            raise ValueError
    except BaseException:
        _refuse("output_unavailable")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def publish_output(raw_receipt, kind, environ):
    dispatch, record, receipt_json = _parse_producer_line(raw_receipt, kind, environ)
    runner_temp = environ.get("RUNNER_TEMP", "")
    try:
        runner_path = Path(runner_temp)
        runner_info = runner_path.lstat()
    except OSError:
        _refuse("output_unavailable")
    if not stat.S_ISDIR(runner_info.st_mode) or runner_info.st_uid == 0:
        _refuse("output_unavailable")
    output_path = environ.get("GITHUB_OUTPUT", "")
    if not output_path:
        _refuse("output_unavailable")
    payload = _read_root_spool(
        runner_path, record["member_name"], record["member_size"], record["ciphertext_digest"],
    )
    _stage_ciphertext(runner_path, record["member_name"], payload)
    _append_github_output(output_path, runner_info.st_uid, runner_info.st_gid, {
        "member_name": record["member_name"],
        "ciphertext_digest": record["ciphertext_digest"],
        "member_size": str(record["member_size"]),
        "producer_receipt": receipt_json,
    })
    return {
        "member_name": record["member_name"],
        "ciphertext_digest": record["ciphertext_digest"],
        "member_size": record["member_size"],
    }


def _parse_cli(arguments):
    if (type(arguments) not in (tuple, list) or len(arguments) != 10
            or arguments[0] != "run" or arguments[1] != "--profile"
            or arguments[3] != "--token-stdin" or arguments[4] != "--source-sha"
            or arguments[6] != "--base-sha" or arguments[8] != "--base-branch"):
        return "invalid", []
    kind = arguments[2]
    if kind not in PROFILE_BY_KIND:
        return "invalid", []
    return kind, [
        "run", "--token-stdin", "--source-sha", arguments[5],
        "--base-sha", arguments[7], "--base-branch", arguments[9],
    ]


def main(arguments=None, environ=None, stdin=None, stdout=None):
    actual = sys.argv[1:] if arguments is None else arguments
    environment = dict(os.environ) if environ is None else dict(environ)
    input_stream = sys.stdin.buffer if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    if (type(actual) in (tuple, list) and len(actual) == 3
            and actual[0] == "publish" and actual[1] == "--profile"):
        kind = actual[2]
        try:
            raw = input_stream.read(8193)
        except BaseException:
            raw = None
        try:
            if type(raw) is not bytes or len(raw) > 8192 or kind not in PROFILE_BY_KIND:
                _refuse("request_invalid")
            result = publish_output(raw, kind, environment)
            payload = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            output_stream.write("KD-FEEDBACK-PUBLISHER " + payload + "\n")
            return 0
        except FeedbackRefusal:
            output_stream.write(
                'KD-FEEDBACK-PUBLISHER-REFUSAL '
                '{"reason":"output_unavailable","schema_version":1,"status":"refused"}\n'
            )
            return 1
    kind, core_arguments = _parse_cli(actual)
    control_path = Path(__file__).resolve(strict=True).parent / "macos_core_contract.py"
    try:
        spec = importlib.util.spec_from_file_location("macos_core_contract", str(control_path))
        if spec is None or spec.loader is None:
            raise ValueError
        core = importlib.util.module_from_spec(spec)
        sys.modules["macos_core_contract"] = core
        spec.loader.exec_module(core)
    except BaseException:
        _refuse("tool_unavailable")
    return core.main(
        arguments=core_arguments,
        environ=environ,
        stdin=stdin,
        stdout=stdout,
        feedback_kind=kind,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FeedbackRefusal:
        sys.stdout.write(
            'KD-FEEDBACK-PRODUCER-REFUSAL '
            '{"diagnostic":"unavailable","reason":"runner_unavailable",'
            '"schema_version":1,"stage":"context","status":"refused"}\n'
        )
        raise SystemExit(1)
