"""Parse committed Cargo.lock files from the supported public registry subset."""

import hashlib
import re


REGISTRY_SOURCE = (
    "registry+https:" + chr(47) * 2 + "github.com" + chr(47)
    + "rust-lang" + chr(47) + "crates.io-index"
)
SPARSE_REGISTRY_SOURCE = "sparse+https:" + chr(47) * 2 + "index.crates.io/"
MAX_LOCK_BYTES = 4 * 1024 * 1024
MAX_LOCK_PACKAGES = 20_000
MAX_LOCK_DEPENDENCIES = 20_000
MAX_DEPENDENCY_ARRAY_BYTES = 1024 * 1024
MAX_DEPENDENCY_ARRAY_LINES = 20_000
HEX40_RE = re.compile(r"[a-f0-9]{40}\Z")
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
PACKAGE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
DEPENDENCY_RE = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9_-]{0,63})"
    r"(?: (?P<version>[^ ()]{1,128}))?"
    r"(?: \((?P<source>[^()]*)\))?\Z"
)
LOCK_FIELDS = frozenset(("name", "version", "source", "checksum", "dependencies"))


class Refusal(Exception):
    """A refusal with a fixed message that never contains caller-provided data."""

    def __init__(self, reason="cargo_lock_invalid"):
        if reason != "cargo_lock_invalid":
            reason = "cargo_lock_invalid"
        self.reason = reason
        super().__init__(reason)


def _refuse(reason="cargo_lock_invalid"):
    raise Refusal(reason)


def _exact_dict(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _valid_hex(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _valid_package_identity(name, version):
    return (
        type(name) is str and PACKAGE_NAME_RE.fullmatch(name) is not None
        and _valid_version(version)
    )


def _valid_version(version):
    if type(version) is not str or len(version) > 128 or VERSION_RE.fullmatch(version) is None:
        return False
    core = version.split("+", 1)[0]
    if "-" in core:
        prerelease = core.split("-", 1)[1]
        for identifier in prerelease.split("."):
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                return False
    return True


def _internal_registry_name(name):
    return name.lower().replace("_", "-").startswith("keeldock" + "-")


def _registry_source(source):
    if source in (REGISTRY_SOURCE, SPARSE_REGISTRY_SOURCE):
        return REGISTRY_SOURCE
    return None


def _is_link_or_reparse(path):
    try:
        metadata = Path(path).lstat()
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse_flag
    )


def _decode_ascii(data, maximum, reason):
    if type(data) is not bytes or len(data) > maximum:
        _refuse(reason)
    try:
        return data.decode("ascii", "strict")
    except UnicodeError:
        _refuse(reason)


def _strip_toml_comment(line):
    quoted = False
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == chr(35) and not quoted:
            return line[:index]
    if quoted or escaped:
        _refuse("cargo_lock_invalid")
    return line


def _parse_toml_string(value):
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        _refuse("cargo_lock_invalid")
    result = []
    index = 1
    while index < len(value) - 1:
        character = value[index]
        if character == "\\":
            index += 1
            if index >= len(value) - 1 or value[index] not in ('"', "\\"):
                _refuse("cargo_lock_invalid")
            character = value[index]
        elif character == '"' or ord(character) < 32:
            _refuse("cargo_lock_invalid")
        result.append(character)
        index += 1
    return "".join(result)


def _parse_string_array(value):
    if not value.startswith("[") or not value.endswith("]"):
        _refuse("cargo_lock_invalid")
    body = value[1:-1]
    result = []
    index = 0
    while index < len(body):
        while index < len(body) and body[index] in " \t":
            index += 1
        if index == len(body):
            break
        if body[index] != '"':
            _refuse("cargo_lock_invalid")
        start = index
        index += 1
        escaped = False
        while index < len(body):
            character = body[index]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                index += 1
                break
            index += 1
        else:
            _refuse("cargo_lock_invalid")
        result.append(_parse_toml_string(body[start:index]))
        if len(result) > MAX_LOCK_DEPENDENCIES or len(result[-1]) > 512:
            _refuse("cargo_lock_invalid")
        while index < len(body) and body[index] in " \t":
            index += 1
        if index == len(body):
            break
        if body[index] != ",":
            _refuse("cargo_lock_invalid")
        index += 1
        while index < len(body) and body[index] in " \t":
            index += 1
        if index < len(body) and body[index] == ",":
            _refuse("cargo_lock_invalid")
    return result


def _scan_array_fragment(value, quoted=False, escaped=False, depth=0):
    complete = False
    for character in value:
        if complete:
            if character not in " \t":
                _refuse("cargo_lock_invalid")
            continue
        if escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif not quoted and character == "[":
            depth += 1
            if depth != 1:
                _refuse("cargo_lock_invalid")
        elif not quoted and character == "]":
            depth -= 1
            if depth == 0:
                complete = True
            if depth < 0:
                _refuse("cargo_lock_invalid")
    return complete, quoted, escaped, depth


def _parse_lock_value(key, value):
    value = value.strip()
    if key == "dependencies":
        return _parse_string_array(value)
    if value.startswith('"'):
        return _parse_toml_string(value)
    if key == "version" and value in ("3", "4"):
        return int(value)
    _refuse("cargo_lock_invalid")


def _dependency_record(value):
    if type(value) is not str or len(value) > 512:
        _refuse("cargo_lock_invalid")
    match = DEPENDENCY_RE.fullmatch(value)
    if match is None:
        _refuse("cargo_lock_invalid")
    name = match.group("name")
    version = match.group("version")
    source = match.group("source")
    if source is not None and _registry_source(source) and _internal_registry_name(name):
        _refuse("cargo_lock_invalid")
    if version is not None and not _valid_package_identity(name, version):
        _refuse("cargo_lock_invalid")
    if source is not None and _registry_source(source) is None:
        _refuse("cargo_lock_invalid")
    if source is not None and version is None:
        _refuse("cargo_lock_invalid")
    return name, version, _registry_source(source) if source is not None else None


def parse_cargo_lock(lock_bytes):
    """Parse the supported v3/v4 Cargo.lock subset without a general TOML parser."""
    text = _decode_ascii(lock_bytes, MAX_LOCK_BYTES, "cargo_lock_invalid")
    if text.startswith("\ufeff"):
        _refuse("cargo_lock_invalid")
    packages = []
    current = None
    lock_version = None
    lines = iter(text.splitlines(keepends=True))
    for raw_line in lines:
        line = _strip_toml_comment(raw_line).strip()
        if not line:
            continue
        if line == "[[package]]":
            if current is not None:
                packages.append(current)
                if len(packages) >= MAX_LOCK_PACKAGES:
                    _refuse("cargo_lock_invalid")
            current = {}
            continue
        if "=" not in line:
            _refuse("cargo_lock_invalid")
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", key) is None:
            _refuse("cargo_lock_invalid")
        raw_value = raw_value.strip()
        if key == "dependencies" and raw_value.startswith("["):
            fragments = [raw_value]
            complete, quoted, escaped, depth = _scan_array_fragment(raw_value)
            total_array_bytes = len(raw_line)
            line_count = 1
            if total_array_bytes > MAX_DEPENDENCY_ARRAY_BYTES:
                _refuse("cargo_lock_invalid")
            while not complete:
                try:
                    continuation_line = next(lines)
                except StopIteration:
                    _refuse("cargo_lock_invalid")
                line_count += 1
                total_array_bytes += len(continuation_line)
                if (line_count > MAX_DEPENDENCY_ARRAY_LINES
                        or total_array_bytes > MAX_DEPENDENCY_ARRAY_BYTES):
                    _refuse("cargo_lock_invalid")
                continuation = _strip_toml_comment(continuation_line).strip()
                if continuation:
                    fragments.append(continuation)
                    complete, quoted, escaped, depth = _scan_array_fragment(
                        continuation, quoted, escaped, depth,
                    )
            raw_value = " ".join(fragments)
        value = _parse_lock_value(key, raw_value)
        if current is None:
            if key != "version" or lock_version is not None:
                _refuse("cargo_lock_invalid")
            lock_version = value
        else:
            if key not in LOCK_FIELDS or key in current:
                _refuse("cargo_lock_invalid")
            current[key] = value
    if current is not None:
        packages.append(current)
    if lock_version not in (3, 4) or not packages:
        _refuse("cargo_lock_invalid")

    seen = set()
    for package in packages:
        if not _valid_package_identity(package.get("name"), package.get("version")):
            _refuse("cargo_lock_invalid")
        name = package["name"]
        version = package["version"]
        source = package.get("source")
        checksum = package.get("checksum")
        if source is None:
            if checksum is not None:
                _refuse("cargo_lock_invalid")
        elif _registry_source(source) is not None:
            if _internal_registry_name(name) or not _valid_hex(checksum, HEX64_RE):
                _refuse("cargo_lock_invalid")
            package["source"] = REGISTRY_SOURCE
        else:
            _refuse("cargo_lock_invalid")
        identity = (name, version)
        if identity in seen:
            _refuse("cargo_lock_invalid")
        seen.add(identity)
        dependencies = package.get("dependencies", [])
        if type(dependencies) is not list:
            _refuse("cargo_lock_invalid")
        parsed_dependencies = [_dependency_record(item) for item in dependencies]
        if len(set(parsed_dependencies)) != len(parsed_dependencies):
            _refuse("cargo_lock_invalid")
        package["dependencies"] = parsed_dependencies

    by_name = {}
    by_identity = {}
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)
        by_identity[(package["name"], package["version"])] = package
    for package in packages:
        for dependency_name, dependency_version, dependency_source in package["dependencies"]:
            if dependency_version is None:
                candidates = by_name.get(dependency_name, [])
                candidate = candidates[0] if len(candidates) == 1 else None
            else:
                candidate = by_identity.get((dependency_name, dependency_version))
            if candidate is None or (dependency_source is not None
                                     and candidate.get("source") != dependency_source):
                _refuse("cargo_lock_invalid")
    return {"version": lock_version, "packages": packages}


def _valid_repository(value):
    if type(value) is not str or len(value) > 128 or value.count("/") != 1:
        return False
    owner, repository = value.split("/", 1)
    pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
    return pattern.fullmatch(owner) is not None and pattern.fullmatch(repository) is not None
