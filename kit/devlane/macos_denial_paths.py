import re


_SLASH = chr(47)
MACOS_DNS_SYSTEM_READ_PREFIXES = tuple(_SLASH + prefix for prefix in (
    "System/", "usr/lib/", "usr/share/", "etc/", "var/run/", "var/db/",
    "Library/Preferences/", "Library/Apple/", "dev/",
))
MACOS_DNS_FILE_READ_TARGET_CLASSES = frozenset(("runner-home", "run-root", "toolcache", "other"))
_PATH_PATTERN = re.compile(_SLASH + r"[A-Za-z0-9._/ -]{0,4095}\Z")
_TOOLCACHE_PREFIXES = (_SLASH + "Users/runner/hostedtoolcache/", _SLASH + "opt/hostedtoolcache/")


def _normalize_absolute_path(path):
    if type(path) is not str or _PATH_PATTERN.fullmatch(path) is None:
        return None
    parts = []
    for part in path.split(_SLASH):
        if not part or part == ".":
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    lowered = [part.casefold() for part in parts]
    if len(parts) >= 3 and lowered[:3] == ["system", "volumes", "data"]:
        parts = parts[3:]
    if parts and parts[0].casefold() == "private":
        parts = parts[1:]
    return _SLASH + _SLASH.join(parts)


def _path_is_within(path, root):
    path = path.casefold().rstrip(_SLASH) or _SLASH
    root = root.casefold().rstrip(_SLASH) or _SLASH
    return path == root or path.startswith(root + _SLASH)


def _is_user_path(path):
    return path.casefold() == _SLASH + "users" or path.casefold().startswith(_SLASH + "users" + _SLASH)


def _is_system_read_path(path):
    lowered = path.casefold()
    return any(lowered.startswith(prefix.casefold()) for prefix in MACOS_DNS_SYSTEM_READ_PREFIXES)


def validate_macos_denial_path(path, run_root=None, *, public_target=False):
    if public_target and path in MACOS_DNS_FILE_READ_TARGET_CLASSES:
        return path
    normalized = _normalize_absolute_path(path)
    if normalized is None:
        return None if public_target else "other"
    if public_target:
        return normalized if not _is_user_path(normalized) and _is_system_read_path(normalized) else None
    if any(_path_is_within(normalized, prefix[:-1]) for prefix in _TOOLCACHE_PREFIXES):
        return "toolcache"
    normalized_run_root = _normalize_absolute_path(str(run_root)) if run_root is not None else None
    if normalized_run_root is not None and _path_is_within(normalized, normalized_run_root):
        return "run-root"
    if _is_user_path(normalized):
        return "runner-home"
    if _is_system_read_path(normalized):
        return normalized
    return "other"
