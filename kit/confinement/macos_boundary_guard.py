"""Pinned macOS identity and scoped PF lifecycle checks."""

from dataclasses import dataclass
import os
from pathlib import Path
import platform
import re
import stat
import subprocess


APPROVED_PRODUCT_VERSION = "15.7.9"
APPROVED_IMAGE_OS = "macos15"
APPROVED_RUNNER_IMAGE_OS = "macos-15-arm64"
APPROVED_IMAGE_VERSION = "20260907.0337.1"
APPROVED_ARCHITECTURE = "arm64"
SANDBOX_EXEC_PATH = "/usr/bin/sandbox-exec"
SW_VERS_PATH = "/usr/bin/sw_vers"
PFCTL_PATH = "/sbin/pfctl"
PF_CONFIG_PATH = "/private" + "/etc/pf.conf"
PF_ANCHOR = "com.apple/ci-probe"
PF_PARENT_ANCHOR = "com.apple/*"
MAX_COMMAND_OUTPUT = 65536
MAX_PF_CONFIG = 262144
COMMAND_TIMEOUT_SECONDS = 10

_PF_RULE_SHAPES = (
    ("inet", "tcp"),
    ("inet", "udp"),
    ("inet6", "tcp"),
    ("inet6", "udp"),
)
_PF_RULE_PATTERN = re.compile(
    r"^block drop out quick (inet6|inet) proto (tcp|udp) all user (?:= )?([0-9]+)$"
)
_PF_PARENT_CONFIG_PATTERN = re.compile(
    r'^\s*anchor\s+"' + re.escape(PF_PARENT_ANCHOR) + r'"(?:\s+all)?\s*$'
)
_PF_PARENT_LIVE_PATTERN = re.compile(
    r'^\s*anchor\s+"' + re.escape(PF_PARENT_ANCHOR) + r'"\s+all\s*$'
)
_PF_PARENT_DECLARATION_PATTERN = re.compile(
    r'^\s*anchor\s+"' + re.escape(PF_PARENT_ANCHOR) + r'"(?:\s|$)'
)
_PF_TOKEN_PATTERN = re.compile(r"(?im)^\s*Token\s*:\s*([0-9]+)\s*$")
_COUNTER_PATTERN = re.compile(
    r"^\s*\[\s*Evaluations:\s*([0-9]+)\s+Packets:\s*([0-9]+)\s+"
    r"Bytes:\s*([0-9]+)(?:\s+States:\s*[0-9]+)?\s*\]\s*$"
)
_ANCHOR_RULE_PATTERN = re.compile(r"(?m)^@([0-9]+)\s+(.+?)\s*$")


class GuardError(RuntimeError):
    """A sanitized refusal with no host diagnostic text."""

    _REASONS = frozenset(
        (
            "platform_unapproved",
            "preflight_unavailable",
            "pf_unavailable",
            "pf_rules_unexpected",
            "cleanup_incomplete",
        )
    )

    def __init__(self, reason: str):
        self.reason = reason if reason in self._REASONS else "preflight_unavailable"
        super().__init__(self.reason)


@dataclass(frozen=True)
class PlatformIdentity:
    product_version: str
    image_os: str
    runner_image_os: str
    image_version: str
    architecture: str

    def as_dict(self):
        return {
            "product_version": self.product_version,
            "image_os": self.image_os,
            "runner_image_os": self.runner_image_os,
            "image_version": self.image_version,
            "architecture": self.architecture,
        }


def _clean_environment():
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _run_command(argv, *, timeout=COMMAND_TIMEOUT_SECONDS):
    try:
        result = subprocess.run(
            [str(part) for part in argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_clean_environment(),
            timeout=timeout,
            check=False,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise GuardError("preflight_unavailable") from None
    if len(result.stdout) > MAX_COMMAND_OUTPUT or len(result.stderr) > MAX_COMMAND_OUTPUT:
        raise GuardError("preflight_unavailable")
    return result


def _validate_directory_metadata(metadata):
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        raise GuardError("preflight_unavailable")


def _validate_file_metadata(metadata, *, executable):
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or (executable and not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    ):
        raise GuardError("preflight_unavailable")


def _check_trusted_system_file(path, *, executable):
    requested = Path(path)
    try:
        if not requested.is_absolute() or ".." in requested.parts:
            raise ValueError
        resolved = requested.resolve(strict=True)
        if resolved.as_posix() != requested.as_posix():
            raise ValueError
        directories = tuple(reversed(resolved.parents))
        for directory in directories:
            _validate_directory_metadata(directory.lstat())
        _validate_file_metadata(resolved.lstat(), executable=executable)
        if executable:
            readonly_flag = getattr(os, "ST_RDONLY", None)
            if readonly_flag is None or not os.statvfs(resolved).f_flag & readonly_flag:
                raise ValueError
    except GuardError:
        raise
    except BaseException:
        raise GuardError("preflight_unavailable") from None


def _identity_from_host():
    if platform.system() != "Darwin" or platform.machine() != APPROVED_ARCHITECTURE:
        raise GuardError("platform_unapproved")

    _check_trusted_system_file(SANDBOX_EXEC_PATH, executable=True)
    _check_trusted_system_file(SW_VERS_PATH, executable=True)
    _check_trusted_system_file(PFCTL_PATH, executable=True)
    _check_trusted_system_file(PF_CONFIG_PATH, executable=False)

    product = _run_command((SW_VERS_PATH, "-productVersion"), timeout=5)
    if product.returncode != 0 or product.stderr:
        raise GuardError("preflight_unavailable")
    try:
        product_version = product.stdout.decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        raise GuardError("preflight_unavailable") from None
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", product_version) is None:
        raise GuardError("preflight_unavailable")

    identity = PlatformIdentity(
        product_version=product_version,
        image_os=os.environ.get("ImageOS", ""),
        runner_image_os=APPROVED_RUNNER_IMAGE_OS,
        image_version=os.environ.get("ImageVersion", ""),
        architecture=platform.machine(),
    )
    if identity != PlatformIdentity(
        product_version=APPROVED_PRODUCT_VERSION,
        image_os=APPROVED_IMAGE_OS,
        runner_image_os=APPROVED_RUNNER_IMAGE_OS,
        image_version=APPROVED_IMAGE_VERSION,
        architecture=APPROVED_ARCHITECTURE,
    ):
        raise GuardError("platform_unapproved")
    return identity


def check_platform():
    """Return the exact approved host identity after trusted-tool checks."""
    return _identity_from_host()


def _pfctl(argv):
    result = _run_command((PFCTL_PATH, *argv))
    if result.returncode != 0:
        raise GuardError("pf_unavailable")
    return result.stdout, result.stderr


def _read_pf_config():
    path = Path(PF_CONFIG_PATH)
    try:
        metadata = path.lstat()
        _validate_file_metadata(metadata, executable=False)
        payload = path.read_bytes()
        if len(payload) > MAX_PF_CONFIG:
            raise ValueError
        text = payload.decode("utf-8", "strict")
    except GuardError:
        raise
    except BaseException:
        raise GuardError("pf_unavailable") from None
    return text


def _has_parent_anchor(text):
    comment = chr(35)
    declarations = []
    for line in text.splitlines():
        active = line.split(comment, 1)[0]
        if _PF_PARENT_DECLARATION_PATTERN.match(active):
            declarations.append(active)
    return (
        len(declarations) == 1
        and _PF_PARENT_CONFIG_PATTERN.fullmatch(declarations[0]) is not None
    )


def _live_parent_is_reachable(text):
    comment = chr(35)
    active_lines = tuple(
        line.split(comment, 1)[0].strip()
        for line in text.splitlines()
        if line.split(comment, 1)[0].strip()
    )
    anchors = tuple(
        index for index, line in enumerate(active_lines)
        if _PF_PARENT_DECLARATION_PATTERN.match(line)
    )
    if len(anchors) != 1:
        return False
    anchor_index = anchors[0]
    if _PF_PARENT_LIVE_PATTERN.fullmatch(active_lines[anchor_index]) is None:
        return False
    for line in active_lines[:anchor_index]:
        if re.match(r"^pass\b", line) and re.search(r"\bquick\b", line):
            return False
    return True


def _has_live_parent_anchor():
    rules, _ = _pfctl(("-sr",))
    try:
        text = rules.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise GuardError("pf_unavailable") from None
    return _live_parent_is_reachable(text)


def _rules_for_uid(uid):
    return tuple(
        "block drop out quick " + family + " proto " + protocol + " all user = " + str(uid)
        for family, protocol in _PF_RULE_SHAPES
    )


def _parse_rule(line):
    normalized = " ".join(line.strip().split())
    match = _PF_RULE_PATTERN.fullmatch(normalized)
    if match is None:
        raise GuardError("pf_rules_unexpected")
    family, protocol, uid_text = match.groups()
    return family, protocol, int(uid_text)


def _rendered_rules(payload):
    try:
        text = payload.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise GuardError("pf_rules_unexpected") from None
    lines = tuple(line.strip() for line in text.splitlines() if line.strip())
    return tuple(_parse_rule(line) for line in lines)


def _expected_rule_keys(uid):
    return tuple((family, protocol, uid) for family, protocol in _PF_RULE_SHAPES)


def _read_counters(payload, expected_keys):
    try:
        text = payload.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise GuardError("pf_rules_unexpected") from None

    lines = text.splitlines()
    records = []
    for index, line in enumerate(lines):
        match = _ANCHOR_RULE_PATTERN.fullmatch(line)
        if match is not None:
            records.append((index, int(match.group(1)), _parse_rule(match.group(2))))

    counter_hints = any(
        "Evaluations:" in line or "Packets:" in line or "Bytes:" in line
        for line in lines
    )
    if not records and not counter_hints:
        return None
    if records and tuple(key for _, _, key in records) != expected_keys:
        raise GuardError("pf_rules_unexpected")
    if not counter_hints:
        return None
    if not records:
        raise GuardError("pf_rules_unexpected")
    if tuple(number for _, number, _ in records) != tuple(range(len(expected_keys))):
        raise GuardError("pf_rules_unexpected")
    if any(
        "Evaluations:" in line or "Packets:" in line or "Bytes:" in line
        for line in lines[:records[0][0]]
    ):
        raise GuardError("pf_rules_unexpected")

    counters = []
    for record_index, (line_index, _, _) in enumerate(records):
        next_rule_index = (
            records[record_index + 1][0] if record_index + 1 < len(records) else len(lines)
        )
        counter_rows = []
        for counter_line in lines[line_index + 1:next_rule_index]:
            match = _COUNTER_PATTERN.fullmatch(counter_line)
            if match is not None:
                counter_rows.append(tuple(int(value) for value in match.groups()))
            elif any(label in counter_line for label in ("Evaluations:", "Packets:", "Bytes:")):
                raise GuardError("pf_rules_unexpected")
        if len(counter_rows) != 1:
            raise GuardError("pf_rules_unexpected")
        counters.append(counter_rows[0])
    if len(counters) != len(expected_keys):
        raise GuardError("pf_rules_unexpected")
    return tuple(counters)


def _write_rules_file(path, rules):
    requested = Path(path)
    try:
        if not requested.is_absolute() or ".." in requested.parts or not requested.name:
            raise ValueError
        parent = requested.parent.resolve(strict=True)
        if parent != requested.parent and requested.parent.is_absolute() and ".." not in requested.parent.parts:
            requested = parent / requested.name
        _validate_directory_metadata(parent.lstat())
        target = parent / requested.name
        payload = ("\n".join(rules) + "\n").encode("ascii")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, 0o600)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        metadata = target.lstat()
        _validate_file_metadata(metadata, executable=False)
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError
        return target
    except GuardError:
        raise
    except BaseException:
        raise GuardError("pf_unavailable") from None


def _parse_token(payload):
    try:
        text = payload.decode("ascii", "strict")
    except UnicodeDecodeError:
        return None
    matches = _PF_TOKEN_PATTERN.findall(text)
    if len(matches) != 1:
        return None
    token = matches[0]
    if len(token) > 20 or int(token) <= 0:
        return None
    return token


class PFGuard:
    """Owns one PF anchor load and one PF enable reference token."""

    def __init__(self, uid, token, rules, rules_file, identity):
        self.uid = uid
        self.token = token
        self.rules = tuple(rules)
        self.rules_file = Path(rules_file)
        self.identity = identity
        self.counters = None
        self._token_released = False
        self._closed = False
        self._load_attempted = False

    def verify(self, *, require_hits=False):
        status, _ = _pfctl(("-s", "info"))
        if re.search(rb"(?m)^Status:\s*Enabled\b", status) is None:
            raise GuardError("pf_unavailable")
        if not _has_live_parent_anchor():
            raise GuardError("pf_unavailable")

        rules, _ = _pfctl(("-a", PF_ANCHOR, "-sr"))
        if _rendered_rules(rules) != _expected_rule_keys(self.uid):
            raise GuardError("pf_rules_unexpected")

        verbose, _ = _pfctl(("-a", PF_ANCHOR, "-vvsr"))
        self.counters = _read_counters(verbose, _expected_rule_keys(self.uid))
        if require_hits:
            if self.counters is None or any(
                evaluations == 0 or packets == 0
                for evaluations, packets, _ in self.counters
            ):
                raise GuardError("pf_unavailable")
        return self.counters

    def close(self):
        if self._closed:
            return

        failed = False
        can_flush = False
        try:
            remaining, _ = _pfctl(("-a", PF_ANCHOR, "-sr"))
            if not remaining.strip():
                can_flush = True
            else:
                current = _rendered_rules(remaining)
                if self._load_attempted and current == _expected_rule_keys(self.uid):
                    can_flush = True
                else:
                    failed = True
        except BaseException:
            failed = True

        if can_flush and self._load_attempted:
            try:
                current, _ = _pfctl(("-a", PF_ANCHOR, "-sr"))
                if current.strip():
                    if _rendered_rules(current) == _expected_rule_keys(self.uid):
                        _pfctl(("-a", PF_ANCHOR, "-F", "rules"))
                    else:
                        failed = True
            except BaseException:
                failed = True

        if not self._token_released:
            try:
                _pfctl(("-X", self.token))
                self._token_released = True
            except BaseException:
                failed = True

        try:
            remaining, _ = _pfctl(("-a", PF_ANCHOR, "-sr"))
            if remaining.strip():
                failed = True
        except BaseException:
            failed = True

        if failed:
            raise GuardError("cleanup_incomplete")
        self._closed = True


def install_pf(uid, rules_file):
    """Install and verify only the dedicated probe anchor and its enable token."""
    identity = check_platform()
    if os.geteuid() != 0 or type(uid) is not int or uid <= 0 or uid > 2147483647:
        raise GuardError("pf_unavailable")
    if not _has_parent_anchor(_read_pf_config()) or not _has_live_parent_anchor():
        raise GuardError("pf_unavailable")

    existing, _ = _pfctl(("-a", PF_ANCHOR, "-sr"))
    if existing.strip():
        raise GuardError("pf_rules_unexpected")

    enable = _run_command((PFCTL_PATH, "-E"))
    if enable.returncode != 0:
        raise GuardError("pf_unavailable")
    token = _parse_token(enable.stdout + b"\n" + enable.stderr)
    if token is None:
        raise GuardError("cleanup_incomplete")

    rules = _rules_for_uid(uid)
    guard = PFGuard(uid, token, rules, rules_file, identity)
    try:
        if not _has_parent_anchor(_read_pf_config()) or not _has_live_parent_anchor():
            raise GuardError("pf_unavailable")
        existing, _ = _pfctl(("-a", PF_ANCHOR, "-sr"))
        if existing.strip():
            raise GuardError("pf_rules_unexpected")
        rules_path = _write_rules_file(rules_file, rules)
        guard.rules_file = rules_path
        guard._load_attempted = True
        _pfctl(("-a", PF_ANCHOR, "-f", str(rules_path)))
        guard.verify()
        return guard
    except BaseException:
        try:
            guard.close()
        except BaseException:
            raise GuardError("cleanup_incomplete") from None
        raise
