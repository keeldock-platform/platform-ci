"""Digest-only scanner for a committed log canary.

The canary is a lowercase hexadecimal string of at least 32 random bytes drawn from a
cryptographically secure generator; low-entropy values are refused. The pinned
configuration carries only SHA-256 digests of the canary and of its fixed encodings, never the
value. The scanner slides fixed-width windows over runs of the matching alphabet in the supplied
bytes and compares window digests, so a match is reported as a closed enum and the matched text is
never read back, stored or returned.

Fixed encodings covered, for the canary text and for the decoded canary bytes where noted:

    plain        the canary text itself, case folded
    hex          the hexadecimal encoding of the canary text bytes
    utf16le      the UTF-16LE encoding of the canary text
    base64       standard Base64 of the text bytes, of the UTF-16LE text bytes and of the
                 decoded bytes
    base64url    URL-safe Base64 of the decoded bytes

For a hexadecimal text the standard and URL-safe Base64 of the text bytes, and of the UTF-16LE
text bytes, are always identical strings, because no sextet reaches 62 or 63. Only one form of
each is therefore kept.

Base64 forms are matched at all three alignments, using only the characters fully determined by
the canary, so the value is found inside a larger encoded blob and with padding removed. Windows
are also taken over a view with NUL bytes removed, which folds any UTF-16 text into plain ASCII,
and over a joined view: consecutive lines that consist entirely of Base64 or URL-safe Base64
characters, after removing a leading log timestamp, are concatenated, so wrapped output at any
column width is found. Work on the joined view counts toward the byte and window budgets.
Percent-escaped values are out of scope: the enforced boundary, not this scanner, is the control
for a hostile writer.
"""

import base64
import hashlib
import json
import re
import sys


MIN_TEXT_LENGTH = 64
MAX_TEXT_LENGTH = 256
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_WINDOWS = 24000000
SLICE_BYTES = 1024 * 1024
ABSENT = "absent"
PRESENT = "present"
RESULTS = (ABSENT, PRESENT)
REFUSAL_REASONS = frozenset(("config_invalid", "config_unpinned", "input_invalid", "scan_limit"))
SHIFTS = (0, 1, 2)
FORMS = ("plain", "hex", "utf16le") + tuple(
    encoding + "-" + source + "-" + str(shift)
    for encoding, source in (
        ("base64", "text"), ("base64", "utf16"), ("base64", "bin"), ("base64url", "bin"),
    )
    for shift in SHIFTS
)
MIN_DISTINCT_NIBBLES = 12
JOIN_LIMIT = 1024 * 1024
LINE_LIMIT = 1024 * 1024
TIMESTAMP_RE = re.compile(rb"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z ")
WRAP_LINE_RE = re.compile(rb"[A-Za-z0-9+/_-]+={0,2}")
CONFIG_FIELDS = frozenset(("digests", "text_length"))
TEXT_RE = re.compile(r"(?:[0-9a-f]{2}){32,128}")
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
ALPHABETS = {
    "hex": b"[0-9A-Fa-f]",
    "b64": b"[A-Za-z0-9+/]",
    "b64url": b"[A-Za-z0-9_-]",
    "utf16": b"(?:[0-9A-Fa-f]\\x00)",
}
PINNED_CONFIG = None


class ScanRefusal(Exception):
    def __init__(self, reason):
        self.reason = reason if type(reason) is str and reason in REFUSAL_REASONS else "input_invalid"
        super().__init__(self.reason)


def _interior(data, shift, url):
    encoder = base64.urlsafe_b64encode if url else base64.b64encode
    encoded = encoder(b"\x00" * shift + data)
    start = -(-8 * shift // 6)
    stop = (8 * (shift + len(data))) // 6
    return encoded[start:stop]


def _form_data(label, text):
    raw_text = text.encode("ascii")
    if label == "plain":
        return raw_text
    if label == "hex":
        return raw_text.hex().encode("ascii")
    if label == "utf16le":
        return text.encode("utf-16-le")
    encoding, source, shift = label.split("-")
    if source == "text":
        data = raw_text
    elif source == "utf16":
        data = text.encode("utf-16-le")
    else:
        data = bytes.fromhex(text)
    return _interior(data, int(shift), encoding == "base64url")


def _form_class(label):
    if label in ("plain", "hex"):
        return "hex"
    if label == "utf16le":
        return "utf16"
    return "b64url" if label.startswith("base64url-") else "b64"


def compute_config(text):
    """Return the pinned digest configuration for a canary value."""
    if (type(text) is not str or TEXT_RE.fullmatch(text) is None
            or len(set(text)) < MIN_DISTINCT_NIBBLES):
        raise ScanRefusal("config_invalid")
    return {
        "digests": {
            label: hashlib.sha256(_form_data(label, text)).hexdigest() for label in FORMS
        },
        "text_length": len(text),
    }


def pinned_config():
    if PINNED_CONFIG is None:
        raise ScanRefusal("config_unpinned")
    return PINNED_CONFIG


class _Group:
    def __init__(self, alphabet, width):
        self.alphabet = alphabet
        self.width = width
        self.digests = set()
        count = width // 2 if alphabet == "utf16" else width
        self.pattern = re.compile(ALPHABETS[alphabet] + b"{" + str(count).encode("ascii") + b",}")


def _plan(config):
    if (type(config) is not dict or set(config) != CONFIG_FIELDS
            or type(config["text_length"]) is not int
            or not MIN_TEXT_LENGTH <= config["text_length"] <= MAX_TEXT_LENGTH
            or config["text_length"] % 2 != 0
            or type(config["digests"]) is not dict
            or set(config["digests"]) != set(FORMS)):
        raise ScanRefusal("config_invalid")
    values = list(config["digests"].values())
    if any(type(value) is not str or DIGEST_RE.fullmatch(value) is None for value in values):
        raise ScanRefusal("config_invalid")
    dummy = "00" * (config["text_length"] // 2)
    groups = {}
    for label in FORMS:
        alphabet = _form_class(label)
        width = len(_form_data(label, dummy))
        group = groups.get((alphabet, width))
        if group is None:
            group = groups[(alphabet, width)] = _Group(alphabet, width)
        group.digests.add(bytes.fromhex(config["digests"][label]))
    return tuple(groups[key] for key in sorted(groups))


class Scanner:
    """Incremental scanner; chunk boundaries never hide a canary."""

    def __init__(self, config):
        self._groups = _plan(config)
        self._carry_length = max(group.width for group in self._groups)
        self._raw_carry = b""
        self._plain_carry = b""
        self._saw_nul = False
        self._total = 0
        self._windows = 0
        self._tail = b""
        self._join = b""
        self._join_lines = 0
        self._finished = False
        self.present = False

    def _flush_join(self, keep):
        if self._join_lines >= 2 and self._join and not self.present:
            self._total += len(self._join)
            if self._total > MAX_TOTAL_BYTES:
                raise ScanRefusal("scan_limit")
            if self._scan(self._join, False):
                self.present = True
        if keep:
            self._join = self._join[-(self._carry_length - 1):]
            self._join_lines = 2
        else:
            self._join = b""
            self._join_lines = 0

    def _wrap_line(self, line):
        if line.endswith(b"\r"):
            line = line[:-1]
        stamp = TIMESTAMP_RE.match(line)
        if stamp is not None:
            line = line[stamp.end():]
        if WRAP_LINE_RE.fullmatch(line) is None:
            self._flush_join(False)
            return
        self._join += line
        self._join_lines += 1
        if len(self._join) > JOIN_LIMIT:
            self._flush_join(True)

    def finish(self):
        """Process the last partial line and any joined run; idempotent."""
        if self._finished:
            return
        self._finished = True
        if self.present:
            return
        if self._tail:
            self._wrap_line(self._tail)
            self._tail = b""
        self._flush_join(False)

    def _scan(self, buffer, include_utf16):
        for group in self._groups:
            utf16 = group.alphabet == "utf16"
            if utf16 and not include_utf16:
                continue
            step = 2 if utf16 else 1
            fold = group.alphabet in ("hex", "utf16")
            for match in group.pattern.finditer(buffer):
                run = match.group()
                if fold:
                    run = run.lower()
                limit = len(run) - group.width + 1
                self._windows += (limit + step - 1) // step
                if self._windows > MAX_WINDOWS:
                    raise ScanRefusal("scan_limit")
                for index in range(0, limit, step):
                    if hashlib.sha256(run[index:index + group.width]).digest() in group.digests:
                        return True
        return False

    def feed(self, chunk):
        if type(chunk) is str:
            chunk = chunk.encode("utf-8", "replace")
        if type(chunk) is not bytes:
            raise ScanRefusal("input_invalid")
        self._total += len(chunk)
        if self._total > MAX_TOTAL_BYTES:
            raise ScanRefusal("scan_limit")
        if self.present:
            return
        keep = self._carry_length - 1
        previous = self._raw_carry
        raw = previous + chunk
        self._raw_carry = raw[-keep:]
        found = self._scan(raw, True)
        if not self._saw_nul and b"\x00" in chunk:
            self._saw_nul = True
            self._plain_carry = previous
        if self._saw_nul and not found:
            plain = self._plain_carry + chunk.translate(None, b"\x00")
            self._plain_carry = plain[-keep:]
            found = self._scan(plain, False)
        if found:
            self.present = True
            return
        parts = (self._tail + chunk).split(b"\n")
        self._tail = parts.pop()
        for line in parts:
            self._wrap_line(line)
            if self.present:
                return
        if len(self._tail) > LINE_LIMIT:
            self._wrap_line(self._tail)
            self._tail = b""

    def result(self):
        return PRESENT if self.present else ABSENT


def scan_chunks(chunks, config):
    scanner = Scanner(config)
    for chunk in chunks:
        scanner.feed(chunk)
        if scanner.present:
            break
    scanner.finish()
    return scanner.result()


def scan_bytes(data, config):
    """Return present or absent for one log, in bounded slices."""
    if type(data) is str:
        data = data.encode("utf-8", "replace")
    if type(data) is not bytes:
        raise ScanRefusal("input_invalid")
    return scan_chunks(
        (data[start:start + SLICE_BYTES] for start in range(0, max(len(data), 1), SLICE_BYTES)),
        config,
    )


def scan_texts(texts, config):
    """Return present when any independent text contains the canary."""
    result = ABSENT
    for text in texts:
        if scan_bytes(text, config) == PRESENT:
            result = PRESENT
    return result


def main(arguments=None, stdin=None, stdout=None):
    """Offline helper: read one canary line from standard input, print the pinned configuration."""
    actual = sys.argv[1:] if arguments is None else arguments
    source = sys.stdin if stdin is None else stdin
    sink = sys.stdout if stdout is None else stdout
    if actual != ["compute"]:
        return 2
    try:
        text = source.readline().rstrip("\n")
        config = compute_config(text)
        sink.write(json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n")
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
