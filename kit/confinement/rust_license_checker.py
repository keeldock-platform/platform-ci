"""Validate lock-to-archive license evidence before the pinned cargo-deny run."""

import re
import sys


HASH_RE = re.compile(r"[a-f0-9]{64}\Z")
NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9.+_-]{1,128}\Z")
MAX_BYTES = 12_000_000


def _refuse():
    return 1


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments != ["--stdin-protocol"]:
        return _refuse()
    payload = sys.stdin.buffer.read(MAX_BYTES + 1)
    if not payload or len(payload) > MAX_BYTES:
        return _refuse()
    try:
        lines = payload.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        return _refuse()
    if not lines or not re.fullmatch(r"KDL-LICENSE-SCOPE\t1\t[1-9][0-9]{0,4}", lines[0]):
        return _refuse()
    count = int(lines[0].rsplit("\t", 1)[1])
    if len(lines) != 1 + 2 * count:
        return _refuse()
    lock = []
    receipts = []
    for line in lines[1:1 + count]:
        fields = line.split("\t")
        if (len(fields) != 4 or fields[0] != "lock" or NAME_RE.fullmatch(fields[1]) is None
                or VERSION_RE.fullmatch(fields[2]) is None or HASH_RE.fullmatch(fields[3]) is None):
            return _refuse()
        lock.append(tuple(fields[1:]))
    for line in lines[1 + count:]:
        fields = line.split("\t")
        if (len(fields) != 5 or fields[0] != "receipt" or NAME_RE.fullmatch(fields[1]) is None
                or VERSION_RE.fullmatch(fields[2]) is None or HASH_RE.fullmatch(fields[3]) is None
                or not fields[4] or len(fields[4]) > 16384):
            return _refuse()
        receipts.append(tuple(fields[1:4]))
    if lock != receipts or lock != sorted(lock) or len(set(lock)) != count:
        return _refuse()
    sys.stdout.buffer.write(b"result=conditional-pass authenticated=no\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
