"""Shared monotonic budget for a single encrypted dev-lane job."""

import argparse
import json
import math
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path


TERM_GRACE_SECONDS = 2
KILL_REAP_SECONDS = 3


class DeadlineRefusal(ValueError):
    pass


def _read(path):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024:
            raise DeadlineRefusal("deadline-file-invalid")
        raw = os.read(descriptor, 1025)
        if len(raw) != metadata.st_size or len(raw) > 1024:
            raise DeadlineRefusal("deadline-file-invalid")
    finally:
        os.close(descriptor)
    value = json.loads(raw.decode("ascii", "strict"))
    if (type(value) is not dict or set(value) != {"schema", "work_deadline", "cleanup_reserve", "job_seconds"}
            or value["schema"] != 1 or type(value["work_deadline"]) not in (int, float)
            or not math.isfinite(value["work_deadline"])
            or type(value["cleanup_reserve"]) is not int or type(value["job_seconds"]) is not int
            or value["cleanup_reserve"] < 1 or value["job_seconds"] < value["cleanup_reserve"]):
        raise DeadlineRefusal("deadline-file-invalid")
    return value


def remaining(path, now=None):
    value = _read(path)
    seconds = value["work_deadline"] - (time.monotonic() if now is None else now)
    if seconds <= 0:
        raise DeadlineRefusal("total-deadline-exhausted")
    return seconds


def _started_at(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64:
            raise DeadlineRefusal("deadline-start-invalid")
        raw = os.read(descriptor, 65)
        if len(raw) != metadata.st_size:
            raise DeadlineRefusal("deadline-start-invalid")
        value = float(raw.decode("ascii", "strict"))
        if not math.isfinite(value) or value <= 0 or value > time.monotonic():
            raise DeadlineRefusal("deadline-start-invalid")
        return value
    except (UnicodeError, ValueError):
        raise DeadlineRefusal("deadline-start-invalid") from None
    finally:
        os.close(descriptor)


def create(path, budget_seconds, cleanup_reserve_seconds, job_seconds, now=None, started_at_file=None):
    if (type(budget_seconds) is not int or type(cleanup_reserve_seconds) is not int
            or type(job_seconds) is not int or budget_seconds < 1
            or cleanup_reserve_seconds < 1 or budget_seconds + cleanup_reserve_seconds > job_seconds):
        raise DeadlineRefusal("deadline-budget-invalid")
    start = _started_at(started_at_file) if started_at_file is not None else (
        time.monotonic() if now is None else now
    )
    if type(start) not in (float, int) or not math.isfinite(start) or start <= 0:
        raise DeadlineRefusal("deadline-start-invalid")
    if time.monotonic() >= start + budget_seconds:
        raise DeadlineRefusal("total-deadline-exhausted")
    payload = json.dumps({
        "schema": 1,
        "work_deadline": start + budget_seconds,
        "cleanup_reserve": cleanup_reserve_seconds,
        "job_seconds": job_seconds,
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


def _terminate_group(process):
    started = time.monotonic()
    sent_term = False
    try:
        os.killpg(process.pid, signal.SIGTERM)
        sent_term = True
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=TERM_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    finally:
        if sent_term:
            left = TERM_GRACE_SECONDS - (time.monotonic() - started)
            if left > 0:
                time.sleep(left)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            process.wait(timeout=KILL_REAP_SECONDS)


def run(path, argv):
    budget = remaining(path)
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        return 127
    completed = False
    try:
        try:
            code = process.wait(timeout=budget)
            completed = True
            return code
        except subprocess.TimeoutExpired:
            _terminate_group(process)
            completed = True
            return 124
    finally:
        if not completed:
            _terminate_group(process)


def main(argv=None):
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="operation", required=True)
    create_parser = commands.add_parser("create")
    create_parser.add_argument("--file", required=True)
    create_parser.add_argument("--budget-seconds", type=int, required=True)
    create_parser.add_argument("--cleanup-reserve-seconds", type=int, required=True)
    create_parser.add_argument("--job-seconds", type=int, required=True)
    create_parser.add_argument("--started-at-file")
    for operation in ("check", "remaining"):
        check_parser = commands.add_parser(operation)
        check_parser.add_argument("--file", required=True)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--file", required=True)
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        if args.operation == "create":
            create(args.file, args.budget_seconds, args.cleanup_reserve_seconds,
                   args.job_seconds, started_at_file=args.started_at_file)
            return 0
        if args.operation == "check":
            remaining(args.file)
            return 0
        if args.operation == "remaining":
            print("deadline_remaining_seconds=%d" % int(remaining(args.file)))
            return 0
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            raise DeadlineRefusal("deadline-command-invalid")
        return run(args.file, command)
    except (DeadlineRefusal, OSError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        print("devlane_deadline_refusal=" + (error.args[0] if isinstance(error, DeadlineRefusal) else "deadline-failed"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
