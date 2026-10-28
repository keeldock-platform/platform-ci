import argparse
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ATTESTATION_PERMISSION_PROFILE = {
    "id-token": "write",
    "attestations": "write",
}
ATTESTER_PERMISSION_PROFILE = {
    "id-token": "write",
    "attestations": "write",
    "actions": "read",
}
ATTESTER_JOB_ID = "capsule-attester"
ATTESTER_NEEDS = ("linux-fetch-encrypt",)
ATTESTER_RUNNER = "ubuntu-24.04"
ATTESTER_TRIGGER = "dispatch-main"
ATTESTER_JOB_FIELDS = frozenset(("id", "needs", "runs-on", "checkout", "trigger"))
ATTESTATION_ACTION_SHA = "1e69f48acb82d1966a394da916b4c1698aa569d6"
SYNTHETIC_PATHS = (".fixture/secret.txt", "src/fixture.txt")
MAX_PUBLIC_FILE_BYTES = 65536
MAX_PUBLIC_OUTPUTS = 256
REPARSE_POINT_ATTRIBUTE = 0x400
READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_BINARY", 0)
)
CREATE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_BINARY", 0)
)


class HandoffRefusal(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SyntheticTree:
    __slots__ = ("root", "canary", "commit_sha")

    def __init__(self, root, canary, commit_sha):
        self.root = Path(root)
        self.canary = canary
        self.commit_sha = commit_sha

    def safe_summary(self):
        return {
            "status": "generated",
            "entries": len(SYNTHETIC_PATHS),
            "canary": "local-only",
        }

    def __repr__(self):
        return "SyntheticTree(<local-only>)"


def validate_attestation_permissions(value):
    return type(value) is dict and value == ATTESTATION_PERMISSION_PROFILE


def validate_attester_permissions(value, job):
    if type(value) is not dict or value != ATTESTER_PERMISSION_PROFILE:
        return False
    if type(job) is not dict or set(job) != ATTESTER_JOB_FIELDS:
        return False
    needs = job["needs"]
    return (
        job["id"] == ATTESTER_JOB_ID
        and type(job["id"]) is str
        and type(needs) in (list, tuple)
        and tuple(needs) == ATTESTER_NEEDS
        and type(job["runs-on"]) is str
        and job["runs-on"] == ATTESTER_RUNNER
        and job["checkout"] is False
        and type(job["trigger"]) is str
        and job["trigger"] == ATTESTER_TRIGGER
    )


def _is_reparse(status):
    attributes = getattr(status, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", REPARSE_POINT_ATTRIBUTE))


def _reparse_at(path):
    try:
        return _is_reparse(os.lstat(path))
    except OSError:
        return False


def create_synthetic_git_tree(root):
    root = Path(root)
    if root.is_symlink() or _reparse_at(root):
        raise HandoffRefusal("synthetic-root-invalid")
    try:
        root.mkdir(parents=True, exist_ok=True)
        if any(root.iterdir()):
            raise HandoffRefusal("synthetic-root-not-empty")
    except OSError:
        raise HandoffRefusal("synthetic-root-invalid")

    canary = "synthetic-" + secrets.token_hex(32)
    (root / ".fixture").mkdir()
    (root / "src").mkdir()
    (root / ".fixture/secret.txt").write_bytes(
        ("synthetic secret canary=" + canary + "\n").encode("ascii")
    )
    (root / "src/fixture.txt").write_bytes(
        ("synthetic source payload=" + canary + "\n").encode("ascii")
    )

    try:
        with tempfile.TemporaryDirectory(prefix="handoff-git-config-") as config_root:
            config_dir = Path(config_root)
            global_config = config_dir / "global"
            global_config.write_bytes(b"")
            template_dir = config_dir / "templates"
            hooks_dir = config_dir / "hooks"
            template_dir.mkdir()
            hooks_dir.mkdir()
            environment = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("GIT_")
                and key not in ("SSH_AUTH_SOCK", "SSH_ASKPASS")
            }
            environment.update(
                {
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": str(global_config),
                    "GIT_TEMPLATE_DIR": str(template_dir),
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_AUTHOR_NAME": "Synthetic Fixture",
                    "GIT_AUTHOR_EMAIL": "synthetic-fixture@example.invalid",
                    "GIT_COMMITTER_NAME": "Synthetic Fixture",
                    "GIT_COMMITTER_EMAIL": "synthetic-fixture@example.invalid",
                }
            )
            _run_git(root, ("init", "--quiet"), environment)
            _run_git(root, ("config", "--local", "core.autocrlf", "false"), environment)
            _run_git(root, ("config", "--local", "core.hooksPath", str(hooks_dir)), environment)
            _run_git(root, ("config", "--local", "commit.gpgsign", "false"), environment)
            _run_git(root, ("add", "--", *SYNTHETIC_PATHS), environment)
            _run_git(
                root,
                ("commit", "--quiet", "-m", "Add generated synthetic fixture"),
                environment,
            )
            commit_sha = _run_git(
                root,
                ("rev-parse", "--verify", "HEAD"),
                environment,
            )
            paths = tuple(
                _run_git(root, ("ls-tree", "-r", "--name-only", "HEAD"), environment).splitlines()
            )
            if paths != SYNTHETIC_PATHS or re.fullmatch(r"[a-f0-9]{40}", commit_sha) is None:
                raise HandoffRefusal("synthetic-repository-invalid")
    except HandoffRefusal:
        raise
    except (OSError, subprocess.SubprocessError):
        raise HandoffRefusal("synthetic-repository-failed")

    return SyntheticTree(root, canary, commit_sha)


def _run_git(root, arguments, environment):
    result = subprocess.run(
        ["git", *arguments],
        cwd=str(root),
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.stdout.strip()


def scan_public_outputs(paths, canary):
    if type(canary) is not str or re.fullmatch(r"synthetic-[a-f0-9]{64}", canary) is None:
        raise HandoffRefusal("canary-invalid")
    if type(paths) not in (list, tuple) or not 0 < len(paths) <= MAX_PUBLIC_OUTPUTS:
        raise HandoffRefusal("public-output-set-invalid")
    needle = canary.encode("ascii")
    for candidate in paths:
        if not isinstance(candidate, (str, os.PathLike)):
            raise HandoffRefusal("public-output-set-invalid")
        path = Path(candidate)
        try:
            path_before = os.lstat(path)
        except OSError:
            raise HandoffRefusal("public-output-unreadable")
        if not stat.S_ISREG(path_before.st_mode) or _is_reparse(path_before):
            raise HandoffRefusal("public-output-invalid")
        if path_before.st_size > MAX_PUBLIC_FILE_BYTES:
            raise HandoffRefusal("public-output-too-large")
        try:
            descriptor = os.open(str(path), READ_FLAGS)
        except OSError:
            raise HandoffRefusal("public-output-unreadable")
        try:
            source = os.fdopen(descriptor, "rb")
        except OSError:
            os.close(descriptor)
            raise HandoffRefusal("public-output-unreadable")
        try:
            with source:
                opened_before = os.fstat(source.fileno())
                if not stat.S_ISREG(opened_before.st_mode) or _is_reparse(opened_before):
                    raise HandoffRefusal("public-output-invalid")
                payload = source.read(MAX_PUBLIC_FILE_BYTES + 1)
                opened_after = os.fstat(source.fileno())
            path_after = os.lstat(path)
        except OSError:
            raise HandoffRefusal("public-output-unreadable")
        if not stat.S_ISREG(opened_after.st_mode) or not stat.S_ISREG(path_after.st_mode):
            raise HandoffRefusal("public-output-invalid")
        if (
            len(payload) > MAX_PUBLIC_FILE_BYTES
            or opened_before.st_size > MAX_PUBLIC_FILE_BYTES
            or opened_after.st_size > MAX_PUBLIC_FILE_BYTES
            or path_after.st_size > MAX_PUBLIC_FILE_BYTES
        ):
            raise HandoffRefusal("public-output-too-large")
        if not _same_file(path_before, opened_before) or not _same_file(opened_after, path_after):
            raise HandoffRefusal("public-output-changed")
        if not _same_metadata(opened_before, opened_after) or len(payload) != opened_after.st_size:
            raise HandoffRefusal("public-output-changed")
        if needle in payload:
            raise HandoffRefusal("public-canary-present")
    return True


def _same_file(left, right):
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _same_metadata(left, right):
    fields = ("st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    return _same_file(left, right) and all(
        getattr(left, field) == getattr(right, field) for field in fields
    )


def safe_gate_report(stage, reason):
    allowed = {
        "windows_receiver": {
            "windows-cng-key-lifecycle-unproven",
        },
        "linux_capsule": {
            "receiver-key-artifact-unverified",
            "same-run-artifact-visibility-unproven",
            "capsule-crypto-backend-unproven",
        },
    }
    if type(stage) is not str or type(reason) is not str or reason not in allowed.get(stage, set()):
        raise HandoffRefusal("report-class-invalid")
    return {
        "schema_version": 1,
        "stage": stage,
        "status": "blocked",
        "reason": reason,
    }


def write_safe_gate_report(path, stage, reason):
    report = safe_gate_report(stage, reason)
    destination = Path(path)
    if destination.is_symlink() or _reparse_at(destination):
        raise HandoffRefusal("report-path-invalid")
    payload = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    try:
        descriptor = os.open(str(destination), CREATE_FLAGS, 0o600)
    except FileExistsError:
        raise HandoffRefusal("report-path-invalid")
    except OSError:
        raise HandoffRefusal("report-write-failed")
    try:
        target = os.fdopen(descriptor, "wb")
    except OSError:
        os.close(descriptor)
        raise HandoffRefusal("report-write-failed")
    try:
        with target:
            target.write(payload)
    except OSError:
        raise HandoffRefusal("report-write-failed")
    return report


def refuse_unproven_gate(gate):
    reasons = {
        "receiver-key": "windows-cng-key-lifecycle-unproven",
        "capsule": "same-run-artifact-visibility-unproven",
        "sandbox": "windows-confinement-unproven",
    }
    reason = reasons.get(gate)
    if reason is None:
        raise HandoffRefusal("gate-unknown")
    raise HandoffRefusal(reason)


class _QuietParser(argparse.ArgumentParser):
    def error(self, message):
        raise HandoffRefusal("synthetic-input-invalid")


def _main(arguments):
    parser = _QuietParser(add_help=False)
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", add_help=False)
    create.add_argument("--root", required=True)

    report = commands.add_parser("report", add_help=False)
    report.add_argument("--path", required=True)
    report.add_argument("--stage", required=True)
    report.add_argument("--reason", required=True)

    refuse = commands.add_parser("refuse", add_help=False)
    refuse.add_argument("--gate", required=True)

    options = parser.parse_args(arguments)
    if options.command == "create":
        create_synthetic_git_tree(options.root)
        print(
            "handoff=synthetic-tree status=generated entries="
            + str(len(SYNTHETIC_PATHS))
            + " canary=local-only"
        )
        return 0
    if options.command == "report":
        write_safe_gate_report(options.path, options.stage, options.reason)
        print("handoff=gate-report status=blocked")
        return 0
    refuse_unproven_gate(options.gate)
    return 1


def main(arguments=None):
    try:
        return _main(sys.argv[1:] if arguments is None else arguments)
    except HandoffRefusal as refusal:
        print("handoff=refused reason=" + refusal.code)
        return 1
    except Exception:
        print("handoff=refused reason=synthetic-input-invalid")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
