"""Attach the fixed SemVer child to its supervisor-created cgroup before dropping uid."""

import os
import resource
import stat
import sys


SET_PRIV_PREFIX = [
    "/usr/bin/setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
    "--no-new-privs", "--bounding-set=-all", "--",
]
SEMVER_BINARY = "/prepared/devlane-tools/cargo-semver-checks"
SEMVER_ARGUMENTS = [
    SEMVER_BINARY, "check-release", "--manifest-path", "/workspace/source/runtime/Cargo.toml",
    "--baseline-root", "/workspace/semver-baseline/runtime", "--workspace", "--all-features",
    "--target", "x86_64-unknown-linux-gnu",
]


def main(arguments=None, *, write=os.write, execve=os.execve):
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    if (os.geteuid() != 0 or len(arguments) < 3 or arguments[0] != "--cgroup-fd"
            or not arguments[1].isascii() or not arguments[1].isdecimal()
            or arguments[2] != "--"):
        return 125
    descriptor = int(arguments[1])
    if descriptor < 3 or descriptor > 1024:
        return 125
    command = arguments[3:]
    if command[:len(SET_PRIV_PREFIX)] != SET_PRIV_PREFIX:
        return 125
    if command[len(SET_PRIV_PREFIX):] != SEMVER_ARGUMENTS:
        return 125
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            return 125
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        resource.setrlimit(resource.RLIMIT_NPROC, (1024, 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (3600, 3600))
        os.umask(0o077)
        payload = (str(os.getpid()) + "\n").encode("ascii")
        if write(descriptor, payload) != len(payload):
            return 125
        os.close(descriptor)
        execve(command[0], command, os.environ.copy())
    except (OSError, ValueError, OverflowError):
        return 125
    return 125


if __name__ == "__main__":
    raise SystemExit(main())
