"""Online dependency preparation in a throwaway PID/mount/IPC boundary.

This module runs only on Linux. It consumes the public, sanitized projection;
no private source or decryption key is available in this phase.
"""

import argparse
import json
import os
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import bundle
import fetch
import deadline as deadline_budget
import diagnostic_contract
import node_tool_snapshot


UID = 65534
GID = 65534
MAX_LOG = 256 * 1024 * 1024
MOUNT_TARGETS = []
DEADLINE_FILE = ""
"""Package lifecycle scripts never run during preparation, at three independent layers: the project .npmrc, this environment, and the explicit install flag. A package that declares an install script is installed as inert files."""
NPMRC_TEXT = ("ignore-scripts=true\naudit=false\nfund=false\nupdate-notifier=false\n"
              "registry=https://registry.npmjs.org/\n")
SCRIPT_SUPPRESSION_ENVIRONMENT = {"NPM_CONFIG_IGNORE_SCRIPTS": "true"}
NPM_CI_ARGUMENTS = ("ci", "--ignore-scripts", "--include=dev", "--include=optional", "--no-audit", "--no-fund")
NODE_TOOL_CACHE_ROOT = Path("/opt/hostedtoolcache")
NODE_TOOL_ROOT = NODE_TOOL_CACHE_ROOT / "node" / "24.22.1" / "x64"
NODE_TOOL_SYSTEM_ANCHORS = ((Path("/"), 0), (node_tool_snapshot.SHARED_TOOLCHAIN_ANCHOR, 0))
NODE_VERSION_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
NODE_VERSION = "24.22.1"
NPM_VERSION = "11.19.1"
MAX_NPM_TOOL_ENTRIES = 100_000
TRUSTED_TOOLCHAIN_SYSTEM_UID = 0
PREPARATION_STAGE = "prepare-argument-parse"

_PREPARATION_EXCEPTION_CATEGORIES = {
    AssertionError: "assertion-error",
    AttributeError: "attribute-error",
    FileExistsError: "file-exists",
    FileNotFoundError: "file-not-found",
    IndexError: "index-error",
    IsADirectoryError: "is-directory",
    KeyError: "key-error",
    MemoryError: "memory-error",
    NameError: "name-error",
    NotADirectoryError: "not-directory",
    OSError: "os-error",
    OverflowError: "overflow-error",
    PermissionError: "permission-denied",
    RecursionError: "recursion-error",
    RuntimeError: "runtime-error",
    TimeoutError: "timeout-error",
    TypeError: "type-error",
    UnicodeError: "unicode-error",
    UnicodeDecodeError: "unicode-decode-error",
    ValueError: "value-error",
    json.JSONDecodeError: "json-decode-error",
    subprocess.CalledProcessError: "process-exit-error",
    subprocess.SubprocessError: "process-error",
    subprocess.TimeoutExpired: "process-timeout",
}


def _set_preparation_stage(stage):
    global PREPARATION_STAGE
    PREPARATION_STAGE = stage if stage in diagnostic_contract.PREPARATION_STAGES else "prepare-protocol"


class _PreparationArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        refuse("preparation-parser-refusal")


def _trusted_toolchain_owner_uids(owner_uid):
    if type(owner_uid) is not int or owner_uid < 1 or owner_uid > 60000 or owner_uid == UID:
        _node_refuse("node-toolchain-owner")
    return frozenset((TRUSTED_TOOLCHAIN_SYSTEM_UID, owner_uid))


def _node_refuse(code):
    raise bundle.Refusal(code)


_NODE_DIRECTORY_WRITE_CODES = {
    "source-anchor": "node-toolchain-source-anchor-write-mode",
    "source-root-anchor": "node-toolchain-source-root-anchor-write-mode",
    "source-opt-anchor": "node-toolchain-source-opt-anchor-write-mode",
    "source-cache-root": "node-toolchain-source-cache-root-write-mode",
    "source-node-layout": "node-toolchain-source-node-layout-write-mode",
    "source-npm-layout": "node-toolchain-source-npm-layout-write-mode",
    "source-npm-tree": "node-toolchain-source-npm-tree-write-mode",
}
_NODE_FILE_WRITE_CODES = {
    "source-node-file": "node-toolchain-source-node-file-write-mode",
    "source-npm-file": "node-toolchain-source-npm-file-write-mode",
}


def _shared_toolchain_anchor_group_write(metadata, path, trusted_source_group_gid):
    return node_tool_snapshot._trusted_shared_anchor_group_write(
        metadata, path, trusted_source_group_gid,
    )


def _node_directory(path, owner_uids, *, role, trusted_source_group_gid=None):
    write_code = _NODE_DIRECTORY_WRITE_CODES.get(role)
    if write_code is None:
        _node_refuse("node-tool-layout")
    try:
        metadata = os.lstat(path)
    except OSError:
        _node_refuse("node-toolchain-missing")
    if not stat.S_ISDIR(metadata.st_mode):
        _node_refuse("node-tool-layout")
    if metadata.st_uid not in owner_uids:
        _node_refuse("node-toolchain-owner")
    mode = stat.S_IMODE(metadata.st_mode)
    if (mode & 0o022
            and not _shared_toolchain_anchor_group_write(metadata, path, trusted_source_group_gid)):
        _node_refuse(write_code)
    if not mode & stat.S_IRUSR or not mode & stat.S_IXUSR:
        _node_refuse("node-toolchain-directory-control-access")


def _node_regular_file(path, owner_uids, *, executable, role):
    write_code = _NODE_FILE_WRITE_CODES.get(role)
    if write_code is None:
        _node_refuse("node-tool-layout")
    try:
        metadata = os.lstat(path)
    except OSError:
        _node_refuse("node-toolchain-missing")
    if not stat.S_ISREG(metadata.st_mode):
        _node_refuse("node-tool-layout")
    if metadata.st_uid not in owner_uids:
        _node_refuse("node-toolchain-owner")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & (0o022 | stat.S_ISUID | stat.S_ISGID):
        _node_refuse(write_code)
    if not mode & stat.S_IRUSR:
        _node_refuse("node-toolchain-file-control-access")
    if executable and not mode & stat.S_IXUSR:
        _node_refuse("node-toolchain-executable")


def _validate_npm_tree(root, owner_uids, deadline_file=None):
    root = Path(root)
    try:
        canonical_root = root.resolve(strict=True)
    except (OSError, RuntimeError):
        _node_refuse("node-toolchain-missing")
    pending = [root]
    seen = 0

    def check_deadline():
        if deadline_file:
            try:
                deadline_budget.remaining(deadline_file)
            except deadline_budget.DeadlineRefusal:
                _node_refuse("total-deadline-exhausted")

    while pending:
        check_deadline()
        directory = pending.pop()
        try:
            with os.scandir(directory) as scan:
                for entry in scan:
                    seen += 1
                    if seen > MAX_NPM_TOOL_ENTRIES:
                        _node_refuse("node-tool-layout")
                    if seen % 128 == 0:
                        check_deadline()
                    path = Path(entry.path)
                    try:
                        metadata = os.lstat(path)
                    except OSError:
                        _node_refuse("node-toolchain-missing")
                    if stat.S_ISDIR(metadata.st_mode):
                        _node_directory(path, owner_uids, role="source-npm-tree")
                        pending.append(path)
                    elif stat.S_ISREG(metadata.st_mode):
                        _node_regular_file(path, owner_uids, executable=False, role="source-npm-file")
                    elif stat.S_ISLNK(metadata.st_mode):
                        if metadata.st_uid not in owner_uids:
                            _node_refuse("node-toolchain-owner")
                        try:
                            target = os.readlink(path)
                            lexical_target = Path(os.path.normpath(os.path.join(str(path.parent), target)))
                            resolved_target = path.resolve(strict=True)
                            target_mode = resolved_target.stat().st_mode
                        except (OSError, RuntimeError):
                            _node_refuse("node-tool-layout")
                        if (Path(target).is_absolute() or not lexical_target.is_relative_to(root)
                                or not resolved_target.is_relative_to(canonical_root)
                                or not (stat.S_ISDIR(target_mode) or stat.S_ISREG(target_mode))):
                            _node_refuse("node-tool-layout")
                    else:
                        _node_refuse("node-tool-layout")
        except PermissionError:
            _node_refuse("node-toolchain-directory-scan-access")
        except OSError:
            _node_refuse("node-toolchain-missing")


def validate_node_toolchain(paths, owner_uid, *, tool_cache_root=None, node_root=None, system_anchors=None,
                            deadline_file=None, trusted_source_group_gid=None):
    """Validate the trusted source tree; worker access is enforced on its sealed snapshot."""
    cache_root = Path(tool_cache_root) if tool_cache_root is not None else NODE_TOOL_CACHE_ROOT
    root = Path(node_root) if node_root is not None else NODE_TOOL_ROOT
    anchors = tuple(system_anchors) if system_anchors is not None else NODE_TOOL_SYSTEM_ANCHORS
    expected_root = cache_root / "node" / NODE_VERSION / "x64"
    if type(paths) is not dict or not paths.get("node") or not paths.get("npm"):
        _node_refuse("node-toolchain-missing")
    owner_uids = _trusted_toolchain_owner_uids(owner_uid)
    if root != expected_root:
        _node_refuse("node-tool-layout")
    if not anchors:
        _node_refuse("node-tool-layout")
    if (trusted_source_group_gid is not None
            and (type(trusted_source_group_gid) is not int
                 or trusted_source_group_gid < 1 or trusted_source_group_gid > 60000
                 or trusted_source_group_gid == GID)):
        _node_refuse("node-toolchain-owner")
    for index, (anchor, anchor_uid) in enumerate(anchors):
        anchor = Path(anchor)
        if index and anchor.parent != Path(anchors[index - 1][0]):
            _node_refuse("node-tool-layout")
        role = (
            "source-root-anchor" if anchor == Path("/") else
            "source-opt-anchor" if anchor == node_tool_snapshot.SHARED_TOOLCHAIN_ANCHOR else
            "source-anchor"
        )
        _node_directory(
            anchor, frozenset((anchor_uid,)), role=role,
            trusted_source_group_gid=trusted_source_group_gid,
        )
    if cache_root.parent != Path(anchors[-1][0]):
        _node_refuse("node-tool-layout")
    _node_directory(cache_root, owner_uids, role="source-cache-root")

    relative_directories = (
        (Path("node"), "source-node-layout"),
        (Path("node") / NODE_VERSION, "source-node-layout"),
        (Path("node") / NODE_VERSION / "x64", "source-node-layout"),
        (Path("node") / NODE_VERSION / "x64/bin", "source-node-layout"),
        (Path("node") / NODE_VERSION / "x64/lib", "source-node-layout"),
        (Path("node") / NODE_VERSION / "x64/lib/node_modules", "source-node-layout"),
        (Path("node") / NODE_VERSION / "x64/lib/node_modules/npm", "source-npm-layout"),
        (Path("node") / NODE_VERSION / "x64/lib/node_modules/npm/bin", "source-npm-layout"),
    )
    for relative, role in relative_directories:
        _node_directory(cache_root / relative, owner_uids, role=role)

    node = root / "bin/node"
    npm_launcher = root / "bin/npm"
    npm_cli = root / "lib/node_modules/npm/bin/npm-cli.js"
    if paths.get("node") != str(node) or paths.get("npm") != str(npm_launcher):
        _node_refuse("node-tool-layout")
    _node_regular_file(node, owner_uids, executable=True, role="source-node-file")
    try:
        launcher_metadata = os.lstat(npm_launcher)
        launcher_target = os.readlink(npm_launcher)
    except OSError:
        _node_refuse("node-toolchain-missing")
    if (not stat.S_ISLNK(launcher_metadata.st_mode)
            or launcher_target != "../lib/node_modules/npm/bin/npm-cli.js"):
        _node_refuse("node-tool-layout")
    if launcher_metadata.st_uid not in owner_uids:
        _node_refuse("node-toolchain-owner")
    _node_regular_file(npm_cli, owner_uids, executable=False, role="source-npm-file")
    _validate_npm_tree(root / "lib/node_modules/npm", owner_uids, deadline_file=deadline_file)
    return {"node": str(node), "npm": str(npm_launcher), "npm_cli": str(npm_cli), "root": str(root)}


def node_version_commands(validated):
    """Run npm's resolved JavaScript entry point with this exact Node executable."""
    return {
        "node": [validated["node"], "--version"],
        "npm": [validated["node"], validated["npm_cli"], "--version"],
    }


def run_node_versions(validated, run):
    results = {
        name: run(argv, env=dict(NODE_VERSION_ENVIRONMENT))
        for name, argv in node_version_commands(validated).items()
    }
    return results


def _prepare_node_version_process(argv, *, env):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=_bounded_timeout(10),
                          check=False, env=env)


def refuse(code):
    raise bundle.Refusal(code)


def _bounded_timeout(cap, *, cleanup=False):
    if not DEADLINE_FILE:
        refuse("total-deadline-unavailable")
    try:
        remaining = (deadline_budget.cleanup_remaining(DEADLINE_FILE) if cleanup
                     else deadline_budget.remaining(DEADLINE_FILE))
        return min(cap, remaining)
    except deadline_budget.DeadlineRefusal:
        refuse("total-deadline-exhausted")


def run(argv, *, timeout, log, environment, cwd=None):
    target = Path(log)
    target.parent.mkdir(parents=True, exist_ok=True)
    bounded = _bounded_timeout(timeout)
    with target.open("xb") as output:
        try:
            process = subprocess.Popen(
                argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                env=environment, close_fds=True, start_new_session=True, preexec_fn=_limits,
            )
            code = process.wait(timeout=bounded)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            process.wait(timeout=5)
            _kill_children()
            refuse("preparation-timeout")
        except OSError:
            _kill_children()
            refuse("preparation-tool-unavailable")
    if target.stat().st_size > MAX_LOG:
        refuse("preparation-log-size")
    _kill_children()
    if code != 0:
        refuse("preparation-failed")


def _kill_children():
    for signum, delay in ((signal.SIGTERM, 0.1), (signal.SIGKILL, 0.0)):
        try:
            os.kill(-1, signum)
        except OSError:
            pass
        if delay:
            time.sleep(delay)
    while True:
        try:
            child, _ = os.waitpid(-1, 0)
            if child <= 0:
                break
        except ChildProcessError:
            break


def _limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))
    resource.setrlimit(resource.RLIMIT_NOFILE, (8192, 8192))
    resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
    resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))
    os.umask(0o077)


def _resolve_rust_tool(path, name):
    """The caller (an unprivileged step with the runner's rustup home) supplies real toolchain
    binaries; a rustup proxy cannot run inside the offline root, so it is refused here."""
    try:
        resolved = Path(path).resolve(strict=True)
    except (OSError, ValueError):
        refuse("rust-toolchain-path")
    if not path or not resolved.is_file() or resolved.name != name:
        refuse("rust-toolchain-path")
    return str(resolved)


def _mount(source, target):
    source = Path(source).resolve(strict=True)
    subprocess.run(["mount", "--bind", str(source), str(target)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=_bounded_timeout(10))
    MOUNT_TARGETS.append(Path(target))
    subprocess.run(["mount", "-o", "remount,bind,ro,nosuid,nodev", str(target)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=_bounded_timeout(10))


def _mount_fs(argv, target):
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=_bounded_timeout(10))
    MOUNT_TARGETS.append(Path(target))


def _copy_tree(source, destination):
    source, destination = Path(source), Path(destination)
    if not source.is_dir() or source.is_symlink() or destination.exists() or destination.is_symlink():
        refuse("prepared-output-invalid")
    root = source.resolve(strict=True)
    destination.mkdir(mode=0o700, parents=True)
    count = total = 0
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        target_dir = destination / current_path.relative_to(root)
        target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        kept = []
        for name in directories:
            entry = current_path / name
            target = target_dir / name
            if entry.is_symlink():
                link = os.readlink(entry)
                if os.path.isabs(link):
                    refuse("prepared-link-invalid")
                resolved = (entry.parent / link).resolve(strict=True)
                if not resolved.is_relative_to(root):
                    refuse("prepared-link-invalid")
                target.symlink_to(link, target_is_directory=True)
                count += 1
            else:
                target.mkdir(mode=0o700, exist_ok=True)
                kept.append(name)
                count += 1
            if count > 250_000:
                refuse("prepared-file-count")
        directories[:] = kept
        for name in files:
            entry = current_path / name
            target = target_dir / name
            mode = entry.lstat().st_mode
            count += 1
            if count > 250_000:
                refuse("prepared-file-count")
            if stat.S_ISLNK(mode):
                link = os.readlink(entry)
                if os.path.isabs(link):
                    refuse("prepared-link-invalid")
                resolved = (entry.parent / link).resolve(strict=True)
                if not resolved.is_relative_to(root):
                    refuse("prepared-link-invalid")
                target.symlink_to(link)
            elif stat.S_ISREG(mode):
                total += entry.stat().st_size
                if total > 4 * 1024 * 1024 * 1024:
                    refuse("prepared-tree-size")
                shutil.copyfile(entry, target, follow_symlinks=False)
                os.chmod(target, 0o444 | (stat.S_IMODE(mode) & 0o111))
            else:
                refuse("prepared-member-type")


def _project_files(projection, project):
    project.mkdir(mode=0o755, parents=True)
    if projection["profile"] == "core-node":
        for name, value in (("package.json", projection["npm_package"]),
                            ("package-lock.json", projection["npm_lock"])):
            (project / name).write_bytes(bundle.canonical_json(value) + b"\n")
        (project / ".npmrc").write_text(NPMRC_TEXT, encoding="ascii")
    else:
        (project / "Cargo.toml").write_text(projection["cargo_manifest"], encoding="utf-8")
        (project / "Cargo.lock").write_text(projection["cargo_lock"], encoding="utf-8")
        (project / "src").mkdir(mode=0o755)
        (project / "src/lib.rs").write_text(chr(35) + "![allow(dead_code)]\npub fn devlane_fixture() {}\n", encoding="ascii")
        for index, workspace in enumerate(projection["cargo_workspaces"], 1):
            sync = project / ("sync-%03d" % index)
            sync.mkdir(mode=0o755)
            (sync / "Cargo.toml").write_text(workspace["manifest"], encoding="utf-8")
            (sync / "Cargo.lock").write_text(workspace["lock"], encoding="utf-8")
            (sync / "src").mkdir(mode=0o755)
            (sync / "src/lib.rs").write_text(chr(35) + "![allow(dead_code)]\npub fn devlane_fixture() {}\n", encoding="ascii")


def _write_resolver(root):
    """Give the online preparation root the runner's own resolver configuration.

    Without it name resolution inside the chroot defaults to a local resolver that does not
    exist there. The files are small, read once, and carry no secrets.
    """
    for name, maximum in (("resolv.conf", 4096), ("nsswitch.conf", 4096)):
        try:
            payload = Path("/etc", name).read_bytes()
        except OSError:
            payload = b""
        if name == "resolv.conf" and (not payload or len(payload) > maximum or b"\x00" in payload):
            refuse("resolver-config-unavailable")
        if payload and len(payload) <= maximum and b"\x00" not in payload:
            (root / "etc" / name).write_bytes(payload)


def _prepare_root(root, tool_roots):
    _set_preparation_stage("prepare-root-mounts")
    root = Path(root)
    if root.is_symlink() or (root.exists() and (not root.is_dir() or any(root.iterdir()))):
        refuse("preparation-root-invalid")
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    _mount_fs(["mount", "-t", "tmpfs", "-o", "size=8g,mode=0755,nosuid,nodev", "tmpfs", str(root)], root)
    for relative in ("bin", "sbin", "lib", "lib64", "usr", "etc/ssl", "dev", "proc", "work", "tools/node", "tools/rust"):
        (root / relative).mkdir(mode=0o755, parents=True, exist_ok=True)
    for source, target in (("/usr", root / "usr"), ("/lib", root / "lib"), ("/lib64", root / "lib64")):
        if Path(source).exists():
            _mount(source, target)
    for name, target in (("bin", "usr/bin"), ("sbin", "usr/sbin")):
        link = root / name
        link.rmdir()
        link.symlink_to(target)
    (root / "etc/passwd").write_text("root:x:0:0:root:/root:/usr/sbin/nologin\ndevlane:x:65534:65534:devlane:/devlane-home:/usr/sbin/nologin\n", encoding="ascii")
    (root / "etc/group").write_text("root:x:0:\ndevlane:x:65534:\n", encoding="ascii")
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n::1 localhost\n", encoding="ascii")
    _write_resolver(root)
    cert_target = root / "etc/ssl/certs"
    cert_target.mkdir(mode=0o755, exist_ok=True)
    if Path("/etc/ssl/certs").is_dir():
        _mount("/etc/ssl/certs", cert_target)
    dev = root / "dev"
    _mount_fs(["mount", "-t", "tmpfs", "-o", "size=64m,mode=0755", "tmpfs", str(dev)], dev)
    for name, mode, major, minor in (("null", 0o666, 1, 3), ("zero", 0o666, 1, 5),
                                     ("random", 0o444, 1, 8), ("urandom", 0o444, 1, 9)):
        os.mknod(str(dev / name), stat.S_IFCHR | mode, os.makedev(major, minor))
    _mount_fs(["mount", "-t", "proc", "-o", "hidepid=2,subset=pid", "proc", str(root / "proc")], root / "proc")
    (root / "devlane-home").mkdir(mode=0o700, parents=True)
    os.chown(str(root / "devlane-home"), UID, GID)
    _mount_fs(["mount", "-t", "tmpfs", "-o", "size=6g,mode=0700,nosuid,nodev", "tmpfs", str(root / "work")], root / "work")
    os.chown(str(root / "work"), UID, GID)
    for family, tool_root in tool_roots.items():
        if tool_root:
            _mount(tool_root, root / ("tools/node" if family == "node" else "tools/rust"))


def _run_worker(root, projection, profile, output_root, tool_paths, owner_uid, owner_gid):
    _set_preparation_stage("prepare-worker-setup")
    work = root / "work"
    project = work / "project"
    prepared = work / "prepared"
    prepared.mkdir(mode=0o700)
    _project_files(projection, project)
    for path in (project, prepared, work / "npm-cache", work / "cargo-home"):
        if not path.exists():
            path.mkdir(mode=0o700, parents=True)
        for current, directories, files in os.walk(path, followlinks=False):
            os.chown(current, UID, GID, follow_symlinks=False)
            for name in directories + files:
                os.chown(str(Path(current) / name), UID, GID, follow_symlinks=False)
    if profile == "core-rust":
        (work / "cargo-home/config.toml").write_text(
            '[registries.crates-io]\nprotocol = "sparse"\n\n[net]\nretry = 1\n',
            encoding="ascii",
        )
    node_bin = "/tools/node/bin"
    rust_bin = "/tools/rust/bin"
    path_parts = ["/usr/bin", "/bin"]
    if profile == "core-node":
        path_parts.insert(0, node_bin)
    else:
        path_parts.insert(0, rust_bin)
    environment = {
        "PATH": ":".join(path_parts), "HOME": "/devlane-home", "TMPDIR": "/work/tmp",
        "LANG": "C.UTF-8", "LC_ALL": "C", "CI": "1", "CARGO_HOME": "/work/cargo-home",
        "NPM_CONFIG_CACHE": "/work/npm-cache", **SCRIPT_SUPPRESSION_ENVIRONMENT,
        "NPM_CONFIG_AUDIT": "false", "NPM_CONFIG_FUND": "false",
        "PLAYWRIGHT_BROWSERS_PATH": "/work/prepared/ms-playwright",
        "XDG_CACHE_HOME": "/work/cache", "PYTHONDONTWRITEBYTECODE": "1",
    }
    (work / "tmp").mkdir(mode=0o700, exist_ok=True)
    (work / "cache").mkdir(mode=0o700, exist_ok=True)
    for path in (work / "tmp", work / "cache"):
        os.chown(path, UID, GID)
    command_prefix = [
        "/usr/sbin/chroot", str(root), "/usr/bin/setpriv",
        "--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--",
        "/bin/sh", "-c", 'cd /work/project && exec "$@"', "devlane-prepare",
    ]
    if profile == "core-node":
        _set_preparation_stage("prepare-dependency-install")
        command = command_prefix + ["npm", "--prefix", "/work/project", *NPM_CI_ARGUMENTS]
        run(command, timeout=3600, log=work / "prepare-npm.log", environment=environment,
            cwd="/")
        if projection["playwright"]:
            _set_preparation_stage("prepare-playwright-install")
            candidates = (
                root / "work/project/node_modules/playwright/cli.js",
                root / "work/project/node_modules/@playwright/test/cli.js",
            )
            cli = next((candidate for candidate in candidates if candidate.is_file() and not candidate.is_symlink()), None)
            if cli is None:
                refuse("playwright-cli-missing")
            cli_guest = "/work/project/node_modules/playwright/cli.js" if candidates[0] == cli else "/work/project/node_modules/@playwright/test/cli.js"
            command = command_prefix + ["node", cli_guest, "install", *projection["playwright"]]
            run(command, timeout=1800, log=work / "prepare-playwright.log", environment=environment,
                cwd="/")
    else:
        _set_preparation_stage("prepare-cargo-vendor")
        """cargo vendor creates its destination as the unprivileged worker; it vendors every locked package, so feature flags are neither needed nor accepted by this command."""
        command = command_prefix + ["cargo", "vendor", "--locked",
                                    "--manifest-path", "/work/project/Cargo.toml"]
        for index in range(1, len(projection["cargo_workspaces"]) + 1):
            command.extend(("--sync", "/work/project/sync-%03d/Cargo.toml" % index))
        command.append("/work/prepared/cargo-vendor")
        run(command, timeout=3600, log=work / "prepare-cargo.log", environment=environment,
            cwd="/")
        config = (
            '[source.crates-io]\nreplace-with = "vendored-sources"\n'
            '[source.vendored-sources]\ndirectory = "/prepared/cargo-vendor"\n'
            '[net]\noffline = true\n'
        )
        (prepared / "cargo-config.toml").write_text(config, encoding="ascii")
    (prepared / "projection.json").write_bytes(bundle.canonical_json(projection) + b"\n")
    if profile == "core-node":
        _copy_tree(project / "node_modules", prepared / "node_modules")
    else:
        if not (prepared / "cargo-vendor").is_dir():
            refuse("cargo-vendor-missing")
    if projection["playwright"]:
        _set_preparation_stage("prepare-prepared-output-copy")
        """Browsers are installed directly under prepared/ (PLAYWRIGHT_BROWSERS_PATH)."""
        if not (prepared / "ms-playwright").is_dir() or (prepared / "ms-playwright").is_symlink():
            refuse("playwright-browsers-missing")
    destination = Path(output_root)
    _set_preparation_stage("prepare-prepared-output-copy")
    if destination.exists() or destination.is_symlink():
        refuse("prepared-output-exists")
    destination.mkdir(mode=0o700, parents=True)
    for item in prepared.iterdir():
        target = destination / item.name
        if item.is_dir():
            _copy_tree(item, target)
        elif item.is_file() and not item.is_symlink():
            shutil.copyfile(item, target)
            os.chmod(target, 0o444)
        else:
            refuse("prepared-output-member")
    for current, directories, files in os.walk(destination, topdown=True, followlinks=False):
        os.chown(current, owner_uid, owner_gid)
        os.chmod(current, 0o755)
        for name in directories + files:
            os.chown(str(Path(current) / name), owner_uid, owner_gid, follow_symlinks=False)
    os.chmod(destination, 0o755)


def _failure_from_exception(error):
    if type(error) is node_tool_snapshot.SnapshotRefusal:
        code = error.code
        return "refusal", code if code in diagnostic_contract.PREPARATION_REFUSAL_CODES else "preparation-refusal-unlisted"
    if type(error) in (bundle.Refusal, deadline_budget.DeadlineRefusal):
        code = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else ""
        return "refusal", code if code in diagnostic_contract.PREPARATION_REFUSAL_CODES else "preparation-refusal-unlisted"
    label = _PREPARATION_EXCEPTION_CATEGORIES.get(type(error), "unclassified")
    return "exception", label if label in diagnostic_contract.PREPARATION_EXCEPTION_LABELS else "unclassified"


def _emit_failure(failure, cleanup, stage=None):
    kind, value = failure
    stage = stage or PREPARATION_STAGE
    stage = stage if stage in diagnostic_contract.PREPARATION_STAGES else "prepare-protocol"
    if kind == "refusal":
        code = value if value in diagnostic_contract.PREPARATION_REFUSAL_CODES else "preparation-refusal-unlisted"
        print("dependency_preparation_refusal=stage=%s code=%s cleanup=%s" % (stage, code, cleanup),
              file=sys.stderr)
        return
    label = value if value in diagnostic_contract.PREPARATION_EXCEPTION_LABELS else "unclassified"
    print("dependency_preparation_exception=stage=%s class=%s cleanup=%s" % (stage, label, cleanup),
          file=sys.stderr)


def _argument_parser():
    parser = _PreparationArgumentParser()
    parser.add_argument("--projection", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--profile", choices=("core-node", "core-rust"), required=True)
    parser.add_argument("--owner-uid", type=int, required=True)
    parser.add_argument("--owner-gid", type=int, required=True)
    parser.add_argument("--deadline-file", required=True)
    parser.add_argument("--node-snapshot-id", default="")
    for name in ("node", "npm", "cargo", "rustc"):
        parser.add_argument("--" + name + "-path", default="")
    return parser


def main(argv=None):
    global DEADLINE_FILE
    MOUNT_TARGETS.clear()
    _set_preparation_stage("prepare-argument-parse")
    parser = _argument_parser()
    root = None
    node_snapshot_id = ""
    node_snapshot_created = False
    failure = None
    failure_stage = None
    cleanup = "not-needed"
    result = 2
    try:
        args = parser.parse_args(argv)
        DEADLINE_FILE = args.deadline_file
        _set_preparation_stage("prepare-deadline-check")
        deadline_budget.remaining(DEADLINE_FILE)
        _set_preparation_stage("prepare-platform-check")
        if not sys.platform.startswith("linux") or os.geteuid() != 0:
            refuse("linux-root-required")
        _set_preparation_stage("prepare-owner-identity")
        if (args.owner_uid < 1 or args.owner_gid < 1 or args.owner_uid > 60000 or args.owner_gid > 60000
                or args.owner_uid == UID or args.owner_gid == GID):
            refuse("owner-identity")
        _set_preparation_stage("prepare-projection-validation")
        projection_path = Path(args.projection)
        projection = fetch.validate_projection(projection_path.read_bytes(), args.profile)
        if projection["tools"] != ({"node": NODE_VERSION, "npm": NPM_VERSION} if args.profile == "core-node" else projection["tools"]):
            refuse("toolchain-version")
        _set_preparation_stage("prepare-toolchain-selection")
        if args.profile == "core-node":
            if not node_tool_snapshot.valid_snapshot_id(args.node_snapshot_id):
                refuse("node-snapshot-id")
            node_snapshot_id = args.node_snapshot_id
            paths = {"node": args.node_path, "npm": args.npm_path, "cargo": "", "rustc": ""}
        else:
            if args.node_snapshot_id:
                refuse("node-snapshot-id")
            paths = {name: getattr(args, name + "_path") or shutil.which(name) or ""
                     for name in ("node", "npm", "cargo", "rustc")}
        if args.profile == "core-rust":
            _set_preparation_stage("prepare-rust-toolchain-validation")
            for name in ("cargo", "rustc"):
                paths[name] = _resolve_rust_tool(paths[name], name)
        if args.profile == "core-node":
            _set_preparation_stage("prepare-node-toolchain-snapshot")
            node_tools = node_tool_snapshot.create_snapshot(
                paths, node_snapshot_id, args.owner_uid, DEADLINE_FILE,
                trusted_source_group_gid=args.owner_gid,
            )
            node_snapshot_created = True
            _set_preparation_stage("prepare-node-snapshot-verification")
            node_tools = node_tool_snapshot.validate_snapshot(
                node_snapshot_id, DEADLINE_FILE, owner_uid=args.owner_uid,
            )
            _set_preparation_stage("prepare-node-version-verification")
            node_results = run_node_versions(node_tools, _prepare_node_version_process)
            for name, expected in (("node", NODE_VERSION), ("npm", NPM_VERSION)):
                expected_text = ("v" + expected) if name == "node" else expected
                try:
                    actual = node_results[name].stdout.decode("ascii", "strict").strip()
                except UnicodeDecodeError:
                    refuse("node-toolchain-version" if name == "node" else "npm-toolchain-version")
                if node_results[name].returncode != 0 or actual != expected_text:
                    refuse("node-toolchain-version" if name == "node" else "npm-toolchain-version")
            paths["node"] = node_tools["node"]
            paths["npm"] = node_tools["npm"]
        elif not paths["cargo"] or not paths["rustc"]:
            refuse("rust-toolchain-missing")
        if args.profile == "core-rust":
            _set_preparation_stage("prepare-rust-version-verification")
            for name in ("cargo", "rustc"):
                version_result = subprocess.run([paths[name], "--version"], stdout=subprocess.PIPE,
                                                stderr=subprocess.DEVNULL, timeout=_bounded_timeout(10), check=False,
                                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                words = version_result.stdout.decode("ascii", "strict").split()
                if version_result.returncode != 0 or len(words) < 2 or words[1] != projection["tools"][name]:
                    refuse("rust-toolchain-version")
        if args.profile == "core-node":
            _set_preparation_stage("prepare-tool-root-selection")
            tool_roots = {"node": Path(node_tools["root"]), "rust": None}
        else:
            cargo_root = Path(paths["cargo"]).resolve(strict=True).parent.parent
            rustc_path = Path(paths["rustc"]).resolve(strict=True)
            if not rustc_path.is_relative_to(cargo_root):
                refuse("rust-tool-layout")
            tool_roots = {"node": None, "rust": cargo_root}
            _set_preparation_stage("prepare-tool-root-selection")
        root = Path(tempfile.mkdtemp(prefix="kd-devlane-prep-", dir="/tmp"))
        cleanup = "confirmed"
        _set_preparation_stage("prepare-namespace-isolation")
        subprocess.run(["mount", "--make-rprivate", "/"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=_bounded_timeout(10))
        _prepare_root(root, tool_roots)
        _run_worker(root, projection, args.profile, args.output, paths, args.owner_uid, args.owner_gid)
        result = 0
    except Exception as error:
        failure = _failure_from_exception(error)
        failure_stage = PREPARATION_STAGE
        if getattr(error, "cleanup_unconfirmed", False):
            cleanup = "unconfirmed"
        elif getattr(error, "cleanup_confirmed", False):
            cleanup = "confirmed"
        result = 2
    finally:
        clean = True
        if root is not None:
            _set_preparation_stage("prepare-cleanup")
            try:
                _kill_children()
            except Exception:
                clean = False
            for target in reversed(MOUNT_TARGETS):
                try:
                    subprocess.run(["umount", str(target)], check=True, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=_bounded_timeout(5, cleanup=True))
                except Exception:
                    clean = False
            MOUNT_TARGETS.clear()
            try:
                root.rmdir()
            except Exception:
                clean = False
        if node_snapshot_created and failure is not None:
            if clean:
                try:
                    node_tool_snapshot.remove_snapshot(
                        node_snapshot_id, DEADLINE_FILE, owner_uid=args.owner_uid,
                    )
                    cleanup = "confirmed"
                except Exception:
                    clean = False
            else:
                clean = False
        if not clean:
            cleanup = "unconfirmed"
            if failure is None:
                failure = ("refusal", "cleanup-incomplete")
                failure_stage = "prepare-cleanup"
                result = 2
        elif root is not None and cleanup != "unconfirmed":
            cleanup = "confirmed"
        if result != 0 and failure is None:
            _set_preparation_stage("prepare-protocol")
            failure = ("refusal", "preparation-refusal-unlisted")
            failure_stage = "prepare-protocol"
            result = 2
    if result == 0:
        print("dependency_preparation=complete")
        return 0
    _emit_failure(failure, cleanup, failure_stage)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
