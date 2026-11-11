"""Online dependency preparation in a throwaway PID/mount/IPC boundary.

This module runs only on Linux. It consumes the public, sanitized projection;
no private source or decryption key is available in this phase.
"""

import argparse
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
NODE_TOOL_SYSTEM_ANCHORS = ((Path("/"), 0), (Path("/opt"), 0))
NODE_VERSION_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
NODE_VERSION = "24.22.1"
NPM_VERSION = "11.19.1"
MAX_NPM_TOOL_ENTRIES = 100_000


def _node_refuse(code):
    raise bundle.Refusal(code)


def _node_directory(path, owner_uid, *, worker_access=False):
    try:
        metadata = os.lstat(path)
    except OSError:
        _node_refuse("node-toolchain-missing")
    if not stat.S_ISDIR(metadata.st_mode):
        _node_refuse("node-tool-layout")
    if metadata.st_uid != owner_uid:
        _node_refuse("node-toolchain-owner")
    mode = stat.S_IMODE(metadata.st_mode)
    if (mode & 0o022 or not mode & stat.S_IRUSR or not mode & stat.S_IXUSR
            or worker_access and (not mode & stat.S_IROTH or not mode & stat.S_IXOTH)):
        _node_refuse("node-toolchain-permissions")


def _node_regular_file(path, owner_uid, *, executable):
    try:
        metadata = os.lstat(path)
    except OSError:
        _node_refuse("node-toolchain-missing")
    if not stat.S_ISREG(metadata.st_mode):
        _node_refuse("node-tool-layout")
    if metadata.st_uid != owner_uid:
        _node_refuse("node-toolchain-owner")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & (0o022 | stat.S_ISUID | stat.S_ISGID):
        _node_refuse("node-toolchain-permissions")
    if not mode & stat.S_IRUSR:
        _node_refuse("node-toolchain-permissions")
    if executable and (not mode & stat.S_IXUSR or not mode & stat.S_IXOTH):
        _node_refuse("node-toolchain-executable")
    if not executable and not mode & stat.S_IROTH:
        _node_refuse("node-toolchain-permissions")


def _validate_npm_tree(root, owner_uid):
    root = Path(root)
    try:
        canonical_root = root.resolve(strict=True)
    except (OSError, RuntimeError):
        _node_refuse("node-toolchain-missing")
    pending = [root]
    seen = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as scan:
                entries = list(scan)
        except PermissionError:
            _node_refuse("node-toolchain-permissions")
        except OSError:
            _node_refuse("node-toolchain-missing")
        for entry in entries:
            seen += 1
            if seen > MAX_NPM_TOOL_ENTRIES:
                _node_refuse("node-tool-layout")
            path = Path(entry.path)
            try:
                metadata = os.lstat(path)
            except OSError:
                _node_refuse("node-toolchain-missing")
            if stat.S_ISDIR(metadata.st_mode):
                _node_directory(path, owner_uid, worker_access=True)
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                _node_regular_file(path, owner_uid, executable=False)
            elif stat.S_ISLNK(metadata.st_mode):
                if metadata.st_uid != owner_uid:
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


def validate_node_toolchain(paths, owner_uid, *, tool_cache_root=None, node_root=None, system_anchors=None):
    """Bind Node and npm to the runner-owned pinned toolcache tree before privileged use."""
    cache_root = Path(tool_cache_root) if tool_cache_root is not None else NODE_TOOL_CACHE_ROOT
    root = Path(node_root) if node_root is not None else NODE_TOOL_ROOT
    anchors = tuple(system_anchors) if system_anchors is not None else NODE_TOOL_SYSTEM_ANCHORS
    expected_root = cache_root / "node" / NODE_VERSION / "x64"
    if type(paths) is not dict or not paths.get("node") or not paths.get("npm"):
        _node_refuse("node-toolchain-missing")
    if type(owner_uid) is not int or owner_uid < 0:
        _node_refuse("node-toolchain-owner")
    if root != expected_root:
        _node_refuse("node-tool-layout")
    if not anchors:
        _node_refuse("node-tool-layout")
    for index, (anchor, anchor_uid) in enumerate(anchors):
        anchor = Path(anchor)
        if index and anchor.parent != Path(anchors[index - 1][0]):
            _node_refuse("node-tool-layout")
        _node_directory(anchor, anchor_uid)
    if cache_root.parent != Path(anchors[-1][0]):
        _node_refuse("node-tool-layout")
    _node_directory(cache_root, owner_uid)

    relative_directories = (
        Path("node"), Path("node") / NODE_VERSION, Path("node") / NODE_VERSION / "x64",
        Path("node") / NODE_VERSION / "x64/bin", Path("node") / NODE_VERSION / "x64/lib",
        Path("node") / NODE_VERSION / "x64/lib/node_modules",
        Path("node") / NODE_VERSION / "x64/lib/node_modules/npm",
        Path("node") / NODE_VERSION / "x64/lib/node_modules/npm/bin",
    )
    for relative in relative_directories:
        _node_directory(cache_root / relative, owner_uid, worker_access=True)

    node = root / "bin/node"
    npm_launcher = root / "bin/npm"
    npm_cli = root / "lib/node_modules/npm/bin/npm-cli.js"
    if paths.get("node") != str(node) or paths.get("npm") != str(npm_launcher):
        _node_refuse("node-tool-layout")
    _node_regular_file(node, owner_uid, executable=True)
    try:
        launcher_metadata = os.lstat(npm_launcher)
        launcher_target = os.readlink(npm_launcher)
    except OSError:
        _node_refuse("node-toolchain-missing")
    if (not stat.S_ISLNK(launcher_metadata.st_mode)
            or launcher_target != "../lib/node_modules/npm/bin/npm-cli.js"):
        _node_refuse("node-tool-layout")
    if launcher_metadata.st_uid != owner_uid:
        _node_refuse("node-toolchain-owner")
    _node_regular_file(npm_cli, owner_uid, executable=False)
    _validate_npm_tree(root / "lib/node_modules/npm", owner_uid)
    return {"node": str(node), "npm": str(npm_launcher), "npm_cli": str(npm_cli), "root": str(root)}


def node_version_commands(validated):
    """Run npm's resolved JavaScript entry point with this exact Node executable."""
    return {
        "node": [validated["node"], "--version"],
        "npm": [validated["node"], validated["npm_cli"], "--version"],
    }


def run_node_version_checks(paths, owner_uid, run):
    validated = validate_node_toolchain(paths, owner_uid)
    results = {
        name: run(argv, env=dict(NODE_VERSION_ENVIRONMENT))
        for name, argv in node_version_commands(validated).items()
    }
    return validated, results


def _prepare_node_version_process(argv, *, env):
    try:
        return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=_bounded_timeout(10),
                              check=False, env=env)
    except (OSError, subprocess.SubprocessError):
        refuse("node-toolchain-version" if len(argv) == 2 else "npm-toolchain-version")


def verify_node_toolchain_versions(paths, owner_uid):
    return run_node_version_checks(paths, owner_uid, _prepare_node_version_process)


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
    subprocess.run(["mount", "-o", "remount,bind,ro,nosuid,nodev", str(target)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=_bounded_timeout(10))
    MOUNT_TARGETS.append(Path(target))


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
        command = command_prefix + ["npm", "--prefix", "/work/project", *NPM_CI_ARGUMENTS]
        run(command, timeout=3600, log=work / "prepare-npm.log", environment=environment,
            cwd="/")
        if projection["playwright"]:
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
        """Browsers are installed directly under prepared/ (PLAYWRIGHT_BROWSERS_PATH)."""
        if not (prepared / "ms-playwright").is_dir() or (prepared / "ms-playwright").is_symlink():
            refuse("playwright-browsers-missing")
    destination = Path(output_root)
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


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--projection", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--profile", choices=("core-node", "core-rust"), required=True)
    parser.add_argument("--owner-uid", type=int, required=True)
    parser.add_argument("--owner-gid", type=int, required=True)
    parser.add_argument("--deadline-file", required=True)
    for name in ("node", "npm", "cargo", "rustc"):
        parser.add_argument("--" + name + "-path", default="")
    args = parser.parse_args(argv)
    global DEADLINE_FILE
    DEADLINE_FILE = args.deadline_file
    try:
        deadline_budget.remaining(DEADLINE_FILE)
    except deadline_budget.DeadlineRefusal:
        print("dependency_preparation_refusal=total-deadline-exhausted", file=sys.stderr)
        return 2
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        print("dependency_preparation_refusal=linux-root-required", file=sys.stderr)
        return 2
    root = None
    result = 2
    try:
        if args.owner_uid < 1 or args.owner_gid < 1 or args.owner_uid > 60000 or args.owner_gid > 60000:
            refuse("owner-identity")
        projection_path = Path(args.projection)
        projection = fetch.validate_projection(projection_path.read_bytes(), args.profile)
        if projection["tools"] != ({"node": NODE_VERSION, "npm": NPM_VERSION} if args.profile == "core-node" else projection["tools"]):
            refuse("toolchain-version")
        if args.profile == "core-node":
            paths = {"node": args.node_path, "npm": args.npm_path, "cargo": "", "rustc": ""}
        else:
            paths = {name: getattr(args, name + "_path") or shutil.which(name) or ""
                     for name in ("node", "npm", "cargo", "rustc")}
        if args.profile == "core-rust":
            for name in ("cargo", "rustc"):
                paths[name] = _resolve_rust_tool(paths[name], name)
        if args.profile == "core-node":
            node_tools, node_results = verify_node_toolchain_versions(paths, args.owner_uid)
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
            for name in ("cargo", "rustc"):
                version_result = subprocess.run([paths[name], "--version"], stdout=subprocess.PIPE,
                                                stderr=subprocess.DEVNULL, timeout=_bounded_timeout(10), check=False,
                                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                words = version_result.stdout.decode("ascii", "strict").split()
                if version_result.returncode != 0 or len(words) < 2 or words[1] != projection["tools"][name]:
                    refuse("rust-toolchain-version")
        if args.profile == "core-node":
            tool_roots = {"node": Path(node_tools["root"]), "rust": None}
        else:
            cargo_root = Path(paths["cargo"]).resolve(strict=True).parent.parent
            rustc_path = Path(paths["rustc"]).resolve(strict=True)
            if not rustc_path.is_relative_to(cargo_root):
                refuse("rust-tool-layout")
            tool_roots = {"node": None, "rust": cargo_root}
        root = Path(tempfile.mkdtemp(prefix="kd-devlane-prep-", dir="/tmp"))
        subprocess.run(["mount", "--make-rprivate", "/"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=_bounded_timeout(10))
        _prepare_root(root, tool_roots)
        _run_worker(root, projection, args.profile, args.output, paths, args.owner_uid, args.owner_gid)
        print("dependency_preparation=complete")
        result = 0
    except (bundle.Refusal, fetch.Refusal) as error:
        print("dependency_preparation_refusal=" + str(error), file=sys.stderr)
        result = 2
    except Exception:
        print("dependency_preparation_refusal=preparation-failed", file=sys.stderr)
        result = 2
    finally:
        _kill_children()
        clean = True
        for target in reversed(MOUNT_TARGETS):
            try:
                subprocess.run(["umount", str(target)], check=True, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=_bounded_timeout(5, cleanup=True))
            except (OSError, subprocess.SubprocessError):
                clean = False
        MOUNT_TARGETS.clear()
        if root is not None:
            try:
                root.rmdir()
            except OSError:
                clean = False
        if not clean:
            print("dependency_preparation_refusal=cleanup-incomplete", file=sys.stderr)
            result = 2
    return result


if __name__ == "__main__":
    raise SystemExit(main())
