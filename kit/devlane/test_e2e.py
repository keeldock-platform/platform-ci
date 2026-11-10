"""Linux/root source-free acceptance of the production encrypted lane path.

Run only from the ubuntu devlane-synthetic workflow.  Fixtures use planted
canaries and fake source code; this test never reads project source or a real
decryption secret.

Scenarios (each runs the production preparation, supervisor, decryptor, profile
commands, adapters, filter and cleanup; nothing is stubbed):

* synthetic-node: fixed-shape fixture with hostile behaviour (descendants that
  outlive their parent, planted workflow-command text on every output channel,
  inspection of the workload's environment, descriptors and files for key bytes),
  a wrong-key refusal, a failing test mapped to its opaque identity, and a
  cancellation while a profile command is running.
* synthetic-rust: build script with planted output, a test inspecting its own
  environment and descriptors.
* real-node: the pinned Vitest, Vite and TypeScript packages (native bindings
  included) installed online from the reviewed lock, run offline, with a passing
  and a failing real test.
* real-rust: real crates.io dependencies and dev-dependencies vendored online,
  built and tested offline.
* real-browser: the pinned Playwright test runner with an installed Chromium,
  run offline.
* install-script-canary: a public package whose lock entry declares an install script
  (esbuild) is installed through the production preparation; its placeholder launcher
  must remain unreplaced, proving lifecycle scripts never run.
"""

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

import bundle
import fetch
import network_probe
import host_cleanup


ROOT = Path(__file__).resolve().parents[2]
RUNNER_TEMP = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())).resolve()
RUN_ID = os.environ.get("GITHUB_RUN_ID", "")
CONTROL_SHA = os.environ.get("CI_SHA", "")
CONTROL_RUN_ID = RUN_ID
SOURCE_CANARY = "SYNTHETIC_SOURCE_CANARY_7f8c"
KEY_CANARY = b"KEYCANARY-73A10X"
KEY_BYTES = KEY_CANARY + bytes(range(16))
COMMAND_CANARIES = ("::add-mask::SYNTHETIC_SOURCE_CANARY_7f8c", "::error::SYNTHETIC_SOURCE_CANARY_7f8c",
                    chr(35) * 2 + "[group]SYNTHETIC_SOURCE_CANARY_7f8c", "::set-output name=x::SYNTHETIC_SOURCE_CANARY_7f8c")
BACKGROUND_MARKER = "DEVLANE_E2E_BACKGROUND_MARKER"
RUST_VERSION = "1.99.1"
PLAYWRIGHT_VERSION = "1.54.2"
SYNTHETIC_LOCK = ROOT / "kit/confinement/synthetic_project/package-lock.json"


def _require(condition, code):
    if not condition:
        raise RuntimeError(code)


def _scan_output(data, code):
    for canary in (SOURCE_CANARY.encode("ascii"), KEY_CANARY, b"::add-mask::", b"::error::", (chr(35) * 2 + "[group]SYNTHETIC").encode("ascii")):
        _require(canary not in data, code)


def _run(argv, *, env=None, timeout=900, expected=0, scan=True, cwd=None):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, timeout=timeout,
                            close_fds=True, check=False, cwd=cwd)
    _require(result.returncode == expected, "production-path-" + Path(argv[0]).name + "-failed")
    if scan:
        _scan_output(result.stdout + result.stderr, "canary-in-command-output")
    return result


def _processes_matching(marker):
    result = subprocess.run(["pgrep", "-f", marker], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    own = {os.getpid(), os.getppid()}
    return [int(item) for item in result.stdout.split() if int(item) not in own]


"""---------------------------------------------------------------- metadata"""

def _node_lock_from_reviewed(dev_dependencies):
    """A non-workspace lock holding exactly the reachable closure of the requested dev packages,
    taken from the reviewed synthetic lock (real integrity hashes, native optional bindings)."""
    original = json.loads(SYNTHETIC_LOCK.read_text(encoding="utf-8"))["packages"]

    def resolve(owner, name):
        """npm's lookup: nested node_modules of the requester first, then each ancestor."""
        base = owner
        while True:
            candidate = (base + "/" if base else "") + "node_modules/" + name
            if candidate in original:
                return candidate
            if "/node_modules/" not in base and not base.startswith("node_modules/"):
                return None
            base = base.rsplit("/node_modules/", 1)[0] if "/node_modules/" in base else ""
            if base == "" and (("node_modules/" + name) not in original):
                return None

    chosen, queue = {}, []
    for name, version in dev_dependencies.items():
        path = "node_modules/" + name
        _require(path in original and original[path].get("version") == version, "reviewed-lock-package-missing")
        queue.append(path)
    while queue:
        path = queue.pop()
        if path in chosen:
            continue
        chosen[path] = dict(original[path])
        entry = original[path]
        for group in ("dependencies", "optionalDependencies", "peerDependencies"):
            for name in entry.get(group, {}):
                found = resolve(path, name)
                if found is not None:
                    queue.append(found)
    return {
        "name": "synthetic-private-canary", "version": "0.0.0", "lockfileVersion": 3, "requires": True,
        "packages": {"": {"name": "synthetic-private-canary", "version": "0.0.0", "devDependencies": dict(dev_dependencies)},
                     **dict(sorted(chosen.items()))},
    }


def _node_projection(source_lock, playwright=()):
    npm_package, npm_lock, npm_rows = fetch.project_npm_lock(bundle.canonical_json(source_lock))
    projection = {
        "schema": 1, "profile": "core-node", "tools": {"node": "24.22.1", "npm": "11.19.1"},
        "npm": npm_rows, "cargo": [], "playwright": list(playwright), "npm_package": npm_package,
        "npm_lock": npm_lock, "cargo_workspaces": [],
    }
    payload = bundle.canonical_json(projection)
    fetch.validate_projection(payload, "core-node")
    return projection, payload


def _generated_lock(manifest_text, *, node):
    """Resolve a lock on the (networked) hosted runner for packages the reviewed lock lacks."""
    with tempfile.TemporaryDirectory(prefix="devlane-lock-", dir=str(RUNNER_TEMP)) as temporary:
        directory = Path(temporary)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": temporary, "LC_ALL": "C"}
        if node:
            (directory / "package.json").write_text(manifest_text, encoding="utf-8")
            _run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
                 env=env, cwd=temporary, timeout=600, scan=False)
            return json.loads((directory / "package-lock.json").read_text(encoding="utf-8"))
        (directory / "src").mkdir()
        (directory / "src/lib.rs").write_text("", encoding="ascii")
        (directory / "build.rs").write_text("fn main() {}\n", encoding="ascii")
        (directory / "Cargo.toml").write_text(manifest_text, encoding="utf-8")
        _run(["cargo", "generate-lockfile"], env=dict(env, CARGO_HOME=str(directory / "cargo-home")),
             cwd=temporary, timeout=600, scan=False)
        return (directory / "Cargo.lock").read_bytes()


def _rust_projection(lock_bytes):
    cargo_manifest, cargo_lock, cargo_rows = fetch.project_cargo_lock(lock_bytes)
    workspace_manifest, workspace_lock, _ = fetch.project_cargo_lock(lock_bytes)
    projection = {
        "schema": 1, "profile": "core-rust", "tools": {"cargo": RUST_VERSION, "rustc": RUST_VERSION},
        "npm": [], "cargo": cargo_rows, "playwright": [], "cargo_manifest": cargo_manifest,
        "cargo_lock": cargo_lock,
        "cargo_workspaces": [
            {"path": "fuzz/Cargo.lock", "manifest": workspace_manifest, "lock": workspace_lock},
            {"path": "runtime/Cargo.lock", "manifest": workspace_manifest, "lock": workspace_lock},
        ],
    }
    payload = bundle.canonical_json(projection)
    fetch.validate_projection(payload, "core-rust")
    return projection, payload


"""---------------------------------------------------------------- fixtures"""

def _probe_script():
    """Workload-side inspection shared by the Node fixtures: it throws if any boundary is open.

    The key hex string is built at run time from its bytes, so no file in the workspace spells it.
    """
    return r'''import fs from 'node:fs';
import path from 'node:path';
const KEY_TEXT = __KEY_CANARY__;
const KEY_HEX = Buffer.from(__KEY_BYTES__).toString('hex');
const names = Object.keys(process.env);
if (names.includes('DEVLANE_DECRYPT_KEY') || names.some((name) => name.startsWith('GITHUB_') || name.startsWith('RUNNER_') || name === 'SYNTHETIC_KEY_CANARY' || name.startsWith('ACTIONS_'))) throw new Error('environment-boundary');
if (Object.values(process.env).some((value) => String(value).includes(KEY_HEX) || String(value).includes(KEY_TEXT))) throw new Error('environment-value-boundary');
if (process.argv.some((argument) => argument.includes(KEY_TEXT) || argument.includes(KEY_HEX))) throw new Error('argument-boundary');
for (const name of fs.readdirSync('/proc/self/fd')) {
  const fd = Number(name);
  if (fd <= 2) continue;
  try { if (fs.readlinkSync(`/proc/self/fd/${fd}`).startsWith('socket:[')) throw new Error('descriptor'); }
  catch (error) { if (error?.message === 'descriptor') throw error; }
}
for (const forbidden of ['/ho' + 'me/runner', '/run/docker.sock', '/var/run/docker.sock', '/proc/1/root/home']) {
  if (fs.existsSync(forbidden)) throw new Error('host-path-boundary');
}
const environ = fs.readFileSync('/proc/self/environ', 'utf8');
if (environ.includes(KEY_HEX) || environ.includes('DEVLANE_DECRYPT_KEY')) throw new Error('environ-boundary');
function walk(directory, depth) {
  if (depth > 6) return;
  let entries = [];
  try { entries = fs.readdirSync(directory, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    const full = path.join(directory, entry.name);
    if (entry.name === 'node_modules' || entry.name === 'cargo-home' || entry.name === 'npm-cache') continue;
    if (entry.isDirectory()) walk(full, depth + 1);
    else if (entry.isFile()) {
      try { if (fs.statSync(full).size < 1048576 && fs.readFileSync(full, 'latin1').includes(KEY_HEX)) throw new Error('key-file-boundary'); }
      catch (error) { if (error?.message === 'key-file-boundary') throw error; }
    }
  }
}
for (const root of ['/trusted', '/workspace/source', '/tmp', '/devlane-home', '/scratch/tmp', '/scratch/reports']) walk(root, 0);
const visible = fs.readdirSync('/proc').filter((name) => /^[0-9]+$/.test(name));
if (visible.length > 64) throw new Error('process-visibility-boundary');
'''.replace("__KEY_CANARY__", json.dumps(KEY_CANARY.decode("ascii"))).replace("__KEY_BYTES__", json.dumps(list(KEY_BYTES)))


def _canary_emitters():
    lines = []
    for canary in COMMAND_CANARIES:
        lines.append("console.log(" + json.dumps(canary) + ");")
        lines.append("console.error(" + json.dumps(canary) + ");")
    lines.append("console.log(" + json.dumps(KEY_CANARY.decode("ascii")) + ");")
    return "\n".join(lines) + "\n"


def _node_source(lock, *, failing_test=False, hang=False, package_name="typescript"):
    version = lock["packages"]["node_modules/" + package_name]["version"]
    package = {
        "name": "synthetic-private-canary", "version": "0.0.0", "private": True,
        "type": "module", "devDependencies": {package_name: version},
        "scripts": {"typecheck": "node -e \"process.exit(0)\"", "test": "node tests/write-report.mjs"},
    }
    tsconfig = {"compilerOptions": {"strict": True, "noEmit": True, "target": "ES2020", "module": "ESNext",
                                    "moduleResolution": "bundler", "skipLibCheck": True}}
    source = ("export const planted = '" + SOURCE_CANARY + "';\n"
              "export const value: number = 41;\n")
    status = "failed" if failing_test else "passed"
    background = ""
    if hang:
        background = ("setInterval(() => {}, 1000);\n"
                      "await new Promise((resolve) => setTimeout(resolve, 600000));\n")
    script = _probe_script() + r'''import { spawn } from 'node:child_process';
const output = process.argv.find((item) => item.startsWith('--outputFile='))?.slice('--outputFile='.length) ?? '/scratch/reports/vitest.json';
spawn(process.execPath, ['-e', 'setTimeout(() => {}, 900000) /* __BACKGROUND_MARKER__ */'], { detached: true, stdio: 'ignore' }).unref();
''' + _canary_emitters() + background + r'''fs.writeFileSync(output, JSON.stringify({ testResults: [{ assertionResults: [{ fullName: 'synthetic canary suite accepted test', status: __TEST_STATUS__, failureMessages: [__SOURCE_CANARY__, __KEY_CANARY__] }] }] }));
'''
    script = (script.replace("__TEST_STATUS__", json.dumps(status))
              .replace("__SOURCE_CANARY__", json.dumps(SOURCE_CANARY))
              .replace("__KEY_CANARY__", json.dumps(KEY_CANARY.decode("ascii")))
              .replace("__BACKGROUND_MARKER__", BACKGROUND_MARKER))
    return {
        "package.json": bundle.canonical_json(package) + b"\n",
        "package-lock.json": bundle.canonical_json(lock) + b"\n",
        "tsconfig.json": bundle.canonical_json(tsconfig) + b"\n",
        "src/example.ts": source.encode("ascii"),
        "tests/write-report.mjs": script.encode("ascii"),
    }


def _real_node_source(lock):
    dev = lock["packages"][""]["devDependencies"]
    package = {
        "name": "synthetic-private-canary", "version": "0.0.0", "private": True, "type": "module",
        "devDependencies": dev,
        "scripts": {"typecheck": "tsc --noEmit -p tsconfig.json", "test": "vitest"},
    }
    tsconfig = {"compilerOptions": {"strict": True, "noEmit": True, "target": "ES2022", "module": "ESNext",
                                    "moduleResolution": "bundler", "skipLibCheck": True}}
    source = ("export const planted = '" + SOURCE_CANARY + "';\n"
              "export function add(left: number, right: number): number { return left + right; }\n")
    tests = (
        "import { expect, test } from 'vitest';\n"
        "import { add, planted } from '../src/example';\n"
        "test('real vitest accepted test', () => {\n"
        + _canary_emitters() +
        "  expect(add(1, 2)).toBe(3);\n});\n"
        "test('real vitest failing test', () => {\n"
        "  expect(planted).toBe('not-the-planted-value');\n});\n"
    )
    return {
        "package.json": bundle.canonical_json(package) + b"\n",
        "package-lock.json": bundle.canonical_json(lock) + b"\n",
        "tsconfig.json": bundle.canonical_json(tsconfig) + b"\n",
        "src/example.ts": source.encode("ascii"),
        "tests/example.test.ts": tests.encode("ascii"),
    }


def _browser_source(lock):
    package = {
        "name": "synthetic-private-canary", "version": "0.0.0", "private": True, "type": "module",
        "devDependencies": lock["packages"][""]["devDependencies"],
        "scripts": {"typecheck": "node -e \"process.exit(0)\"", "test": "node tests/write-report.mjs"},
    }
    config = ("import { defineConfig } from '@playwright/test';\n"
              "export default defineConfig({ testDir: './browser', reporter: 'json', workers: 1 });\n")
    spec = (
        "import { test, expect } from '@playwright/test';\n"
        "test('browser frame accepted', async ({ page }) => {\n"
        "  await page.setContent('<h1 id=\"x\">" + SOURCE_CANARY + "</h1>');\n"
        + _canary_emitters() +
        "  await expect(page.locator('h1')).toBeVisible();\n});\n"
    )
    report = (
        "import fs from 'node:fs';\n"
        "fs.mkdirSync('/scratch/reports', { recursive: true });\n"
        "fs.writeFileSync('/scratch/reports/vitest.json', JSON.stringify({ testResults: [{ assertionResults: "
        "[{ fullName: 'browser lane unit placeholder', status: 'passed', failureMessages: [] }] }] }));\n"
    )
    return {
        "package.json": bundle.canonical_json(package) + b"\n",
        "package-lock.json": bundle.canonical_json(lock) + b"\n",
        "tsconfig.json": bundle.canonical_json({"compilerOptions": {"noEmit": True, "skipLibCheck": True,
                                                                     "target": "ES2022", "module": "ESNext",
                                                                     "moduleResolution": "bundler"}}) + b"\n",
        "src/example.ts": ("export const planted = '" + SOURCE_CANARY + "';\n").encode("ascii"),
        "playwright.config.ts": config.encode("ascii"),
        "browser/frame.spec.ts": spec.encode("ascii"),
        "tests/write-report.mjs": report.encode("ascii"),
    }


def _rust_test_source(extra_assert=""):
    marker = chr(35)
    return (
        marker + "[cfg(test)]\nmod tests {\n    " + marker + "[test]\n"
        "    fn child_has_no_control_secrets_or_sockets() {\n"
        "        for (name, _) in std::env::vars() {\n"
        "            assert!(name != \"DEVLANE_DECRYPT_KEY\");\n"
        "            assert!(!name.starts_with(\"GITHUB_\"));\n"
        "            assert!(!name.starts_with(\"RUNNER_\"));\n"
        "            assert!(name != \"SYNTHETIC_KEY_CANARY\");\n"
        "        }\n"
        "        let key_canary = \"" + KEY_CANARY.decode("ascii") + "\";\n"
        "        assert!(!std::env::args().any(|argument| argument.contains(key_canary)));\n"
        "        assert!(!std::path::Path::new(\"/ho\\x6de/runner\").exists());\n"
        "        let fds = std::fs::read_dir(\"/proc/self/fd\").expect(\"proc-fd\");\n"
        "        for entry in fds.flatten() {\n"
        "            if let Ok(target) = std::fs::read_link(entry.path()) {\n"
        "                assert!(!target.to_string_lossy().starts_with(\"socket:[\"));\n"
        "            }\n        }\n"
        + extra_assert +
        "        let _private = \"" + SOURCE_CANARY + "\";\n    }\n}\n"
    )


def _rust_build_script():
    return (
        "fn main() {\n"
        "    println!(\"cargo:warning=" + SOURCE_CANARY + "\");\n"
        "    println!(\"cargo:warning=" + KEY_CANARY.decode("ascii") + "\");\n"
        "    println!(\"cargo:warning=::add-mask::" + SOURCE_CANARY + "\");\n"
        "}\n"
    )


def _rust_files(manifest, lock, *, real_dependencies=False):
    extra = ""
    library = _rust_test_source(extra)
    if real_dependencies:
        library = ("pub fn rendered(value: u32) -> String { let mut buffer = itoa::Buffer::new(); buffer.format(value).to_owned() }\n"
                   + _rust_test_source("        assert_eq!(super::rendered(7), \"7\");\n"
                                       "        let _ = fastrand::u8(..);\n"))
    return {
        "Cargo.toml": manifest.encode("utf-8"),
        "Cargo.lock": lock,
        "build.rs": _rust_build_script().encode("ascii"),
        "src/lib.rs": library.encode("ascii"),
    }


def _archive(files, profile, projection_sha, allowed_files, allowed_tests, frames):
    inventory = [{"path": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
                 for name, payload in sorted(files.items())]
    lock_name = "package-lock.json" if profile == "core-node" else "Cargo.lock"
    manifest = {
        "schema": 1, "profile": profile, "profile_revision": 1, "source_revision": CONTROL_SHA,
        "tree_sha256": hashlib.sha256(bundle.canonical_json(inventory)).hexdigest(),
        "files": inventory,
        "original_lockfiles": {lock_name: hashlib.sha256(files[lock_name]).hexdigest()},
        "fetch_sha256": projection_sha,
        "allowed_files": allowed_files, "allowed_tests": allowed_tests, "frames": frames,
        "limits": {"ciphertext_bytes": bundle.MAX_CIPHERTEXT, "expanded_bytes": bundle.MAX_EXPANDED,
                   "files": bundle.MAX_FILES, "file_bytes": bundle.MAX_FILE},
    }
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o600
            info.uid = info.gid = info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
        payload = bundle.canonical_json(manifest)
        info = tarfile.TarInfo(".devlane/manifest.json")
        info.size = len(payload)
        info.mode = 0o600
        info.uid = info.gid = info.mtime = 0
        archive.addfile(info, io.BytesIO(payload))
    return gzip.compress(stream.getvalue(), mtime=0)


def scenarios():
    """The scenario table; building it needs the network only for the generated-lock scenarios."""
    result = []
    node_lock = _node_lock_from_reviewed({"typescript": "6.0.3"})
    projection, payload = _node_projection(node_lock)
    result.append({
        "name": "synthetic-node", "profile": "core-node", "projection": projection, "payload": payload,
        "files": lambda **kw: _node_source(node_lock, **kw),
        "allowed_files": {"src/example.ts": "file_0001"},
        "allowed_tests": {"synthetic canary suite accepted test": "case_0001"}, "frames": {},
        "variants": ("startup-refusal", "accept", "wrong-key", "failing-test", "cancel"),
    })
    real_lock = _node_lock_from_reviewed({"typescript": "6.0.3", "vite": "8.3.5", "vitest": "5.0.5"})
    projection, payload = _node_projection(real_lock)
    result.append({
        "name": "real-node", "profile": "core-node", "projection": projection, "payload": payload,
        "files": lambda **kw: _real_node_source(real_lock),
        "allowed_files": {"src/example.ts": "file_0001"},
        "allowed_tests": {"real vitest accepted test": "case_0001", "real vitest failing test": "case_0002"},
        "frames": {}, "variants": ("accept-with-failure",),
    })
    return result


INSTALL_SCRIPT_PACKAGE = "esbuild"
INSTALL_SCRIPT_VERSION = "0.25.9"
INSTALL_SCRIPT_PLACEHOLDER_LIMIT = 64 * 1024


def _install_script_canary_check(prepared_path):
    """esbuild's public install script replaces its placeholder launcher with the native binary.

    With scripts suppressed the launcher must still be the small placeholder, while the platform
    package that carries the binary is present: the package installed, its script did not run.
    """
    launcher = Path(prepared_path) / "node_modules" / INSTALL_SCRIPT_PACKAGE / "bin" / INSTALL_SCRIPT_PACKAGE
    _require(launcher.is_file() and not launcher.is_symlink(), "install-script-canary-missing")
    _require(launcher.stat().st_size < INSTALL_SCRIPT_PLACEHOLDER_LIMIT, "install-script-ran")
    _require((Path(prepared_path) / "node_modules" / "@esbuild").is_dir(), "install-script-canary-platform-package-missing")


def late_scenarios():
    """Scenarios that resolve packages from the public registries on the hosted runner."""
    result = []
    canary_manifest = json.dumps({"name": "synthetic-private-canary", "version": "0.0.0", "private": True,
                                  "devDependencies": {INSTALL_SCRIPT_PACKAGE: INSTALL_SCRIPT_VERSION}})
    canary_lock = _generated_lock(canary_manifest, node=True)
    _require(bool(canary_lock["packages"]["node_modules/" + INSTALL_SCRIPT_PACKAGE].get("hasInstallScript")),
             "install-script-canary-lacks-marker")
    projection, payload = _node_projection(canary_lock)
    result.append({
        "name": "install-script-canary", "profile": "core-node", "projection": projection, "payload": payload,
        "files": lambda **kw: _node_source(canary_lock, package_name=INSTALL_SCRIPT_PACKAGE, **kw),
        "allowed_files": {"src/example.ts": "file_0001"},
        "allowed_tests": {"synthetic canary suite accepted test": "case_0001"}, "frames": {},
        "variants": ("accept",), "after_prepare": _install_script_canary_check,
    })
    rust_manifest = (
        '[package]\nname = "devlane-projection"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n\n'
        '[lib]\npath = "src/lib.rs"\n\n[dependencies]\nitoa = "=1.0.15"\n\n[dev-dependencies]\nfastrand = "=2.3.0"\n'
    )
    lock = _generated_lock(rust_manifest, node=False)
    projection, payload = _rust_projection(lock)
    result.append({
        "name": "real-rust", "profile": "core-rust", "projection": projection, "payload": payload,
        "files": lambda **kw: _rust_files(rust_manifest, lock, real_dependencies=True),
        "allowed_files": {"src/lib.rs": "file_0001"},
        "allowed_tests": {"tests::child_has_no_control_secrets_or_sockets": "case_0001"}, "frames": {},
        "variants": ("accept",),
    })
    browser_manifest = json.dumps({"name": "synthetic-private-canary", "version": "0.0.0", "private": True,
                                   "devDependencies": {"@playwright/test": PLAYWRIGHT_VERSION}})
    browser_lock = _generated_lock(browser_manifest, node=True)
    projection, payload = _node_projection(browser_lock, playwright=("chromium",))
    result.append({
        "name": "real-browser", "profile": "core-node", "projection": projection, "payload": payload,
        "files": lambda **kw: _browser_source(browser_lock),
        "allowed_files": {"src/example.ts": "file_0001"},
        "allowed_tests": {"browser lane unit placeholder": "case_0001"},
        "frames": {"browser frame accepted": "frame_0001"}, "variants": ("accept",),
    })
    return result


"""---------------------------------------------------------------- production path"""

def _tool_paths(profile):
    paths = {name: shutil.which(name) or "" for name in ("node", "npm", "cargo", "rustc")}
    if profile == "core-rust":
        rustup = shutil.which("rustup")
        _require(bool(rustup), "rustup-unavailable")
        for name in ("cargo", "rustc"):
            result = _run([rustup, "which", "--toolchain", RUST_VERSION, name], timeout=15)
            paths[name] = result.stdout.decode("ascii", "strict").strip()
    return paths


def _prepare(profile, projection_path, prepared_path):
    paths = _tool_paths(profile)
    command = [
        "sudo", "-n", "unshare", "--mount", "--pid", "--ipc", "--fork", "--mount-proc", "--kill-child", "--",
        sys.executable, "-B", str(ROOT / "kit/devlane/prepare.py"),
        "--projection", str(projection_path), "--output", str(prepared_path), "--profile", profile,
        "--owner-uid", str(os.getuid()), "--owner-gid", str(os.getgid()),
    ]
    for name, path in paths.items():
        command.extend(("--" + name + "-path", path))
    _run(command, timeout=60 * 60)
    _require(prepared_path.is_dir() and not prepared_path.is_symlink(), "prepared-tree-missing")
    return paths


def _positive_control(path):
    value = network_probe.positive_control(timeout=5)
    _require(value == {"connected": True, "target": "public-tls-control"}, "positive-control-failed")
    path.write_bytes(bundle.canonical_json(value) + b"\n")


def _supervisor(*arguments):
    return [sys.executable, "-B", str(ROOT / "kit/devlane/supervisor.py"), *arguments]


def _run_variant(scenario, projection_bytes, prepared_path, tool_paths, key_bytes, variant):
    profile = scenario["profile"]
    root = RUNNER_TEMP / ("devlane-" + RUN_ID)
    _require(not root.exists() and not root.is_symlink(), "runner-root-already-exists")
    root.mkdir(mode=0o700)
    try:
        projection_path = root / "projection.json"
        projection_path.write_bytes(projection_bytes)
        expires = int(time.time()) + 3600
        label = scenario["name"].replace("-", "")
        wave_id = "e2e-wave-" + label
        bundle_id = "e2e-bundle-" + label + variant.replace("-", "")
        projection_sha = hashlib.sha256(projection_bytes).hexdigest()
        files = scenario["files"](**({"failing_test": True} if variant == "failing-test" else
                                     {"hang": True} if variant == "cancel" else {}))
        archive = _archive(files, profile, projection_sha, scenario["allowed_files"],
                           scenario["allowed_tests"], scenario["frames"])
        bindings = {
            "format": "kd-public-devlane-aesgcm-v1", "repository_id": fetch.REPOSITORY_ID,
            "control_sha": CONTROL_SHA, "workflow_path": fetch.WORKFLOW_PATH, "profile": profile,
            "wave_id": wave_id, "bundle_id": bundle_id, "fetch_sha256": projection_sha, "expires": expires,
        }
        envelope = bundle.build_envelope(archive, key_bytes, bindings)
        bundle_path = root / "bundle.enc"
        bundle_path.write_bytes(envelope)
        context = {
            "repository": fetch.REPOSITORY, "repository_id": fetch.REPOSITORY_ID,
            "server_url": "https://github.com", "event": "workflow_dispatch", "ref": "refs/heads/main",
            "control_sha": CONTROL_SHA, "control_run_id": CONTROL_RUN_ID,
            "workflow_path": fetch.WORKFLOW_PATH, "run_attempt": 1, "profile": profile,
            "wave_id": wave_id, "bundle_id": bundle_id, "bundle_asset_id": "123456",
            "bundle_sha256": hashlib.sha256(envelope).hexdigest(), "bundle_size": len(envelope),
            "projection_asset_id": "123457", "projection_sha256": projection_sha,
            "projection_size": len(projection_bytes), "expires": expires,
        }
        fetch.validate_dispatch(context)
        context_path = root / "context.json"
        context_path.write_bytes(bundle.canonical_json(context) + b"\n")
        positive_path = root / "positive-control.json"
        _positive_control(positive_path)
        state_path = root / "state"
        if variant == "startup-refusal":
            """Startup fails after the supervisor process exists: cleanup must still confirm and leave nothing."""
            projection_path.write_bytes(projection_bytes + b" ")
        start = _supervisor("start", "--state-dir", str(state_path), "--context", str(context_path),
                            "--workspace", str(ROOT), "--prepared", str(prepared_path),
                            "--bundle", str(bundle_path), "--projection", str(projection_path),
                            "--positive-control", str(positive_path))
        for name in ("node", "npm", "cargo", "rustc"):
            start.extend(("--" + name + "-path", tool_paths[name]))
        if variant == "startup-refusal":
            _run(start, timeout=90, expected=2)
            host_cleanup.clean(str(root), str(RUNNER_TEMP))
            _require(not root.exists(), "host-cleanup-root-remains")
            _require(not _processes_matching("supervisor.py"), "supervisor-survived-startup-refusal")
            return
        _run(start, timeout=90)
        _run(_supervisor("probe", "--state-dir", str(state_path)), timeout=90)

        key_path = root / "synthetic-key.hex"
        bundle.write_private_key(key_path, key_bytes)
        supplied_key = bundle.read_key_file(key_path).hex()
        if variant == "wrong-key":
            supplied_key = bytes(reversed(key_bytes)).hex()
        decrypt_env = os.environ.copy()
        decrypt_env["DEVLANE_DECRYPT_KEY"] = supplied_key
        try:
            _run(_supervisor("decrypt", "--state-dir", str(state_path)), env=decrypt_env, timeout=180,
                 expected=2 if variant == "wrong-key" else 0)
        finally:
            decrypt_env.pop("DEVLANE_DECRYPT_KEY", None)
            supplied_key = ""
            key_path.unlink(missing_ok=True)
        execute = _supervisor("execute", "--state-dir", str(state_path), "--context", str(context_path))
        if variant == "wrong-key":
            """A refused decryption must leave execution refused: exit 2 and no summary at all."""
            refused = _run(execute, expected=2)
            _require(refused.stdout == b"", "summary-after-decrypt-refusal")
        elif variant == "cancel":
            process = subprocess.Popen(execute, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, close_fds=True)
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline and process.poll() is None and not _processes_matching(BACKGROUND_MARKER):
                time.sleep(1)
            _require(process.poll() is None and bool(_processes_matching(BACKGROUND_MARKER)),
                     "cancel-target-did-not-start")
            host_cleanup.clean(str(root), str(RUNNER_TEMP))
            try:
                output, errors = process.communicate(timeout=180)
            except subprocess.TimeoutExpired:
                process.kill()
                raise RuntimeError("cancelled-execute-did-not-end") from None
            _require(process.returncode != 0, "cancelled-execute-reported-success")
            _scan_output(output + errors, "canary-after-cancel")
        else:
            expected = 1 if variant in ("failing-test", "accept-with-failure") else 0
            result = _run(execute, timeout=60 * 40, expected=expected)
            summary = result.stdout.splitlines()
            _require(all(line.startswith(b"{") for line in summary), "summary-schema-invalid")
            allowed = (b"file_0001", b"case_0001", b"case_0002", b"frame_0001", b"DEVLANE_FAILURE")
            _require(all(any(item in line for item in allowed) for line in summary), "summary-identity-invalid")
            _require(len(summary) <= 100 and len(result.stdout) <= 16 * 1024, "summary-limits")
            if variant in ("failing-test", "accept-with-failure"):
                wanted = b'"test":"case_0001"' if variant == "failing-test" else b'"test":"case_0002"'
                _require(any(wanted in line for line in summary), "test-failure-not-mapped")
            if scenario["frames"]:
                _require(any(b'"frame":"frame_0001"' in line and b'"status":"pass"' in line for line in summary),
                         "browser-frame-not-reported")
            if variant == "accept" and scenario["name"] == "synthetic-node":
                _require(not any(b'"kind":"control"' in line for line in summary), "unexpected-control-failure")
        os.environ.setdefault("GITHUB_RUN_ID", RUN_ID)
        host_cleanup.clean(str(root), str(RUNNER_TEMP))
        _require(not root.exists(), "host-cleanup-root-remains")
        """Descendants that outlived their parent must not outlive cleanup."""
        _require(not _processes_matching(BACKGROUND_MARKER), "background-process-survived-cleanup")
    finally:
        (root / "synthetic-key.hex").unlink(missing_ok=True)
        if root.exists() and not root.is_symlink():
            os.environ.setdefault("GITHUB_RUN_ID", RUN_ID)
            host_cleanup.clean(str(root), str(RUNNER_TEMP))


def _run_scenario(scenario):
    prepared = RUNNER_TEMP / ("devlane-e2e-" + RUN_ID + "-" + scenario["name"])
    projection_path = RUNNER_TEMP / ("devlane-e2e-projection-" + RUN_ID + "-" + scenario["name"])
    try:
        projection_path.write_bytes(scenario["payload"])
        tool_paths = _prepare(scenario["profile"], projection_path, prepared)
        if "after_prepare" in scenario:
            scenario["after_prepare"](prepared)
        key_bytes = KEY_CANARY + bytes(range(16))
        for variant in scenario["variants"]:
            _run_variant(scenario, scenario["payload"], prepared, tool_paths, key_bytes, variant)
    finally:
        if prepared.exists() and not prepared.is_symlink():
            shutil.rmtree(prepared)
        projection_path.unlink(missing_ok=True)


def main():
    _require(sys.platform.startswith("linux") and os.geteuid() != 0, "linux-runner-user-required")
    _require(bool(RUN_ID and RUN_ID.isdecimal() and CONTROL_SHA and len(CONTROL_SHA) == 40), "workflow-identity-required")
    _require(shutil.which("sudo") and shutil.which("unshare") and shutil.which("pgrep"), "linux-tools-required")
    done = []
    for scenario in scenarios():
        _run_scenario(scenario)
        done.append(scenario["name"])
    """Synthetic fixture for the Rust profile (no network resolution needed)."""
    cargo_lock = b'version = 3\n\n[[package]]\nname = "devlane-projection"\nversion = "0.0.0"\n'
    projection, payload = _rust_projection(cargo_lock)
    synthetic_rust = {
        "name": "synthetic-rust", "profile": "core-rust", "projection": projection, "payload": payload,
        "files": lambda **kw: _rust_files(projection["cargo_manifest"], projection["cargo_lock"].encode("utf-8")),
        "allowed_files": {"src/lib.rs": "file_0001"},
        "allowed_tests": {"tests::child_has_no_control_secrets_or_sockets": "case_0001"}, "frames": {},
        "variants": ("accept", "wrong-key"),
    }
    _run_scenario(synthetic_rust)
    done.append(synthetic_rust["name"])
    for scenario in late_scenarios():
        _run_scenario(scenario)
        done.append(scenario["name"])
    print("devlane_production_e2e=pass scenarios=" + ",".join(done))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        code = str(error) if type(error) is RuntimeError and len(str(error)) < 80 else "unexpected-failure"
        print("devlane_production_e2e=refused code=" + code, file=sys.stderr)
        raise SystemExit(1)
