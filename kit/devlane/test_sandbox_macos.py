"""Source-free unit and local Seatbelt acceptance for the macOS devlane worker."""

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

import sandbox_macos as sandbox

NODE = shutil.which("node")
if NODE:
    NODE = str(Path(NODE).resolve(strict=True))
PRIVATE_RUN = chr(47) + "private" + chr(47) + "run"


def _hosted_profile_probe_available():
    if platform.system() != "Darwin" or not NODE or not Path("/usr/bin/sandbox-exec").exists():
        return False
    try:
        product = subprocess.run(["/usr/bin/sw_vers", "-productVersion"], check=True, capture_output=True,
                                 text=True, timeout=5).stdout.strip()
        node_version = subprocess.run([NODE, "--version"], check=True, capture_output=True, text=True,
                                      timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    return product.startswith("15.") and node_version == "v24.22.1"


class MacProfileTests(unittest.TestCase):
    def test_profile_is_deny_default_and_has_required_boundary_rules(self):
        text = sandbox.profile_text(
            workspace="/tmp/devlane-workspace", prepared="/tmp/devlane-prepared",
            scratch="/tmp/devlane-scratch", home="/tmp/devlane-home",
            control="/tmp/devlane-control", node="/usr/bin/python3",
            developer="/Library/Developer/CommandLineTools", clang="/usr/bin/true",
            npm_cli="/opt/node/lib/node_modules/npm/bin/npm-cli.js",
        )
        self.assertTrue(text.startswith("(version 1)\n(deny default)\n"))
        self.assertIn("(deny network*)", text)
        self.assertIn("(deny lsopen)", text)
        self.assertIn("(deny mach-lookup)", text)
        self.assertIn('(allow process-exec (literal "/usr/bin/python3"))', text)
        self.assertIn('(allow process-exec (literal "/bin/bash"))', text)
        self.assertIn('(allow process-exec (subpath "/tmp/devlane-workspace/source"))', text)
        self.assertIn('(allow file-read* (subpath "/opt/node/lib/node_modules/npm"))', text)
        self.assertIn('(subpath "/tmp/devlane-workspace/source")', next(
            line for line in text.splitlines() if line.startswith("(allow file-map-executable")))
        self.assertNotIn('(allow file-write* (subpath "/tmp")', text)

    def test_profile_rejects_unsafe_path_text(self):
        for value in ("relative", "/tmp/a\n(allow default)", "/tmp/a\"b"):
            with self.subTest(path=value), self.assertRaises(sandbox.Refusal):
                sandbox._quote(value)

    @unittest.skipUnless(platform.system() == "Darwin" and Path("/usr/bin/sandbox-exec").exists(),
                         "macOS Seatbelt tools are unavailable")
    def test_generated_profile_is_accepted_by_sandbox_exec(self):
        with tempfile.TemporaryDirectory(prefix="devlane-seatbelt-syntax-") as temporary:
            root = Path(temporary).resolve(strict=True)
            for name in ("workspace/source", "prepared", "scratch", "home", "trusted"):
                (root / name).mkdir(parents=True, exist_ok=True)
            profile = root / "worker.sb"
            profile.write_text(sandbox.profile_text(
                workspace=root / "workspace", prepared=root / "prepared", scratch=root / "scratch",
                home=root / "home", control=sandbox.CONTROL_ROOT, node=NODE or "/usr/bin/true",
                developer="/Library/Developer/CommandLineTools", clang="/usr/bin/true",
            ), encoding="utf-8")
            result = subprocess.run(
                ["/usr/bin/sandbox-exec", "-f", str(profile), "/usr/bin/true"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "HOME": str(root / "home"),
                     "TMPDIR": str(root / "scratch"), "LC_ALL": "C"},
                timeout=10, check=False, close_fds=True,
            )
            self.assertNotEqual(result.returncode, 64, result.stderr.decode("utf-8", "replace"))
            self.assertNotIn(b"syntax error", result.stderr.lower())

    def test_only_fixed_virtual_paths_are_mapped_to_private_run_paths(self):
        worker = {
            "source": PRIVATE_RUN + "/workspace/source", "prepared": PRIVATE_RUN + "/prepared",
            "scratch": PRIVATE_RUN + "/scratch",
        }
        result = sandbox._mapped_command([
            "npm", "--prefix", "/workspace/source/packages/kernel-ui-kit",
            "--report=/scratch/reports/result", "/workspace/source-escape/file",
        ], worker)
        self.assertEqual(result, [
            "npm", "--prefix", PRIVATE_RUN + "/workspace/source/packages/kernel-ui-kit",
            "--report=" + PRIVATE_RUN + "/scratch/reports/result", "/workspace/source-escape/file",
        ])

    def test_cleanup_requires_a_well_formed_directory_service_listing(self):
        self.assertFalse(sandbox._account_is_listed(b"daemon 1\n_runner 501\n", "kddevlane123"))
        self.assertTrue(sandbox._account_is_listed(b"daemon 1\nkddevlane123 502\n", "kddevlane123"))
        for payload in (b"malformed\n", b"daemon nope\n", b"\xff\n"):
            with self.subTest(payload=payload), self.assertRaises(sandbox.Refusal):
                sandbox._account_is_listed(payload, "kddevlane123")

    @unittest.skipUnless(_hosted_profile_probe_available(), "requires the pinned macOS 15 hosted toolchain")
    def test_local_sessionless_seatbelt_denies_network_and_outside_access(self):
        with tempfile.TemporaryDirectory(prefix="devlane-seatbelt-") as temporary:
            root = Path(temporary).resolve(strict=True)
            workspace = root / "workspace"
            source = workspace / "source"
            prepared = root / "prepared"
            scratch = root / "scratch"
            home = root / "home"
            trusted = root / "trusted"
            for path in (source, prepared, scratch, home, trusted):
                path.mkdir(parents=True)
            outside = root / "outside-canary"
            outside.write_bytes(b"outside-canary")
            profile = root / "worker.sb"
            profile.write_text(sandbox.profile_text(
                workspace=workspace, prepared=prepared, scratch=scratch, home=home,
                control=sandbox.CONTROL_ROOT, node=NODE,
                developer="/Library/Developer/CommandLineTools", clang="/usr/bin/true",
            ), encoding="utf-8")
            script = (
                "const fs=require('node:fs');const net=require('node:net');"
                "const [scratch,outside]=process.argv.slice(1);const result={};"
                "try{fs.writeFileSync(scratch+'/inside','ok');result.inside=true;}catch{result.inside=false;}"
                "try{fs.writeFileSync(outside,'bad');result.outside_write=false;}"
                "catch(error){result.outside_write=['EACCES','EPERM'].includes(error.code);}"
                "try{fs.readFileSync(outside);result.outside_read=false;}"
                "catch(error){result.outside_read=['EACCES','EPERM'].includes(error.code);}"
                "let finished=false;function finish(){if(finished)return;finished=true;"
                "process.stdout.write(JSON.stringify(result));}"
                "const socket=net.createConnection({host:'192.0.2.1',port:443,timeout:500});"
                "socket.on('connect',()=>{result.network=false;socket.destroy();finish();});"
                "socket.on('timeout',()=>{result.network=false;socket.destroy();finish();});"
                "socket.on('error',error=>{result.network=['EACCES','EPERM'].includes(error.code);finish();});"
            )
            result = subprocess.run(
                ["/usr/bin/sandbox-exec", "-f", str(profile), NODE, "-e", script, str(scratch), str(outside)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(scratch), "LC_ALL": "C"},
                timeout=20, check=False, close_fds=True, start_new_session=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
            self.assertEqual(json.loads(result.stdout), {
                "inside": True, "outside_read": True, "outside_write": True, "network": True,
            })
            self.assertEqual(outside.read_bytes(), b"outside-canary")


if __name__ == "__main__":
    unittest.main(verbosity=2)
