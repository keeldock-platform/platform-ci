"""Source-free unit and local Seatbelt acceptance for the macOS devlane worker."""

import json
import io
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

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
        self.assertIn('(allow file-read* (subpath "/tmp/devlane-scratch"))', text)
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


class MacRoundOneRegressionTests(unittest.TestCase):
    def test_dependency_preparation_is_unprivileged_and_network_outbound_only(self):
        profile = sandbox.preparation_profile_text(
            project=PRIVATE_RUN + "/preparation-project", prepared=PRIVATE_RUN + "/prepared",
            cache=PRIVATE_RUN + "/cache", home=PRIVATE_RUN + "/home", temporary=PRIVATE_RUN + "/tmp",
            node="/opt/node/bin/node", npm_cli="/opt/node/lib/node_modules/npm/bin/npm-cli.js",
        )
        self.assertIn("(deny default)", profile)
        self.assertIn("(allow network-outbound)", profile)
        self.assertIn("(deny network-inbound)", profile)
        self.assertNotIn("(allow network*)", profile)
        self.assertIn('(allow file-write* (subpath "' + PRIVATE_RUN + '/cache")', profile)
        self.assertNotIn('(allow file-write* (subpath "/Users")', profile)
        process = mock.Mock(returncode=0)
        with mock.patch.object(sandbox.subprocess, "Popen", return_value=process) as spawn, \
                mock.patch.object(sandbox, "_terminate_worker_processes"):
            self.assertEqual(sandbox._run_preparation_process(
                ("/opt/node/bin/node", "/opt/npm/cli.js", "ci"),
                ident={"uid": 544, "gid": sandbox.WORKER_GROUP}, profile=PRIVATE_RUN + "/preparation.sb",
                cwd=PRIVATE_RUN + "/preparation-project", env={"PATH": "/usr/bin:/bin"},
                output=io.BytesIO(), timeout=20,
            ), 0)
        self.assertEqual(spawn.call_args.args[0][:4], [
            "/usr/bin/sandbox-exec", "-f", PRIVATE_RUN + "/preparation.sb", "/opt/node/bin/node",
        ])
        self.assertEqual(spawn.call_args.kwargs["user"], 544)
        self.assertEqual(spawn.call_args.kwargs["group"], sandbox.WORKER_GROUP)
        self.assertEqual(spawn.call_args.kwargs["extra_groups"], ())

    def test_capture_log_finalization_uses_the_open_descriptor_after_path_swap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "captured.log"
            protected = root / "protected"
            original.write_bytes(b"worker output")
            protected.write_bytes(b"keep this file")
            protected_mode = protected.stat().st_mode & 0o777
            descriptor = os.open(original, os.O_WRONLY)
            try:
                original.unlink()
                original.symlink_to(protected)
                with self.assertRaises(sandbox.Refusal):
                    sandbox._finalize_capture_log(descriptor, os.getuid(), os.getgid())
            finally:
                os.close(descriptor)
            self.assertEqual(protected.read_bytes(), b"keep this file")
            self.assertEqual(protected.stat().st_mode & 0o777, protected_mode)

    def test_worker_uid_reaper_terminates_session_detached_processes(self):
        processes = [[501], [501], []]
        calls = []

        def run(argv, **_kwargs):
            calls.append(argv)
            return 0, b"", b""

        with mock.patch.object(sandbox, "_worker_process_ids", side_effect=processes), \
                mock.patch.object(sandbox, "_run", side_effect=run), \
                mock.patch.object(sandbox.time, "monotonic", side_effect=[0, 2, 4, 5, 6]), \
                mock.patch.object(sandbox.time, "sleep"):
            sandbox._terminate_worker_processes(544)
        self.assertEqual([call[1] for call in calls], ["-TERM", "-KILL"])
        self.assertEqual(calls[0][-2:], ("-U", "544"))

    def test_summary_filter_accepts_failure_records_and_empty_success(self):
        allowlists = {
            "files": {}, "tests": {}, "frames": {}, "stages": ["unit"],
            "codes": ["DEVLANE_FAILURE"], "suites": [], "max_lines": {},
        }
        failed = sandbox._filter_summary([{
            "kind": "control", "stage": "unit", "status": "fail", "subreason": "report-missing",
        }], allowlists)
        self.assertEqual(failed, b'{"kind":"control","stage":"unit","status":"fail","subreason":"report-missing"}\n')
        self.assertEqual(sandbox._filter_summary([], allowlists), b"")

    def test_encrypted_workflow_leaves_workspace_creation_to_root_supervisor(self):
        workflow = (sandbox.CONTROL_ROOT / ".github/workflows/devlane-encrypted.yml").read_text(encoding="utf-8")
        download = workflow.split("- name: Fetch ciphertext and sanitized dependency projection", 1)[1].split(
            "- name: Install pinned Rust toolchain", 1,
        )[0]
        self.assertNotIn('mkdir -m 700 "$RUN_ROOT/workspace"', download)
        self.assertIn('(root / "workspace").mkdir(mode=0o700)',
                      (sandbox.CONTROL_ROOT / "kit/devlane/sandbox_macos.py").read_text(encoding="utf-8"))

    def test_decrypt_refusal_prints_the_safe_reason_grammar(self):
        stderr = io.StringIO()
        arguments = ["decrypt", "--state-dir", PRIVATE_RUN + "/state", "--context", PRIVATE_RUN + "/context",
                     "--bundle", PRIVATE_RUN + "/bundle", "--projection", PRIVATE_RUN + "/projection",
                     "--deadline-file", PRIVATE_RUN + "/deadline"]
        with mock.patch.object(sandbox, "_state_paths", return_value=(Path(PRIVATE_RUN + "/state"), Path(PRIVATE_RUN))), \
                mock.patch.object(sandbox, "_decrypt", side_effect=sandbox.Refusal(
                    "decrypt-rejected", decrypt_refusal="auth-tag")), \
                mock.patch.dict(os.environ, {"DEVLANE_DECRYPT_KEY": "opaque"}), \
                mock.patch("sys.stderr", stderr):
            self.assertEqual(sandbox.main(arguments), 2)
        self.assertEqual(stderr.getvalue(),
                         "devlane_supervisor_refusal=decrypt-rejected\ndecrypt_refusal=auth-tag\n")

    def test_root_cleanup_attempts_plaintext_and_account_cleanup_after_firewall_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary).resolve()
            root = temp / "devlane-123"
            state = root / "state"
            workspace = temp / "workspace"
            state.mkdir(parents=True)
            workspace.mkdir()
            for name in (sandbox.CLEANUP_INTENT_FILE, sandbox.IDENTITY_FILE, sandbox.PF_STATE_FILE):
                (state / name).write_text("{}", encoding="ascii")
            intent = {"schema": 1, "run_id": "123", "runner_uid": 501, "uid": 544,
                      "gid": sandbox.WORKER_GROUP, "account": "kddevlane123",
                      "home": str(root / "worker-home")}
            identity = {**intent, "node": "/node", "npm_cli": "/npm", "node_sha256": "a" * 64,
                        "npm_sha256": "b" * 64, "developer_directory": "/developer", "clang": "/clang",
                        "host_identity": {}}
            guard = mock.Mock()
            guard.close.side_effect = RuntimeError("PF close failed")
            cleanup_tree = mock.Mock(side_effect=lambda path: sandbox.shutil.rmtree(path))
            with mock.patch.object(sandbox.os, "geteuid", return_value=0), \
                    mock.patch.object(sandbox, "_cleanup_intent", return_value=intent), \
                    mock.patch.object(sandbox, "_identity", return_value=identity), \
                    mock.patch.object(sandbox, "_terminate_worker_processes"), \
                    mock.patch.object(sandbox, "_pf_guard_from_file", return_value=(guard, {"rules_file": str(temp / "rules")})), \
                    mock.patch.object(sandbox, "_delete_worker_account") as delete_account, \
                    mock.patch.object(sandbox, "_clean_tree", cleanup_tree), \
                    mock.patch.object(sandbox, "_directory_users", return_value=set()), \
                    mock.patch.object(sandbox, "_worker_process_ids", return_value=[]), \
                    self.assertRaises(sandbox.Refusal):
                sandbox._root_cleanup(state, root, temp, workspace, "123")
            delete_account.assert_called_once_with(intent)
            cleanup_tree.assert_called_once_with(root)
            self.assertFalse(root.exists())

    def test_incomplete_identity_creation_is_reconciled_from_durable_cleanup_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary).resolve()
            root = temp / "devlane-123"
            state = root / "state"
            workspace = temp / "workspace"
            state.mkdir(parents=True)
            workspace.mkdir()
            intent = {"schema": 1, "run_id": "123", "runner_uid": 501, "uid": 544,
                      "gid": sandbox.WORKER_GROUP, "account": "kddevlane123",
                      "home": str(root / "worker-home")}
            (state / sandbox.CLEANUP_INTENT_FILE).write_bytes(
                sandbox.bundle.canonical_json(intent) + b"\n",
            )
            (state / sandbox.IDENTITY_FILE).write_bytes(b"{")
            account = intent["account"]
            directory_users = [{account}, set(), set()]
            commands = []

            def run_command(argv, **_kwargs):
                commands.append(argv)
                if "-read" in argv:
                    return mock.Mock(returncode=0, stdout=(
                        "PrimaryGroupID: 20\nNFSHomeDirectory: " + intent["home"] + "\n"
                    ).encode("ascii"), stderr=b"")
                return mock.Mock(returncode=0, stdout=b"", stderr=b"")

            with mock.patch.object(sandbox.os, "geteuid", return_value=0), \
                    mock.patch.object(sandbox, "_directory_users", side_effect=directory_users), \
                    mock.patch.object(sandbox, "_terminate_worker_processes"), \
                    mock.patch.object(sandbox, "_worker_process_ids", return_value=[]), \
                    mock.patch.object(sandbox, "_worker_account_attributes", return_value={
                        "PrimaryGroupID": "20", "NFSHomeDirectory": intent["home"],
                    }), \
                    mock.patch.object(sandbox.boundary_guard, "_run_command", side_effect=run_command), \
                    mock.patch.object(sandbox, "_clean_tree", side_effect=lambda path: sandbox.shutil.rmtree(path)), \
                    mock.patch.object(sandbox.time, "sleep"):
                sandbox._root_cleanup(state, root, temp, workspace, "123")
            self.assertTrue(any("-delete" in call for call in commands))
            self.assertFalse(root.exists())

    def test_partial_worker_account_attributes_are_checked_before_deletion(self):
        intent = {"schema": 1, "run_id": "123", "runner_uid": 501, "uid": 544,
                  "gid": sandbox.WORKER_GROUP, "account": "kddevlane123", "home": PRIVATE_RUN + "/worker-home"}
        with mock.patch.object(sandbox, "_directory_users", side_effect=[{intent["account"]}, set(), set()]), \
                mock.patch.object(sandbox, "_worker_account_attributes", return_value={
                    "PrimaryGroupID": "20", "NFSHomeDirectory": intent["home"],
                }), \
                mock.patch.object(sandbox.boundary_guard, "_run_command", return_value=mock.Mock(
                    returncode=0, stdout=b"", stderr=b"")) as command:
            sandbox._delete_worker_account(intent)
        self.assertEqual(command.call_args.args[0][-1], chr(47) + "Users" + chr(47) + intent["account"])

    def test_cleanup_does_not_shred_tree_while_worker_processes_remain(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary).resolve()
            root = temp / "devlane-123"
            state = root / "state"
            workspace = temp / "workspace"
            state.mkdir(parents=True)
            workspace.mkdir()
            intent = {"schema": 1, "run_id": "123", "runner_uid": 501, "uid": 544,
                      "gid": sandbox.WORKER_GROUP, "account": "kddevlane123",
                      "home": str(root / "worker-home")}
            (state / sandbox.CLEANUP_INTENT_FILE).write_bytes(
                sandbox.bundle.canonical_json(intent) + b"\n",
            )
            with mock.patch.object(sandbox.os, "geteuid", return_value=0), \
                    mock.patch.object(sandbox, "_directory_users", return_value=set()), \
                    mock.patch.object(sandbox, "_terminate_worker_processes", side_effect=sandbox.Refusal()), \
                    mock.patch.object(sandbox, "_worker_process_ids", return_value=[999]), \
                    mock.patch.object(sandbox, "_clean_tree") as clean_tree, \
                    self.assertRaises(sandbox.Refusal):
                sandbox._root_cleanup(state, root, temp, workspace, "123")
            clean_tree.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
