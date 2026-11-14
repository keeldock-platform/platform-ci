"""Integrity checks for the isolated control-only Python dependency tree."""

import base64
import os
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import control_python
import public_audit as audit


def _control_tree(parent, *, posix_modes):
    parent = parent.resolve(strict=True)
    root = parent / "control-python-deps"
    files = {
        "cffi/__init__.py": b'__version__ = "2.1.1"\n',
        "cryptography/__init__.py": b'__version__ = "50.0.2"\n',
        "cryptography/hazmat/__init__.py": b"",
        "cryptography/hazmat/primitives/__init__.py": b"",
        "cryptography/hazmat/primitives/ciphers/__init__.py": b"",
        "cryptography/hazmat/primitives/ciphers/aead.py": b"class AESGCM: pass\n",
        "pycparser/__init__.py": b'__version__ = "3.12"\n',
    }
    for relative, payload in files.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        destination.write_bytes(payload)
    if posix_modes:
        for directory in (root, *[path for path in root.rglob("*") if path.is_dir()]):
            os.chmod(directory, 0o755)
        for path in root.rglob("*"):
            if path.is_file():
                os.chmod(path, 0o644)
    return root


@unittest.skipUnless(hasattr(os, "getuid") and os.getuid() > 0, "requires an unprivileged local test owner")
class ControlPythonTreeTests(unittest.TestCase):
    def _tree(self, parent):
        return _control_tree(parent, posix_modes=True)

    def test_seal_and_validate_bind_every_file_digest(self):
        with tempfile.TemporaryDirectory(prefix="control-python-") as temporary:
            root = self._tree(Path(temporary))
            owner = os.getuid()
            self.assertEqual(control_python.seal(root, "macos", owner), owner)
            self.assertEqual(control_python.validate(root, "macos", owner), root)

            (root / "cryptography" / "__init__.py").write_bytes(b"changed package fixture\n")
            with self.assertRaisesRegex(control_python.CryptoRefusal, "crypto-unavailable"):
                control_python.validate(root, "macos", owner)

    def test_seal_rejects_group_or_other_writable_dependency_directory(self):
        with tempfile.TemporaryDirectory(prefix="control-python-") as temporary:
            root = self._tree(Path(temporary))
            os.chmod(root, 0o777)
            with self.assertRaisesRegex(control_python.CryptoRefusal, "crypto-unavailable"):
                control_python.seal(root, "macos", os.getuid())

    def test_seal_rejects_wrong_owner(self):
        with tempfile.TemporaryDirectory(prefix="control-python-") as temporary:
            root = self._tree(Path(temporary))
            wrong_owner = os.getuid() + 1
            with self.assertRaisesRegex(control_python.CryptoRefusal, "crypto-unavailable"):
                control_python.seal(root, "macos", wrong_owner)

    def test_seal_rejects_dependency_symlink(self):
        with tempfile.TemporaryDirectory(prefix="control-python-") as temporary:
            root = self._tree(Path(temporary))
            (root / "cryptography" / "linked.py").symlink_to(root / "cryptography" / "__init__.py")
            with self.assertRaisesRegex(control_python.CryptoRefusal, "crypto-unavailable"):
                control_python.seal(root, "macos", os.getuid())

    def test_predecrypt_check_imports_pinned_crypto_before_key_is_available(self):
        with tempfile.TemporaryDirectory(prefix="control-python-") as temporary:
            root = self._tree(Path(temporary))
            control_python.seal(root, "macos", os.getuid())
            package_names = ("cffi", "cryptography", "pycparser")
            saved_modules = {
                name: module for name, module in sys.modules.items()
                if any(name == package or name.startswith(package + ".") for package in package_names)
            }
            for name in saved_modules:
                sys.modules.pop(name, None)
            isolated_path = list(sys.path)
            with mock.patch.object(control_python.sys, "path", isolated_path), \
                    mock.patch.dict(os.environ, {"DEVLANE_DECRYPT_KEY": "test-key"}, clear=False):
                os.environ.pop("DEVLANE_DECRYPT_KEY", None)
                try:
                    result = control_python.main([
                        "--target", str(root), "--platform", "macos", "--owner-uid", str(os.getuid()),
                        "check", "--require-key-absent",
                    ])
                    self.assertEqual(result, 0)
                    self.assertEqual(isolated_path[0], str(root))
                    for package in package_names:
                        self.assertTrue(Path(sys.modules[package].__file__).resolve().is_relative_to(root))
                    self.assertIn("cryptography.hazmat.primitives.ciphers.aead", sys.modules)
                    self.assertEqual(os.environ.get("DEVLANE_DECRYPT_KEY"), None)
                finally:
                    for name in tuple(sys.modules):
                        if any(name == package or name.startswith(package + ".") for package in package_names):
                            sys.modules.pop(name, None)
                    sys.modules.update(saved_modules)

            with mock.patch.dict(os.environ, {"DEVLANE_DECRYPT_KEY": "test-key"}, clear=False):
                self.assertEqual(control_python.main([
                    "--target", str(root), "--platform", "macos", "--owner-uid", str(os.getuid()),
                    "check", "--require-key-absent",
                ]), 2)

    def test_run_prepends_validated_dependencies_only_inside_the_control_process(self):
        with tempfile.TemporaryDirectory(prefix="control-python-") as temporary:
            parent = Path(temporary).resolve(strict=True)
            root = self._tree(parent)
            script = parent / "trusted-control.py"
            script.write_text("pass\n", encoding="ascii")
            control_python.seal(root, "macos", os.getuid())
            isolated_path = list(sys.path)
            package_names = ("cffi", "cryptography", "pycparser")
            saved_modules = {
                name: module for name, module in sys.modules.items()
                if any(name == package or name.startswith(package + ".") for package in package_names)
            }
            for name in saved_modules:
                sys.modules.pop(name, None)
            before_env = dict(os.environ)
            with mock.patch.object(control_python.sys, "path", isolated_path), \
                    mock.patch.object(control_python.runpy, "run_path") as run_path:
                try:
                    self.assertEqual(control_python._run_script(
                        root, str(script), [], platform_name="macos", owner_uid=os.getuid(), key_absent=False,
                    ), 0)
                    self.assertEqual(isolated_path[0], str(root))
                    run_path.assert_called_once_with(str(script), run_name="__main__")
                    self.assertEqual(dict(os.environ), before_env)
                finally:
                    for name in tuple(sys.modules):
                        if any(name == package or name.startswith(package + ".") for package in package_names):
                            sys.modules.pop(name, None)
                    sys.modules.update(saved_modules)


class ControlPythonWindowsTests(unittest.TestCase):
    def test_windows_owner_change_invalidates_sealed_tree(self):
        with tempfile.TemporaryDirectory(prefix="control-python-windows-owner-") as temporary:
            root = _control_tree(Path(temporary), posix_modes=False)
            with mock.patch.object(control_python, "_powershell_acl_owner", return_value="S-1-5-21-100"):
                control_python.seal(root, "windows")
            with mock.patch.object(control_python, "_powershell_acl_owner", return_value="S-1-5-21-200"):
                with self.assertRaisesRegex(control_python.CryptoRefusal, "crypto-unavailable"):
                    control_python.validate(root, "windows")

    def test_windows_tree_seals_native_extension_record_and_bytecode_files(self):
        with tempfile.TemporaryDirectory(prefix="control-python-windows-") as temporary:
            parent = Path(temporary).resolve(strict=True)
            root = parent / "control-python-deps"
            files = {
                "cryptography/__init__.py": b'__version__ = "50.0.2"\n',
                "cryptography/_rust.abi3.pyd": b"native-extension-fixture",
                "cryptography-50.0.2.dist-info/RECORD": b"cryptography/_rust.abi3.pyd,,\n",
                "cryptography/__pycache__/fixture.pyc": b"bytecode-fixture",
            }
            for relative, payload in files.items():
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
            with mock.patch.object(control_python, "_powershell_acl_owner", return_value="S-1-5-21-100"):
                control_python.seal(root, "windows")
                control_python.validate(root, "windows")
            manifest = control_python._read_manifest(root, "windows", "S-1-5-21-100")
            self.assertEqual([row["path"] for row in manifest["files"]], sorted(files))
            self.assertIn("cryptography/_rust.abi3.pyd", [row["path"] for row in manifest["files"]])
            self.assertIn("cryptography-50.0.2.dist-info/RECORD", [row["path"] for row in manifest["files"]])
            self.assertIn("cryptography/__pycache__/fixture.pyc", [row["path"] for row in manifest["files"]])

            (root / "cryptography" / "_rust.abi3.pyd").write_bytes(b"changed extension")
            with mock.patch.object(control_python, "_powershell_acl_owner", return_value="S-1-5-21-100"), \
                    self.assertRaisesRegex(control_python.CryptoRefusal, "crypto-unavailable") as caught:
                control_python.validate(root, "windows")
            self.assertEqual(caught.exception.reason, "crypto-tree-mismatch")


class ControlPythonPortableTests(unittest.TestCase):
    def test_seal_and_check_print_only_fixed_subreason_codes(self):
        output = io.StringIO()
        with mock.patch.object(control_python, "seal", side_effect=control_python.CryptoRefusal("crypto-acl-owner-untrusted")), \
                mock.patch("sys.stderr", output):
            self.assertEqual(control_python.main([
                "--target", "/tmp/control-python-deps", "--platform", "windows", "seal",
            ]), 2)
        self.assertEqual(output.getvalue(), "devlane_crypto_refusal=crypto-acl-owner-untrusted\n")

        output = io.StringIO()
        with mock.patch.object(control_python, "validate", side_effect=control_python.CryptoRefusal("private-path")), \
                mock.patch("sys.stderr", output):
            self.assertEqual(control_python.main([
                "--target", "/tmp/control-python-deps", "--platform", "windows", "check",
            ]), 2)
        self.assertEqual(output.getvalue(), "devlane_crypto_refusal=crypto-control-invalid\n")

    def test_windows_acl_exit_codes_have_fixed_subreasons(self):
        expected = {
            3: "crypto-acl-reparse-point",
            4: "crypto-acl-owner-unresolved",
            5: "crypto-acl-owner-untrusted",
            6: "crypto-acl-writer-untrusted",
        }
        for exit_code, reason in expected.items():
            with self.subTest(exit_code=exit_code):
                self.assertEqual(control_python._powershell_acl_exit_reason(exit_code), reason)
        self.assertIsNone(control_python._powershell_acl_exit_reason(0))
        self.assertEqual(control_python._powershell_acl_exit_reason(7), "crypto-acl-exit-7")
        self.assertEqual(control_python._powershell_acl_exit_reason(16), "crypto-acl-exit-other")

    def test_windows_acl_output_parser_accepts_only_one_sid_line_and_normalizes_bom_crlf(self):
        self.assertEqual(
            control_python._powershell_acl_stdout_sid(b"\xef\xbb\xbfS-1-5-21-100\r\n"),
            "S-1-5-21-100",
        )
        self.assertEqual(control_python._powershell_acl_stdout_sid(b"S-1-5-21-100\n"), "S-1-5-21-100")
        cases = (
            (b"", "crypto-acl-stdout-empty"),
            (b"\n", "crypto-acl-stdout-empty"),
            (b"S-1-5-21-100\nextra\n", "crypto-acl-stdout-multiple-lines"),
            (b"not-a-sid\n", "crypto-acl-stdout-not-sid"),
            (b" S-1-5-21-100\n", "crypto-acl-stdout-bom-or-whitespace"),
            (b"S-1-5-21-100\n\n", "crypto-acl-stdout-multiple-lines"),
            (b"S-1-5-21-100\r", "crypto-acl-stdout-bom-or-whitespace"),
            (b"S-1-5-21-100\xff\n", "crypto-acl-stdout-non-ascii"),
        )
        for payload, reason in cases:
            with self.subTest(reason=reason, payload=payload), self.assertRaises(control_python.CryptoRefusal) as caught:
                control_python._powershell_acl_stdout_sid(payload)
            self.assertEqual(caught.exception.reason, reason)

    def test_windows_acl_command_output_failures_have_fixed_subreasons(self):
        with mock.patch.object(Path, "is_file", return_value=False):
            with self.assertRaises(control_python.CryptoRefusal) as caught:
                control_python._powershell_acl_owner(Path("D:/run/control-python-deps"))
        self.assertEqual(caught.exception.reason, "crypto-acl-powershell-unavailable")

        for result, reason in (
            (mock.Mock(returncode=3, stdout=b"", stderr=b""), "crypto-acl-reparse-point"),
            (mock.Mock(returncode=4, stdout=b"", stderr=b""), "crypto-acl-owner-unresolved"),
            (mock.Mock(returncode=5, stdout=b"", stderr=b""), "crypto-acl-owner-untrusted"),
            (mock.Mock(returncode=6, stdout=b"", stderr=b""), "crypto-acl-writer-untrusted"),
            (mock.Mock(returncode=0, stdout=b"not-a-sid\n", stderr=b""), "crypto-acl-stdout-not-sid"),
            (mock.Mock(returncode=0, stdout=b"S-1-5-21-100\nextra\n", stderr=b""), "crypto-acl-stdout-multiple-lines"),
            (mock.Mock(returncode=0, stdout=b"S-1-5-21-100\n", stderr=b"warning\n"), "crypto-acl-stderr-nonempty"),
            (mock.Mock(returncode=0, stdout=b"\xff", stderr=b""), "crypto-acl-stdout-non-ascii"),
            (mock.Mock(returncode=7, stdout=b"", stderr=b""), "crypto-acl-exit-7"),
            (mock.Mock(returncode=28, stdout=b"", stderr=b""), "crypto-acl-exit-other"),
        ):
            with self.subTest(reason=reason, returncode=result.returncode), \
                    mock.patch.object(Path, "is_file", return_value=True), \
                    mock.patch.object(control_python.subprocess, "run", return_value=result), \
                    self.assertRaises(control_python.CryptoRefusal) as caught:
                control_python._powershell_acl_owner(Path("D:/run/control-python-deps"))
            self.assertEqual(caught.exception.reason, reason)

    def test_windows_acl_powershell_command_is_quiet_and_text_formatted(self):
        command = control_python._powershell_acl_command(Path("D:/run/control-python-deps"), Path("pwsh.exe"))
        self.assertEqual(command[1:7], ["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand"])
        script = base64.b64decode(command[-1]).decode("utf-16le")
        self.assertIn("$ProgressPreference = 'SilentlyContinue'", script)
        self.assertEqual(script.count("[Console]::Out.WriteLine($ownerSid)"), 1)

    def test_windows_crypto_acl_bootstrap_is_protected_before_install(self):
        root = Path(__file__).resolve().parents[2]
        workflow = audit.parse_workflow(root / ".github/workflows/devlane-encrypted.yml")
        steps = workflow[audit.WINDOWS_RUN_JOB]["steps"]
        bootstrap = next(step for step in steps if step["name"] == "Fetch public control and validate dispatch")
        script = "\n".join(bootstrap["run"])
        run_root_protection = script.index("Protect-PrivateDirectory $runRoot $runnerSid")
        start_marker = script.index("$started = Join-Path $runRoot 'deadline-start'")
        target_creation = script.index("New-Item -ItemType Directory -Path $cryptoTarget")
        install = script.index("python -B -m pip install")
        self.assertLess(run_root_protection, start_marker)
        self.assertLess(target_creation, install)
        self.assertLess(script.index("Protect-PrivateDirectory $cryptoTarget $runnerSid"), install)
        self.assertIn("$security.SetAccessRuleProtection($true, $false)", script)
        self.assertIn("[Security.AccessControl.FileSystemRights]::FullControl", script)
        self.assertIn("'S-1-5-18'", script)
        self.assertIn("'S-1-5-32-544'", script)
        self.assertIn("[Security.AccessControl.InheritanceFlags]::ContainerInherit", script)
        self.assertIn("[Security.AccessControl.InheritanceFlags]::ObjectInherit", script)

        source = (root / "kit/devlane/control_python.py").read_text(encoding="utf-8")
        self.assertIn("$rule.PropagationFlags", source)
        self.assertIn("[Security.AccessControl.PropagationFlags]::InheritOnly", source)


if __name__ == "__main__":
    unittest.main()
