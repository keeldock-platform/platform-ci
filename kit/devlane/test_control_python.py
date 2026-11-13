"""Integrity checks for the isolated control-only Python dependency tree."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import control_python


@unittest.skipUnless(hasattr(os, "getuid") and os.getuid() > 0, "requires an unprivileged local test owner")
class ControlPythonTreeTests(unittest.TestCase):
    def _tree(self, parent):
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
        for directory in (root, *[path for path in root.rglob("*") if path.is_dir()]):
            os.chmod(directory, 0o755)
        for path in root.rglob("*"):
            if path.is_file():
                os.chmod(path, 0o644)
        return root

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

    def test_windows_owner_change_invalidates_sealed_tree(self):
        with tempfile.TemporaryDirectory(prefix="control-python-") as temporary:
            root = self._tree(Path(temporary))
            with mock.patch.object(control_python, "_powershell_acl_owner", return_value="S-1-5-21-100"):
                control_python.seal(root, "windows")
            with mock.patch.object(control_python, "_powershell_acl_owner", return_value="S-1-5-21-200"):
                with self.assertRaisesRegex(control_python.CryptoRefusal, "crypto-unavailable"):
                    control_python.validate(root, "windows")

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


if __name__ == "__main__":
    unittest.main()
