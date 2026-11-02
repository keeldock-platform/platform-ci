import ast
import re
import sys
import unittest
from pathlib import Path


__all__ = ["KitDoesNotDependOnCoreCiTests", "CoreCiDependsOnlyOnSharedConfinementTests"]

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "kit"
CORE_CI = ROOT / "core-ci"
FOLDER = "core-ci"
MODULES = ("linux_quick_return", "test_linux_quick_return", "test_separation", "core_ci")
REGISTRY = frozenset((
    "kit/bootstrap/action.yml",
    "kit/bootstrap/policy_linux.py",
    "kit/bootstrap/test_policy_linux.py",
    "kit/bootstrap/public_tree.py",
    "kit/bootstrap/test_public_tree.py",
))
IMPORT_FORMS = (
    re.compile(r"(?m)^[ \t]*(?:import|from)[ \t]+(?:" + "|".join(MODULES) + r")\b"),
    re.compile(r"(?:importlib|spec_from_file_location|sys\.path|runpy|__import__)[^\n]*" + re.escape(FOLDER)),
    re.compile(r"(?:import|require)[^\n]*['\"][^'\"\n]*" + re.escape(FOLDER)),
    re.compile(r"(?m)^[ \t]*(?:import|export)[^\n]*from[ \t]+['\"][^'\"\n]*(?:" + "|".join(MODULES) + r")"),
)
SHARED_PREFIX = "kit/confinement/"
KIT_PATH = re.compile(r"kit/[A-Za-z0-9_./-]+")


def kit_files():
    return sorted(path for path in KIT.rglob("*") if path.is_file() and "__pycache__" not in path.parts)


def text_of(path):
    return path.read_bytes().decode("utf-8", errors="ignore")


def relative(path):
    return path.relative_to(ROOT).as_posix()


class KitDoesNotDependOnCoreCiTests(unittest.TestCase):
    def test_the_folder_exists_beside_the_kit_and_not_inside_it(self):
        self.assertTrue(CORE_CI.is_dir())
        self.assertTrue(KIT.is_dir())
        self.assertFalse((KIT / FOLDER).exists())
        self.assertEqual(CORE_CI.parent, KIT.parent)

    def test_nothing_under_the_kit_imports_from_the_folder(self):
        files = kit_files()
        self.assertGreater(len(files), 50)
        for path in files:
            body = text_of(path)
            for form in IMPORT_FORMS:
                with self.subTest(path=relative(path), form=form.pattern[:24]):
                    self.assertIsNone(form.search(body))

    def test_the_kit_python_modules_never_import_a_folder_module_by_name(self):
        for path in kit_files():
            if path.suffix != ".py":
                continue
            with self.subTest(path=relative(path)):
                tree = ast.parse(path.read_bytes(), filename=relative(path))
                names = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        names.update(alias.name.split(".")[0] for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        names.add(node.module.split(".")[0])
                self.assertFalse(names.intersection(MODULES), sorted(names.intersection(MODULES)))

    def test_only_the_registration_and_workflow_policy_files_may_name_the_folder(self):
        named = set()
        for path in kit_files():
            body = text_of(path)
            if FOLDER in body or any(name in body for name in MODULES[:2]):
                named.add(relative(path))
        self.assertEqual(sorted(named - REGISTRY), [])
        for name in REGISTRY:
            self.assertTrue((ROOT / name).is_file(), name)

    def test_registry_files_name_only_the_workflow_scripts_and_the_test_discovery(self):
        allowed = re.compile(
            r"core-ci(?:/(?:linux_quick_return|test_linux_quick_return|test_separation)\.py|"
            r"\"|'|/|\s|\)|$)"
        )
        for name in sorted(REGISTRY):
            body = text_of(ROOT / name)
            for match in re.finditer(re.escape(FOLDER), body):
                with self.subTest(path=name, offset=match.start()):
                    self.assertIsNotNone(allowed.match(body, match.start()))


class CoreCiDependsOnlyOnSharedConfinementTests(unittest.TestCase):
    def folder_files(self):
        return sorted(path for path in CORE_CI.rglob("*") if path.is_file() and "__pycache__" not in path.parts)

    def test_the_folder_holds_only_quick_tier_python_files(self):
        names = [path.name for path in self.folder_files()]
        self.assertEqual(
            names, ["linux_quick_return.py", "test_linux_quick_return.py", "test_separation.py"]
        )

    def test_every_kit_path_the_folder_names_is_the_shared_confinement_kit(self):
        for path in self.folder_files():
            if path.name == "test_separation.py":
                continue
            found_any = KIT_PATH.findall(text_of(path))
            for found in found_any:
                with self.subTest(path=relative(path), found=found):
                    self.assertTrue(found.startswith(SHARED_PREFIX), found)

    def test_python_imports_are_the_standard_library_or_the_folder_siblings(self):
        siblings = {path.stem for path in self.folder_files()}
        standard = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else None
        for path in self.folder_files():
            tree = ast.parse(path.read_bytes(), filename=relative(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module.split(".")[0]]
                else:
                    continue
                for name in names:
                    with self.subTest(path=relative(path), module=name):
                        self.assertNotIn(name, {"policy", "policy_linux", "public_tree", "linux_source_build"})
                        if standard is not None:
                            self.assertTrue(name in standard or name in siblings, name)

    def test_the_shared_confinement_helper_the_module_reads_is_where_it_expects_it(self):
        self.assertTrue((KIT / "confinement" / "feedback_producer_crypto.mjs").is_file())
        source = text_of(CORE_CI / "linux_quick_return.py")
        self.assertIn('"kit" / "confinement" / "feedback_producer_crypto.mjs"', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
