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
    re.compile(r"\b(?:import|require)\b[^\n]*['\"][^'\"\n]*" + re.escape(FOLDER)),
    re.compile(r"(?m)^[ \t]*(?:import|export)[^\n]*from[ \t]+['\"][^'\"\n]*(?:" + "|".join(MODULES) + r")"),
)
SHARED_PREFIX = "kit/confinement/"
KIT_PATH = re.compile(r"(?<![A-Za-z0-9_.-])kit/[A-Za-z0-9_./-]+")
PATH_CLASSES = ("Path", "PurePath")
REGISTRY_FOLDER_MENTION = re.compile(
    r"core-ci(?:/(?:linux_quick_return|test_linux_quick_return|test_separation)\.py"
    r"|/\[a-z_\]\+\)\\\.py|[\"'])"
)


def is_division(node):
    return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)


def path_chain(node):
    if is_division(node):
        return path_chain(node.left) + path_chain(node.right)
    if isinstance(node, ast.Call) and node.args:
        called = getattr(node.func, "id", getattr(node.func, "attr", None))
        if called in PATH_CLASSES:
            return list(node.args)
    return [node]


def text_constant(node):
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def accepted_kit_segments(tree):
    inner = {id(node.left) for node in ast.walk(tree) if is_division(node) and is_division(node.left)}
    accepted = set()
    for node in ast.walk(tree):
        segments = None
        if is_division(node) and id(node) not in inner:
            segments = path_chain(node)
        elif isinstance(node, ast.Call) and len(node.args) > 1:
            segments = node.args
        if segments is None:
            continue
        for index, segment in enumerate(segments[:-1]):
            if text_constant(segment) == "kit" and text_constant(segments[index + 1]) == "confinement":
                accepted.add(id(segment))
    return accepted


def kit_path_violations(tree):
    accepted = accepted_kit_segments(tree)
    found = []
    for node in ast.walk(tree):
        value = text_constant(node)
        if value is None:
            continue
        if value == "kit" and id(node) not in accepted:
            found.append(value)
        found.extend(match for match in KIT_PATH.findall(value) if not match.startswith(SHARED_PREFIX))
    return found


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
        for name in sorted(REGISTRY):
            body = text_of(ROOT / name)
            for match in re.finditer(re.escape(FOLDER), body):
                with self.subTest(path=name, offset=match.start()):
                    self.assertIsNotNone(REGISTRY_FOLDER_MENTION.match(body, match.start()))

    def test_the_registry_mention_pattern_rejects_any_other_path_in_the_folder(self):
        for accepted in (
            "core-ci/linux_quick_return.py", "core-ci/test_linux_quick_return.py",
            "core-ci/test_separation.py", 'core-ci" -p', "core-ci' -p",
        ):
            with self.subTest(accepted=accepted):
                self.assertIsNotNone(REGISTRY_FOLDER_MENTION.match(accepted))
        for rejected in (
            "core-ci/other.py", "core-ci/", "core-ci ", "core-ci", "core-ci\n", "core-ci)",
            "core-ci/linux_quick_return.sh", "core-ci/test_linux_quick_return.sh",
            "core-ci/anything/else.py",
        ):
            with self.subTest(rejected=rejected):
                self.assertIsNone(REGISTRY_FOLDER_MENTION.match(rejected))


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
            with self.subTest(path=relative(path), form="text"):
                for found in KIT_PATH.findall(text_of(path)):
                    self.assertTrue(found.startswith(SHARED_PREFIX), found)
            if path.suffix == ".py":
                with self.subTest(path=relative(path), form="syntax"):
                    tree = ast.parse(path.read_bytes(), filename=relative(path))
                    self.assertEqual(kit_path_violations(tree), [])

    def test_the_kit_path_check_sees_path_joins_and_ignores_words_that_end_in_kit(self):
        shared = ast.parse('base / "kit" / "confinement" / "helper.mjs"')
        self.assertEqual(kit_path_violations(shared), [])
        self.assertEqual(kit_path_violations(ast.parse('Path("kit", "confinement", "helper.mjs")')), [])
        self.assertEqual(kit_path_violations(ast.parse('Path("kit") / "confinement" / "helper.mjs"')), [])
        self.assertEqual(kit_path_violations(ast.parse('value = "kit/confinement/helper.mjs"')), [])
        for source in (
            'base / "kit" / "bootstrap" / "policy.py"',
            'base / "kit"',
            'Path("kit", "bootstrap")',
            'Path("kit") / "selector"',
            'name = "kit/bootstrap/policy.py"',
            'join(base, "kit", "cache")',
        ):
            with self.subTest(source=source):
                self.assertNotEqual(kit_path_violations(ast.parse(source)), [])
        self.assertIsNone(KIT_PATH.search("toolkit/bootstrap"))
        self.assertIsNone(KIT_PATH.search("skit/cache"))
        self.assertIsNotNone(KIT_PATH.search("../kit/bootstrap"))

    def test_python_imports_never_reach_the_shared_policy_modules(self):
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

    def test_python_imports_are_the_standard_library_or_the_folder_siblings(self):
        if not hasattr(sys, "stdlib_module_names"):
            self.skipTest("sys.stdlib_module_names needs Python 3.10 or later")
        siblings = {path.stem for path in self.folder_files()}
        standard = set(sys.stdlib_module_names)
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
                        self.assertTrue(name in standard or name in siblings, name)

    def test_the_shared_confinement_helper_the_module_reads_is_where_it_expects_it(self):
        self.assertTrue((KIT / "confinement" / "feedback_producer_crypto.mjs").is_file())
        source = text_of(CORE_CI / "linux_quick_return.py")
        self.assertIn('"kit" / "confinement" / "feedback_producer_crypto.mjs"', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
