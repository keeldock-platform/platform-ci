"""Static import closure for the Linux worker's copied control surface."""

import ast
import unittest
from pathlib import Path

import supervisor


DEVLANE_ROOT = Path(supervisor.__file__).resolve().parent
LOCAL_MODULES = frozenset(path.stem for path in DEVLANE_ROOT.glob("*.py"))

FUNCTION_LOCAL_IMPORT_ALLOWLIST = {
    ("constraint_resolver.py", "run_cargo_fixed_point", "deadline"): {
        "mode": "staged",
        "reason": "run_cargo_fixed_point is called in the Rust preparation chroot; deadline.py is staged there and in WORKER_CONTROL_FILES.",
    },
    ("diagnostic_contract.py", "public_e2e_command_summary_record", "filter"): {
        "mode": "host-only",
        "reason": "public_e2e_command_diagnostic is consumed by host audit/acceptance readers; the Linux worker entry points do not reach it.",
    },
}
HOST_DIAGNOSTIC_CALLERS = frozenset(("acceptance_diagnostics.py", "public_audit.py"))


class ImportEdges(ast.NodeVisitor):
    def __init__(self):
        self.functions = []
        self.module_imports = []
        self.function_imports = []

    def visit_FunctionDef(self, node):
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Import(self, node):
        for alias in node.names:
            module = alias.name.split(".", 1)[0]
            if module in LOCAL_MODULES:
                self._record(module, node.lineno)

    def visit_ImportFrom(self, node):
        if node.module:
            module = node.module.split(".", 1)[0]
            if module in LOCAL_MODULES:
                self._record(module, node.lineno)

    def _record(self, module, line):
        edge = (self.functions[-1] if self.functions else "", module, line)
        (self.function_imports if self.functions else self.module_imports).append(edge)


def _staged_python_sources(names):
    return {
        name: (DEVLANE_ROOT / name).read_text(encoding="utf-8")
        for name in names if name.endswith(".py")
    }


def _call_sites(function_name):
    calls = set()

    class Calls(ast.NodeVisitor):
        def __init__(self, relative):
            self.relative = relative
            self.functions = []

        def visit_FunctionDef(self, node):
            self.functions.append(node.name)
            self.generic_visit(node)
            self.functions.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            called = node.func.id if isinstance(node.func, ast.Name) else (
                node.func.attr if isinstance(node.func, ast.Attribute) else ""
            )
            if called == function_name:
                calls.add((self.relative, self.functions[-1] if self.functions else ""))
            self.generic_visit(node)

    for path in DEVLANE_ROOT.glob("*.py"):
        if path.name.startswith("test_"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        Calls(path.name).visit(tree)
    return calls


class WorkerControlImportTests(unittest.TestCase):
    def test_every_staged_python_module_has_a_closed_module_import_set(self):
        names = supervisor.WORKER_CONTROL_FILES
        self.assertEqual(len(names), len(set(names)), "worker control file list has duplicates")
        self.assertTrue(all((DEVLANE_ROOT / name).is_file() for name in names))

        staged_modules = {Path(name).stem for name in names if name.endswith(".py")}
        missing = set()
        function_imports = set()
        for filename, source in _staged_python_sources(names).items():
            imports = ImportEdges()
            imports.visit(ast.parse(source, filename=filename))
            missing.update(
                (filename, module)
                for _scope, module, _line in imports.module_imports
                if module not in staged_modules
            )
            function_imports.update(
                (filename, scope, module)
                for scope, module, _line in imports.function_imports
            )

        self.assertEqual(missing, set(), f"unstaged module-level local imports: {sorted(missing)}")
        self.assertEqual(
            function_imports & set(FUNCTION_LOCAL_IMPORT_ALLOWLIST),
            set(FUNCTION_LOCAL_IMPORT_ALLOWLIST),
            "a documented function-local import moved or disappeared; review its worker path",
        )

        missing_function_targets = {
            edge for edge in function_imports if edge[2] not in staged_modules
        }
        allowed_host_only = {
            edge for edge, policy in FUNCTION_LOCAL_IMPORT_ALLOWLIST.items()
            if policy["mode"] == "host-only"
        }
        self.assertEqual(missing_function_targets, allowed_host_only)
        for edge, policy in FUNCTION_LOCAL_IMPORT_ALLOWLIST.items():
            filename, function, module = edge
            with self.subTest(import_edge=edge):
                if policy["mode"] == "staged":
                    self.assertIn(module, staged_modules, policy["reason"])
                else:
                    self.assertNotIn(module, staged_modules, policy["reason"])
                    self.assertEqual(
                        _call_sites("public_e2e_command_summary_record"),
                        {("diagnostic_contract.py", "public_e2e_command_diagnostic")},
                        policy["reason"],
                    )
                    host_calls = _call_sites("public_e2e_command_diagnostic")
                    self.assertEqual(
                        {relative for relative, _function in host_calls},
                        HOST_DIAGNOSTIC_CALLERS,
                        policy["reason"],
                    )
                    self.assertTrue(HOST_DIAGNOSTIC_CALLERS.isdisjoint(names))

        self.assertEqual(
            {edge for edge in FUNCTION_LOCAL_IMPORT_ALLOWLIST},
            {
                ("constraint_resolver.py", "run_cargo_fixed_point", "deadline"),
                ("diagnostic_contract.py", "public_e2e_command_summary_record", "filter"),
            },
        )

    def test_worker_control_copy_stays_within_file_and_tree_budgets(self):
        sizes = [(name, (DEVLANE_ROOT / name).stat().st_size)
                 for name in supervisor.WORKER_CONTROL_FILES]
        too_large = [(name, size) for name, size in sizes
                     if size > supervisor.MAX_WORKER_CONTROL_FILE_BYTES]
        self.assertEqual(too_large, [])
        self.assertLessEqual(sum(size for _name, size in sizes),
                             supervisor.MAX_WORKER_CONTROL_TREE_BYTES)


if __name__ == "__main__":
    unittest.main()
