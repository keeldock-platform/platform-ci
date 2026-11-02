import io
import json
import unittest
from contextlib import redirect_stdout

import confinement_verdict
import gate_table


LINUX_PROJECT = "/work/project"
LINUX_ARGUMENTS = (LINUX_PROJECT, "/rust/bin/cargo", "/node/bin/node", "/node/bin/npm")
WINDOWS_ARGUMENTS = (
    "C:\\work\\project", "C:\\rust\\bin\\cargo.exe", "C:\\node\\node.exe",
    "C:\\node\\node_modules\\npm\\bin\\npm-cli.js",
)


def _render(include_runtime=False, arguments=LINUX_ARGUMENTS, separator="/"):
    return gate_table.render(gate_table.gate_templates(include_runtime), *arguments, separator=separator)


class GateSetTests(unittest.TestCase):
    def test_gate_names_and_counts_are_the_closed_sets(self):
        self.assertEqual(
            gate_table.GATES,
            (
                "format", "clippy", "workspace_tests", "api_tests", "api_feature_clippy",
                "api_feature_tests", "mock_tests", "conformance_tests", "parser_format",
                "parser_clippy", "parser_replay", "node_dependency_prepare",
                "node_dependency_audit", "typescript_typecheck", "typescript_tests",
            ),
        )
        self.assertEqual(gate_table.RUNTIME_GATE_NAMES, ("runtime_format", "runtime_clippy", "runtime_tests"))
        self.assertEqual(gate_table.REQUIRED_GATES, 15)
        self.assertEqual(gate_table.MAX_GATES, 18)
        self.assertEqual(len(set(gate_table.GATES + gate_table.RUNTIME_GATE_NAMES)), 18)
        self.assertEqual(gate_table.RUNTIME_ROOT_FILES, ("runtime/Cargo.toml", "runtime/Cargo.lock"))

    def test_the_verdict_accepts_exactly_the_table_counts(self):
        self.assertEqual(confinement_verdict.REQUIRED_GATES, gate_table.REQUIRED_GATES)
        self.assertEqual(confinement_verdict.MAX_GATES, gate_table.MAX_GATES)
        self.assertEqual(
            confinement_verdict.ACCEPTED_GATE_COUNTS, (gate_table.REQUIRED_GATES, gate_table.MAX_GATES),
        )

    def test_the_table_matches_the_macos_and_node_contract_names(self):
        try:
            import foundation_node_feedback
            import macos_core_contract
        except ImportError:
            self.skipTest("the macOS contract modules are not importable here")
        self.assertEqual(gate_table.RUST_GATE_NAMES, macos_core_contract.GATE_NAMES)
        self.assertEqual(gate_table.PARSER_GATE_NAMES, macos_core_contract.PARSER_GATE_NAMES)
        self.assertEqual(gate_table.RUNTIME_GATE_NAMES, macos_core_contract.RUNTIME_GATE_NAMES)
        self.assertEqual(gate_table.API_FEATURE_NAME, macos_core_contract.API_FEATURE_NAME)
        self.assertEqual(gate_table.NODE_GATE_NAMES, foundation_node_feedback.NODE_GATE_NAMES)

    def test_selection_with_and_without_the_runtime_workspace(self):
        self.assertEqual(gate_table.selected_gate_names(False), gate_table.GATES)
        self.assertEqual(
            gate_table.selected_gate_names(True), gate_table.GATES + gate_table.RUNTIME_GATE_NAMES,
        )
        for value in (None, 1, "yes", 0):
            with self.subTest(value=value):
                with self.assertRaises(gate_table.GateTableRefusal):
                    gate_table.gate_templates(value)


class RenderTests(unittest.TestCase):
    def test_linux_rendering_is_the_exact_historical_argv_with_the_feature_gates(self):
        by_name = dict(_render(True))
        cargo = "/rust/bin/cargo"
        workspace = "/work/project/Cargo.toml"
        api = "/work/project/crates/host/api/Cargo.toml"
        self.assertEqual(by_name["format"], (
            cargo, "--locked", "--offline", "fmt", "--manifest-path", workspace, "--all", "--", "--check",
        ))
        self.assertEqual(by_name["clippy"], (
            cargo, "clippy", "--offline", "--manifest-path", workspace, "--workspace", "--all-targets",
            "--locked", "--", "-D", "warnings",
        ))
        self.assertEqual(by_name["workspace_tests"], (
            cargo, "test", "--offline", "--manifest-path", workspace, "--workspace", "--all-targets",
            "--locked",
        ))
        self.assertEqual(by_name["api_tests"], (
            cargo, "test", "--offline", "--manifest-path", api, "--all-targets", "--locked",
        ))
        self.assertEqual(by_name["api_feature_clippy"], (
            cargo, "clippy", "--offline", "--manifest-path", api, "--all-targets",
            "--features", "dev-uat-policy-import", "--locked", "--", "-D", "warnings",
        ))
        self.assertEqual(by_name["api_feature_tests"], (
            cargo, "test", "--offline", "--manifest-path", api, "--all-targets",
            "--features", "dev-uat-policy-import", "--locked",
        ))
        self.assertEqual(by_name["parser_replay"], (
            cargo, "run", "--locked", "--offline", "--manifest-path", "/work/project/fuzz/Cargo.toml",
        ))
        self.assertEqual(by_name["node_dependency_prepare"], (
            "/node/bin/node", "/node/bin/npm", "--offline", "--ignore-scripts", "--audit=false",
            "--fund=false", "ci", "--workspaces=true", "--include-workspace-root",
        ))
        self.assertEqual(by_name["node_dependency_audit"], (
            "/node/bin/node", "/node/bin/npm", "--offline", "ls", "--all", "--workspaces=true",
            "--include-workspace-root",
        ))
        self.assertEqual(by_name["typescript_typecheck"], (
            "/node/bin/node", "/node/bin/npm", "--offline", "run", "typecheck", "--workspaces",
            "--ignore-scripts",
        ))
        self.assertEqual(by_name["typescript_tests"], (
            "/node/bin/node", "/node/bin/npm", "--offline", "run", "test", "--workspaces",
            "--ignore-scripts",
        ))
        self.assertEqual(by_name["runtime_tests"], (
            cargo, "test", "--offline", "--manifest-path", "/work/project/runtime/Cargo.toml",
            "--workspace", "--all-targets", "--locked",
        ))

    def test_every_gate_is_offline_and_node_gates_keep_the_workspace_flags(self):
        rendered = _render(True)
        self.assertEqual(tuple(name for name, unused in rendered), gate_table.GATES + gate_table.RUNTIME_GATE_NAMES)
        for name, argv in rendered:
            with self.subTest(gate=name):
                self.assertIn("--offline", argv)
                if name.startswith(("format", "clippy", "workspace", "api", "mock", "conformance",
                                    "parser", "runtime")):
                    self.assertIn("--locked", argv)
        by_name = dict(rendered)
        for name in ("node_dependency_prepare", "typescript_typecheck", "typescript_tests"):
            with self.subTest(gate=name):
                self.assertIn("--ignore-scripts", by_name[name])
        for name in gate_table.NODE_GATE_NAMES:
            with self.subTest(gate=name):
                self.assertTrue(any(item.startswith("--workspaces") for item in by_name[name]))

    def test_windows_rendering_uses_backslash_paths_and_the_same_flags(self):
        linux = _render(True)
        windows = _render(True, WINDOWS_ARGUMENTS, "\\")
        self.assertEqual(tuple(name for name, unused in linux), tuple(name for name, unused in windows))
        by_name = dict(windows)
        self.assertEqual(by_name["format"][0], "C:\\rust\\bin\\cargo.exe")
        self.assertIn("C:\\work\\project\\Cargo.toml", by_name["format"])
        self.assertIn("C:\\work\\project\\crates\\host\\api\\Cargo.toml", by_name["api_tests"])
        self.assertEqual(by_name["typescript_tests"][:2], (
            "C:\\node\\node.exe", "C:\\node\\node_modules\\npm\\bin\\npm-cli.js",
        ))
        for (name, linux_argv), (unused, windows_argv) in zip(linux, windows):
            with self.subTest(gate=name):
                self.assertEqual(len(linux_argv), len(windows_argv))
                for left, right in zip(linux_argv, windows_argv):
                    if left.startswith("-") or left in ("fmt", "test", "clippy", "run", "ci", "ls", "all"):
                        self.assertEqual(left, right)

    def test_rendering_refuses_hostile_values(self):
        templates = gate_table.gate_templates(False)
        good = LINUX_ARGUMENTS
        for index in range(4):
            for bad in ("", "{cargo}", "a{b", "a}b", "a\x00b", None, 5, b"x", "x" * 5000):
                arguments = list(good)
                arguments[index] = bad
                with self.subTest(index=index, bad=bad):
                    with self.assertRaises(gate_table.GateTableRefusal):
                        gate_table.render(templates, *arguments)
        for separator in ("", "//", ":", None, "\\\\"):
            with self.subTest(separator=separator):
                with self.assertRaises(gate_table.GateTableRefusal):
                    gate_table.render(templates, *good, separator=separator)

    def test_rendering_refuses_malformed_templates(self):
        good = LINUX_ARGUMENTS
        cases = (
            (("format", ("{cargo}", "{unknown}")),),
            (("format", ("{cargo}", "x{cargo}")),),
            (("format", ("{cargo}", "{project}x")),),
            (("format", ("{cargo}", "{project}/../x")),),
            (("format", ("{cargo}", "{project}//x")),),
            (("format", ("{cargo}", "{project}/a\\b")),),
            (("format", ("{cargo}", "")),),
            (("format", ()),),
            (("format", ["{cargo}"]),),
            (("Format", ("{cargo}",)),),
            (("format", ("{cargo}",)), ("format", ("{cargo}",))),
            (("format",),),
            (["format", ("{cargo}",)],),
        )
        for templates in cases:
            with self.subTest(templates=templates):
                with self.assertRaises(gate_table.GateTableRefusal):
                    gate_table.render(templates, *good)

    def test_rendered_argv_never_keeps_a_placeholder(self):
        for include_runtime in (False, True):
            for name, argv in _render(include_runtime):
                with self.subTest(gate=name):
                    self.assertFalse(any("{" in item or "}" in item for item in argv))


class EmitTests(unittest.TestCase):
    def _emit(self, arguments):
        output = io.StringIO()
        with redirect_stdout(output):
            code = gate_table.main(arguments)
        return code, output.getvalue()

    def test_emit_prints_the_template_table_as_compact_json(self):
        for selection, include_runtime in (("base", False), ("runtime", True)):
            with self.subTest(selection=selection):
                code, text = self._emit(["emit", selection])
                self.assertEqual(code, 0)
                self.assertTrue(text.endswith("\n"))
                self.assertEqual(text.count("\n"), 1)
                value = json.loads(text)
                self.assertEqual(set(value), {"schema_version", "gates"})
                self.assertEqual(value["schema_version"], 1)
                self.assertEqual(
                    [entry["name"] for entry in value["gates"]],
                    list(gate_table.selected_gate_names(include_runtime)),
                )
                for entry in value["gates"]:
                    self.assertEqual(set(entry), {"name", "argv"})
                    self.assertTrue(all(type(item) is str for item in entry["argv"]))
                    self.assertEqual(entry["argv"][0] in ("{cargo}", "{node}"), True)
                rebuilt = tuple((entry["name"], tuple(entry["argv"])) for entry in value["gates"])
                self.assertEqual(rebuilt, gate_table.gate_templates(include_runtime))

    def test_emit_refuses_other_arguments(self):
        for arguments in ([], ["emit"], ["emit", "all"], ["show", "base"], ["emit", "base", "x"]):
            with self.subTest(arguments=arguments):
                code, text = self._emit(arguments)
                self.assertEqual(code, 2)
                self.assertEqual(text, "")


if __name__ == "__main__":
    unittest.main()
