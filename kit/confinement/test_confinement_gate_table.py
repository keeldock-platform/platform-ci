import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

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


class BrowserGateTests(unittest.TestCase):
    def test_the_browser_gate_is_opt_in_and_outside_the_shared_gate_sets(self):
        self.assertEqual(gate_table.BROWSER_GATE_NAMES, ("ui_kit_browser",))
        self.assertEqual(gate_table.BROWSER_WORKSPACE, "packages/kernel-ui-kit")
        self.assertNotIn("ui_kit_browser", gate_table.GATES + gate_table.RUNTIME_GATE_NAMES)
        self.assertEqual(gate_table.REQUIRED_GATES, 15)
        self.assertEqual(gate_table.MAX_GATES, 18)
        self.assertEqual(gate_table.selected_gate_names(False), gate_table.GATES)
        self.assertEqual(
            gate_table.selected_gate_names(False, True), gate_table.GATES + gate_table.BROWSER_GATE_NAMES,
        )
        self.assertEqual(
            gate_table.selected_gate_names(True, True),
            gate_table.GATES + gate_table.RUNTIME_GATE_NAMES + gate_table.BROWSER_GATE_NAMES,
        )
        for value in (None, 1, "yes", 0):
            with self.subTest(value=value):
                with self.assertRaises(gate_table.GateTableRefusal):
                    gate_table.gate_templates(False, value)

    def test_the_browser_gate_runs_the_workspace_script_offline_without_lifecycle_scripts(self):
        rendered = dict(gate_table.render(gate_table.gate_templates(False, True), *LINUX_ARGUMENTS))
        self.assertEqual(rendered["ui_kit_browser"], (
            "/node/bin/node", "/node/bin/npm", "--offline", "run", "test:browser",
            "--workspace=packages/kernel-ui-kit", "--ignore-scripts",
        ))
        self.assertEqual(
            tuple(name for name, unused in gate_table.gate_templates(True, True))[-1], "ui_kit_browser",
        )

    def test_neither_the_windows_emit_nor_the_shared_emit_carries_the_browser_gate(self):
        for selection in ("base", "runtime"):
            for arguments in (["emit", selection], ["emit", selection, "windows"]):
                with self.subTest(arguments=arguments):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        self.assertEqual(gate_table.main(arguments), 0)
                    names = [entry["name"] for entry in json.loads(output.getvalue())["gates"]]
                    self.assertNotIn("ui_kit_browser", names)
                    self.assertEqual(len(names), 15 if selection == "base" else 18)


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

    def test_windows_emits_the_stepped_npm_gate_with_the_same_name_count_order_and_flags(self):
        for selection, include_runtime in (("base", False), ("runtime", True)):
            with self.subTest(selection=selection):
                code, text = self._emit(["emit", selection, "windows"])
                self.assertEqual(code, 0)
                self.assertEqual(text.count("\n"), 1)
                value = json.loads(text)
                self.assertEqual(set(value), {"schema_version", "gates"})
                self.assertEqual(value["schema_version"], 1)
                self.assertEqual(
                    [entry["name"] for entry in value["gates"]],
                    list(gate_table.selected_gate_names(include_runtime)),
                )
                shared = dict(gate_table.gate_templates(include_runtime))
                stepped = [entry["name"] for entry in value["gates"] if "steps" in entry]
                self.assertEqual(stepped, [gate_table.WINDOWS_STEPPED_GATE])
                for entry in value["gates"]:
                    if entry["name"] == gate_table.WINDOWS_STEPPED_GATE:
                        self.assertEqual(set(entry), {"name", "steps"})
                        self.assertEqual(
                            tuple(tuple(step) for step in entry["steps"]), gate_table.windows_prepare_steps(),
                        )
                    else:
                        self.assertEqual(set(entry), {"name", "argv"})
                        self.assertEqual(tuple(entry["argv"]), shared[entry["name"]])
        dry_run, install = gate_table.windows_prepare_steps()
        self.assertEqual(dry_run, (
            "{node}", "{npm}", "--offline", "--ignore-scripts", "--audit=false", "--fund=false", "ci", "--dry-run",
            "--workspaces=true", "--include-workspace-root",
        ))
        self.assertEqual(install, (
            "{node}", "{npm}", "--offline", "--ignore-scripts", "--audit=false", "--fund=false", "install",
            "--no-save", "--workspaces=true", "--include-workspace-root",
        ))
        prepare = dict(gate_table.gate_templates(False))[gate_table.WINDOWS_STEPPED_GATE]
        for step in (dry_run, install):
            with self.subTest(step=step[6]):
                kept = [item for item in step if item not in ("ci", "install", "--dry-run", "--no-save")]
                self.assertEqual(kept, [item for item in prepare if item != "ci"])
        rendered = gate_table.render(
            (("prepare_check", dry_run), ("prepare_install", install)), *WINDOWS_ARGUMENTS, separator="\\",
        )
        self.assertEqual(rendered[0][1][:2], ("C:\\node\\node.exe", "C:\\node\\node_modules\\npm\\bin\\npm-cli.js"))
        self.assertEqual(rendered[1][1][-4:], ("install", "--no-save", "--workspaces=true", "--include-workspace-root"))
        self.assertEqual(gate_table.emit_json(False), gate_table.emit_json(False, None))
        with self.assertRaises(gate_table.GateTableRefusal):
            gate_table.emit_json(False, "linux")

    def test_emit_refuses_other_arguments(self):
        for arguments in ([], ["emit"], ["emit", "all"], ["show", "base"], ["emit", "base", "x"],
                          ["emit", "base", "linux"], ["emit", "all", "windows"], ["emit", "base", "windows", "x"],
                          ["emit", "base", "Windows"]):
            with self.subTest(arguments=arguments):
                code, text = self._emit(arguments)
                self.assertEqual(code, 2)
                self.assertEqual(text, "")


class ManifestDigestTests(unittest.TestCase):
    def _write(self, base, root_extra=None):
        root = {
            "name": "synthetic-root", "version": "1.0.0", "workspaces": ["packages/*"],
            "devDependencies": {"typescript": "6.0.3"},
        }
        root.update(root_extra or {})
        for name in ("host-api", "kernel-i18n"):
            (base / "packages" / name).mkdir(parents=True)
            (base / "packages" / name / "package.json").write_text(
                json.dumps({"name": "@synthetic/" + name, "version": "1.0.0"}), encoding="ascii",
            )
        (base / "package.json").write_text(json.dumps(root), encoding="ascii")
        return base

    @unittest.skipUnless(sys.platform.startswith("linux"), "linux_source_build needs POSIX-only modules")
    def test_the_digest_is_the_one_implementation_linux_source_build_uses(self):
        import linux_source_build
        with tempfile.TemporaryDirectory() as directory:
            base = self._write(Path(directory))
            self.assertEqual(gate_table.manifest_digest(base), linux_source_build._manifest_digest(base))
            self.assertEqual(len(gate_table.manifest_digest(base)), 64)
        self.assertIs(linux_source_build.MANIFEST_WORKSPACE_PATHS, gate_table.MANIFEST_WORKSPACE_PATHS)

    def test_the_module_needs_no_posix_only_import(self):
        source = Path(gate_table.__file__).read_text(encoding="ascii")
        for name in ("fcntl", "pwd", "grp", "resource"):
            self.assertNotIn("import " + name, source)

    def test_refusals_use_the_closed_lock_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            base = self._write(Path(directory), {"resolutions": {"a": "1.0.0"}})
            with self.assertRaises(gate_table.GateTableRefusal) as caught:
                gate_table.manifest_digest(base)
            self.assertEqual(caught.exception.reason, "lock")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gate_table.GateTableRefusal):
                gate_table.manifest_digest(directory)

    def test_the_command_prints_the_digest_and_refuses_other_shapes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = self._write(Path(directory))
            sink = io.StringIO()
            with redirect_stdout(sink):
                code = gate_table.main(["manifest-digest", "--root", str(base)])
            self.assertEqual((code, sink.getvalue()), (0, gate_table.manifest_digest(base) + "\n"))
            sink = io.StringIO()
            with redirect_stdout(sink):
                code = gate_table.main(["manifest-digest", "--root", str(base / "missing")])
            self.assertEqual((code, sink.getvalue()), (1, "gate-table=refused reason=lock\n"))
        for arguments in (["manifest-digest"], ["manifest-digest", "--root"], ["manifest-digest", "--dir", "x"],
                          ["manifest-digest", "--root", "a", "b"]):
            with self.subTest(arguments=arguments):
                self.assertEqual(gate_table.main(arguments), 2)


if __name__ == "__main__":
    unittest.main()
