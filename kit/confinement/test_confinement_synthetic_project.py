import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

import gate_table


CONFINEMENT = Path(__file__).resolve().parent
ROOT = CONFINEMENT.parents[1]
FIXTURE = CONFINEMENT / "synthetic_project"
FIXTURE_PREFIX = "kit/confinement/synthetic_project/"
sys.path.append(str(ROOT / "kit" / "bootstrap"))

import public_tree


EXPECTED_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "crates/host/api/Cargo.toml",
    "crates/host/api/src/lib.rs",
    "crates/host/api/tests/feature.rs",
    "crates/host/api/tests/surface.rs",
    "crates/host/conformance/Cargo.toml",
    "crates/host/conformance/src/lib.rs",
    "crates/host/conformance/tests/conformance.rs",
    "crates/host/conformance/tests/process_pipe.rs",
    "crates/host/mock/Cargo.toml",
    "crates/host/mock/src/lib.rs",
    "crates/host/mock/tests/mock.rs",
    "fuzz/Cargo.lock",
    "fuzz/Cargo.toml",
    "fuzz/src/main.rs",
    "package-lock.json",
    "package.json",
    "packages/host-api/package.json",
    "packages/host-api/src/index.js",
    "packages/host-api/tests/run.js",
    "packages/kernel-i18n/package.json",
    "packages/kernel-i18n/src/index.js",
    "packages/kernel-i18n/tests/run.js",
    "runtime/Cargo.lock",
    "runtime/Cargo.toml",
    "runtime/src/lib.rs",
    "runtime/tests/runtime.rs",
)
SRI_PATTERN = re.compile(r"sha512-[A-Za-z0-9+/]{86}==\Z")
TARBALL_PATTERN = re.compile(r"https://registry\.npmjs\.org/[a-z0-9._-]+/-/[a-z0-9._-]+\.tgz\Z")
FORBIDDEN_NODE_SPAWN = ("child_process", "fork(", "spawn(", "vitest")


def _text(relative):
    return (FIXTURE / relative).read_bytes().decode("utf-8")


def _json(relative):
    return json.loads(_text(relative))


def _gate_arguments(include_runtime):
    rendered = gate_table.render(
        gate_table.gate_templates(include_runtime), str(FIXTURE), "cargo", "node", "npm",
    )
    return {name: argv for name, argv in rendered}


class FixtureShapeTests(unittest.TestCase):
    def test_the_tree_is_exactly_the_expected_regular_files(self):
        actual = sorted(
            path.relative_to(FIXTURE).as_posix() for path in FIXTURE.rglob("*") if not path.is_dir()
        )
        self.assertEqual(actual, list(EXPECTED_FILES))
        for path in FIXTURE.rglob("*"):
            self.assertFalse(path.is_symlink())

    def test_every_file_is_small_ascii_without_hash_characters(self):
        for relative in EXPECTED_FILES:
            with self.subTest(relative=relative):
                payload = (FIXTURE / relative).read_bytes()
                self.assertLessEqual(len(payload), public_tree.MAX_FILE_BYTES)
                payload.decode("ascii")
                self.assertNotIn(chr(35).encode("ascii"), payload)
                self.assertNotIn(b"\r", payload)
                self.assertTrue(payload.endswith(b"\n"))

    def test_every_file_passes_the_public_text_scanner(self):
        for relative in EXPECTED_FILES:
            with self.subTest(relative=relative):
                public_tree.inspect_text(_text(relative), "platform")

    def test_every_file_is_registered_and_pinned_in_the_public_tree(self):
        for relative in EXPECTED_FILES:
            name = FIXTURE_PREFIX + relative
            with self.subTest(name=name):
                self.assertIn(name, public_tree.PLATFORM_FILES)
                self.assertEqual(
                    public_tree.PINNED_FILE_SHA256[name],
                    hashlib.sha256((FIXTURE / relative).read_bytes()).hexdigest(),
                )

    def test_the_fetch_workflow_builds_its_synthetic_capsule_from_this_fixture(self):
        workflow = (ROOT / ".github/workflows/lane-h-linux-fetch-encrypt.yml").read_text(encoding="utf-8")
        self.assertIn('fixture="' + FIXTURE_PREFIX.rstrip("/") + '"', workflow)
        self.assertIn('cp -R "$fixture/." "$repository/"', workflow)
        self.assertIn("gate_table.py manifest-digest --root", workflow)
        self.assertIn('"$repository/package-lock.json"', workflow)


class RustGateTests(unittest.TestCase):
    def test_every_manifest_in_both_gate_sets_exists_and_is_locked(self):
        for include_runtime in (False, True):
            for name, argv in _gate_arguments(include_runtime).items():
                if "--manifest-path" not in argv:
                    continue
                manifest = Path(argv[argv.index("--manifest-path") + 1])
                with self.subTest(gate=name):
                    self.assertTrue(manifest.is_file())
                    relative = manifest.relative_to(FIXTURE).parts
                    own_workspace = relative[0] in ("fuzz", "runtime")
                    workspace = manifest.parent if own_workspace else FIXTURE
                    self.assertTrue((workspace / "Cargo.lock").is_file())

    def test_the_runtime_gate_set_is_selected_by_the_runtime_root_files(self):
        for relative in gate_table.RUNTIME_ROOT_FILES:
            self.assertTrue((FIXTURE / relative).is_file())
        base = _gate_arguments(False)
        runtime = _gate_arguments(True)
        self.assertEqual(len(base), gate_table.REQUIRED_GATES)
        self.assertEqual(len(runtime), gate_table.MAX_GATES)
        self.assertEqual(
            tuple(name for name in runtime if name not in base), gate_table.RUNTIME_GATE_NAMES,
        )

    def test_the_api_feature_gates_use_a_declared_feature(self):
        feature = gate_table.API_FEATURE_NAME
        manifest = _text("crates/host/api/Cargo.toml")
        self.assertRegex(manifest, r"(?m)^\[features\]\n" + re.escape(feature) + r" = \[\]$")
        gates = _gate_arguments(False)
        for name in ("api_feature_clippy", "api_feature_tests"):
            with self.subTest(gate=name):
                argv = gates[name]
                self.assertEqual(argv[argv.index("--features") + 1], feature)
        self.assertIn("cfg!(feature = \"" + feature + "\")", _text("crates/host/api/tests/feature.rs"))
        self.assertIn("cfg!(feature = \"" + feature + "\")", _text("crates/host/api/src/lib.rs"))

    def test_workspace_membership_matches_the_gate_manifests(self):
        root = _text("Cargo.toml")
        for directory in ("crates/host/api", "crates/host/mock", "crates/host/conformance"):
            self.assertIn('"' + directory + '"', root)
        self.assertIn('exclude = ["fuzz", "runtime"]', root)
        self.assertIn("[workspace]", _text("fuzz/Cargo.toml"))
        self.assertIn("[workspace]", _text("runtime/Cargo.toml"))

    def test_the_lock_files_hold_only_path_packages(self):
        for relative in ("Cargo.lock", "fuzz/Cargo.lock", "runtime/Cargo.lock"):
            text = _text(relative)
            with self.subTest(relative=relative):
                self.assertTrue(text.startswith("version = 4\n"))
                self.assertNotRegex(text, r"(?m)^\s*(source|checksum)\s*=")
                self.assertIn("[[package]]", text)

    def test_every_test_target_runs_without_the_libtest_harness(self):
        for relative in EXPECTED_FILES:
            if not relative.endswith("Cargo.toml") or relative == "Cargo.toml":
                continue
            text = _text(relative)
            targets = re.findall(r'(?m)^path = "(tests/[a-z_]+\.rs)"$', text)
            with self.subTest(relative=relative):
                self.assertEqual(text.count("[[test]]"), len(targets))
                self.assertEqual(text.count("harness = false"), len(targets))
                for target in targets:
                    self.assertTrue((FIXTURE / Path(relative).parent / target).is_file())

    def test_the_child_process_test_pipes_with_a_cleared_environment(self):
        text = _text("crates/host/conformance/tests/process_pipe.rs")
        for needle in ("env_clear()", "Stdio::piped()", "current_exe()", "read_to_string", "status.success()"):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)
        self.assertLess(text.index("env_clear()"), text.index(".spawn()"))

    def test_the_parser_replay_binary_is_the_single_default_target(self):
        text = _text("fuzz/Cargo.toml")
        self.assertNotIn("[[bin]]", text)
        self.assertTrue((FIXTURE / "fuzz/src/main.rs").is_file())
        self.assertFalse((FIXTURE / "fuzz/src/lib.rs").exists())

    def test_rust_sources_carry_no_comment_lines(self):
        for relative in EXPECTED_FILES:
            if not relative.endswith(".rs"):
                continue
            with self.subTest(relative=relative):
                text = _text(relative)
                self.assertNotRegex(text, r"(?m)^\s*//")


class NodeGateTests(unittest.TestCase):
    def test_the_workspace_layout_is_the_manifest_digest_contract(self):
        root = _json("package.json")
        self.assertEqual(root["workspaces"], ["packages/*"])
        for path in gate_table.MANIFEST_WORKSPACE_PATHS:
            with self.subTest(path=path):
                package = _json(path + "/package.json")
                self.assertEqual(package["scripts"]["typecheck"], "node --check src/index.js")
                self.assertEqual(package["scripts"]["test"], "node tests/run.js")
                self.assertTrue((FIXTURE / path / "src/index.js").is_file())
                self.assertTrue((FIXTURE / path / "tests/run.js").is_file())

    def test_the_manifest_digest_is_a_stable_sha256(self):
        first = gate_table.manifest_digest(FIXTURE)
        self.assertRegex(first, r"[0-9a-f]{64}\Z")
        self.assertEqual(first, gate_table.manifest_digest(FIXTURE))

    def test_node_gates_are_the_workspace_script_gates(self):
        gates = _gate_arguments(False)
        self.assertEqual(gates["typescript_typecheck"][2:], (
            "--offline", "run", "typecheck", "--workspaces", "--ignore-scripts",
        ))
        self.assertEqual(gates["typescript_tests"][2:], (
            "--offline", "run", "test", "--workspaces", "--ignore-scripts",
        ))
        self.assertIn("ci", gates["node_dependency_prepare"])
        self.assertIn("ls", gates["node_dependency_audit"])

    def test_the_tests_run_on_worker_threads_and_spawn_nothing(self):
        for path in gate_table.MANIFEST_WORKSPACE_PATHS:
            for relative in ("src/index.js", "tests/run.js"):
                text = _text(path + "/" + relative)
                with self.subTest(path=path, relative=relative):
                    for needle in FORBIDDEN_NODE_SPAWN:
                        self.assertNotIn(needle, text)
            tests = _text(path + "/tests/run.js")
            self.assertIn("node:worker_threads", tests)
            self.assertIn("new Worker(new URL(import.meta.url))", tests)
            self.assertIn("parentPort.postMessage", tests)

    def test_the_lock_carries_real_registry_integrity_for_every_external_package(self):
        lock = _json("package-lock.json")
        self.assertEqual(lock["lockfileVersion"], 3)
        packages = lock["packages"]
        external = {key: value for key, value in packages.items() if "resolved" in value and not value.get("link")}
        self.assertEqual(sorted(external), ["node_modules/ms"])
        for key, value in external.items():
            with self.subTest(key=key):
                self.assertRegex(value["resolved"], TARBALL_PATTERN)
                self.assertRegex(value["integrity"], SRI_PATTERN)
                self.assertEqual(value["version"], "2.1.3")
                self.assertTrue(value["resolved"].endswith("/ms-2.1.3.tgz"))
        links = {key: value["resolved"] for key, value in packages.items() if value.get("link")}
        self.assertEqual(
            links,
            {
                "node_modules/fixture-host-api": "packages/host-api",
                "node_modules/fixture-kernel-i18n": "packages/kernel-i18n",
            },
        )
        for path in gate_table.MANIFEST_WORKSPACE_PATHS:
            package = _json(path + "/package.json")
            entry = packages[path]
            self.assertEqual(entry["name"], package["name"])
            self.assertEqual(entry["version"], package["version"])
            self.assertEqual(entry.get("dependencies"), package.get("dependencies"))
        self.assertEqual(packages[""]["workspaces"], ["packages/*"])

    def test_the_dependency_is_used_by_exactly_one_workspace(self):
        self.assertEqual(_json("packages/kernel-i18n/package.json")["dependencies"], {"ms": "2.1.3"})
        self.assertNotIn("dependencies", _json("packages/host-api/package.json"))
        self.assertNotIn("dependencies", _json("package.json"))
        self.assertIn("from 'ms'", _text("packages/kernel-i18n/src/index.js"))


if __name__ == "__main__":
    unittest.main()
