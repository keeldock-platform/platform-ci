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
    "packages/host-api/src/index.ts",
    "packages/host-api/tests/no-net-use.mjs",
    "packages/host-api/tests/run.js",
    "packages/host-api/tests/vitest.test.ts",
    "packages/host-api/tsconfig.json",
    "packages/host-api/vitest.config.ts",
    "packages/kernel-i18n/package.json",
    "packages/kernel-i18n/src/index.js",
    "packages/kernel-i18n/tests/run.js",
    "runtime/Cargo.lock",
    "runtime/Cargo.toml",
    "runtime/src/lib.rs",
    "runtime/tests/runtime.rs",
)
SRI_PATTERN = re.compile(r"sha512-[A-Za-z0-9+/]{86}==\Z")
TARBALL_PATTERN = re.compile(
    r"https://registry\.npmjs\.org/(?:@[a-z0-9._-]+/)?[a-z0-9._-]+/-/[a-z0-9._-]+\.tgz\Z"
)
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


def _npm_dependency_closure(packages, roots):
    selected = set()
    pending = list(roots)
    while pending:
        key = pending.pop()
        if key in selected:
            continue
        selected.add(key)
        package_path = Path(key)
        for section in ("dependencies", "optionalDependencies"):
            for name in packages[key].get(section, {}):
                ancestor = package_path
                target = None
                while True:
                    candidate = (ancestor / "node_modules" / name).as_posix()
                    if candidate in packages:
                        target = candidate
                        break
                    if ancestor == Path("."):
                        break
                    ancestor = ancestor.parent
                if target is None:
                    raise AssertionError((key, section, name))
                pending.append(target)
    return selected


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
                public_tree.inspect_text(_text(relative), "platform", FIXTURE_PREFIX + relative)

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
                if path == "packages/host-api":
                    self.assertEqual(
                        package["scripts"]["typecheck"],
                        "tsc --project tsconfig.json --noEmit && node --check src/index.js",
                    )
                    self.assertEqual(
                        package["scripts"]["test"],
                        "node --import ./tests/no-net-use.mjs ../../node_modules/vitest/vitest.mjs run --configLoader runner && node tests/run.js",
                    )
                else:
                    self.assertEqual(package["scripts"]["typecheck"], "node --check src/index.js")
                    self.assertEqual(package["scripts"]["test"], "node tests/run.js")
                self.assertTrue((FIXTURE / path / "src/index.js").is_file())
                self.assertTrue((FIXTURE / path / "tests/run.js").is_file())

    def test_the_host_api_typescript_and_vitest_sources_are_declared(self):
        package = _json("packages/host-api/package.json")
        self.assertEqual(
            package["devDependencies"],
            {"esbuild": "0.27.0", "rollup": "4.44.2", "typescript": "6.0.3",
             "vite": "8.3.5", "vitest": "5.0.5"},
        )
        self.assertTrue((FIXTURE / "packages/host-api/tsconfig.json").is_file())
        self.assertIn('pool: \'threads\'', _text("packages/host-api/vitest.config.ts"))
        self.assertIn("tests/**/*.test.ts", _text("packages/host-api/vitest.config.ts"))
        self.assertIn("it(", _text("packages/host-api/tests/vitest.test.ts"))
        self.assertIn("expect(true).toBe(true)", _text("packages/host-api/tests/vitest.test.ts"))
        self.assertIn("fixtureValue: number", _text("packages/host-api/src/index.ts"))

    def test_the_host_api_test_script_uses_the_pinned_preload_and_keeps_the_smoke(self):
        package = _json("packages/host-api/package.json")
        self.assertEqual(
            package["scripts"]["test"],
            "node --import ./tests/no-net-use.mjs ../../node_modules/vitest/vitest.mjs run --configLoader runner && node tests/run.js",
        )
        packages = _json("package-lock.json")["packages"]
        self.assertEqual(packages["node_modules/vitest"]["version"], "5.0.5")
        self.assertEqual(packages["packages/host-api"]["devDependencies"], {
            "esbuild": "0.27.0", "rollup": "4.44.2", "typescript": "6.0.3",
            "vite": "8.3.5", "vitest": "5.0.5",
        })
        preload = (FIXTURE / "packages/host-api/tests/no-net-use.mjs").read_bytes()
        blob = b"blob " + str(len(preload)).encode("ascii") + b"\0" + preload
        self.assertEqual(hashlib.sha1(blob).hexdigest(), "8fcc6c75e84040fa9e6e1fde9c709920cf7d8739")
        self.assertNotIn(chr(35), preload.decode("ascii"))

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
        closure = _npm_dependency_closure(
            packages,
            ("node_modules/typescript", "node_modules/vite", "node_modules/vitest",
             "node_modules/esbuild", "node_modules/rollup"),
        )
        self.assertEqual(set(external), closure | {"node_modules/ms"})
        self.assertEqual(len(closure), 111)
        for key, value in external.items():
            with self.subTest(key=key):
                self.assertRegex(value["resolved"], TARBALL_PATTERN)
                self.assertRegex(value["integrity"], SRI_PATTERN)
        self.assertEqual(external["node_modules/ms"]["version"], "2.1.3")
        self.assertTrue(external["node_modules/ms"]["resolved"].endswith("/ms-2.1.3.tgz"))
        for name, version in (("typescript", "6.0.3"), ("vite", "8.3.5"), ("vitest", "5.0.5"),
                              ("esbuild", "0.27.0"), ("rollup", "4.44.2")):
            with self.subTest(name=name):
                self.assertEqual(packages["node_modules/" + name]["version"], version)
        for name in ("@esbuild/linux-x64", "@rollup/rollup-linux-x64-gnu"):
            with self.subTest(name=name):
                native = packages["node_modules/" + name]
                self.assertTrue(native["optional"])
                self.assertEqual(native["os"], ["linux"])
                self.assertEqual(native["cpu"], ["x64"])
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
            self.assertEqual(entry.get("devDependencies"), package.get("devDependencies"))
        self.assertEqual(packages["packages/host-api"]["devDependencies"], {
            "esbuild": "0.27.0",
            "rollup": "4.44.2",
            "typescript": "6.0.3",
            "vite": "8.3.5",
            "vitest": "5.0.5",
        })
        self.assertEqual(packages[""]["workspaces"], ["packages/*"])

    def test_vite_lock_fields_match_the_8_3_5_registry_manifest(self):
        vite = _json("package-lock.json")["packages"]["node_modules/vite"]
        self.assertEqual(vite["version"], "8.3.5")
        self.assertEqual(vite["resolved"], "https://registry.npmjs.org/vite/-/vite-8.3.5.tgz")
        self.assertEqual(
            vite["integrity"],
            "sha512-z1YpjieJ9g0ebTmQpLBv/oq9E3F9EIlOe+7LahW8SrE3LTiG3udBRUXQOlYXP9b+IC2q2phHeVxj9xGlw34OEQ==",
        )
        self.assertEqual(vite["license"], "MIT")
        self.assertTrue(vite["dev"])
        self.assertEqual(vite["dependencies"], {
            "postcss": "^8.5.30",
            "rolldown": "~1.2.14",
            "picomatch": "^4.0.7",
            "tinyglobby": "^0.2.17",
            "lightningcss": "^1.33.0",
        })
        self.assertEqual(vite["optionalDependencies"], {"fsevents": "~2.3.3"})
        self.assertEqual(vite["peerDependencies"], {
            "tsx": "^4.8.1",
            "jiti": ">=1.21.0",
            "less": "^4.0.0",
            "sass": "^1.70.0",
            "yaml": "^2.4.2",
            "stylus": ">=0.54.8",
            "terser": "^5.16.0",
            "esbuild": "^0.27.0 || ^0.28.0",
            "sugarss": "^5.0.0",
            "@types/node": "^20.19.0 || >=22.12.0",
            "sass-embedded": "^1.70.0",
            "@vitejs/devtools": "^0.7.1 || ^0.8.0",
        })
        self.assertEqual(vite["peerDependenciesMeta"], {
            name: {"optional": True}
            for name in vite["peerDependencies"]
        })
        self.assertEqual(vite["engines"], {"node": "^20.19.0 || >=22.12.0"})
        self.assertEqual(vite["bin"], {"vite": "bin/vite.js"})

    def test_the_dependencies_are_used_by_the_expected_workspaces(self):
        self.assertEqual(_json("packages/kernel-i18n/package.json")["dependencies"], {"ms": "2.1.3"})
        self.assertNotIn("dependencies", _json("packages/host-api/package.json"))
        self.assertNotIn("dependencies", _json("package.json"))
        self.assertNotIn("devDependencies", _json("package.json"))
        self.assertIn("from 'ms'", _text("packages/kernel-i18n/src/index.js"))


if __name__ == "__main__":
    unittest.main()
