import base64
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bundle
import fetch
import node_vendor_source
import prepare
import project


TOOLS = {
    "node": "26.8.1",
    "npm": "11.19.0",
    "cargo": "1.99.1",
    "rustc": "1.99.1",
}


def _git(repository, *arguments):
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout


class DesktopProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name) / "source"
        self.repository.mkdir()
        _git(self.repository, "init", "--quiet")
        _git(self.repository, "config", "user.name", "Fixture")
        _git(self.repository, "config", "user.email", "fixture@example.invalid")
        integrity = "sha512-" + base64.b64encode(bytes(64)).decode("ascii")
        package_lock = {
            "name": "desktop-fixture",
            "version": "0.1.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {
                    "name": "desktop-fixture",
                    "version": "0.1.0",
                    "devDependencies": {"is-number": "7.0.0"},
                },
                "node_modules/is-number": {
                    "version": "7.0.0",
                    "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
                    "integrity": integrity,
                    "dev": True,
                },
            },
        }
        source = "registry+https://index.crates.io/"
        cargo_lock = (
            "version = 3\n\n"
            "[[package]]\n"
            "name = \"itoa\"\n"
            "version = \"1.0.15\"\n"
            "source = " + json.dumps(source) + "\n"
            "checksum = \"" + ("1" * 64) + "\"\n"
        )
        files = {
            "package.json": json.dumps({
                "name": "desktop-fixture",
                "version": "0.1.0",
                "private": True,
                "devDependencies": {"is-number": "7.0.0"},
            }),
            "package-lock.json": json.dumps(package_lock),
            "Cargo.toml": '[workspace]\nmembers = ["src-tauri"]\nresolver = "3"\n',
            "src-tauri/Cargo.toml": '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n',
            "Cargo.lock": cargo_lock,
        }
        for relative, payload in files.items():
            target = self.repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(payload, encoding="utf-8")
        _git(self.repository, "add", ".")
        _git(self.repository, "commit", "--quiet", "-m", "fixture")
        self.revision = _git(self.repository, "rev-parse", "HEAD").decode("ascii").strip()
        self.request = {
            "schema": 1,
            "repository": str(self.repository),
            "source_revision": self.revision,
            "profile": "desktop",
            "tools": dict(TOOLS),
            "playwright": [],
            "lockfiles": ["package-lock.json", "Cargo.lock"],
        }

    def tearDown(self):
        self.temporary.cleanup()

    def test_projection_combines_two_lockfiles_without_source_manifests(self):
        payload = project.build_projection(self.request)
        projection_value = fetch.validate_projection(payload, "desktop")
        self.assertEqual(projection_value["profile"], "desktop")
        self.assertEqual(projection_value["tools"], TOOLS)
        self.assertEqual(projection_value["npm_package"]["name"], "devlane-projection")
        self.assertEqual(projection_value["cargo_manifest"].splitlines()[1], 'name = "devlane-projection"')
        self.assertEqual(projection_value["cargo_workspaces"], [])
        self.assertNotIn("desktop-fixture", payload.decode("ascii"))

    def test_projection_rejects_a_changed_lockfile_inventory(self):
        request = dict(self.request, lockfiles=["package-lock.json"])
        with self.assertRaisesRegex(bundle.Refusal, "projection-desktop-lockfile-set"):
            project.build_projection(request)

    def test_projection_rejects_a_nonregular_workspace_manifest(self):
        (self.repository / "Cargo.toml").unlink()
        (self.repository / "Cargo.toml").symlink_to("src-tauri/Cargo.toml")
        _git(self.repository, "add", "--all")
        _git(self.repository, "commit", "--quiet", "-m", "symlink workspace manifest")
        request = dict(self.request, source_revision=_git(
            self.repository, "rev-parse", "HEAD").decode("ascii").strip())
        with self.assertRaisesRegex(bundle.Refusal, "projection-desktop-manifest-missing"):
            project.build_projection(request)

    def test_preparation_project_contains_both_dependency_manifests(self):
        projection_value = fetch.validate_projection(project.build_projection(self.request), "desktop")
        project_root = Path(self.temporary.name) / "projected"
        prepare._project_files(projection_value, project_root)
        self.assertTrue((project_root / "package.json").is_file())
        self.assertTrue((project_root / "package-lock.json").is_file())
        self.assertTrue((project_root / ".npmrc").is_file())
        self.assertTrue((project_root / "Cargo.toml").is_file())
        self.assertTrue((project_root / "Cargo.lock").is_file())
        self.assertTrue((project_root / "src/lib.rs").is_file())

    def test_mixed_preparation_runs_npm_ci_and_cargo_vendor(self):
        projection_value = fetch.validate_projection(project.build_projection(self.request), "desktop")
        root = Path(self.temporary.name) / "preparation"
        (root / "work").mkdir(parents=True)
        commands = []

        def run_command(argv, **_options):
            commands.append(argv)
            if "npm" in argv:
                (root / "work/project/node_modules").mkdir()
            elif "cargo" in argv:
                (root / "work/prepared/cargo-vendor").mkdir()

        with patch.object(prepare, "run", side_effect=run_command), \
                patch.object(prepare.os, "chown"), \
                patch.object(prepare, "_copy_tree"), \
                patch.object(prepare, "_publish_prepared_output"):
            prepare._run_worker(root, projection_value, "desktop", Path(self.temporary.name) / "prepared",
                                {}, 1000, 1000)
        self.assertEqual([argv[argv.index("npm")] if "npm" in argv else argv[argv.index("cargo")]
                          for argv in commands], ["npm", "cargo"])
        self.assertIn("--ignore-scripts", commands[0])
        self.assertIn("vendor", commands[1])
        self.assertIn("--locked", commands[1])

    def test_profile_inventory_has_the_mixed_offline_command_set(self):
        profile = json.loads(Path("ci/devlane-profiles.json").read_text(encoding="utf-8"))["profiles"]["desktop"]
        commands = profile["commands"]
        self.assertEqual(commands[0][:2], ["cargo", "fmt"])
        self.assertEqual(commands[1][:2], ["cargo", "clippy"])
        self.assertIn("--all-features", commands[2])
        self.assertEqual(commands[3][:2], ["cargo", "test"])
        self.assertIn("--all-features", commands[4])
        self.assertEqual(commands[5][1:3], ["--prefix", "/workspace/source"])
        self.assertEqual(commands[5][3:], ["run", "typecheck"])
        self.assertEqual(commands[6][3:], ["run", "test"])
        self.assertEqual([command[-1] for command in commands[-3:]],
                         ["minimal", "git-only", "all-tools-so-far"])
        self.assertIn("libwebkit2gtk-4.1-dev", profile["system_dependencies"])

    def test_desktop_node_distribution_is_separately_pinned(self):
        distribution = node_vendor_source._distribution("desktop")
        self.assertEqual(distribution["node_version"], TOOLS["node"])
        self.assertEqual(distribution["npm_version"], TOOLS["npm"])
        self.assertEqual(
            distribution["archive_sha256"],
            "3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d",
        )


if __name__ == "__main__":
    unittest.main()
