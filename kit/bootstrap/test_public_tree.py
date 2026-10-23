import tempfile
import unittest
from pathlib import Path

from public_tree import PublicTreeError, inspect_text, scan_tree


ROOT = Path(__file__).resolve().parents[2]


class PublicTreeTests(unittest.TestCase):
    def test_platform_candidate_has_only_the_allowlisted_tree(self):
        result = scan_tree(ROOT, "platform")
        self.assertIn("kit/bootstrap/policy.py", result)

    def test_consumer_shape_accepts_only_workflow_and_policy_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/public-policy.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("name: public-policy\n", encoding="utf-8")
            policy = root / "ci/policy.json"
            policy.parent.mkdir()
            policy.write_text('{"pool":"connect","schema_version":1}\n', encoding="utf-8")
            self.assertEqual(scan_tree(root, "connect"), (".github/workflows/public-policy.yml", "ci/policy.json"))
            (root / "README.md").write_text("text", encoding="utf-8")
            with self.assertRaisesRegex(PublicTreeError, "tree-shape"):
                scan_tree(root, "connect")

    def test_empty_docs_directory_and_symlink_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/public-policy.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("name: public-policy\n", encoding="utf-8")
            policy = root / "ci/policy.json"
            policy.parent.mkdir()
            policy.write_text('{"pool":"data","schema_version":1}\n', encoding="utf-8")
            (root / "docs").mkdir()
            with self.assertRaisesRegex(PublicTreeError, "tree-shape"):
                scan_tree(root, "data")
            (root / "docs").rmdir()
            link = root / "ci/linked"
            link.symlink_to(policy)
            with self.assertRaisesRegex(PublicTreeError, "tree-shape|symlink-present|non-regular-file"):
                scan_tree(root, "data")

    def test_identifying_content_fails_without_echoing_it(self):
        fixtures = (
            "purpose " + chr(35) + " comment",
            "rule " + "D" + "90",
            chr(47) + "Users" + chr(47) + "person" + chr(47) + "secret",
            "source " + "C:" + chr(92) + "Users" + chr(92) + "person" + chr(92) + "secret",
            "source " + "C:" + chr(47) + "Users" + chr(47) + "person" + chr(47) + "secret",
            "network " + chr(92) * 2 + "server" + chr(92) + "Users" + chr(92) + "person" + chr(92) + "secret",
            "network " + chr(47) * 2 + "server" + chr(47) + "Users" + chr(47) + "person" + chr(47) + "secret",
            "extended " + chr(92) * 2 + "?" + chr(92) + "UNC" + chr(92) + "server" + chr(92) + "Users" + chr(92) + "person" + chr(92) + "secret",
            "extended drive " + chr(92) * 2 + "?" + chr(92) + "C:" + chr(92) + "Users" + chr(92) + "person" + chr(92) + "secret",
            "prefix " + "keeldock" + "-" + "core",
            "https:" + chr(47) * 2 + "github.com" + chr(47) + "owner" + chr(47) + "private",
            "agents" + "-work/files/state",
        )
        for fixture in fixtures:
            with self.subTest(fixture_class="identifying"):
                with self.assertRaises(PublicTreeError):
                    inspect_text(fixture, "platform")

    def test_public_cross_pool_references_remain_allowed(self):
        inspect_text("uses: keeldock-platform/platform-ci/kit/bootstrap@" + "a" * 40, "connect")

    def test_file_bound_is_checked_before_full_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (".github/workflows/public-policy.yml", "ci/policy.json"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"x" * 262145)
            with self.assertRaisesRegex(PublicTreeError, "file-too-large"):
                scan_tree(root, "connect")


if __name__ == "__main__":
    unittest.main(verbosity=2)
