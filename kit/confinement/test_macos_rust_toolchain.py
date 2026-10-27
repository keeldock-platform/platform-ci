import importlib.util
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest


MODULE_PATH = Path(__file__).resolve().parent / "macos_rust_toolchain.py"
PRIVATE_TMP = Path(chr(47) + "private" + chr(47) + "tmp")
SPEC = importlib.util.spec_from_file_location("macos_rust_toolchain", MODULE_PATH)
rust = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rust
SPEC.loader.exec_module(rust)


class RustToolchainContractTests(unittest.TestCase):
    def test_pinned_components_match_official_macos_release_metadata(self):
        self.assertEqual(rust.TOOLCHAIN_VERSION, "1.99.1")
        self.assertEqual(rust.TARGET, "aarch64-apple-darwin")
        self.assertEqual(rust.OFFICIAL_MANIFEST_SHA256,
                         "fb152be80975c194aa5fc684b2aec3a6e14e2b855efe2faa4e5f8ae6e590f463")
        self.assertEqual(
            {component.name: component.sha256 for component in rust.COMPONENTS},
            {
                "rustc": "23948a0a9c162fd2952defb3fb0462c44e8fcfd1a4ab8a274a1e1bdb2cf810a3",
                "rust-std": "fe79d6ab5a0321de26463999d8c112b8ad3eafbcbcf822d66a2300b45dde1031",
                "cargo": "685e563d94db1f003ffa5f5831439eec02569b9950b69867953c8213269c1eaf",
                "rustfmt-preview": "8b80dda570f140ee9ced8799294e812bba847a025f185bae4cba85a2ba235570",
                "clippy-preview": "c463f31831196702fc544900a0dc4c1837905327507fbec751fe46e59ca098bf",
            },
        )
        self.assertTrue(all(rust._valid_component(component) for component in rust.COMPONENTS))

    def test_control_sha_and_run_context_require_canonical_values(self):
        self.assertTrue(rust.valid_control_sha("a" * 40))
        self.assertFalse(rust.valid_control_sha("A" * 40))
        self.assertFalse(rust.valid_control_sha("a" * 39))
        self.assertFalse(rust.valid_control_sha("a" * 41))
        with self.assertRaises(rust.Refusal):
            rust._strict_context({
                "GITHUB_RUN_ID": "01",
                "GITHUB_RUN_ATTEMPT": "1",
                "RUNNER_TEMP": "/tmp/runner",
            }, "a" * 40)

    def test_cli_accepts_only_the_bound_control_sha(self):
        self.assertEqual(rust._parse_args(["--control-sha", "a" * 40]), "a" * 40)
        for argv in (
            [],
            ["--control-sha", "a" * 40, "--compiler", "/tmp/rustc"],
            ["--control-sha", "../" + "a" * 37],
            ["--control-sha", "A" * 40],
        ):
            with self.subTest(argv=argv), self.assertRaises(rust.Refusal):
                rust._parse_args(argv)

    def test_archive_names_reject_traversal_and_non_posix_paths(self):
        self.assertEqual(
            rust._safe_archive_name("rustc-1.99.1-aarch64-apple-darwin/bin/rustc"),
            "rustc-1.99.1-aarch64-apple-darwin/bin/rustc",
        )
        for name in (
            "../outside", "/absolute/path", "root/../../outside", "root\\outside",
            "root//duplicate-separator", "root/./dot", "root/naïve",
        ):
            with self.subTest(name=name):
                self.assertIsNone(rust._safe_archive_name(name))

    def test_archive_links_must_stay_inside_the_pinned_component(self):
        root = "rustc-1.99.1-aarch64-apple-darwin"
        self.assertTrue(rust._safe_link_target(root + "/bin/rustc", "../lib/rustlib", root))
        self.assertTrue(rust._safe_link_target(
            root + "/bin/rustc", root + "/lib/rustc", root, hardlink=True,
        ))
        for name, target, hardlink in (
            (root + "/bin/rustc", "../../../../etc/passwd", False),
            (root + "/bin/rustc", "/etc/passwd", False),
            (root + "/bin/rustc", "../outside", True),
            (root + "/bin/rustc", "..\\outside", False),
        ):
            with self.subTest(target=target, hardlink=hardlink):
                self.assertFalse(rust._safe_link_target(name, target, root, hardlink=hardlink))

    def test_worker_traversal_root_is_search_only_and_root_owned(self):
        worker_uid = 501
        root_info = SimpleNamespace(
            st_mode=stat.S_IFDIR | rust.WORKER_TRAVERSAL_MODE,
            st_uid=0,
        )
        self.assertTrue(rust._worker_traversal_root_is_safe(root_info, worker_uid))
        for mode, owner, uid in (
            (0o700, 0, worker_uid),
            (0o755, 0, worker_uid),
            (0o713, 0, worker_uid),
            (0o711, worker_uid, worker_uid),
            (0o711, 0, 0),
        ):
            with self.subTest(mode=oct(mode), owner=owner, uid=uid):
                info = SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=owner)
                self.assertFalse(rust._worker_traversal_root_is_safe(info, uid))

    def test_download_redirects_are_limited_to_official_same_path_hosts(self):
        import urllib.error
        from urllib.request import Request

        handler = rust._PinnedRedirect()
        original = Request(
            "https://static.rust-lang.org/dist/2026-10-15/cargo.tar.xz",
            method="GET",
        )
        self.assertIsNotNone(handler.redirect_request(
            original, None, 302, "Found", {},
            "https://static-rust-lang-org.s3.amazonaws.com/dist/2026-10-15/cargo.tar.xz",
        ))
        for target in (
            "https://evil.example/dist/2026-10-15/cargo.tar.xz",
            "http://static.rust-lang.org/dist/2026-10-15/cargo.tar.xz",
            "https://static.rust-lang.org/dist/other/cargo.tar.xz",
        ):
            with self.subTest(target=target), self.assertRaises(urllib.error.HTTPError):
                rust._PinnedRedirect().redirect_request(original, None, 302, "Found", {}, target)

    def test_receipt_uses_the_closed_schema_and_binds_run_attempt(self):
        versions = {
            "rustc": rust.EXPECTED_VERSIONS["rustc"],
            "cargo": "1.99.1",
            "rustfmt": rust.EXPECTED_VERSIONS["rustfmt"],
            "clippy": rust.EXPECTED_VERSIONS["clippy"],
        }
        record = rust._validated_receipt("a" * 40, "123456", "2", versions)
        self.assertEqual(set(record), {
            "schema_version", "concern", "status", "control_sha", "run_id", "run_attempt",
            "host", "toolchain", "components", "versions", "target", "smoke", "source",
            "offline", "cleanup",
        })
        self.assertEqual(record["run_id"], "123456")
        self.assertEqual(record["run_attempt"], "2")
        self.assertEqual(record["components"], {
            component.name: component.sha256 for component in rust.COMPONENTS
        })
        self.assertEqual(record["versions"], versions)
        self.assertEqual(record["smoke"], {"fmt": "passed", "clippy": "passed", "test": "passed"})
        self.assertEqual(record["source"], "none")
        self.assertIs(record["offline"], True)
        self.assertEqual(record["cleanup"], "complete")
        self.assertEqual(len(record), 15)

    def test_receipt_json_is_canonical_and_payload_has_no_paths_or_raw_output(self):
        versions = {
            "rustc": rust.EXPECTED_VERSIONS["rustc"],
            "cargo": "0.100.0",
            "rustfmt": rust.EXPECTED_VERSIONS["rustfmt"],
            "clippy": rust.EXPECTED_VERSIONS["clippy"],
        }
        record = rust._validated_receipt("b" * 40, "77", "1", versions)
        payload = rust._receipt_bytes(record)
        body = payload[:-1].decode("ascii")
        parsed = json.loads(body)
        canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self.assertEqual(body, canonical)
        self.assertNotIn(PRIVATE_TMP.as_posix(), body)
        self.assertNotIn("stdout", body)
        self.assertNotIn("stderr", body)
        self.assertLessEqual(len(payload), 8192)

    @unittest.skipIf(sys.platform == "win32", "POSIX native path validation")
    def test_toolchain_paths_accept_absolute_pathlib_paths_and_reject_relative_paths(self):
        root = PRIVATE_TMP / "rust-toolchain-smoke-run"
        prefix = root / "toolchain"
        tools = {
            name: prefix / "bin" / filename
            for name, filename in (
                ("rustc", "rustc"),
                ("cargo", "cargo"),
                ("rustfmt", "rustfmt"),
                ("cargo_fmt", "cargo-fmt"),
                ("cargo_clippy", "cargo-clippy"),
                ("clippy_driver", "clippy-driver"),
            )
        }
        value = rust.ToolchainPaths(
            root=root,
            prefix=prefix,
            **tools,
            host=rust.TARGET,
            rustc_version=rust.EXPECTED_VERSIONS["rustc"],
            cargo_version="1.99.1",
            rustfmt_version=rust.EXPECTED_VERSIONS["rustfmt"],
            clippy_version=rust.EXPECTED_VERSIONS["clippy"],
            component_hashes=tuple((component.name, component.sha256) for component in rust.COMPONENTS),
        )
        self.assertEqual(value.command_paths()["rustc"], tools["rustc"])
        with self.assertRaises(rust.Refusal):
            rust.ToolchainPaths(
                root=root,
                prefix=prefix,
                **{**tools, "rustc": Path("rustc")},
                host=rust.TARGET,
                rustc_version=rust.EXPECTED_VERSIONS["rustc"],
                cargo_version="1.99.1",
                rustfmt_version=rust.EXPECTED_VERSIONS["rustfmt"],
                clippy_version=rust.EXPECTED_VERSIONS["clippy"],
                component_hashes=tuple((component.name, component.sha256) for component in rust.COMPONENTS),
            )

    @unittest.skipIf(sys.platform == "win32", "POSIX worker environment paths")
    def test_worker_environment_is_allowlisted_and_offline(self):
        class ReviewedBuildStub:
            @staticmethod
            def _child_environment(home, storage, toolchain, worker_tools):
                return {
                    "PATH": worker_tools["path"],
                    "HOME": str(home),
                    "TMPDIR": str(storage / "tmp"),
                    "DEVELOPER_DIR": toolchain["developer_directory"],
                    "LANG": "C",
                    "LC_ALL": "C",
                }

        class CapabilityStub:
            MAX_TOOL_PATH_BYTES = 4096

        prefix = PRIVATE_TMP / "rust-root" / "toolchain"
        storage = PRIVATE_TMP / "rust-root" / "worker-storage"
        env = rust._worker_environment(
            PRIVATE_TMP / "rust-home", storage, prefix,
            {"rustc": prefix / "bin" / "rustc"},
            {"developer_directory": "/Applications/Xcode.app/Contents/Developer"},
            {"path": "/usr/bin:/bin"}, CapabilityStub, ReviewedBuildStub,
        )
        self.assertEqual(env["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(env["CARGO_HOME"], str(storage / "cargo-home"))
        self.assertEqual(env["CARGO_TARGET_DIR"], str(storage / "target"))
        self.assertEqual(env["RUSTC"], str(prefix / "bin" / "rustc"))
        self.assertTrue(env["PATH"].startswith(str(prefix / "bin") + ":"))
        self.assertFalse({"GITHUB_TOKEN", "GH_TOKEN", "RUSTUP_TOOLCHAIN", "CARGO_REGISTRIES_CRATES_IO_TOKEN"}
                         & set(env))

    def test_worker_command_refusals_carry_only_closed_private_checks(self):
        class ProbeFailure(Exception):
            def __init__(self, *, cleanup_complete=True, command_check=None):
                self.cleanup_complete = cleanup_complete
                self.command_check = command_check

        deadline = rust.time.monotonic() + 30

        def invoke(result=None, error=None, stage="format"):
            def run_as_probe_user(*unused_args, **unused_kwargs):
                if error is not None:
                    raise error
                return result

            capability = SimpleNamespace(
                ProbeFailure=ProbeFailure,
                _run_as_probe_user=run_as_probe_user,
            )
            return rust._run_worker_command(
                ("cargo", "fmt"), 502, {}, "/usr/bin/python3", capability,
                stage=stage, deadline=deadline,
            )

        cases = (
            (ProbeFailure(command_check="spawn_failure"), None, "version_mismatch", "spawn_failure"),
            (ProbeFailure(command_check="unknown_check_value"), None, "version_mismatch", "helper_failure"),
            (None, SimpleNamespace(returncode=9, stdout=b"", stderr=b""), "version_mismatch", "nonzero_exit"),
            (None, SimpleNamespace(returncode=0, stdout="private", stderr=b""), "capture_invalid", "capture_invalid"),
            (None, SimpleNamespace(
                returncode=0, stdout=b"x" * (rust.MAX_CAPTURE_BYTES + 1), stderr=b"",
            ), "capture_invalid", "capture_overflow"),
        )
        for error, result, expected_reason, expected_check in cases:
            with self.subTest(command_check=expected_check), self.assertRaises(rust.Refusal) as raised:
                invoke(result=result, error=error)
            self.assertEqual(raised.exception.reason, expected_reason)
            self.assertEqual(raised.exception.command_check, expected_check)

        with self.assertRaises(rust.Refusal) as timed_out:
            invoke(error=ProbeFailure(cleanup_complete=False, command_check="timeout"))
        self.assertEqual(timed_out.exception.reason, "cleanup_incomplete")
        self.assertEqual(timed_out.exception.command_check, "timeout")

        with self.assertRaises(rust.Refusal) as smoke_failed:
            invoke(result=SimpleNamespace(returncode=9, stdout=b"", stderr=b""), stage="smoke")
        self.assertEqual(smoke_failed.exception.reason, "smoke_failed")
        self.assertIsNone(smoke_failed.exception.command_check)

        self.assertIsNone(rust.Refusal("gate_failed", command_check="unknown_check_value").command_check)


if __name__ == "__main__":
    unittest.main()
