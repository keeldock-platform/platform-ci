import ast
import json
import unittest

import linux_channels as channels
import linux_fixtures as fixtures


__all__ = ["LinuxFixtureGenerationTests", "LinuxFixtureEvaluationTests"]

NONCE = "0123456789abcdef01234567"
PORTS = {"https4": 1111, "udp": 2222, "dns_udp": 53, "proxy": 3333}
HOSTILE_NAMES = (
    "tcp-connect",
    "udp-send",
    "dns-lookup",
    "proxy-connect",
    "boundary-setuid",
    "boundary-unshare",
    "boundary-mount",
    "boundary-sysctl",
    "boundary-sudo",
    "output-exfil",
)


def joined(form):
    return "\n".join(text for text, mode in fixtures.fixture_files(form).values())


class LinuxFixtureGenerationTests(unittest.TestCase):
    def test_all_five_requested_forms_are_generated_with_unique_rooted_paths(self):
        self.assertEqual(fixtures.FORMS, ("build_rs", "proc_macro", "shell", "python", "npm_postinstall"))
        seen = set()
        for form in fixtures.FORMS:
            files = fixtures.fixture_files(form)
            self.assertTrue(files)
            for path, (text, mode) in files.items():
                self.assertTrue(path.startswith("/fixtures/" + form + "/"))
                self.assertNotIn(path, seen)
                seen.add(path)
                self.assertTrue(text.endswith("\n"))
                self.assertIn(mode, (0o444, 0o555))
        self.assertEqual(set(fixtures.all_sources()), seen)

    def test_every_form_attempts_network_output_and_boundary_disablement(self):
        for form in fixtures.FORMS:
            source = joined(form)
            with self.subTest(form=form):
                for name in HOSTILE_NAMES:
                    self.assertIn(name, source)
                self.assertIn("KDATT", source)
                self.assertIn("::error::", source)
                self.assertIn("ptrace_scope", source)

    def test_every_planned_attempt_is_present_in_its_form(self):
        for form in fixtures.FORMS:
            source = joined(form)
            for name, accepted in fixtures.fixture_rules(form):
                with self.subTest(form=form, name=name):
                    self.assertIn(name, source)

    def test_comment_markers_appear_only_in_the_proc_macro_attribute(self):
        marker = chr(35)
        for form in fixtures.FORMS:
            count = joined(form).count(marker)
            self.assertEqual(count, 1 if form == "proc_macro" else 0, form)
        self.assertIn(marker + "[proc_macro]", joined("proc_macro"))

    def test_python_fixture_is_valid_python_and_reuses_the_probe_helpers(self):
        source = fixtures.python_fixture_source()
        ast.parse(source)
        self.assertIn("def attempt(", source)
        self.assertIn("fx-python-", source)

    def test_rust_forms_use_only_the_standard_library_and_declared_extern_functions(self):
        for form in ("build_rs", "proc_macro"):
            source = joined(form)
            with self.subTest(form=form):
                self.assertIn('extern "C"', source)
                self.assertNotIn("extern crate libc", source)
                self.assertNotIn("cargo", source.lower())
        self.assertIn("fn main()", joined("build_rs"))
        self.assertIn("pub fn hostile(", joined("proc_macro"))
        self.assertIn("hostile::hostile!();", joined("proc_macro"))

    def test_rust_drivers_compile_with_the_supplied_toolchain_only(self):
        for form in ("build_rs", "proc_macro"):
            driver = fixtures.fixture_files(form)["/fixtures/" + form + "/run.sh"][0]
            self.assertIn('"$KD_RUSTC"', driver)
            self.assertIn("--edition 2021", driver)
            self.assertNotIn("curl", driver)
            self.assertNotIn("rustup", driver)
        self.assertIn("--crate-type proc-macro", joined("proc_macro"))

    def test_npm_form_emulates_the_lifecycle_runner_from_the_package_manifest(self):
        files = fixtures.fixture_files("npm_postinstall")
        manifest = json.loads(files["/fixtures/npm_postinstall/package.json"][0])
        self.assertEqual(manifest["scripts"]["postinstall"], "node install.js")
        driver = files["/fixtures/npm_postinstall/run.sh"][0]
        self.assertIn("npm_lifecycle_event=postinstall", driver)
        self.assertIn("scripts.postinstall", driver)

    def test_shell_form_uses_bash_network_paths_and_never_devnull(self):
        source = joined("shell")
        self.assertIn("/dev/tcp/", source)
        self.assertIn("/dev/udp/", source)
        self.assertNotIn("/dev/null", source)
        self.assertNotIn("unix-connect", source)

    def test_fixture_environment_has_no_runner_or_secret_names_and_rustc_only_for_rust(self):
        for form in fixtures.FORMS:
            rustc = "/toolchain/bin/rustc" if form in fixtures.NEEDS_RUSTC else None
            env = fixtures.fixture_env(form, NONCE, PORTS, "/ipc/docker.sock", rustc)
            with self.subTest(form=form):
                self.assertEqual(env["KD_NONCE"], NONCE)
                self.assertEqual(env["KD_TCP_PORT"], "1111")
                self.assertEqual(env["KD_FORM"], fixtures.slug(form))
                self.assertEqual("KD_RUSTC" in env, form in fixtures.NEEDS_RUSTC)
                for name in env:
                    self.assertFalse(name.startswith(("GITHUB_", "ACTIONS_", "RUNNER_")))
                    self.assertNotIn("SECRET", name)
                    self.assertNotIn("TOKEN", name)
        with self.assertRaises(ValueError):
            fixtures.fixture_env("build_rs", NONCE, PORTS, "/ipc/docker.sock", None)

    def test_slugs_are_dns_label_safe(self):
        for form in fixtures.FORMS:
            self.assertRegex(fixtures.slug(form), r"^[a-z0-9]+$")
        with self.assertRaises(ValueError):
            fixtures.slug("unknown")

    def test_commands_run_through_fixed_interpreters_with_the_nonce(self):
        self.assertEqual(
            fixtures.fixture_argv("shell", NONCE),
            ["/usr/bin/bash", "/fixtures/shell/run.sh"],
        )
        python = fixtures.fixture_argv("python", NONCE)
        self.assertEqual(python[:4], ["/usr/bin/python3", "-B", "/fixtures/python/fixture.py", "python"])
        self.assertEqual(json.loads(python[4]), {"nonce": NONCE})
        for form in ("build_rs", "proc_macro", "npm_postinstall"):
            self.assertEqual(fixtures.fixture_argv(form, NONCE), ["/usr/bin/bash", "/fixtures/" + form + "/run.sh"])

    def test_timeouts_cover_every_form_and_rust_forms_get_the_longest_budget(self):
        self.assertEqual(set(fixtures.RUN_TIMEOUT), set(fixtures.FORMS))
        self.assertEqual(fixtures.RUN_TIMEOUT["build_rs"], max(fixtures.RUN_TIMEOUT.values()))


class LinuxFixtureEvaluationTests(unittest.TestCase):
    def test_rules_require_denial_everywhere_and_contain_only_output(self):
        for form in fixtures.FORMS:
            rules = fixtures.fixture_rules(form)
            with self.subTest(form=form):
                for name, accepted in rules:
                    if name == "output-exfil":
                        self.assertEqual(accepted, channels.CONTAINED)
                    else:
                        self.assertEqual(accepted, channels.DENIED)
                self.assertEqual(("unix-connect" in [name for name, accepted in rules]), form != "shell")

    def test_judgement_accepts_complete_denied_output_and_refuses_partial_or_allowed(self):
        for form in fixtures.FORMS:
            rules = fixtures.fixture_rules(form)
            optional = fixtures.fixture_optional(form)
            good = ("".join("KDATT " + name + " " + accepted[0] + chr(10) for name, accepted in rules)).encode("ascii")
            with self.subTest(form=form):
                self.assertEqual(channels.judge_attempts(rules, good, optional), "ok")
                self.assertEqual(channels.judge_attempts(rules, good.replace(b"tcp-connect denied", b"tcp-connect allowed"), optional), "leak")
                self.assertEqual(channels.judge_attempts(rules, good.split(b"KDATT udp-send")[0], optional), "incomplete")
                self.assertEqual(channels.judge_attempts(rules, b"", optional), "incomplete")

    def test_optional_attempts_are_limited_to_tools_that_may_be_absent(self):
        for form in fixtures.FORMS:
            optional = fixtures.fixture_optional(form)
            self.assertTrue(set(optional) <= {"boundary-setuid", "boundary-unshare", "boundary-mount", "boundary-sudo"})
            self.assertIn("boundary-sudo", optional)
            self.assertNotIn("tcp-connect", optional)
            self.assertNotIn("output-exfil", optional)

    def test_control_markers_cover_network_proxy_and_unix_paths_where_the_form_has_them(self):
        for form in fixtures.FORMS:
            markers = fixtures.control_markers(form, NONCE)
            expected = ["https4", "udp", "dns_udp", "proxy"] + ([] if form == "shell" else ["unix"])
            with self.subTest(form=form):
                self.assertEqual([listener for listener, marker in markers], expected)
                for listener, marker in markers:
                    self.assertEqual(marker, "fx-" + fixtures.slug(form) + "-" + NONCE)

    def test_boundary_attempts_and_output_are_reported_as_uncontrolled_evidence(self):
        for form in fixtures.FORMS:
            names = fixtures.uncontrolled_attempts(form)
            with self.subTest(form=form):
                self.assertIn("boundary-setuid", names)
                self.assertIn("output-exfil", names)
                self.assertNotIn("tcp-connect", names)
                self.assertNotIn("proxy-connect", names)
                self.assertEqual(len(names) + len([1 for key in fixtures.CONTROLLED if not (form == "shell" and key == "unix-connect")]), len(fixtures.fixture_rules(form)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
