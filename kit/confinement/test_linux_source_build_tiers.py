import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, call, patch

if not sys.platform.startswith("linux"):
    raise unittest.SkipTest("the Linux source build suite runs only on Linux")

import gate_table
import linux_source_build


__all__ = ["WindowsSourceBindingTests", "LinuxBrowserTierTests"]


def _path_only_lock(count, prefix="member"):
    names = [prefix + "-" + str(index) for index in range(count)]
    text = "version = 4\n"
    for index, name in enumerate(names):
        text += '\n[[package]]\nname = "' + name + '"\nversion = "0.1.0"\n'
        if index == 0 and count > 1:
            text += "dependencies = [\n"
            for dependency in names[1:]:
                text += ' "' + dependency + '",\n'
            text += "]\n"
    return text


class WindowsSourceBindingTests(unittest.TestCase):
    SOURCE = "a" * 40
    BASE = "b" * 40
    CONTROL = "d" * 40
    FINGERPRINT = "c" * 64

    def _environment(self, prefix="WINDOWS_SOURCE"):
        return {
            "REQUESTED_SOURCE_SHA": self.SOURCE, "REQUESTED_BASE_SHA": self.BASE,
            "REQUESTED_BASE_BRANCH": "main", "REQUESTED_FINGERPRINT": self.FINGERPRINT,
            "CI_SHA": self.CONTROL,
            prefix + "_ALLOWED_SHA": self.SOURCE, prefix + "_ALLOWED_BASE_SHA": self.BASE,
            prefix + "_ALLOWED_BASE_BRANCH": "main",
            prefix + "_ALLOWED_FINGERPRINT": self.FINGERPRINT,
            prefix + "_ALLOWED_CONTROL_SHA": self.CONTROL,
            "SOURCE_REPOSITORY_ID": "7", "SOURCE_REPOSITORY_OWNER": "owner",
            "SOURCE_REPOSITORY_NAME": "source", "SOURCE_READER_INSTALLATION_ID": "8",
            "SOURCE_READER_CLIENT_ID": "client",
            prefix + "_ACCEPTED_NODE_LOCK_SHA256": "f" * 64,
            prefix + "_ACCEPTED_MANIFEST_SHA256": "1" * 64,
            prefix + "_ACCEPTED_NODE_PROVENANCE_JSON": "{}",
            prefix + "_ENVIRONMENT_NAME": "linux-source-read",
            "REQUESTED_ENVIRONMENT_NAME": "linux-source-read",
        }

    def _dispatch_environment(self, ref, mode):
        return {
            "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
            "CI_SHA": self.CONTROL, "GITHUB_SHA": self.CONTROL, "CI_REF": ref, "CI_MODE": mode,
        }

    def test_prefixes_are_the_closed_pair(self):
        self.assertEqual(linux_source_build.LINUX_SOURCE_PREFIX, "LINUX_SOURCE")
        self.assertEqual(linux_source_build.WINDOWS_SOURCE_PREFIX, "WINDOWS_SOURCE")
        self.assertEqual(linux_source_build.SOURCE_PREFIXES, ("LINUX_SOURCE", "WINDOWS_SOURCE"))
        self.assertEqual(
            linux_source_build.WINDOWS_TIER, ("windows-source-admission.yml", "Windows admission source "),
        )

    def test_windows_binding_reads_only_the_windows_names(self):
        with patch.object(linux_source_build, "_validate_provenance_binding") as provenance:
            identity = linux_source_build._source_inputs(self._environment(), prefix="WINDOWS_SOURCE")
            self.assertEqual(identity["source_sha"], self.SOURCE)
            self.assertEqual(identity["reviewed_diff_sha256"], self.FINGERPRINT)
            self.assertEqual(identity["repository_id"], "7")
            provenance.assert_called_once()
            self.assertEqual(provenance.call_args.args[2], "WINDOWS_SOURCE")
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build._source_inputs(self._environment("LINUX_SOURCE"), prefix="WINDOWS_SOURCE")
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build._source_inputs(self._environment("WINDOWS_SOURCE"))
            provenance.assert_called_once()
            linux_source_build._source_inputs(self._environment("LINUX_SOURCE"))
            self.assertEqual(provenance.call_count, 2)

    def test_every_windows_binding_name_is_required_and_checked(self):
        for suffix in (
            "_ALLOWED_SHA", "_ALLOWED_BASE_SHA", "_ALLOWED_BASE_BRANCH", "_ALLOWED_FINGERPRINT",
            "_ALLOWED_CONTROL_SHA", "_ACCEPTED_NODE_LOCK_SHA256", "_ACCEPTED_MANIFEST_SHA256",
            "_ACCEPTED_NODE_PROVENANCE_JSON", "_ENVIRONMENT_NAME",
        ):
            changes = ("missing", "empty") if suffix == "_ACCEPTED_NODE_PROVENANCE_JSON" else ("missing", "empty", "other")
            for change in changes:
                environment = self._environment()
                name = "WINDOWS_SOURCE" + suffix
                if change == "missing":
                    del environment[name]
                elif change == "empty":
                    environment[name] = ""
                else:
                    environment[name] = "x" * 3
                with self.subTest(name=name, change=change), patch.object(
                    linux_source_build, "_validate_provenance_binding"
                ) as provenance:
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                        linux_source_build._source_inputs(environment, prefix="WINDOWS_SOURCE")
                    provenance.assert_not_called()
        environment = self._environment()
        environment["WINDOWS_SOURCE_ENVIRONMENT_NAME"] = "source-read"
        environment["REQUESTED_ENVIRONMENT_NAME"] = "source-read"
        with patch.object(linux_source_build, "_validate_provenance_binding"):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build._source_inputs(environment, prefix="WINDOWS_SOURCE")

    def test_unknown_prefixes_are_refused_everywhere(self):
        for prefix in ("", "WINDOWS", "windows_source", "LINUX_SOURCE_", "MACOS_SOURCE", 5, b"LINUX_SOURCE"):
            with self.subTest(prefix=prefix):
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                    linux_source_build._source_inputs(self._environment("LINUX_SOURCE"), prefix=prefix)
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "lock"):
                    linux_source_build._validate_provenance_binding({}, {}, prefix)
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                    linux_source_build.validate_dispatch({}, "token", prefix)

    def test_a_linux_dispatch_refuses_a_stray_source_prefix_variable(self):
        environment = self._dispatch_environment("refs/heads/main", "synthetic")
        environment["KD_SOURCE_PREFIX"] = "WINDOWS_SOURCE"
        with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
            linux_source_build.validate_dispatch(environment, None, "LINUX_SOURCE")

    def test_the_prefix_comes_from_the_dispatch_environment_when_not_passed(self):
        with patch.object(linux_source_build, "_validate_provenance_binding") as provenance:
            environment = self._environment("WINDOWS_SOURCE")
            environment["KD_SOURCE_PREFIX"] = "WINDOWS_SOURCE"
            identity = linux_source_build._source_inputs(environment)
            self.assertEqual(identity["source_sha"], self.SOURCE)
            self.assertEqual(provenance.call_args.args[2], "WINDOWS_SOURCE")
            environment["KD_SOURCE_PREFIX"] = "LINUX_SOURCE"
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build._source_inputs(environment)
            for value in ("", "WINDOWS", "windows_source", "MACOS_SOURCE"):
                environment["KD_SOURCE_PREFIX"] = value
                with self.subTest(value=value):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                        linux_source_build._source_inputs(environment)

    def test_the_lock_provenance_check_reads_the_prefixed_accepted_values(self):
        environment = self._environment("WINDOWS_SOURCE")
        environment["KD_SOURCE_PREFIX"] = "WINDOWS_SOURCE"
        lock = b"{}"
        environment["WINDOWS_SOURCE_ACCEPTED_NODE_LOCK_SHA256"] = hashlib.sha256(lock).hexdigest()
        environment["WINDOWS_SOURCE_ACCEPTED_MANIFEST_SHA256"] = "2" * 64
        with patch.object(
            linux_source_build, "_validate_provenance_binding",
            return_value={"lock_sha256": hashlib.sha256(lock).hexdigest()},
        ), patch.object(linux_source_build, "_manifest_digest", return_value="2" * 64):
            self.assertEqual(
                linux_source_build._check_lock_provenance(lock, {}, environment, Path(".")),
                (hashlib.sha256(lock).hexdigest(), "2" * 64),
            )
            environment["WINDOWS_SOURCE_ACCEPTED_MANIFEST_SHA256"] = "3" * 64
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "lock"):
                linux_source_build._check_lock_provenance(lock, {}, environment, Path("."))

    def test_windows_provenance_text_comes_from_the_windows_variable(self):
        with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "lock"):
            linux_source_build._validate_provenance_binding(
                {}, {"LINUX_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON": "{}"}, "WINDOWS_SOURCE",
            )
        with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "lock"):
            linux_source_build._validate_provenance_binding(
                {}, {"WINDOWS_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON": "{}"},
            )

    def test_windows_source_dispatch_runs_only_on_untrusted_and_synthetic_only_on_main(self):
        order = []
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(
            linux_source_build, "_source_inputs", side_effect=lambda environ, prefix: order.append(prefix) or {}
        ), patch.object(
            linux_source_build, "_verify_environment", side_effect=lambda token: order.append("environment")
        ), patch.object(
            linux_source_build, "_require_no_duplicate",
            side_effect=lambda token, environ, workflow: order.append(workflow),
        ):
            env = self._dispatch_environment("refs/heads/untrusted", "source")
            self.assertEqual(linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE"), "source")
        self.assertEqual(order, ["WINDOWS_SOURCE", "environment", linux_source_build.WINDOWS_TIER])
        with patch.object(linux_source_build, "_reference_sha", side_effect=[self.CONTROL, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="identical"
        ), patch.object(
            linux_source_build, "_source_inputs", side_effect=AssertionError("no binding for a main source run")
        ):
            env = self._dispatch_environment("refs/heads/main", "source")
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE")
        with patch.object(linux_source_build, "_reference_sha", side_effect=[self.CONTROL, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="identical"
        ), patch.object(
            linux_source_build, "_source_inputs", side_effect=AssertionError("no binding in synthetic")
        ), patch.object(linux_source_build, "_verify_environment") as environment:
            env = self._dispatch_environment("refs/heads/main", "synthetic")
            self.assertEqual(linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE"), "synthetic")
            environment.assert_called_once_with("token")
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ):
            env = self._dispatch_environment("refs/heads/untrusted", "synthetic")
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE")

    def test_windows_dispatch_refuses_a_linux_tier_variable_and_a_stale_untrusted_branch(self):
        for tier in ("quick", "admission", "windows", ""):
            with self.subTest(tier=tier):
                env = dict(self._dispatch_environment("refs/heads/untrusted", "source"), KD_LINUX_TIER=tier)
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                    linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE")
        env = self._dispatch_environment("refs/heads/untrusted", "source")
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, "e" * 40]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "freshness"):
                linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE")
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="diverged"
        ):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "untrusted"):
                linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE")

    def test_windows_duplicate_check_uses_the_windows_workflow_and_title(self):
        calls = []

        def runs(title):
            def fake(path, token, method="GET", payload=None, expected=(200,)):
                calls.append(path)
                status = "queued" if path.endswith("status=queued") else "in_progress"
                return 200, {"total_count": 1, "workflow_runs": [{
                    "id": 9, "display_title": title + self.SOURCE, "status": status, "event": "workflow_dispatch",
                }]}
            return fake

        environment = {"GITHUB_RUN_ID": "5", "REQUESTED_SOURCE_SHA": self.SOURCE}
        windows = linux_source_build.WINDOWS_TIER
        with patch.object(linux_source_build, "_api_request", side_effect=runs("Windows admission source ")):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "duplicate"):
                linux_source_build._require_no_duplicate("token", environment, workflow=windows)
        self.assertTrue(calls[0].startswith(
            "/repos/" + linux_source_build.REPOSITORY + "/actions/workflows/windows-source-admission.yml/runs?"
        ))
        with patch.object(linux_source_build, "_api_request", side_effect=runs("Linux admission source ")):
            self.assertIsNone(linux_source_build._require_no_duplicate("token", environment, workflow=windows))
        for workflow in (("linux-source-admission.yml", "Linux admission source "), ("x", "y"), "windows", ()):
            with self.subTest(workflow=workflow):
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "duplicate"):
                    linux_source_build._require_no_duplicate("token", environment, workflow=workflow)

    def test_duplicate_check_retries_only_a_lagging_total_count_and_then_refuses(self):
        environment = {"GITHUB_RUN_ID": "5", "REQUESTED_SOURCE_SHA": self.SOURCE}
        windows = linux_source_build.WINDOWS_TIER
        title = "Windows admission source " + self.SOURCE

        def listing(totals, runs=()):
            calls = []

            def fake(path, token, method="GET", payload=None, expected=(200,)):
                calls.append(path)
                total = totals[min(len(calls) - 1, len(totals) - 1)]
                return 200, {"total_count": total, "workflow_runs": list(runs)}
            return fake, calls

        fake, calls = listing([1, 0])
        with patch.object(linux_source_build, "_api_request", side_effect=fake), patch.object(
            linux_source_build.time, "sleep"
        ) as sleep:
            self.assertIsNone(linux_source_build._require_no_duplicate("token", environment, workflow=windows))
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleep.call_args_list, [call(5)])
        fake, calls = listing([1])
        with patch.object(linux_source_build, "_api_request", side_effect=fake), patch.object(
            linux_source_build.time, "sleep"
        ) as sleep:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "duplicate"):
                linux_source_build._require_no_duplicate("token", environment, workflow=windows)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleep.call_args_list, [call(5), call(5)])
        active = {"id": 9, "display_title": title, "status": "queued", "event": "workflow_dispatch"}
        fake, calls = listing([5], [active])
        with patch.object(linux_source_build, "_api_request", side_effect=fake), patch.object(
            linux_source_build.time, "sleep"
        ) as sleep:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "duplicate"):
                linux_source_build._require_no_duplicate("token", environment, workflow=windows)
        self.assertEqual(len(calls), 1)
        sleep.assert_not_called()
        for payload in ({"total_count": "1", "workflow_runs": []}, {"total_count": 0}, [], {"total_count": 0, "workflow_runs": [1]}):
            with self.subTest(payload=payload):
                with patch.object(linux_source_build, "_api_request", return_value=(200, payload)) as request, patch.object(
                    linux_source_build.time, "sleep"
                ) as sleep:
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "duplicate"):
                        linux_source_build._require_no_duplicate("token", environment, workflow=windows)
                self.assertEqual(request.call_count, 1)
                sleep.assert_not_called()

    def test_windows_entry_points_print_fixed_lines(self):
        environment = {"GITHUB_TOKEN": "token"}
        for function, name, suffix in (
            (linux_source_build.windows_preflight, "windows-source-preflight", " cache-mode=none"),
        ):
            with patch.object(linux_source_build, "validate_dispatch", return_value="source") as dispatch:
                output = io.StringIO()
                with patch.object(linux_source_build.sys, "stdout", output):
                    self.assertEqual(function(environment), 0)
                self.assertEqual(output.getvalue(), name + "=verified mode=source" + suffix + "\n")
                self.assertEqual(dispatch.call_args.args[2], "WINDOWS_SOURCE")
                self.assertEqual(dispatch.call_args.kwargs, {"source_identity": True})
            for error, reason in (
                (linux_source_build.SourceBuildRefusal("binding"), "binding"), (ValueError("x"), "invalid"),
            ):
                with patch.object(linux_source_build, "validate_dispatch", side_effect=error):
                    output = io.StringIO()
                    with patch.object(linux_source_build.sys, "stdout", output):
                        self.assertEqual(function(environment), 1)
                    self.assertEqual(output.getvalue(), name + "=refused reason=" + reason + "\n")
        audit = types.SimpleNamespace(
            _default_api_factory=Mock(return_value="api"), _collect_caches=Mock(return_value=[]),
            cache_inventory_digest=Mock(return_value="e" * 64),
        )
        with tempfile.TemporaryDirectory() as temporary:
            sink = Path(temporary) / "output"
            environment = {"GITHUB_TOKEN": "token", "GITHUB_OUTPUT": str(sink)}
            with patch.object(linux_source_build, "_audit_modules", return_value=(audit, None, None)), patch.object(
                linux_source_build, "validate_dispatch", return_value="synthetic"
            ) as dispatch:
                output = io.StringIO()
                with patch.object(linux_source_build.sys, "stdout", output):
                    self.assertEqual(linux_source_build.windows_snapshot(environment), 0)
                self.assertEqual(output.getvalue(), "windows-source-settings=verified mode=synthetic cache=snapped\n")
                self.assertEqual(dispatch.call_args.args, (environment, "token", "WINDOWS_SOURCE"))
                self.assertEqual(dispatch.call_args.kwargs, {"source_identity": False})
            self.assertEqual(sink.read_text(encoding="ascii"), "cache_digest=" + "e" * 64 + "\n")
            with patch.object(linux_source_build, "_audit_modules", side_effect=ValueError("x")):
                output = io.StringIO()
                with patch.object(linux_source_build.sys, "stdout", output):
                    self.assertEqual(linux_source_build.windows_snapshot(environment), 1)
                self.assertEqual(output.getvalue(), "windows-source-settings=refused reason=invalid\n")

    def test_windows_commands_are_routed_by_the_dispatcher(self):
        for command, function in (
            ("windows-snapshot", "windows_snapshot"), ("windows-preflight", "windows_preflight"),
        ):
            with self.subTest(command=command), patch.object(linux_source_build, function, return_value=0) as target:
                self.assertEqual(linux_source_build.main([command]), 0)
                target.assert_called_once_with()
        self.assertEqual(linux_source_build.main(["windows-unknown"]), 2)

    def _settings_environment(self):
        environment = self._environment()
        for name in linux_source_build.SOURCE_IDENTITY_NAMES:
            del environment[name]
        return environment

    def test_the_held_names_are_the_source_identity_and_the_reader_credentials(self):
        self.assertEqual(linux_source_build.SOURCE_IDENTITY_NAMES, (
            "SOURCE_REPOSITORY_ID", "SOURCE_REPOSITORY_OWNER", "SOURCE_REPOSITORY_NAME",
            "SOURCE_READER_INSTALLATION_ID", "SOURCE_READER_CLIENT_ID",
        ))
        self.assertEqual(
            linux_source_build.SOURCE_HELD_NAMES,
            linux_source_build.SOURCE_IDENTITY_NAMES + ("SOURCE_READER_PRIVATE_KEY", "SOURCE_READER_TOKEN"),
        )

    def test_the_settings_binding_checks_the_request_without_any_source_identity(self):
        with patch.object(linux_source_build, "_validate_provenance_binding") as provenance:
            binding = linux_source_build._settings_binding(self._settings_environment(), "WINDOWS_SOURCE")
            provenance.assert_not_called()
        self.assertEqual(binding, {
            "source_sha": self.SOURCE, "base_sha": self.BASE, "base_branch": "main",
            "reviewed_diff_sha256": self.FINGERPRINT, "control_sha": self.CONTROL,
        })
        for name in ("repository_id", "owner", "name"):
            self.assertNotIn(name, binding)

    def test_the_settings_binding_refuses_any_held_source_name_even_when_empty(self):
        for name in linux_source_build.SOURCE_HELD_NAMES:
            for value in ("", "7", "owner"):
                environment = self._settings_environment()
                environment[name] = value
                with self.subTest(name=name, value=value), patch.object(
                    linux_source_build, "_validate_provenance_binding"
                ) as provenance:
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                        linux_source_build._settings_binding(environment, "WINDOWS_SOURCE")
                    provenance.assert_not_called()

    def test_the_settings_binding_is_windows_only(self):
        for prefix in ("LINUX_SOURCE", "", None, "windows_source", 5):
            with self.subTest(prefix=prefix):
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                    linux_source_build._settings_binding(self._settings_environment(), prefix)

    def test_the_settings_binding_still_checks_every_request_name(self):
        for suffix in (
            "_ALLOWED_SHA", "_ALLOWED_BASE_SHA", "_ALLOWED_BASE_BRANCH", "_ALLOWED_FINGERPRINT",
            "_ALLOWED_CONTROL_SHA", "_ACCEPTED_NODE_LOCK_SHA256", "_ACCEPTED_MANIFEST_SHA256",
            "_ACCEPTED_NODE_PROVENANCE_JSON", "_ENVIRONMENT_NAME",
        ):
            changes = ("missing", "empty") if suffix == "_ACCEPTED_NODE_PROVENANCE_JSON" else ("missing", "empty", "other")
            for change in changes:
                environment = self._settings_environment()
                name = "WINDOWS_SOURCE" + suffix
                if change == "missing":
                    del environment[name]
                elif change == "empty":
                    environment[name] = ""
                else:
                    environment[name] = "x" * 3
                with self.subTest(name=name, change=change):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                        linux_source_build._settings_binding(environment, "WINDOWS_SOURCE")
        for name, value in (
            ("REQUESTED_SOURCE_SHA", "e" * 40), ("REQUESTED_BASE_SHA", "e" * 40),
            ("REQUESTED_BASE_BRANCH", "develop"), ("REQUESTED_FINGERPRINT", "e" * 64),
            ("REQUESTED_ENVIRONMENT_NAME", "windows-source-exec"), ("CI_SHA", "e" * 40),
        ):
            environment = self._settings_environment()
            environment[name] = value
            with self.subTest(name=name):
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                    linux_source_build._settings_binding(environment, "WINDOWS_SOURCE")

    def test_the_fetch_job_binding_still_requires_the_full_source_identity(self):
        for name in linux_source_build.SOURCE_IDENTITY_NAMES:
            for change in ("missing", "empty"):
                environment = self._environment()
                if change == "missing":
                    del environment[name]
                else:
                    environment[name] = ""
                with self.subTest(name=name, change=change), patch.object(
                    linux_source_build, "_validate_provenance_binding"
                ) as provenance:
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                        linux_source_build._source_inputs(environment, prefix="WINDOWS_SOURCE")
                    provenance.assert_not_called()
        for name, value in (
            ("SOURCE_REPOSITORY_ID", "07"), ("SOURCE_READER_INSTALLATION_ID", "x"),
            ("SOURCE_REPOSITORY_OWNER", "-owner"), ("SOURCE_REPOSITORY_NAME", "a/b"),
        ):
            environment = self._environment()
            environment[name] = value
            with self.subTest(name=name), patch.object(linux_source_build, "_validate_provenance_binding"):
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                    linux_source_build._source_inputs(environment, prefix="WINDOWS_SOURCE")
        with patch.object(linux_source_build, "_validate_provenance_binding") as provenance:
            identity = linux_source_build._source_inputs(self._environment(), prefix="WINDOWS_SOURCE")
        self.assertEqual(
            (identity["repository_id"], identity["owner"], identity["name"]), ("7", "owner", "source"),
        )
        self.assertIs(provenance.call_args.args[0], identity)

    def test_a_windows_settings_source_dispatch_binds_the_request_but_not_the_source(self):
        order = []
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(
            linux_source_build, "_source_inputs", side_effect=AssertionError("no source identity in settings")
        ), patch.object(
            linux_source_build, "_settings_binding",
            side_effect=lambda environ, prefix: order.append(("settings", prefix)) or {},
        ), patch.object(
            linux_source_build, "_verify_environment", side_effect=lambda token: order.append("environment")
        ), patch.object(
            linux_source_build, "_require_no_duplicate",
            side_effect=lambda token, environ, workflow: order.append(workflow),
        ):
            env = self._dispatch_environment("refs/heads/untrusted", "source")
            self.assertEqual(
                linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE", source_identity=False),
                "source",
            )
        self.assertEqual(
            order, [("settings", "WINDOWS_SOURCE"), "environment", linux_source_build.WINDOWS_TIER],
        )

    def test_a_windows_settings_source_dispatch_runs_on_the_real_settings_names(self):
        environment = dict(self._settings_environment(), **self._dispatch_environment("refs/heads/untrusted", "source"))
        environment["KD_SOURCE_PREFIX"] = "WINDOWS_SOURCE"
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(
            linux_source_build, "_validate_provenance_binding", side_effect=AssertionError("no provenance in settings")
        ), patch.object(linux_source_build, "_verify_environment") as verified, patch.object(
            linux_source_build, "_require_no_duplicate"
        ) as duplicate:
            self.assertEqual(
                linux_source_build.validate_dispatch(
                    environment, "token", "WINDOWS_SOURCE", source_identity=False,
                ),
                "source",
            )
        verified.assert_called_once_with("token")
        duplicate.assert_called_once_with("token", environment, workflow=linux_source_build.WINDOWS_TIER)
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build.validate_dispatch(environment, "token", "WINDOWS_SOURCE")

    def test_a_settings_dispatch_refuses_held_names_before_any_network_read(self):
        for mode, ref in (("source", "refs/heads/untrusted"), ("synthetic", "refs/heads/main")):
            for name in linux_source_build.SOURCE_HELD_NAMES:
                environment = dict(self._dispatch_environment(ref, mode), **{name: ""})
                with self.subTest(mode=mode, name=name), patch.object(
                    linux_source_build, "_reference_sha", side_effect=AssertionError("network")
                ):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                        linux_source_build.validate_dispatch(
                            environment, "token", "WINDOWS_SOURCE", source_identity=False,
                        )

    def test_only_a_windows_dispatch_may_skip_the_source_identity_and_only_by_a_boolean(self):
        environment = self._dispatch_environment("refs/heads/main", "synthetic")
        with patch.object(linux_source_build, "_reference_sha", side_effect=AssertionError("network")):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                linux_source_build.validate_dispatch(environment, "token", "LINUX_SOURCE", source_identity=False)
            for value in (None, 0, 1, "false", "", []):
                with self.subTest(value=value):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                        linux_source_build.validate_dispatch(
                            environment, "token", "WINDOWS_SOURCE", source_identity=value,
                        )

    def test_gate_commands_render_the_shared_table_including_the_feature_gates(self):
        commands = linux_source_build._gate_commands(Path("/work"), "/rust", "/node")
        self.assertEqual(
            commands,
            gate_table.render(
                gate_table.gate_templates(False), "/work", "/rust/bin/cargo", "/node/node", "/node/npm",
            ),
        )
        by_name = dict(commands)
        feature = ("--features", "dev-uat-policy-import")
        for name in ("api_feature_clippy", "api_feature_tests"):
            with self.subTest(gate=name):
                argv = by_name[name]
                self.assertEqual(argv[argv.index("--features"):argv.index("--features") + 2], feature)
                self.assertIn("/work/crates/host/api/Cargo.toml", argv)
        self.assertEqual(linux_source_build.GATES, gate_table.GATES)
        self.assertEqual(linux_source_build.RUNTIME_GATE_NAMES, gate_table.RUNTIME_GATE_NAMES)
        self.assertEqual(linux_source_build.RUNTIME_ROOT_FILES, gate_table.RUNTIME_ROOT_FILES)
        with patch.object(linux_source_build.gate_table, "render", side_effect=gate_table.GateTableRefusal("tool")):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "gate"):
                linux_source_build._gate_commands(Path("/work"), "/rust", "/node")


def _browser_zip(path, entries):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            archive.writestr(info, data)


class LinuxBrowserTierTests(unittest.TestCase):
    def test_the_pinned_chromium_matches_the_playwright_release_and_is_hash_verified(self):
        subject = linux_source_build
        self.assertEqual(subject.PLAYWRIGHT_VERSION, "1.64.1")
        self.assertEqual(subject.BROWSER_REVISION, "1248")
        self.assertEqual(subject.BROWSER_VERSION, "156.0.8078.4")
        self.assertEqual(subject.BROWSER_DIRECTORY, "chromium_headless_shell-1248")
        self.assertEqual(
            subject.BROWSER_ARCHIVE_URL,
            "https://storage.googleapis.com/chrome-for-testing-public/156.0.8078.4/linux64/"
            "chrome-headless-shell-linux64.zip",
        )
        self.assertRegex(subject.BROWSER_ARCHIVE_SHA256, r"[a-f0-9]{64}\Z")
        self.assertEqual(
            subject.BROWSER_ARCHIVE_SHA256, "c3e50596aef52c58f8fda3c6b3411c33d34c88b177b3ed1c2243359fd3b8ba20",
        )
        self.assertEqual(subject.BROWSER_PACKAGE_DIRECTORY, "chrome-headless-shell-linux64")
        self.assertEqual(subject.BROWSER_EXECUTABLE, "chrome-headless-shell")
        self.assertEqual(subject.BROWSER_MARKER, "INSTALLATION_COMPLETE")

    def test_the_system_packages_are_pinned_by_name_sorted_and_unique(self):
        packages = linux_source_build.BROWSER_APT_PACKAGES
        self.assertEqual(list(packages), sorted(set(packages)))
        for name in packages:
            self.assertRegex(name, r"[a-z0-9][a-z0-9.+-]{1,60}\Z")
        for required in ("libnss3", "libnspr4", "libgbm1", "libasound2t64", "libxkbcommon0"):
            self.assertIn(required, packages)
        for absent in ("xvfb", "libgtk-3-0t64", "wget", "xdg-utils"):
            self.assertNotIn(absent, packages)

    def test_system_packages_install_in_the_trusted_phase_with_a_clean_environment(self):
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return types.SimpleNamespace(returncode=0)

        with patch.object(linux_source_build.subprocess, "run", side_effect=run):
            linux_source_build._install_browser_packages()
        self.assertEqual(len(calls), 2)
        update, install = calls
        self.assertEqual(update[0][-1], "update")
        self.assertTrue(update[1]["check"])
        self.assertTrue(install[1]["check"])
        self.assertEqual(install[0][:2], ["/usr/bin/sudo", "-n"])
        self.assertIn("DEBIAN_FRONTEND=noninteractive", install[0])
        separator = install[0].index("--")
        self.assertEqual(tuple(install[0][separator + 1:]), linux_source_build.BROWSER_APT_PACKAGES)
        self.assertIn("--no-install-recommends", install[0][:separator])
        for argv, kwargs in calls:
            self.assertEqual(set(kwargs["env"]), {"PATH", "LANG", "LC_ALL"})
            self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], linux_source_build.BROWSER_APT_TIMEOUT_SECONDS)
            self.assertNotIn("http", " ".join(argv))

    def test_a_failed_package_index_refresh_or_a_failed_install_refuses(self):
        outcomes = [subprocess.CalledProcessError(100, "apt"), types.SimpleNamespace(returncode=0)]
        with patch.object(linux_source_build.subprocess, "run", side_effect=outcomes) as run:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "toolchain"):
                linux_source_build._install_browser_packages()
        self.assertEqual(run.call_count, 1)
        outcomes = [types.SimpleNamespace(returncode=0), subprocess.CalledProcessError(100, "apt")]
        with patch.object(linux_source_build.subprocess, "run", side_effect=outcomes):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "toolchain"):
                linux_source_build._install_browser_packages()
        with patch.object(linux_source_build.subprocess, "run", side_effect=OSError("missing")):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "toolchain"):
                linux_source_build._install_browser_packages()

    def test_the_archive_extracts_regular_files_only_under_the_pinned_directory(self):
        package = linux_source_build.BROWSER_PACKAGE_DIRECTORY
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "browser.zip"
            _browser_zip(archive, (
                (package + "/chrome-headless-shell", b"binary", 0o100755),
                (package + "/locales/en-US.pak", b"data", 0o100600),
                (package + "/empty/", b"", 0o40755),
            ))
            root = linux_source_build._extract_browser_archive(str(archive), str(Path(temporary) / "out"))
            executable = root / package / "chrome-headless-shell"
            self.assertEqual(executable.read_bytes(), b"binary")
            self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((root / package / "locales" / "en-US.pak").stat().st_mode), 0o644)
            self.assertTrue((root / package / "empty").is_dir())

    def test_the_archive_refuses_links_escapes_foreign_roots_missing_binary_and_oversize(self):
        package = linux_source_build.BROWSER_PACKAGE_DIRECTORY
        good = (package + "/chrome-headless-shell", b"binary", 0o100755)
        cases = {
            "symlink": (good, (package + "/link", b"chrome-headless-shell", 0o120777)),
            "escape": (good, (package + "/../escape", b"x", 0o100644)),
            "absolute": (good, ("/" + package + "/absolute", b"x", 0o100644)),
            "foreign_root": (good, ("other/file", b"x", 0o100644)),
            "device": (good, (package + "/node", b"", 0o20666)),
            "missing_binary": ((package + "/locales/en-US.pak", b"data", 0o100644),),
            "not_executable": ((package + "/chrome-headless-shell", b"binary", 0o100644),),
        }
        for label, entries in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                archive = Path(temporary) / "browser.zip"
                _browser_zip(archive, entries)
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "toolchain"):
                    linux_source_build._extract_browser_archive(str(archive), str(Path(temporary) / "out"))
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "browser.zip"
            _browser_zip(archive, (good, (package + "/second", b"two", 0o100644)))
            for name, value in (("BROWSER_UNPACKED_MAX_BYTES", 8), ("BROWSER_MAX_MEMBERS", 1)):
                with self.subTest(limit=name), patch.object(linux_source_build, name, value):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "toolchain"):
                        linux_source_build._extract_browser_archive(str(archive), str(Path(temporary) / name))
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "browser.zip"
            archive.write_bytes(b"not a zip")
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "toolchain"):
                linux_source_build._extract_browser_archive(str(archive), str(Path(temporary) / "out"))

    def test_preparation_downloads_the_pin_extracts_read_only_inputs_and_marks_the_install(self):
        package = linux_source_build.BROWSER_PACKAGE_DIRECTORY
        order = []

        def download(url, expected, destination, maximum):
            order.append("download")
            self.assertEqual(url, linux_source_build.BROWSER_ARCHIVE_URL)
            self.assertEqual(expected, linux_source_build.BROWSER_ARCHIVE_SHA256)
            self.assertEqual(maximum, linux_source_build.BROWSER_ARCHIVE_MAX_BYTES)
            _browser_zip(destination, ((package + "/chrome-headless-shell", b"binary", 0o100755),))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                linux_source_build, "_install_browser_packages", side_effect=lambda: order.append("packages")
            ), patch.object(linux_source_build, "_download", side_effect=download):
                browsers = linux_source_build._prepare_browser(root)
            self.assertEqual(order, ["packages", "download"])
            self.assertEqual(browsers, root / "browsers")
            directory = browsers / linux_source_build.BROWSER_DIRECTORY
            self.assertTrue((directory / package / "chrome-headless-shell").is_file())
            self.assertEqual((directory / "INSTALLATION_COMPLETE").read_bytes(), b"")
            self.assertFalse((root / "chrome-headless-shell-linux64.zip").exists())

    def test_the_toolchain_step_provisions_the_browser_only_when_the_tier_flag_is_set(self):
        source = Path(linux_source_build.__file__).read_text(encoding="utf-8")
        body = source[source.index("def prepare_toolchains"):source.index("def _run(")]
        self.assertIn('env.get(BROWSER_FLAG_ENV) == "1"', body)
        self.assertLess(body.index("_prepare_browser(root)"), body.index("os.chmod(root, 0o755)"))
        self.assertIn('"browser_root=" + str(browser_root)', body)

    def test_the_installed_browser_check_accepts_only_the_trusted_layout(self):
        with tempfile.TemporaryDirectory() as temporary:
            toolchains = Path(temporary) / "toolchains"
            browsers = toolchains / "browsers"
            directory = browsers / linux_source_build.BROWSER_DIRECTORY
            executable = directory / linux_source_build.BROWSER_PACKAGE_DIRECTORY / "chrome-headless-shell"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"binary")
            executable.chmod(0o755)
            with patch.object(linux_source_build, "TOOLCHAIN_ROOT", toolchains):
                self.assertFalse(linux_source_build._browser_installed(str(browsers)))
                (directory / "INSTALLATION_COMPLETE").write_bytes(b"")
                self.assertTrue(linux_source_build._browser_installed(str(browsers)))
                self.assertFalse(linux_source_build._browser_installed(str(Path(temporary) / "elsewhere")))
                self.assertFalse(linux_source_build._browser_installed(""))
                executable.chmod(0o644)
                self.assertFalse(linux_source_build._browser_installed(str(browsers)))
                executable.chmod(0o755)
                moved = executable.with_name("real")
                executable.rename(moved)
                executable.symlink_to(moved)
                self.assertFalse(linux_source_build._browser_installed(str(browsers)))

    def test_gate_commands_add_the_browser_gate_last_and_only_when_asked(self):
        plain = linux_source_build._gate_commands(Path("/work"), "/rust", "/node")
        self.assertEqual(tuple(name for name, argv in plain), linux_source_build.GATES)
        browser = linux_source_build._gate_commands(Path("/work"), "/rust", "/node", True)
        self.assertEqual(
            tuple(name for name, argv in browser), linux_source_build.GATES + linux_source_build.BROWSER_GATE_NAMES,
        )
        self.assertEqual(dict(browser)["ui_kit_browser"], (
            "/node/node", "/node/npm", "--offline", "run", "test:browser",
            "--workspace=packages/kernel-ui-kit", "--ignore-scripts",
        ))

    def _run_with_browser(self, temporary, browser_root, installed=True, kit=True):
        root = Path(temporary)
        worker = root / "source"
        worker.mkdir()
        (worker / "Cargo.lock").write_text(_path_only_lock(4), encoding="ascii")

        def commands(project, rust_root, node_bin, browser=False):
            names = linux_source_build.GATES + (linux_source_build.BROWSER_GATE_NAMES if browser else ())
            return tuple((name, ("/usr/bin/true",)) for name in names)

        environment = {
            "RUNNER_TEMP": temporary, "WORKER_PATH": str(worker),
            "CARGO_HOME": str(worker / ".kd-cargo-home"), "RUST_ROOT": "/rust", "NODE_BIN": "/node",
            "REQUESTED_SOURCE_SHA": "a" * 40,
        }
        if browser_root is not None:
            environment["BROWSER_ROOT"] = browser_root
        with patch.object(
            linux_source_build.rust_license_gate, "require_lock_admission",
            wraps=linux_source_build.rust_license_gate.require_lock_admission,
        ), patch.object(linux_source_build, "_job_elapsed_seconds", return_value=0.0), patch.object(
            linux_source_build, "_project_gate_directories",
        ), patch.object(
            linux_source_build, "_gate_commands", side_effect=commands,
        ), patch.object(
            linux_source_build, "_runtime_workspace_present", return_value=False,
        ), patch.object(
            linux_source_build, "_browser_installed", return_value=installed,
        ), patch.object(
            linux_source_build, "_ui_kit_workspace_present", return_value=kit,
        ), patch.object(
            linux_source_build.linux_session, "run_host",
            return_value=types.SimpleNamespace(exit_code=0, timed_out=False, stdout=b"", stderr=b""),
        ) as session, patch.object(linux_source_build.sys, "stdout", io.StringIO()):
            code = linux_source_build.run_project_gates(environment)
        return code, session, root / "kd-records"

    def test_the_browser_gate_alone_gets_loopback_the_browser_path_and_no_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, session, records = self._run_with_browser(temporary, "/tmp/kd-toolchains/browsers")
            self.assertEqual(code, 0)
            self.assertEqual(session.call_count, 16)
            for position, invocation in enumerate(session.call_args_list):
                environment = invocation.args[3]
                if position == 15:
                    self.assertEqual(environment["PLAYWRIGHT_BROWSERS_PATH"], "/tmp/kd-toolchains/browsers")
                    self.assertEqual(environment["PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD"], "1")
                    self.assertIs(invocation.kwargs["loopback"], True)
                    self.assertEqual(invocation.kwargs["limits"], "project")
                    self.assertEqual(invocation.kwargs["timeout"], 1800)
                else:
                    self.assertFalse([key for key in environment if key.startswith("PLAYWRIGHT")])
                    self.assertNotIn("loopback", invocation.kwargs)
                self.assertLessEqual(set(environment), linux_source_build.linux_session.PROJECT_ENV_NAMES)
            receipt = json.loads((records / "gates.json").read_text(encoding="ascii"))
            self.assertEqual(receipt["selected_gates"][-1], "ui_kit_browser")
            self.assertEqual(receipt["gate_count"], 16)

    def test_without_a_provisioned_browser_no_browser_gate_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, session, records = self._run_with_browser(temporary, None, kit=False)
            self.assertEqual(code, 0)
            self.assertEqual(session.call_count, 15)
            for invocation in session.call_args_list:
                self.assertNotIn("loopback", invocation.kwargs)
                self.assertFalse([key for key in invocation.args[3] if key.startswith("PLAYWRIGHT")])
            receipt = json.loads((records / "gates.json").read_text(encoding="ascii"))
            self.assertEqual(receipt["selected_gates"], list(linux_source_build.GATES))

    def test_a_core_tree_without_the_ui_kit_runs_no_browser_gate_even_with_a_browser_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, session, records = self._run_with_browser(temporary, "/tmp/kd-toolchains/browsers", kit=False)
            self.assertEqual(code, 0)
            self.assertEqual(session.call_count, 15)
            for invocation in session.call_args_list:
                self.assertNotIn("loopback", invocation.kwargs)
                self.assertFalse([key for key in invocation.args[3] if key.startswith("PLAYWRIGHT")])
            receipt = json.loads((records / "gates.json").read_text(encoding="ascii"))
            self.assertEqual(receipt["selected_gates"], list(linux_source_build.GATES))
            self.assertEqual(receipt["gate_count"], 15)

    def test_the_ui_kit_workspace_is_present_only_with_its_regular_package_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            worker = Path(temporary) / "worker"
            worker.mkdir()
            self.assertFalse(linux_source_build._ui_kit_workspace_present(worker))
            (worker / "packages").mkdir()
            self.assertFalse(linux_source_build._ui_kit_workspace_present(worker))
            (worker / "packages" / "kernel-ui-kit").mkdir()
            self.assertFalse(linux_source_build._ui_kit_workspace_present(worker))
            manifest = worker / "packages" / "kernel-ui-kit" / "package.json"
            manifest.write_bytes(b"{}")
            self.assertTrue(linux_source_build._ui_kit_workspace_present(worker))
            manifest.unlink()
            manifest.mkdir()
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "gate"):
                linux_source_build._ui_kit_workspace_present(worker)
            manifest.rmdir()
            outside = Path(temporary) / "outside.json"
            outside.write_bytes(b"{}")
            manifest.symlink_to(outside)
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "gate"):
                linux_source_build._ui_kit_workspace_present(worker)

    def test_an_untrusted_browser_root_refuses_before_any_gate_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "gate"):
                self._run_with_browser(temporary, "/tmp/other", installed=False)
            self.assertFalse((Path(temporary) / "kd-records" / "gates.json").exists())

    def test_a_core_tree_with_the_ui_kit_but_no_browser_root_refuses_before_any_gate_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "gate"):
                self._run_with_browser(temporary, None, kit=True)
            self.assertFalse((Path(temporary) / "kd-records" / "gates.json").exists())

    def test_a_failed_browser_gate_is_named_in_the_refusal_line(self):
        self.assertEqual(
            linux_source_build._gate_refusal_line(15, 1, "ui_kit_browser", "exit"),
            "linux-project-gates=refused completed=15 failed=1 gate=ui_kit_browser cause=exit\n",
        )

    def test_the_verified_count_accepts_all_four_gate_sets_and_reports_the_shared_contract_count(self):
        names = {
            "base": linux_source_build.GATES,
            "runtime": linux_source_build.GATES + linux_source_build.RUNTIME_GATE_NAMES,
        }
        browser = linux_source_build.BROWSER_GATE_NAMES
        cases = (
            (names["base"], 15), (names["runtime"], 18),
            (names["base"] + browser, 15), (names["runtime"] + browser, 18),
            (browser + names["base"], 0), (names["base"][:-1], 0), (names["base"] + names["runtime"], 0),
        )
        for selected, expected in cases:
            with self.subTest(selected=len(selected), expected=expected), tempfile.TemporaryDirectory() as temporary:
                records = Path(temporary) / "kd-records"
                records.mkdir()
                gates = {
                    "schema_version": 1, "selected_gates": list(selected), "completed_gates": list(selected),
                    "gates": {name: "passed" for name in selected}, "gate_count": len(selected), "failed": 0,
                }
                receipt = {
                    "schema_version": 1, "status": "confirmed", "control_sha": "a" * 40,
                    "run_id": "7", "run_attempt": "1", "installation_id": "19", "rejected_after_revoke": True,
                }
                (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
                (records / "revocation.json").write_text(json.dumps(receipt), encoding="ascii")
                environment = {
                    "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1",
                    "SOURCE_READER_INSTALLATION_ID": "19",
                    "LINUX_API_FEATURE_GATE_NAMES": ",".join(linux_source_build.API_FEATURE_GATE_NAMES),
                }
                self.assertEqual(linux_source_build._verified_gate_count(records, environment), expected)

    def test_the_admission_and_quick_workflows_provision_and_pass_the_browser(self):
        root = Path(__file__).resolve().parents[2] / ".github" / "workflows"
        admission = (root / "linux-source-admission.yml").read_text(encoding="utf-8")
        quick = (root / "core-linux-quick-return.yml").read_text(encoding="utf-8")
        self.assertEqual(admission.count('KD_BROWSER_TIER: "1"'), 2)
        self.assertEqual(admission.count("BROWSER_ROOT: ${{ steps."), 2)
        self.assertEqual(admission.count("REQUESTED_SOURCE_SHA,BROWSER_ROOT python3"), 2)
        self.assertIn("BROWSER_ROOT: ${{ steps.toolchains.outputs.browser_root }}", admission)
        self.assertIn("BROWSER_ROOT: ${{ steps.verifier-toolchain.outputs.browser_root }}", admission)
        self.assertEqual(quick.count('KD_BROWSER_TIER: "1"'), 1)
        self.assertEqual(quick.count("BROWSER_ROOT: ${{ steps.toolchains.outputs.browser_root }}"), 1)
        self.assertEqual(quick.count("REQUESTED_SOURCE_SHA,BROWSER_ROOT python3"), 1)
        self.assertNotIn("PLAYWRIGHT", quick)
        quick_block = quick[quick.index("      - name: Record image and fetch pinned Rust and Node toolchains"):].split("\n      - name:", 1)[0]
        self.assertIn('KD_BROWSER_TIER: "1"', quick_block)
        encrypt = quick[quick.index("      - name: Encrypt bounded quick return"):].split("\n      - name:", 1)[0]
        self.assertIn("WORKER_PATH: ${{ steps.project-deps.outputs.worker_path }}", encrypt)
        self.assertIn("ImageVersion,WORKER_PATH python3", encrypt)
        upload = quick[quick.index("      - name: Upload the single encrypted member"):].split("\n      - name:", 1)[0]
        self.assertIn("path: ${{ runner.temp }}/kd-quick-upload/\n", upload)
        for step in ("Record image and fetch pinned Rust and Node toolchains",
                     "Record verifier image and fetch pinned toolchains"):
            block = admission[admission.index("      - name: " + step):].split("\n      - name:", 1)[0]
            self.assertIn('KD_BROWSER_TIER: "1"', block)

    def test_the_session_environment_allows_exactly_the_two_browser_variables(self):
        allowed = linux_source_build.linux_session.PROJECT_ENV_NAMES
        self.assertIn("PLAYWRIGHT_BROWSERS_PATH", allowed)
        self.assertIn("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", allowed)
        self.assertEqual(sorted(name for name in allowed if "PLAYWRIGHT" in name), [
            "PLAYWRIGHT_BROWSERS_PATH", "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD",
        ])


if __name__ == "__main__":
    unittest.main(verbosity=2)
