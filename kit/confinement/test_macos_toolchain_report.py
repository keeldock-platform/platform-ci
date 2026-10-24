import contextlib
import io
import os
import sys
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock

import macos_capability
import macos_toolchain_report as report


def metadata(uid=0, gid=0, mode=0o755, kind=stat.S_IFREG):
    return types.SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=kind | mode)


DEVELOPER = Path("/Fixture/Xcode.app/Contents/Developer")
FIXTURE_RESOLVED = {
    "python": "/Fixture/python3",
    "clang": "/Fixture/clang",
    "sdk": "/Fixture/sdk",
    "linker": "/Fixture/ld",
    "developer_directory": DEVELOPER.as_posix(),
}


@contextlib.contextmanager
def synthetic_host(euid=502, python_ok=True, developer=DEVELOPER, outcome=("refuse", None, False)):
    def fake_path_stage(name, raw, emit, **kwargs):
        if name == "python_path" and not python_ok:
            return (name, report.REFUSE, "fixture"), None
        return (name, report.PASS, None), Path(FIXTURE_RESOLVED["python"] if name == "python_path" else "/Fixture/" + name)

    def fake_file_stage(name, raw, directory, kind, emit):
        return (name, report.PASS, None), Path(FIXTURE_RESOLVED["sdk" if kind == "sdk" else kind])

    query = types.SimpleNamespace(returncode=0, stdout=b"/Fixture/tool\n", stderr=b"")
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(os, "geteuid", return_value=euid))
        stack.enter_context(mock.patch.object(sys, "platform", "darwin"))
        stack.enter_context(mock.patch.object(report, "run_query", return_value=query))
        stack.enter_context(mock.patch.object(report, "path_stage", side_effect=fake_path_stage))
        stack.enter_context(mock.patch.object(report, "toolchain_file_stage", side_effect=fake_file_stage))
        stack.enter_context(mock.patch.object(report, "developer_directory_for", return_value=developer))
        stack.enter_context(mock.patch.object(report, "print_walk"))
        stack.enter_context(mock.patch.object(report, "unconditional_diagnostics"))
        stack.enter_context(mock.patch.object(macos_capability, "_trusted_path_metadata", side_effect=lambda p, directory=False: p))
        stack.enter_context(mock.patch.object(report, "real_resolver_outcome", return_value=outcome))
        yield


class ComponentVerdictTests(unittest.TestCase):
    def test_root_owned_unwritable_component_passes(self):
        self.assertEqual(report.component_verdict(metadata(kind=stat.S_IFDIR)), ())

    def test_each_condition_is_reported_on_its_own(self):
        self.assertEqual(report.component_verdict(metadata(uid=501)), ("owner_not_root",))
        self.assertEqual(report.component_verdict(metadata(mode=0o757)), ("world_writable",))
        self.assertEqual(
            report.component_verdict(metadata(gid=20, mode=0o775)), ("group_writable_primary_gid",)
        )

    def test_group_writable_with_another_group_passes(self):
        self.assertEqual(report.component_verdict(metadata(gid=80, mode=0o775)), ())
        self.assertEqual(report.component_verdict(metadata(gid=20, mode=0o755)), ())

    def test_conditions_combine_in_check_order(self):
        failed = report.component_verdict(metadata(uid=501, gid=20, mode=0o777))
        self.assertEqual(failed, ("owner_not_root", "world_writable", "group_writable_primary_gid"))

    def test_verdict_agrees_with_the_real_predicate(self):
        for uid in (0, 501):
            for gid in (0, 20, 80):
                for mode in (0o755, 0o775, 0o757, 0o777, 0o700):
                    meta = metadata(uid=uid, gid=gid, mode=mode, kind=stat.S_IFDIR)
                    with self.subTest(uid=uid, gid=gid, mode=oct(mode)):
                        self.assertEqual(
                            bool(report.component_verdict(meta)),
                            report.real_refuses_metadata(meta, True),
                        )


class LeafVerdictTests(unittest.TestCase):
    def test_executable_regular_file_passes(self):
        self.assertEqual(report.leaf_verdict(metadata(), False), ())

    def test_file_leaf_failures(self):
        self.assertEqual(report.leaf_verdict(metadata(mode=0o644), False), ("not_executable",))
        self.assertEqual(report.leaf_verdict(metadata(mode=0o4755), False), ("setid_bit_set",))
        self.assertEqual(report.leaf_verdict(metadata(mode=0o2755), False), ("setid_bit_set",))
        self.assertEqual(
            report.leaf_verdict(metadata(kind=stat.S_IFDIR), False), ("not_a_regular_file",)
        )

    def test_directory_leaf_requirement(self):
        self.assertEqual(report.leaf_verdict(metadata(kind=stat.S_IFDIR), True), ())
        self.assertEqual(report.leaf_verdict(metadata(), True), ("not_a_directory",))


class WalkTests(unittest.TestCase):
    def test_walk_lists_every_ancestor_from_root_down(self):
        with tempfile.TemporaryDirectory() as directory:
            leaf = Path(directory) / "a" / "b"
            leaf.mkdir(parents=True)
            rows = report.walk_components(leaf)
            self.assertEqual(rows[0][0], Path("/"))
            self.assertEqual(rows[-1][0], leaf)
            self.assertEqual(len(rows), len(leaf.parents) + 1)
            self.assertTrue(all(row[1] is not None and row[2] is None for row in rows))

    def test_missing_component_reports_error_type_only(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = report.walk_components(Path(directory) / "missing")
            self.assertEqual(rows[-1][1], None)
            self.assertEqual(rows[-1][2], "FileNotFoundError")


class ToolOutputVerdictTests(unittest.TestCase):
    def verdict(self, returncode=0, stdout=b"/usr/bin/clang\n", stderr=b""):
        return report.tool_output_verdict(returncode, stdout, stderr)

    def test_single_clean_line_is_accepted(self):
        self.assertEqual(self.verdict(), (True, None))

    def test_each_rejection_is_named(self):
        cases = (
            (dict(returncode=1), "returncode_nonzero"),
            (dict(stderr=b"warning\n"), "stderr_not_empty"),
            (dict(stdout=b"/usr/bin/clang"), "no_trailing_newline"),
            (dict(stdout=b"/a\n/b\n"), "not_exactly_one_newline"),
            (dict(stdout=b"/" + b"a" * 4096 + b"\n"), "over_max_tool_path_bytes"),
            (dict(stdout="/café\n".encode("utf-8")), "not_ascii"),
            (dict(stdout=b" /usr/bin/clang\n"), "empty_or_whitespace_padded"),
            (dict(stdout=b"/usr/bin/clang \n"), "empty_or_whitespace_padded"),
            (dict(stdout=b"\n"), "empty_or_whitespace_padded"),
        )
        for changes, reason in cases:
            with self.subTest(reason=reason, changes=sorted(changes)):
                self.assertEqual(self.verdict(**changes), (False, reason))

    def test_nonzero_return_code_wins_over_later_conditions(self):
        self.assertEqual(self.verdict(returncode=2, stderr=b"x", stdout=b""), (False, "returncode_nonzero"))


class ShapeTests(unittest.TestCase):
    XCODE = Path("/Applications/Fixture.app/Contents/Developer")
    CLT = Path("/Library/Developer/CommandLineTools")

    def test_xcode_shapes(self):
        base = self.XCODE.as_posix()
        clang = base + "/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
        sdk = base + "/Platforms/MacOSX.platform/Developer/SDKs/MacOSX15.2.sdk"
        self.assertIsNone(report.relative_shape_verdict(clang, self.XCODE, "clang"))
        self.assertIsNone(report.relative_shape_verdict(sdk, self.XCODE, "sdk"))
        self.assertEqual(
            report.relative_shape_verdict(base + "/usr/bin/clang", self.XCODE, "clang"),
            "unexpected_relative_shape",
        )
        self.assertEqual(
            report.relative_shape_verdict("/usr/bin/clang", self.XCODE, "clang"),
            "outside_developer_directory",
        )
        self.assertEqual(
            report.relative_shape_verdict(base + "/Platforms/MacOSX.platform/Developer/SDKs/Other.sdk", self.XCODE, "sdk"),
            "unexpected_relative_shape",
        )

    def test_command_line_tools_shapes(self):
        base = self.CLT.as_posix()
        self.assertIsNone(report.relative_shape_verdict(base + "/usr/bin/ld", self.CLT, "linker"))
        self.assertIsNone(report.relative_shape_verdict(base + "/SDKs/MacOSX.sdk", self.CLT, "sdk"))
        self.assertEqual(
            report.relative_shape_verdict(base + "/SDKs/MacOSX.sdk/extra", self.CLT, "sdk"),
            "unexpected_relative_shape",
        )

    def test_shape_agrees_with_the_real_resolver(self):
        cases = []
        for directory in (self.XCODE, self.CLT):
            base = directory.as_posix()
            xcode = directory is self.XCODE
            toolchain = "/Toolchains/XcodeDefault.xctoolchain/usr/bin/" if xcode else "/usr/bin/"
            sdks = "/Platforms/MacOSX.platform/Developer/SDKs/" if xcode else "/SDKs/"
            cases.extend(
                (
                    (directory, "clang", base + toolchain + "clang"),
                    (directory, "clang", base + toolchain + "ld"),
                    (directory, "linker", base + toolchain + "ld"),
                    (directory, "linker", base + "/bin/ld"),
                    (directory, "sdk", base + sdks + "MacOSX15.2.sdk"),
                    (directory, "sdk", base + sdks + "Other.sdk"),
                    (directory, "sdk", base + sdks + "MacOSX.sdk/extra"),
                    (directory, "clang", "/usr/bin/clang"),
                )
            )
        for directory, kind, raw in cases:
            with self.subTest(directory=directory.name, kind=kind, raw=raw):
                shape_ok = report.relative_shape_verdict(raw, directory, kind) is None
                with mock.patch.object(macos_capability, "_resolve_trusted_path", return_value=Path(raw)):
                    try:
                        macos_capability._resolve_toolchain_file(raw, directory, kind=kind)
                        real_ok = True
                    except macos_capability.ProbeFailure:
                        real_ok = False
                self.assertEqual(shape_ok, real_ok)


class FirstRefusalTests(unittest.TestCase):
    def test_all_passing_stages_report_pass(self):
        stages = [("a", report.PASS, None), ("b", report.PASS, None)]
        self.assertIsNone(report.first_refusal(stages))
        self.assertEqual(report.verdict_line(stages), "verdict: all conditions pass")

    def test_first_refusal_in_order_is_named(self):
        stages = [("a", report.PASS, None), ("b", report.REFUSE, "first"), ("c", report.REFUSE, "second")]
        self.assertEqual(report.first_refusal(stages), ("b", "first"))
        self.assertEqual(report.verdict_line(stages), "verdict: first refusal=b detail=first")

    def test_skipped_and_not_applicable_are_never_refusals(self):
        stages = [("a", report.NOT_APPLICABLE, "x"), ("b", report.SKIPPED, "y"), ("c", report.PASS, None)]
        self.assertIsNone(report.first_refusal(stages))
        self.assertEqual(
            report.verdict_line(stages),
            "verdict: no refusal found (not_applicable=a; skipped=b)",
        )
        self.assertEqual(report.own_outcome(stages), "incomplete")
        self.assertEqual(report.own_outcome(stages[:1] + stages[2:]), "pass")


def sandbox_tool(directory, name="tool", mode=0o755):
    leaf = Path(directory) / name
    leaf.write_text("x", encoding="ascii")
    leaf.chmod(mode)
    return leaf


class ExplainWalkTests(unittest.TestCase):
    def rows(self, *entries):
        return [(Path(path), meta, None if meta is not None else "FileNotFoundError") for path, meta in entries]

    def test_attribution_is_confirmed_against_the_real_predicate(self):
        rows = self.rows(
            ("/", metadata(kind=stat.S_IFDIR)),
            ("/a", metadata(uid=501, kind=stat.S_IFDIR)),
            ("/a/b", metadata(uid=501)),
        )
        with mock.patch.object(report, "walk_components", return_value=rows):
            self.assertEqual(report.explain_walk(Path("/a/b"), False), "'/a':owner_not_root")

    def test_leaf_cause_is_named_when_every_ancestor_passes(self):
        rows = self.rows(
            ("/", metadata(kind=stat.S_IFDIR)),
            ("/a", metadata(mode=0o644)),
        )
        with mock.patch.object(report, "walk_components", return_value=rows):
            self.assertEqual(report.explain_walk(Path("/a"), False), "'/a':not_executable")

    def test_missing_leaf_is_a_stat_error(self):
        rows = self.rows(("/", metadata(kind=stat.S_IFDIR)), ("/a", None))
        with mock.patch.object(report, "walk_components", return_value=rows):
            self.assertEqual(report.explain_walk(Path("/a"), False), "'/a':stat_error")

    def test_disagreeing_rederivation_is_labelled_not_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            leaf = sandbox_tool(directory)
            with mock.patch.object(report, "real_refuses_metadata", return_value=True):
                with mock.patch.object(report, "component_verdict", return_value=()):
                    with mock.patch.object(report, "leaf_verdict", return_value=()):
                        self.assertEqual(report.explain_walk(leaf, False), report.COULD_NOT_EXPLAIN)

    def test_real_accepting_a_blamed_component_is_labelled(self):
        with tempfile.TemporaryDirectory() as directory:
            leaf = sandbox_tool(directory)
            with mock.patch.object(report, "real_refuses_metadata", return_value=False):
                with mock.patch.object(report, "component_verdict", return_value=("world_writable",)):
                    self.assertEqual(report.explain_walk(leaf, False), report.COULD_NOT_EXPLAIN)

    def test_stand_in_matches_the_real_predicate_on_each_condition(self):
        cases = (
            (metadata(), False, False),
            (metadata(uid=501), False, True),
            (metadata(mode=0o757), False, True),
            (metadata(gid=20, mode=0o775), False, True),
            (metadata(mode=0o644), False, True),
            (metadata(mode=0o4755), False, True),
            (metadata(kind=stat.S_IFDIR), True, False),
            (metadata(), True, True),
        )
        for meta, directory, refuses in cases:
            with self.subTest(mode=oct(meta.st_mode), directory=directory):
                self.assertEqual(report.real_refuses_metadata(meta, directory), refuses)
                self.assertEqual(
                    bool(report.component_verdict(meta) + report.leaf_verdict(meta, directory)), refuses
                )


class PathStageTests(unittest.TestCase):
    def run_stage(self, raw, **kwargs):
        lines = []
        stage, path = report.path_stage("p", raw, lines.append, **kwargs)
        return stage, path, lines

    def test_string_level_causes_are_named(self):
        cases = (
            (("", {}), "raw_not_nonempty_nul_free_str"),
            (("/a\0b", {}), "raw_not_nonempty_nul_free_str"),
            (("/" + "a" * 5000, {}), "over_max_tool_path_bytes"),
            (("relative/x", {}), "not_absolute"),
            (("/usr/bin/python3", {"reject_python_shim": True}), "python_shim_path"),
        )
        for (raw, kwargs), cause in cases:
            with self.subTest(cause=cause):
                stage, path, _ = self.run_stage(raw, **kwargs)
                self.assertEqual(stage, ("p", report.REFUSE, cause))
                self.assertIsNone(path)

    def test_unresolvable_path_names_the_error_type(self):
        with mock.patch.object(Path, "lstat", side_effect=FileNotFoundError()):
            stage, path, _ = self.run_stage("/nonexistent-report-fixture/x")
        self.assertEqual(stage[1], report.REFUSE)
        self.assertTrue(stage[2].startswith("supplied_path_unresolvable:"))

    def test_accepted_path_returns_resolved_and_passes(self):
        with mock.patch.object(macos_capability, "_resolve_trusted_path", return_value=Path("/Fixture/tool")):
            with mock.patch.object(report, "print_walk"):
                stage, path, lines = self.run_stage("/Fixture/tool")
        self.assertEqual(stage, ("p", report.PASS, None))
        self.assertEqual(path, Path("/Fixture/tool"))
        self.assertTrue(any("real _resolve_trusted_path=accept" in line for line in lines))

    def test_untrusted_resolved_path_is_attributed_to_a_component(self):
        refusal = macos_capability.ProbeFailure("native_preflight_unavailable")
        lstat = types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o755)
        real = macos_capability._trusted_path_metadata

        def refuse_unless_stand_in(path, directory=False):
            if isinstance(path, report.StandInPath):
                return real(path, directory=directory)
            raise refusal

        rows = [
            (Path("/"), metadata(kind=stat.S_IFDIR), None),
            (Path("/Fixture"), metadata(uid=501, kind=stat.S_IFDIR), None),
            (Path("/Fixture/tool"), metadata(uid=501), None),
        ]
        with mock.patch.object(macos_capability, "_resolve_trusted_path", side_effect=refusal):
            with mock.patch.object(macos_capability, "_trusted_path_metadata", side_effect=refuse_unless_stand_in):
                with mock.patch.object(Path, "lstat", return_value=lstat):
                    with mock.patch.object(Path, "resolve", return_value=Path("/Fixture/tool")):
                        with mock.patch.object(report, "walk_components", return_value=rows):
                            stage, path, lines = self.run_stage("/Fixture/link")
        self.assertEqual(stage, ("p", report.REFUSE, "'/Fixture':owner_not_root"))
        self.assertIsNone(path)

    def test_non_root_supplied_link_is_named(self):
        refusal = macos_capability.ProbeFailure("native_preflight_unavailable")
        lstat = types.SimpleNamespace(st_uid=501, st_mode=stat.S_IFLNK | 0o755)
        with mock.patch.object(macos_capability, "_resolve_trusted_path", side_effect=refusal):
            with mock.patch.object(Path, "lstat", return_value=lstat):
                stage, path, _ = self.run_stage("/Fixture/link")
        self.assertEqual(stage, ("p", report.REFUSE, "supplied_path_owner_not_root"))

    def test_contradictory_real_checks_are_labelled(self):
        refusal = macos_capability.ProbeFailure("native_preflight_unavailable")
        lstat = types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
        with mock.patch.object(Path, "resolve", return_value=Path("/Fixture/tool")):
            with mock.patch.object(macos_capability, "_resolve_trusted_path", side_effect=refusal):
                with mock.patch.object(macos_capability, "_trusted_path_metadata", side_effect=lambda p, directory=False: p):
                    with mock.patch.object(Path, "lstat", return_value=lstat):
                        with mock.patch.object(report, "print_walk"):
                            stage, _, _ = self.run_stage("/Fixture/tool")
        self.assertEqual(stage, ("p", report.REFUSE, report.COULD_NOT_EXPLAIN))

    def test_hostile_path_never_forges_a_log_line(self):
        with tempfile.TemporaryDirectory() as directory:
            hostile = Path(directory) / "a\n::set-output name=x::y\x1b[31m"
            hostile.mkdir()
            leaf = hostile / "tool"
            leaf.write_text("x", encoding="ascii")
            lines = []
            report.print_walk(leaf, False, lines.append)
            report.path_stage("p", str(leaf), lines.append)
            for line in lines:
                self.assertTrue(line.isascii() and line.isprintable(), line)
                self.assertFalse(line.startswith("::"), line)


class ToolchainFileStageTests(unittest.TestCase):
    XCODE = Path("/Applications/Fixture.app/Contents/Developer")

    def run_stage(self, raw, kind="clang", directory=None):
        lines = []
        stage, path = report.toolchain_file_stage(
            "f", raw, directory or self.XCODE, kind, lines.append
        )
        return stage, path, lines

    def test_accept_passes_and_returns_the_path(self):
        with mock.patch.object(macos_capability, "_resolve_toolchain_file", return_value=Path("/x/clang")):
            stage, path, lines = self.run_stage("/x/clang")
        self.assertEqual(stage, ("f", report.PASS, None))
        self.assertEqual(path, Path("/x/clang"))

    def test_trust_refusal_is_reported_through_the_trust_stage(self):
        stage, path, lines = self.run_stage("relative/clang")
        self.assertEqual(stage, ("f", report.REFUSE, "not_absolute"))
        self.assertIsNone(path)
        self.assertTrue(any(line.startswith("path f_trust") for line in lines))

    def test_shape_refusal_when_the_path_is_trusted(self):
        trusted = ("f_trust", report.PASS, None), Path("/usr/bin/xcrun")
        with mock.patch.object(report, "path_stage", return_value=trusted):
            stage, path, lines = self.run_stage("/usr/bin/xcrun")
        self.assertEqual(stage, ("f", report.REFUSE, "outside_developer_directory"))
        self.assertTrue(any("relative shape verdict=outside_developer_directory" in line for line in lines))

    def test_unexplained_shape_is_labelled(self):
        trusted = ("f_trust", report.PASS, None), Path("/usr/bin/xcrun")
        with mock.patch.object(report, "path_stage", return_value=trusted):
            with mock.patch.object(report, "relative_shape_verdict", return_value=None):
                stage, _, _ = self.run_stage("/usr/bin/xcrun")
        self.assertEqual(stage, ("f", report.REFUSE, report.COULD_NOT_EXPLAIN))


class ToolOutputStageTests(unittest.TestCase):
    def query(self, **fields):
        base = dict(returncode=0, stdout=b"/usr/bin/clang\n", stderr=b"")
        base.update(fields)
        return types.SimpleNamespace(**base)

    def test_missing_query_is_a_refusal_not_a_skip(self):
        stage, value = report.tool_output_stage("q", None, [].append)
        self.assertEqual(stage, ("q", report.REFUSE, "query_did_not_run"))
        self.assertIsNone(value)

    def test_clean_output_passes_with_the_decoded_path(self):
        stage, value = report.tool_output_stage("q", self.query(), [].append)
        self.assertEqual(stage, ("q", report.PASS, None))
        self.assertEqual(value, "/usr/bin/clang")

    def test_rejection_names_the_reason(self):
        stage, value = report.tool_output_stage("q", self.query(stderr=b"w"), [].append)
        self.assertEqual(stage, ("q", report.REFUSE, "stderr_not_empty"))
        self.assertIsNone(value)

    def test_drift_is_emitted_and_follows_the_real_predicate(self):
        lines = []
        with mock.patch.object(macos_capability, "_read_tool_path", return_value="x"):
            stage, value = report.tool_output_stage("q", self.query(stderr=b"w"), lines.append)
        self.assertEqual(stage[:2], ("q", report.PASS))
        self.assertTrue(any(line.startswith("drift:") for line in lines))
        lines = []
        with mock.patch.object(
            macos_capability, "_read_tool_path", side_effect=macos_capability.ProbeFailure("native_preflight_unavailable")
        ):
            stage, value = report.tool_output_stage("q", self.query(), lines.append)
        self.assertEqual(stage, ("q", report.REFUSE, report.COULD_NOT_EXPLAIN))
        self.assertTrue(any(line.startswith("drift:") for line in lines))


class CrossCheckTests(unittest.TestCase):
    PASSING = [("a", report.PASS, None), ("b", report.NOT_APPLICABLE, "x")]
    REFUSING = [("a", report.PASS, None), ("b", report.REFUSE, "why")]
    RESOLVED = {"python": "/p", "clang": "/c", "sdk": "/s", "linker": "/l", "developer_directory": "/d"}

    def check(self, stages, outcome, real=None, resolved=None):
        lines = []
        stage = report.cross_check(
            stages,
            self.RESOLVED if resolved is None else resolved,
            lines.append,
            real_outcome=lambda: (outcome, real, False),
        )
        return stage, lines

    def test_agreement_in_both_directions(self):
        stage, lines = self.check(self.PASSING, "accept", dict(self.RESOLVED))
        self.assertEqual(stage[:2], (report.CROSS_CHECK_STAGE, report.AGREE))
        self.assertTrue(any("cross-check: agreement" in line for line in lines))
        stage, lines = self.check(self.REFUSING, "refuse")
        self.assertEqual(stage[:2], (report.CROSS_CHECK_STAGE, report.AGREE))

    def test_drift_when_real_accepts_but_report_refuses(self):
        stage, lines = self.check(self.REFUSING, "accept", dict(self.RESOLVED))
        self.assertEqual(stage[1], report.DRIFT)
        drift = [line for line in lines if line.startswith("drift:")]
        self.assertEqual(len(drift), 1)
        self.assertIn("ACCEPTS", drift[0])
        self.assertIn("'b'", drift[0])

    def test_drift_when_real_refuses_but_report_passes(self):
        stage, lines = self.check(self.PASSING, "refuse")
        self.assertEqual(stage[1], report.DRIFT)
        drift = [line for line in lines if line.startswith("drift:")]
        self.assertEqual(len(drift), 1)
        self.assertIn("REFUSES", drift[0])
        self.assertIn("all stages pass", drift[0])

    def test_drift_when_accepted_values_differ(self):
        other = dict(self.RESOLVED, clang="/elsewhere")
        stage, lines = self.check(self.PASSING, "accept", other)
        self.assertEqual(stage[1], report.DRIFT)
        self.assertTrue(any(line.startswith("drift:") and "clang" in line for line in lines))

    def test_drift_when_the_report_is_incomplete_without_a_refusal(self):
        stage, _ = self.check([("a", report.SKIPPED, "x")], "refuse")
        self.assertEqual(stage[1], report.DRIFT)

    def test_unexpected_real_exception_is_drift(self):
        stage, lines = self.check(self.PASSING, "error:KeyError")
        self.assertEqual(stage[1], report.DRIFT)

    def test_real_outcome_stubs_only_the_euid_gate_and_restores_it(self):
        seen = []

        def resolver():
            seen.append(os.geteuid())
            return {"python": "/p"}

        for euid, stubbed in ((502, True), (0, False)):
            original = os.geteuid
            with mock.patch.object(os, "geteuid", return_value=euid):
                patched = os.geteuid
                with mock.patch.object(macos_capability, "_resolve_trusted_toolchain", side_effect=resolver):
                    outcome = report.real_resolver_outcome()
                self.assertIs(os.geteuid, patched)
            self.assertIs(os.geteuid, original)
            self.assertEqual(outcome, ("accept", {"python": "/p"}, stubbed))
            self.assertEqual(seen[-1], 0)

    def test_real_outcome_classifies_refusal_and_unexpected_errors(self):
        with mock.patch.object(
            macos_capability, "_resolve_trusted_toolchain", side_effect=macos_capability.ProbeFailure("native_preflight_unavailable")
        ):
            self.assertEqual(report.real_resolver_outcome()[0], "refuse")
        with mock.patch.object(macos_capability, "_resolve_trusted_toolchain", side_effect=KeyError("k")):
            self.assertEqual(report.real_resolver_outcome()[0], "error:KeyError")
        with mock.patch.object(macos_capability, "_resolve_trusted_toolchain", return_value={"python": "/p"}):
            self.assertEqual(report.real_resolver_outcome()[:2], ("accept", {"python": "/p"}))


class BuildReportTests(unittest.TestCase):
    def build(self, **fixture):
        lines = []
        with synthetic_host(**fixture):
            stages = report.build_report(lines.append)
        return stages, lines

    def states(self, stages):
        return dict((name, state) for name, state, _ in stages)

    def test_healthy_host_passes_every_stage_and_agrees(self):
        stages, lines = self.build(euid=0, outcome=("accept", dict(FIXTURE_RESOLVED), False))
        names = [name for name, _, _ in stages]
        self.assertEqual(names[:4], ["platform_darwin", "euid_root_gate", "python_version", "python_path"])
        self.assertEqual(names[-1], report.CROSS_CHECK_STAGE)
        states = self.states(stages)
        self.assertEqual(set(states.values()), {report.PASS, report.AGREE})
        self.assertIsNone(report.first_refusal(stages))

    def test_unprivileged_context_marks_the_euid_gate_not_applicable(self):
        stages, _ = self.build(euid=502, outcome=("accept", dict(FIXTURE_RESOLVED), False))
        states = self.states(stages)
        self.assertEqual(states["euid_root_gate"], report.NOT_APPLICABLE)
        self.assertEqual(states[report.CROSS_CHECK_STAGE], report.AGREE)

    def test_refused_python_path_skips_dependent_stages_without_refusing_them(self):
        stages, _ = self.build(python_ok=False)
        states = self.states(stages)
        self.assertEqual(states["python_path"], report.REFUSE)
        for name in ("python_layout", "developer_directory", "clang_file", "sdk_file", "linker_output", "linker_file"):
            self.assertEqual(states[name], report.SKIPPED, name)
        self.assertEqual(states[report.CROSS_CHECK_STAGE], report.AGREE)

    def test_unmatched_layout_is_refused_and_later_stages_are_skipped(self):
        stages, _ = self.build(developer=None)
        states = self.states(stages)
        self.assertEqual(states["python_path"], report.PASS)
        self.assertEqual(states["python_layout"], report.REFUSE)
        for name in ("developer_directory", "clang_file", "sdk_file", "linker_output", "linker_file"):
            self.assertEqual(states[name], report.SKIPPED, name)
        self.assertEqual(report.first_refusal(stages)[0], "python_layout")

    def test_cross_check_stage_always_present_even_after_a_collect_failure(self):
        lines = []
        with mock.patch.object(report, "collect_stages", side_effect=RuntimeError("boom")):
            with mock.patch.object(report, "real_resolver_outcome", return_value=("refuse", None, False)):
                stages = report.build_report(lines.append)
        self.assertEqual(stages[0], ("report_error", report.REFUSE, "RuntimeError"))
        self.assertEqual(stages[-1][0], report.CROSS_CHECK_STAGE)
        self.assertEqual(stages[-1][1], report.AGREE)

    def test_forced_drift_surfaces_in_the_stage_and_lines(self):
        stages, lines = self.build(euid=0, outcome=("refuse", None, False))
        self.assertEqual(stages[-1][1], report.DRIFT)
        self.assertTrue(any(line.startswith("drift: real resolver REFUSES") for line in lines))
        stages, lines = self.build(python_ok=False, outcome=("accept", dict(FIXTURE_RESOLVED), False))
        self.assertEqual(stages[-1][1], report.DRIFT)
        self.assertTrue(any(line.startswith("drift: real resolver ACCEPTS") for line in lines))


class MainTests(unittest.TestCase):
    def run_main(self, **fixture):
        output = io.StringIO()
        with synthetic_host(**fixture):
            with contextlib.redirect_stdout(output):
                code = report.main()
        return code, output.getvalue()

    def test_main_exits_zero_and_prints_a_verdict_even_when_the_report_fails(self):
        with mock.patch.object(report, "build_report", side_effect=RuntimeError("boom")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = report.main()
        self.assertEqual(code, 0)
        self.assertIn("verdict: first refusal=report_error detail=RuntimeError", output.getvalue())

    def test_main_prints_the_drift_flag_and_still_exits_zero(self):
        code, text = self.run_main(euid=0, outcome=("refuse", None, False))
        self.assertEqual(code, 0)
        self.assertIn("drift_detected=yes", text)
        self.assertIn("drift: real resolver REFUSES", text)

    def test_main_reports_no_drift_when_both_agree(self):
        code, text = self.run_main(euid=0, outcome=("accept", dict(FIXTURE_RESOLVED), False))
        self.assertEqual(code, 0)
        self.assertIn("drift_detected=no", text)
        self.assertIn("verdict: all conditions pass", text)

    def test_main_marks_skipped_stages_distinctly(self):
        stages = [
            ("python_path", report.REFUSE, "x"),
            ("linker_output", report.SKIPPED, "y"),
            ("euid_root_gate", report.NOT_APPLICABLE, "z"),
        ]
        with mock.patch.object(report, "build_report", return_value=stages):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                report.main()
        self.assertIn("stages python_path=REFUSE linker_output=skipped euid_root_gate=not_applicable", output.getvalue())

    def test_unsafe_lines_are_suppressed(self):
        self.assertEqual(report.safe_line("ok line"), "ok line")
        for line in ("::set-output name=x::y", "a\nb", "\x1b[31m", "caf\u00e9"):
            with self.subTest(line=line):
                safe = report.safe_line(line)
                self.assertTrue(safe.startswith("unsafe_line_suppressed="))
                self.assertTrue(safe.isascii() and safe.isprintable())


class DiagnosticTests(unittest.TestCase):
    def run_diagnostics(self, sys_executable, queries, trusted=None):
        lines = []
        fake_sys = mock.patch.object(sys, "executable", sys_executable)
        fake_queries = mock.patch.object(report, "run_query", side_effect=queries)
        with fake_sys, fake_queries:
            if trusted is None:
                report.unconditional_diagnostics(lines.append)
            else:
                with mock.patch.object(macos_capability, "_trusted_path_metadata", side_effect=trusted):
                    report.unconditional_diagnostics(lines.append)
        return lines

    def ok(self, text):
        return types.SimpleNamespace(returncode=0, stdout=text.encode() + b"\n", stderr=b"")

    def test_lstat_chain_shows_symlinks_as_symlinks_with_owner_and_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real"
            real.write_text("x")
            link = Path(directory) / "link"
            link.symlink_to(real)
            lines = []
            report.diagnostic_lstat_chain(str(link), lines.append)
        leaf = [line for line in lines if "/link' type=symlink " in line]
        self.assertEqual(len(leaf), 1)
        self.assertIn("uid=" + str(os.lstat(__file__).st_uid), leaf[0])
        self.assertIn("mode=0", leaf[0])
        self.assertIn("/120000", leaf[0])
        self.assertIn("target=", leaf[0])
        self.assertTrue(any(" type=directory " in line for line in lines))

    def test_lstat_chain_reports_missing_component_without_raising(self):
        lines = []
        report.diagnostic_lstat_chain("/nonexistent-fixture/a/b", lines.append)
        self.assertTrue(any("lstat_error=FileNotFoundError" in line for line in lines))

    def test_diagnostics_run_all_targets_and_banner_even_when_python_would_refuse(self):
        queries = [self.ok("/Fixture/dev"), self.ok("/Fixture/dev/clang"), self.ok("/Fixture/dev/sdk")]
        refuse = macos_capability.ProbeFailure("fixture")

        def refusing(path, directory=False):
            raise refuse

        lines = self.run_diagnostics("/Fixture/bin/python3", queries, trusted=refusing)
        self.assertTrue(lines[0].startswith(report.DIAGNOSTIC_BANNER))
        self.assertTrue(lines[-1].startswith(report.DIAGNOSTIC_BANNER))
        for label in ("python_realpath", "xcode_select_directory", "clang_path", "sdk_path"):
            self.assertTrue(any(line.startswith("diag target " + label) for line in lines), label)
        self.assertEqual(sum(line.endswith("=REFUSE") for line in lines), 4)
        self.assertTrue(any("(directory=True)=REFUSE" in line for line in lines))
        self.assertTrue(any("(directory=False)=REFUSE" in line for line in lines))
        self.assertTrue(any("matches PYTHON_XCODE_LAYOUT=False" in line for line in lines))
        self.assertTrue(any("matches PYTHON_CLT_LAYOUT=False" in line for line in lines))
        self.assertTrue(any(line.startswith("diag lstat chain") for line in lines))

    def test_unavailable_queries_are_printed_not_raised(self):
        lines = self.run_diagnostics("/Fixture/bin/python3", [None])
        self.assertIn("diag xcode-select directory unavailable", lines)
        self.assertEqual(lines[-1], report.DIAGNOSTIC_BANNER + " end")
        lines = self.run_diagnostics("/Fixture/bin/python3", [self.ok("/Fixture/dev"), None, None])
        self.assertIn("diag clang path unavailable", lines)
        self.assertIn("diag sdk path unavailable", lines)

    def test_layout_match_is_reported_for_a_matching_target(self):
        target = "/Applications/Xcode_1.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9"
        with mock.patch.object(os.path, "realpath", return_value=target):
            lines = self.run_diagnostics("/Fixture/bin/python3", [None])
        matches = [line for line in lines if "matches PYTHON_" in line]
        self.assertEqual(len(matches), 2)
        self.assertTrue(any("XCODE_LAYOUT=True" in line for line in matches))

    def test_unexpected_errors_in_a_target_are_contained(self):
        queries = [self.ok("/Fixture/dev"), None, None]
        with mock.patch.object(report, "print_walk", side_effect=RuntimeError("fixture")):
            lines = self.run_diagnostics("/Fixture/bin/python3", queries)
        self.assertIn("  diagnostic_error=RuntimeError", lines)
        self.assertEqual(lines[-1], report.DIAGNOSTIC_BANNER + " end")

    def test_hostile_path_cannot_forge_a_diagnostic_line(self):
        queries = [self.ok("/Fixture/d\x1bev"), None, None]
        lines = self.run_diagnostics("/Fixture/p\ny::x", queries)
        for line in lines:
            self.assertTrue(line.isascii() and line.isprintable(), line)

    def test_diagnostics_never_change_stages_verdict_or_drift(self):
        outputs = []
        for diagnostics in (lambda emit: None, lambda emit: emit("diag fixture line")):
            with synthetic_host(python_ok=False):
                with mock.patch.object(report, "unconditional_diagnostics", side_effect=diagnostics):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(report.main(), 0)
            outputs.append([line for line in output.getvalue().splitlines() if not line.startswith("diag ")])
        self.assertEqual(outputs[0], outputs[1])

    def test_a_failing_diagnostic_never_breaks_build_report_or_main(self):
        with synthetic_host(python_ok=False):
            with mock.patch.object(report, "unconditional_diagnostics", side_effect=RuntimeError("fixture")):
                lines = []
                stages = report.build_report(lines.append)
        self.assertIn("diagnostic_error=RuntimeError", lines)
        self.assertEqual(report.first_refusal(stages)[0], "python_path")

    def test_build_report_runs_diagnostics_after_a_refused_python_path(self):
        calls = []
        with synthetic_host(python_ok=False):
            with mock.patch.object(report, "unconditional_diagnostics", side_effect=calls.append):
                report.build_report([].append)
        self.assertEqual(len(calls), 1)


class PreviewTests(unittest.TestCase):
    def test_preview_is_bounded_and_ascii(self):
        text = report.preview(b"a" * 2000)
        self.assertLess(len(text), 600)
        self.assertTrue(text.isascii())

    def test_hostile_bytes_cannot_forge_lines_or_commands(self):
        data = b"\x1b[2J::set-output name=x::y\nline2\r\n\xff\x00" + b"a" * 2000
        text = report.preview(data)
        self.assertTrue(text.isascii() and text.isprintable())
        self.assertNotIn("\n", text)
        self.assertNotIn("\x1b", text)
        self.assertFalse(text.startswith("::"))
        self.assertIn("::set-output", text)
        self.assertLess(len(text), 700)

    def test_newline_in_a_path_is_escaped_in_every_printed_form(self):
        lines = []
        report.path_stage("p", "/tmp/a\n::workflow-command", lines.append)
        for line in lines:
            self.assertTrue(line.isascii() and line.isprintable(), line)


if __name__ == "__main__":
    unittest.main(verbosity=2)
