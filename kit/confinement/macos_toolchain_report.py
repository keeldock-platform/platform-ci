import glob
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import types

import macos_capability


TOOL_OUTPUT_PREVIEW_BYTES = 512
CHILD_OUTPUT_PREVIEW_BYTES = 2048
QUERY_TIMEOUT_SECONDS = 10
CHILD_TIMEOUT_SECONDS = 60
SDK_NAME_PATTERN = r"MacOSX[0-9]*(?:\.[0-9]+)*\.sdk"
PASS = "pass"
REFUSE = "REFUSE"
SKIPPED = "skipped"
NOT_APPLICABLE = "not_applicable"
AGREE = "agree"
DRIFT = "DRIFT"
COULD_NOT_EXPLAIN = "report-could-not-explain"
CROSS_CHECK_STAGE = "real_resolver_cross_check"
COMPONENT_CONDITIONS = (
    ("owner_not_root", "uid!=0"),
    ("world_writable", "S_IWOTH"),
    ("group_writable_primary_gid", "S_IWGRP&gid20"),
)


def component_verdict(metadata):
    mode = metadata.st_mode
    failed = []
    if metadata.st_uid != 0:
        failed.append("owner_not_root")
    if mode & stat.S_IWOTH:
        failed.append("world_writable")
    if mode & stat.S_IWGRP and metadata.st_gid == macos_capability.PROBE_PRIMARY_GID:
        failed.append("group_writable_primary_gid")
    return tuple(failed)


def leaf_verdict(metadata, directory):
    failed = []
    if directory:
        if not stat.S_ISDIR(metadata.st_mode):
            failed.append("not_a_directory")
    else:
        if not stat.S_ISREG(metadata.st_mode):
            failed.append("not_a_regular_file")
        if not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            failed.append("not_executable")
        if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
            failed.append("setid_bit_set")
    return tuple(failed)


class StandInPath:
    def __init__(self, metadata):
        self.parents = []
        self.metadata = metadata

    def stat(self):
        return self.metadata


def real_refuses_metadata(metadata, directory):
    try:
        macos_capability._trusted_path_metadata(StandInPath(metadata), directory=directory)
    except macos_capability.ProbeFailure:
        return True
    return False


def ancestor_components(path):
    path = Path(path)
    return list(reversed(path.parents)) + [path]


def walk_components(path):
    rows = []
    for component in ancestor_components(path):
        try:
            rows.append((component, component.stat(), None))
        except OSError as error:
            rows.append((component, None, type(error).__name__))
    return rows


def tool_output_verdict(returncode, stdout, stderr):
    result = types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
    try:
        macos_capability._read_tool_path(result)
        accepted = True
    except macos_capability.ProbeFailure:
        accepted = False
    reason = None
    if returncode != 0:
        reason = "returncode_nonzero"
    elif stderr:
        reason = "stderr_not_empty"
    elif not stdout.endswith(b"\n"):
        reason = "no_trailing_newline"
    elif stdout.count(b"\n") != 1:
        reason = "not_exactly_one_newline"
    elif len(stdout) > macos_capability.MAX_TOOL_PATH_BYTES:
        reason = "over_max_tool_path_bytes"
    else:
        try:
            value = stdout[:-1].decode("ascii")
        except UnicodeDecodeError:
            reason = "not_ascii"
        else:
            if not value or value != value.strip():
                reason = "empty_or_whitespace_padded"
    if accepted and reason is not None:
        return True, "drift: real predicate accepts, report sees " + reason
    if not accepted and reason is None:
        return False, "drift: real predicate refuses, report sees no reason"
    return accepted, reason


def expected_relative(kind, developer_directory):
    is_xcode = PurePosixPath(developer_directory.as_posix()).name == "Developer"
    if kind in ("clang", "linker"):
        name = "clang" if kind == "clang" else "ld"
        if is_xcode:
            return "Toolchains/XcodeDefault.xctoolchain/usr/bin/" + name
        return "usr/bin/" + name
    if is_xcode:
        return "Platforms/MacOSX.platform/Developer/SDKs/<" + SDK_NAME_PATTERN + ">"
    return "SDKs/<" + SDK_NAME_PATTERN + ">"


def relative_shape_verdict(path, developer_directory, kind):
    try:
        relative = PurePosixPath(Path(path).as_posix()).relative_to(
            PurePosixPath(developer_directory.as_posix())
        ).parts
    except ValueError:
        return "outside_developer_directory"
    expected = expected_relative(kind, developer_directory)
    if kind == "sdk":
        prefix = expected.rsplit("/", 1)[0]
        expected_parts = tuple(prefix.split("/")) if "/" in expected else ()
        sdk_name = relative[-1] if relative else ""
        ok = (
            len(relative) == len(expected_parts) + 1
            and relative[:-1] == expected_parts
            and re.fullmatch(SDK_NAME_PATTERN, sdk_name) is not None
        )
    else:
        ok = relative == tuple(expected.split("/"))
    return None if ok else "unexpected_relative_shape"


def explain_walk(path, directory):
    rows = walk_components(path)
    last = len(rows) - 1
    for index, (component, metadata, error) in enumerate(rows):
        if metadata is None:
            return ascii(str(component)) + ":stat_error"
        leaf = index == last
        causes = list(component_verdict(metadata))
        if leaf:
            causes.extend(leaf_verdict(metadata, directory))
        if bool(causes) != real_refuses_metadata(metadata, directory if leaf else True):
            return COULD_NOT_EXPLAIN
        if causes:
            return ascii(str(component)) + ":" + causes[0]
    return COULD_NOT_EXPLAIN


def first_refusal(stages):
    for name, state, detail in stages:
        if state == REFUSE:
            return name, detail
    return None


def names_in_state(stages, state):
    return [name for name, current, _ in stages if current == state]


def verdict_line(stages):
    refusal = first_refusal(stages)
    if refusal is None:
        notes = []
        for state in (NOT_APPLICABLE, SKIPPED):
            names = names_in_state(stages, state)
            if names:
                notes.append(state + "=" + ",".join(names))
        if not notes:
            return "verdict: all conditions pass"
        return "verdict: no refusal found (" + "; ".join(notes) + ")"
    name, detail = refusal
    return "verdict: first refusal=" + name + " detail=" + str(detail)


def preview(data, limit=TOOL_OUTPUT_PREVIEW_BYTES):
    shown = data[:limit]
    suffix = "" if len(data) <= limit else "...(+" + str(len(data) - len(shown)) + " bytes)"
    return ascii(shown) + suffix


def mode_text(metadata):
    return format(stat.S_IMODE(metadata.st_mode), "04o") + "/" + format(stat.S_IFMT(metadata.st_mode), "06o")


def print_walk(path, directory, emit):
    emit("walk " + ascii(str(path)))
    rows = walk_components(path)
    for component, metadata, error in rows:
        if metadata is None:
            emit("  " + ascii(str(component)) + " stat_error=" + str(error))
            continue
        failed = component_verdict(metadata)
        flags = " ".join(
            label + "=" + ("FAIL" if key in failed else "ok") for key, label in COMPONENT_CONDITIONS
        )
        emit(
            "  "
            + ascii(str(component))
            + " uid="
            + str(metadata.st_uid)
            + " gid="
            + str(metadata.st_gid)
            + " mode="
            + mode_text(metadata)
            + " "
            + flags
        )
    leaf = rows[-1][1]
    if leaf is None:
        emit("  leaf verdict=unavailable")
    else:
        failed = leaf_verdict(leaf, directory)
        emit("  leaf verdict=" + ("FAIL " + ",".join(failed) if failed else "ok") + " directory_required=" + str(directory))


def string_level_cause(raw, reject_python_shim):
    if not isinstance(raw, str) or not raw or "\0" in raw:
        return "raw_not_nonempty_nul_free_str"
    try:
        if len(os.fsencode(raw)) > macos_capability.MAX_TOOL_PATH_BYTES:
            return "over_max_tool_path_bytes"
    except (UnicodeError, ValueError):
        return "raw_not_encodable"
    if not PurePosixPath(raw).is_absolute():
        return "not_absolute"
    if reject_python_shim and PurePosixPath(raw).as_posix() == "/usr/bin/python3":
        return "python_shim_path"
    return None


def path_stage(name, raw, emit, *, directory=False, reject_python_shim=False):
    emit("path " + name + " raw=" + ascii(raw))
    try:
        resolved = macos_capability._resolve_trusted_path(
            raw, directory=directory, reject_python_shim=reject_python_shim
        )
        emit("  real _resolve_trusted_path=accept resolved=" + ascii(resolved.as_posix()))
        print_walk(resolved, directory, emit)
        return (name, PASS, None), resolved
    except macos_capability.ProbeFailure:
        emit("  real _resolve_trusted_path=REFUSE")
    detail = string_level_cause(raw, reject_python_shim)
    resolved = None
    if detail is None:
        detail = COULD_NOT_EXPLAIN
        try:
            link_metadata = Path(raw).lstat()
            emit("  supplied lstat uid=" + str(link_metadata.st_uid) + " mode=" + mode_text(link_metadata))
            if link_metadata.st_uid != 0:
                detail = "supplied_path_owner_not_root"
            else:
                resolved = Path(raw).resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            detail = "supplied_path_unresolvable:" + type(error).__name__
    if resolved is not None:
        emit("  resolved=" + ascii(resolved.as_posix()))
        print_walk(resolved, directory, emit)
        try:
            macos_capability._trusted_path_metadata(resolved, directory=directory)
        except macos_capability.ProbeFailure:
            detail = explain_walk(resolved, directory)
        else:
            detail = COULD_NOT_EXPLAIN
    return (name, REFUSE, detail), None


def toolchain_file_stage(name, raw, developer_directory, kind, emit):
    emit("file " + name + " raw=" + ascii(raw))
    try:
        path = macos_capability._resolve_toolchain_file(raw, developer_directory, kind=kind)
        emit("  real _resolve_toolchain_file=accept")
        print_walk(path, kind == "sdk", emit)
        return (name, PASS, None), path
    except macos_capability.ProbeFailure:
        emit("  real _resolve_toolchain_file=REFUSE")
    emit("  expected relative shape=" + expected_relative(kind, developer_directory))
    trust_stage, path = path_stage(name + "_trust", raw, emit, directory=kind == "sdk")
    if trust_stage[1] != PASS:
        return (name, REFUSE, trust_stage[2]), None
    shape = relative_shape_verdict(path, developer_directory, kind)
    emit("  relative shape verdict=" + ("ok" if shape is None else shape))
    return (name, REFUSE, shape or COULD_NOT_EXPLAIN), None


def tool_output_stage(name, query, emit):
    emit("query " + name)
    if query is None:
        emit("  query did not run")
        return (name, REFUSE, "query_did_not_run"), None
    emit("  returncode=" + str(query.returncode))
    emit("  stdout=" + preview(query.stdout))
    emit("  stderr=" + preview(query.stderr))
    accepted, reason = tool_output_verdict(query.returncode, query.stdout, query.stderr)
    if reason is not None and reason.startswith("drift:"):
        emit(reason)
        if accepted:
            return (name, PASS, None), query.stdout[:-1].decode("ascii", "replace")
        return (name, REFUSE, COULD_NOT_EXPLAIN), None
    emit("  _read_tool_path would " + ("accept" if accepted else "REFUSE (" + str(reason) + ")"))
    if not accepted:
        return (name, REFUSE, reason), None
    return (name, PASS, None), query.stdout[:-1].decode("ascii")


def run_query(argv, env, emit):
    try:
        return macos_capability._run(argv, env=env, timeout=QUERY_TIMEOUT_SECONDS)
    except macos_capability.ProbeFailure:
        emit("  could not run " + ascii(str(argv[0])))
        return None


def run_child(argv, env, emit):
    try:
        return macos_capability._run(argv, env=env, timeout=CHILD_TIMEOUT_SECONDS)
    except macos_capability.ProbeFailure:
        emit("  could not run " + ascii(str(argv[0])))
        return None


def developer_directory_for(python, emit):
    text = python.as_posix()
    emit("python matches PYTHON_XCODE_LAYOUT=" + str(bool(macos_capability.PYTHON_XCODE_LAYOUT.fullmatch(text))))
    emit("python matches PYTHON_CLT_LAYOUT=" + str(bool(macos_capability.PYTHON_CLT_LAYOUT.fullmatch(text))))
    try:
        directory = macos_capability._python_developer_directory(python)
    except macos_capability.ProbeFailure:
        return None
    emit("developer directory=" + ascii(directory.as_posix()))
    return directory


def own_outcome(stages):
    if first_refusal(stages) is not None:
        return "refuse"
    if all(state in (PASS, NOT_APPLICABLE) for _, state, _ in stages):
        return "pass"
    return "incomplete"


def real_resolver_outcome():
    stubbed = os.geteuid() != 0
    original = os.geteuid
    if stubbed:
        os.geteuid = lambda: 0
    try:
        try:
            return "accept", macos_capability._resolve_trusted_toolchain(), stubbed
        except macos_capability.ProbeFailure:
            return "refuse", None, stubbed
        except BaseException as error:
            return "error:" + type(error).__name__, None, stubbed
    finally:
        os.geteuid = original


def cross_check(stages, resolved, emit, real_outcome=None):
    real_outcome = real_outcome or real_resolver_outcome
    own = own_outcome(stages)
    outcome, real, stubbed = real_outcome()
    emit(
        "cross-check: real _resolve_trusted_toolchain="
        + ascii(outcome)
        + (" (euid gate stubbed to 0 in-process; reported separately as not_applicable)" if stubbed else "")
        + " report="
        + own
    )
    drifts = []
    if outcome == "accept":
        if own != "pass":
            drifts.append("real resolver ACCEPTS but report claims " + own + " at " + str(first_refusal(stages)))
        else:
            for key, value in sorted(real.items()):
                if resolved.get(key) != value:
                    drifts.append("real resolver " + key + "=" + ascii(value) + " differs from report " + ascii(resolved.get(key)))
    elif outcome == "refuse":
        if own == "pass":
            drifts.append("real resolver REFUSES but report claims all stages pass")
        elif own == "incomplete":
            drifts.append("real resolver REFUSES but report has skipped stages and names no refusal")
    else:
        drifts.append("real resolver raised unexpected " + ascii(outcome))
    if drifts:
        for text in drifts:
            emit("drift: " + text)
        return (CROSS_CHECK_STAGE, DRIFT, "; ".join(drifts))
    emit("cross-check: agreement (binary: the real resolver exposes no cause, so per-stage causes are verified separately)")
    return (CROSS_CHECK_STAGE, AGREE, None)


def collect_stages(emit, stages, resolved):
    emit("conditions: uid!=0 is st_uid != 0; S_IWOTH is mode & S_IWOTH; S_IWGRP&gid20 is mode & S_IWGRP and st_gid == 20")
    emit("sys.executable=" + ascii(sys.executable))
    emit("sys.platform=" + sys.platform)
    emit("sys.version_info=" + str(tuple(sys.version_info)))
    emit("realpath(sys.executable)=" + ascii(os.path.realpath(sys.executable)))
    emit("euid=" + str(os.geteuid()))
    query_env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
    }
    select = run_query(["/usr/bin/xcode-select", "-p"], query_env, emit)
    selected = None
    if select is not None:
        emit("xcode-select -p returncode=" + str(select.returncode) + " stdout=" + preview(select.stdout) + " stderr=" + preview(select.stderr))
        if select.returncode == 0 and select.stdout.endswith(b"\n"):
            try:
                selected = Path(select.stdout[:-1].decode("ascii"))
            except UnicodeDecodeError:
                selected = None

    stages.append(("platform_darwin", PASS if sys.platform == "darwin" else REFUSE, "sys.platform=" + sys.platform))
    if os.geteuid() == 0:
        stages.append(("euid_root_gate", PASS, None))
    else:
        stages.append(("euid_root_gate", NOT_APPLICABLE, "real job requires euid 0; this report runs at euid " + str(os.geteuid())))
    stages.append(("python_version", PASS if sys.version_info >= (3, 9) else REFUSE, "sys.version_info<3.9"))
    stage, python = path_stage("python_path", sys.executable, emit, reject_python_shim=True)
    stages.append(stage)
    if python is not None:
        resolved["python"] = python.as_posix()
    developer_directory = None
    if python is not None:
        developer_directory = developer_directory_for(python, emit)
        if developer_directory is None:
            stages.append(("python_layout", REFUSE, "python_path_matches_neither_layout"))
        else:
            stages.append(("python_layout", PASS, None))
    else:
        stages.append(("python_layout", SKIPPED, "python_path_refused"))
    queries_directory = developer_directory
    if queries_directory is None and selected is not None:
        queries_directory = selected
        emit("developer directory not derived; queries use the xcode-select directory instead (diagnostic only)")
    if developer_directory is not None:
        emit("developer directory trust walk")
        try:
            macos_capability._trusted_path_metadata(developer_directory, directory=True)
            emit("  real _trusted_path_metadata=accept")
            stages.append(("developer_directory", PASS, None))
            resolved["developer_directory"] = developer_directory.as_posix()
        except macos_capability.ProbeFailure:
            emit("  real _trusted_path_metadata=REFUSE")
            stages.append(("developer_directory", REFUSE, explain_walk(developer_directory, True)))
        print_walk(developer_directory, True, emit)
    else:
        stages.append(("developer_directory", SKIPPED, "no_developer_directory_derived"))

    stage, xcrun = path_stage("xcrun_path", "/usr/bin/xcrun", emit)
    stages.append(stage)
    if queries_directory is None or xcrun is None:
        stages.append(("toolchain_queries", SKIPPED, "needs_a_directory_and_xcrun"))
        return
    env = dict(query_env)
    env["DEVELOPER_DIR"] = queries_directory.as_posix()
    clang_query = run_query([str(xcrun), "--sdk", "macosx", "--find", "clang"], env, emit)
    sdk_query = run_query([str(xcrun), "--sdk", "macosx", "--show-sdk-path"], env, emit)
    clang = sdk = None
    stage, clang_raw = tool_output_stage("clang_output", clang_query, emit)
    stages.append(stage)
    if clang_raw is not None and developer_directory is not None:
        stage, clang = toolchain_file_stage("clang_file", clang_raw, developer_directory, "clang", emit)
        stages.append(stage)
        if clang is not None:
            resolved["clang"] = clang.as_posix()
    else:
        stages.append(("clang_file", SKIPPED, "needs_clang_output_and_developer_directory"))
    stage, sdk_raw = tool_output_stage("sdk_output", sdk_query, emit)
    stages.append(stage)
    if sdk_raw is not None and developer_directory is not None:
        stage, sdk = toolchain_file_stage("sdk_file", sdk_raw, developer_directory, "sdk", emit)
        stages.append(stage)
        if sdk is not None:
            resolved["sdk"] = sdk.as_posix()
    else:
        stages.append(("sdk_file", SKIPPED, "needs_sdk_output_and_developer_directory"))
    if clang is None or sdk is None:
        emit("linker query not run: it needs the resolved clang and sdk")
        stages.append(("linker_output", SKIPPED, "needs_resolved_clang_and_sdk"))
        stages.append(("linker_file", SKIPPED, "needs_linker_output"))
        return
    linker_query = run_query([str(clang), "-isysroot", str(sdk), "-print-prog-name=ld"], env, emit)
    stage, linker_raw = tool_output_stage("linker_output", linker_query, emit)
    stages.append(stage)
    if linker_raw is not None:
        stage, linker = toolchain_file_stage("linker_file", linker_raw, developer_directory, "linker", emit)
        stages.append(stage)
        if linker is not None:
            resolved["linker"] = linker.as_posix()
    else:
        stages.append(("linker_file", SKIPPED, "needs_linker_output"))


DIAGNOSTIC_BANNER = "unconditional-diagnostic-walks"
CLT_ROOT = "/Library/Developer/CommandLineTools"
CLT_CLANG_RELATIVE = "usr/bin/clang"
CLT_SDK_RELATIVE = "SDKs/MacOSX.sdk"
CLT_PYTHON_GLOB_RELATIVE = "Library/Frameworks/Python3.framework/Versions/*/bin/python3.*"
USR_BIN_PYTHON3 = "/usr/bin/python3"


def file_type_text(metadata):
    mode = metadata.st_mode
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    return "other"


def diagnostic_trust_line(path, directory, emit):
    try:
        macos_capability._trusted_path_metadata(Path(path), directory=directory)
        outcome = "accept"
    except macos_capability.ProbeFailure:
        outcome = "REFUSE"
    except BaseException as error:
        outcome = "error:" + type(error).__name__
    emit("  real _trusted_path_metadata(directory=" + str(directory) + ")=" + outcome)


def diagnostic_target(label, path, directory, emit):
    emit("diag target " + label + " path=" + ascii(str(path)))
    try:
        print_walk(Path(path), directory, emit)
        diagnostic_trust_line(path, directory, emit)
    except BaseException as error:
        emit("  diagnostic_error=" + type(error).__name__)


def diagnostic_lstat_chain(raw, emit):
    emit("diag lstat chain " + ascii(str(raw)))
    try:
        components = ancestor_components(raw)
    except BaseException as error:
        emit("  diagnostic_error=" + type(error).__name__)
        return
    for component in components:
        try:
            metadata = component.lstat()
        except OSError as error:
            emit("  " + ascii(str(component)) + " lstat_error=" + type(error).__name__)
            continue
        line = (
            "  "
            + ascii(str(component))
            + " type="
            + file_type_text(metadata)
            + " uid="
            + str(metadata.st_uid)
            + " gid="
            + str(metadata.st_gid)
            + " mode="
            + mode_text(metadata)
        )
        if stat.S_ISLNK(metadata.st_mode):
            try:
                line += " target=" + ascii(os.readlink(str(component)))
            except OSError as error:
                line += " readlink_error=" + type(error).__name__
        emit(line)


def diagnostic_query_value(query):
    if query is None or query.returncode != 0 or query.stderr:
        return None
    if not query.stdout.endswith(b"\n") or query.stdout.count(b"\n") != 1:
        return None
    try:
        value = query.stdout[:-1].decode("ascii")
    except UnicodeDecodeError:
        return None
    return value or None


def discover_clt_pythons(root):
    pattern = os.path.join(glob.escape(root), CLT_PYTHON_GLOB_RELATIVE)
    return sorted(glob.glob(pattern))


CLT_INTERPRETER_PROGRAM = "\n".join(
    (
        "import os, sys",
        "sys.path.insert(0, sys.argv[1])",
        "print('clt-interpreter-executable=' + ascii(sys.executable))",
        "try:",
        "    import macos_capability",
        "    real_geteuid = os.geteuid",
        "    os.geteuid = lambda: 0",
        "    try:",
        "        resolved = macos_capability._resolve_trusted_toolchain()",
        "    finally:",
        "        os.geteuid = real_geteuid",
        "    print('clt-interpreter-result=accept ' + ' '.join(",
        "        key + '=' + ascii(resolved[key])",
        "        for key in ('python', 'clang', 'sdk', 'linker', 'developer_directory')))",
        "except BaseException as error:",
        "    if type(error).__name__ == 'ProbeFailure':",
        "        print('clt-interpreter-result=refuse')",
        "    else:",
        "        print('clt-interpreter-result=error:' + type(error).__name__)",
    )
)


def diagnostic_clt_query(label, argv, env, emit):
    emit("diag clt query " + label + " DEVELOPER_DIR=" + ascii(env["DEVELOPER_DIR"]))
    query = run_query(argv, env, emit)
    if query is None:
        emit("  query did not run")
        return None
    emit("  returncode=" + str(query.returncode))
    emit("  stdout=" + preview(query.stdout))
    emit("  stderr=" + preview(query.stderr))
    try:
        value = macos_capability._read_tool_path(query)
        emit("  _read_tool_path would accept value=" + ascii(value))
        return value
    except macos_capability.ProbeFailure:
        emit("  _read_tool_path would REFUSE")
        return None


def clt_linker_probe(clang, sdk, root, env, emit):
    emit("diag clt linker clang=" + ascii(str(clang)) + " sdk=" + ascii(str(sdk)) + " DEVELOPER_DIR=" + ascii(root))
    query = run_query([clang, "-isysroot", sdk, "-print-prog-name=ld"], env, emit)
    if query is None:
        emit("  diag clt linker query did not run")
        return
    emit("  diag clt linker returncode=" + str(query.returncode))
    emit("  diag clt linker stdout=" + preview(query.stdout))
    emit("  diag clt linker stderr=" + preview(query.stderr))
    try:
        value = macos_capability._read_tool_path(query)
        emit("  diag clt linker _read_tool_path would accept value=" + ascii(value))
    except macos_capability.ProbeFailure:
        emit("  diag clt linker _read_tool_path would REFUSE")
        return
    if value.startswith("/"):
        try:
            diagnostic_target("clt_linker", value, False, emit)
        except BaseException as error:
            emit("  diagnostic_error=" + type(error).__name__)
    else:
        emit("  diag clt linker value is not an absolute path; ancestor walk skipped")
    try:
        accepted = macos_capability._resolve_toolchain_file(value, Path(root), kind="linker")
        emit("  diag clt linker real _resolve_toolchain_file(kind=linker)=accept " + ascii(str(accepted)))
    except macos_capability.ProbeFailure:
        emit("  diag clt linker real _resolve_toolchain_file(kind=linker)=REFUSE")
    except BaseException as error:
        emit("  diag clt linker real _resolve_toolchain_file(kind=linker)=error:" + type(error).__name__)


def clt_interpreter_probe(pythons, query_env, emit):
    chosen = [
        python for python in pythons if macos_capability.PYTHON_CLT_LAYOUT.fullmatch(Path(python).as_posix())
    ]
    if not chosen:
        emit("diag clt interpreter skipped: no discovered python fits PYTHON_CLT_LAYOUT")
        return
    capability_directory = os.path.dirname(os.path.abspath(macos_capability.__file__))
    for python in chosen:
        emit("diag clt interpreter python=" + ascii(str(python)) + " capability_dir=" + ascii(capability_directory))
        child = run_child([python, "-B", "-I", "-c", CLT_INTERPRETER_PROGRAM, capability_directory], dict(query_env), emit)
        if child is None:
            emit("  diag clt interpreter child did not run")
            continue
        emit("  diag clt interpreter returncode=" + str(child.returncode))
        emit("  diag clt interpreter stdout=" + preview(child.stdout, CHILD_OUTPUT_PREVIEW_BYTES))
        emit("  diag clt interpreter stderr=" + preview(child.stderr))


def clt_diagnostics(emit, query_env):
    root = CLT_ROOT
    try:
        emit("diag clt root=" + ascii(root) + " exists=" + str(os.path.lexists(root)))
    except BaseException as error:
        emit("  diagnostic_error=" + type(error).__name__)
    try:
        diagnostic_target("clt_root", root, True, emit)
    except BaseException as error:
        emit("  diagnostic_error=" + type(error).__name__)
    fixed = (
        ("clt_clang", os.path.join(root, CLT_CLANG_RELATIVE), False),
        ("clt_sdk", os.path.join(root, CLT_SDK_RELATIVE), True),
    )
    for label, path, directory in fixed:
        try:
            if os.path.lexists(path):
                diagnostic_target(label, path, directory, emit)
            else:
                emit("diag target " + label + " path=" + ascii(path) + " absent")
        except BaseException as error:
            emit("  diagnostic_error=" + type(error).__name__)
    pythons = []
    try:
        pythons = discover_clt_pythons(root)
        emit("diag clt python3 candidates=" + str(len(pythons)))
        for index, python in enumerate(pythons):
            try:
                diagnostic_target("clt_python_" + str(index), python, False, emit)
                text = Path(python).as_posix()
                emit("  matches PYTHON_CLT_LAYOUT=" + str(bool(macos_capability.PYTHON_CLT_LAYOUT.fullmatch(text))))
            except BaseException as error:
                emit("  diagnostic_error=" + type(error).__name__)
    except BaseException as error:
        emit("  diagnostic_error=" + type(error).__name__)
    try:
        env = dict(query_env)
        env["DEVELOPER_DIR"] = root
    except BaseException as error:
        emit("  diagnostic_error=" + type(error).__name__)
        return
    queries = (
        ("find_clang", ["/usr/bin/xcrun", "--find", "clang"]),
        ("show_sdk_path", ["/usr/bin/xcrun", "--show-sdk-path"]),
    )
    values = {}
    for label, argv in queries:
        try:
            values[label] = diagnostic_clt_query(label, argv, env, emit)
        except BaseException as error:
            emit("  diagnostic_error=" + type(error).__name__)
    try:
        diagnostic_lstat_chain(USR_BIN_PYTHON3, emit)
    except BaseException as error:
        emit("  diagnostic_error=" + type(error).__name__)
    try:
        clang = values.get("find_clang")
        sdk = values.get("show_sdk_path")
        if clang is None or sdk is None:
            emit("diag clt linker skipped: clang or sdk path not accepted")
        else:
            clt_linker_probe(clang, sdk, root, env, emit)
    except BaseException as error:
        emit("  diagnostic_error=" + type(error).__name__)
    try:
        clt_interpreter_probe(pythons, query_env, emit)
    except BaseException as error:
        emit("  diagnostic_error=" + type(error).__name__)


def unconditional_diagnostics(emit):
    emit(DIAGNOSTIC_BANNER + " begin (diagnostic only; changes no verdict)")
    try:
        target = os.path.realpath(sys.executable)
        diagnostic_target("python_realpath", target, False, emit)
        diagnostic_lstat_chain(sys.executable, emit)
        text = Path(target).as_posix()
        emit("diag python realpath matches PYTHON_XCODE_LAYOUT=" + str(bool(macos_capability.PYTHON_XCODE_LAYOUT.fullmatch(text))))
        emit("diag python realpath matches PYTHON_CLT_LAYOUT=" + str(bool(macos_capability.PYTHON_CLT_LAYOUT.fullmatch(text))))
    except BaseException as error:
        emit("diagnostic_error=" + type(error).__name__)
    query_env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
    }
    try:
        selected = diagnostic_query_value(run_query(["/usr/bin/xcode-select", "-p"], query_env, emit))
        if selected is None:
            emit("diag xcode-select directory unavailable")
        else:
            diagnostic_target("xcode_select_directory", selected, True, emit)
            env = dict(query_env)
            env["DEVELOPER_DIR"] = selected
            clang = diagnostic_query_value(
                run_query(["/usr/bin/xcrun", "--sdk", "macosx", "--find", "clang"], env, emit)
            )
            sdk = diagnostic_query_value(
                run_query(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], env, emit)
            )
            if clang is None:
                emit("diag clang path unavailable")
            else:
                diagnostic_target("clang_path", clang, False, emit)
            if sdk is None:
                emit("diag sdk path unavailable")
            else:
                diagnostic_target("sdk_path", sdk, True, emit)
    except BaseException as error:
        emit("diagnostic_error=" + type(error).__name__)
    try:
        clt_diagnostics(emit, query_env)
    except BaseException as error:
        emit("diagnostic_error=" + type(error).__name__)
    emit(DIAGNOSTIC_BANNER + " end")


def build_report(emit):
    stages = []
    resolved = {}
    try:
        collect_stages(emit, stages, resolved)
    except BaseException as error:
        emit("report_error=" + type(error).__name__)
        stages.append(("report_error", REFUSE, type(error).__name__))
    stages.append(cross_check(stages, resolved, emit))
    try:
        unconditional_diagnostics(emit)
    except BaseException as error:
        emit("diagnostic_error=" + type(error).__name__)
    return stages


def safe_line(line):
    if line.isascii() and line.isprintable() and not line.startswith("::"):
        return line
    return "unsafe_line_suppressed=" + ascii(line)


def main():
    lines = []
    stages = []
    try:
        stages = build_report(lines.append)
    except BaseException as error:
        lines.append("report_error=" + type(error).__name__)
        stages.append(("report_error", REFUSE, type(error).__name__))
    drift = any(state == DRIFT for _, state, _ in stages) or any(line.startswith("drift:") for line in lines)
    for line in lines:
        print(safe_line(line))
    print("stages " + " ".join(name + "=" + state for name, state, _ in stages))
    print(safe_line(verdict_line(stages)))
    print("drift_detected=" + ("yes" if drift else "no"))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
