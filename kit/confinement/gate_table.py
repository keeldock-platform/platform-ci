"""Operating-system neutral project gate table shared by the Linux and Windows source admission.

The table holds argv templates only. A caller substitutes the tool paths and the project root for
its own operating system with render(), so the gate set, its order and every flag are defined once.
Placeholders are the exact strings {cargo}, {node} and {npm} for a whole argument, and a leading
{project} for a path below the project root with forward slashes between the parts. Any other brace
in a template or a rendered value is refused.
"""

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path


SCHEMA_VERSION = 1
API_FEATURE_NAME = "dev-uat-policy-import"
RUST_GATE_NAMES = (
    "format", "clippy", "workspace_tests", "api_tests", "api_feature_clippy", "api_feature_tests",
    "mock_tests", "conformance_tests",
)
PARSER_GATE_NAMES = ("parser_format", "parser_clippy", "parser_replay")
NODE_GATE_NAMES = (
    "node_dependency_prepare", "node_dependency_audit", "typescript_typecheck", "typescript_tests",
)
GATES = RUST_GATE_NAMES + PARSER_GATE_NAMES + NODE_GATE_NAMES
RUNTIME_GATE_NAMES = ("runtime_format", "runtime_clippy", "runtime_tests")
RUNTIME_ROOT_FILES = ("runtime/Cargo.toml", "runtime/Cargo.lock")
REQUIRED_GATES = len(GATES)
MAX_GATES = REQUIRED_GATES + len(RUNTIME_GATE_NAMES)
CARGO = "{cargo}"
NODE = "{node}"
NPM = "{npm}"
PROJECT = "{project}"
WORKSPACE_MANIFEST = PROJECT + "/Cargo.toml"
MAX_ARGUMENT_BYTES = 4096
NAME_RE = re.compile(r"[a-z][a-z_]{0,62}\Z")
EMIT_SELECTIONS = ("base", "runtime")


class GateTableRefusal(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _manifest(directory):
    return PROJECT + "/" + directory + "/Cargo.toml"


def _node(*arguments):
    return (NODE, NPM) + arguments


def _format(manifest):
    return (CARGO, "--locked", "--offline", "fmt", "--manifest-path", manifest, "--all", "--", "--check")


def _clippy(manifest, *scope):
    return (CARGO, "clippy", "--offline", "--manifest-path", manifest) + scope + (
        "--locked", "--", "-D", "warnings",
    )


def _test(manifest, *scope):
    return (CARGO, "test", "--offline", "--manifest-path", manifest) + scope + ("--locked",)


def _table():
    workspace = WORKSPACE_MANIFEST
    api = _manifest("crates/host/api")
    fuzz = _manifest("fuzz")
    feature = ("--features", API_FEATURE_NAME)
    return (
        ("format", _format(workspace)),
        ("clippy", _clippy(workspace, "--workspace", "--all-targets")),
        ("workspace_tests", _test(workspace, "--workspace", "--all-targets")),
        ("api_tests", _test(api, "--all-targets")),
        ("api_feature_clippy", _clippy(api, "--all-targets", *feature)),
        ("api_feature_tests", _test(api, "--all-targets", *feature)),
        ("mock_tests", _test(_manifest("crates/host/mock"), "--all-targets")),
        ("conformance_tests", _test(_manifest("crates/host/conformance"), "--all-targets")),
        ("parser_format", _format(fuzz)),
        ("parser_clippy", _clippy(fuzz, "--all-targets")),
        ("parser_replay", (CARGO, "run", "--locked", "--offline", "--manifest-path", fuzz)),
        ("node_dependency_prepare", _node(
            "--offline", "--ignore-scripts", "--audit=false", "--fund=false", "ci",
            "--workspaces=true", "--include-workspace-root",
        )),
        ("node_dependency_audit", _node(
            "--offline", "ls", "--all", "--workspaces=true", "--include-workspace-root",
        )),
        ("typescript_typecheck", _node("--offline", "run", "typecheck", "--workspaces", "--ignore-scripts")),
        ("typescript_tests", _node("--offline", "run", "test", "--workspaces", "--ignore-scripts")),
    )


def _runtime_table():
    runtime = _manifest("runtime")
    return (
        ("runtime_format", _format(runtime)),
        ("runtime_clippy", _clippy(runtime, "--workspace", "--all-targets")),
        ("runtime_tests", _test(runtime, "--workspace", "--all-targets")),
    )


def gate_templates(include_runtime):
    if type(include_runtime) is not bool:
        raise GateTableRefusal("selection")
    table = _table()
    if include_runtime:
        table = table + _runtime_table()
    return table


def selected_gate_names(include_runtime):
    return tuple(name for name, unused_argv in gate_templates(include_runtime))


def _text(value, reason):
    if (type(value) is not str or not value or len(value.encode("utf-8", "replace")) > MAX_ARGUMENT_BYTES
            or "\x00" in value or "{" in value or "}" in value):
        raise GateTableRefusal(reason)
    return value


def render(templates, project, cargo, node, npm, separator="/"):
    """Return ((name, argv), ...) with the tool paths and project root substituted."""
    if type(separator) is not str or separator not in ("/", "\\"):
        raise GateTableRefusal("separator")
    values = {
        CARGO: _text(cargo, "tool"),
        NODE: _text(node, "tool"),
        NPM: _text(npm, "tool"),
    }
    root = _text(project, "project")
    seen = set()
    rendered = []
    for entry in templates:
        if type(entry) is not tuple or len(entry) != 2:
            raise GateTableRefusal("entry")
        name, argv = entry
        if type(name) is not str or NAME_RE.fullmatch(name) is None or name in seen:
            raise GateTableRefusal("entry")
        seen.add(name)
        if type(argv) is not tuple or not argv:
            raise GateTableRefusal("entry")
        arguments = []
        for item in argv:
            if type(item) is not str or not item:
                raise GateTableRefusal("entry")
            if item in values:
                arguments.append(values[item])
            elif item == PROJECT or item.startswith(PROJECT + "/"):
                tail = item[len(PROJECT):]
                if "{" in tail or "}" in tail or "\\" in tail or "//" in tail or ".." in tail:
                    raise GateTableRefusal("entry")
                arguments.append(root + tail.replace("/", separator))
            else:
                arguments.append(_text(item, "entry"))
        rendered.append((name, tuple(arguments)))
    return tuple(rendered)


def emit_json(include_runtime):
    table = [{"name": name, "argv": list(argv)} for name, argv in gate_templates(include_runtime)]
    return json.dumps(
        {"schema_version": SCHEMA_VERSION, "gates": table}, sort_keys=True, separators=(",", ":"),
    )


MANIFEST_WORKSPACE_PATHS = ("packages/host-api", "packages/kernel-i18n")
MANIFEST_GROUPS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
MANIFEST_PACKAGE_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$")
MANIFEST_VERSION_RE = re.compile(r"^[0-9A-Za-z.*^~<>=|+ -]{1,128}$")
MANIFEST_WORKSPACE_VERSION_RE = re.compile(r"workspace:(?:\*|\^|~|[0-9][0-9A-Za-z.+-]*)")
MANIFEST_ROOT_OVERRIDES = {"lightningcss": "1.33.0"}
MAX_PACKAGE_JSON_BYTES = 256 * 1024
OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)


def manifest_json(path):
    descriptor = -1
    try:
        descriptor = os.open(path, OPEN_FLAGS)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PACKAGE_JSON_BYTES:
            raise GateTableRefusal("lock")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            payload = source.read(MAX_PACKAGE_JSON_BYTES + 1)
    except OSError:
        raise GateTableRefusal("lock") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not payload or len(payload) > MAX_PACKAGE_JSON_BYTES:
        raise GateTableRefusal("lock")

    def unique_pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        return json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=unique_pairs,
            parse_constant=lambda unused: (_ for _ in ()).throw(ValueError()),
        )
    except BaseException:
        raise GateTableRefusal("lock") from None


def _manifest_root_overrides(root):
    if "overrides" not in root:
        return None
    value = root["overrides"]
    if (type(value) is not dict or set(value) != set(MANIFEST_ROOT_OVERRIDES)
            or any(type(item) is not str or item != MANIFEST_ROOT_OVERRIDES[name] for name, item in value.items())):
        raise GateTableRefusal("lock")
    return dict(value)


def manifest_digest(source_root):
    root = manifest_json(Path(source_root) / "package.json")
    if (type(root) is not dict or type(root.get("name")) is not str
            or type(root.get("version")) is not str
            or any(key in root for key in ("resolutions", "bundleDependencies", "bundledDependencies"))):
        raise GateTableRefusal("lock")
    workspaces = root.get("workspaces")
    if type(workspaces) is dict:
        if set(workspaces) != {"packages"}:
            raise GateTableRefusal("lock")
        workspaces = workspaces.get("packages")
    if (type(workspaces) is not list or len(workspaces) != 1
            or workspaces[0] != "packages/*"):
        raise GateTableRefusal("lock")
    root_expected = {"name": root["name"], "version": root["version"], "workspaces": workspaces}
    for group in MANIFEST_GROUPS:
        if group in root:
            root_expected[group] = root[group]
    overrides = _manifest_root_overrides(root)
    if overrides is not None:
        root_expected["overrides"] = overrides
    workspace_paths = []
    for workspace_path in MANIFEST_WORKSPACE_PATHS:
        if any(pattern == workspace_path or pattern == "packages/*" and workspace_path.startswith("packages/")
               for pattern in workspaces):
            workspace_paths.append(workspace_path)
    if len(workspace_paths) != len(MANIFEST_WORKSPACE_PATHS):
        raise GateTableRefusal("lock")
    workspace_manifests = []
    for workspace_path in workspace_paths:
        package = manifest_json(Path(source_root) / workspace_path / "package.json")
        if (type(package) is not dict or type(package.get("name")) is not str
                or type(package.get("version")) is not str
                or any(key in package for key in ("overrides", "resolutions", "bundleDependencies", "bundledDependencies"))):
            raise GateTableRefusal("lock")
        workspace_expected = {"path": workspace_path, "name": package["name"], "version": package["version"]}
        for group in MANIFEST_GROUPS:
            if group in package:
                workspace_expected[group] = package[group]
        workspace_manifests.append(workspace_expected)
    workspace_names = {item["name"] for item in workspace_manifests}
    for manifest in [root_expected] + workspace_manifests:
        for group in MANIFEST_GROUPS:
            dependencies = manifest.get(group, {})
            if type(dependencies) is not dict or len(dependencies) > 512:
                raise GateTableRefusal("lock")
            for name, spec in dependencies.items():
                if (type(name) is not str or len(name) > 214 or not MANIFEST_PACKAGE_RE.fullmatch(name)
                        or ".." in name or type(spec) is not str or len(spec) > 128):
                    raise GateTableRefusal("lock")
                if name in workspace_names and spec.startswith("workspace:"):
                    if MANIFEST_WORKSPACE_VERSION_RE.fullmatch(spec) is None:
                        raise GateTableRefusal("lock")
                elif not MANIFEST_VERSION_RE.fullmatch(spec):
                    raise GateTableRefusal("lock")
    expected = {"root": root_expected, "workspaces": workspace_manifests}
    try:
        encoded = json.dumps(
            expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
    except BaseException:
        raise GateTableRefusal("lock") from None
    if len(encoded) > 256 * 1024:
        raise GateTableRefusal("lock")
    return hashlib.sha256(encoded).hexdigest()


def main(arguments=None):
    actual = sys.argv[1:] if arguments is None else list(arguments)
    if len(actual) == 2 and actual[0] == "emit" and actual[1] in EMIT_SELECTIONS:
        sys.stdout.write(emit_json(actual[1] == "runtime") + "\n")
        return 0
    if len(actual) == 3 and actual[0] == "manifest-digest" and actual[1] == "--root":
        try:
            digest = manifest_digest(actual[2])
        except GateTableRefusal:
            sys.stdout.write("gate-table=refused reason=lock\n")
            return 1
        sys.stdout.write(digest + "\n")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
