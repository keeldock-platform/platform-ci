"""Operating-system neutral project gate table shared by the Linux and Windows source admission.

The table holds argv templates only. A caller substitutes the tool paths and the project root for
its own operating system with render(), so the gate set, its order and every flag are defined once.
Placeholders are the exact strings {cargo}, {node} and {npm} for a whole argument, and a leading
{project} for a path below the project root with forward slashes between the parts. Any other brace
in a template or a rendered value is refused.
"""

import json
import re
import sys


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


def main(arguments=None):
    actual = sys.argv[1:] if arguments is None else arguments
    if len(actual) != 2 or actual[0] != "emit" or actual[1] not in EMIT_SELECTIONS:
        return 2
    sys.stdout.write(emit_json(actual[1] == "runtime") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
