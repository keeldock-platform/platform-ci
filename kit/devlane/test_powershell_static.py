"""Static PowerShell syntax guard for hosts where pwsh cannot run reliably."""

import re
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HASH = chr(35)
LEADING_OPERATOR = re.compile(
    r"^(?:-(?:or|and|xor|eq|ne|gt|ge|lt|le|match|notmatch|like|notlike|contains|"
    r"notcontains|in|notin|replace|join|split|f|is|isnot|as|band|bor|bxor|shl|shr)\b|[|+])",
    re.IGNORECASE,
)
LEADING_METHOD = re.compile(r"^\.[A-Za-z_][A-Za-z0-9_]*\s*(?:\(|$)")
JOB_START = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(?:" + re.escape(HASH) + r".*)?$")
STEP_START = re.compile(r"^ {6}-\s+")
SHELL_VALUE = re.compile(r"^\s*shell:\s*[\"']?([A-Za-z0-9_-]+)", re.IGNORECASE)
RUN_VALUE = re.compile(r"^(?P<indent> *)run:\s*(?P<value>.*)$")


@dataclass(frozen=True)
class PowerShellSource:
    name: str
    text: str
    first_line: int = 1


def _shell_kind(value):
    token = value.strip().split(None, 1)[0].strip("\"'").lower() if value.strip() else ""
    return token if token in {"pwsh", "powershell"} else ""


def _workflow_powershell_blocks(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    jobs_index = next((index for index, line in enumerate(lines) if line == "jobs:"), None)
    if jobs_index is None:
        return []

    workflow_default = ""
    for index, line in enumerate(lines[:jobs_index]):
        if line == "defaults:":
            for nested in lines[index + 1:jobs_index]:
                if nested and len(nested) - len(nested.lstrip()) <= 0:
                    break
                if nested == "  run:":
                    continue
                if nested.startswith("    shell:"):
                    match = SHELL_VALUE.match(nested)
                    workflow_default = _shell_kind(match.group(1)) if match else ""

    starts = [index for index in range(jobs_index + 1, len(lines)) if JOB_START.match(lines[index])]
    blocks = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        job_lines = lines[start + 1:end]
        default_shell = workflow_default
        for index, line in enumerate(job_lines):
            if line != "    defaults:":
                continue
            for nested in job_lines[index + 1:]:
                if nested and len(nested) - len(nested.lstrip()) <= 4:
                    break
                if nested.startswith("        shell:"):
                    match = SHELL_VALUE.match(nested)
                    default_shell = _shell_kind(match.group(1)) if match else ""

        step_starts = [index for index, line in enumerate(job_lines) if STEP_START.match(line)]
        for step_position, step_start in enumerate(step_starts):
            step_end = step_starts[step_position + 1] if step_position + 1 < len(step_starts) else len(job_lines)
            step_lines = job_lines[step_start:step_end]
            explicit_shell = ""
            for line in step_lines:
                if len(line) - len(line.lstrip()) == 8 and line.lstrip().startswith("shell:"):
                    match = SHELL_VALUE.match(line)
                    explicit_shell = _shell_kind(match.group(1)) if match else ""
                    break
            shell = explicit_shell or default_shell
            if not shell:
                continue
            for line_index, line in enumerate(step_lines):
                match = RUN_VALUE.match(line)
                if not match:
                    continue
                value = match.group("value")
                run_indent = len(match.group("indent"))
                if value.startswith(("|", ">")):
                    body_end = line_index + 1
                    while body_end < len(step_lines):
                        candidate = step_lines[body_end]
                        if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= run_indent:
                            break
                        body_end += 1
                    body = step_lines[line_index + 1:body_end]
                    nonblank_indents = [len(item) - len(item.lstrip()) for item in body if item.strip()]
                    content_indent = min(nonblank_indents, default=run_indent + 1)
                    content = "\n".join(item[content_indent:] if item.strip() else "" for item in body)
                    first_line = start + 1 + step_start + line_index + 2
                    blocks.append(PowerShellSource(f"{path.relative_to(ROOT)} run block", content, first_line))
                elif _shell_kind(shell):
                    first_line = start + 1 + step_start + line_index + 1
                    blocks.append(PowerShellSource(f"{path.relative_to(ROOT)} run line", value, first_line))
    return blocks


def powershell_sources(root=ROOT):
    sources = [
        PowerShellSource(str(path.relative_to(root)), path.read_text(encoding="utf-8"))
        for path in sorted(root.rglob("*.ps1"))
        if ".git" not in path.parts and "node_modules" not in path.parts
    ]
    workflow_dir = root / ".github/workflows"
    for path in sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml"))):
        sources.extend(_workflow_powershell_blocks(path))
    return sources


def _masked_code(text):
    """Mask strings, comments, and here-string bodies while preserving line numbers."""
    output = []
    quote = None
    quote_line = None
    here_end = None
    here_line = None
    for line_number, line in enumerate(text.splitlines(), 1):
        masked = [" "] * len(line)
        if here_end is not None:
            if line.startswith(here_end):
                tail = line[len(here_end):]
                if not tail.strip() or tail.lstrip().startswith(HASH):
                    here_end = None
                    here_line = None
            output.append("".join(masked))
            continue

        index = 0
        while index < len(line):
            char = line[index]
            if quote is not None:
                if quote == "'" and char == "'" and index + 1 < len(line) and line[index + 1] == "'":
                    index += 2
                    continue
                if quote == '"' and char == "`":
                    index += 2
                    continue
                if char == quote:
                    quote = None
                    quote_line = None
                index += 1
                continue
            if char == HASH:
                break
            if line[index:index + 2] in ("@'", '@"') and not line[index + 2:].strip():
                here_end = "'@" if line[index:index + 2] == "@'" else '"@'
                here_line = line_number
                index = len(line)
                break
            if char in ("'", '"'):
                quote = char
                quote_line = line_number
                index += 1
                continue
            masked[index] = char
            index += 1
        output.append("".join(masked))

    hazards = []
    if here_end is not None:
        hazards.append((here_line, "unclosed-here-string"))
    if quote is not None:
        hazards.append((quote_line, "unclosed-string"))
    return output, hazards


def syntax_hazards(text):
    masked_lines, hazards = _masked_code(text)
    source_lines = text.splitlines()
    for line_number, line in enumerate(source_lines, 1):
        stripped = line.lstrip().lstrip("\ufeff")
        if not masked_lines[line_number - 1].strip():
            continue
        if LEADING_OPERATOR.match(stripped):
            hazards.append((line_number, "line-leading-operator"))
        elif LEADING_METHOD.match(stripped):
            hazards.append((line_number, "line-leading-method"))

    delimiters = {"}": "{", ")": "(", "]": "["}
    opening = set(delimiters.values())
    stack = []
    for line_number, line in enumerate(masked_lines, 1):
        for column, char in enumerate(line):
            if char in opening:
                stack.append((char, line_number, column + 1))
            elif char in delimiters:
                if not stack or stack[-1][0] != delimiters[char]:
                    hazards.append((line_number, "unbalanced-delimiter"))
                else:
                    stack.pop()
    hazards.extend((line_number, "unbalanced-delimiter") for _char, line_number, _column in stack)
    return sorted(set(hazards))


class PowerShellStaticTests(unittest.TestCase):
    def test_repository_scripts_and_workflow_blocks_have_no_static_parse_hazards(self):
        sources = powershell_sources()
        self.assertTrue(sources, "PowerShell source inventory is empty")
        workflow_sources = [source for source in sources if source.name.startswith(".github/workflows/")]
        self.assertGreaterEqual(len(workflow_sources), 50)
        workflow_names = {source.name for source in workflow_sources}
        self.assertIn(".github/workflows/devlane-encrypted.yml run block", workflow_names)
        self.assertIn(".github/workflows/windows-confinement.yml run block", workflow_names)
        failures = []
        for source in sources:
            for line_number, hazard in syntax_hazards(source.text):
                failures.append(f"{source.name}:{source.first_line + line_number - 1}: {hazard}")
        self.assertEqual(failures, [])

    def test_checker_rejects_line_leading_operators_methods_and_open_constructs(self):
        sample = "if ($x -eq 1)\n    -or $y -eq 2\n| ForEach-Object {}\n.Trim()\nif ($open) {\n$x = @'\nbody\n"
        hazards = {hazard for _line, hazard in syntax_hazards(sample)}
        self.assertIn("line-leading-operator", hazards)
        self.assertIn("line-leading-method", hazards)
        self.assertIn("unclosed-here-string", hazards)
        self.assertIn("unbalanced-delimiter", hazards)
        self.assertEqual(syntax_hazards("$value = @'\ntext\n'@\n"), [])
        self.assertEqual(syntax_hazards('"value" | Add-Content\n'), [])

    def test_windows_crypto_target_acl_errors_emit_only_fixed_refusals(self):
        workflow = ROOT / ".github/workflows/devlane-encrypted.yml"
        sources = _workflow_powershell_blocks(workflow)
        source = next(item for item in sources
                      if "control-python-deps" in item.text and "Protect-PrivateDirectory" in item.text)
        script = source.text
        target_assignment = script.index("$cryptoTarget = Join-Path")
        start = script.rfind("try {", 0, target_assignment)
        end = script.index("$sealOutput =", target_assignment)
        target_block = script[start:end]
        catches = re.findall(r"catch\s*\{([^{}]*)\}", target_block)
        self.assertEqual(len(catches), 1)
        self.assertEqual(
            [[line.strip() for line in body.splitlines() if line.strip()] for body in catches],
            [
                ["Write-Output 'devlane_crypto_refusal=crypto-target-invalid'",
                 "Refuse-Bootstrap 'crypto-dependency-seal-failed'"],
            ],
        )
        self.assertNotRegex(target_block, r"(?i)Write-Error|Write-Host|throw\b")
        self.assertIn("Join-Path -Path $runRoot -ChildPath 'control-python-deps' -ErrorAction Stop", target_block)
        self.assertIn("New-Item -ItemType Directory -Path $cryptoTarget -ErrorAction Stop", target_block)

        protect_start = script.index("$runRoot = Join-Path -Path $env:RUNNER_TEMP")
        protect_end = script.index("$started = Join-Path", protect_start)
        protect_block = script[protect_start:protect_end]
        self.assertIn(
            "Join-Path -Path $env:RUNNER_TEMP -ChildPath ('devlane-' + $env:CI_RUN_ID) -ErrorAction Stop",
            protect_block,
        )
        self.assertIn("if (Test-Path -LiteralPath $runRoot -ErrorAction Stop)", protect_block)
        self.assertLess(
            protect_block.index("Write-Output 'devlane_crypto_refusal=crypto-target-invalid'"),
            protect_block.index("New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop"),
        )
        self.assertIn("New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop", protect_block)
        self.assertIn("$env:RUN_ROOT = $runRoot", protect_block)
        self.assertIn(
            "Add-Content -LiteralPath $env:GITHUB_ENV -Value ('RUN_ROOT=' + $runRoot) -Encoding utf8",
            protect_block,
        )
        self.assertLess(
            protect_block.index("New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop"),
            protect_block.index("$env:RUN_ROOT = $runRoot"),
        )
        self.assertLess(
            protect_block.index("Add-Content -LiteralPath $env:GITHUB_ENV"),
            protect_block.index("Protect-PrivateDirectory $runRoot $runnerSid"),
        )
        self.assertLess(
            protect_block.index("Add-Content -LiteralPath $env:GITHUB_ENV"),
            protect_block.index("Write-Output 'devlane_crypto_state=run-root-exported'"),
        )
        self.assertIn(
            "[System.IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]$Path, $security)",
            script,
        )
        self.assertNotIn("Set-Acl -LiteralPath $Path", script)
        self.assertNotIn("$security.SetOwner(", script)
        self.assertIn("devlane_crypto_acl_failure=operation=", script)
        self.assertRegex(
            protect_block,
            re.compile(
                r"try\s*\{\s*\$runnerSid\s*=.*?\}\s*catch\s*\{", re.DOTALL,
            ),
        )
        self.assertIn("if (-not (Protect-PrivateDirectory $runRoot $runnerSid 'run-root'))", protect_block)
        for line in re.findall(r"Write-Output\s+([^\r\n]+)", protect_block):
            self.assertRegex(line, r"^(?:'devlane_(?:crypto_state=run-root-not-exported|crypto_state=run-root-exported|crypto_refusal=crypto-(?:target-invalid|acl-protection-failed)|deadline_refusal=crypto-dependency-seal-failed|refusal=windows-runner-failed)'|\$script:CryptoAclDiagnostic)\s*\}?$")
        self.assertNotRegex(protect_block, r"(?i)Write-Error|Write-Host|throw\b")
        self.assertIn("$Failure.Exception", script)
        self.assertNotIn("$Failure.Exception.Message", script)
        self.assertRegex(
            protect_block,
            re.compile(
                r"try\s*\{\s*Add-Content -LiteralPath \$env:GITHUB_ENV.*?\}\s*catch\s*\{"
                r".*?Remove-Item -LiteralPath \$runRoot.*?if \(\$removeFailed\) \{\s*"
                r"Write-Output 'devlane_refusal=windows-runner-failed'\s*\}", re.DOTALL,
            ),
        )

        checkout_index = script.index("git -C $env:CI_WORKSPACE checkout --quiet --detach FETCH_HEAD")
        checkout_marker_index = script.index("New-Item -ItemType File -Path $checkoutMarker")
        checkout_state_index = script.index("Write-Output 'devlane_crypto_state=checkout-complete'")
        self.assertLess(checkout_index, checkout_marker_index)
        self.assertLess(checkout_marker_index, checkout_state_index)

        cleanup_source = next(item for item in sources if "windows_precheckout_cleanup=confirmed" in item.text)
        cleanup = cleanup_source.text
        precheckout_start = cleanup.index("if (-not (Test-Path -LiteralPath $checkoutMarker -ErrorAction Stop))")
        precheckout_end = cleanup.index("} else {", precheckout_start)
        precheckout = cleanup[precheckout_start:precheckout_end]
        self.assertIn("Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction Stop", precheckout)
        self.assertNotIn("sandbox_windows.py", precheckout)
        self.assertIn("Write-Output 'devlane_refusal=windows-runner-failed'", cleanup)
        self.assertNotRegex(precheckout, r"(?i)\$_|\$PSItem|Write-Error|Write-Host")


if __name__ == "__main__":
    unittest.main()
