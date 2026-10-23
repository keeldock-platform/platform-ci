import json
import re
import subprocess


PUBLIC_POOLS = frozenset(("platform", "connect", "workspace", "data"))
SAFE_CHECKS = frozenset(("public-policy", "public-tree"))
CONTROL_SHA_PATTERN = re.compile(r"[a-f0-9]{40}\Z")
MAX_POLICY_BYTES = 2048
MAX_RESULT_BYTES = 2048
MAX_COUNT = 100000
MAX_DURATION_MS = 86400000


class PolicyError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("duplicate-field")
        result[key] = value
    return result


def _reject_constant(value):
    raise PolicyError("invalid-number")


def load_bounded_object(payload, maximum, failure_code):
    if type(payload) is not bytes:
        raise PolicyError("invalid-input-type")
    if len(payload) > maximum:
        raise PolicyError("input-too-large")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except PolicyError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise PolicyError("invalid-json")
    if type(value) is not dict:
        raise PolicyError(failure_code)
    return value


def validate_control_sha(value):
    if type(value) is not str or CONTROL_SHA_PATTERN.fullmatch(value) is None:
        raise PolicyError("control-sha-invalid")
    return value


def verify_git_head(root, expected_sha):
    validate_control_sha(expected_sha)
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=str(root),
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        raise PolicyError("control-head-unavailable")
    actual_sha = result.stdout.strip()
    validate_control_sha(actual_sha)
    if actual_sha != expected_sha:
        raise PolicyError("control-sha-mismatch")
    return actual_sha


def validate_policy_document(value, expected_pool=None):
    if type(value) is not dict or set(value) != {"pool", "schema_version"}:
        raise PolicyError("policy-fields")
    pool = value["pool"]
    if type(pool) is not str or pool not in PUBLIC_POOLS:
        raise PolicyError("policy-pool")
    if expected_pool is not None and (type(expected_pool) is not str or pool != expected_pool):
        raise PolicyError("policy-pool-mismatch")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise PolicyError("policy-version")
    return pool


def load_policy_document(path, expected_pool=None):
    try:
        with open(path, "rb") as source:
            payload = source.read(MAX_POLICY_BYTES + 1)
    except OSError:
        raise PolicyError("policy-unavailable")
    value = load_bounded_object(payload, MAX_POLICY_BYTES, "policy-fields")
    return validate_policy_document(value, expected_pool)


PLATFORM_WORKFLOW_TEMPLATE = """name: public-policy
on:
  push:
    branches:
      - "**"
  pull_request:
  workflow_dispatch:
permissions: {}
jobs:
  policy:
    name: policy-${{ matrix.runner }}
    strategy:
      fail-fast: true
      matrix:
        runner:
          - ubuntu-24.04
          - macos-15
          - windows-2025
    runs-on: ${{ matrix.runner }}
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    env:
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
    steps:
      - name: Fetch public candidate
        run: |
          set -euo pipefail
          if [[ ! "$CI_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
            exit 1
          fi
          if [[ ! "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]; then
            exit 1
          fi
          if [[ ! "$CI_SERVER_URL" =~ ^https://[A-Za-z0-9.-]+$ ]]; then
            exit 1
          fi
          if [[ "$CI_EVENT_NAME" == "pull_request" ]]; then
            if [[ ! "$CI_REF" =~ ^refs/pull/[1-9][0-9]*/merge$ ]]; then
              exit 1
            fi
            requested_ref="$CI_REF"
          else
            if [[ ! "$CI_REF" =~ ^refs/heads/[A-Za-z0-9._/-]+$ ]]; then
              exit 1
            fi
            requested_ref="$CI_REF"
          fi
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$requested_ref" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          actual_sha="$(git rev-parse --verify HEAD 2>/dev/null)"
          if [[ "$actual_sha" != "$CI_SHA" ]]; then
            exit 1
          fi
      - name: Run source-free policy checks
        uses: ./kit/bootstrap
        with:
          pool: platform
"""


LINUX_CONFINEMENT_WORKFLOW_TEMPLATE = """name: linux-confinement
on:
  push:
    branches:
      - "**"
  pull_request:
  workflow_dispatch:
permissions: {}
jobs:
  linux-policy:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    env:
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
      CI_WORKSPACE: ${{ github.workspace }}
    steps:
      - name: Fetch public candidate
        run: |
          set -euo pipefail
          if [[ ! "$CI_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
            exit 1
          fi
          if [[ ! "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]; then
            exit 1
          fi
          if [[ ! "$CI_SERVER_URL" =~ ^https://[A-Za-z0-9.-]+$ ]]; then
            exit 1
          fi
          if [[ "$CI_EVENT_NAME" == "pull_request" ]]; then
            if [[ ! "$CI_REF" =~ ^refs/pull/[1-9][0-9]*/merge$ ]]; then
              exit 1
            fi
            requested_ref="$CI_REF"
          else
            if [[ ! "$CI_REF" =~ ^refs/heads/[A-Za-z0-9._/-]+$ ]]; then
              exit 1
            fi
            requested_ref="$CI_REF"
          fi
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$requested_ref" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          actual_sha="$(git rev-parse --verify HEAD 2>/dev/null)"
          if [[ "$actual_sha" != "$CI_SHA" ]]; then
            exit 1
          fi
      - name: Run unprivileged source-free checks
        run: |
          set -euo pipefail
          python3 -B kit/bootstrap/test_policy.py
          python3 -B kit/bootstrap/test_public_tree.py
          python3 -B kit/confinement/test_linux_harness.py
          python3 -B kit/bootstrap/check_candidate.py --root "$CI_WORKSPACE" --pool platform --sha "$CI_SHA"
  linux-confinement:
    needs: linux-policy
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    defaults:
      run:
        shell: bash
    env:
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
      CI_WORKSPACE: ${{ github.workspace }}
    steps:
      - name: Fetch reviewed main control
        run: |
          set -euo pipefail
          if [[ "$CI_EVENT_NAME" != "workflow_dispatch" || "$CI_REF" != "refs/heads/main" ]]; then
            exit 1
          fi
          if [[ "$CI_REPOSITORY" != "keeldock-platform/platform-ci" || "$CI_SERVER_URL" != "https://github.com" ]]; then
            exit 1
          fi
          if [[ ! "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]; then
            exit 1
          fi
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$CI_REF" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          actual_sha="$(git rev-parse --verify HEAD 2>/dev/null)"
          if [[ "$actual_sha" != "$CI_SHA" ]]; then
            exit 1
          fi
      - name: Check reviewed control tree
        run: |
          set -euo pipefail
          python3 -B kit/bootstrap/test_policy.py
          python3 -B kit/bootstrap/test_public_tree.py
          python3 -B kit/confinement/test_linux_harness.py
          python3 -B kit/bootstrap/check_candidate.py --root "$CI_WORKSPACE" --pool platform --sha "$CI_SHA"
      - name: Run Linux synthetic confinement proof
        run: |
          set -euo pipefail
          sudo -n -- env PYTHONDONTWRITEBYTECODE=1 python3 -B kit/confinement/linux_harness.py --control-sha "$CI_SHA"
"""


MACOS_CAPABILITY_WORKFLOW_TEMPLATE = """name: macos-capability
on:
  workflow_dispatch:
permissions: {}
jobs:
  macos-capability:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: macos-15
    timeout-minutes: 20
    defaults:
      run:
        shell: bash
    env:
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
      CI_WORKSPACE: ${{ github.workspace }}
    steps:
      - name: Fetch reviewed main control
        run: |
          set -euo pipefail
          if [[ "$CI_EVENT_NAME" != "workflow_dispatch" || "$CI_REF" != "refs/heads/main" ]]; then
            exit 1
          fi
          if [[ "$CI_REPOSITORY" != "keeldock-platform/platform-ci" || "$CI_SERVER_URL" != "https://github.com" ]]; then
            exit 1
          fi
          if [[ ! "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]; then
            exit 1
          fi
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$CI_REF" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          actual_sha="$(git rev-parse --verify HEAD 2>/dev/null)"
          if [[ "$actual_sha" != "$CI_SHA" ]]; then
            exit 1
          fi
      - name: Validate source-free control tree
        run: |
          set -euo pipefail
          python3 -B kit/bootstrap/test_policy.py
          python3 -B kit/bootstrap/test_public_tree.py
          python3 -B kit/confinement/test_linux_harness.py
          python3 -B kit/confinement/test_macos_harness.py
          python3 -B kit/confinement/test_macos_capability.py
          python3 -B kit/bootstrap/check_candidate.py --root "$CI_WORKSPACE" --pool platform --sha "$CI_SHA"
      - name: Run source-free capability experiment
        run: |
          set -euo pipefail
          sudo -n -- env \\
            CI_EVENT_NAME="$CI_EVENT_NAME" \\
            CI_REF="$CI_REF" \\
            CI_REPOSITORY="$CI_REPOSITORY" \\
            CI_SERVER_URL="$CI_SERVER_URL" \\
            CI_SHA="$CI_SHA" \\
            GITHUB_ENV="$GITHUB_ENV" \\
            GITHUB_OUTPUT="$GITHUB_OUTPUT" \\
            GITHUB_PATH="$GITHUB_PATH" \\
            GITHUB_STEP_SUMMARY="$GITHUB_STEP_SUMMARY" \\
            PYTHONDONTWRITEBYTECODE=1 \\
            RUNNER_TEMP="$RUNNER_TEMP" \\
            CI_WORKSPACE="$CI_WORKSPACE" \\
            /usr/bin/python3 -B kit/confinement/macos_capability.py --control-sha "$CI_SHA"
"""


CONSUMER_ACTION_PREFIX = "keeldock-platform/platform-ci/kit/bootstrap@"


def consumer_workflow_template(pool, pin):
    if type(pool) is not str or pool not in ("connect", "workspace", "data"):
        raise PolicyError("workflow-pool")
    validate_control_sha(pin)
    return (
        "name: public-policy\n"
        "on:\n"
        "  push:\n"
        "    branches:\n"
        "      - \"**\"\n"
        "  pull_request:\n"
        "  workflow_dispatch:\n"
        "permissions: {}\n"
        "jobs:\n"
        "  policy:\n"
        "    name: policy-${{ matrix.runner }}\n"
        "    strategy:\n"
        "      fail-fast: true\n"
        "      matrix:\n"
        "        runner:\n"
        "          - ubuntu-24.04\n"
        "          - macos-15\n"
        "          - windows-2025\n"
        "    runs-on: ${{ matrix.runner }}\n"
        "    timeout-minutes: 10\n"
        "    env:\n"
        "      CI_SHA: ${{ github.sha }}\n"
        "    steps:\n"
        "      - name: Run source-free policy checks\n"
        "        uses: " + CONSUMER_ACTION_PREFIX + pin + "\n"
        "        with:\n"
        "          pool: " + pool + "\n"
    )


def validate_workflow_text(text, pool, workflow_kind="public-policy"):
    if type(text) is not str or type(pool) is not str or pool not in PUBLIC_POOLS:
        raise PolicyError("workflow-input")
    if workflow_kind == "linux-confinement":
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        expected = LINUX_CONFINEMENT_WORKFLOW_TEMPLATE
    elif workflow_kind == "macos-capability":
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        expected = MACOS_CAPABILITY_WORKFLOW_TEMPLATE
    elif workflow_kind != "public-policy":
        raise PolicyError("workflow-kind")
    elif pool == "platform":
        expected = PLATFORM_WORKFLOW_TEMPLATE
    else:
        pattern = re.compile(
            r"(?m)^        uses: " + re.escape(CONSUMER_ACTION_PREFIX) + r"([a-f0-9]{40})$"
        )
        matches = pattern.findall(text)
        if len(matches) != 1:
            raise PolicyError("workflow-action-ref")
        expected = consumer_workflow_template(pool, matches[0])
    if text != expected:
        raise PolicyError("workflow-template-mismatch")
    return True


def validate_public_result(payload):
    value = load_bounded_object(payload, MAX_RESULT_BYTES, "result-fields")
    required = {"check_id", "status", "passed", "failed", "duration_ms"}
    if set(value) != required:
        raise PolicyError("result-fields")
    check_id = value["check_id"]
    if type(check_id) is not str or check_id not in SAFE_CHECKS:
        raise PolicyError("result-check-id")
    status = value["status"]
    if type(status) is not str or status not in ("passed", "failed", "skipped"):
        raise PolicyError("result-status")
    passed = value["passed"]
    failed = value["failed"]
    if any(type(number) is not int or number < 0 or number > MAX_COUNT for number in (passed, failed)):
        raise PolicyError("result-count")
    if passed + failed > MAX_COUNT:
        raise PolicyError("result-count-total")
    if status == "passed" and failed != 0:
        raise PolicyError("result-status-counts")
    if status == "failed" and failed == 0:
        raise PolicyError("result-status-counts")
    if status == "skipped" and (passed != 0 or failed != 0):
        raise PolicyError("result-status-counts")
    duration = value["duration_ms"]
    if type(duration) is not int or duration < 0 or duration > MAX_DURATION_MS:
        raise PolicyError("result-duration")
    return {
        "check_id": check_id,
        "status": status,
        "passed": passed,
        "failed": failed,
        "duration_ms": duration,
    }


def encode_public_result(payload):
    result = validate_public_result(payload)
    return json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
