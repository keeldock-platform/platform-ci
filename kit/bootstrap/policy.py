import hashlib
import json
import re
import subprocess
from types import MappingProxyType

import policy_baselines
import policy_handoff
import policy_linux
import policy_devlane
import policy_windows
from policy_linux import LINUX_CONFINEMENT_WORKFLOW_TEMPLATE
from policy_windows import WINDOWS_NATIVE_PREFLIGHT_WORKFLOW_TEMPLATE


PUBLIC_POOLS = frozenset(("platform", "connect", "workspace", "data"))
SAFE_CHECKS = frozenset(("public-policy", "public-tree"))
CONTROL_SHA_PATTERN = re.compile(r"[a-f0-9]{40}\Z")
MAX_POLICY_BYTES = 2048
MAX_RESULT_BYTES = 2048
MAX_COUNT = 100000
MAX_DURATION_MS = 86400000
MACOS_SOURCE_READER_ACTION_SHA = "64ab729a6294000f5aa4a4bc0b73d1f32bc45510"
MACOS_SOURCE_READER_WORKFLOW_SHA256 = "e6082feb71990ef2590c791f09927d6a33a277d0bfc60cf2a6ab472ab4f417fc"
MACOS_RULES_SOURCE_READER_WORKFLOW_SHA256 = "c0f145c306a6fff9739496d2a6b352016f4203cb5836807cefc3b862facf8431"
MACOS_RULES_BOOTSTRAP_WORKFLOW_SHA256 = "f56e0c0eb86493c320a72048201d4bfae6bedbec46ee85a8b027674d5cd62d3a"
MACOS_CORE_BOOTSTRAP_WORKFLOW_SHA256 = "b140312f22310633089594255fb17d25aeece02869355e608408098c4e91a4eb"
MACOS_CORE_CONTRACT_WORKFLOW_SHA256 = "e55f8d95bb4666a965912b2832aa68aded0f6c166c324082e61ca599b7bac9cc"
DEVELOPMENT_FEEDBACK_SMOKE_WORKFLOW_SHA256 = "380f71c2f95239492dea787383eadc648077d75ce676d9640186ff3b88dc65a9"


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


PLATFORM_WORKFLOW_TEMPLATE = r"""name: public-policy
run-name: public control=${{ inputs.control_wave_id }}
on:
  workflow_dispatch:
    inputs:
      control_wave_id:
        description: Opaque control-wave identifier
        required: true
        type: string
permissions: {}
concurrency:
  group: public-control-${{ github.ref }}
  cancel-in-progress: false
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
    timeout-minutes: 15
    defaults:
      run:
        shell: bash
    env:
      CI_REPOSITORY: ${{ github.repository }}
      CI_REPOSITORY_ID: ${{ github.repository_id }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
      CI_WORKSPACE: ${{ github.workspace }}
      CI_CONTROL_WAVE_ID: ${{ inputs.control_wave_id }}
    steps:
      - name: Fetch public control and validate manual protected-branch dispatch
        env:
          CI_RUNNER: ${{ runner.os }}
        run: |
          set -euo pipefail
          [[ "$CI_REPOSITORY" == "keeldock-platform/platform-ci" ]]
          [[ "$CI_REPOSITORY_ID" == "1430960557" ]]
          [[ "$CI_SERVER_URL" == "https://github.com" ]]
          [[ "$CI_EVENT_NAME" == "workflow_dispatch" ]]
          [[ "$CI_REF" =~ ^refs/heads/[A-Za-z0-9._/-]{1,200}$ ]]
          [[ "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]
          [[ "$CI_CONTROL_WAVE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$ ]]
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$CI_SHA" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          actual_sha="$(git rev-parse --verify HEAD 2>/dev/null)"
          [[ "$actual_sha" == "$CI_SHA" ]]
          printf 'KD-PLATFORM-CONTROL schema=1 wave-id=%s control-sha=%s run-id=%s attempt=1 runner=%s\n' \
            "$CI_CONTROL_WAVE_ID" "$CI_SHA" "$GITHUB_RUN_ID" "$CI_RUNNER"
      - name: Run source-free platform policy and candidate checks
        uses: ./kit/bootstrap
        with:
          pool: platform
  node-lock-smoke:
    name: node-lock-smoke
    uses: ./.github/workflows/node-lock-smoke.yml
  linux-confinement:
    name: linux-confinement
    uses: ./.github/workflows/linux-confinement.yml
  windows-confinement:
    name: windows-confinement
    uses: ./.github/workflows/windows-confinement.yml
  windows-handoff-synthetic:
    name: windows-handoff-synthetic
    uses: ./.github/workflows/windows-handoff-synthetic.yml
  development-feedback-smoke:
    name: development-feedback-smoke
    permissions:
      actions: read
      checks: read
    uses: ./.github/workflows/development-feedback-smoke.yml
  devlane-synthetic:
    name: devlane-synthetic
    uses: ./.github/workflows/devlane-synthetic.yml
  control-audit:
    name: control-audit
    if: ${{ always() }}
    needs:
      - policy
      - node-lock-smoke
      - linux-confinement
      - windows-confinement
      - windows-handoff-synthetic
      - development-feedback-smoke
      - devlane-synthetic
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      actions: read
      checks: read
      statuses: write
    env:
      CI_REPOSITORY: ${{ github.repository }}
      CI_REPOSITORY_ID: ${{ github.repository_id }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
      CI_CONTROL_WAVE_ID: ${{ inputs.control_wave_id }}
      GITHUB_RUN_ID: ${{ github.run_id }}
      GITHUB_RUN_ATTEMPT: ${{ github.run_attempt }}
    steps:
      - name: Fetch public control and validate manual protected-branch dispatch
        run: |
          set -euo pipefail
          [[ "$CI_REPOSITORY" == "keeldock-platform/platform-ci" ]]
          [[ "$CI_REPOSITORY_ID" == "1430960557" ]]
          [[ "$CI_SERVER_URL" == "https://github.com" ]]
          [[ "$CI_EVENT_NAME" == "workflow_dispatch" ]]
          [[ "$CI_REF" =~ ^refs/heads/[A-Za-z0-9._/-]{1,200}$ ]]
          [[ "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]
          [[ "$CI_CONTROL_WAVE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$ ]]
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$CI_SHA" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          actual_sha="$(git rev-parse --verify HEAD 2>/dev/null)"
          [[ "$actual_sha" == "$CI_SHA" ]]
      - name: Audit the exact 18-job control graph
        env:
          GITHUB_TOKEN: ${{ github.token }}
          DEVLANE_CONTROL_EVIDENCE_PATH: ${{ runner.temp }}/devlane-control-evidence/permit.json
        run: python3 -B kit/devlane/control_audit.py
      - name: Save exact source-free control evidence
        if: ${{ github.ref == 'refs/heads/main' }}
        uses: actions/cache/save@3edfce9056124e459a23f683a21433670d47daca
        with:
          path: ${{ runner.temp }}/devlane-control-evidence/permit.json
          key: devlane-control-v1-${{ github.run_id }}
"""
MACOS_CAPABILITY_WORKFLOW_TEMPLATE = """name: macos-capability
on:
  workflow_dispatch:
permissions: {}
jobs:
  macos-public-snapshot:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    permissions:
      actions: read
    outputs:
      cache_snapshot: ${{ steps.snapshot.outputs.cache_snapshot }}
    env:
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
      CI_WORKSPACE: ${{ github.workspace }}
      GITHUB_TOKEN: ${{ github.token }}
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
      - name: Snapshot cache inventory
        id: snapshot
        run: python3 -B kit/confinement/macos_public_audit.py snapshot
  macos-capability:
    needs: macos-public-snapshot
    permissions: {}
    outputs:
      receipt: ${{ steps.proof.outputs.receipt }}
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
          /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B -m unittest discover -s kit/confinement -p "test_macos*.py"
          python3 -B kit/bootstrap/check_candidate.py --root "$CI_WORKSPACE" --pool platform --sha "$CI_SHA"
      - name: Run source-free capability experiment
        id: proof
        run: |
          set -euo pipefail
          sudo -n -- env -i \\
            PATH=/usr/bin:/bin:/usr/sbin:/sbin \\
            LANG=C \\
            LC_ALL=C \\
            CI_EVENT_NAME="$CI_EVENT_NAME" \\
            CI_REF="$CI_REF" \\
            CI_REPOSITORY="$CI_REPOSITORY" \\
            CI_SERVER_URL="$CI_SERVER_URL" \\
            CI_SHA="$CI_SHA" \\
            GITHUB_RUN_ID="$GITHUB_RUN_ID" \\
            GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" \\
            ImageOS="$ImageOS" \\
            ImageVersion="$ImageVersion" \\
            RUNNER_HOME="$HOME" \\
            GITHUB_ENV="$GITHUB_ENV" \\
            GITHUB_OUTPUT="$GITHUB_OUTPUT" \\
            GITHUB_PATH="$GITHUB_PATH" \\
            GITHUB_STEP_SUMMARY="$GITHUB_STEP_SUMMARY" \\
            PYTHONDONTWRITEBYTECODE=1 \\
            RUNNER_TEMP="$RUNNER_TEMP" \\
            CI_WORKSPACE="$CI_WORKSPACE" \\
            /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B kit/confinement/macos_deny_default.py --control-sha "$CI_SHA"
  macos-public-surface-audit:
    if: ${{ always() }}
    needs: [macos-public-snapshot, macos-capability]
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    permissions:
      actions: read
      checks: read
    env:
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
      CI_WORKSPACE: ${{ github.workspace }}
      GITHUB_TOKEN: ${{ github.token }}
      MACOS_CACHE_SNAPSHOT: ${{ needs.macos-public-snapshot.outputs.cache_snapshot }}
      MACOS_NATIVE_RECEIPT_B64URL: ${{ needs.macos-capability.outputs.receipt }}
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
      - name: Audit public surfaces
        run: python3 -B kit/confinement/macos_harness.py --control-sha "$CI_SHA"
"""


MACOS_REVIEWED_BUILD_WORKFLOW_TEMPLATE = r"""name: macos-reviewed-build
on:
  workflow_dispatch:
env:
  KD_CACHE_POLICY_MODE: none
permissions: {}
jobs:
  macos-public-snapshot:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    permissions:
      actions: read
    outputs:
      cache_snapshot: ${{ steps.snapshot.outputs.cache_snapshot }}
    env:
      KD_CACHE_POLICY_MODE: none
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
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
      - name: Snapshot cache inventory
        id: snapshot
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: python3 -B kit/confinement/macos_public_audit.py reviewed-snapshot
  macos-reviewed-smoke:
    needs: macos-public-snapshot
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: macos-15
    timeout-minutes: 20
    permissions: {}
    defaults:
      run:
        shell: bash
    env:
      KD_CACHE_POLICY_MODE: none
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
          /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B -m unittest discover -s kit/confinement -p "test_macos*.py"
          python3 -B kit/bootstrap/check_candidate.py --root "$CI_WORKSPACE" --pool platform --sha "$CI_SHA"
      - name: Prove source-free network observer
        run: |
          set -euo pipefail
          if [[ ! "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]; then
            exit 1
          fi
          if [[ ! "$GITHUB_RUN_ID" =~ ^[1-9][0-9]{0,18}$ || ! "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,18}$ ]]; then
            exit 1
          fi
          sudo -n -- env -i \
            PATH=/usr/bin:/bin:/usr/sbin:/sbin \
            LANG=C \
            LC_ALL=C \
            CI_SHA="$CI_SHA" \
            GITHUB_RUN_ID="$GITHUB_RUN_ID" \
            GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" \
            PYTHONDONTWRITEBYTECODE=1 \
            /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B kit/confinement/macos_network_observer.py selftest
      - name: Run source-free reviewed build smoke
        run: |
          set -euo pipefail
          if [[ -z "${ImageOS:-}" || -z "${ImageVersion:-}" ]]; then
            exit 1
          fi
          sudo -n -- env -i \
            PATH=/usr/bin:/bin:/usr/sbin:/sbin \
            LANG=C \
            LC_ALL=C \
            CI_EVENT_NAME="$CI_EVENT_NAME" \
            CI_REF="$CI_REF" \
            CI_REPOSITORY="$CI_REPOSITORY" \
            CI_SERVER_URL="$CI_SERVER_URL" \
            CI_SHA="$CI_SHA" \
            CI_STEP_SUMMARY="$GITHUB_STEP_SUMMARY" \
            GITHUB_RUN_ID="$GITHUB_RUN_ID" \
            GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" \
            ImageOS="$ImageOS" \
            ImageVersion="$ImageVersion" \
            RUNNER_HOME="$HOME" \
            RUNNER_TEMP="$RUNNER_TEMP" \
            CI_WORKSPACE="$CI_WORKSPACE" \
            PYTHONDONTWRITEBYTECODE=1 \
            /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B kit/confinement/macos_reviewed_build.py --control-sha "$CI_SHA"
      - name: Write trusted summary visibility control
        run: |
          set -euo pipefail
          if [[ "$CI_EVENT_NAME" != "workflow_dispatch" || "$CI_REF" != "refs/heads/main" ]]; then
            exit 1
          fi
          if [[ ! "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]; then
            exit 1
          fi
          if [[ ! "$GITHUB_RUN_ID" =~ ^[1-9][0-9]{0,18}$ || ! "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,18}$ ]]; then
            exit 1
          fi
          if [[ -z "${GITHUB_STEP_SUMMARY:-}" ]]; then
            exit 1
          fi
          summary_prefix="macos-summary-"
          summary_line="${summary_prefix}control=trusted-write schema=1 control-sha=$CI_SHA run-id=$GITHUB_RUN_ID run-attempt=$GITHUB_RUN_ATTEMPT"
          printf '%s\n' "$summary_line" >> "$GITHUB_STEP_SUMMARY"
          printf '%s\n' "$summary_line"
  macos-public-surface-audit:
    if: ${{ always() }}
    needs: [macos-public-snapshot, macos-reviewed-smoke]
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    permissions:
      actions: read
      checks: read
    env:
      KD_CACHE_POLICY_MODE: none
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
      MACOS_CACHE_SNAPSHOT: ${{ needs.macos-public-snapshot.outputs.cache_snapshot }}
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
      - name: Audit public surfaces
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: python3 -B kit/confinement/macos_public_audit.py reviewed-audit
"""


MACOS_RUST_TOOLCHAIN_WORKFLOW_TEMPLATE = r"""name: macos-rust-toolchain-smoke
on:
  workflow_dispatch:
env:
  KD_CACHE_POLICY_MODE: none
permissions: {}
jobs:
  macos-rust-toolchain-snapshot:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    permissions:
      actions: read
    outputs:
      cache_snapshot: ${{ steps.snapshot.outputs.cache_snapshot }}
    env:
      KD_CACHE_POLICY_MODE: none
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
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
      - name: Snapshot cache inventory
        id: snapshot
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: python3 -B kit/confinement/macos_public_audit.py rust-toolchain-snapshot
  macos-rust-toolchain-smoke:
    needs: macos-rust-toolchain-snapshot
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: macos-15
    timeout-minutes: 35
    permissions: {}
    defaults:
      run:
        shell: bash
    env:
      KD_CACHE_POLICY_MODE: none
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
          /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B -m unittest discover -s kit/confinement -p "test_macos*.py"
          python3 -B kit/bootstrap/check_candidate.py --root "$CI_WORKSPACE" --pool platform --sha "$CI_SHA"
      - name: Run source-free reviewed build smoke
        run: |
          set -euo pipefail
          if [[ -z "${ImageOS:-}" || -z "${ImageVersion:-}" ]]; then
            exit 1
          fi
          sudo -n -- env -i \
            PATH=/usr/bin:/bin:/usr/sbin:/sbin \
            LANG=C \
            LC_ALL=C \
            CI_EVENT_NAME="$CI_EVENT_NAME" \
            CI_REF="$CI_REF" \
            CI_REPOSITORY="$CI_REPOSITORY" \
            CI_SERVER_URL="$CI_SERVER_URL" \
            CI_SHA="$CI_SHA" \
            CI_STEP_SUMMARY="$GITHUB_STEP_SUMMARY" \
            GITHUB_RUN_ID="$GITHUB_RUN_ID" \
            GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" \
            ImageOS="$ImageOS" \
            ImageVersion="$ImageVersion" \
            RUNNER_HOME="$HOME" \
            RUNNER_TEMP="$RUNNER_TEMP" \
            CI_WORKSPACE="$CI_WORKSPACE" \
            PYTHONDONTWRITEBYTECODE=1 \
            /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B kit/confinement/macos_reviewed_build.py --control-sha "$CI_SHA"
      - name: Run source-free Rust toolchain smoke
        run: |
          set -euo pipefail
          rust_marker_prefix="KD-RUST-"
          rust_success_prefix="${rust_marker_prefix}SMOKE "
          rust_refusal_prefix="${rust_marker_prefix}REFUSAL reason="
          if [[ ! "$CI_SHA" =~ ^[a-f0-9]{40}$ \
            || ! "$GITHUB_RUN_ID" =~ ^[1-9][0-9]{0,18}$ \
            || ! "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,18}$ ]]; then
            printf '%s%s\n' "$rust_refusal_prefix" "invalid_input"
            exit 1
          fi
          if [[ -z "${RUNNER_TEMP:-}" || "$RUNNER_TEMP" != /* || -z "${GITHUB_STEP_SUMMARY:-}" ]]; then
            printf '%s%s\n' "$rust_refusal_prefix" "runner_unavailable"
            exit 1
          fi
          if ! capture_dir="$(/usr/bin/mktemp -d "${RUNNER_TEMP%/}/rust-toolchain-smoke.XXXXXX" 2>/dev/null)"; then
            printf '%s%s\n' "$rust_refusal_prefix" "runner_unavailable"
            exit 1
          fi
          stdout_file="$capture_dir/stdout"
          stderr_file="$capture_dir/stderr"
          validated_file="$capture_dir/validated"
          validator_stderr_file="$capture_dir/validator-stderr"
          trap '/bin/rm -rf "$capture_dir" 2>/dev/null' EXIT
          set +e
          sudo -n -- /usr/bin/env -i \
            PATH=/usr/bin:/bin:/usr/sbin:/sbin \
            LANG=C \
            LC_ALL=C \
            RUNNER_TEMP="$RUNNER_TEMP" \
            GITHUB_RUN_ID="$GITHUB_RUN_ID" \
            GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" \
            /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B kit/confinement/macos_rust_toolchain.py --control-sha "$CI_SHA" \
            >"$stdout_file" 2>"$stderr_file"
          status=$?
          set -e
          if [[ "$status" -ne 0 ]]; then
            printf '%s%s\n' "$rust_refusal_prefix" "smoke_failed"
            exit 1
          fi
          set +e
          /usr/bin/env -i \
            PATH=/usr/bin:/bin:/usr/sbin:/sbin \
            LANG=C \
            LC_ALL=C \
            CI_SHA="$CI_SHA" \
            GITHUB_SHA="$GITHUB_SHA" \
            GITHUB_REPOSITORY="$CI_REPOSITORY" \
            GITHUB_EVENT_NAME="$CI_EVENT_NAME" \
            GITHUB_REF="$CI_REF" \
            GITHUB_RUN_ID="$GITHUB_RUN_ID" \
            GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" \
            /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B kit/confinement/macos_public_audit.py rust-toolchain-publish \
            <"$stdout_file" >"$validated_file" 2>"$validator_stderr_file"
          validator_status=$?
          set -e
          if [[ "$validator_status" -ne 0 ]]; then
            printf '%s%s\n' "$rust_refusal_prefix" "capture_invalid"
            exit 1
          fi
          if [[ ! -f "$validated_file" || ! -r "$validated_file" \
            || "$(/usr/bin/wc -l < "$validated_file" 2>/dev/null)" -ne 1 \
            || "$(/usr/bin/wc -c < "$validated_file" 2>/dev/null)" -gt 16384 ]]; then
            printf '%s%s\n' "$rust_refusal_prefix" "capture_invalid"
            exit 1
          fi
          IFS= read -r receipt_line < "$validated_file" || {
            printf '%s%s\n' "$rust_refusal_prefix" "capture_invalid"
            exit 1
          }
          if [[ "$receipt_line" != "${rust_success_prefix}"* ]]; then
            printf '%s%s\n' "$rust_refusal_prefix" "capture_invalid"
            exit 1
          fi
          if ! /bin/rm -rf "$capture_dir" 2>/dev/null; then
            printf '%s%s\n' "$rust_refusal_prefix" "cleanup_incomplete"
            exit 1
          fi
          trap - EXIT
          if ! printf '%s\n' "$receipt_line" 2>/dev/null >> "$GITHUB_STEP_SUMMARY"; then
            printf '%s%s\n' "$rust_refusal_prefix" "runner_unavailable"
            exit 1
          fi
          printf '%s\n' "$receipt_line"
      - name: Write trusted summary visibility control
        run: |
          set -euo pipefail
          if [[ "$CI_EVENT_NAME" != "workflow_dispatch" || "$CI_REF" != "refs/heads/main" ]]; then
            exit 1
          fi
          if [[ ! "$CI_SHA" =~ ^[a-f0-9]{40}$ \
            || ! "$GITHUB_RUN_ID" =~ ^[1-9][0-9]{0,18}$ \
            || ! "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,18}$ ]]; then
            exit 1
          fi
          if [[ -z "${GITHUB_STEP_SUMMARY:-}" ]]; then
            exit 1
          fi
          summary_prefix="macos-summary-"
          summary_line="${summary_prefix}control=trusted-write schema=1 control-sha=$CI_SHA run-id=$GITHUB_RUN_ID run-attempt=$GITHUB_RUN_ATTEMPT"
          printf '%s\n' "$summary_line" 2>/dev/null >> "$GITHUB_STEP_SUMMARY"
          printf '%s\n' "$summary_line"
  macos-rust-toolchain-audit:
    if: ${{ always() }}
    needs: [macos-rust-toolchain-snapshot, macos-rust-toolchain-smoke]
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    permissions:
      actions: read
      checks: read
    env:
      KD_CACHE_POLICY_MODE: none
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
      MACOS_CACHE_SNAPSHOT: ${{ needs.macos-rust-toolchain-snapshot.outputs.cache_snapshot }}
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
      - name: Audit public surfaces
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: python3 -B kit/confinement/macos_public_audit.py rust-toolchain-audit
"""


MACOS_CACHE_PROOF_ACTION_SHA = "3edfce9056124e459a23f683a21433670d47daca"
MACOS_CACHE_PROOF_WORKFLOW_TEMPLATE = r"""name: macos-cache-proof
on:
  workflow_dispatch:
env:
  KD_CACHE_POLICY_MODE: none
permissions: {}
jobs:
  macos-cache-public-snapshot:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    permissions:
      actions: read
    outputs:
      cache_snapshot: ${{ steps.snapshot.outputs.cache_snapshot }}
    env:
      KD_CACHE_POLICY_MODE: none
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
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
      - name: Snapshot cache inventory
        id: snapshot
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: python3 -B kit/confinement/macos_public_audit.py cache-proof-snapshot
  macos-cache-seed:
    needs: macos-cache-public-snapshot
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: macos-15
    timeout-minutes: 10
    permissions: {}
    defaults:
      run:
        shell: bash
    env:
      KD_CACHE_POLICY_MODE: write
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
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
      - name: Prepare public cache fixture
        run: |
          set -euo pipefail
          fixture_dir="$RUNNER_TEMP/macos-public-cache"
          mkdir -p "$fixture_dir"
          printf '%s\n' 'Public macOS cache fixture v1' > "$fixture_dir/fixture.txt"
      - name: Save public cache fixture
        id: save
        uses: actions/cache/save@3edfce9056124e459a23f683a21433670d47daca
        with:
          path: ${{ runner.temp }}/macos-public-cache/fixture.txt
          key: macos-public-cache-seed-v1-${{ github.run_id }}-${{ github.run_attempt }}
      - name: Confirm seed step completed
        env:
          SAVE_OUTCOME: ${{ steps.save.outcome }}
        run: |
          set -euo pipefail
          if [[ "$SAVE_OUTCOME" != "success" ]]; then
            exit 1
          fi
          printf 'macos-cache-seed=step-complete schema=1 run-id=%s run-attempt=%s\n' "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"
  macos-cache-positive:
    needs: macos-cache-seed
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: macos-15
    timeout-minutes: 10
    permissions: {}
    defaults:
      run:
        shell: bash
    env:
      KD_CACHE_POLICY_MODE: read
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
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
      - name: Restore the known public cache fixture
        id: restore
        uses: actions/cache/restore@3edfce9056124e459a23f683a21433670d47daca
        with:
          path: ${{ runner.temp }}/macos-public-cache/fixture.txt
          key: macos-public-cache-seed-v1-${{ github.run_id }}-${{ github.run_attempt }}
          fail-on-cache-miss: true
      - name: Verify exact fixture bytes after a cache hit
        env:
          CACHE_HIT: ${{ steps.restore.outputs.cache-hit }}
        run: |
          set -euo pipefail
          if [[ "$CACHE_HIT" != "true" ]]; then
            exit 1
          fi
          expected="$RUNNER_TEMP/macos-public-cache-expected.txt"
          printf '%s\n' 'Public macOS cache fixture v1' > "$expected"
          cmp -s "$expected" "$RUNNER_TEMP/macos-public-cache/fixture.txt"
          printf 'macos-cache-positive=restored schema=1 run-id=%s run-attempt=%s\n' "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"
  macos-cache-none-probe:
    needs: macos-cache-positive
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: macos-15
    timeout-minutes: 10
    permissions: {}
    defaults:
      run:
        shell: bash
    env:
      KD_CACHE_POLICY_MODE: none
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
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
      - name: Fetch the exact pinned public cache client
        run: |
          set -euo pipefail
          client_dir="$RUNNER_TEMP/macos-cache-client"
          if [[ -e "$client_dir" || -L "$client_dir" ]]; then
            exit 1
          fi
          git init -q "$client_dir" 2>/dev/null
          git -C "$client_dir" config core.autocrlf false 2>/dev/null
          git -C "$client_dir" remote add origin "${CI_SERVER_URL%/}/actions/cache.git" 2>/dev/null
          git -C "$client_dir" fetch --quiet --no-tags --depth=1 origin 3edfce9056124e459a23f683a21433670d47daca 2>/dev/null
          git -C "$client_dir" checkout --quiet --detach FETCH_HEAD 2>/dev/null
          actual_client_sha="$(git -C "$client_dir" rev-parse --verify HEAD 2>/dev/null)"
          if [[ "$actual_client_sha" != "3edfce9056124e459a23f683a21433670d47daca" ]]; then
            exit 1
          fi
          printf 'macos-cache-client-source=verified schema=1 action-sha=%s\n' "$actual_client_sha"
      - name: Require fixture is absent before the denied read
        run: |
          set -euo pipefail
          if [[ -e "$RUNNER_TEMP/macos-public-cache/fixture.txt" ]]; then
            exit 1
          fi
      - name: Request the known fixture through the pinned cache client
        id: denied-restore
        uses: ./kit/confinement/macos_cache_client
        with:
          mode: read
          path: ${{ runner.temp }}/macos-public-cache/fixture.txt
          key: macos-public-cache-seed-v1-${{ github.run_id }}-${{ github.run_attempt }}
      - name: Verify the none-scoped read did not restore bytes
        env:
          CACHE_HIT: ${{ steps.denied-restore.outputs.cache-hit }}
        run: |
          set -euo pipefail
          if [[ ( -n "$CACHE_HIT" && "$CACHE_HIT" != "false" ) || -e "$RUNNER_TEMP/macos-public-cache/fixture.txt" ]]; then
            exit 1
          fi
          printf 'macos-cache-none-read=local-absent schema=1 run-id=%s run-attempt=%s\n' "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"
      - name: Prepare a distinct public write probe
        run: |
          set -euo pipefail
          fixture_dir="$RUNNER_TEMP/macos-public-cache-write"
          mkdir -p "$fixture_dir"
          printf '%s\n' 'Public macOS cache write probe v1' > "$fixture_dir/fixture.txt"
      - name: Request a save through the pinned cache client
        id: denied-save
        uses: ./kit/confinement/macos_cache_client
        with:
          mode: write
          path: ${{ runner.temp }}/macos-public-cache-write/fixture.txt
          key: macos-public-cache-none-write-v1-${{ github.run_id }}-${{ github.run_attempt }}
      - name: Confirm save request completed
        env:
          SAVE_OUTCOME: ${{ steps.denied-save.outcome }}
        run: |
          set -euo pipefail
          if [[ "$SAVE_OUTCOME" != "success" ]]; then
            exit 1
          fi
          printf 'macos-cache-none-save=request-finished schema=1 run-id=%s run-attempt=%s\n' "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"
  macos-cache-public-audit:
    if: ${{ always() }}
    needs: [macos-cache-public-snapshot, macos-cache-seed, macos-cache-positive, macos-cache-none-probe]
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    permissions:
      actions: read
      checks: read
    env:
      KD_CACHE_POLICY_MODE: none
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
      MACOS_CACHE_SNAPSHOT: ${{ needs.macos-cache-public-snapshot.outputs.cache_snapshot }}
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
      - name: Audit cache proof and public surfaces
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: python3 -B kit/confinement/macos_public_audit.py cache-proof-audit
  macos-cache-cleanup:
    if: ${{ always() }}
    needs: [macos-cache-public-snapshot, macos-cache-seed, macos-cache-positive, macos-cache-none-probe, macos-cache-public-audit]
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    permissions:
      actions: write
    env:
      KD_CACHE_POLICY_MODE: none
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
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
      - name: Remove only this run attempt cache fixtures
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: python3 -B kit/confinement/macos_public_audit.py cache-proof-cleanup
"""


NODE_LOCK_SMOKE_WORKFLOW_TEMPLATE = 'name: node-lock-smoke\non:\n  workflow_call:\npermissions: {}\njobs:\n  node-lock-smoke:\n    name: node-lock-smoke-${{ matrix.runner }}\n    strategy:\n      fail-fast: true\n      matrix:\n        runner:\n          - ubuntu-24.04\n          - macos-15\n          - windows-2025\n    runs-on: ${{ matrix.runner }}\n    timeout-minutes: 10\n    defaults:\n      run:\n        shell: bash\n    env:\n      CI_REPOSITORY: ${{ github.repository }}\n      CI_REF: ${{ github.ref }}\n      CI_SHA: ${{ github.sha }}\n      CI_SERVER_URL: ${{ github.server_url }}\n      CI_EVENT_NAME: ${{ github.event_name }}\n    steps:\n      - name: Fetch public candidate\n        run: |\n          set -euo pipefail\n          [[ "$CI_EVENT_NAME" == "workflow_dispatch" ]]\n          [[ "$CI_REPOSITORY" == "keeldock-platform/platform-ci" ]]\n          [[ "$CI_SERVER_URL" == "https://github.com" ]]\n          [[ "$CI_REF" =~ ^refs/heads/[A-Za-z0-9._/-]{1,200}$ ]]\n          [[ "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]\n          requested_ref="$CI_SHA"\n          git init -q . 2>/dev/null\n          git config core.autocrlf false 2>/dev/null\n          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null\n          git fetch --quiet --no-tags --depth=1 origin "$requested_ref" 2>/dev/null\n          git checkout --quiet --detach FETCH_HEAD 2>/dev/null\n          actual_sha="$(git rev-parse --verify HEAD 2>/dev/null)"\n          if [[ "$actual_sha" != "$CI_SHA" ]]; then\n            exit 1\n          fi\n      - name: Set up the pinned Node runtime\n        uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1\n        with:\n          node-version: "24.22.1"\n          check-latest: false\n          cache: ""\n          package-manager-cache: false\n      - name: Run source-free helper tests\n        run: |\n          set -euo pipefail\n          [[ "$(node --version)" == "v24.22.1" ]]\n          [[ "$(npm --version)" == "11.19.1" ]]\n          node --test kit/confinement/test_node_lock_envelope.mjs kit/confinement/test_node_lock_manifest.mjs\n          python_command=python3\n          if [[ "$RUNNER_OS" == "Windows" ]]; then\n            python_command=python\n          fi\n          "$python_command" -B -m unittest discover -s kit/confinement -p "test_node_lock_receipt.py"\n          "$python_command" -B -m unittest discover -s kit/confinement -p "test_sbom_normalizer.py"\n          if [[ "$RUNNER_OS" == "macOS" ]]; then\n            /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I -S -B -m unittest discover -s kit/confinement -p "test_sbom_normalizer.py"\n          fi\n'

CONSUMER_ACTION_PREFIX = "keeldock-platform/platform-ci/kit/bootstrap@"


def consumer_workflow_template(pool, pin):
    if type(pool) is not str or pool not in ("connect", "workspace", "data"):
        raise PolicyError("workflow-pool")
    validate_control_sha(pin)
    return (
        "name: public-policy\n"
        "on:\n"
        "  push:\n"
        "  pull_request:\n"
        "  workflow_dispatch:\n"
        "permissions: {}\n"
        "jobs:\n"
        "  promotion-check-reuse:\n"
        "    if: ${{ github.event_name == 'push' && (github.ref == 'refs/heads/uat' || github.ref == 'refs/heads/main') }}\n"
        "    runs-on: ubuntu-24.04\n"
        "    timeout-minutes: 5\n"
        "    permissions:\n"
        "      checks: read\n"
        "      contents: read\n"
        "      statuses: read\n"
        "    outputs:\n"
        "      skip_checks: ${{ steps.decide.outputs.skip_checks }}\n"
        "    steps:\n"
        "      - name: Fetch the exact candidate SHA\n"
        "        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
        "        with:\n"
        "          ref: ${{ github.sha }}\n"
        "          persist-credentials: false\n"
        "      - name: Fetch the pinned promotion policy\n"
        "        env:\n"
        "          CONTROL_SHA: " + pin + "\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        "          timeout 1m git init -q control\n"
        "          timeout 1m git -C control config core.autocrlf false\n"
        "          timeout 1m git -C control remote add origin \"${GITHUB_SERVER_URL%/}/${GITHUB_REPOSITORY}.git\"\n"
        "          timeout 1m git -C control fetch --quiet --no-tags --depth=1 origin \"$CONTROL_SHA\"\n"
        "          timeout 1m git -C control checkout --quiet --detach FETCH_HEAD\n"
        "          actual_sha=\"$(timeout 1m git -C control rev-parse HEAD)\"\n"
        "          [[ \"$actual_sha\" == \"$CONTROL_SHA\" ]]\n"
        "      - name: Check prior workflow results for this exact SHA\n"
        "        id: decide\n"
        "        env:\n"
        "          GH_TOKEN: ${{ github.token }}\n"
        "          PROMOTION_TARGET: ${{ github.ref_name }}\n"
        "          PROMOTION_SHA: ${{ github.sha }}\n"
        "          PROMOTION_WORKFLOW: public-policy\n"
        "        run: timeout 1m python -B control/kit/promotion/branch_promotion.py --reuse-checks-if-green --target \"$PROMOTION_TARGET\" --sha \"$PROMOTION_SHA\" --workflow \"$PROMOTION_WORKFLOW\"\n"
        "  policy:\n"
        "    needs: promotion-check-reuse\n"
        "    if: ${{ always() && (needs.promotion-check-reuse.result == 'skipped' || needs.promotion-check-reuse.outputs.skip_checks != 'true') }}\n"
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


FEEDBACK_RETURN_WORKFLOW_SHA256 = {
    'core-rust-format-return': 'c56fc9e8199681d2dab689f7f09a9fbb57825549c0f6132c27a7016ce72c79ab',
    'core-build-diagnostic-return': 'd75840b7a8b8541a1f1a083a35c5b54255d3ce8e5242c6e7e8bd1eb06bbd13ad',
}
ATTESTATION_PROBE_WORKFLOW_SHA256 = '804d5bf224067808374c42886e615723ab1b1d77716463a3990391c812976e3e'


SHARED_WORKFLOW_KINDS = frozenset(
    (
        "public-policy",
        "node-lock-smoke",
        "development-feedback-smoke",
        "attestation-probe",
        "macos-capability",
        "macos-reviewed-build",
        "macos-rust-toolchain-smoke",
        "macos-cache-proof",
        "macos-rules-bootstrap",
        "macos-core-bootstrap",
        "macos-core-contract",
        "macos-source-reader",
        "macos-rules-source-reader",
    )
) | frozenset(FEEDBACK_RETURN_WORKFLOW_SHA256)
LANE_MODULES = (policy_linux, policy_windows, policy_handoff, policy_baselines, policy_devlane)
LANE_DIGEST_PATTERN = re.compile(r"[a-f0-9]{64}\Z")


def build_lane_registry(lane_modules, shared_kinds):
    templates = {}
    digests = {}
    owners = {}
    candidates = []
    for module in lane_modules:
        for table, target, is_digest in (
            (module.WORKFLOW_TEMPLATES, templates, False),
            (module.WORKFLOW_SHA256, digests, True),
        ):
            for kind, value in table.items():
                if type(kind) is not str or type(value) is not str:
                    raise PolicyError("workflow-registry")
                if kind in shared_kinds or kind in owners:
                    raise PolicyError("workflow-registry")
                if is_digest and LANE_DIGEST_PATTERN.match(value) is None:
                    raise PolicyError("workflow-registry")
                target[kind] = value
                owners[kind] = module
        for path, kind, failure_code in module.CANDIDATE_WORKFLOWS:
            if kind not in owners or owners[kind] is not module:
                raise PolicyError("workflow-registry")
            candidates.append((path, kind, failure_code))
    return (
        MappingProxyType(templates),
        MappingProxyType(digests),
        MappingProxyType(owners),
        tuple(candidates),
    )


(
    LANE_WORKFLOW_TEMPLATES,
    LANE_WORKFLOW_SHA256,
    WORKFLOW_KIND_LANES,
    LANE_CANDIDATE_WORKFLOWS,
) = build_lane_registry(LANE_MODULES, SHARED_WORKFLOW_KINDS)


def validate_workflow_text(text, pool, workflow_kind="public-policy"):
    if type(text) is not str or type(pool) is not str or pool not in PUBLIC_POOLS:
        raise PolicyError("workflow-input")
    if workflow_kind in FEEDBACK_RETURN_WORKFLOW_SHA256:
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != FEEDBACK_RETURN_WORKFLOW_SHA256[workflow_kind]:
            raise PolicyError("workflow-template-mismatch")
        return True
    if workflow_kind == "development-feedback-smoke":
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != DEVELOPMENT_FEEDBACK_SMOKE_WORKFLOW_SHA256:
            raise PolicyError("workflow-template-mismatch")
        return True
    if workflow_kind == "attestation-probe":
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != ATTESTATION_PROBE_WORKFLOW_SHA256:
            raise PolicyError("workflow-template-mismatch")
        return True
    if workflow_kind == "node-lock-smoke":
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        expected = NODE_LOCK_SMOKE_WORKFLOW_TEMPLATE
    elif workflow_kind == "macos-capability":
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        expected = MACOS_CAPABILITY_WORKFLOW_TEMPLATE
    elif workflow_kind == "macos-reviewed-build":
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        expected = MACOS_REVIEWED_BUILD_WORKFLOW_TEMPLATE
    elif workflow_kind == "macos-rust-toolchain-smoke":
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        expected = MACOS_RUST_TOOLCHAIN_WORKFLOW_TEMPLATE
    elif workflow_kind == "macos-cache-proof":
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        expected = MACOS_CACHE_PROOF_WORKFLOW_TEMPLATE
    elif workflow_kind in {"macos-rules-bootstrap", "macos-core-bootstrap", "macos-core-contract"}:
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        expected_digest = (
            MACOS_RULES_BOOTSTRAP_WORKFLOW_SHA256
            if workflow_kind == "macos-rules-bootstrap"
            else MACOS_CORE_BOOTSTRAP_WORKFLOW_SHA256
            if workflow_kind == "macos-core-bootstrap"
            else MACOS_CORE_CONTRACT_WORKFLOW_SHA256
        )
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != expected_digest:
            raise PolicyError("workflow-template-mismatch")
        return True
    elif workflow_kind in {"macos-source-reader", "macos-rules-source-reader"}:
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        expected_digest = (
            MACOS_SOURCE_READER_WORKFLOW_SHA256
            if workflow_kind == "macos-source-reader"
            else MACOS_RULES_SOURCE_READER_WORKFLOW_SHA256
        )
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != expected_digest:
            raise PolicyError("workflow-template-mismatch")
        return True
    elif workflow_kind in LANE_WORKFLOW_TEMPLATES:
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        expected = LANE_WORKFLOW_TEMPLATES[workflow_kind]
    elif workflow_kind in LANE_WORKFLOW_SHA256:
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != LANE_WORKFLOW_SHA256[workflow_kind]:
            raise PolicyError("workflow-template-mismatch")
        return True
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
