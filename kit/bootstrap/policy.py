import hashlib
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
MACOS_SOURCE_READER_ACTION_SHA = "64ab729a6294000f5aa4a4bc0b73d1f32bc45510"
MACOS_SOURCE_READER_WORKFLOW_SHA256 = "6c7e82c8a9d91436ae98f1357fd0fe4f09847f5fd17abc4843eadb130405b626"
MACOS_RULES_SOURCE_READER_WORKFLOW_SHA256 = "cb9b70226175069e9c148c06f18d4d89cf8b6d5b33b39e02579a4aa2de5ee8a6"
MACOS_RULES_BOOTSTRAP_WORKFLOW_SHA256 = "a91387440f8caceadf8f19f7c87feb3d82377eb3c9e1813de48b518992d48807"
MACOS_CORE_BOOTSTRAP_WORKFLOW_SHA256 = "08cf50d62e18e52661befe3153294c2d188b8a980f914437dab7cbd899744b81"
MACOS_CORE_CONTRACT_WORKFLOW_SHA256 = "38c33a1b30bc18378359910af0da73e493026e8105511062f96f6f80fafbe096"


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
cache-mode: none
permissions: {}
jobs:
  macos-public-snapshot:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-24.04
    cache-mode: none
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
    cache-mode: none
    timeout-minutes: 20
    permissions: {}
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
    cache-mode: none
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
cache-mode: none
permissions: {}
jobs:
  macos-rust-toolchain-snapshot:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-24.04
    cache-mode: none
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
    cache-mode: none
    timeout-minutes: 35
    permissions: {}
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
    cache-mode: none
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
cache-mode: none
permissions: {}
jobs:
  macos-cache-public-snapshot:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-24.04
    cache-mode: none
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
    cache-mode: write
    timeout-minutes: 10
    permissions: {}
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
    cache-mode: read
    timeout-minutes: 10
    permissions: {}
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
    cache-mode: none
    timeout-minutes: 10
    permissions: {}
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
    cache-mode: none
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
    cache-mode: none
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    permissions:
      actions: write
    env:
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


WINDOWS_NATIVE_PREFLIGHT_WORKFLOW_TEMPLATE = """name: windows-native-preflight
on:
  workflow_dispatch:
permissions: {}
jobs:
  windows-native-preflight:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: windows-2025
    timeout-minutes: 20
    defaults:
      run:
        shell: pwsh
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
          $ErrorActionPreference = 'Stop'
          $ProgressPreference = 'SilentlyContinue'
          if ($env:CI_EVENT_NAME -ne 'workflow_dispatch' -or $env:CI_REF -ne 'refs/heads/main') { exit 1 }
          if ($env:CI_REPOSITORY -ne 'keeldock-platform/platform-ci' -or $env:CI_SERVER_URL -ne 'https://github.com') { exit 1 }
          if ($env:CI_SHA -notmatch '^[a-f0-9]{40}$') { exit 1 }
          git init --quiet . 2>$null
          if ($LASTEXITCODE -ne 0) { exit 1 }
          git config core.autocrlf false 2>$null
          if ($LASTEXITCODE -ne 0) { exit 1 }
          git remote add origin "$($env:CI_SERVER_URL)/$($env:CI_REPOSITORY).git" 2>$null
          if ($LASTEXITCODE -ne 0) { exit 1 }
          git fetch --quiet --no-tags --depth=1 origin $env:CI_REF 2>$null
          if ($LASTEXITCODE -ne 0) { exit 1 }
          git checkout --quiet --detach FETCH_HEAD 2>$null
          if ($LASTEXITCODE -ne 0) { exit 1 }
          $actualSha = git rev-parse --verify HEAD 2>$null
          if ($LASTEXITCODE -ne 0 -or $actualSha.Trim() -ne $env:CI_SHA) { exit 1 }
      - name: Validate source-free control tree
        run: |
          $ErrorActionPreference = 'Stop'
          python -B kit/bootstrap/test_policy.py
          if ($LASTEXITCODE -ne 0) { exit 1 }
          python -B kit/bootstrap/test_public_tree.py
          if ($LASTEXITCODE -ne 0) { exit 1 }
          python -B kit/confinement/test_windows_native_preflight.py
          if ($LASTEXITCODE -ne 0) { exit 1 }
          python -B kit/bootstrap/check_candidate.py --root $env:CI_WORKSPACE --pool platform --sha $env:CI_SHA
          if ($LASTEXITCODE -ne 0) { exit 1 }
      - name: Run source-free native diagnostic
        run: |
          $ErrorActionPreference = 'Stop'
          & kit/confinement/windows_native_preflight.ps1
          if ($LASTEXITCODE -ne 0) { exit 1 }
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
    elif workflow_kind == "windows-native-preflight":
        if pool != "platform":
            raise PolicyError("workflow-kind-pool")
        expected = WINDOWS_NATIVE_PREFLIGHT_WORKFLOW_TEMPLATE
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
