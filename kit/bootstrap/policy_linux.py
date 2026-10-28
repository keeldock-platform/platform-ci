"""Linux lane workflow validation data.

This module holds the exact reviewed workflow templates and digests that belong
to the Linux lane. It is imported statically by the shared policy module, which
dispatches to it through a fixed registry. It must not import the shared policy
module, so that the registry stays free of import cycles.

Lane interface, identical in every lane module:

WORKFLOW_TEMPLATES maps a workflow kind to its exact expected text.
WORKFLOW_SHA256 maps a workflow kind to the expected SHA-256 of its text.
CANDIDATE_WORKFLOWS lists, in order, the path, workflow kind and size-failure
code that the candidate checker validates when the pool is platform.
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

LINUX_SOURCE_ADMISSION_WORKFLOW_TEMPLATE = r"""name: linux-source-admission
on:
  workflow_dispatch:
permissions: {}
cache-mode: none
jobs:
  linux-source-admission-settings:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    cache-mode: none
    permissions:
      contents: read
    outputs:
      mode: ${{ steps.settings.outputs.mode }}
      untrusted: ${{ steps.settings.outputs.untrusted }}
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
      - name: Fetch exact public control
        run: |
          set -euo pipefail
          [[ "$CI_EVENT_NAME" == "workflow_dispatch" && "$CI_REF" == "refs/heads/main" ]]
          [[ "$CI_REPOSITORY" == "keeldock-platform/platform-ci" && "$CI_SERVER_URL" == "https://github.com" ]]
          [[ "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$CI_REF" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          [[ "$(git rev-parse --verify HEAD 2>/dev/null)" == "$CI_SHA" ]]
      - name: Verify synthetic mode, settings and freshness
        id: settings
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          python3 -B kit/confinement/linux_settings.py
  linux-source-admission-unit:
    needs: linux-source-admission-settings
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && needs.linux-source-admission-settings.result == 'success' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    cache-mode: none
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
      - name: Fetch exact public control
        run: |
          set -euo pipefail
          [[ "$CI_EVENT_NAME" == "workflow_dispatch" && "$CI_REF" == "refs/heads/main" ]]
          [[ "$CI_REPOSITORY" == "keeldock-platform/platform-ci" && "$CI_SERVER_URL" == "https://github.com" ]]
          [[ "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$CI_REF" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          [[ "$(git rev-parse --verify HEAD 2>/dev/null)" == "$CI_SHA" ]]
      - name: Run unprivileged source-free checks
        run: |
          set -euo pipefail
          python3 -B kit/bootstrap/test_policy.py
          python3 -B kit/bootstrap/test_public_tree.py
          python3 -B kit/confinement/test_linux_harness.py
          python3 -B kit/bootstrap/check_candidate.py --root "$CI_WORKSPACE" --pool platform --sha "$CI_SHA"
  linux-source-admission-boundary:
    needs:
      - linux-source-admission-settings
      - linux-source-admission-unit
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && needs.linux-source-admission-settings.outputs.mode == 'synthetic' && needs.linux-source-admission-unit.result == 'success' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    cache-mode: none
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
      - name: Fetch exact public control
        run: |
          set -euo pipefail
          [[ "$CI_EVENT_NAME" == "workflow_dispatch" && "$CI_REF" == "refs/heads/main" ]]
          [[ "$CI_REPOSITORY" == "keeldock-platform/platform-ci" && "$CI_SERVER_URL" == "https://github.com" ]]
          [[ "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$CI_REF" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          [[ "$(git rev-parse --verify HEAD 2>/dev/null)" == "$CI_SHA" ]]
      - name: Record runner image and resolve the preinstalled toolchain
        id: toolchain
        run: |
          set -euo pipefail
          [[ "${ImageOS:-}" =~ ^[A-Za-z0-9._-]{1,64}$ && "${ImageVersion:-}" =~ ^[A-Za-z0-9._-]{1,64}$ ]]
          sysroot="$(rustc --print sysroot)"
          [[ "$sysroot" =~ ^/[A-Za-z0-9._/@+=-]{1,300}$ && -x "$sysroot/bin/rustc" ]]
          node_path="$(command -v node)"
          [[ "$node_path" == /usr/* ]]
          printf '%s\n' "rust_sysroot=$sysroot" >> "$GITHUB_OUTPUT"
          mkdir -p "$RUNNER_TEMP/kd-records"
          printf '%s\n' "KD-LINUX-IMAGE schema=1 image-os=$ImageOS image-version=$ImageVersion rust=present node=present"
      - name: Boundary self-test with generated hostile fixtures and secret canaries
        env:
          KD_CANARY_SECRET: kd-synthetic-standin-NOT-A-SECRET-0123456789abcdef0123456789abcd
          KD_RUST_SYSROOT: ${{ steps.toolchain.outputs.rust_sysroot }}
        run: |
          set -euo pipefail
          arguments=(--control-sha "$CI_SHA" --runner-uid "$(id -u)" --runner-home "$HOME" --runner-temp "$RUNNER_TEMP" --rust-sysroot "$KD_RUST_SYSROOT" --synthetic-standin)
          sudo -n --preserve-env=KD_CANARY_SECRET python3 -B kit/confinement/linux_boundary.py selftest "${arguments[@]}" --record "$RUNNER_TEMP/kd-records/selftest.json"
      - name: Synthetic project phase marker
        run: |
          set -euo pipefail
          printf '%s\n' "KD-LINUX-PROJECT schema=1 mode=synthetic project-execution=none"
      - name: Re-run positive controls immediately before the first project command
        env:
          KD_CANARY_SECRET: kd-synthetic-standin-NOT-A-SECRET-0123456789abcdef0123456789abcd
          KD_RUST_SYSROOT: ${{ steps.toolchain.outputs.rust_sysroot }}
        run: |
          set -euo pipefail
          arguments=(--control-sha "$CI_SHA" --runner-uid "$(id -u)" --runner-home "$HOME" --runner-temp "$RUNNER_TEMP" --rust-sysroot "$KD_RUST_SYSROOT" --synthetic-standin)
          sudo -n --preserve-env=KD_CANARY_SECRET python3 -B kit/confinement/linux_boundary.py recheck "${arguments[@]}" --record "$RUNNER_TEMP/kd-records/recheck.json"
      - name: Merge phase records
        run: |
          set -euo pipefail
          sudo -n python3 -B kit/confinement/linux_boundary.py merge --selftest "$RUNNER_TEMP/kd-records/selftest.json" --recheck "$RUNNER_TEMP/kd-records/recheck.json" --out "$RUNNER_TEMP/kd-records/merged.json"
      - name: Forced faults must fail closed
        env:
          KD_CANARY_SECRET: kd-synthetic-standin-NOT-A-SECRET-0123456789abcdef0123456789abcd
          KD_RUST_SYSROOT: ${{ steps.toolchain.outputs.rust_sysroot }}
        run: |
          set -euo pipefail
          arguments=(--control-sha "$CI_SHA" --runner-uid "$(id -u)" --runner-home "$HOME" --runner-temp "$RUNNER_TEMP" --rust-sysroot "$KD_RUST_SYSROOT" --synthetic-standin)
          sudo -n --preserve-env=KD_CANARY_SECRET python3 -B kit/confinement/linux_boundary.py faults "${arguments[@]}"
  linux-source-admission-audit:
    needs:
      - linux-source-admission-settings
      - linux-source-admission-unit
      - linux-source-admission-boundary
    if: ${{ always() && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    cache-mode: none
    permissions: {}
    defaults:
      run:
        shell: bash
    env:
      SETTINGS_RESULT: ${{ needs.linux-source-admission-settings.result }}
      UNIT_RESULT: ${{ needs.linux-source-admission-unit.result }}
      BOUNDARY_RESULT: ${{ needs.linux-source-admission-boundary.result }}
    steps:
      - name: Source-free audit placeholder
        run: |
          set -euo pipefail
          for result in "$SETTINGS_RESULT" "$UNIT_RESULT" "$BOUNDARY_RESULT"; do
            [[ "$result" =~ ^(success|failure|cancelled|skipped)$ ]]
          done
          printf '%s\n' "KD-LINUX-AUDIT schema=1 status=placeholder settings=$SETTINGS_RESULT unit=$UNIT_RESULT boundary=$BOUNDARY_RESULT"
          [[ "$SETTINGS_RESULT" == "success" && "$UNIT_RESULT" == "success" && "$BOUNDARY_RESULT" == "success" ]]
"""

WORKFLOW_TEMPLATES = {
    "linux-confinement": LINUX_CONFINEMENT_WORKFLOW_TEMPLATE,
    "linux-source-admission": LINUX_SOURCE_ADMISSION_WORKFLOW_TEMPLATE,
}
WORKFLOW_SHA256 = {}
CANDIDATE_WORKFLOWS = (
    (".github/workflows/linux-confinement.yml", "linux-confinement", "linux-workflow-too-large"),
    (
        ".github/workflows/linux-source-admission.yml",
        "linux-source-admission",
        "linux-source-admission-workflow-too-large",
    ),
)
