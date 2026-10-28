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

WORKFLOW_TEMPLATES = {
    "linux-confinement": LINUX_CONFINEMENT_WORKFLOW_TEMPLATE,
}
WORKFLOW_SHA256 = {}
CANDIDATE_WORKFLOWS = (
    (".github/workflows/linux-confinement.yml", "linux-confinement", "linux-workflow-too-large"),
)
