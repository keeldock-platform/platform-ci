"""Baselines preparation lane workflow validation data.

This lane registers the source-free baselines preparation workflow with its
exact reviewed template. The shared policy module imports this module and
dispatches through its fixed registry. This module must not import shared policy.

Lane interface, identical in every lane module:

WORKFLOW_TEMPLATES maps a workflow kind to its exact expected text.
WORKFLOW_SHA256 maps a workflow kind to the expected SHA-256 of its text.
CANDIDATE_WORKFLOWS lists, in order, the path, workflow kind and size-failure
code that the candidate checker validates when the pool is platform.
"""

BASELINES_PREPARE_WORKFLOW_TEMPLATE = """name: baselines-prepare
on:
  workflow_dispatch:
cache-mode: none
permissions: {}
jobs:
  baselines-prepare:
    name: baselines-prepare-${{ matrix.platform }}
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - platform: linux
            runner: ubuntu-24.04
          - platform: windows
            runner: windows-2025
          - platform: macos
            runner: macos-15
    runs-on: ${{ matrix.runner }}
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
      CI_PLATFORM: ${{ matrix.platform }}
      PYTHONDONTWRITEBYTECODE: "1"
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
          if command -v python3 >/dev/null 2>&1; then
            python_bin="$(command -v python3)"
          elif command -v python >/dev/null 2>&1; then
            python_bin="$(command -v python)"
          else
            exit 1
          fi
          "$python_bin" -B kit/bootstrap/test_policy.py
          "$python_bin" -B kit/bootstrap/test_public_tree.py
          "$python_bin" -B kit/baselines/test_baselines_prepare.py
          "$python_bin" -B kit/bootstrap/check_candidate.py --root . --pool platform --sha "$CI_SHA"
      - name: Run source-free baselines preparation
        run: |
          set -euo pipefail
          if command -v python3 >/dev/null 2>&1; then
            python_bin="$(command -v python3)"
          elif command -v python >/dev/null 2>&1; then
            python_bin="$(command -v python)"
          else
            exit 1
          fi
          "$python_bin" -B kit/baselines/baselines_prepare.py --root . --platform "$CI_PLATFORM" --control-sha "$CI_SHA"
"""

WORKFLOW_TEMPLATES = {
    "baselines-prepare": BASELINES_PREPARE_WORKFLOW_TEMPLATE,
}
WORKFLOW_SHA256 = {}
CANDIDATE_WORKFLOWS = (
    (
        ".github/workflows/baselines-prepare.yml",
        "baselines-prepare",
        "baselines-workflow-too-large",
    ),
)
