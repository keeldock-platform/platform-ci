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
run-name: Linux admission ${{ inputs.mode }} ${{ inputs.mode == 'source' && inputs.source_sha || 'synthetic' }}
on:
  workflow_dispatch:
    inputs:
      mode:
        description: Run the synthetic proof or the bound source candidate
        required: true
        type: choice
        options:
          - synthetic
          - source
        default: synthetic
      source_sha:
        description: Bound private source commit
        required: false
        type: string
      base_sha:
        description: Admitted source base commit
        required: false
        type: string
      base_branch:
        description: Admitted permanent source branch
        required: false
        type: choice
        options:
          - main
          - develop
          - uat
      fingerprint:
        description: Reviewed source diff fingerprint
        required: false
        type: string
      environment_name:
        description: Protected source-read environment
        required: false
        type: string
        default: source-read
permissions: {}
cache-mode: none
jobs:
  linux-source-admission-settings:
    if: ${{ github.event_name == 'workflow_dispatch' && (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/untrusted') && (inputs.mode == 'source' || (inputs.mode == 'synthetic' && github.ref == 'refs/heads/main')) }}
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    cache-mode: none
    permissions:
      actions: read
      contents: read
    outputs:
      mode: ${{ inputs.mode }}
      expected: ${{ steps.snapshot.outputs.expected || steps.identity.outputs.expected }}
      cache_digest: ${{ steps.snapshot.outputs.cache_digest }}
    defaults:
      run:
        shell: bash
    env:
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
      CI_MODE: ${{ inputs.mode }}
      CACHE_MODE: none
      REQUESTED_SOURCE_SHA: ${{ inputs.source_sha }}
      REQUESTED_BASE_SHA: ${{ inputs.base_sha }}
      REQUESTED_BASE_BRANCH: ${{ inputs.base_branch }}
      REQUESTED_FINGERPRINT: ${{ inputs.fingerprint }}
      REQUESTED_ENVIRONMENT_NAME: ${{ inputs.environment_name }}
      SOURCE_REPOSITORY_ID: ${{ vars.SOURCE_REPOSITORY_ID }}
      SOURCE_REPOSITORY_OWNER: ${{ vars.LINUX_SOURCE_REPOSITORY_OWNER }}
      SOURCE_REPOSITORY_NAME: ${{ vars.LINUX_SOURCE_REPOSITORY_NAME }}
      SOURCE_READER_INSTALLATION_ID: ${{ vars.SOURCE_READER_INSTALLATION_ID }}
      SOURCE_READER_CLIENT_ID: ${{ vars.SOURCE_READER_CLIENT_ID }}
      LINUX_SOURCE_ALLOWED_SHA: ${{ vars.LINUX_SOURCE_ALLOWED_SHA }}
      LINUX_SOURCE_ALLOWED_BASE_SHA: ${{ vars.LINUX_SOURCE_ALLOWED_BASE_SHA }}
      LINUX_SOURCE_ALLOWED_BASE_BRANCH: ${{ vars.LINUX_SOURCE_ALLOWED_BASE_BRANCH }}
      LINUX_SOURCE_ALLOWED_FINGERPRINT: ${{ vars.LINUX_SOURCE_ALLOWED_FINGERPRINT }}
      LINUX_SOURCE_ALLOWED_CONTROL_SHA: ${{ vars.LINUX_SOURCE_ALLOWED_CONTROL_SHA }}
      LINUX_SOURCE_ENVIRONMENT_NAME: ${{ vars.LINUX_SOURCE_ENVIRONMENT_NAME }}
      LINUX_SOURCE_ACCEPTED_NODE_LOCK_SHA256: ${{ vars.LINUX_SOURCE_ACCEPTED_NODE_LOCK_SHA256 }}
      LINUX_SOURCE_ACCEPTED_MANIFEST_SHA256: ${{ vars.LINUX_SOURCE_ACCEPTED_MANIFEST_SHA256 }}
      LINUX_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON: ${{ vars.LINUX_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON }}
    steps:
      - name: Fetch exact public control
        run: |
          set -euo pipefail
          [[ "$CI_REPOSITORY" == "keeldock-platform/platform-ci" && "$CI_SERVER_URL" == "https://github.com" ]]
          [[ "$CI_REF" == "refs/heads/main" || "$CI_REF" == "refs/heads/untrusted" ]]
          [[ "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$CI_REF" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          [[ "$(git rev-parse --verify HEAD 2>/dev/null)" == "$CI_SHA" ]]
      - name: Prepare audit identity
        id: identity
        run: python3 -B kit/confinement/linux_source_build.py audit-expected
      - name: Snapshot cache inventory and validate preflight
        id: snapshot
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: python3 -B kit/confinement/linux_source_build.py snapshot
  linux-source-admission-unit:
    needs: linux-source-admission-settings
    if: ${{ github.event_name == 'workflow_dispatch' && needs.linux-source-admission-settings.result == 'success' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 20
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
          [[ "$CI_REPOSITORY" == "keeldock-platform/platform-ci" && "$CI_SERVER_URL" == "https://github.com" ]]
          [[ "$CI_REF" == "refs/heads/main" || "$CI_REF" == "refs/heads/untrusted" ]]
          [[ "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$CI_REF" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          [[ "$(git rev-parse --verify HEAD 2>/dev/null)" == "$CI_SHA" ]]
      - name: Run unprivileged source-free checks
        env:
          CI_WORKSPACE: ${{ github.workspace }}
        run: |
          set -euo pipefail
          python3 -B kit/bootstrap/test_policy.py
          python3 -B kit/bootstrap/test_policy_linux.py
          python3 -B kit/bootstrap/test_public_tree.py
          python3 -B kit/confinement/test_linux_harness.py
          python3 -B kit/confinement/test_linux_session.py
          python3 -B kit/confinement/test_linux_canaries.py
          python3 -B kit/confinement/test_linux_channels.py
          python3 -B kit/confinement/test_linux_source_build.py
          python3 -B kit/bootstrap/check_candidate.py --root "$CI_WORKSPACE" --pool platform --sha "$CI_SHA"
  linux-source-admission-source-read:
    needs:
      - linux-source-admission-settings
      - linux-source-admission-unit
    if: ${{ github.event_name == 'workflow_dispatch' && needs.linux-source-admission-settings.result == 'success' && needs.linux-source-admission-unit.result == 'success' && (inputs.mode == 'source' || (inputs.mode == 'synthetic' && github.ref == 'refs/heads/main')) && (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/untrusted') }}
    runs-on: ubuntu-24.04
    environment:
      name: ${{ inputs.mode == 'source' && inputs.environment_name || 'none' }}
    timeout-minutes: 120
    cache-mode: none
    permissions:
      actions: read
      contents: read
    defaults:
      run:
        shell: bash
    env:
      CI_REPOSITORY: ${{ github.repository }}
      CI_REF: ${{ github.ref }}
      CI_SHA: ${{ github.sha }}
      CI_SERVER_URL: ${{ github.server_url }}
      CI_EVENT_NAME: ${{ github.event_name }}
      CI_MODE: ${{ inputs.mode }}
      CI_WORKSPACE: ${{ github.workspace }}
      CACHE_MODE: none
      REQUESTED_SOURCE_SHA: ${{ inputs.source_sha }}
      REQUESTED_BASE_SHA: ${{ inputs.base_sha }}
      REQUESTED_BASE_BRANCH: ${{ inputs.base_branch }}
      REQUESTED_FINGERPRINT: ${{ inputs.fingerprint }}
      REQUESTED_ENVIRONMENT_NAME: ${{ inputs.environment_name }}
      SOURCE_REPOSITORY_ID: ${{ vars.SOURCE_REPOSITORY_ID }}
      SOURCE_REPOSITORY_OWNER: ${{ vars.LINUX_SOURCE_REPOSITORY_OWNER }}
      SOURCE_REPOSITORY_NAME: ${{ vars.LINUX_SOURCE_REPOSITORY_NAME }}
      SOURCE_READER_INSTALLATION_ID: ${{ vars.SOURCE_READER_INSTALLATION_ID }}
      SOURCE_READER_CLIENT_ID: ${{ vars.SOURCE_READER_CLIENT_ID }}
      LINUX_SOURCE_ALLOWED_SHA: ${{ vars.LINUX_SOURCE_ALLOWED_SHA }}
      LINUX_SOURCE_ALLOWED_BASE_SHA: ${{ vars.LINUX_SOURCE_ALLOWED_BASE_SHA }}
      LINUX_SOURCE_ALLOWED_BASE_BRANCH: ${{ vars.LINUX_SOURCE_ALLOWED_BASE_BRANCH }}
      LINUX_SOURCE_ALLOWED_FINGERPRINT: ${{ vars.LINUX_SOURCE_ALLOWED_FINGERPRINT }}
      LINUX_SOURCE_ALLOWED_CONTROL_SHA: ${{ vars.LINUX_SOURCE_ALLOWED_CONTROL_SHA }}
      LINUX_SOURCE_ENVIRONMENT_NAME: ${{ vars.LINUX_SOURCE_ENVIRONMENT_NAME }}
      LINUX_SOURCE_ACCEPTED_NODE_LOCK_SHA256: ${{ vars.LINUX_SOURCE_ACCEPTED_NODE_LOCK_SHA256 }}
      LINUX_SOURCE_ACCEPTED_MANIFEST_SHA256: ${{ vars.LINUX_SOURCE_ACCEPTED_MANIFEST_SHA256 }}
      LINUX_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON: ${{ vars.LINUX_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON }}
    steps:
      - name: Fetch exact public control
        run: |
          set -euo pipefail
          [[ "$CI_REPOSITORY" == "keeldock-platform/platform-ci" && "$CI_SERVER_URL" == "https://github.com" ]]
          [[ "$CI_REF" == "refs/heads/main" || "$CI_REF" == "refs/heads/untrusted" ]]
          [[ "$CI_SHA" =~ ^[a-f0-9]{40}$ ]]
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${CI_SERVER_URL%/}/${CI_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$CI_REF" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          [[ "$(git rev-parse --verify HEAD 2>/dev/null)" == "$CI_SHA" ]]
      - name: Repeat preflight in source-read
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: python3 -B kit/confinement/linux_source_build.py preflight
      - name: Record image and fetch pinned Rust and Node toolchains
        id: toolchains
        run: |
          set -euo pipefail
          if [[ "$CI_MODE" == "source" ]]; then
            python3 -B kit/confinement/linux_source_build.py toolchains
          else
            [[ "${ImageOS:-}" =~ ^[A-Za-z0-9._-]{1,64}$ && "${ImageVersion:-}" =~ ^[A-Za-z0-9._-]{1,64}$ ]]
            sysroot="$(rustc --print sysroot)"
            node_path="$(command -v node)"
            [[ "$sysroot" =~ ^/[A-Za-z0-9._/@+=-]{1,300}$ && -x "$sysroot/bin/rustc" ]]
            [[ "$node_path" == /usr/* ]]
            mkdir -p "$RUNNER_TEMP/kd-records"
            printf '%s\n' "rust_sysroot=$sysroot" >> "$GITHUB_OUTPUT"
            printf '%s\n' "linux-source-image schema=1 image-os=$ImageOS image-version=$ImageVersion mode=synthetic"
          fi
      - name: Harden runner paths before the proof
        run: |
          set -euo pipefail
          sudo -n python3 -B kit/confinement/linux_boundary.py harden --runner-uid "$(id -u)" --runner-home "$HOME" --runner-temp "$RUNNER_TEMP"
      - name: Boundary self-test before source-reader mint
        id: selftest
        env:
          KD_CANARY_SECRET: ${{ inputs.mode == 'synthetic' && 'kd-synthetic-standin-NOT-A-SECRET-0123456789abcdef0123456789abcd' || secrets.KD_LINUX_LOG_CANARY }}
          KD_RUST_SYSROOT: ${{ steps.toolchains.outputs.rust_sysroot }}
        run: |
          set -euo pipefail
          arguments=(--control-sha "$CI_SHA" --runner-uid "$(id -u)" --runner-home "$HOME" --runner-temp "$RUNNER_TEMP" --rust-sysroot "$KD_RUST_SYSROOT")
          if [[ "$CI_MODE" == "synthetic" ]]; then
            arguments+=(--synthetic-standin)
          fi
          sudo -n --preserve-env=KD_CANARY_SECRET python3 -B kit/confinement/linux_boundary.py selftest "${arguments[@]}" --record "$RUNNER_TEMP/kd-records/selftest.json"
      - name: Mint scoped source-reader token
        id: source-reader-token
        if: ${{ inputs.mode == 'source' }}
        uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510
        env:
          SOURCE_READER_PRIVATE_KEY: ${{ secrets.SOURCE_READER_PRIVATE_KEY }}
        with:
          client-id: ${{ vars.SOURCE_READER_CLIENT_ID }}
          private-key: ${{ env.SOURCE_READER_PRIVATE_KEY }}
          owner: ${{ vars.LINUX_SOURCE_REPOSITORY_OWNER }}
          repositories: ${{ vars.LINUX_SOURCE_REPOSITORY_NAME }}
          permission-contents: read
          skip-token-revoke: true
      - name: Verify selected installation identity
        if: ${{ inputs.mode == 'source' }}
        env:
          EXPECTED_INSTALLATION_ID: ${{ vars.SOURCE_READER_INSTALLATION_ID }}
          ACTUAL_INSTALLATION_ID: ${{ steps.source-reader-token.outputs.installation-id }}
        run: |
          set -euo pipefail
          [[ "$EXPECTED_INSTALLATION_ID" =~ ^[1-9][0-9]{0,18}$ ]]
          [[ "$ACTUAL_INSTALLATION_ID" =~ ^[1-9][0-9]{0,18}$ && "$ACTUAL_INSTALLATION_ID" == "$EXPECTED_INSTALLATION_ID" ]]
          printf '%s\n' "linux-source-installation=verified id=$ACTUAL_INSTALLATION_ID"
      - name: Fetch exact source and verify binding, tree, signatures and lock provenance
        id: checkout
        if: ${{ inputs.mode == 'source' }}
        env:
          SOURCE_READER_TOKEN: ${{ steps.source-reader-token.outputs.token }}
        run: python3 -B kit/confinement/linux_source_build.py checkout
      - name: Revoke source-reader token and verify rejection
        if: ${{ always() && steps.source-reader-token.outputs.token != '' }}
        env:
          SOURCE_READER_TOKEN: ${{ steps.source-reader-token.outputs.token }}
        run: python3 -B kit/confinement/linux_source_build.py revoke
      - name: Fetch npm tarballs by committed lock integrity
        id: npm-tarballs
        if: ${{ inputs.mode == 'source' }}
        env:
          SOURCE_PATH: ${{ steps.checkout.outputs.source_path }}
        run: python3 -B kit/confinement/linux_source_build.py npm-tarballs
      - name: Run trusted dependency audit
        if: ${{ inputs.mode == 'source' }}
        env:
          SOURCE_PATH: ${{ steps.checkout.outputs.source_path }}
          NODE_BIN: ${{ steps.toolchains.outputs.node_bin }}
        run: python3 -B kit/confinement/linux_source_build.py trusted-audit
      - name: Prepare offline project inputs
        id: project-deps
        if: ${{ inputs.mode == 'source' }}
        env:
          SOURCE_PATH: ${{ steps.checkout.outputs.source_path }}
          NPM_TARBALL_INDEX: ${{ steps.npm-tarballs.outputs.tarball_index }}
          RUST_ROOT: ${{ steps.toolchains.outputs.rust_root }}
          EXPECTED_NODE_LOCK_SHA256: ${{ steps.checkout.outputs.lock_sha256 }}
          EXPECTED_MANIFEST_SHA256: ${{ steps.checkout.outputs.manifest_sha256 }}
        run: sudo -n --preserve-env=SOURCE_PATH,NPM_TARBALL_INDEX,RUST_ROOT,EXPECTED_NODE_LOCK_SHA256,EXPECTED_MANIFEST_SHA256,RUNNER_TEMP,GITHUB_OUTPUT python3 -B kit/confinement/linux_source_build.py prepare-project
      - name: Re-run positive controls immediately before the first project command
        id: recheck
        env:
          KD_CANARY_SECRET: ${{ inputs.mode == 'synthetic' && 'kd-synthetic-standin-NOT-A-SECRET-0123456789abcdef0123456789abcd' || secrets.KD_LINUX_LOG_CANARY }}
          KD_RUST_SYSROOT: ${{ steps.toolchains.outputs.rust_sysroot }}
        run: |
          set -euo pipefail
          arguments=(--control-sha "$CI_SHA" --runner-uid "$(id -u)" --runner-home "$HOME" --runner-temp "$RUNNER_TEMP" --rust-sysroot "$KD_RUST_SYSROOT")
          if [[ "$CI_MODE" == "synthetic" ]]; then
            arguments+=(--synthetic-standin)
          fi
          sudo -n --preserve-env=KD_CANARY_SECRET python3 -B kit/confinement/linux_boundary.py recheck "${arguments[@]}" --record "$RUNNER_TEMP/kd-records/recheck.json"
      - name: Run all thirteen offline project gates
        if: ${{ inputs.mode == 'source' }}
        env:
          SOURCE_PATH: ${{ steps.checkout.outputs.source_path }}
          NPM_TARBALL_INDEX: ${{ steps.npm-tarballs.outputs.tarball_index }}
          RUST_ROOT: ${{ steps.toolchains.outputs.rust_root }}
          NODE_BIN: ${{ steps.toolchains.outputs.node_bin }}
          WORKER_PATH: ${{ steps.project-deps.outputs.worker_path }}
          CARGO_HOME: ${{ steps.project-deps.outputs.cargo_home }}
        run: sudo -n --preserve-env=WORKER_PATH,CARGO_HOME,RUST_ROOT,NODE_BIN,RUNNER_TEMP python3 -B kit/confinement/linux_source_build.py gates
      - name: Merge confinement phase records
        if: ${{ always() && steps.selftest.outcome != 'skipped' && steps.recheck.outcome != 'skipped' }}
        run: |
          set -euo pipefail
          sudo -n python3 -B kit/confinement/linux_boundary.py merge --selftest "$RUNNER_TEMP/kd-records/selftest.json" --recheck "$RUNNER_TEMP/kd-records/recheck.json" --out "$RUNNER_TEMP/kd-records/merged.json"
      - name: Forced faults must fail closed
        if: ${{ inputs.mode == 'synthetic' }}
        env:
          KD_CANARY_SECRET: kd-synthetic-standin-NOT-A-SECRET-0123456789abcdef0123456789abcd
          KD_RUST_SYSROOT: ${{ steps.toolchains.outputs.rust_sysroot }}
        run: |
          set -euo pipefail
          arguments=(--control-sha "$CI_SHA" --runner-uid "$(id -u)" --runner-home "$HOME" --runner-temp "$RUNNER_TEMP" --rust-sysroot "$KD_RUST_SYSROOT" --synthetic-standin)
          sudo -n --preserve-env=KD_CANARY_SECRET python3 -B kit/confinement/linux_boundary.py faults "${arguments[@]}"
  linux-source-admission-verdict:
    needs:
      - linux-source-admission-settings
      - linux-source-admission-unit
      - linux-source-admission-source-read
    if: ${{ always() && github.event_name == 'workflow_dispatch' && (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/untrusted') }}
    runs-on: ubuntu-24.04
    environment:
      name: ${{ inputs.mode == 'source' && inputs.environment_name || 'none' }}
    timeout-minutes: 15
    cache-mode: none
    permissions:
      contents: read
    defaults:
      run:
        shell: bash
    env:
      CI_SHA: ${{ github.sha }}
      CI_MODE: ${{ inputs.mode }}
      PRODUCER_RESULT: ${{ needs.linux-source-admission-source-read.result }}
    steps:
      - name: Fetch exact public control
        run: |
          set -euo pipefail
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${GITHUB_SERVER_URL%/}/${GITHUB_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$GITHUB_REF" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          [[ "$(git rev-parse --verify HEAD 2>/dev/null)" == "$GITHUB_SHA" ]]
      - name: Record verifier image and Rust sysroot
        id: verifier-toolchain
        run: |
          set -euo pipefail
          [[ "${ImageOS:-}" =~ ^[A-Za-z0-9._-]{1,64}$ && "${ImageVersion:-}" =~ ^[A-Za-z0-9._-]{1,64}$ ]]
          sysroot="$(rustc --print sysroot)"
          [[ "$sysroot" =~ ^/[A-Za-z0-9._/@+=-]{1,300}$ && -x "$sysroot/bin/rustc" ]]
          mkdir -p "$RUNNER_TEMP/kd-records"
          printf '%s\n' "rust_sysroot=$sysroot" >> "$GITHUB_OUTPUT"
          printf '%s\n' "linux-verifier-image schema=1 image-os=$ImageOS image-version=$ImageVersion"
      - name: Harden verifier runner paths
        run: |
          set -euo pipefail
          sudo -n python3 -B kit/confinement/linux_boundary.py harden --runner-uid "$(id -u)" --runner-home "$HOME" --runner-temp "$RUNNER_TEMP"
      - name: Run independent boundary self-test
        env:
          KD_CANARY_SECRET: ${{ inputs.mode == 'synthetic' && 'kd-synthetic-standin-NOT-A-SECRET-0123456789abcdef0123456789abcd' || secrets.KD_LINUX_LOG_CANARY }}
          KD_RUST_SYSROOT: ${{ steps.verifier-toolchain.outputs.rust_sysroot }}
        run: |
          set -euo pipefail
          arguments=(--control-sha "$CI_SHA" --runner-uid "$(id -u)" --runner-home "$HOME" --runner-temp "$RUNNER_TEMP" --rust-sysroot "$KD_RUST_SYSROOT")
          if [[ "$CI_MODE" == "synthetic" ]]; then
            arguments+=(--synthetic-standin)
          fi
          sudo -n --preserve-env=KD_CANARY_SECRET python3 -B kit/confinement/linux_boundary.py selftest "${arguments[@]}" --record "$RUNNER_TEMP/kd-records/selftest.json"
      - name: Re-run independent positive controls
        env:
          KD_CANARY_SECRET: ${{ inputs.mode == 'synthetic' && 'kd-synthetic-standin-NOT-A-SECRET-0123456789abcdef0123456789abcd' || secrets.KD_LINUX_LOG_CANARY }}
          KD_RUST_SYSROOT: ${{ steps.verifier-toolchain.outputs.rust_sysroot }}
        run: |
          set -euo pipefail
          arguments=(--control-sha "$CI_SHA" --runner-uid "$(id -u)" --runner-home "$HOME" --runner-temp "$RUNNER_TEMP" --rust-sysroot "$KD_RUST_SYSROOT")
          if [[ "$CI_MODE" == "synthetic" ]]; then
            arguments+=(--synthetic-standin)
          fi
          sudo -n --preserve-env=KD_CANARY_SECRET python3 -B kit/confinement/linux_boundary.py recheck "${arguments[@]}" --record "$RUNNER_TEMP/kd-records/recheck.json"
      - name: Merge independent confinement records
        run: |
          set -euo pipefail
          sudo -n python3 -B kit/confinement/linux_boundary.py merge --selftest "$RUNNER_TEMP/kd-records/selftest.json" --recheck "$RUNNER_TEMP/kd-records/recheck.json" --out "$RUNNER_TEMP/kd-records/merged.json"
      - name: Publish confinement verdict
        if: ${{ always() }}
        run: python3 -B kit/confinement/linux_source_build.py verdict
  linux-source-admission-audit:
    needs:
      - linux-source-admission-settings
      - linux-source-admission-unit
      - linux-source-admission-source-read
      - linux-source-admission-verdict
    if: ${{ always() && github.event_name == 'workflow_dispatch' && (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/untrusted') }}
    runs-on: ubuntu-24.04
    environment:
      name: ${{ inputs.mode == 'source' && inputs.environment_name || 'none' }}
    timeout-minutes: 15
    cache-mode: none
    permissions:
      actions: read
      checks: read
    defaults:
      run:
        shell: bash
    env:
      CI_MODE: ${{ inputs.mode }}
      CONFINEMENT_AUDIT_EXPECTED: ${{ needs.linux-source-admission-settings.outputs.expected }}
    steps:
      - name: Fetch exact public control
        run: |
          set -euo pipefail
          git init -q . 2>/dev/null
          git config core.autocrlf false 2>/dev/null
          git remote add origin "${GITHUB_SERVER_URL%/}/${GITHUB_REPOSITORY}.git" 2>/dev/null
          git fetch --quiet --no-tags --depth=1 origin "$GITHUB_REF" 2>/dev/null
          git checkout --quiet --detach FETCH_HEAD 2>/dev/null
          [[ "$(git rev-parse --verify HEAD 2>/dev/null)" == "$GITHUB_SHA" ]]
      - name: Audit logs, artifacts, cache metadata and verdict
        env:
          GITHUB_TOKEN: ${{ github.token }}
          KD_LINUX_LOG_CANARY: ${{ inputs.mode == 'synthetic' && '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' || secrets.KD_LINUX_LOG_CANARY }}
        run: python3 -B kit/confinement/linux_source_build.py audit
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

