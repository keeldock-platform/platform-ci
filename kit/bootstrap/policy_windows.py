"""Windows lane workflow validation data.

This module holds the exact reviewed workflow templates and digests that belong
to the Windows lane. It is imported statically by the shared policy module,
which dispatches to it through a fixed registry. It must not import the shared
policy module, so that the registry stays free of import cycles.

Lane interface, identical in every lane module:

WORKFLOW_TEMPLATES maps a workflow kind to its exact expected text.
WORKFLOW_SHA256 maps a workflow kind to the expected SHA-256 of its text.
CANDIDATE_WORKFLOWS lists, in order, the path, workflow kind and size-failure
code that the candidate checker validates when the pool is platform.
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

WINDOWS_CONFINEMENT_WORKFLOW_TEMPLATE = """name: windows-confinement
on:
  push:
    branches:
      - "**"
  pull_request:
  workflow_dispatch:
permissions: {}
jobs:
  windows-policy:
    runs-on: windows-2025
    timeout-minutes: 15
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
      - name: Fetch public candidate
        run: |
          $ErrorActionPreference = 'Stop'
          $ProgressPreference = 'SilentlyContinue'
          if ($env:CI_REPOSITORY -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { exit 1 }
          if ($env:CI_SHA -notmatch '^[a-f0-9]{40}$') { exit 1 }
          if ($env:CI_SERVER_URL -notmatch '^https://[A-Za-z0-9.-]+$') { exit 1 }
          if ($env:CI_EVENT_NAME -eq 'pull_request') {
            if ($env:CI_REF -notmatch '^refs/pull/[1-9][0-9]*/merge$') { exit 1 }
          } else {
            if ($env:CI_REF -notmatch '^refs/heads/[A-Za-z0-9._/-]+$') { exit 1 }
          }
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
      - name: Run unprivileged source-free checks
        run: |
          $ErrorActionPreference = 'Stop'
          python -B kit/bootstrap/test_public_tree.py
          if ($LASTEXITCODE -ne 0) { exit 1 }
          python -B kit/bootstrap/test_policy_windows.py
          if ($LASTEXITCODE -ne 0) { exit 1 }
          python -B kit/confinement/test_windows_confinement.py
          if ($LASTEXITCODE -ne 0) { exit 1 }
          python -B kit/bootstrap/check_candidate.py --root $env:CI_WORKSPACE --pool platform --sha $env:CI_SHA
          if ($LASTEXITCODE -ne 0) { exit 1 }
      - name: Compile native confinement module
        run: |
          $ErrorActionPreference = 'Stop'
          & kit/confinement/windows_confinement.ps1 -Mode compile
          if ($LASTEXITCODE -ne 0) { exit 1 }
  windows-confinement-spike:
    needs: windows-policy
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on: windows-2025
    timeout-minutes: 45
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
      - name: Check reviewed control tree
        run: |
          $ErrorActionPreference = 'Stop'
          python -B kit/bootstrap/test_public_tree.py
          if ($LASTEXITCODE -ne 0) { exit 1 }
          python -B kit/bootstrap/test_policy_windows.py
          if ($LASTEXITCODE -ne 0) { exit 1 }
          python -B kit/confinement/test_windows_confinement.py
          if ($LASTEXITCODE -ne 0) { exit 1 }
          python -B kit/bootstrap/check_candidate.py --root $env:CI_WORKSPACE --pool platform --sha $env:CI_SHA
          if ($LASTEXITCODE -ne 0) { exit 1 }
      - name: Run source-free LPAC toolchain spike
        run: |
          $ErrorActionPreference = 'Stop'
          & kit/confinement/windows_confinement.ps1 -Mode spike
          if ($LASTEXITCODE -ne 0) { exit 1 }
"""

WORKFLOW_TEMPLATES = {
    "windows-native-preflight": WINDOWS_NATIVE_PREFLIGHT_WORKFLOW_TEMPLATE,
    "windows-confinement": WINDOWS_CONFINEMENT_WORKFLOW_TEMPLATE,
}
WORKFLOW_SHA256 = {}
CANDIDATE_WORKFLOWS = (
    (
        ".github/workflows/windows-native-preflight.yml",
        "windows-native-preflight",
        "windows-workflow-too-large",
    ),
    (
        ".github/workflows/windows-confinement.yml",
        "windows-confinement",
        "windows-confinement-workflow-too-large",
    ),
)
