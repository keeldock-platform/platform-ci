**Encrypted dev lane: owner procedure**

This is the committed procedure for running the encrypted public dev lane. It is a draft for owner review and has not been executed. Every command runs from an authenticated clone of `keeldock-platform/platform-ci` at the exact reviewed commit. The tools never dispatch a workflow, create a secret or touch a setting on their own; every GitHub write in this document is a command the owner types.

**Standing rules**

- Keep the owner directory (`DEVLANE_PRIVATE` below) at mode 0700, outside every checkout. It holds request files, the ledger, the projection, the ciphertext and, briefly, the key file.
- Never put key material on a command line, in a checkout, in an environment variable of a long-lived shell, or in a log. The key reaches GitHub over standard input. A shell trap removes the local key file on handled shell exits; process kill, interpreter failure and host loss can bypass it.
- One open wave at a time. A bundle is never reused. Never retry a dispatch; reconcile instead.
- Revoking the key as soon as the decrypt step concludes is mandatory and timed (step 8). A wave whose revocation missed the limit is recorded as late and reviewed before the next wave.
- A coordinator `finally` block and its watcher run only while that process and host remain alive. Process kill, interpreter failure or host loss can leave a secret installed. Before any later wave, run `recover-pending-secrets`, verify it completes, and resolve every open wave. This recovery is durable and resumable; it cannot guarantee revocation within 120 seconds during process, host or API loss.
- Keep `record-control-evidence` mandatory (step 1). Any job running on `main` can write an Actions cache entry named like control evidence, so the cache entry alone is never trusted; the coordinator re-reads the real control run, its 18 jobs and the single matching cache entry.
- Outputs are drafts until reviewed. Do not use a private wave result for a business decision before the rehearsal below has passed on the exact commit.

**One-time GitHub setup (owner)**

1. Branch rules and the order in which to apply them are in `docs/branch-promotion.md`. They must be complete, with the control green on `main` at the commit you intend to use.
2. Create the decryption environment. It admits only `main`, gives administrators no bypass of that rule (`can_admins_bypass` is false) and has no reviewers, no wait timer, no variables and no secrets until a wave installs one. A reviewer gate or a wait timer would hold a run while the key is installed, so neither is allowed.

   ```sh
   gh api --method PUT repos/keeldock-platform/platform-ci/environments/devlane-decrypt --input - <<'JSON'
   {"can_admins_bypass":false,"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
   JSON
   gh api --method POST repos/keeldock-platform/platform-ci/environments/devlane-decrypt/deployment-branch-policies --input - <<'JSON'
   {"name":"main","type":"branch"}
   JSON
   ```

   The coordinator checks this before every install (`mark-secret-installing` refuses unless the environment exists, uses custom branch policies, lists exactly the branch `main` and has `can_admins_bypass` false). `dispatch-wave` repeats the check after installation and rereads remote `main` before dispatch.
3. Make sure no repository-wide secret named `DEVLANE_DECRYPT_KEY` exists. The key lives only in the environment. A repository-wide copy would be readable by any workflow on any branch, so the coordinator refuses to reserve a wave while one exists and deletes any it finds during revocation.
4. Choose one owner-approved release for temporary assets and note its numeric release ID.

**Variables used below**

```sh
set -euo pipefail
umask 077
REPO=keeldock-platform/platform-ci
CONTROL_SHA="$(git rev-parse HEAD)"
CONTROL_WAVE_ID="control-$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
CONTROL_RUN_ID=""
WAVE_ID="wave-$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
BUNDLE_ID="bundle-$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
DEVLANE_PRIVATE="$HOME/devlane-owner/$WAVE_ID"
mkdir -p -m 700 "$DEVLANE_PRIVATE" "$DEVLANE_PRIVATE/ledger"
```

The clone must be checked out at the exact reviewed commit that is on `main`. The following guard binds the wave to that full SHA before any dispatch:

```sh
test "$(git branch --show-current)" = main
REMOTE_MAIN_SHA="$(gh api "repos/$REPO/git/ref/heads/main" --jq '.object.sha')"
test "$CONTROL_SHA" = "$REMOTE_MAIN_SHA"
```

`CONTROL_SHA`, `CONTROL_WAVE_ID`, and `CONTROL_RUN_ID` are defined before step 1. `CONTROL_WAVE_ID`, `WAVE_ID`, and `BUNDLE_ID` are fresh opaque identifiers (8 to 64 characters from letters, digits, underscore and hyphen); never reuse one. Step 1 persists the dispatch interval and exact wave identity in the private ledger, then reconciles complete paginated run inventories to a fixed deadline. It refuses incomplete or multiple matches and never dispatches again. `RUN_ID` is set by the coordinator only after exact repository, workflow, `main` ref, full SHA, attempt, title/input and dispatch interval checks. `RELEASE_ID` is the numeric release ID from setup. The local clock must be synchronised by NTP (check System Settings, Date and Time, "Set time and date automatically"): revocation latency uses GitHub's decrypt-step timestamp.

**Wave sequence (rehearsal and private waves are identical except where marked)**

1. Run the source-free control on `main` at the exact commit, with a fresh opaque control wave identifier. The coordinator verifies remote `main`, records one dispatch interval before calling GitHub, issues exactly one dispatch, and polls complete paginated inventories for the exact `public control=<CONTROL_WAVE_ID>` title and canonical run identity. Zero results are polled until the persisted deadline; API refusal, incomplete inventory or multiple matches stops the operation. It never dispatches again.

   ```sh
   (
     set -euo pipefail
     [[ "$(git branch --show-current)" == "main" ]] || { echo "checkout must be main" >&2; exit 2; }
     REMOTE_MAIN_SHA="$(gh api "repos/$REPO/git/ref/heads/main" --jq '.object.sha')"
     [[ "$REMOTE_MAIN_SHA" == "$CONTROL_SHA" ]] || { echo "remote main moved" >&2; exit 2; }
     python3 -B kit/devlane/coordinator.py dispatch-control \
       --ledger "$DEVLANE_PRIVATE/ledger" --control-sha "$CONTROL_SHA" \
       --control-wave-id "$CONTROL_WAVE_ID" > "$DEVLANE_PRIVATE/control-dispatch.out"
     CONTROL_RUN_ID="$(sed -n 's/^control_reconciliation=attached run-id=\([0-9]*\)$/\1/p' \
       "$DEVLANE_PRIVATE/control-dispatch.out" | tail -n 1)"
     [[ "$CONTROL_RUN_ID" =~ ^[1-9][0-9]*$ ]] || { echo "control run id missing" >&2; exit 2; }
     printf '%s\n' "$CONTROL_RUN_ID" > "$DEVLANE_PRIVATE/control-run-id.txt"
     gh run watch "$CONTROL_RUN_ID" --repo "$REPO" --exit-status
     python3 -B kit/devlane/coordinator.py record-control-evidence \
       --ledger "$DEVLANE_PRIVATE/ledger" --control-run-id "$CONTROL_RUN_ID" \
       --control-sha "$CONTROL_SHA" --control-wave-id "$CONTROL_WAVE_ID"
   )
   CONTROL_RUN_ID="$(cat -- "$DEVLANE_PRIVATE/control-run-id.txt")"
   [[ "$CONTROL_RUN_ID" =~ ^[1-9][0-9]*$ ]] || { echo "saved control run id invalid" >&2; exit 2; }
   ```
2. The parent shell reloads and validates `control-run-id.txt` after the checked step-1 subshell. It uses that value for the evidence command and later request construction. The checked control command records evidence only after the exact run completes with all 18 jobs green and the expected wave title. If it fails, inspect the private dispatch record and reconcile; do not retry the dispatch.

3. Build the inputs.
   - Rehearsal: create the throwaway synthetic repository and its projection request.

     ```sh
     python3 -B kit/devlane/rehearsal.py source --directory "$DEVLANE_PRIVATE"
     ```

   - Private wave: write `projection-request.json` yourself in the owner directory. It holds `schema` 1, the absolute `repository` path, the exact `source_revision`, `profile`, the `tools` versions (`node` and `npm`, or `cargo` and `rustc`), `playwright` and the lockfile path (`lockfile` for the Node profile, `lockfiles` for the Rust profile).

   Then build the sanitized dependency projection from the lock at that exact revision:

   ```sh
   python3 -B kit/devlane/project.py --request "$DEVLANE_PRIVATE/projection-request.json" --output "$DEVLANE_PRIVATE/projection.json"
   ```

4. Reserve the wave. The request lifetime is at most one hour, so build it only when you are ready to run the whole sequence.
   - Rehearsal: `python3 -B kit/devlane/rehearsal.py requests --directory "$DEVLANE_PRIVATE" --control-sha "$CONTROL_SHA" --control-run-id "$CONTROL_RUN_ID" --wave-id "$WAVE_ID" --bundle-id "$BUNDLE_ID" --release-id "$RELEASE_ID" --lifetime-seconds 3300` writes `reserve.json` and `bundle-request.json`.
   - Private wave: write `reserve.json` (exactly `schema` 2, `wave_id`, `bundle_id`, `control_run_id`, `control_sha`, `profile`, `expires` in Unix seconds, `release_id`) and `bundle-request.json` (exactly `repository`, `source_revision`, `profile`, `fetch_sha256` equal to the SHA-256 of `projection.json`, `wave_id`, `bundle_id`, `control_sha`, `expires`, `source_files`, `allowed_files`, `allowed_tests`, `frames`) with the same `expires`.

   ```sh
   python3 -B kit/devlane/coordinator.py reserve-wave --ledger "$DEVLANE_PRIVATE/ledger" --request "$DEVLANE_PRIVATE/reserve.json"
   ```

5. Create the encrypted bundle. The producer generates a fresh random key per bundle and writes it to the key file (mode 0600). The key is disposable for the rehearsal and is treated as secret for every private wave.

   ```sh
   python3 -B kit/devlane/bundle.py create --request "$DEVLANE_PRIVATE/bundle-request.json" --ciphertext "$DEVLANE_PRIVATE/bundle.enc" --key-file "$DEVLANE_PRIVATE/key.hex"
   ```

6. Stage the cleanup obligations before any upload.

   ```sh
   python3 -B kit/devlane/rehearsal.py staged --directory "$DEVLANE_PRIVATE"
   python3 -B kit/devlane/coordinator.py stage-bundle --ledger "$DEVLANE_PRIVATE/ledger" --wave-id "$WAVE_ID" --request "$DEVLANE_PRIVATE/staged-assets.json"
   ```

7. Upload only the ciphertext and the projection, as files named exactly as recorded in the ledger (an asset takes its file name), read the numeric asset IDs back, take the cache baseline immediately before recording the intent, and record it.

   ```sh
   BUNDLE_ASSET_NAME="devlane-$WAVE_ID-$BUNDLE_ID.enc"
   PROJECTION_ASSET_NAME="devlane-$WAVE_ID-$BUNDLE_ID.projection.json"
   cp -- "$DEVLANE_PRIVATE/bundle.enc" "$DEVLANE_PRIVATE/$BUNDLE_ASSET_NAME"
   cp -- "$DEVLANE_PRIVATE/projection.json" "$DEVLANE_PRIVATE/$PROJECTION_ASSET_NAME"
   gh release upload "$RELEASE_TAG" "$DEVLANE_PRIVATE/$BUNDLE_ASSET_NAME" "$DEVLANE_PRIVATE/$PROJECTION_ASSET_NAME" --repo "$REPO"
   BUNDLE_ASSET_ID="$(gh api "repos/$REPO/releases/$RELEASE_ID/assets" --paginate --jq ".[] | select(.name==\"$BUNDLE_ASSET_NAME\") | .id")"
   PROJECTION_ASSET_ID="$(gh api "repos/$REPO/releases/$RELEASE_ID/assets" --paginate --jq ".[] | select(.name==\"$PROJECTION_ASSET_NAME\") | .id")"
   CACHE_BASELINE_SHA256="$(python3 -B kit/devlane/coordinator.py cache-baseline | sed 's/^cache_baseline_sha256=//')"
   python3 -B kit/devlane/rehearsal.py intent --directory "$DEVLANE_PRIVATE" --wave-id "$WAVE_ID" --bundle-asset-id "$BUNDLE_ASSET_ID" --projection-asset-id "$PROJECTION_ASSET_ID" --cache-baseline-sha256 "$CACHE_BASELINE_SHA256"
   python3 -B kit/devlane/coordinator.py record-intent --ledger "$DEVLANE_PRIVATE/ledger" --request "$DEVLANE_PRIVATE/intent.json"
   ```

   `RELEASE_TAG` is the tag of the release chosen in setup.

8. Install the key, dispatch once, reconcile and arm timed revocation as one coordinator operation. The operation checks remote `main` before installation and again before dispatch. Immediately after GitHub confirms installation, it persists an absolute 300-second reconciliation deadline and starts a watcher. The watcher follows only the ledger-bound run, revokes when the decrypt step concludes or the run ends, and revokes at the deadline if no run becomes visible. Failed or ambiguous dispatch responses still reconcile; no second dispatch is issued. API refusal, multiple/incomplete inventory, deadline expiry, interruption or watcher failure enters the in-process revocation path. A caught failure leaves `installation-pending` or `secret-delete-pending` in the fsynced ledger until both secret endpoints are verified absent. `finally` and the watcher do not survive process or host loss; recovery is mandatory before the next wave. Do not audit, guess, attach, delete or redispatch an unbound run.

   ```sh
   (
     set -euo pipefail
     cleanup() {
       status=$?
       trap - EXIT INT TERM HUP
       rm -f -- "$DEVLANE_PRIVATE/key.hex" || echo "local key-file removal failed" >&2
       python3 -B kit/devlane/coordinator.py revoke-secret \
         --ledger "$DEVLANE_PRIVATE/ledger" --wave-id "$WAVE_ID" || \
         echo "secret revocation remains pending; inspect ledger and retry revoke-secret" >&2
       exit "$status"
     }
     trap cleanup EXIT
     trap 'exit 130' INT
     trap 'exit 143' TERM
     trap 'exit 129' HUP
     REMOTE_MAIN_SHA="$(gh api "repos/$REPO/git/ref/heads/main" --jq '.object.sha')"
     [[ "$REMOTE_MAIN_SHA" == "$CONTROL_SHA" ]] || { echo "remote main moved" >&2; exit 2; }
     python3 -B kit/devlane/coordinator.py dispatch-wave \
       --ledger "$DEVLANE_PRIVATE/ledger" --wave-id "$WAVE_ID" \
       --key-file "$DEVLANE_PRIVATE/key.hex" > "$DEVLANE_PRIVATE/dispatch-wave.out"
     RUN_ID="$(sed -n 's/^dispatch_wave=attached run-id=\([0-9]*\)$/\1/p' \
       "$DEVLANE_PRIVATE/dispatch-wave.out" | tail -n 1)"
     [[ "$RUN_ID" =~ ^[1-9][0-9]*$ ]] || { echo "run id missing" >&2; exit 2; }
     printf '%s\n' "$RUN_ID" > "$DEVLANE_PRIVATE/run-id.txt"
   )
   ```

9. After the coordinator returns successfully, read the run ID from the private file and wait for the run to complete. This command does not change the recorded run identity.

   ```sh
   RUN_ID="$(cat -- "$DEVLANE_PRIVATE/run-id.txt")"
   [[ "$RUN_ID" =~ ^[1-9][0-9]*$ ]] || { echo "run id missing" >&2; exit 2; }
   gh run watch "$RUN_ID" --repo "$REPO" --exit-status
   ```

10. When the run completes, mark it terminal. This revokes again if needed, verifies absence before anything is audited, runs the auditor over the real public surfaces and preserves validated diagnostics privately.

   ```sh
   python3 -B kit/devlane/coordinator.py mark-terminal --ledger "$DEVLANE_PRIVATE/ledger" --wave-id "$WAVE_ID"
   ```

11. Clean up until it reports complete. It is resumable, revokes first, then deletes both assets, logs, artifacts and the run, verifying each absence. An open wave blocks the next wave.

    ```sh
    python3 -B kit/devlane/coordinator.py cleanup-terminal --ledger "$DEVLANE_PRIVATE/ledger" --wave-id "$WAVE_ID"
    ```

   If cleanup is incomplete, keep the ledger and wave open, read the obligation states and rerun after the external refusal or ambiguity is resolved. Never dispatch a replacement wave before `terminal_cleanup=complete`.

12. Before reserving any later wave, explicitly recover durable secret obligations left by an interrupted process. This operation verifies absence at both secret endpoints and retains the pending record if either API call is refused. A pending record blocks `reserve-wave` until recovery completes. If the host or GitHub API is unavailable, the 120-second revocation criterion remains open; do not report it as met.

    ```sh
    python3 -B kit/devlane/coordinator.py recover-pending-secrets --ledger "$DEVLANE_PRIVATE/ledger"
    ```

**Rehearsal wave (required before the first private wave)**

Run the whole wave sequence above on the exact commit that is on `main`. The default `rehearsal.py source` profile is the hostile synthetic Node fixture. For the Rust matrix, select `core-rust` explicitly:

```sh
python3 -B kit/devlane/rehearsal.py source --directory "$DEVLANE_PRIVATE" --profile core-rust
```

The Rust fixture is a multi-crate root workspace, an independent fuzz-replay package, a second workspace with a listener package, and three committed `Cargo.lock` files. Its only crates.io dependencies are `itoa` and `fastrand`, so the workflow exercises offline vendoring. The source plants source and key canaries plus workflow-command text in build and test output. Its isolation test fails if network access, host paths, control environment values, key bytes in visible files, or inherited socket descriptors are present. It contains no private source. Both profile runs use the existing encrypted workflow dispatch and audit path; the source-free control never runs that path.

Pass criteria. All of them must hold before any private wave:

1. Step 8 installed the key as an environment secret on `devlane-decrypt`, and the coordinator accepted the environment restriction to `main`. Both the environment branch policy and the workflow's own reference check admit only `main`; the coordinator rechecks the environment and remote `main` immediately before installation and dispatch.
2. The run took the real permit path, restored the control evidence cache, saved and restored the one-run permit, fetched both assets anonymously, received the secret only in the decrypt step, and printed no canary text anywhere. For `core-rust`, the report must contain every fixed matrix coverage ID; all 22 non-SemVer suites pass and the synthetic-only `semver-runtime` row is the exact fail-closed `DEVLANE_SEMVER_EXECUTION` negative control described below.
3. Step 8 printed `within_limit=true`.
4. Step 10 recorded the audit disposition `accepted`, which means the real hosted log satisfied the closed log grammar. Read it with:

   ```sh
   python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["cleanup_attempts"][-1]["audit_disposition"])' "$DEVLANE_PRIVATE/ledger/$WAVE_ID.json"
   ```

   A different value, or a refusal naming a log line, means the grammar needs one reviewed adjustment for a line the hosted runner really prints. The grammar fails closed, so adjust it in a reviewed change and repeat the rehearsal with a new wave and bundle. Do not relax the auditor ad hoc.
5. Step 11 reported `terminal_cleanup=complete` and the ledger state is `deleted`: the key, both release assets, the logs, any artifacts and the run are absent, and later requests for them return 404.
6. Duplicate refusal. Dispatch the duplicate only after step 8 has attached the first run and that run's step named Claim this bundle for one run before decryption has succeeded (check with `gh run view "$RUN_ID" --repo "$REPO" --json jobs`); an earlier duplicate makes the complete inventory ambiguous, so the coordinator refuses attachment and revokes while retaining cleanup obligations. While the first run is still queued or running, dispatch the same inputs a second time with the same bundle identifier (the per-bundle concurrency group holds it until the first run ends). Do this without installing a second key. When it runs, it must fail at the step named Claim this bundle for one run before decryption, with every later step, including the decrypt step, not started. Check the failed step with `gh run view "$DUPLICATE_RUN_ID" --repo "$REPO" --json jobs`, and check that the duplicate started before the bundle `expires` value, so that the refusal is for reuse and not for expiry. The duplicate is outside the ledger by design (the ledger refuses a reused bundle at reservation). Match it by its run title and its run identifier being different from the first, then delete it and confirm it is gone:

   ```sh
   gh run delete "$DUPLICATE_RUN_ID" --repo "$REPO"
   gh api -i "repos/$REPO/actions/runs/$DUPLICATE_RUN_ID" | head -n 1
   ```

   Its audit job is expected to fail, because the duplicate never decrypts.
7. After the rehearsal, confirm that no environment secret and no repository secret named `DEVLANE_DECRYPT_KEY` remains and that the local key file is gone.

Record the rehearsal verdict, the commit it ran on and the measured revocation latency. If any criterion fails, fix it in a reviewed change, rebase the commit onto `main`, rerun the control and repeat the rehearsal. The rehearsal never counts for a different commit.

**Profile coverage and Rust acceptance.** A `core-rust` rehearsal uses the pinned Rust toolchain, the three-workspace matrix, default and all-feature test arms, replay target, and the same encrypted workflow, cleanup, audit, and duplicate-refusal path. For this synthetic schema-1 fixture, `semver-runtime` must refuse with `DEVLANE_SEMVER_EXECUTION`: the production SemVer v2 stage is bound to the real candidate and baseline source maps, which this small synthetic tree cannot satisfy. Treat that one exact refusal as expected only for this fixture; any other missing or failed coverage is a rehearsal failure. The in-run audit must still accept the completed log grammar, and terminal cleanup must complete.

This fixture proves the encrypted legacy Rust vendoring and matrix path and that the source-bound SemVer gate still fails closed. It does not exercise the production schema-2 Rust preparation and SemVer execution path, so it cannot authorize private `core-rust` waves. Keep those waves disabled until a reviewed schema-2 source-bound rehearsal can exercise that path on the exact commit on `main`. `core-node` remains governed by its own successful rehearsal criteria.

**Residual risks the owner has accepted**

- Dependency disclosure. The sanitized projection asset is public while a wave is open and lists every public dependency name and version (and the crate list for the Rust profile). Anyone who fetches it in that window learns the dependency set of the private project. It is deleted at cleanup.
- Records side channel. Code that runs during the offline phase, including third-party dependency code, controls up to 100 records per run, each with a file identifier, line, diagnostic code and test result. That is a few kilobits per run, enough to carry a short credential or a fragment of source. The records are limited to opaque identifiers, 100 records and 16 KiB, and nothing else leaves the runner.
- Report integrity. The test adapters and the workload run as the same user inside the isolation, so a test binary could rewrite its own report. The effect is limited to a false pass or false failure; the public output is still filtered through the allowlist and cannot carry anything else. Treat a private wave result as evidence from code you chose to run, not as a verified attestation.
- Install scripts. A dependency that declares an install script is accepted. Scripts are never run (project configuration, environment and the install flag each suppress them), the marker is not projected, and the control installs a public package with an install script to prove the suppression.
- Step names. Some check step names still read "protected-branch dispatch" although the source-free control now accepts any `refs/heads/` branch. The names are fixed in the exact policy templates and auditors; they are cosmetic and renaming them is deferred.
- Revocation window. The key stays installed until the decrypt step concludes (step 8). Revoking earlier, once the run job's setup step completes (secrets are handed to the runner at assignment), would shrink that window and is deferred until the rehearsal can prove it on a real run.
- Hosted behavior. Secret masking and injection, run deletion semantics and the exact hosted log format are proven only by a real dispatch, which is why the rehearsal is required.
