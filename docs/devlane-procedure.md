**Encrypted dev lane: owner procedure**

This is the committed procedure for running the encrypted public dev lane. It is a draft for owner review and has not been executed. Every command runs from an authenticated clone of `keeldock-platform/platform-ci` at the exact reviewed commit. The tools never dispatch a workflow, create a secret or touch a setting on their own; every GitHub write in this document is a command the owner types.

**Standing rules**

- Keep the owner directory (`DEVLANE_PRIVATE` below) at mode 0700, outside every checkout. It holds request files, the ledger, the projection, the ciphertext and, briefly, the key file.
- Never put key material on a command line, in a checkout, in an environment variable of a long-lived shell, or in a log. The key reaches GitHub over standard input and the local key file is removed by a trap on every exit path.
- One open wave at a time. A bundle is never reused. Never retry a dispatch; reconcile instead.
- Revoking the key as soon as the decrypt step concludes is mandatory and timed (step 11). A wave whose revocation missed the limit is recorded as late and reviewed before the next wave.
- Keep `record-control-evidence` mandatory (step 2). Any job running on `main` can write an Actions cache entry named like control evidence, so the cache entry alone is never trusted; the coordinator re-reads the real control run, its 18 jobs and the single matching cache entry.
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

   The coordinator checks this before every install (`mark-secret-installing` refuses unless the environment exists, uses custom branch policies, lists exactly the branch `main` and has `can_admins_bypass` false). `mark-secret-installed` repeats the same check, so a setting changed between the install and the dispatch is caught.
3. Make sure no repository-wide secret named `DEVLANE_DECRYPT_KEY` exists. The key lives only in the environment. A repository-wide copy would be readable by any workflow on any branch, so the coordinator refuses to reserve a wave while one exists and deletes any it finds during revocation.
4. Choose one owner-approved release for temporary assets and note its numeric release ID.

**Variables used below**

```sh
umask 077
REPO=keeldock-platform/platform-ci
WAVE_ID="wave-$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
BUNDLE_ID="bundle-$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
DEVLANE_PRIVATE="$HOME/devlane-owner/$WAVE_ID"
mkdir -p -m 700 "$DEVLANE_PRIVATE" "$DEVLANE_PRIVATE/ledger"
```

`WAVE_ID` and `BUNDLE_ID` are fresh opaque identifiers (8 to 64 characters from letters, digits, underscore and hyphen), defined above before any use; never reuse one. `RELEASE_ID` is the numeric release ID from setup. `CONTROL_RUN_ID` and `CONTROL_SHA` come from step 1. `RUN_ID` is set by step 10 from the coordinator output. The local clock must be synchronised by NTP (check System Settings, Date and Time, "Set time and date automatically"): step 11 compares it with GitHub's timestamps.

**Wave sequence (rehearsal and private waves are identical except where marked)**

1. Run the source-free control on `main` at the exact commit, with a fresh opaque control wave identifier, and wait for it to pass all 18 jobs.

   ```sh
   gh workflow run public-policy.yml --repo "$REPO" --ref main -f control_wave_id="$CONTROL_WAVE_ID"
   gh run list --repo "$REPO" --workflow public-policy.yml --branch main --limit 5 --json databaseId,headSha,status,conclusion
   ```

2. Record the control evidence. It reads the run, all 18 jobs, their steps and the single evidence cache entry. Stop if anything is missing or the commit differs.

   ```sh
   python3 -B kit/devlane/coordinator.py record-control-evidence --ledger "$DEVLANE_PRIVATE/ledger" --control-run-id "$CONTROL_RUN_ID" --control-sha "$CONTROL_SHA"
   ```

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

8. Install the key into the environment, immediately before the one dispatch. The subshell removes the local key file on every exit path. If it fails, do not dispatch: run the cleanup in step 13, which revokes first.

   ```sh
   (
     set -euo pipefail
     trap 'rm -f -- "$DEVLANE_PRIVATE/key.hex"' EXIT
     python3 -B kit/devlane/coordinator.py mark-secret-installing --ledger "$DEVLANE_PRIVATE/ledger" --wave-id "$WAVE_ID"
     gh secret set DEVLANE_DECRYPT_KEY --env devlane-decrypt --repo "$REPO" < "$DEVLANE_PRIVATE/key.hex"
     python3 -B kit/devlane/coordinator.py mark-secret-installed --ledger "$DEVLANE_PRIVATE/ledger" --wave-id "$WAVE_ID"
   )
   ```

9. Mark the dispatch, then dispatch exactly once on `main`. Send only public identity fields. The sizes and digests come from the stage record and the expiry and profile from the reservation.

   ```sh
   field() { python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }
   BUNDLE_SHA256="$(field "$DEVLANE_PRIVATE/staged-assets.json" bundle_sha256)"
   BUNDLE_SIZE="$(field "$DEVLANE_PRIVATE/staged-assets.json" bundle_size)"
   PROJECTION_SHA256="$(field "$DEVLANE_PRIVATE/staged-assets.json" projection_sha256)"
   PROJECTION_SIZE="$(field "$DEVLANE_PRIVATE/staged-assets.json" projection_size)"
   EXPIRES="$(field "$DEVLANE_PRIVATE/reserve.json" expires)"
   PROFILE="$(field "$DEVLANE_PRIVATE/reserve.json" profile)"
   python3 -B kit/devlane/coordinator.py mark-dispatch-requested --ledger "$DEVLANE_PRIVATE/ledger" --wave-id "$WAVE_ID"
   gh workflow run devlane-encrypted.yml --repo "$REPO" --ref main -f profile="$PROFILE" -f control_run_id="$CONTROL_RUN_ID" -f wave_id="$WAVE_ID" -f bundle_id="$BUNDLE_ID" -f bundle_asset_id="$BUNDLE_ASSET_ID" -f bundle_sha256="$BUNDLE_SHA256" -f bundle_size="$BUNDLE_SIZE" -f projection_asset_id="$PROJECTION_ASSET_ID" -f projection_sha256="$PROJECTION_SHA256" -f projection_size="$PROJECTION_SIZE" -f expires="$EXPIRES" -f cache_baseline_sha256="$CACHE_BASELINE_SHA256"
   ```

10. Reconcile to find the one run bound to this wave (by its run title, else its in-run marker). Repeat while it exits 3; stop on exit 2. Never attach a run by guess. `RUN_ID` is taken from the coordinator's own `dispatch_reconciliation=attached run-id=...` line.

    ```sh
    while :; do
      status=0
      python3 -B kit/devlane/coordinator.py reconcile-dispatch --ledger "$DEVLANE_PRIVATE/ledger" --wave-id "$WAVE_ID" > "$DEVLANE_PRIVATE/reconcile.out" || status=$?
      if [ "$status" -eq 3 ]; then sleep 10; continue; fi
      [ "$status" -eq 0 ] || { echo "reconcile refused"; break; }
      RUN_ID="$(sed -n 's/^dispatch_reconciliation=attached run-id=\([0-9]*\)$/\1/p' "$DEVLANE_PRIVATE/reconcile.out")"
      break
    done
    echo "RUN_ID=$RUN_ID"
    ```

11. Timed revocation. Start this as soon as the run is attached and leave it running. It polls the run, and the moment the step named Decrypt authenticated bundle concludes (or the run ends, or the timeout passes) it revokes the environment secret and any repository-wide copy, verifies absence, and prints the latency. A poll error is retried until the timeout and never skips the revocation, which also runs if the command is interrupted. Exit 0 means revoked within 120 seconds of the step concluding. Exit 3 means revoked but late, after a timeout or after the polling failed (`within_limit=false`; the output shows `timed_out` and `poll_failed`). Exit 2 means the revocation itself failed or the wave was not in the right state: run `revoke-secret` immediately and repeat until it reports the key absent. Record the printed latency with the wave. The latency compares your local clock with GitHub's step timestamp and clamps a negative difference to zero, so a clock that is behind GitHub's understates it; keep the clock NTP-synchronised and treat a figure within a second or two of the limit as unproven.

    ```sh
    python3 -B kit/devlane/coordinator.py await-decrypt-and-revoke --ledger "$DEVLANE_PRIVATE/ledger" --wave-id "$WAVE_ID"
    ```

12. When the run completes, mark it terminal. This revokes again if needed, verifies absence before anything is audited, runs the auditor over the real public surfaces and preserves validated diagnostics privately.

    ```sh
    gh run watch "$RUN_ID" --repo "$REPO" --exit-status
    python3 -B kit/devlane/coordinator.py mark-terminal --ledger "$DEVLANE_PRIVATE/ledger" --wave-id "$WAVE_ID"
    ```

13. Clean up until it reports complete. It is resumable, revokes first, then deletes both assets, logs, artifacts and the run, verifying each absence. An open wave blocks the next wave.

    ```sh
    python3 -B kit/devlane/coordinator.py cleanup-terminal --ledger "$DEVLANE_PRIVATE/ledger" --wave-id "$WAVE_ID"
    ```

    If cleanup is incomplete, keep the ledger and wave open, read the obligation states and rerun after the external refusal or ambiguity is resolved. Never dispatch a replacement wave before `terminal_cleanup=complete`.

**Rehearsal wave (required before the first private wave)**

Run the whole wave sequence above once with the synthetic source from `rehearsal.py source`, on the exact commit that is on `main`. The source is the hostile synthetic Node fixture: planted source and key canary text, workflow-command text on every output channel and a workload that fails if any isolation boundary is open. It contains no private source. The rehearsal proves what the source-free control cannot, because the control never runs the encrypted workflow itself.

Pass criteria. All of them must hold before any private wave:

1. Step 8 installed the key as an environment secret on `devlane-decrypt`, and the coordinator accepted the environment restriction to `main`. Both the environment branch policy and the workflow's own reference check admit only `main`; the coordinator check covers the environment half.
2. The run took the real permit path, restored the control evidence cache, saved and restored the one-run permit, fetched both assets anonymously, received the secret only in the decrypt step, and printed no canary text anywhere.
3. Step 11 printed `within_limit=true`.
4. Step 12 recorded the audit disposition `accepted`, which means the real hosted log satisfied the closed log grammar. Read it with:

   ```sh
   python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["cleanup_attempts"][-1]["audit_disposition"])' "$DEVLANE_PRIVATE/ledger/$WAVE_ID.json"
   ```

   A different value, or a refusal naming a log line, means the grammar needs one reviewed adjustment for a line the hosted runner really prints. The grammar fails closed, so adjust it in a reviewed change and repeat the rehearsal with a new wave and bundle. Do not relax the auditor ad hoc.
5. Step 13 reported `terminal_cleanup=complete` and the ledger state is `deleted`: the key, both release assets, the logs, any artifacts and the run are absent, and later requests for them return 404.
6. Duplicate refusal. Dispatch the duplicate only after step 10 has attached the first run and that run's step named Claim this bundle for one run before decryption has succeeded (check with `gh run view "$RUN_ID" --repo "$REPO" --json jobs`); an earlier duplicate gives `reconcile-dispatch` two runs with the same title and leaves the wave stuck at `dispatch-unreconciled`. While the first run is still queued or running, dispatch the same inputs a second time with the same bundle identifier (the per-bundle concurrency group holds it until the first run ends). Do this without installing a second key. When it runs, it must fail at the step named Claim this bundle for one run before decryption, with every later step, including the decrypt step, not started. Check the failed step with `gh run view "$DUPLICATE_RUN_ID" --repo "$REPO" --json jobs`, and check that the duplicate started before the bundle `expires` value, so that the refusal is for reuse and not for expiry. The duplicate is outside the ledger by design (the ledger refuses a reused bundle at reservation). Match it by its run title and its run identifier being different from the first, then delete it and confirm it is gone:

   ```sh
   gh run delete "$DUPLICATE_RUN_ID" --repo "$REPO"
   gh api -i "repos/$REPO/actions/runs/$DUPLICATE_RUN_ID" | head -n 1
   ```

   Its audit job is expected to fail, because the duplicate never decrypts.
7. After the rehearsal, confirm that no environment secret and no repository secret named `DEVLANE_DECRYPT_KEY` remains and that the local key file is gone.

Record the rehearsal verdict, the commit it ran on and the measured revocation latency. If any criterion fails, fix it in a reviewed change, rebase the commit onto `main`, rerun the control and repeat the rehearsal. The rehearsal never counts for a different commit.

**Profile coverage.** The rehearsal exercises the `core-node` profile only. The Rust steps of the encrypted workflow (the pinned toolchain setup) are not covered by it and fail closed. No private wave may use the `core-rust` profile until a core-rust rehearsal, with a synthetic Rust source, has passed on the exact commit on `main`; that rehearsal needs a reviewed Rust fixture and is a separate change. Until then, private waves are `core-node` only.

**Residual risks the owner has accepted**

- Dependency disclosure. The sanitized projection asset is public while a wave is open and lists every public dependency name and version (and the crate list for the Rust profile). Anyone who fetches it in that window learns the dependency set of the private project. It is deleted at cleanup.
- Records side channel. Code that runs during the offline phase, including third-party dependency code, controls up to 100 records per run, each with a file identifier, line, diagnostic code and test result. That is a few kilobits per run, enough to carry a short credential or a fragment of source. The records are limited to opaque identifiers, 100 records and 16 KiB, and nothing else leaves the runner.
- Report integrity. The test adapters and the workload run as the same user inside the isolation, so a test binary could rewrite its own report. The effect is limited to a false pass or false failure; the public output is still filtered through the allowlist and cannot carry anything else. Treat a private wave result as evidence from code you chose to run, not as a verified attestation.
- Install scripts. A dependency that declares an install script is accepted. Scripts are never run (project configuration, environment and the install flag each suppress them), the marker is not projected, and the control installs a public package with an install script to prove the suppression.
- Step names. Some check step names still read "protected-branch dispatch" although the source-free control now accepts any `refs/heads/` branch. The names are fixed in the exact policy templates and auditors; they are cosmetic and renaming them is deferred.
- Revocation window. The key stays installed until the decrypt step concludes (step 11). Revoking earlier, once the run job's setup step completes (secrets are handed to the runner at assignment), would shrink that window and is deferred until the rehearsal can prove it on a real run.
- Hosted behavior. Secret masking and injection, run deletion semantics and the exact hosted log format are proven only by a real dispatch, which is why the rehearsal is required.
