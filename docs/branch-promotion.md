**Fast-forward branch promotion**

`kit/promotion/branch_promotion.py` promotes one SHA from `develop` to `uat`, then from `uat` to `main`. First run the manual `public-policy.yml` control once on the candidate SHA on `develop`; it dispatches the five same-commit reusable suites and audits their exact 18-job graph. Then run the promotion commands from an authenticated clone of `keeldock-platform/platform-ci`:

```sh
python3 -B kit/promotion/branch_promotion.py --target uat --sha "$GREEN_SHA" --owner-approved
python3 -B kit/promotion/branch_promotion.py --target main --sha "$GREEN_SHA" --owner-approved
```

Set `GREEN_SHA` to the full commit SHA that is green on `develop`.

The tool checks that the source branch still points to the supplied SHA, the destination is its ancestor, the source and destination have identical required status-check contexts and app IDs, and every required check is green on that exact SHA. Only the latest attempt may count, and it must be completed with a `success` conclusion; any newer non-success attempt invalidates the older success. It pushes the SHA itself and reads the remote destination back; promotion fails unless the destination is exactly that SHA. Run the second command only after the first succeeds.

The consolidated control workflow and the reusable suites it calls hold no secret and no environment, so a manual dispatch is accepted from any branch (`refs/heads/` names only; never from a tag, a pull request ref or a fork, and never from a `pull_request` or `push` event). That is what keeps `develop` satisfiable without any protection bypass: a pull request head can be checked by dispatching the control on its branch, and GitHub then finds all 18 required contexts on the head commit. The durable control evidence cache is saved only on `main`, and the encrypted dev lane is dispatched only on `main`; neither rule is relaxed. Promotion leaves the successful check runs on the exact candidate SHA intact. The promotion tool requires every configured context from the same SHA, and GitHub branch rules enforce those contexts independently; an unchecked SHA remains blocked. It requests all check-run attempts, follows every API page, and selects the greatest run ID for each context. A newer queued, in-progress, skipped, cancelled, or failed attempt is not green and cannot be replaced by an older success.

**Checking a pull request into `develop`**

Dispatch the control on the pull request branch, for example `gh workflow run public-policy.yml --repo keeldock-platform/platform-ci --ref "$BRANCH" -f control_wave_id="$WAVE"` (GitHub dispatches the workflow file as it exists on that ref, and it may also require the `workflow_dispatch` trigger to be present on the default branch's copy; `main` at the base commit `6f1d2a3` has only `push` and `pull_request`, so the first dispatch from a branch can be refused until the trigger-only change below is on `main`). The 18 check runs attach to the branch head commit and satisfy the required contexts for the merge. Linear history means the merge creates a new commit on `develop`, so run the control again on that new `develop` head before promoting it. The promotion tool also refuses when `develop` and the target require any context that the control cannot produce, so a context that only a protected branch could satisfy cannot be added to `develop` by mistake.

**One-time migration order**

The change that introduces this rule has to be merged under the old rules, so apply the settings in this order and never with a protection bypass:

0. Probe dispatch. Before step 1, dispatch `public-policy.yml` on the pull request branch (`gh workflow run public-policy.yml --repo keeldock-platform/platform-ci --ref "$BRANCH" -f control_wave_id="$WAVE"`). If it is accepted, cancel that probe run (`gh run cancel`) or let it finish, and continue. If GitHub answers HTTP 422 (workflow does not have a `workflow_dispatch` trigger), first promote a small change that only adds the `workflow_dispatch` trigger and its `control_wave_id` input to `main`'s copy of `public-policy.yml`: merge it under the old rules, with no other edit to the file, and repeat the probe. This trigger-only fallback must not change the job graph, permissions or checks, and `main` must not otherwise be reconfigured for it.
1. Relax or replace `develop`'s old required contexts (the previous per-suite names) so that the pull request carrying this change can be merged.
2. Merge the change.
3. Run the control on `develop` at the merge commit and wait until all 18 jobs pass.
4. Set the 18 contexts above, pinned to app `15368`, on `uat` and `main`, and on `develop` in place of the relaxed rule (the promotion tool requires `develop` and the target to match). The promotion tool requires exactly these 18 contexts, each pinned to app `15368`: a subset, an extra context or an unpinned context is refused.
5. Promote `develop` to `uat` and then `main` at that commit with the commands above.
6. Run the control on `main` at the same commit. This saves the durable control evidence that the encrypted lane requires.

The Linux and Windows manual confinement diagnostics remain available through `linux-confinement-diagnostic.yml` and `windows-confinement-diagnostic.yml`. They dispatch only their separate `linux-confinement` and `windows-confinement-spike` job checks on `main`; neither check is part of the 18 promotion contexts. The commands above use Python directly and do not require GNU `timeout`, so they also run on macOS.

**GitHub branch rules to configure**

Apply these settings in `keeldock-platform/platform-ci` for each of `develop`, `uat`, and `main`:

1. Require status checks to pass before updating the branch. Use the same context names and GitHub Actions app identity on all three branches. The contexts checked by the promotion tool are:

   - `policy-ubuntu-24.04`
   - `policy-macos-15`
   - `policy-windows-2025`
   - `node-lock-smoke / node-lock-smoke-ubuntu-24.04`
   - `node-lock-smoke / node-lock-smoke-macos-15`
   - `node-lock-smoke / node-lock-smoke-windows-2025`
   - `linux-confinement / linux-policy`
   - `linux-confinement / linux-harness`
   - `windows-confinement / windows-policy`
   - `windows-confinement / windows-native-synthetic`
   - `windows-handoff-synthetic / handoff-unit-ubuntu-24.04`
   - `windows-handoff-synthetic / handoff-unit-windows-2025`
   - `development-feedback-smoke / feedback-smoke-producer ubuntu-24.04`
   - `development-feedback-smoke / feedback-smoke-producer macos-15`
   - `development-feedback-smoke / feedback-smoke-producer windows-2025`
   - `development-feedback-smoke / feedback-smoke-audit`
   - `devlane-synthetic / devlane-synthetic`
   - `control-audit`

   Use the job check names GitHub reports: explicit job `name` values include their rendered matrix values, unnamed jobs use the job ID, and reusable-workflow jobs use GitHub's `caller / callee` form.

   Pin each context to GitHub Actions app ID `15368`. If another required context is added, add it to the promotion checker and this list before enabling it in branch rules. Applying repository settings remains an owner action; this implementation changes no GitHub settings.

2. Require linear history, block force pushes, and block branch deletion. Keep ordinary pull-request review rules on `develop`.

3. For `uat` and `main`, allow the designated promotion identity to make direct fast-forward updates while the required-check rules remain enforced. Do not exempt that identity from required status checks. If the active ruleset cannot allow direct updates without bypassing checks, split the update allow-list from the required-check rule so the check rule still applies.

4. Do not require a pull request to update `uat` or `main`; this tool advances them with the already-checked commit. Keep both branches protected by their required checks and linear-history rules.

For the Core repository, allow the public reusable workflow in `keeldock-platform/platform-ci` under **Settings → Actions → General**. On Core's `develop` branch rule, require the four checks GitHub reports for the reusable call: `dependencies / dependency-preflight`, `dependencies / rust`, `dependencies / core.runtime.workspace`, and `dependencies / npm`. The `core.runtime.workspace` job runs `npm --prefix runtime run check:workspace` against the exact Core checkout inside its confined, no-network workspace. The reusable preflight reads the caller workflow at the exact Core SHA and requires its `uses` ref and `control_sha` input to match; `ci/dependency-checks.toml` remains an exact pin for manual dispatches. Configure the `linux-source-read` environment and source-reader values in Core for protected pushes. Core pull requests use the job-scoped read-only `GITHUB_TOKEN` to read their exact merge commit and use a separate `linux-source-read-untrusted` environment with no secrets. Rust cache operations are disabled for all Core callers.

For public Platform cache jobs, configure a separate `linux-source-read-main` environment restricted to `main`, copy the source-reader secrets and variables needed by those jobs, and store `RUST_CACHE_ENCRYPTION_KEY` there as a base64-encoded 32-byte random value. Do not store that cache key as a repository-wide secret. The dependency workflow selects this environment only for a Platform `main` dispatch; other Platform refs and all Core callers run without Rust cache operations. Cache imports, exports, and saves are best-effort, so a missing key or failed cache operation falls back to a normal build. Platform cache archives are encrypted before GitHub stores them; public Platform PRs do not restore these caches.

These are repository settings for an owner to apply. This change does not modify GitHub branch protection or organization settings.
