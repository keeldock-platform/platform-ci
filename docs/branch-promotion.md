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

Dispatch the source-free control on the pull request branch, for example `gh workflow run public-policy.yml --repo keeldock-platform/platform-ci --ref "$BRANCH" -f control_wave_id="$WAVE"`. The manual-dispatch bootstrap is already on `main`: pull request 173 merged by protected linear fast-forward at `5ef503e19fbeb600c3bbef9b047a15c238602efc`. The 18 check runs attach to the branch head commit and satisfy the required contexts for the merge. Linear history means the merge creates a new commit on `develop`, so run the control again on that new `develop` head before promoting it. The promotion tool also refuses when `develop` and the target require any context that the control cannot produce, so a context that only a protected branch could satisfy cannot be added to `develop` by mistake.

**One-time migration order (bootstrap completed)**

The manual-dispatch bootstrap is complete. Pull request 173 merged through the protected linear fast-forward path at `5ef503e19fbeb600c3bbef9b047a15c238602efc`. The former base `6f1d2a360438181e162ce4c7ddd2a33ae66f8fd9` lacked `workflow_dispatch`; it is historical context, not the current `main` state. Do not reapply the bootstrap patch or repeat its dispatch. Continue with the remaining protection and exact-SHA checks below, without a protection bypass:

0. **Completed:** the bootstrap added `workflow_dispatch`, the `control_wave_id` input and its matching validator/template and pins/contracts while preserving the old job graph, permissions and required contexts. The existing 14 checks passed on the bootstrap candidate before the protected merge.
1. Dispatch the full control on the devlane pull request head and require all 18 checks to pass on that exact head SHA. If registration is delayed or ambiguous, reconcile the recorded dispatch; do not issue a duplicate.
2. Replace `develop`'s old 14 required contexts with exactly the 18 contexts above, each pinned to GitHub Actions app `15368`. Keep required checks enabled and preserve all other protection settings. The pull request can merge only after the 18 checks are green on its head; use no protection bypass.
3. Merge the reviewed change through the permitted protected-branch process.
4. Run the full control on the resulting `develop` merge SHA and require all 18 checks on that exact commit.
5. Replace `uat` and `main`'s old contexts with the same exact 18 contexts, all pinned to app `15368`. Keep the rules enforced and do not grant a status-check bypass. The promotion tool refuses a subset, extra, missing or unpinned context.
6. After the owner's promotion go, fast-forward `develop` to `uat`, then `uat` to `main`, at the exact SHA whose full control is green. Run the full control on `main` at that same SHA to save the durable evidence required by the encrypted lane.

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

Private product source must not run through private-repository Actions or a source-reader workflow. Use only the approved public encrypted devlane: dependencies are fetched with lifecycle scripts disabled before network access is cut, plaintext execution stays offline, output is filtered, and product-code artifacts and caches are prohibited. A development-feedback result does not replace source admission or release evidence.

These are repository settings for an owner to apply. This change does not modify GitHub branch protection or organization settings.
