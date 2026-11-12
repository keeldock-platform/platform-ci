**Fast-forward branch promotion**

GitHub does not count check runs created by a `workflow_dispatch` workflow toward required status checks. The public control is manual-dispatch only, and a manual dispatch is accepted from any branch ref, so its 18 green job checks cannot themselves be the required checks on `develop`, `uat` or `main`.

After `kit/devlane/control_audit.py` accepts the complete 18-job graph, `control-audit` posts one commit status to the exact control SHA. The context is `keeldock/control-verified`, the state is `success`, the description is `18-job source-free control verified`, and the target URL is that control run. A failed or refused audit posts no status. The audit runs on any branch ref, including `main`.

The commit-status API record reports `creator.login` as `github-actions[bot]` with type `Bot`, and includes the context. It has no `app` or `sha` field; the statuses endpoint is scoped to the SHA in its request path. Branch protection pins the required context to GitHub Actions app ID `15368`; the promotion tool checks that pin, the latest status creator and state from that SHA-scoped endpoint, and every control check run independently.

Set `GREEN_SHA` to the full commit SHA on `develop` whose manual control is accepted and green. Then run the tool from an authenticated clone of `keeldock-platform/platform-ci`:

```sh
python3 -B kit/promotion/branch_promotion.py --target uat --sha "$GREEN_SHA" --owner-approved
python3 -B kit/promotion/branch_promotion.py --target main --sha "$GREEN_SHA" --owner-approved
```

The tool moves `develop` to `uat`, then `uat` to `main`. It verifies that the source branch still points to the supplied SHA, the target is its ancestor, and the source and target have identical required check contexts and app IDs. The required set must be exactly `keeldock/control-verified`, pinned to app ID `15368`.

Before pushing, the tool checks all 18 control check runs on the exact SHA. It selects the latest attempt for each job by check-run ID, and each must be completed with a `success` conclusion from the Actions app. It also selects the newest `keeldock/control-verified` status by status ID; that record must be a success from `github-actions[bot]` on the exact SHA. A newer queued, in-progress, skipped, cancelled, failed, or non-Actions status blocks promotion. The tool pushes the SHA itself and reads the remote destination back; promotion fails unless the destination is exactly that SHA. Run the second command only after the first succeeds.

**Checking a pull request into `develop`**

Dispatch the source-free control on the pull request branch so its status and 18 checks attach to the head SHA, for example:

```sh
gh workflow run public-policy.yml --repo keeldock-platform/platform-ci --ref "$BRANCH" -f control_wave_id="$WAVE"
```

The manual-dispatch bootstrap is already on `main`, merged through the protected linear fast-forward path at `5ef503e19fbeb600c3bbef9b047a15c238602efc`. A linear merge creates a new commit on `develop`, so dispatch the control again on that resulting SHA before promoting it. The promotion tool independently verifies that SHA and refuses if any of the 18 check runs or the latest gate status is missing or not green.

**One-time branch-rule setup**

For each of `develop`, `uat` and `main`, apply the rule “Require status checks to pass before updating the branch” and configure the required checks to contain exactly one entry:

   - `keeldock/control-verified`

Pin that context to GitHub Actions app ID `15368`. Keep linear history required, block force pushes, and block branch deletion. Then fast-forward with the promotion tool above. Do not add the 18 dispatch-only job checks as required contexts; GitHub reports them as expected even when their check runs are green.

Keep the usual pull-request review rules on `develop`. Do not grant a required-check bypass for the promotion identity. For `uat` and `main`, allow the designated promotion identity to make direct fast-forward updates while the status rule remains enforced. If the active ruleset cannot allow those updates without bypassing checks, split the update allow-list from the required-check rule so the status rule still applies.

Applying repository settings remains an owner action; this implementation changes no GitHub settings. The Linux and Windows manual confinement diagnostics remain available through `linux-confinement-diagnostic.yml` and `windows-confinement-diagnostic.yml`; neither diagnostic check is part of the promotion gate.

Private product source must not run through private-repository Actions or a source-reader workflow. Use only the approved public encrypted devlane. Dependency fetching happens with lifecycle scripts disabled before network access is cut, plaintext execution stays offline, output is filtered, and product-code artifacts and caches are prohibited. A development-feedback result does not replace source admission or release evidence.
