**Fast-forward branch promotion**

`kit/promotion/branch_promotion.py` promotes one SHA from `develop` to `uat`, then from `uat` to `main`. Run it from an authenticated clone of `keeldock-platform/platform-ci` after the candidate SHA has passed the required checks on `develop`:

```sh
timeout 15m python3 -B kit/promotion/branch_promotion.py --target uat --sha "$GREEN_SHA" --owner-approved
timeout 15m python3 -B kit/promotion/branch_promotion.py --target main --sha "$GREEN_SHA" --owner-approved
```

Set `GREEN_SHA` to the full commit SHA that is green on `develop`.

The tool checks that the source branch still points to the supplied SHA, the destination is its ancestor, the source and destination have identical required status-check contexts and app IDs, and every required check is green on that exact SHA. It pushes the SHA itself and reads the remote destination back; promotion fails unless the destination is exactly that SHA. Run the second command only after the first succeeds.

On pushes to `uat` and `main`, each CI workflow checks for completed green evidence on the same SHA and skips its build jobs when the evidence is still current. A newer queued, in-progress, cancelled, or failed attempt makes the evidence unusable, even when an older attempt passed. A later job skipped by this reuse coordinator does not supersede the earlier successful run because that job did not execute the check. `promotion-check-reuse` is an internal coordination job and must not be a required status check.

**GitHub branch rules to configure**

Apply these settings in `keeldock-platform/platform-ci` for each of `develop`, `uat`, and `main`:

1. Require status checks to pass before updating the branch. Use the same context names and GitHub Actions app identity on all three branches. The contexts checked by the promotion tool are:

   - `policy-ubuntu-24.04`
   - `policy-macos-15`
   - `policy-windows-2025`
   - `handoff-unit-ubuntu-24.04`
   - `handoff-unit-windows-2025`
   - `linux-policy`
   - `node-lock-smoke-ubuntu-24.04`
   - `node-lock-smoke-macos-15`
   - `node-lock-smoke-windows-2025`
   - `windows-policy`
   - `feedback-smoke-producer ubuntu-24.04`
   - `feedback-smoke-producer macos-15`
   - `feedback-smoke-producer windows-2025`
   - `feedback-smoke-audit`

   Use the job check names GitHub reports: explicit job `name` values include their rendered matrix values, unnamed jobs use the job ID, and reusable-workflow jobs use GitHub's `caller / callee` form.

   Pin each context to GitHub Actions app ID `15368`. Do not add `promotion-check-reuse` as a required context. If another required context is added, add it to the promotion checker and this list before enabling it in branch rules.

2. Require linear history, block force pushes, and block branch deletion. Keep ordinary pull-request review rules on `develop`.

3. For `uat` and `main`, allow the designated promotion identity to make direct fast-forward updates while the required-check rules remain enforced. Do not exempt that identity from required status checks. If the active ruleset cannot allow direct updates without bypassing checks, split the update allow-list from the required-check rule so the check rule still applies.

4. Do not require a pull request to update `uat` or `main`; this tool advances them with the already-checked commit. Keep both branches protected by their required checks and linear-history rules.

For the Core repository, allow the public reusable workflow in `keeldock-platform/platform-ci` under **Settings → Actions → General**. On Core's `develop` branch rule, require the four checks GitHub reports for the reusable call: `dependencies / dependency-preflight`, `dependencies / rust`, `dependencies / core.runtime.workspace`, and `dependencies / npm`. The reusable preflight reads the caller workflow at the exact Core SHA and requires its `uses` ref and `control_sha` input to match; `ci/dependency-checks.toml` remains an exact pin for manual dispatches. Configure the `linux-source-read` environment and source-reader values in Core for protected pushes. Core pull requests use the job-scoped read-only `GITHUB_TOKEN` to read their exact merge commit and use a separate `linux-source-read-untrusted` environment with no secrets. Rust cache operations are disabled for all Core callers.

For public Platform cache jobs, configure a separate `linux-source-read-main` environment restricted to `main`, copy the source-reader secrets and variables needed by those jobs, and store `RUST_CACHE_ENCRYPTION_KEY` there as a base64-encoded 32-byte random value. Do not store that cache key as a repository-wide secret. The dependency workflow selects this environment only for a Platform `main` dispatch; other Platform refs and all Core callers run without Rust cache operations. Cache imports, exports, and saves are best-effort, so a missing key or failed cache operation falls back to a normal build. Platform cache archives are encrypted before GitHub stores them; public Platform PRs do not restore these caches.

These are repository settings for an owner to apply. This change does not modify GitHub branch protection or organization settings.
