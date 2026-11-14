import hashlib
import json
import os
import re
from pathlib import Path


PLATFORM_FILES = frozenset(
    (
        ".gitattributes",
        ".github/workflows/public-policy.yml",
        ".github/workflows/devlane-encrypted.yml",
        ".github/workflows/devlane-synthetic.yml",
        ".github/workflows/core-dependency-checks.yml",
        "docs/branch-promotion.md",
        '.github/workflows/core-rust-format-return.yml',
        '.github/workflows/core-build-diagnostic-return.yml',
        'kit/confinement/macos_feedback_producer.py',
        'kit/confinement/test_macos_feedback_producer.py',
        'kit/confinement/feedback_producer_crypto.mjs',
        'kit/confinement/test_feedback_producer_crypto.mjs',
        'kit/confinement/feedback_admin.py',
        'kit/confinement/test_feedback_admin.py',
        'kit/confinement/feedback_admin_crypto.mjs',
        'kit/confinement/test_feedback_admin_crypto.mjs',
        'kit/confinement/test_feedback_admin_integration.py',
        'kit/confinement/feedback_api.py',
        'kit/confinement/test_feedback_api.py',
        'kit/confinement/feedback_failure.py',
        'kit/confinement/test_feedback_failure.py',
        'kit/confinement/feedback_public_audit.py',
        'kit/confinement/test_feedback_public_audit.py',

        '.github/workflows/node-lock-smoke.yml',
        '.github/workflows/development-feedback-smoke.yml',
        'kit/confinement/development_feedback.mjs',
        'kit/confinement/test_development_feedback.mjs',
        'kit/confinement/feedback_request.py',
        'kit/confinement/test_feedback_request.py',
        'kit/confinement/feedback_smoke.mjs',
        'kit/confinement/test_feedback_smoke.mjs',
        'kit/confinement/feedback_smoke_audit.py',
        'kit/confinement/test_feedback_smoke_audit.py',
        'kit/devlane/__init__.py',
        'kit/devlane/test_rehearsal.py',
        'kit/devlane/rehearsal.py',
        'kit/devlane/rust_rehearsal_fixture.py',
        'kit/devlane/fixtures/real-netns-dump-ubuntu2404.txt',
        'kit/devlane/fixtures/real-netns-rtnetlink-ipv4-ubuntu2404.bin',
        'kit/devlane/fixtures/real-netns-rtnetlink-ipv6-ubuntu2404.bin',
        'kit/devlane/fixtures/core-rust-rehearsal/Cargo.lock',
        'kit/devlane/fixtures/core-rust-rehearsal/Cargo.toml',
        'kit/devlane/fixtures/core-rust-rehearsal/build.rs',
        'kit/devlane/fixtures/core-rust-rehearsal/deny.toml',
        'kit/devlane/fixtures/core-rust-rehearsal/crates/support/Cargo.toml',
        'kit/devlane/fixtures/core-rust-rehearsal/crates/support/src/lib.rs',
        'kit/devlane/fixtures/core-rust-rehearsal/src/lib.rs',
        'kit/devlane/fixtures/core-rust-rehearsal/supply-chain/audits.toml',
        'kit/devlane/fixtures/core-rust-rehearsal/supply-chain/config.toml',
        'kit/devlane/fixtures/core-rust-rehearsal/supply-chain/imports.lock',
        'kit/devlane/fixtures/core-rust-rehearsal/fuzz/Cargo.lock',
        'kit/devlane/fixtures/core-rust-rehearsal/fuzz/Cargo.toml',
        'kit/devlane/fixtures/core-rust-rehearsal/fuzz/corpus/valid-array.json',
        'kit/devlane/fixtures/core-rust-rehearsal/fuzz/corpus/valid-object.json',
        'kit/devlane/fixtures/core-rust-rehearsal/fuzz/src/main.rs',
        'kit/devlane/fixtures/core-rust-rehearsal/runtime/Cargo.lock',
        'kit/devlane/fixtures/core-rust-rehearsal/runtime/Cargo.toml',
        'kit/devlane/fixtures/core-rust-rehearsal/runtime/crates/services/listener/Cargo.toml',
        'kit/devlane/fixtures/core-rust-rehearsal/runtime/crates/services/listener/src/lib.rs',
        'kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/audits.toml',
        'kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/config.toml',
        'kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/imports.lock',
        'docs/devlane-procedure.md',
        'kit/devlane/decrypt_once.py',
        'kit/devlane/acceptance_diagnostics.py',
        'kit/devlane/diagnostic_contract.py',
        'kit/devlane/node_tool_snapshot.py',
        'kit/devlane/node_vendor_source.py',
        'kit/devlane/bounded_registry_io.py',
        'kit/devlane/cargo_projection.py',
        'kit/devlane/constraint_resolver.py',
        'kit/devlane/registry_prefetch.py',
        'kit/devlane/rust_preparation_v2.py',
        'kit/devlane/test_source_projection.py',
        'kit/devlane/rust_preparation_smoke.py',
        'kit/devlane/rust_lock_generation.py',
        'kit/devlane/test_rust_preparation_v2.py',
        'kit/devlane/test_rust_lock_generation.py',
        'kit/devlane/test_node_vendor_source.py',
        'kit/devlane/test_node_vendor_source_r2.py',
        'kit/devlane/isolated_cleanup.py',
        'kit/devlane/permit.py',
        'kit/devlane/rust_test_runner.py',
        'kit/devlane/test_e2e.py',
        'kit/devlane/test_rust_report.py',
        'kit/devlane/test_rust_test_runner.py',
        'kit/devlane/test_desktop_profile.py',
        'kit/devlane/public_audit.py',
        'kit/devlane/sandbox_macos.py',
        'kit/devlane/control-crypto-requirements.txt',
        'kit/devlane/control_python.py',
        'kit/devlane/bundle.py',
        'kit/devlane/control_audit.py',
        'kit/devlane/coordinator.py',
        'kit/devlane/fetch.py',
        'kit/devlane/filter.py',
        'kit/devlane/host_cleanup.py',
        'kit/devlane/owned_tree_cleanup.py',
        'kit/devlane/network_probe.py',
        'kit/devlane/refusal_codes.py',
        'kit/devlane/prepare.py',
        'kit/devlane/project.py',
        'kit/devlane/safe_json.mjs',
        'kit/devlane/supervisor.py',
        "kit/devlane/semver-pins.json",
        "kit/devlane/semver_cargo_wrapper.py",
        "kit/devlane/semver_offline_cache.py",
        "kit/devlane/semver_stage.py",
        "kit/devlane/cgroup_exec.py",
        "kit/devlane/temp_project_checkpoints.py",
        "kit/devlane/test_semver_review_fixes.py",
        'kit/devlane/test_acceptance.py',
        'kit/devlane/test_worker_control_imports.py',
        'kit/devlane/test_adapters.mjs',
        'kit/devlane/test_audit_contracts.py',
        'kit/devlane/test_sandbox_macos.py',
        'kit/devlane/test_control_python.py',
        'kit/devlane/sandbox_windows.py',
        'kit/devlane/sandbox_windows.ps1',
        'kit/devlane/sandbox_windows_native.cs',
        'kit/devlane/sandbox_windows_reporter.mjs',
        'kit/devlane/test_windows_sandbox.py',
        'kit/devlane/fixtures/control-synthetic-43245798187.log.hex',
        'kit/devlane/fixtures/encrypted-audit-43284558151.log.hex',
        'kit/devlane/fixtures/encrypted-run-43284558151-identity.json',
        'kit/devlane/fixtures/encrypted-run-43284558151-jobs.json.hex',
        'kit/devlane/fixtures/encrypted-audit-43296698158.log.hex',
        'kit/devlane/fixtures/encrypted-run-43296698158-identity.json',
        'kit/devlane/fixtures/encrypted-run-43296698158-jobs.json.hex',
        'kit/devlane/fixtures/encrypted-run-43296698158.log.hex',
        'kit/devlane/fixtures/encrypted-run-43284558151.log.hex',
        'kit/devlane/fixtures/encrypted-workflow-43284558151.yml',
        'kit/devlane/fixtures/encrypted-workflow-f0ddd39554b2e48fbad7e61126319f5ffcdd2b84.yml',
        'kit/devlane/fixtures/synthetic-workflow-43245798187.yml',
        'kit/devlane/test_coordinator.py',
        'kit/devlane/test_linux_runtime.py',
        'kit/devlane/typescript_reporter.mjs',
        'ci/devlane-profiles.json',
        'kit/confinement/node_lock_envelope.mjs',
        'kit/confinement/test_node_lock_envelope.mjs',
        'kit/confinement/node_lock_inventory.mjs',
        'kit/confinement/node_lock_manifest.mjs',
        'kit/confinement/test_node_lock_manifest.mjs',
        'kit/confinement/node_lock_receipt.py',
        'kit/confinement/test_node_lock_receipt.py',
        'kit/confinement/cargo_lock_parser.py',
        'kit/confinement/test_cargo_lock_parser.py',
        'kit/confinement/sbom_normalizer.py',
        'kit/confinement/test_sbom_normalizer.py',
        'kit/confinement/fixtures/cargo-deny/issue-910-cycle/Cargo.toml',
        'kit/confinement/fixtures/cargo-deny/issue-910-cycle/Cargo.lock',
        'kit/confinement/fixtures/cargo-deny/issue-910-cycle/a/Cargo.toml',
        'kit/confinement/fixtures/cargo-deny/issue-910-cycle/a/src/lib.rs',
        'kit/confinement/fixtures/cargo-deny/issue-910-cycle/b/Cargo.toml',
        'kit/confinement/fixtures/cargo-deny/issue-910-cycle/b/src/lib.rs',
        'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/Cargo.toml',
        'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/Cargo.lock',
        'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/build.rs',
        'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/src/lib.rs',
        'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/Cargo.toml',
        'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/Cargo.lock',
        'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/build.rs',
        'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/src/lib.rs',
        'kit/bootstrap/policy_rust.py',
        'kit/bootstrap/test_policy_rust.py',
        'kit/confinement/cargo_lock_bootstrap.py',
        'kit/confinement/test_confinement_cargo_lock_bootstrap.py',
        'kit/bootstrap/policy_npm.py',
        'kit/bootstrap/test_policy_npm.py',
        ".github/workflows/linux-confinement.yml",
        ".github/workflows/linux-confinement-diagnostic.yml",
        ".github/workflows/linux-source-admission.yml",
        ".github/workflows/windows-attestation-permission-probe.yml",
        ".github/workflows/attestation-probe.yml",
        ".github/workflows/windows-source-admission.yml",
        ".github/workflows/lane-h-windows-receiver.yml",
        ".github/workflows/lane-h-linux-fetch-encrypt.yml",
        ".github/workflows/lane-h-capsule-attester.yml",
        ".github/workflows/macos-capability.yml",
        ".github/workflows/macos-reviewed-build.yml",
        ".github/workflows/macos-rust-toolchain-smoke.yml",
        ".github/workflows/macos-cache-proof.yml",
        ".github/workflows/macos-source-reader-preflight.yml",
        ".github/workflows/macos-rules-reader-preflight.yml",
        ".github/workflows/macos-rules-bootstrap.yml",
        ".github/workflows/macos-core-bootstrap.yml",
        ".github/workflows/macos-core-contract.yml",
        ".github/workflows/windows-native-preflight.yml",
        ".github/workflows/windows-confinement-diagnostic.yml",
        "ci/policy.json",
        "ci/api-budgets.json",
        "ci/revoked-signer-fingerprints",
        "kit/bootstrap/action.yml",
        "kit/bootstrap/api_budget.py",
        "kit/bootstrap/check_candidate.py",
        "kit/bootstrap/policy.py",
        "kit/bootstrap/policy_devlane.py",
        "kit/bootstrap/policy_handoff.py",
        "kit/bootstrap/policy_linux.py",
        "kit/bootstrap/policy_windows.py",
        "kit/bootstrap/public_tree.py",
        "kit/bootstrap/test_policy.py",
        "kit/bootstrap/test_policy_handoff.py",
        "kit/bootstrap/test_policy_linux.py",
        "kit/bootstrap/test_policy_windows.py",
        "kit/bootstrap/test_public_tree.py",
        ".github/workflows/windows-handoff-synthetic.yml",
        "kit/handoff/source_free.py",
        "kit/handoff/test_source_free.py",
        "kit/selector/suite_selector.py",
        "kit/selector/test_suite_selector.py",
        "kit/cache/policy.py",
        "kit/cache/test_policy.py",
        "kit/bootstrap/test_api_controls.py",
        "kit/confinement/macos_boundary_guard.py",
        "kit/confinement/test_macos_boundary_guard.py",
        "kit/confinement/test_macos_context_load.py",
        "kit/confinement/test_macos_feedback_output_limits.py",
        "kit/confinement/macos_canary_scan.py",
        "kit/confinement/macos_deny_default.py",
        "kit/confinement/test_macos_deny_default.py",
        "kit/confinement/macos_public_audit.py",
        "kit/confinement/test_macos_public_audit.py",
        "kit/confinement/macos_cache_client/action.yml",
        "kit/confinement/macos_cache_client/index.js",
        "kit/confinement/macos_reviewed_build.py",
        "kit/confinement/test_macos_reviewed_build.py",
        "kit/confinement/macos_rust_toolchain.py",
        "kit/confinement/test_macos_rust_toolchain.py",
        "kit/confinement/macos_network_observer.py",
        "kit/confinement/test_macos_network_observer.py",
        'kit/confinement/macos_rules_bootstrap.py',
        'kit/confinement/test_macos_rules_bootstrap.py',
        'kit/confinement/macos_core_bootstrap.py',
        'kit/confinement/test_macos_core_bootstrap.py',
        'kit/confinement/macos_core_contract.py',
        'kit/confinement/test_macos_core_contract.py',
        "kit/confinement/macos_private_validation.py",
        "kit/confinement/test_macos_private_validation.py",
        "kit/confinement/test_macos_wave70.py",
        "kit/confinement/macos_source_reader.py",
        "kit/confinement/test_macos_source_reader.py",
        "kit/confinement/macos_harness.py",
        "kit/confinement/test_macos_harness.py",
        "kit/confinement/macos_capability.py",
        "kit/confinement/macos_capability.swift",
        "kit/confinement/test_macos_capability.py",
        "kit/confinement/test_macos_capability_census.py",
        "kit/confinement/test_macos_descriptors.py",
        "kit/confinement/test_macos_revocation_rule.py",
        "kit/confinement/linux_harness.py",
        "kit/confinement/test_linux_harness.py",
        "kit/confinement/linux_boundary.py",
        "kit/confinement/test_linux_boundary.py",
        "kit/confinement/linux_canaries.py",
        "kit/confinement/test_linux_canaries.py",
        "kit/confinement/linux_channels.py",
        "kit/confinement/test_linux_channels.py",
        "kit/confinement/linux_fixtures.py",
        "kit/confinement/test_linux_fixtures.py",
        "kit/confinement/linux_probes.py",
        "kit/confinement/linux_session.py",
        "kit/confinement/test_linux_session.py",
        "kit/confinement/linux_settings.py",
        "kit/confinement/test_linux_settings.py",
        "kit/confinement/linux_source_build.py",
        "kit/confinement/test_linux_source_build.py",
        "kit/confinement/test_linux_source_build_tiers.py",
        "kit/confinement/fixtures/npm11_audit_report.json",
        ".github/workflows/core-linux-quick-return.yml",
        "core-ci/linux_quick_return.py",
        "core-ci/test_linux_quick_return.py",
        "core-ci/test_separation.py",
        "kit/promotion/branch_promotion.py",
        "kit/promotion/test_branch_promotion.py",
        "kit/confinement/native_loopback_profile.py",
        "kit/confinement/test_native_loopback_profile.py",
        "kit/confinement/windows_native_preflight.cs",
        "kit/confinement/windows_native_preflight.ps1",
        "kit/confinement/test_windows_native_preflight.py",
        ".github/workflows/windows-confinement.yml",
        "kit/confinement/windows_confinement.cs",
        "kit/confinement/windows_confinement.ps1",
        "kit/confinement/windows_probe.rs",
        "kit/confinement/windows_npm_link_shim.cjs",
        "kit/confinement/test_windows_confinement.py",
        "kit/confinement/windows_source_run.ps1",
        "kit/confinement/test_windows_source_run.py",
        "kit/confinement/confinement_verdict.py",
        "kit/confinement/test_confinement_verdict.py",
        "kit/confinement/attestation_probe.py",
        "kit/confinement/test_attestation_probe.py",
        "kit/confinement/release_provenance.py",
        "kit/confinement/test_confinement_release_provenance.py",
        "kit/confinement/role_signer.py",
        "kit/confinement/gate_table.py",
        "kit/confinement/test_confinement_gate_table.py",
        "kit/handoff/source_capsule.py",
        "kit/handoff/test_source_capsule.py",
        "kit/handoff/provider_requirements.txt",
        "kit/confinement/test_role_signer.py",
        "kit/confinement/confinement_public_audit.py",
        "kit/confinement/test_confinement_public_audit.py",
        "kit/confinement/log_canary.py",
        "kit/confinement/test_log_canary.py",
        "kit/confinement/capsule_frame.py",
        "kit/confinement/test_capsule_frame.py",
        "kit/confinement/source_bundle_preflight.py",
        "kit/confinement/test_source_bundle_preflight.py",
        "kit/confinement/capsule_frame.cs",
        "kit/confinement/capsule_frame.ps1",
        "kit/confinement/capsule_frame_vectors.json",
        "kit/confinement/capsule_frame_crosscheck.md",
        "kit/confinement/capsule_frame_vector_gate.py",
        ".github/workflows/capsule-vectors.yml",
        "kit/confinement/release_build_verify.py",
        "kit/confinement/test_release_build_verify.py",
        "kit/confinement/release_evidence.py",
        "kit/confinement/test_release_evidence.py",
        "kit/confinement/release_tool_ledger.py",
        "kit/confinement/release_tool_ledger.json",
        "kit/confinement/test_release_tool_ledger.py",
        ".github/workflows/baselines-prepare.yml",
        "kit/baselines/baselines_prepare.py",
        "kit/baselines/test_baselines_prepare.py",
        "kit/bootstrap/policy_baselines.py",
        "kit/bootstrap/test_policy_baselines.py",
        "kit/confinement/synthetic_project/Cargo.lock",
        "kit/confinement/synthetic_project/Cargo.toml",
        "kit/confinement/synthetic_project/crates/host/api/Cargo.toml",
        "kit/confinement/synthetic_project/crates/host/api/src/lib.rs",
        "kit/confinement/synthetic_project/crates/host/api/tests/feature.rs",
        "kit/confinement/synthetic_project/crates/host/api/tests/surface.rs",
        "kit/confinement/synthetic_project/crates/host/conformance/Cargo.toml",
        "kit/confinement/synthetic_project/crates/host/conformance/src/lib.rs",
        "kit/confinement/synthetic_project/crates/host/conformance/tests/conformance.rs",
        "kit/confinement/synthetic_project/crates/host/conformance/tests/process_pipe.rs",
        "kit/confinement/synthetic_project/crates/host/mock/Cargo.toml",
        "kit/confinement/synthetic_project/crates/host/mock/src/lib.rs",
        "kit/confinement/synthetic_project/crates/host/mock/tests/mock.rs",
        "kit/confinement/synthetic_project/fuzz/Cargo.lock",
        "kit/confinement/synthetic_project/fuzz/Cargo.toml",
        "kit/confinement/synthetic_project/fuzz/src/main.rs",
        "kit/confinement/synthetic_project/package-lock.json",
        "kit/confinement/synthetic_project/package.json",
        "kit/confinement/synthetic_project/packages/host-api/package.json",
        "kit/confinement/synthetic_project/packages/host-api/src/index.js",
        "kit/confinement/synthetic_project/packages/host-api/src/index.ts",
        "kit/confinement/synthetic_project/packages/host-api/tests/run.js",
        "kit/confinement/synthetic_project/packages/host-api/tests/no-net-use.mjs",
        "kit/confinement/synthetic_project/packages/host-api/tests/vitest.test.ts",
        "kit/confinement/synthetic_project/packages/host-api/tsconfig.json",
        "kit/confinement/synthetic_project/packages/host-api/vitest.config.ts",
        "kit/confinement/synthetic_project/packages/kernel-i18n/package.json",
        "kit/confinement/synthetic_project/packages/kernel-i18n/src/index.js",
        "kit/confinement/synthetic_project/packages/kernel-i18n/tests/run.js",
        "kit/confinement/synthetic_project/runtime/Cargo.lock",
        "kit/confinement/synthetic_project/runtime/Cargo.toml",
        "kit/confinement/synthetic_project/runtime/src/lib.rs",
        "kit/confinement/synthetic_project/runtime/tests/runtime.rs",
        "kit/confinement/test_confinement_synthetic_project.py",
        '.github/workflows/ci-future-stages.yml',
        '.github/workflows/appium-ci.yml',
        '.github/workflows/performance-shadow.yml',
        'kit/selector/ci19_catalogue.py',
        'kit/selector/fixtures/ci19_mcp_feature_owners.json',
        'kit/ci/feature_states.py',
        'kit/ci/test_feature_states.py',
        'kit/ci/future_stage.py',
        'kit/ci/test_future_stage.py',
        'kit/ci/future-stage-inventory.json',
        'kit/ci/perf_shadow.py',
        'kit/ci/test_perf_shadow.py',
        'kit/devlane/deadline.py',
        'kit/devlane/rust_matrix_runner.py',
        'kit/devlane/rust_tooling.py',
        'kit/devlane/test_deadline.py',
        'kit/devlane/test_powershell_static.py',
        'kit/devlane/test_powershell_live.py',
        'kit/devlane/test_network_probe.py',
        'kit/devlane/test_rust_matrix_runner.py',
        'kit/devlane/test_rust_public_audit.py',
        '.github/workflows/desktop-tauri-smoke.yml',
        'kit/devlane/fixtures/desktop-tauri-smoke/package-lock.json',
        'kit/devlane/fixtures/desktop-tauri-smoke/package.json',
        'kit/devlane/fixtures/desktop-tauri-smoke/build.mjs',
        'kit/devlane/fixtures/desktop-tauri-smoke/index.html',
        'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/Cargo.lock',
        'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/Cargo.toml',
        'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/build.rs',
        'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/icons/icon.png',
        'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/src/lib.rs',
        'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/src/main.rs',
        'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/tauri.conf.json',
    )
)
CONSUMER_FILES = frozenset((".github/workflows/public-policy.yml", "ci/policy.json"))
ALLOWED_FILES = {
    "platform": PLATFORM_FILES,
    "connect": CONSUMER_FILES,
    "workspace": CONSUMER_FILES,
    "data": CONSUMER_FILES,
}
MAX_FILE_BYTES = 262144
SYNTHETIC_NPM_LOCK_PATH = "kit/confinement/synthetic_project/package-lock.json"
SYNTHETIC_NPM_LOCK_PATHS = frozenset((
    SYNTHETIC_NPM_LOCK_PATH,
    "kit/devlane/fixtures/desktop-tauri-smoke/package-lock.json",
))
SELF_PIN_PATH = "kit/bootstrap/public_tree.py"
SELF_PIN_LINE_PATTERN = re.compile(
    rb"(?m)^    'kit/bootstrap/public_tree\.py': '[0-9a-f]{64}',$"
)
PINNED_FILE_SHA256 = {
    '.gitattributes': '0f2d6e841d5533b577f130d4865e5e6b68f24f3a2325c4bfa2ece6b943b4edbc',
    'kit/devlane/test_rehearsal.py': 'a2b4326daca943ab2ff32f4a0c0d4f5a09bb09e4f2061fabcfbd413333a7a3fb',
    'kit/devlane/rehearsal.py': 'df2a2c5be0e93496b27cafbba8a56e01176332fb7b84b9e3f0dba40ad3ece4d4',
    'docs/devlane-procedure.md': 'db2f77254bf226f7a944162a140290daa0a266f8003eed15b888200fd51548d6',
    '.github/workflows/appium-ci.yml': '961eaa4fc03e0fe687fa437673116e68479af9437dcb69173444ec57098db2d3',
    '.github/workflows/baselines-prepare.yml': '2df5141dca9ad0e5067c0bfa258f0feca5ebf46c451a5e7ec34562159683aa0f',
    '.github/workflows/capsule-vectors.yml': '7366acdb58988c5675e86268abe268e71f71bc16681ab560ba8e33f37fc9f9f7',
    '.github/workflows/ci-future-stages.yml': '16f7140d456f057a4681f871d9eb90e185133cb738c6aaf974cd07f633396815',
    '.github/workflows/core-build-diagnostic-return.yml': 'd75840b7a8b8541a1f1a083a35c5b54255d3ce8e5242c6e7e8bd1eb06bbd13ad',
    '.github/workflows/core-dependency-checks.yml': '2a0db4d6a1d1a6803fe01a938898a75d61ea3bfdbe9d713fa39030320d14fdff',
    '.github/workflows/core-linux-quick-return.yml': 'ecfcff18ffbb03fbbe058132590a675ddd2407b92ae2be1a2d4bfeeb95674298',
    '.github/workflows/core-rust-format-return.yml': 'c56fc9e8199681d2dab689f7f09a9fbb57825549c0f6132c27a7016ce72c79ab',
    '.github/workflows/development-feedback-smoke.yml': '380f71c2f95239492dea787383eadc648077d75ce676d9640186ff3b88dc65a9',
    '.github/workflows/devlane-encrypted.yml': 'c0c7bf0ccfcbe143e1b5433b5d448c0f9f4ae0d9d0e0954f8628a66310a5acbc',
    '.github/workflows/devlane-synthetic.yml': 'eba36edd34d8e4209c032216f015e28c5f67aa560af2fce26ede6b4ba0ceb9ac',
    '.github/workflows/lane-h-capsule-attester.yml': '192d78328f8bf093a68bef0f1dd323a88772e2929d79c92b24a8864d17c1b48c',
    '.github/workflows/lane-h-linux-fetch-encrypt.yml': 'c173b2298dca7757b37a67669ad6ae4abf6eaf32cf1dea94b8b0a17a1c50d423',
    '.github/workflows/lane-h-windows-receiver.yml': 'a6033b3c5dd1748bd4e55fa0dc4da82e40cd3ccfeee6b0fcc3ba3f88e165bde3',
    '.github/workflows/linux-source-admission.yml': '1947aa8af6730b30342b2e5d9a0a298aca32f2c30ec282e25ced1cf8cb6a7ffd',
    '.github/workflows/macos-core-bootstrap.yml': 'b140312f22310633089594255fb17d25aeece02869355e608408098c4e91a4eb',
    '.github/workflows/macos-core-contract.yml': 'e55f8d95bb4666a965912b2832aa68aded0f6c166c324082e61ca599b7bac9cc',
    '.github/workflows/macos-rules-bootstrap.yml': 'f56e0c0eb86493c320a72048201d4bfae6bedbec46ee85a8b027674d5cd62d3a',
    '.github/workflows/macos-rust-toolchain-smoke.yml': 'fe72b0118d0ff44090f2ea21e954a212c6bda35676a14b64cfe278ffa6c7582e',
    '.github/workflows/node-lock-smoke.yml': 'b8b772c843ba46cf816024e8ded8056381582d1c3041f3accaa78574f710830e',
    '.github/workflows/performance-shadow.yml': '9a64b2eb8240c1806e669de1e7a1fa42a3631d9988a205482872d3af68cc9d46',
    '.github/workflows/windows-native-preflight.yml': 'da294aadfc0e99cbe109aba90f9fb86df65867cd32d3325d26a9e9a5b035e5bb',
    '.github/workflows/windows-source-admission.yml': 'ef10b21b69f841f6c2b69bc22497400e89e959fdfd6e24740a24e4b00139b5a8',
    'ci/devlane-profiles.json': 'b0993c7f2183830fc09d200c0463eb1d8134fd0868d78697f91d00e65eadb45a',
    'ci/revoked-signer-fingerprints': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'core-ci/linux_quick_return.py': 'b711e81a2779d891cbba6d11becfe07d730331acc71c7ed2a9841f41439b5fd8',
    'core-ci/test_linux_quick_return.py': 'f6653e9db604a7a3a2213c285ab30567f8c39d46632b1650e4a15c4d8ee8b634',
    'core-ci/test_separation.py': 'da46b8bad44cd603a2153031cd9ea801a3e0729151d36a640f6675d7b5a1e38c',
    'docs/branch-promotion.md': '1a1ab7145e8851de28ca79e0ade137c2c67680f48c41e868ad63baf1757f1c7b',
    ('platform', '.github/workflows/public-policy.yml'): '75a640532ab2c36b819583dade17e6af65bc6fe16e30d2f263f928767ca1154e',
    'kit/bootstrap/policy.py': '43d3182aac5a1afa60cfb2ee98fb108008a104686a9d756bed43f716dbd36350',
    'kit/bootstrap/test_policy.py': '2bd13cd26a2056fe62e8ad796ff3ed0d63f4499cc5fb79458da08ddbd2202e1f',
    'kit/baselines/baselines_prepare.py': '2bd39ebcaccf6e0522d6b3081fa91a898037a9c771730e3f1c00b881ee7f77ee',
    'kit/baselines/test_baselines_prepare.py': '76dda4abf5b311b4cfac3eeced6a28dcad12e6870a36861d31d333b51c0910ab',
    'kit/bootstrap/action.yml': 'f4cdc92174efecb25ea31724addb43db0ae264c636f1f55a201275c7c54fed50',
    'kit/bootstrap/policy_baselines.py': 'f221172213f5610b4c4e25c499b6066f0559b7d598255161853de38aaf7f2a1a',
    'kit/bootstrap/policy_devlane.py': 'a58fdc2611603e0f49d5514febe0fa190a66bb2ea0f05d4ed7ed62776337b4fc',
    'kit/bootstrap/policy_handoff.py': '743e8c4431b80c260b0fdfabc1e08bccc67b3cce59a2b311e18cd36eeb065c60',
    'kit/bootstrap/policy_linux.py': '0b314a645e43f2aaec58ca23150386b5865e8a27c3101459d00d42370e7d5a5f',
    'kit/bootstrap/policy_npm.py': 'b110b4573b2919003792e05bdcec60a0108f9e2ea1ebc1ce820ff77216271794',
    'kit/bootstrap/policy_rust.py': '4306a55701a5a04c884b2b21091a6d06307134e3570f0d5d65cb103ff84023ec',
    'kit/bootstrap/public_tree.py': 'da061ea1f2d7a53f40095c42d371a713645d2a1f60c8bb5234c647312287e5a8',
    'kit/bootstrap/test_policy_baselines.py': '690980cc3a140970d2b813d854823e3e9f32d8b09db9e25c0ca143140c3af627',
    'kit/bootstrap/test_policy_handoff.py': '3cf707fec6cc1a62e49a948b496fe00765a04ec171fd4cdc57b07d214d3100a2',
    'kit/bootstrap/test_policy_linux.py': 'f1c62480d608d680e73cdbf0ca8b7c83552919bd5de4caa095d5e04e8c3e5f8c',
    'kit/bootstrap/test_policy_npm.py': '8893c4a89ab447a8813806afd2b35bbedbc78d530f1c5a1c8bdf67fc55865eed',
    'kit/bootstrap/test_policy_rust.py': '2465451eb33dec7787807d27ae9ef574b7447a52953c2c3f1951003243b6294a',
    'kit/bootstrap/test_public_tree.py': 'b0e39102ce5c8eb56ebe737b4c6c1741e5101385c6b5aa2d91a3a125d4f86ff5',
    'kit/ci/feature_states.py': 'e058de49cf9e96b61e8037ee533a095082f3210429586d4183d6c44c4f57d479',
    'kit/ci/future-stage-inventory.json': '185663fbc7c94b010dc4c74f7e6867898b5186a0d88acb95e61414f15cb695aa',
    'kit/ci/future_stage.py': '11023901b556599b0f5f747b84ed540c45eae5a2d2ad65ea3a1ba95f81775d41',
    'kit/ci/perf_shadow.py': '422584f8eea3e074f92ee4ba509d4a4fe29aa5d083f0e2ac240a9c4e70e39cc0',
    'kit/ci/test_feature_states.py': '9feb186807e3ec6a2571599be392eb58989304a0dd3ad1348e51961f56d91e4f',
    'kit/ci/test_future_stage.py': 'e7cf55f87a17662867db748c6ad7dd7d6bdb69a66d0c92e80b3bce138bb514f3',
    'kit/ci/test_perf_shadow.py': '6c76a2ace13bae1cefd0da2fffd8bbf4241f3ac4279735cdda0018431e398dc0',
    'kit/confinement/capsule_frame.cs': 'b7de9b0af02e305d23e75ea58daf856a9e51d340b0ccee0920925930ffb1bc84',
    'kit/confinement/capsule_frame.ps1': '0fafd0ef16b277afaea9ec5301bc67b93fb4842e0f620c506e662956f080d51d',
    'kit/confinement/capsule_frame_vectors.json': 'fb0660998011eec479ee01e919510dcd8f88ae5266114d9f82a899b4fa72fb94',
    'kit/confinement/cargo_lock_bootstrap.py': '04e97a7c0b7de07fda93ff208e385d74ef5a12cf73a1439ee16090883934fad8',
    'kit/confinement/cargo_lock_parser.py': '0acae8f9ed3c29f8990ab85dcabb286fb826ca27b5cdf9e32ad6925979cc7322',
    'kit/confinement/confinement_public_audit.py': '2c153a935786b5f1d40c7aca689fa3447a8b6bd34dc0a31244799b9b721f7a94',
    'kit/confinement/development_feedback.mjs': '4ce84c90229b5addd0456f8350850483c4241024f18ac6fa5bcd7d201f79ed45',
    'kit/confinement/feedback_admin.py': 'e85f29bd3efec5702c42c182d36538f8ffe0ea922224b69877e2b429957c1431',
    'kit/confinement/feedback_admin_crypto.mjs': '169b8e70d59694162760315e50e140507d8e1f8eed29ac6a1efbb0026bbe029b',
    'kit/confinement/feedback_api.py': 'c2ee2f073493dc07a4801cd75f10554c63b17183523308693177984529b1ca65',
    'kit/confinement/feedback_failure.py': '464742193a5199f359c13ffa6dd90eea37df3a944b113d02157068f984713ca9',
    'kit/confinement/feedback_producer_crypto.mjs': 'd3dda950df99c3e3d925136a61c3e765bd19823f786ae0813ced2c9261cc08b7',
    'kit/confinement/feedback_public_audit.py': '888cd166a65b59ab1080419852f49c598a082067a71bb284fd12161484248cea',
    'kit/confinement/feedback_request.py': '78dba5d462ec4fa75fed71f53d52004f6002069f8ff6eafb1fb38e4d550f4ea4',
    'kit/confinement/feedback_smoke.mjs': 'c97d454d01565211fe6152324e2024d9ca1064eb8857a9c4c4829722b8ef2ef4',
    'kit/confinement/feedback_smoke_audit.py': 'e2ff4fb2dcb0dda4b0c9c1d61f04fe1f9158a76e7543cd425247af4b406018e7',
    'kit/confinement/fixtures/cargo-deny/issue-910-cycle/Cargo.lock': '7a4f80b6cffd817335120ff08a8b39702be006df94c711d7329e123982656db6',
    'kit/confinement/fixtures/cargo-deny/issue-910-cycle/Cargo.toml': '82f3bebd82dd0383344f3eed0a46a439dcdc3db2b3f67da4418933b277beed07',
    'kit/confinement/fixtures/cargo-deny/issue-910-cycle/a/Cargo.toml': '15fe7a8a1ed598593a131f4275f0f504d1f1d2ed6a1331a848258aab165235f8',
    'kit/confinement/fixtures/cargo-deny/issue-910-cycle/a/src/lib.rs': 'e253d7a7bfc8fd4e0e3c8a553cf61cda3b24430eb2178de99ce7932e43de8068',
    'kit/confinement/fixtures/cargo-deny/issue-910-cycle/b/Cargo.toml': 'cc0e2d0520418ea2100411ede6a3ff7f771ba94776a7e67268cc038cb2c2e535',
    'kit/confinement/fixtures/cargo-deny/issue-910-cycle/b/src/lib.rs': 'e253d7a7bfc8fd4e0e3c8a553cf61cda3b24430eb2178de99ce7932e43de8068',
    'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/Cargo.lock': '21eccdb8188fd36537470e8be62b2e2b784911ccfc908b962ff2e890c4097760',
    'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/Cargo.toml': '240924ba4cd7a625cea567b525661417863c6dd26ef4e713506d868c036acdd2',
    'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/build.rs': 'f7e2dd7b2556a69cad9e53a8b669db78501f0714535beb721e07d2879e2a39f3',
    'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/src/lib.rs': 'cda80e149e714cd5812691af2a372f893932ea53f3823fc24a47611532086438',
    'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/Cargo.lock': '6d650ddae5135ab203a02ed5ea3a03f853c1c27edbd07200c691a454d847d8d2',
    'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/Cargo.toml': 'c3b8aec1eec1ce3aa65e0b24edb512a2aab613b86904a917c70c02987c8df2d3',
    'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/build.rs': 'f7e2dd7b2556a69cad9e53a8b669db78501f0714535beb721e07d2879e2a39f3',
    'kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/src/lib.rs': '2fb15942ef04e6b4b1da6039e6b0492a711b6e3a9b1e9ab5f45cfe084eea2aed',
    'kit/confinement/fixtures/npm11_audit_report.json': 'fa181d1de0aff938377cd7ffb1217a1f620599b6e0808ae75a7da3c97bbe4baa',
    'kit/confinement/gate_table.py': '79f31334148550050f4f3ffb51cf0326d88cb10b6f120e73baa567e0b17c04dd',
    'kit/confinement/linux_boundary.py': '73adda7947d6add804d4f2b5b8117543d465830bfce72e7e1b4de22601c48394',
    'kit/confinement/linux_channels.py': 'dedc4f256440924c83e15be8201a998df9485fa6180f32126a5d5fe320837c5b',
    'kit/confinement/linux_harness.py': 'b58046a859edecefa69799a0eae484da1ffbab3011447d0bc9322fbbe258c8ef',
    'kit/confinement/linux_session.py': 'f71809d23fb576ab46b51882a9a4867856066dbcee2b132a10662acf42c5571b',
    'kit/confinement/linux_source_build.py': '02430a54cc3429c8919cbea30bb5996ffeb48cc7c346d78ef870387f22975a1f',
    'kit/confinement/macos_core_bootstrap.py': 'e7850a53709609dc6ce2ea0c817454694f95f7cd913c44da102b1448321ef4ac',
    'kit/confinement/macos_core_contract.py': 'af3aec230452009799f80de2491b16b73e6609687399c8230bbdd8c8b88a2c9d',
    'kit/confinement/macos_deny_default.py': '266970473298d83d8d1022dfd3b942ff79b7a264c154871eabb80ee5bcb74b89',
    'kit/confinement/macos_feedback_producer.py': '957573a464bcaa8229d02833102f4ddbceae51e70c8b7e514ca21f3afeaaf361',
    'kit/confinement/macos_network_observer.py': 'a7cf6cb16e68f00513e9f8ee08d52511619b18bb8edd37205faf907dcf0a98d9',
    'kit/confinement/macos_private_validation.py': 'c8ae1c308ba25ac18fe8f7d01793013300575d6feadb04516ae4f58ac67a3c5d',
    'kit/confinement/macos_public_audit.py': '155b23fc5d88f123309ed5068ebf4aeb4739f1634eecf803145271cc9b4a976e',
    'kit/confinement/macos_boundary_guard.py': 'badd3ab014d9bfb2040b7f89fa95e2d049bf7e7dddbae1f6e41a5026fe7c2e38',
    'kit/confinement/test_macos_boundary_guard.py': 'cd9994c38d5d3698af203c049ca286cb9d8af2b4d0a7127825f561bd53b3b180',
    'kit/confinement/test_macos_context_load.py': 'e01a9e3eaa328c2d1216c4a2316eae3a76ff628910dfed176a18078beadc6e4d',
    'kit/confinement/test_macos_deny_default.py': '101fd6c41abc8269f673f7b3d391686499f654d38f03a82c58d645eb33ac1419',
    'kit/confinement/test_macos_public_audit.py': 'c02c0c6370cd8254efe509a22d9e32515985554d531e1373068c01e62d8a70f8',
    'kit/devlane/sandbox_macos.py': '434bf52721ce7b7631e79af54bd7fad2608169b5e4c6d546d5dd933b892bb6e6',
    'kit/devlane/control-crypto-requirements.txt': '3d1b66ef228e4034282166fa8c333b1b41836aaaf0f803bc3ef655f594a6c25b',
    'kit/devlane/control_python.py': '14ffa43d5e341ad4b4094a3a3697d7fc133ea38c2e8873785db14f3f48db3774',
    'kit/devlane/test_sandbox_macos.py': '48d0dfdb8dace5e83d89335bd890c30f91a878d0877662596b95f60e877dbaae',
    'kit/confinement/macos_rules_bootstrap.py': '05345e0899b883bda0154d5ac79b68e027b28b32df0cbabb1124a9a6da9a29dc',
    'kit/confinement/macos_rust_toolchain.py': '7a6f5d95942be39f646c514f1b5f209c0089c3f767a5c2eed69a503371abd305',
    'kit/confinement/macos_source_reader.py': 'd3fbda5c68ac7d21761e946b0f546607b19c23ccb725e453f3fffef3321c0d70',
    'kit/confinement/native_loopback_profile.py': '5dee8e3f29e1d9178099eeefdec9f7520efe3939ab9b8cae71406b8da48a4ab7',
    'kit/confinement/node_lock_envelope.mjs': '0062366f9d6672211c87fc76702487a8d4d860f0ab9e7f1389a066cb063554ba',
    'kit/confinement/node_lock_inventory.mjs': '682f880a03edbd3c91b08dd4c581679cdb5d4ac70e93215044804c6152fc6f69',
    'kit/confinement/node_lock_manifest.mjs': 'edf77e688d5c1e18807fdbab2cbc50d4fbaf94f0630b6a6f483eb1723c3aeaae',
    'kit/confinement/node_lock_receipt.py': 'f5c14fcf7fb1e6f72793a1f96c4b889d5f6ab856c5f5392e6b0c744c0fed90a2',
    'kit/confinement/release_build_verify.py': 'ad9b18d2faaa6e7f408ea854f8483d9d97ebca0a7a2711e57d521203a882d91e',
    'kit/confinement/release_evidence.py': '2609b125bf2d3cbde256e2e4229c576fc0de1c5da898faf206807205dee49ae2',
    'kit/confinement/release_provenance.py': '6e9dbe1264623f68d95d01fe4b73c5c3e4d736a784c49c31fe0dea1b0fff8717',
    'kit/confinement/release_tool_ledger.json': '2c0004d1e83780d780c501b794a15e6c6928f8aa352dcfab46fe389fe871dc0b',
    'kit/confinement/release_tool_ledger.py': 'e9a4f50f806fad3d5ae7c7323adfc3024eaaa1f564a8725e9ef7281fa01c6657',
    'kit/confinement/role_signer.py': 'd99af1913617fe0d9e24577b5bafa3c9ab9f52cfe50d19aa1e7deef64afd0460',
    'kit/confinement/sbom_normalizer.py': '2fac64f1426b7f63c8a426719d4b9e0e6ea9d7e0cc190d8f913dbdb8fb961d3b',
    'kit/confinement/synthetic_project/Cargo.lock': '6f169382c34589f08ed2e3bd2f9d57c254b2e0856c9a7aa9b9b1391c72db9f1b',
    'kit/confinement/synthetic_project/Cargo.toml': '41867f8fbf2463eb725d084d25f91377307566a4c436e75d54b508b61fa9ab36',
    'kit/confinement/synthetic_project/crates/host/api/Cargo.toml': 'a7e10266f87a889cb2c0e6fd43018d8d2c8c78db595aa8c2cc174290f707e453',
    'kit/confinement/synthetic_project/crates/host/api/src/lib.rs': 'd7239985b313cd4089b75267dc125e9b02060e3dc5f5eec54c7eb867ec65d500',
    'kit/confinement/synthetic_project/crates/host/api/tests/feature.rs': '9617f0535a43ebe1fe2868a33ee519836d51a64ab7b6e090bf0c1c18d366fef4',
    'kit/confinement/synthetic_project/crates/host/api/tests/surface.rs': 'c3b968f5220c2c3aeca2f79491946ac7b03fda35239721c4e49489eca0fea4f9',
    'kit/confinement/synthetic_project/crates/host/conformance/Cargo.toml': '2c540cbb6b1ee66926b0e13eb2a342bc64305d7047dc5744b36e21b716ca8907',
    'kit/confinement/synthetic_project/crates/host/conformance/src/lib.rs': 'dbf4bcae7a2681bc8ba866a275bbffd2a53e5436357a6b5cc9c99024475f733c',
    'kit/confinement/synthetic_project/crates/host/conformance/tests/conformance.rs': '36e4d0607c4b6e24bd2b6e10ec98c16843e2cf8bd98fc95d2b451639f2125ea8',
    'kit/confinement/synthetic_project/crates/host/conformance/tests/process_pipe.rs': 'f1577608ba7ab4bc4c954b9ec6ea97327aff705a1f2a6834bbd04324c54baf45',
    'kit/confinement/synthetic_project/crates/host/mock/Cargo.toml': '7ffa03dc5053cb952c162ebfffacfc3a68d103ad478a274bbc370c28cd2fd678',
    'kit/confinement/synthetic_project/crates/host/mock/src/lib.rs': 'afbf54901b0324d830cc93bfcf48d58a7e56dd39ce33d254c058f78b7541470c',
    'kit/confinement/synthetic_project/crates/host/mock/tests/mock.rs': 'a3d9eb71d059dde42ea15c0c02fbce6628381ff3278cfcced1fad6d609522027',
    'kit/confinement/synthetic_project/fuzz/Cargo.lock': '8830b2d5813276d9f6bca6c1014eb5b2a23d2077dfd2afd08757318c923e753d',
    'kit/confinement/synthetic_project/fuzz/Cargo.toml': '7f94441d88f5cc6fdc48ad0f96e0f702d4f5369910efe8f10bf8259ba467243a',
    'kit/confinement/synthetic_project/fuzz/src/main.rs': '4440b336abdd23785c6d8f6ff0559468033b9460e10c3715c51adcc5b0a7961f',
    'kit/confinement/synthetic_project/package-lock.json': '45c29b459ac9a7e13597f424fe7ba2bfa1233d599b714d49bb0a0253de966642',
    'kit/confinement/synthetic_project/package.json': '63847331195f7d981044d5187c727065f303aa116982261e0bb472238e306a69',
    'kit/confinement/synthetic_project/packages/host-api/package.json': '3362fe24300e7cea1432bd5ccf3accdde14c83165f2245a0e8e3ba596fab0539',
    'kit/confinement/synthetic_project/packages/host-api/src/index.js': '93d2550086d545dbe2c53ef4e66d47e5e58e58c6232b830ad35fd47d2b50fac3',
    'kit/confinement/synthetic_project/packages/host-api/src/index.ts': '944f13e51b6f4882f5a6d32aba8646a31ec8cef4b94750dcd3da4f8ae7c9d39f',
    'kit/confinement/synthetic_project/packages/host-api/tests/no-net-use.mjs': 'b4bcd60e16bcf9399e314a0263e5167c25c7df0ddb574188fe5a71dc59f1f321',
    'kit/confinement/synthetic_project/packages/host-api/tests/run.js': '8b2a170f1c0cdd7787039cd8764f1c74534ed7818f352fe866b818efea3e9134',
    'kit/confinement/synthetic_project/packages/host-api/tests/vitest.test.ts': '81d0ad5e5a8b8175113bf4968cc845c9294a469f7b623a7acd1e1e3e8c6ece13',
    'kit/confinement/synthetic_project/packages/host-api/tsconfig.json': '8d2377f94f98025e7d3a48de2275c8a4afd01224dfe8b97fdd3d704f0748c3d3',
    'kit/confinement/synthetic_project/packages/host-api/vitest.config.ts': 'f226c491c4ed27a1b7f23ef8aaef33b74a0632d98e37fc86360749bb9eba34e8',
    'kit/confinement/synthetic_project/packages/kernel-i18n/package.json': '9f47cb3edc3211e1759ff29b12193d059c95c889b5e28bdfc61d51c1f82318f7',
    'kit/confinement/synthetic_project/packages/kernel-i18n/src/index.js': '5cb814c7a240ce0a3e0df21b4c1bdedba8ebb936c42cc46353dafb41d3847fd7',
    'kit/confinement/synthetic_project/packages/kernel-i18n/tests/run.js': '4fa83c16417d678b1a585021825d3e6af84c322d75e70fde695c34590d0f482e',
    'kit/confinement/synthetic_project/runtime/Cargo.lock': '15912d46236a56e1d33ef33aa5e4d28ff4f9881157684b72c4f0b08eb4088688',
    'kit/confinement/synthetic_project/runtime/Cargo.toml': '2163035d5965adad6df65622156c46adf3e4c22328259050d7862203efc2a571',
    'kit/confinement/synthetic_project/runtime/src/lib.rs': '2fdb08e9c85709dcbf2045c2bbda456dca7c012910f7e31e8a3eab2e9621b343',
    'kit/confinement/synthetic_project/runtime/tests/runtime.rs': '10b8b82ccc7ce5111fc25391648152f538073020ab7aef902e91c7d781688d97',
    'kit/confinement/test_cargo_lock_parser.py': '92801b5e56abc7e9388caf16c46f6e5e7852720e2355335177974382131bc49d',
    'kit/confinement/test_confinement_cargo_lock_bootstrap.py': '2cb6f8a133516d647b54c1ae4fbcca52fceaa1793f805b9395e90faa947d066f',
    'kit/confinement/test_confinement_gate_table.py': '438aa7792edefdfc58338c30b5cf53fb2579e63995db4ab58aaf514079297440',
    'kit/confinement/test_confinement_release_provenance.py': '1e630a123396e28e23063842575f780a3a9aaaaf44a3264f431ccdcd4d68c6fa',
    'kit/confinement/test_confinement_synthetic_project.py': 'da37a10a3fb05eef1ca68a885ced0d8cf96e927f185ce9d6a1e3c3e6e0732368',
    'kit/confinement/test_development_feedback.mjs': '7c8aecaf3286ed578feeaf662426f86ddf85a50518eaa796433855b40b32c273',
    'kit/confinement/test_feedback_admin.py': '56d3c7dbd6836e3b44c926dbcb1dd30f61a50a72aeb36d2cb1a2933990c72897',
    'kit/confinement/test_feedback_admin_crypto.mjs': '35e7109afd8b43eda8541a9c6af9bdc375a19d35ce6932438506fa97f76a0931',
    'kit/confinement/test_feedback_admin_integration.py': '5cd59a4833de05dea5826699e807baac871d0398cdc8c590f1f89c829720b5dd',
    'kit/confinement/test_feedback_api.py': '2be1551d5ff5aee195db6d5726ce514b401172669cfa42361a43921573eb7181',
    'kit/confinement/test_feedback_failure.py': '6976d7d22c1b65483e587f5b65a524e18fa8f667c9acda76b6fc17c70600288b',
    'kit/confinement/test_feedback_producer_crypto.mjs': 'fce674b341e6e8d1237350591719efb1fb39b054ac0174121ad3fa92c95dfac2',
    'kit/confinement/test_feedback_public_audit.py': 'c7c3c94c9c85646ea3af2f7035f95da93b5fdaf1afedfe9de89e65f768f73691',
    'kit/confinement/test_feedback_request.py': 'bda86c433252e8d02b302da4705d22761b42cbf3520b69c05ce853fb38bfdd4a',
    'kit/confinement/test_feedback_smoke.mjs': 'bfac55b9fc394fe61ee17f7a7f8bf2d82acf7096e6f45f1be33e4d3ef0b9bf49',
    'kit/confinement/test_feedback_smoke_audit.py': '9f42b828f104d840ab007c8967babf90a93497fd6e064b77bc3e946f5a831b97',
    'kit/confinement/test_linux_boundary.py': '360059febee2441715457093640d7d3ef5f3be3d46e2198bd4fec19fe933f23f',
    'kit/confinement/test_linux_channels.py': 'bddad18cd3fbc9ad9290004d56c08976dfd7e309e5cc32e30483d1aa15fa5adc',
    'kit/confinement/test_linux_session.py': '4905cf0c27e7bc3e302abe714a02cd08de6512b65061357f6d371792ab61129b',
    'kit/confinement/test_linux_source_build.py': 'db4c1258700a2f845525da00b05ab591913566a6dcf370010da4555ed402b9a6',
    'kit/confinement/test_linux_source_build_tiers.py': 'a14ac0ebc3be6eeb9aba172ff1099a7cc37b010ae6eeaaa762056bc1001bc32a',
    'kit/confinement/test_macos_core_bootstrap.py': '69ab67960a31e4a298c8136f7492b7c5c84ea80b855fd5c2be0726d1125f7115',
    'kit/confinement/test_macos_core_contract.py': '912b587088bd3a83c2c57201994da53aa961e25dd4bdd7ca97ec506c6a297470',
    'kit/confinement/test_macos_feedback_output_limits.py': 'b9bdf52adb9504a0bb57ad79553a71f907cd636b53f386a3c8776304b6dbb0ca',
    'kit/confinement/test_macos_feedback_producer.py': 'e6c245cdec2736cb4c12e06038effb3adddf9ad008f2ec4d651c65a76e626da4',
    'kit/confinement/test_macos_network_observer.py': '0187ffbe5a7b7395b2edc2025a4dd3e4c0adf5a48c881f8878578010d76307a3',
    'kit/confinement/test_macos_private_validation.py': '178b5f479db66b879e5b9c323fa2c03ead2bf0124e0dbd94d9014b443f223746',
    'kit/confinement/test_macos_rules_bootstrap.py': 'f1bf5de1635a0e06d6ac0c25b21675005d8ea4d813354747202a522deeb213c9',
    'kit/confinement/test_macos_rust_toolchain.py': '81c625bb61c2b8689e1e5420f60e930450d8395a5d2de5d37e4e9de15d94b0b6',
    'kit/confinement/test_macos_source_reader.py': 'ed8e9b850f7d3a80346ad4a6efc182b28ff9c22fa669eda241f2c5feb3ccf806',
    'kit/confinement/test_macos_wave70.py': 'c3c1aa78b476e703247333f8898fae1727d6d186d41310a620a44f22ec508e4d',
    'kit/confinement/test_native_loopback_profile.py': 'acbc69ae710ac56931429fdc881a853ceadfaf63327a62aace5e6f1d76e8683d',
    'kit/confinement/test_node_lock_envelope.mjs': '4bbe2c72a2cef7720ea5e50217bbaf3fb622cccbef2e07f208889d50c291319c',
    'kit/confinement/test_node_lock_manifest.mjs': 'c4830b7d8db4b08d9fc4ea2371c71c36f1f1e9d2625caa154fa374af3e219c87',
    'kit/confinement/test_node_lock_receipt.py': '428d7a9a2d16eddd061df8e6939b538ba738ed8689b8bf1af9e282ce409a0bb7',
    'kit/confinement/test_release_build_verify.py': '08c8b7dcb28307d8470cab9675202bcc206492261d20dec70064232c197f2579',
    'kit/confinement/test_release_evidence.py': '8157fdaf8f9a691d4bae699eec3b7eb07143cc8f0fef6bed7619ebf45da8c6f3',
    'kit/confinement/test_release_tool_ledger.py': '20ef9cfb0f4a64c73e34443c3d726be599c34ac6145df875d1abe8a427de8a4e',
    'kit/confinement/test_role_signer.py': '31cd7cc4189aeba885da2870c04292423cd72032746d6351ef6ef480f182cc6e',
    'kit/confinement/test_sbom_normalizer.py': '2d6e4026d3f317be2036d6e015f4b41fbdec855ac930f4b812f1097dd03451d6',
    'kit/confinement/test_windows_confinement.py': '893d6d7371530764df22baefc9b6b79f82381d8240389d4d005c8b7685d8106a',
    'kit/confinement/test_windows_native_preflight.py': '07defbc65611505f9107e5cb9186f4e15bbb9616797ff07032b3f314480eea7d',
    'kit/confinement/test_windows_source_run.py': '4bdae301112ed6cbcd8d18f3b7d7faa808582cbc387fd9bc14003ba71eb128a9',
    'kit/confinement/windows_confinement.cs': 'd35721f5fcf4733e066fe481a2d692814e1cc5cf072c4daff5f64c40d3753cbe',
    'kit/confinement/windows_confinement.ps1': '1bd0b04dde27eaca58b2a7873345e3c1cacb4e988ff8b8980ebdda0bcf82f036',
    'kit/confinement/windows_native_preflight.cs': 'ba0f8859db9d8bcc1e4c8274520bcb67a3292cb311f553127e1f29fe13838543',
    'kit/confinement/windows_native_preflight.ps1': '8dbaaaad105c2fe0439dedb1b7c9572b8e7ec74a8db29f8edcab91169b06c58b',
    'kit/confinement/windows_npm_link_shim.cjs': '668148b9f106454b05aacd6274b9f6c07590f3ed0e532fdc9639696dc287855a',
    'kit/confinement/windows_probe.rs': 'cf9e58d8f31e2a9773f2c4eba935fd1ed531d94397ac53e530a93c5169d08727',
    'kit/confinement/windows_source_run.ps1': '2b37591c61db5394dce725e15546df0dff466d3f2d28d529aa91e2329ee50eb6',
    'kit/devlane/__init__.py': 'e19ad6f4a13d793137d6cffdba831912e2e7da6c739bc538dcfce9f3171a704f',
    'kit/devlane/bundle.py': '6db2b6edaad1197e5047f7aeff8e8047e48890a1f2dab21dc853b6e3d89faaee',
    'kit/devlane/control_audit.py': '80f29ac73edf583f9dc8d2dc05e3071e0cbd033c626f915a294ad542b08af7ba',
    'kit/devlane/coordinator.py': 'ea13e691fccfd7b0ec3cef8938b51a587251f036e0a8c72d5a62b3259b7ddc91',
    'kit/devlane/decrypt_once.py': 'ee139f6dbb1adee9b7ce6c17f2c1ae127280d613362313a53a6b49476a8045a3',
    'kit/devlane/acceptance_diagnostics.py': '57f8212ff066a891cc8c07415793178b5d594c8bbf9bda95063c43d943ce174a',
    'kit/devlane/diagnostic_contract.py': 'b699338c67555da800cf01881805cb58b7c4a11a6751144c44ec6180041ed83d',
    'kit/devlane/node_tool_snapshot.py': '7d36e7e5b08a89d5a70f01d67b838eb4db026d60e32c21c8db846df5c69fd7d1',
    'kit/devlane/test_node_vendor_source_r2.py': 'f03d16132d69908df01dfcfc03159bf9d9abc47a85eb65fb1fb149a132153f61',
    'kit/devlane/test_node_vendor_source.py': '146e2f7a059bb55ef4a2bdc7ea3e0965d2bab8a53540b8c9931a013295d0ec38',
    'kit/devlane/bounded_registry_io.py': 'ed5dcb8a3c746bfc7ccc2220287633fa2a4ee51ad2acf99a6e85ebf6da570f67',
    'kit/devlane/cargo_projection.py': 'ea0557e6a1d72dacbaa2449449d8ce994f579d8b42bb6263e25643a6da447328',
    'kit/devlane/constraint_resolver.py': '774586d37af1b4f523fa8332b46b5069dfa71e39f637bce98199d5d8bf765b12',
    'kit/devlane/registry_prefetch.py': '585c02674ca6532b09a4ad426217c34f7a8279412d947b28fb33ebfe8525a45a',
    'kit/devlane/test_source_projection.py': '74cf2a5ea69e05ca01dd33976a67d46e0616b9921c76c5c954ac3ebb5c331a97',
    'kit/devlane/rust_preparation_smoke.py': '344c06abd73da11d8eec6e49e27f155507f2e05c2c724c9e4c3f959a198ddde2',
    'kit/devlane/rust_preparation_v2.py': 'f38b3049d0cfbf852406a3dc807341a8bba482e3a2f25530fa390a6182e86422',
    'kit/devlane/rust_lock_generation.py': '86b999e05b6c24e320591f9a1e2853dcdd7e68615936b42707669c866fa9d3b5',
    'kit/devlane/test_rust_preparation_v2.py': '7c93b6e3e39ab77a776e2986283195b5ab7ed1de21c6f43bdda26594f5464118',
    'kit/devlane/test_rust_lock_generation.py': '0185fc13150416df75e3d67f475753b1737bbe6d2066ebcf9d412c8cecb45e7b',
    'kit/devlane/node_vendor_source.py': '1892bfe55efbde30774ffee545777728523deb2b4925f91ffe886a379f5aea7b',
    'kit/devlane/fetch.py': 'c2f7b27d3b14f605e489fd6bcbd59bbf8cef0de88cdd44c9a01b137380eccefe',
    'kit/devlane/filter.py': '5115b391ea7582e679235e90ed341a5767b51c7b49baf0f11cb6f2a880973f60',
    'kit/devlane/host_cleanup.py': '497b1ad122a379890d9ad48741b1985d61e7e1fdf891fd0cb0e38aee65c68cf3',
    'kit/devlane/owned_tree_cleanup.py': '94f5f190a42cdcd177cd6ba4f923fba4fffbb60049c6e10351c4917427ebe06f',
    'kit/devlane/isolated_cleanup.py': '142a08f4b4921d79f5e0ca6373af393d2e0b0867806328e0733b8f37b91ea527',
    'kit/devlane/refusal_codes.py': 'bf53c21a9c0ad97c9d5cf6f0dc68de1ffbde8beb1f91258c47e442e63779a696',
    'kit/devlane/network_probe.py': '4e86639f63dd4a08415817f45e0998ed6aad58f701ab920e28369a2bde575f29',
    'kit/devlane/permit.py': 'd82256237f812343a74eadb1802f41c725fffbe5237d6a563b46a2efdc2b0817',
    'kit/devlane/prepare.py': 'f44b732fd4e0906442959fecbcd990c37ba08ed80c93c6f97dc02d44cd6eb830',
    'kit/devlane/project.py': '3c86f89e65676646d2b02eca0993b3745f9d7c2fc567d421c5728cb6951e5727',
    'kit/devlane/public_audit.py': '2fce6c34bd244f8b8d5ff4b6996b3b474b05098cb8e9f045fd2f89e5523879c5',
    'kit/devlane/rust_test_runner.py': '1b0b655d8f89eba1a251b25c93c3df48e9376b5694e1cc19a6b0c4f1b7667a68',
    'kit/devlane/safe_json.mjs': '17d44acd9970efeea8b9b2c80d746efc940460008287f75e7dc2a749239ee169',
    'kit/devlane/supervisor.py': '13723880e8e067f6e04700a4a8df795f952749e25bd9a201b04614a66a6827b6',
    'kit/devlane/test_acceptance.py': 'd5f34210f17c947a06f64d70a7767a4c1a98ec1516f70ad26b09ce21a9b6cd75',
    'kit/devlane/test_worker_control_imports.py': '127c3580c30e24744e9ef7a24f338a5a96765a14073252f0c746507c8a38923f',
    'kit/devlane/test_adapters.mjs': '8347496bbad7dba397ff583359dc205a7035c19b9b5ece4641bcba625ff2486a',
    'kit/devlane/test_audit_contracts.py': '5e3fac8bb68f058d786b8ad7781bdfb3cb6ceaf949ed65d1708a538bd31a2d87',
    'kit/devlane/test_control_python.py': '040d7f94c584de2d6de13b26a4506f1085d118b9bf2e223aa1211be628b59e18',
    'kit/devlane/fixtures/encrypted-audit-43284558151.log.hex': '6c795bf0e798e9fd07eeac786aedcf082af192a8749d56b4afbdab03ede3d3f8',
    'kit/devlane/fixtures/encrypted-run-43284558151-identity.json': 'd2d6fcc8e3f22bb177af015828940abeed97590e6ae8b3c2b764222d53024f9a',
    'kit/devlane/fixtures/encrypted-run-43284558151-jobs.json.hex': '6bc71d86ee0f1aeb269d9cb1658c463c203992d5c1b8b7476a21f7361b3d1719',
    'kit/devlane/fixtures/encrypted-run-43284558151.log.hex': 'e07c7b2823ec0ff3fa14ad0c7d7f64e692c86e9c5675f33eb2c474036d1846d9',
    'kit/devlane/fixtures/encrypted-workflow-43284558151.yml': '8a53ac1d47e469750c7a7e25d7c7a1565e4df598063e6b42ed7565a5b1353e86',
    'kit/devlane/fixtures/encrypted-workflow-f0ddd39554b2e48fbad7e61126319f5ffcdd2b84.yml': 'f380785d045a262801a5ae01ba5c5f66637c46c6011357bd1d62e84bfac53939',
    'kit/devlane/fixtures/encrypted-audit-43296698158.log.hex': '93abcb2d92fe08f7e3d42e7c9390f66fd3aa2907f23d6f05dec04cd7dc52950e',
    'kit/devlane/fixtures/encrypted-run-43296698158-identity.json': '3e1c7db0d6caceb09f0bc1fcb22ad23498dc0486310e1d4bcc12c542bc5e9087',
    'kit/devlane/fixtures/encrypted-run-43296698158-jobs.json.hex': '62611a45607ebf7f5076d72f2d75ddcdc8d59282672eb3ead57c9c61ca20c037',
    'kit/devlane/fixtures/encrypted-run-43296698158.log.hex': '75bc3b7abdb823faf4681ed46584137b072596a306cee96519fd170bf0355337',
    'kit/devlane/fixtures/control-synthetic-43245798187.log.hex': 'b53f89bbf7e668540103432e5de9fe042464850b3fa04a9ab6d366f04310c0bd',
    'kit/devlane/fixtures/synthetic-workflow-43245798187.yml': '9a0e52bcad34b144e8a507af24f35c10c8408f5f85488c9f24217a057a667e13',
    'kit/devlane/test_desktop_profile.py': '748a0d60df0ed430ab891d1d331c4af44233ea71571b403371f164ea010bffe0',
    'kit/devlane/test_coordinator.py': '15ac8d15b67b407a9773353b27c9a47e4cabfcd221e27d30c02f5b26cd41ce23',
    'kit/devlane/test_e2e.py': 'c207653a95ee2e0cd4e6e5e0f3d1d36749d7e457c6625ae22e47b76c7db99511',
    'kit/devlane/test_linux_runtime.py': '8cc12a9d0aa9f0fa10353a538a589b0598845e3c4dea4a8e34f19ba5e015e014',
    'kit/devlane/test_rust_report.py': 'd81dba0fe3813941bcc5bab639afc13823badabdf01ec8a1eb9199969e1523f6',
    'kit/devlane/test_rust_test_runner.py': '251de8978e4eafcb94734362da9508f94b6acebe84e348a25561245fa9b72a6e',
    'kit/devlane/typescript_reporter.mjs': 'd5975143d83c7bf77f34c806b5cbd93bec66f2272e7c559afe17254befbe1fc4',
    'kit/devlane/deadline.py': '516753a2259bbc7e1089bf544ec792f37b782c61ff2c5edc3c019cb3dce5d64c',
    'kit/devlane/rust_matrix_runner.py': '99b0600acb1d0166f583bfce1b98a5e7bc77ea29889cd859b4126844de536307',
    'kit/devlane/rust_tooling.py': '1efd8bc87a217ccc5d9df4bb7b206a742458cc9dc9c3c4855c852d001e1bdabb',
    'kit/devlane/test_deadline.py': 'e95bd38085287567ecd62054046346257bba3720c05030a533d530cd48bf6c47',
    'kit/devlane/test_powershell_static.py': '638457f4fcc33a8ed8ec65dc24881d06bb8a226eedd826e7e22f20acb44a2c4b',
    'kit/devlane/test_powershell_live.py': '883286725271f8ade1c154b440bb81a1656e87926751daf8070222f99db61487',
    'kit/devlane/test_network_probe.py': 'cfb2ae49d17cfb55dff4847965116e2caa4ce2def3c978b48c5d2f5faa767b18',
    'kit/devlane/test_rust_matrix_runner.py': 'be439afd8b20898307b0efebc30d6cddc80e2ccd3db3b792a7b1bb6dde33847e',
    'kit/devlane/test_rust_public_audit.py': '47bc82c21f5cd2b4165090ad578bf0fbe8c3c6885a386233cc314f462611d9e0',
    'kit/handoff/provider_requirements.txt': 'c812f3c3f036921e86568feaa3bc934040b68f3d743072cefce8ea758bd56150',
    'kit/handoff/source_capsule.py': 'a1369abb354f0723bd3cfc3209aa15c4769bfb113b2fe6369023c7f95e4546ac',
    'kit/handoff/test_source_capsule.py': '6ea11945a8e08040b78faa4d4861abdd600901ed048abe22a2edfc3b97bfcd57',
    'kit/promotion/branch_promotion.py': '26386626323326183cc381ccbf84d29e856a3bce8ba963d7fc66c1fbd9bee3f2',
    'kit/promotion/test_branch_promotion.py': '99ca63d8e84f8a36c578220382d20bea7933c3dabe1a8d46301d32eb9cac787a',
    'kit/selector/ci19_catalogue.py': '7fe71cbf6307035d9351ab417951baeb12b39eb860a121077f55a1a70002df71',
    'kit/selector/fixtures/ci19_mcp_feature_owners.json': '69124b6f86729cac26478957d5430346dad9fedf4f98c8cb677536d66f5bf306',
    'kit/selector/suite_selector.py': '6c9a497566179ae7169717d2d58b6ae9239ed6ff4573de493b8cad55cab8a4fa',
    'kit/selector/test_suite_selector.py': '7c1a4caedcd7fbdcc9b3d08092e3af7ce67ae1409f0d86e3a0421c11e8878a29',
    'kit/devlane/semver-pins.json': 'e18a8428350c9e9843081623697dfcba76bcefbe23a08491460480f1cb112688',
    'kit/devlane/semver_cargo_wrapper.py': '1f2ebc4ada3ebc841c7909c2c2fb35bcd12a633eef000b076d286f638fa25195',
    'kit/devlane/semver_offline_cache.py': '6c0436afc81b570d805c6877b7286489b620244ac605527e26fb2e4eb972c199',
    'kit/devlane/semver_stage.py': '450e0803627f607b58db0ab0cedb16b1339d9a8393b36d273625da31631460dc',
    'kit/devlane/cgroup_exec.py': '8a8a7dbaa74488d7cc70fbd6630c19cb46c9c3311da1c579e6c17666a3b34dba',
    'kit/devlane/temp_project_checkpoints.py': '93e47b3867f6c5e4c7051f5705fc4acea765438c88c73ba272941f6ea11db299',
    'kit/devlane/test_semver_review_fixes.py': '3dcb144105ac3253e9a4a31db18ff7b68b1e9d6e566d68abdbb5ab04f0a3d11d',
    'kit/devlane/rust_rehearsal_fixture.py': '7b8f159c9c98df50f3d3c81d4e449b3815112045efe7d8cce5896b4d5cc8be6a',
    'kit/devlane/fixtures/real-netns-dump-ubuntu2404.txt': '12d2185f34de2ec223b931402bb7fb683987be2e974df5a6b67fa8228d1ea774',
    'kit/devlane/fixtures/real-netns-rtnetlink-ipv4-ubuntu2404.bin': '14e9c17acac01882acc4cfe9b5e90d63e4aff226e625058300bdfe55e90b9f2c',
    'kit/devlane/fixtures/real-netns-rtnetlink-ipv6-ubuntu2404.bin': '76b8fc1db99045e71f24f9ba84253df4b0d03b7e2e8d9b5c5372f80c57bde024',
    'kit/devlane/fixtures/core-rust-rehearsal/Cargo.lock': '5a188f2fa3aac2d7a5422b178e0efb5c7deae6dcc5dd7133c7bfa2df2c5e4e95',
    'kit/devlane/fixtures/core-rust-rehearsal/Cargo.toml': 'b7d06db7992bd2554161a9792ae15941c8b5c2016d23311571ae4c21c2feba5c',
    'kit/devlane/fixtures/core-rust-rehearsal/build.rs': '990a2d90dced8c4bc2885071889c305b864c70bfa70c78e2518b835ad1f769a4',
    'kit/devlane/fixtures/core-rust-rehearsal/crates/support/Cargo.toml': '308645a2b3887a75f0b1a8fa57902d9f629ee569504e19a6ef7349af00adcca0',
    'kit/devlane/fixtures/core-rust-rehearsal/crates/support/src/lib.rs': 'b5baf6d15d3e047af8a9db2a690a6126b13edea2494538e9893baf6160fc4e86',
    'kit/devlane/fixtures/core-rust-rehearsal/deny.toml': '991face3dfdaf807d4cb425f8aa8c3b6c0286874519d2527d03d5b4b635a5f43',
    'kit/devlane/fixtures/core-rust-rehearsal/fuzz/Cargo.lock': '6d5c674ec012532f178f84b2cc216e80699e888277d67750180ef2b66bef706c',
    'kit/devlane/fixtures/core-rust-rehearsal/fuzz/Cargo.toml': 'cd01602ab9435b59a7c6c117dc671aecd373160e80d81c39517cdd5e698cf568',
    'kit/devlane/fixtures/core-rust-rehearsal/fuzz/corpus/valid-array.json': 'fa1822cf964944168ed1b27f202824922f045d5a479c5629900410a6a5be0001',
    'kit/devlane/fixtures/core-rust-rehearsal/fuzz/corpus/valid-object.json': '317fa3b56b76822840892e4846f9165b03bd8199c9cd3882ae14ba855f44cc24',
    'kit/devlane/fixtures/core-rust-rehearsal/fuzz/src/main.rs': '354a548b87809a075616fa1cc65c49c6b79a577b1033662ad2091b0e395e5be8',
    'kit/devlane/fixtures/core-rust-rehearsal/runtime/Cargo.lock': '089e3cc0c3abb7d93ad8b20b9ef08b98bf1f10af076935ac824f3f9b556bd21c',
    'kit/devlane/fixtures/core-rust-rehearsal/runtime/Cargo.toml': 'b809bf2ea62dca2ee4d388ca2f2ae306a4890b3f6c0d83de8b839775494ee191',
    'kit/devlane/fixtures/core-rust-rehearsal/runtime/crates/services/listener/Cargo.toml': '3a9a69094ebfcfc6509c0373c2a93612f2d16929a7c90c4b67bf5908996358c8',
    'kit/devlane/fixtures/core-rust-rehearsal/runtime/crates/services/listener/src/lib.rs': '09838534254715563720c2cd0744b95272d7280a7bb874ffecb3433c8e6dc173',
    'kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/audits.toml': '628720e4cf05595b314bd06d3bb73e6434e3d3be10f1a394dfbbfe6ea248403c',
    'kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/config.toml': '59a01b16d2e3411ebc1685b0a6ccfddb633695e3fe0f18780b519f9fdf373a03',
    'kit/devlane/fixtures/core-rust-rehearsal/src/lib.rs': '845d6336d20a5c4206ea3e8cee5e52cf0f285bfdd768dc53ab30d4ba91911833',
    'kit/devlane/fixtures/core-rust-rehearsal/supply-chain/audits.toml': '628720e4cf05595b314bd06d3bb73e6434e3d3be10f1a394dfbbfe6ea248403c',
    'kit/devlane/fixtures/core-rust-rehearsal/supply-chain/config.toml': '6511f4606f1ce0496bb2d7196bcf47bde1dc79d9271048eb8510818fbd77efbd',
    'kit/devlane/fixtures/core-rust-rehearsal/supply-chain/imports.lock': 'ff01c4f0f1a725196404edd25fbab0b4ad073de1264fa124b92e2344ec39eb7a',
    'kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/imports.lock': 'ff01c4f0f1a725196404edd25fbab0b4ad073de1264fa124b92e2344ec39eb7a',
    '.github/workflows/desktop-tauri-smoke.yml': '66657210c34c3d6ca76b7f224fc9e82b06e68fcea92c21934895e638d7ac70af',
    ('platform', 'ci/policy.json'): 'e28afbcceece16eb7590ba1e7910e13e4f07bfb1455e1ea68bfb5de31d4435b7',
    'kit/bootstrap/check_candidate.py': '3155dc7990286f3dbfac345475e7258c4d9837d574dcbc3b9f9a9591a23f2e71',
    'kit/devlane/fixtures/desktop-tauri-smoke/package-lock.json': 'ac46fa7a64e3d42eae4c876ea4eb9e812f98ddb24ae471036cf9f4299e8a623a',
    'kit/devlane/fixtures/desktop-tauri-smoke/package.json': 'd903118c9fcb7eb14264bc3e15c28c59022f91ef4f87f7b239d76a88b9f79837',
    'kit/devlane/fixtures/desktop-tauri-smoke/build.mjs': 'd1234349731053a1c6e777113f4b32eddb1eb949e3093d1da75d2579f724c9a3',
    'kit/devlane/fixtures/desktop-tauri-smoke/index.html': '733c4c284857374634f1d0ce2a51497d47cea001042df53a96d655ba3910ce36',
    'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/Cargo.lock': 'e268f6e248b44b48559cd20a8757bbbf545e1795e00abb87429adc57ead479b0',
    'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/Cargo.toml': '21544791c139e83d112c6b7e36ab4a929b0844f112d1dfa2732b09a05e1ddfe0',
    'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/build.rs': '487059eaf8a947b80f20a9aacac038a5047b2ad69d2401b827376c67d6fe847f',
    'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/icons/icon.png': 'de7472f4851586243f8b19d5f254a4553400a9a303244fb5aefa855317d367bd',
    'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/src/lib.rs': '4705cc63d675b1621bfd01b28d87d789e58622b066697a47de775ae9d099bab6',
    'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/src/main.rs': 'cadaae13fdda82c558f51a943c89cdf05dbcf151eed89dca388c66b1f74a3539',
    'kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/tauri.conf.json': '9bce3fca18224c76a7825207f84b34dae160e4e133b9d51e7230fe25dcebd2d7',
    'kit/devlane/sandbox_windows.py': 'ce1d27f3ccf85625685028b5307811c685771b14b2df9646da6a18d8e182e378',
    'kit/devlane/sandbox_windows.ps1': '713761901db31f27bde795b661e861938aeaf5ef8320a1265cd90a0b7ecc3900',
    'kit/devlane/sandbox_windows_native.cs': 'd2e52c637650ed61d2f330c4c36b0e16c1dc606a8bfd0b4e02da54d3e8c50001',
    'kit/devlane/sandbox_windows_reporter.mjs': 'ac3ebae312331a2095dfe2c11200dae4f3db2c9be77add796bedd1a60f496d6d',
    'kit/devlane/test_windows_sandbox.py': '7a61e424d2b6b85d355acc71f3fdc134d11c150bf61e56472bc4b551d38ac3fc',
}
BINARY_FIXTURE_FILES = frozenset((
    "kit/devlane/fixtures/real-netns-rtnetlink-ipv4-ubuntu2404.bin",
    "kit/devlane/fixtures/real-netns-rtnetlink-ipv6-ubuntu2404.bin",
    "kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/icons/icon.png",
))
PLAN_ID_PATTERN = re.compile(r"(?<![A-Za-z0-9])(?:D|R|H|X|CI|PF|K)[0-9]{1,3}(?![0-9])")
SHA512_SRI_PATTERN = re.compile(r"sha512-[A-Za-z0-9+/]{86}==\Z")
ACTION_VERSION_COMMENT_PATTERN = re.compile(
    r"^\s*uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}\s+"
    + re.escape("\x23")
    + r"\s+v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$"
)
PRIVATE_PATH_PATTERN = re.compile(chr(47) + r"(?:Users|home|private)/[A-Za-z0-9._-]+")
WINDOWS_PRIVATE_PATH_PATTERN = re.compile(
    r"[A-Za-z]:[\\/]" + r"(?:Users|Documents and Settings)[\\/]" + r"[A-Za-z0-9._ -]+",
    re.IGNORECASE,
)
WINDOWS_UNC_PRIVATE_PATH_PATTERN = re.compile(
    r"(?:\\\\\?\\UNC\\|//\?/UNC/|\\\\|//)"
    + r"[^\\/\s]+"
    + r"(?:[\\/][^\\/\s]+)?"
    + r"[\\/](?:Users|Documents and Settings)[\\/][A-Za-z0-9._ -]+",
    re.IGNORECASE,
)
REPOSITORY_URL_PATTERN = re.compile(
    re.escape("https:" + chr(47) * 2 + "github.com" + chr(47))
    + r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
)
PINNED_DEPENDENCY_CHECKS_REPOSITORIES = frozenset((
    "https:" + "//github.com/" + "EmbarkStudios/cargo-deny",
    "https:" + "//github.com/" + "RustSec/rustsec",
    "https:" + "//github.com/" + "mozilla/cargo-vet",
))
PINNED_RUST_TOOLING_PATH = "kit/devlane/rust_tooling.py"
PINNED_RUST_TOOLING_URLS = frozenset((
    "https:" + "//github.com/" + 'EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz',
    "https:" + "//github.com/" + 'RustSec/rustsec/releases/download/cargo-audit/v0.22.2/cargo-audit-x86_64-unknown-linux-gnu-v0.22.2.tgz',
    "https:" + "//github.com/" + 'mozilla/cargo-vet/releases/download/v0.10.3/cargo-vet-x86_64-unknown-linux-gnu.tar.xz',
    "https:" + "//github.com/" + 'obi1kenobi/cargo-semver-checks/releases/download/v0.51.0/cargo-semver-checks-x86_64-unknown-linux-gnu.tar.gz',
    "https:" + "//github.com/" + 'RustSec/advisory-db.git',
))
RUST_TOOLING_URL_PATTERN = re.compile(
    re.escape("https:" + "//github.com/") + r"[^\s\"'<>]+"
)
PINNED_CARGO_FIXTURE_REGISTRY = "https:" + "//github.com/" + "rust-lang/crates.io-index"
PINNED_CARGO_FIXTURE_LOCKS = frozenset((
    "kit/confinement/fixtures/cargo-deny/issue-910-cycle/Cargo.lock",
    "kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/Cargo.lock",
    "kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/Cargo.lock",
    "kit/devlane/fixtures/core-rust-rehearsal/Cargo.lock",
    "kit/devlane/fixtures/core-rust-rehearsal/fuzz/Cargo.lock",
    "kit/devlane/fixtures/core-rust-rehearsal/runtime/Cargo.lock",
    "kit/devlane/fixtures/desktop-tauri-smoke/src-tauri/Cargo.lock",
))
PINNED_CARGO_REGISTRY_READERS = frozenset((
    "kit/devlane/cargo_projection.py",
    "kit/devlane/constraint_resolver.py",
    "kit/devlane/test_rust_lock_generation.py",
))
PINNED_CARGO_REGISTRY_FIXTURES = frozenset((
    "kit/devlane/fixtures/core-rust-rehearsal/deny.toml",
))
_CARGO_VET_HASH = chr(35)
PINNED_CARGO_VET_STORE_HEADERS = {
    "kit/devlane/fixtures/core-rust-rehearsal/supply-chain/config.toml": _CARGO_VET_HASH + " cargo-vet config file",
    "kit/devlane/fixtures/core-rust-rehearsal/supply-chain/audits.toml": _CARGO_VET_HASH + " cargo-vet audits file",
    "kit/devlane/fixtures/core-rust-rehearsal/supply-chain/imports.lock": _CARGO_VET_HASH + " cargo-vet imports lock",
    "kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/config.toml": _CARGO_VET_HASH + " cargo-vet config file",
    "kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/audits.toml": _CARGO_VET_HASH + " cargo-vet audits file",
    "kit/devlane/fixtures/core-rust-rehearsal/runtime/supply-chain/imports.lock": _CARGO_VET_HASH + " cargo-vet imports lock",
}
PINNED_RUST_TEST_ATTRIBUTE_FILES = frozenset((
    "kit/devlane/fixtures/core-rust-rehearsal/src/lib.rs",
    "kit/devlane/fixtures/core-rust-rehearsal/fuzz/src/main.rs",
    "kit/devlane/fixtures/core-rust-rehearsal/runtime/crates/services/listener/src/lib.rs",
))
_RUST_HASH = chr(35)
_RUST_TEST_ATTRIBUTES = frozenset((_RUST_HASH + "[cfg(test)]", _RUST_HASH + "[test]"))
PINNED_DEPENDENCY_CHECKS_PATH = ".github/workflows/core-dependency-checks.yml"
PRIVATE_REPOSITORY_PREFIX = "keeldock" + "-"
PUBLIC_REPOSITORY_PREFIX = "keeldock" + "-" + "platform"
PRIVATE_PATH_MARKERS = (
    "agents" + "-work",
    "Plans" + chr(47) + "PluginSystem",
    "." + "claude",
)


class PublicTreeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _pinned_file_hash(relative, payload):
    if relative != SELF_PIN_PATH:
        return hashlib.sha256(payload).hexdigest()
    normalized, replacements = SELF_PIN_LINE_PATTERN.subn(
        b"    'kit/bootstrap/public_tree.py': '" + b"0" * 64 + b"',", payload,
    )
    if replacements != 1:
        raise PublicTreeError("self-pin-shape")
    return hashlib.sha256(normalized).hexdigest()


def _valid_sha512_integrity_spans(text):
    try:
        json.loads(text)
    except (TypeError, ValueError, RecursionError):
        return ()

    decoder = json.JSONDecoder()

    def skip_whitespace(index):
        while index < len(text) and text[index] in " \t\r\n":
            index += 1
        return index

    def parse_value(index):
        index = skip_whitespace(index)
        if text[index] == "{":
            index = skip_whitespace(index + 1)
            if text[index] == "}":
                return index + 1
            while True:
                key, index = decoder.raw_decode(text, index)
                index = skip_whitespace(index)
                index = skip_whitespace(index + 1)
                value_start = index
                if key == "integrity" and text[value_start] == '"':
                    value, index = decoder.raw_decode(text, value_start)
                    if type(value) is str and SHA512_SRI_PATTERN.fullmatch(value):
                        spans.append((value_start, index))
                else:
                    index = parse_value(value_start)
                index = skip_whitespace(index)
                if text[index] == "}":
                    return index + 1
                index = skip_whitespace(index + 1)
        if text[index] == "[":
            index = skip_whitespace(index + 1)
            if text[index] == "]":
                return index + 1
            while True:
                index = parse_value(index)
                index = skip_whitespace(index)
                if text[index] == "]":
                    return index + 1
                index = skip_whitespace(index + 1)
        _, index = decoder.raw_decode(text, index)
        return index

    spans = []
    try:
        parse_value(0)
    except (IndexError, ValueError, RecursionError):
        return ()
    return tuple(spans)


def _plan_scan_text(text, relative_path):
    if relative_path not in SYNTHETIC_NPM_LOCK_PATHS:
        return text
    spans = _valid_sha512_integrity_spans(text)
    if not spans:
        return text
    characters = list(text)
    for start, end in spans:
        characters[start:end] = " " * (end - start)
    return "".join(characters)


def inspect_text(text, pool, relative_path=None):
    lowered = text.lower()
    hash_lines = [line for line in text.splitlines() if "\x23" in line]
    rust_test_attributes = (
        bool(hash_lines) and relative_path in PINNED_RUST_TEST_ATTRIBUTE_FILES
        and all(line.strip() in _RUST_TEST_ATTRIBUTES for line in hash_lines)
    )
    action_version_comments = bool(hash_lines) and all(
        ACTION_VERSION_COMMENT_PATTERN.fullmatch(line) for line in hash_lines
    )
    cargo_vet_store_header = (
        relative_path in PINNED_CARGO_VET_STORE_HEADERS
        and hash_lines == [PINNED_CARGO_VET_STORE_HEADERS[relative_path]]
        and (
            text == "\n" + PINNED_CARGO_VET_STORE_HEADERS[relative_path] + "\n"
            if relative_path.endswith("/imports.lock")
            else text.startswith("\n" + PINNED_CARGO_VET_STORE_HEADERS[relative_path] + "\n\n")
        )
    )
    if hash_lines and not (rust_test_attributes or action_version_comments or cargo_vet_store_header):
        raise PublicTreeError("comment-present")
    if PLAN_ID_PATTERN.search(_plan_scan_text(text, relative_path)):
        raise PublicTreeError("plan-id-present")
    if PRIVATE_PATH_PATTERN.search(text):
        raise PublicTreeError("absolute-path-present")
    if WINDOWS_PRIVATE_PATH_PATTERN.search(text):
        raise PublicTreeError("absolute-path-present")
    if WINDOWS_UNC_PRIVATE_PATH_PATTERN.search(text):
        raise PublicTreeError("absolute-path-present")
    repository_urls = set(REPOSITORY_URL_PATTERN.findall(text))
    dependency_checks_repository_exception = (
        relative_path == PINNED_DEPENDENCY_CHECKS_PATH
        and repository_urls == PINNED_DEPENDENCY_CHECKS_REPOSITORIES
    )
    fixture_registry_exception = (
        relative_path in (PINNED_CARGO_FIXTURE_LOCKS | PINNED_CARGO_REGISTRY_READERS
                          | PINNED_CARGO_REGISTRY_FIXTURES)
        and repository_urls == {PINNED_CARGO_FIXTURE_REGISTRY}
    )
    rust_tooling_exception = (
        pool == "platform" and relative_path == PINNED_RUST_TOOLING_PATH
        and set(RUST_TOOLING_URL_PATTERN.findall(text)) == PINNED_RUST_TOOLING_URLS
    )
    if repository_urls and not (
        dependency_checks_repository_exception or fixture_registry_exception or rust_tooling_exception
    ):
        raise PublicTreeError("repository-url-present")
    allowed_prefixes = ("keeldock" + "-" + pool, PUBLIC_REPOSITORY_PREFIX)
    without_public_names = lowered
    for public_prefix in allowed_prefixes:
        without_public_names = without_public_names.replace(public_prefix, "")
    if PRIVATE_REPOSITORY_PREFIX in without_public_names:
        raise PublicTreeError("private-name-present")
    if any(marker.lower() in lowered for marker in PRIVATE_PATH_MARKERS):
        raise PublicTreeError("private-path-present")


def _expected_directories(files):
    result = set()
    for name in files:
        parent = Path(name).parent
        while str(parent) != ".":
            result.add(parent.as_posix())
            parent = parent.parent
    return result


def scan_tree(root, pool):
    if type(pool) is not str or pool not in ALLOWED_FILES:
        raise PublicTreeError("pool-unknown")
    root = Path(root)
    if not root.is_dir():
        raise PublicTreeError("tree-unavailable")
    actual_files = set()
    actual_directories = set()
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        relative_current = current_path.relative_to(root)
        if relative_current.parts and relative_current.parts[0] == ".git":
            directories[:] = []
            continue
        retained = []
        for directory in directories:
            item = current_path / directory
            if item.is_symlink():
                raise PublicTreeError("symlink-present")
            if directory == ".git" and relative_current == Path("."):
                continue
            retained.append(directory)
            actual_directories.add((relative_current / directory).as_posix())
        directories[:] = retained
        for filename in files:
            item = current_path / filename
            relative = item.relative_to(root).as_posix()
            if relative == ".git" and item.is_file() and not item.is_symlink():
                continue
            if relative.startswith(".git/"):
                continue
            if item.is_symlink() or not item.is_file():
                raise PublicTreeError("non-regular-file")
            actual_files.add(relative)
    expected_files = ALLOWED_FILES[pool]
    if actual_files != expected_files or actual_directories != _expected_directories(expected_files):
        raise PublicTreeError("tree-shape")
    for relative in sorted(actual_files):
        item = root / relative
        try:
            with item.open("rb") as source:
                payload = source.read(MAX_FILE_BYTES + 1)
        except OSError:
            raise PublicTreeError("file-unreadable")
        if len(payload) > MAX_FILE_BYTES:
            raise PublicTreeError("file-too-large")
        expected_hash = PINNED_FILE_SHA256.get((pool, relative), PINNED_FILE_SHA256.get(relative))
        if relative in BINARY_FIXTURE_FILES:
            if expected_hash is None or _pinned_file_hash(relative, payload) != expected_hash:
                raise PublicTreeError("file-hash-mismatch")
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            raise PublicTreeError("file-not-utf8")
        if expected_hash is not None and _pinned_file_hash(relative, payload) != expected_hash:
            raise PublicTreeError("file-hash-mismatch")
        inspect_text(text, pool, relative)
    return tuple(sorted(actual_files))
