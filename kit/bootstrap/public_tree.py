import hashlib
import json
import os
import re
from pathlib import Path


PLATFORM_FILES = frozenset(
    (
        ".github/workflows/public-policy.yml",
        '.github/workflows/node-lock-return.yml',
        '.github/workflows/core-rust-format-return.yml',
        '.github/workflows/core-build-diagnostic-return.yml',
        'kit/confinement/foundation_node_feedback.py',
        'kit/confinement/test_foundation_node_feedback.py',
        'kit/confinement/macos_node_contract.py',
        'kit/confinement/test_macos_node_contract.py',
        'kit/confinement/node_contract_validation.mjs',
        'kit/confinement/test_node_contract_validation.mjs',
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
        'kit/confinement/node_lock_envelope.mjs',
        'kit/confinement/test_node_lock_envelope.mjs',
        'kit/confinement/node_lock_inventory.mjs',
        'kit/confinement/node_lock_manifest.mjs',
        'kit/confinement/test_node_lock_manifest.mjs',
        'kit/confinement/node_lock_receipt.py',
        'kit/confinement/test_node_lock_receipt.py',
        'kit/confinement/cargo_lock_receipt.py',
        'kit/confinement/test_cargo_lock_receipt.py',
        'kit/confinement/cargo_rust_admission.py',
        'kit/confinement/test_cargo_rust_admission.py',
        'kit/confinement/cargo_deny_qualification.py',
        'kit/confinement/cargo_deny_qualification_reviewed.json',
        'kit/confinement/test_cargo_deny_qualification.py',
        'kit/confinement/cargo_archive_producer.py',
        'kit/confinement/test_cargo_archive_producer.py',
        'kit/confinement/cargo_deny_installer.py',
        'kit/confinement/test_cargo_deny_installer.py',
        'kit/confinement/cargo_deny_policy.toml',
        'kit/confinement/rust_license_checker.py',
        'kit/confinement/sbom_normalizer.py',
        'kit/confinement/test_sbom_normalizer.py',
        'kit/confinement/npm_admission.py',
        'kit/confinement/test_confinement_npm_admission.py',
        'kit/confinement/cargo_vendor_verify.py',
        'kit/confinement/test_cargo_vendor_verify.py',
        'kit/confinement/cargo_vendor_producer.py',
        'kit/confinement/test_cargo_vendor_producer.py',
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
        '.github/workflows/core-rust-lock-return.yml',
        'kit/bootstrap/policy_rust.py',
        'kit/bootstrap/test_policy_rust.py',
        'kit/confinement/cargo_lock_bootstrap.py',
        'kit/confinement/test_confinement_cargo_lock_bootstrap.py',
        '.github/workflows/core-npm-admission-return.yml',
        'kit/bootstrap/policy_npm.py',
        'kit/bootstrap/test_policy_npm.py',
        'kit/confinement/npm_admission_bootstrap.py',
        'kit/confinement/test_confinement_npm_admission_bootstrap.py',
        'kit/confinement/npm_semver.py',
        'kit/confinement/test_confinement_npm_semver.py',
        'kit/confinement/test_feedback_request_npm.py',
        'kit/confinement/test_macos_feedback_producer_npm.py',
        'kit/confinement/test_npm_admission_feedback.mjs',
        ".github/workflows/linux-confinement.yml",
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
        "ci/policy.json",
        "ci/api-budgets.json",
        "ci/revoked-signer-fingerprints",
        "kit/bootstrap/action.yml",
        "kit/bootstrap/api_budget.py",
        "kit/bootstrap/check_candidate.py",
        "kit/bootstrap/policy.py",
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
        "kit/confinement/rust_license_gate.py",
        "kit/confinement/test_rust_license_gate.py",
        "kit/confinement/cargo_deny_installer.py",
        "kit/confinement/test_cargo_deny_installer.py",
        "kit/confinement/cargo_deny_policy.toml",
        "kit/confinement/rust_license_checker.py",
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
SELF_PIN_PATH = "kit/bootstrap/public_tree.py"
SELF_PIN_LINE_PATTERN = re.compile(
    rb"(?m)^    'kit/bootstrap/public_tree\.py': '[0-9a-f]{64}',$"
)
PINNED_FILE_SHA256 = {
    '.github/workflows/linux-source-admission.yml': '3289ca0b02871ac345743f0727bd40f5cae0b10e90e4f9f9a984c2a389103046',
    'kit/bootstrap/action.yml': '6d0022330e8d8be3923937217227fdbe831fc2a0fab14c70a23550478dd487e3',
    'kit/bootstrap/public_tree.py': '3ee68ee14d2a70b12f255fcea6ec610ebde688d76e4fa8228f29a5006097d3f2',
    'kit/confinement/release_tool_ledger.py': 'e9a4f50f806fad3d5ae7c7323adfc3024eaaa1f564a8725e9ef7281fa01c6657',
    'kit/confinement/release_tool_ledger.json': '2c0004d1e83780d780c501b794a15e6c6928f8aa352dcfab46fe389fe871dc0b',
    'kit/confinement/test_release_tool_ledger.py': '20ef9cfb0f4a64c73e34443c3d726be599c34ac6145df875d1abe8a427de8a4e',
    'kit/confinement/foundation_node_feedback.py': 'c421937b6cf5daa7355a7e9b1eb250b4891e7e7c7e75e854f794be7a214eb111',
    'kit/confinement/test_foundation_node_feedback.py': '9dfeae330816568746ee807c3cb830b298a0edfaabbfc0a4058f9c1ba8bec549',
    'kit/confinement/native_loopback_profile.py': '5dee8e3f29e1d9178099eeefdec9f7520efe3939ab9b8cae71406b8da48a4ab7',
    'kit/confinement/test_native_loopback_profile.py': 'acbc69ae710ac56931429fdc881a853ceadfaf63327a62aace5e6f1d76e8683d',
    'kit/confinement/linux_harness.py': 'b58046a859edecefa69799a0eae484da1ffbab3011447d0bc9322fbbe258c8ef',
    'kit/confinement/macos_deny_default.py': 'ff99d93537c4f57d052e87760285537e0b4328685a50746bb9de0191f777243c',
    'kit/confinement/macos_node_contract.py': '14b3a27e98e63c6dd41f48beb09602365d484625a9d2d91af6aec8e81132e4bd',
    'kit/confinement/test_macos_node_contract.py': '367e3395030bf1fc8e122f1d07c05b461d561de240e11f67cd61fe1ec15287c7',
    'kit/confinement/node_contract_validation.mjs': '6fb6cc01625f7f6e9ec4cae9b1e6c6ec552a6378283342fe36702dda518af529',
    'kit/confinement/test_node_contract_validation.mjs': 'dbff413c3fc887d0532224a699d68331e5e609c734ba7643ce40c98912aea0bf',
    'kit/confinement/test_feedback_failure.py': '5cfb9f712e7c44943ca3113a16baa6f2bb0a06d9d4a629fe33b75c5039ec1a26',
    'kit/confinement/feedback_failure.py': '3886eb5d455626f2c95428b674b81aeb4d8a6534333aca29e768e5dd23ccec11',
    '.github/workflows/development-feedback-smoke.yml': '09e058574372baa40016327e8a0da12d130a262a8bd70baba3a38ed10acc3d7a',
    'kit/confinement/development_feedback.mjs': '5abfb74a5efb9099012a474d88b19e3a320c093a2b9c895af54622e9d6fd23a2',
    'kit/confinement/test_development_feedback.mjs': '77e6414f712ea7bd59bee39443c05f709f6950898c100805ee4aab649db830b7',
    'kit/confinement/feedback_request.py': '8075fd99d3be444fbc9b07dd5d2c4b2db7455bc0fb934726ce4c95d5b1b9b0d9',
    'kit/confinement/test_feedback_request.py': 'c4f95387db278fb1ee60bde3729b9195a124bbd61667af7f821bd559eed8c0c0',
    'kit/confinement/feedback_smoke.mjs': 'de814d03e2202d91312879b1a3ef1e280026d8d8dc53836f35c7f4d1bae59bf6',
    'kit/confinement/test_feedback_smoke.mjs': '2498a04a338a01b1e3f510ebd9b66eca970baa1acac7a78286ebcd5b391dbd0d',
    'kit/confinement/feedback_smoke_audit.py': '258e2d745b6fa40b57f45deee6445f80a1e89c25d29425bdda1a561e72da03a4',
    'kit/confinement/test_feedback_smoke_audit.py': 'cf89b9fba919d568d967c8e4c236b255581c4e0f8380c589c24be0ab4338e028',
    '.github/workflows/node-lock-smoke.yml': '56793792e10d9e824d6da55e13181b0bc877440568b1980bde6d3bb695e5a59b',
    'kit/confinement/node_lock_envelope.mjs': 'ff2da2a570fde170a7f91078a15d0821f1df5c651f4f9367592a25ddac94e9c6',
    'kit/confinement/test_node_lock_envelope.mjs': '3d37cdb6ed1362647460376c99bb8e379de323b055b4e976ef42215c1fcba4f5',
    'kit/confinement/node_lock_inventory.mjs': '682f880a03edbd3c91b08dd4c581679cdb5d4ac70e93215044804c6152fc6f69',
    'kit/confinement/node_lock_manifest.mjs': 'c636d53b611f5cc7893b72021c2ec477f2922de4038d988f2870ab98c9bc54d5',
    'kit/confinement/test_node_lock_manifest.mjs': '108d3230c5cb597861ebd7d48126ad7c9fff733e2fc7642fbf5cba285b552c97',
    'kit/confinement/sbom_normalizer.py': 'd0f686536749239295f3c74f19e3052f7d3807de0f8984525da15d8822c27d3f',
    'kit/confinement/test_sbom_normalizer.py': '422fd582c58692b948d586870381ba7c3025d4b7cd6dc1ce49c3aab95ad10f89',
    'kit/confinement/node_lock_receipt.py': 'ade987d617a6cfe8a8b9f937ea6c17510a639a9ea671437625afeecd0c7e1a63',
    'kit/confinement/test_node_lock_receipt.py': '76163ace7dc4e239c16c993de84da44deaf402e42ba4fccb1a28fd8c28fae6b6',
    '.github/workflows/macos-core-contract.yml': '38c33a1b30bc18378359910af0da73e493026e8105511062f96f6f80fafbe096',
    'kit/confinement/macos_core_contract.py': 'a62a64d15707fa1b5b1b288e918d443c4e5f0636feffd4ed2340517a1882b902',
    'kit/confinement/test_macos_core_contract.py': '50d48ea43fe1ebf49675c1b5841892372b892cb5d59290f317cb4ee34850322b',
    'kit/confinement/linux_source_build.py': '0749ce612fb814203f9ddfa564bb9c8792034741079abf675ae33d6a87d8c7fd',
    'kit/confinement/test_linux_source_build.py': '750d42339f0e07e6416fc9c6e0790e3a0926bf0beaef8aca35be8edad43f370c',
    'kit/confinement/linux_boundary.py': '73adda7947d6add804d4f2b5b8117543d465830bfce72e7e1b4de22601c48394',
    'kit/confinement/test_linux_boundary.py': 'bead2ac12c4e5a9eef40a76c0256523e6fa69c778bb732548e2a2e17794c9c5f',
    'kit/confinement/linux_session.py': '7713f8719e1094c17fe899bef2edab6e34613275bd47f602ad523f70b772055f',
    'kit/confinement/test_linux_session.py': 'c7bfb1544264327e7a415ea54d75e273c176da94896106caecc0afda31389f9d',
    'kit/confinement/linux_channels.py': 'dedc4f256440924c83e15be8201a998df9485fa6180f32126a5d5fe320837c5b',
    'kit/confinement/test_linux_channels.py': 'bddad18cd3fbc9ad9290004d56c08976dfd7e309e5cc32e30483d1aa15fa5adc',
    'kit/confinement/npm_admission.py': '1235b29ff44ed1f92bdb60d5b1bbcf0367762dba5ba3101032b12c1114f631c9',
    'kit/confinement/test_confinement_npm_admission.py': '5cde9e51e9291049fceedec30efbf9d471a3eda65fcbe2d41e389246f02950ce',
    'kit/bootstrap/policy_linux.py': '55392bbbfd9ef4845611236d4fbf1e75f404ce9edc3146553539c24a69b453b0',
    'kit/bootstrap/test_policy_linux.py': 'd96e6b642c2f5971fd38773bd30a1ce70b10d572b5e71de4f3df7f681bef020c',
    'kit/confinement/test_linux_source_build_tiers.py': '655e6d48fb991c93a3243176b2f8dcbbb44198f05ad837ebe1a6a57e917665bc',
    '.github/workflows/core-linux-quick-return.yml': '7a8716975cb2e0f2810f0d2aaaa8263163a7659e528475dcdc648dbd1f2ee4f3',
    'core-ci/linux_quick_return.py': 'b711e81a2779d891cbba6d11becfe07d730331acc71c7ed2a9841f41439b5fd8',
    'core-ci/test_linux_quick_return.py': 'f6653e9db604a7a3a2213c285ab30567f8c39d46632b1650e4a15c4d8ee8b634',
    'kit/confinement/fixtures/npm11_audit_report.json': 'fa181d1de0aff938377cd7ffb1217a1f620599b6e0808ae75a7da3c97bbe4baa',
    'core-ci/test_separation.py': 'e7ff85c8f45a7ecd03f98f72c4123018a5d39847fcb49442fbdf7f9225d9cb3b',
    'kit/confinement/rust_license_gate.py': '0f68992c1f59cf4c586afb3d41ef9798d3a276c098b067167e485a287c4c887e',
    'kit/confinement/test_rust_license_gate.py': '2da661d83bbd2257541a3ab651c14732b630ef6a2d45fa60a05de96ee0cba930',
    'kit/confinement/cargo_lock_receipt.py': 'e4c1eb774f99c3fea380e8a5bb1ea8b775dbeccbd345bd9c9b7aec51ed823e1d',
    'kit/confinement/test_cargo_lock_receipt.py': '9352e8fb05121fcb32843c7df1b569bc936781b9160ac4bb7c9a0074451726af',
    '.github/workflows/macos-rust-toolchain-smoke.yml': 'cdf7068f8887c22958d74f3c2cc0a73c5c8c4c41f4eff0b43e16e47f61e58bb7',
    'kit/confinement/macos_rust_toolchain.py': '3e7720ee36e34f594c126217b918de69b09e7d827ea95f52242890c905c9a116',
    'kit/confinement/test_macos_rust_toolchain.py': '525f10b5f691eb26e78f05a4f2a86006b885ef265fec6bbd7938915798f0e03b',
    '.github/workflows/macos-rules-bootstrap.yml': 'a91387440f8caceadf8f19f7c87feb3d82377eb3c9e1813de48b518992d48807',
    '.github/workflows/macos-core-bootstrap.yml': '08cf50d62e18e52661befe3153294c2d188b8a980f914437dab7cbd899744b81',
    'kit/confinement/macos_rules_bootstrap.py': '84bd6dcbd184a63c64fda78151af1540e6a166fc8bde7194b43c8336b93b5fad',
    'kit/confinement/test_macos_rules_bootstrap.py': 'b242888ff3348337941441dd82c5f69a934cac2f5f3cb9d6b8a219fded6f8e24',
    'kit/confinement/macos_core_bootstrap.py': '0b03235d000b1504848d49215a2bed9c4dec5ee3dd47d26b4177c7fa44c16836',
    'kit/confinement/test_macos_core_bootstrap.py': 'f8e56bde25e64fc691adc25c3288924179797b83c8d6da66ef21c5fad256c38e',
    'kit/confinement/macos_network_observer.py': 'a7cf6cb16e68f00513e9f8ee08d52511619b18bb8edd37205faf907dcf0a98d9',
    'kit/confinement/test_macos_network_observer.py': '0187ffbe5a7b7395b2edc2025a4dd3e4c0adf5a48c881f8878578010d76307a3',
    'kit/confinement/macos_private_validation.py': 'ec25724d19acefa8a0e77d583e1c570fee6ddf3cf8f9499ae3f4b004aca2b381',
    'kit/confinement/test_macos_private_validation.py': 'e1ca9b78c9ae35964abc71e7eb885a530a42258c0858f07bb258ba4b494954fa',
    'kit/confinement/test_macos_wave70.py': '9300f3c2785a90f6c47c856ec1369ed635b926c1beebe99532b47f59a0609949',
    'ci/revoked-signer-fingerprints': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    '.github/workflows/capsule-vectors.yml': '7366acdb58988c5675e86268abe268e71f71bc16681ab560ba8e33f37fc9f9f7',
    'kit/confinement/capsule_frame.cs': 'b7de9b0af02e305d23e75ea58daf856a9e51d340b0ccee0920925930ffb1bc84',
    'kit/confinement/capsule_frame.ps1': '0fafd0ef16b277afaea9ec5301bc67b93fb4842e0f620c506e662956f080d51d',
    'kit/confinement/capsule_frame_vectors.json': 'fb0660998011eec479ee01e919510dcd8f88ae5266114d9f82a899b4fa72fb94',
    '.github/workflows/windows-native-preflight.yml': 'da294aadfc0e99cbe109aba90f9fb86df65867cd32d3325d26a9e9a5b035e5bb',
    'kit/confinement/windows_native_preflight.cs': 'ba0f8859db9d8bcc1e4c8274520bcb67a3292cb311f553127e1f29fe13838543',
    'kit/confinement/windows_native_preflight.ps1': '8dbaaaad105c2fe0439dedb1b7c9572b8e7ec74a8db29f8edcab91169b06c58b',
    'kit/confinement/test_windows_native_preflight.py': '07defbc65611505f9107e5cb9186f4e15bbb9616797ff07032b3f314480eea7d',
    'kit/confinement/windows_confinement.cs': 'd35721f5fcf4733e066fe481a2d692814e1cc5cf072c4daff5f64c40d3753cbe',
    'kit/confinement/windows_confinement.ps1': '1bd0b04dde27eaca58b2a7873345e3c1cacb4e988ff8b8980ebdda0bcf82f036',
    'kit/confinement/test_windows_confinement.py': '76765017107cadd28795f1ce867562a74792ce8b536b7e3949b85d3ea8c1bc53',
    'kit/confinement/windows_source_run.ps1': '5875d1ae42e323e5ebf9317791e8270d6eb6c335b079fdfd0ae53305f44a9ea9',
    'kit/confinement/test_windows_source_run.py': 'ce6885694e439894265bfdfcb2a59c09b33a7f20003536074be21ed71b088fdd',
    'kit/confinement/windows_probe.rs': 'cf9e58d8f31e2a9773f2c4eba935fd1ed531d94397ac53e530a93c5169d08727',
    'kit/confinement/windows_npm_link_shim.cjs': '668148b9f106454b05aacd6274b9f6c07590f3ed0e532fdc9639696dc287855a',
    'kit/confinement/macos_source_reader.py': 'd3fbda5c68ac7d21761e946b0f546607b19c23ccb725e453f3fffef3321c0d70',
    'kit/confinement/test_macos_source_reader.py': 'ed8e9b850f7d3a80346ad4a6efc182b28ff9c22fa669eda241f2c5feb3ccf806',
    '.github/workflows/node-lock-return.yml': 'd8ff50dbe107182819694d22238e4b7d7146d226c8e4e5f756b11ece228bd5e5',
    '.github/workflows/core-rust-format-return.yml': '2fc271cfb7e87e3175e3033eceeda9bedbc4bafca21eae4bd10f69d9f81d413c',
    '.github/workflows/core-build-diagnostic-return.yml': '22d44fd5c3e67319c3a1e99b83a4094e02534a5a2c8b683135e24123a95655c7',
    '.github/workflows/windows-source-admission.yml': '118975166728aed8ee2ecc79c48fb5171f94fe5d4413ff05defaa556892c8273',
    '.github/workflows/lane-h-windows-receiver.yml': '52c564f8b52db004f6e89202aff310a9d9b9b6f92e264814027a9e67f0edd772',
    '.github/workflows/lane-h-linux-fetch-encrypt.yml': 'a23f7cf71baba02cba9d20e49abb0536505930c40b3312d76a4e8fdf6b22f8b1',
    '.github/workflows/lane-h-capsule-attester.yml': '192d78328f8bf093a68bef0f1dd323a88772e2929d79c92b24a8864d17c1b48c',
    'kit/confinement/macos_feedback_producer.py': '424447471d6d6e3acd820d35e7311ab3395fada39f79e42be8c3ca70af9bd8ce',
    'kit/confinement/test_macos_feedback_producer.py': '012e2a5b03bfdadebe1ce5806e2be090e05447fcf8127f19b98990550d91f415',
    'kit/confinement/feedback_producer_crypto.mjs': 'dd023247587eba82cb631160516641658b88f1c4584c0471247048a8c87be3aa',
    'kit/confinement/test_feedback_producer_crypto.mjs': '2661534fe1d6d41661e6a056dc03c7800dc146d2d042584841a0799123e868e0',
    'kit/confinement/feedback_admin.py': 'd9f6d9ca2f6bcdeffd38f92e57b127025af5433cf1c3480df3c6e7a2c5edc692',
    'kit/confinement/test_feedback_admin.py': '6896a7dab1e4ca201285237406dce61206cec685c1125e485bd5d8bfcbc8bd2c',
    'kit/confinement/feedback_admin_crypto.mjs': '205bd0c24c7c57675b4fae124a0bf10ae61d44bf00d53735d92a5b5490095b7a',
    'kit/confinement/test_feedback_admin_crypto.mjs': 'd705361166a158b8bbf9495e3b3a55b3e355df3aab7351762f216f1e64f40659',
    'kit/confinement/test_feedback_admin_integration.py': 'a668a1d799fe7eb10fa174a4a5141e914724968196be055f6a3f7e6b67fc5ae8',
    'kit/confinement/test_macos_feedback_output_limits.py': 'd03c4e508b83c7a6ef7be7e9f402b2b3775d3878306fb1d010e27276625d9f99',
    'kit/confinement/feedback_api.py': 'efeeca428b14189e05dbeaeb4096234f7f80e5ca2af4890f69104e89d2a46c47',
    'kit/confinement/test_feedback_api.py': '31ebd1229ca1b1eb38c4ea7fca87323e505b73c20a27671cf640fb601fc5a7f3',
    'kit/confinement/feedback_public_audit.py': '48302d0d3b4a92b41fccf5958396132bf4758bf34dafba2624d616f84a48a6bb',
    'kit/confinement/test_feedback_public_audit.py': '25d3067bc5b1c85236436435c6e7cece563f0e28e14af1aae01e02cd696412c2',
    'kit/confinement/release_provenance.py': '6e9dbe1264623f68d95d01fe4b73c5c3e4d736a784c49c31fe0dea1b0fff8717',
    'kit/confinement/test_confinement_release_provenance.py': '1e630a123396e28e23063842575f780a3a9aaaaf44a3264f431ccdcd4d68c6fa',
    'kit/confinement/role_signer.py': '9bfe545fc9286e46258a3d3b72afdea1ccc1be64677f6dfc06dd536c2463b319',
    'kit/confinement/gate_table.py': '79f31334148550050f4f3ffb51cf0326d88cb10b6f120e73baa567e0b17c04dd',
    'kit/confinement/test_confinement_gate_table.py': '1e2926d680603d3bf167183a8cf263e55de3aee1a26c9376c01fe0f50439a309',
    'kit/handoff/source_capsule.py': 'a1369abb354f0723bd3cfc3209aa15c4769bfb113b2fe6369023c7f95e4546ac',
    'kit/handoff/test_source_capsule.py': '6ea11945a8e08040b78faa4d4861abdd600901ed048abe22a2edfc3b97bfcd57',
    'kit/handoff/provider_requirements.txt': 'c812f3c3f036921e86568feaa3bc934040b68f3d743072cefce8ea758bd56150',
    'kit/confinement/test_role_signer.py': '31cd7cc4189aeba885da2870c04292423cd72032746d6351ef6ef480f182cc6e',
    'kit/bootstrap/policy_handoff.py': '5eda9a596929dc6066147d904a9640504475445c8397700d7d052dde7afe6813',
    'kit/bootstrap/test_policy_handoff.py': '2bea84bccc3dba7e42b485d4d4f70ff3715513e968603f4631957680d926cf56',
    'kit/confinement/confinement_public_audit.py': '9ad9e5d5425f8d83fa8e61c2a71afd62fea0171342cf7a0d495a6e6d02d31808',
    'kit/confinement/macos_public_audit.py': 'd874c153f17abe085617bc6c783b99af45faec6d94c4a7e631337bc5925ab751',
    'kit/confinement/release_build_verify.py': 'ad9b18d2faaa6e7f408ea854f8483d9d97ebca0a7a2711e57d521203a882d91e',
    'kit/confinement/test_release_build_verify.py': '08c8b7dcb28307d8470cab9675202bcc206492261d20dec70064232c197f2579',
    'kit/confinement/cargo_vendor_verify.py': '84edfe12b2184d41dc5fc9b039274f2dae530b66bcf4f22bf221df22f9abf2b4',
    'kit/confinement/test_cargo_vendor_verify.py': 'e556686c9c2da4501a62a22eeadb7e1bb4302b87426f8e142f9393083f6c6065',
    'kit/confinement/cargo_archive_producer.py': 'df1d21026043d3bd536b04905013aa6fdb309c672df521aecd0f6150dcb6ab01',
    'kit/confinement/test_cargo_archive_producer.py': '2e500a15ff95228d376d128d32074ded502cbdc314d9e2698f45db755449f85b',
    'kit/confinement/cargo_deny_installer.py': '4350f1fb5f2d0b4469871c452aa8965484a26a2249cdc6f051f6cb6549d69510',
    'kit/confinement/test_cargo_deny_installer.py': '5065c4fae97dd1e0e6e963301a1d11210787f570f326f78db44a8dab56d2bd03',
    'kit/confinement/cargo_deny_policy.toml': '1c73e15eaa5605465b953c9907bfea22ab071583dd2fff67c25f14459387b810',
    'kit/confinement/rust_license_checker.py': '64df5b2a584948f20f455b25d01fae51ecbf8dabc913c13dc960c0455c13b33c',
    'kit/bootstrap/test_public_tree.py': '6d4ba5757f242410572509a4c73fdef1fdec4b281b6457bb4f6a450732fde67f',
    'kit/confinement/release_evidence.py': '2609b125bf2d3cbde256e2e4229c576fc0de1c5da898faf206807205dee49ae2',
    'kit/confinement/test_confinement_cargo_lock_bootstrap.py': '2cd1480ac823deefecb50b84004b602916fe1734bf52b65cfbc9f9eef50a516c',
    'kit/confinement/cargo_lock_bootstrap.py': '647ecf2bb504bc072dc77e954607555f99b2fed3d55628520fc5f0f49189dda6',
    'kit/bootstrap/test_policy_rust.py': '292adddc0b07b9fe8ceadc1cc1230534e0c6d8af5fdf46ff2b83dddf6b0c55b6',
    'kit/bootstrap/policy_rust.py': '97d3011957793d3ae7d86d961c360ec747b2716023d6fac62227b464f403b4a6',
    '.github/workflows/core-rust-lock-return.yml': '0bba35117fe56ba09f25022b674a3fee3d01aba935b0342ce9023cc87cb2aa88',
    '.github/workflows/core-npm-admission-return.yml': '279b4f0514ba2303a79ddbc9709ae60dd02a8292d78089da0edf7d2bfece0029',
    'kit/bootstrap/policy_npm.py': '7902d076d4726f525ce28d39e74d2f51014446c23d64a9b40e59df785ab7f9ba',
    'kit/bootstrap/test_policy_npm.py': '07265cd97faeb30380a17289be4c779fb8ee645f4d420aee361e8dc2f347d87e',
    'kit/confinement/npm_admission_bootstrap.py': '6d6cd3942d2e79e563a4a7f0ce3d00909d1281a986c01f6135424364012d8b85',
    'kit/confinement/test_confinement_npm_admission_bootstrap.py': '4e03171b75dcc2c7cda8f25075a10d73bccd1f065b41cf9b2747df4b7ca005e1',
    'kit/confinement/npm_semver.py': '0f6207724ea97a793d9c64175a5e9245f138e0fb4b057ab776c67d1722b1c26f',
    'kit/confinement/test_confinement_npm_semver.py': 'de0caa828a3af80166ee7cd1946276ef251504be8c967bc4b2cac046f8e65395',
    'kit/confinement/test_feedback_request_npm.py': 'b9c3207988600e4b718aa5e386617463a32ea6d3ec2e24cb5565aaa5eba57d2b',
    'kit/confinement/test_macos_feedback_producer_npm.py': '5a21a8f5c962b556e3d1041d32cddbaf6ff78b4dd6ccf5b7dabe90dbf67db277',
    'kit/confinement/test_npm_admission_feedback.mjs': '9747c72b866894b850ec8b7d00692bc96e50a5fb4be3beb66966dba1912225ef',
    'kit/confinement/test_release_evidence.py': '8157fdaf8f9a691d4bae699eec3b7eb07143cc8f0fef6bed7619ebf45da8c6f3',
    '.github/workflows/baselines-prepare.yml': '970eec0b3be196ab2c0e02f7652a06e186b9ab2f76df704daba53a935af0388d',
    'kit/baselines/baselines_prepare.py': 'b51af2756756c1fe2db08eaa8eb097df58b635bd6caef75f68da013a49e2a2f5',
    'kit/baselines/test_baselines_prepare.py': 'e32265ac4159db206af4e2c6516a370713ae060d32b52e30e6e854e476516a55',
    'kit/bootstrap/policy_baselines.py': '62878db53091a36a743d10e6e3355f7b9bb8227ae763337082608e9935edd8b8',
    'kit/bootstrap/test_policy_baselines.py': '3e9041e973239aaf75c57ada33356b94f422c9941747a45b13f608de65f939aa',
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
    'kit/confinement/synthetic_project/package-lock.json': '4091b20ce5719c9786da0b6f38223e5de7ce24b6d08b0269a6debe55b15b44fa',
    'kit/confinement/synthetic_project/package.json': '63847331195f7d981044d5187c727065f303aa116982261e0bb472238e306a69',
    'kit/confinement/synthetic_project/packages/host-api/package.json': 'b8cfe76d0423a82ace7b913d7608ff55eb3c1f7880cd831ec19140c9f44d2453',
    'kit/confinement/synthetic_project/packages/host-api/src/index.js': '93d2550086d545dbe2c53ef4e66d47e5e58e58c6232b830ad35fd47d2b50fac3',
    'kit/confinement/synthetic_project/packages/host-api/src/index.ts': '944f13e51b6f4882f5a6d32aba8646a31ec8cef4b94750dcd3da4f8ae7c9d39f',
    'kit/confinement/synthetic_project/packages/host-api/tests/run.js': '8b2a170f1c0cdd7787039cd8764f1c74534ed7818f352fe866b818efea3e9134',
    'kit/confinement/synthetic_project/packages/host-api/tests/no-net-use.mjs': 'b4bcd60e16bcf9399e314a0263e5167c25c7df0ddb574188fe5a71dc59f1f321',
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
    'kit/confinement/test_confinement_synthetic_project.py': 'cf274bb1a02670972e643384f23ff953801b5d2c184153c731ff40ddab3ab0f3',
    'kit/confinement/cargo_deny_qualification.py': '10145a679836a3a6ca10b0684e763cff23ddf8213391117569ba0f59dda2f019',
    'kit/confinement/cargo_deny_qualification_reviewed.json': '8c9885e6f5f47b79615595787b2254959e3324cc2f6898507801b659f4bbd76d',
    'kit/confinement/cargo_rust_admission.py': 'd70980409ea424ec2eb16eeec9d6721ea4670028f87f13c18af2816cfa9aaad1',
    'kit/confinement/cargo_vendor_producer.py': 'ad3679bb3daf046e71d3c092f5f9d28c51a187e4151d9d4f0ca2eccc3ec95606',
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
    'kit/confinement/test_cargo_deny_qualification.py': 'ffbde9bf6c249d4c98d6cd2b3b51e8f15686b3e1f9ec51fde9286aeb77d4ceab',
    'kit/confinement/test_cargo_rust_admission.py': '8e4cb424f2c85b64899df6e7c7d9b896406248718f24a772e1427bcdb0d1922f',
    'kit/confinement/test_cargo_vendor_producer.py': 'fc284d8163f1d9315ee012afc0fc5e52fc33d98ee4b281ddf4c79c7db04e51e2',
    '.github/workflows/ci-future-stages.yml': '16f7140d456f057a4681f871d9eb90e185133cb738c6aaf974cd07f633396815',
    '.github/workflows/appium-ci.yml': '961eaa4fc03e0fe687fa437673116e68479af9437dcb69173444ec57098db2d3',
    '.github/workflows/performance-shadow.yml': '9a64b2eb8240c1806e669de1e7a1fa42a3631d9988a205482872d3af68cc9d46',
    'kit/selector/suite_selector.py': '6c9a497566179ae7169717d2d58b6ae9239ed6ff4573de493b8cad55cab8a4fa',
    'kit/selector/test_suite_selector.py': '8a43471ff3900c59065a7552262f418c22c77ac1479c0550fb1e7b8c4c1f7cdc',
    'kit/ci/feature_states.py': 'e058de49cf9e96b61e8037ee533a095082f3210429586d4183d6c44c4f57d479',
    'kit/ci/test_feature_states.py': '9feb186807e3ec6a2571599be392eb58989304a0dd3ad1348e51961f56d91e4f',
    'kit/ci/future_stage.py': '11023901b556599b0f5f747b84ed540c45eae5a2d2ad65ea3a1ba95f81775d41',
    'kit/ci/test_future_stage.py': '4de0e9b619bbddc3cac5527c839a052adaf1b9444cd64deffa24204117b2504b',
    'kit/ci/future-stage-inventory.json': '185663fbc7c94b010dc4c74f7e6867898b5186a0d88acb95e61414f15cb695aa',
    'kit/ci/perf_shadow.py': '422584f8eea3e074f92ee4ba509d4a4fe29aa5d083f0e2ac240a9c4e70e39cc0',
    'kit/ci/test_perf_shadow.py': '6c76a2ace13bae1cefd0da2fffd8bbf4241f3ac4279735cdda0018431e398dc0',
    'kit/selector/ci19_catalogue.py': '7fe71cbf6307035d9351ab417951baeb12b39eb860a121077f55a1a70002df71',
    'kit/selector/fixtures/ci19_mcp_feature_owners.json': '69124b6f86729cac26478957d5430346dad9fedf4f98c8cb677536d66f5bf306',
}
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
PINNED_CARGO_DENY_POLICY_REPOSITORIES = frozenset((
    "https:" + "//github.com/" + "RustSec/advisory-db",
    "https:" + "//github.com/" + "rust-lang/crates.io-index",
))
PINNED_CARGO_FIXTURE_REGISTRY = "https:" + "//github.com/" + "rust-lang/crates.io-index"
PINNED_CARGO_FIXTURE_LOCKS = frozenset((
    "kit/confinement/fixtures/cargo-deny/issue-910-cycle/Cargo.lock",
    "kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/Cargo.lock",
    "kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/Cargo.lock",
))
PINNED_CARGO_DENY_POLICY_PATH = "kit/confinement/cargo_deny_policy.toml"
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
    if relative_path != SYNTHETIC_NPM_LOCK_PATH:
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
    if any(
        "\x23" in line and not ACTION_VERSION_COMMENT_PATTERN.fullmatch(line)
        for line in text.splitlines()
    ):
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
    policy_repository_exception = (
        relative_path == PINNED_CARGO_DENY_POLICY_PATH
        and repository_urls == PINNED_CARGO_DENY_POLICY_REPOSITORIES
    )
    fixture_registry_exception = (
        relative_path in PINNED_CARGO_FIXTURE_LOCKS
        and repository_urls == {PINNED_CARGO_FIXTURE_REGISTRY}
    )
    if repository_urls and not (policy_repository_exception or fixture_registry_exception):
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
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            raise PublicTreeError("file-not-utf8")
        expected_hash = PINNED_FILE_SHA256.get(relative)
        if expected_hash is not None and _pinned_file_hash(relative, payload) != expected_hash:
            raise PublicTreeError("file-hash-mismatch")
        inspect_text(text, pool, relative)
    return tuple(sorted(actual_files))
