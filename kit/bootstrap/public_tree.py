import hashlib
import json
import os
import re
from pathlib import Path


PLATFORM_FILES = frozenset(
    (
        ".github/workflows/public-policy.yml",
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
    '.github/workflows/core-dependency-checks.yml': '745055a2b3aa8b5b5203454873c6aa0546f0b9725d816c9c8008643b9f9d7682',
    'docs/branch-promotion.md': 'ef942bc4182f46b752cee063571e49b4d294f347c48a72387e34939818178e54',
    '.github/workflows/linux-source-admission.yml': '1947aa8af6730b30342b2e5d9a0a298aca32f2c30ec282e25ced1cf8cb6a7ffd',
    'kit/bootstrap/action.yml': 'cef91cc35242c2b3d07ddce5b754cdc89b6c83f4187f942afe39cd3140df837f',
    'kit/bootstrap/public_tree.py': '379762d25bff44f1208eed71bb8782656d1744c97701536fba52b38cf44a970e',
    'kit/confinement/release_tool_ledger.py': 'e9a4f50f806fad3d5ae7c7323adfc3024eaaa1f564a8725e9ef7281fa01c6657',
    'kit/confinement/release_tool_ledger.json': '2c0004d1e83780d780c501b794a15e6c6928f8aa352dcfab46fe389fe871dc0b',
    'kit/confinement/test_release_tool_ledger.py': '20ef9cfb0f4a64c73e34443c3d726be599c34ac6145df875d1abe8a427de8a4e',
    'kit/confinement/native_loopback_profile.py': '5dee8e3f29e1d9178099eeefdec9f7520efe3939ab9b8cae71406b8da48a4ab7',
    'kit/confinement/test_native_loopback_profile.py': 'acbc69ae710ac56931429fdc881a853ceadfaf63327a62aace5e6f1d76e8683d',
    'kit/confinement/linux_harness.py': 'b58046a859edecefa69799a0eae484da1ffbab3011447d0bc9322fbbe258c8ef',
    'kit/confinement/macos_deny_default.py': 'ff99d93537c4f57d052e87760285537e0b4328685a50746bb9de0191f777243c',
    'kit/confinement/test_feedback_failure.py': '6976d7d22c1b65483e587f5b65a524e18fa8f667c9acda76b6fc17c70600288b',
    'kit/confinement/feedback_failure.py': '464742193a5199f359c13ffa6dd90eea37df3a944b113d02157068f984713ca9',
    '.github/workflows/development-feedback-smoke.yml': '8f55731d8c013ba9741595e6fd7a4d0ce1c0cae0bff75c5ea40fa750ec4fca09',
    'kit/confinement/development_feedback.mjs': '4ce84c90229b5addd0456f8350850483c4241024f18ac6fa5bcd7d201f79ed45',
    'kit/confinement/test_development_feedback.mjs': '7c8aecaf3286ed578feeaf662426f86ddf85a50518eaa796433855b40b32c273',
    'kit/confinement/feedback_request.py': '78dba5d462ec4fa75fed71f53d52004f6002069f8ff6eafb1fb38e4d550f4ea4',
    'kit/confinement/test_feedback_request.py': 'bda86c433252e8d02b302da4705d22761b42cbf3520b69c05ce853fb38bfdd4a',
    'kit/confinement/feedback_smoke.mjs': 'c97d454d01565211fe6152324e2024d9ca1064eb8857a9c4c4829722b8ef2ef4',
    'kit/confinement/test_feedback_smoke.mjs': 'bfac55b9fc394fe61ee17f7a7f8bf2d82acf7096e6f45f1be33e4d3ef0b9bf49',
    'kit/confinement/feedback_smoke_audit.py': '07d20821048eb158559d79ee323ce8fb0754953137ab9bb5115e9b8cadb17653',
    'kit/confinement/test_feedback_smoke_audit.py': '30a7de9279e8af4a0d93018a16d2445d8c3ff5022523586adb6b1a4981c99fd8',
    '.github/workflows/node-lock-smoke.yml': '88dadcc38a04f1766bfe23b2264f9d9ec604c182a28be184917c9cb19ddfd511',
    'kit/confinement/node_lock_envelope.mjs': '0062366f9d6672211c87fc76702487a8d4d860f0ab9e7f1389a066cb063554ba',
    'kit/confinement/test_node_lock_envelope.mjs': '4bbe2c72a2cef7720ea5e50217bbaf3fb622cccbef2e07f208889d50c291319c',
    'kit/confinement/node_lock_inventory.mjs': '682f880a03edbd3c91b08dd4c581679cdb5d4ac70e93215044804c6152fc6f69',
    'kit/confinement/node_lock_manifest.mjs': 'edf77e688d5c1e18807fdbab2cbc50d4fbaf94f0630b6a6f483eb1723c3aeaae',
    'kit/confinement/test_node_lock_manifest.mjs': 'c4830b7d8db4b08d9fc4ea2371c71c36f1f1e9d2625caa154fa374af3e219c87',
    'kit/confinement/sbom_normalizer.py': '2fac64f1426b7f63c8a426719d4b9e0e6ea9d7e0cc190d8f913dbdb8fb961d3b',
    'kit/confinement/test_sbom_normalizer.py': '2d6e4026d3f317be2036d6e015f4b41fbdec855ac930f4b812f1097dd03451d6',
    'kit/confinement/node_lock_receipt.py': 'f5c14fcf7fb1e6f72793a1f96c4b889d5f6ab856c5f5392e6b0c744c0fed90a2',
    'kit/confinement/test_node_lock_receipt.py': '428d7a9a2d16eddd061df8e6939b538ba738ed8689b8bf1af9e282ce409a0bb7',
    '.github/workflows/macos-core-contract.yml': '38c33a1b30bc18378359910af0da73e493026e8105511062f96f6f80fafbe096',
    'kit/confinement/macos_core_contract.py': 'af3aec230452009799f80de2491b16b73e6609687399c8230bbdd8c8b88a2c9d',
    'kit/confinement/test_macos_core_contract.py': '912b587088bd3a83c2c57201994da53aa961e25dd4bdd7ca97ec506c6a297470',
    'kit/confinement/linux_source_build.py': '052210be0634aa61131baaed68dc948ca48718bcac82cde8c3c5c3e9af1b8043',
    'kit/confinement/test_linux_source_build.py': 'bb7537ee13686647e4b72d50e4f47ed6ddee8ec37345d5df04fcbd42d951f952',
    'kit/confinement/linux_boundary.py': '73adda7947d6add804d4f2b5b8117543d465830bfce72e7e1b4de22601c48394',
    'kit/confinement/test_linux_boundary.py': 'bead2ac12c4e5a9eef40a76c0256523e6fa69c778bb732548e2a2e17794c9c5f',
    'kit/confinement/linux_session.py': 'f71809d23fb576ab46b51882a9a4867856066dbcee2b132a10662acf42c5571b',
    'kit/confinement/test_linux_session.py': '3635631f62f06b354f081566670f4d83ced7a9eecd0394efd8d80f84f1863fa7',
    'kit/confinement/linux_channels.py': 'dedc4f256440924c83e15be8201a998df9485fa6180f32126a5d5fe320837c5b',
    'kit/confinement/test_linux_channels.py': 'bddad18cd3fbc9ad9290004d56c08976dfd7e309e5cc32e30483d1aa15fa5adc',
    'kit/bootstrap/policy_linux.py': '7288b080d68e56d98b8e01407c59149eb80864b4c66ec9d5763959b6f05d8668',
    'kit/bootstrap/test_policy_linux.py': 'd81469394360b4e7ef63fae1813e9fe49e31ded6406d5782df04acfd281728ba',
    'kit/confinement/test_linux_source_build_tiers.py': 'a14ac0ebc3be6eeb9aba172ff1099a7cc37b010ae6eeaaa762056bc1001bc32a',
    '.github/workflows/core-linux-quick-return.yml': 'ecfcff18ffbb03fbbe058132590a675ddd2407b92ae2be1a2d4bfeeb95674298',
    'core-ci/linux_quick_return.py': 'b711e81a2779d891cbba6d11becfe07d730331acc71c7ed2a9841f41439b5fd8',
    'core-ci/test_linux_quick_return.py': 'f6653e9db604a7a3a2213c285ab30567f8c39d46632b1650e4a15c4d8ee8b634',
    'kit/confinement/fixtures/npm11_audit_report.json': 'fa181d1de0aff938377cd7ffb1217a1f620599b6e0808ae75a7da3c97bbe4baa',
    'core-ci/test_separation.py': 'e7ff85c8f45a7ecd03f98f72c4123018a5d39847fcb49442fbdf7f9225d9cb3b',
    'kit/promotion/branch_promotion.py': '617182493670a9c3e2be96aed6cbefc5d143d2f0bb4afb65d858abd3527671ea',
    'kit/promotion/test_branch_promotion.py': 'a5e5412574fc5ea23fb069215f0c2ca99fef1e7715ebd5c55e93998ed313885d',
    'kit/confinement/cargo_lock_parser.py': '0acae8f9ed3c29f8990ab85dcabb286fb826ca27b5cdf9e32ad6925979cc7322',
    'kit/confinement/test_cargo_lock_parser.py': '92801b5e56abc7e9388caf16c46f6e5e7852720e2355335177974382131bc49d',
    '.github/workflows/macos-rust-toolchain-smoke.yml': 'cdf7068f8887c22958d74f3c2cc0a73c5c8c4c41f4eff0b43e16e47f61e58bb7',
    'kit/confinement/macos_rust_toolchain.py': '7a6f5d95942be39f646c514f1b5f209c0089c3f767a5c2eed69a503371abd305',
    'kit/confinement/test_macos_rust_toolchain.py': '81c625bb61c2b8689e1e5420f60e930450d8395a5d2de5d37e4e9de15d94b0b6',
    '.github/workflows/macos-rules-bootstrap.yml': 'f56e0c0eb86493c320a72048201d4bfae6bedbec46ee85a8b027674d5cd62d3a',
    '.github/workflows/macos-core-bootstrap.yml': 'b140312f22310633089594255fb17d25aeece02869355e608408098c4e91a4eb',
    'kit/confinement/macos_rules_bootstrap.py': '05345e0899b883bda0154d5ac79b68e027b28b32df0cbabb1124a9a6da9a29dc',
    'kit/confinement/test_macos_rules_bootstrap.py': 'f1bf5de1635a0e06d6ac0c25b21675005d8ea4d813354747202a522deeb213c9',
    'kit/confinement/macos_core_bootstrap.py': 'e7850a53709609dc6ce2ea0c817454694f95f7cd913c44da102b1448321ef4ac',
    'kit/confinement/test_macos_core_bootstrap.py': '69ab67960a31e4a298c8136f7492b7c5c84ea80b855fd5c2be0726d1125f7115',
    'kit/confinement/macos_network_observer.py': 'a7cf6cb16e68f00513e9f8ee08d52511619b18bb8edd37205faf907dcf0a98d9',
    'kit/confinement/test_macos_network_observer.py': '0187ffbe5a7b7395b2edc2025a4dd3e4c0adf5a48c881f8878578010d76307a3',
    'kit/confinement/macos_private_validation.py': 'c8ae1c308ba25ac18fe8f7d01793013300575d6feadb04516ae4f58ac67a3c5d',
    'kit/confinement/test_macos_private_validation.py': '178b5f479db66b879e5b9c323fa2c03ead2bf0124e0dbd94d9014b443f223746',
    'kit/confinement/test_macos_wave70.py': 'c3c1aa78b476e703247333f8898fae1727d6d186d41310a620a44f22ec508e4d',
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
    'kit/confinement/test_windows_confinement.py': '7fe1a7e3ccdcfa9e3fd12608368b180c6442b14f24b690f69866b443a22d5faa',
    'kit/confinement/windows_source_run.ps1': '2b37591c61db5394dce725e15546df0dff466d3f2d28d529aa91e2329ee50eb6',
    'kit/confinement/test_windows_source_run.py': '4bdae301112ed6cbcd8d18f3b7d7faa808582cbc387fd9bc14003ba71eb128a9',
    'kit/confinement/windows_probe.rs': 'cf9e58d8f31e2a9773f2c4eba935fd1ed531d94397ac53e530a93c5169d08727',
    'kit/confinement/windows_npm_link_shim.cjs': '668148b9f106454b05aacd6274b9f6c07590f3ed0e532fdc9639696dc287855a',
    'kit/confinement/macos_source_reader.py': 'd3fbda5c68ac7d21761e946b0f546607b19c23ccb725e453f3fffef3321c0d70',
    'kit/confinement/test_macos_source_reader.py': 'ed8e9b850f7d3a80346ad4a6efc182b28ff9c22fa669eda241f2c5feb3ccf806',
    '.github/workflows/core-rust-format-return.yml': 'c56fc9e8199681d2dab689f7f09a9fbb57825549c0f6132c27a7016ce72c79ab',
    '.github/workflows/core-build-diagnostic-return.yml': 'd75840b7a8b8541a1f1a083a35c5b54255d3ce8e5242c6e7e8bd1eb06bbd13ad',
    '.github/workflows/windows-source-admission.yml': 'ef10b21b69f841f6c2b69bc22497400e89e959fdfd6e24740a24e4b00139b5a8',
    '.github/workflows/lane-h-windows-receiver.yml': 'a6033b3c5dd1748bd4e55fa0dc4da82e40cd3ccfeee6b0fcc3ba3f88e165bde3',
    '.github/workflows/lane-h-linux-fetch-encrypt.yml': 'c173b2298dca7757b37a67669ad6ae4abf6eaf32cf1dea94b8b0a17a1c50d423',
    '.github/workflows/lane-h-capsule-attester.yml': '192d78328f8bf093a68bef0f1dd323a88772e2929d79c92b24a8864d17c1b48c',
    'kit/confinement/macos_feedback_producer.py': '957573a464bcaa8229d02833102f4ddbceae51e70c8b7e514ca21f3afeaaf361',
    'kit/confinement/test_macos_feedback_producer.py': 'e6c245cdec2736cb4c12e06038effb3adddf9ad008f2ec4d651c65a76e626da4',
    'kit/confinement/feedback_producer_crypto.mjs': 'd3dda950df99c3e3d925136a61c3e765bd19823f786ae0813ced2c9261cc08b7',
    'kit/confinement/test_feedback_producer_crypto.mjs': 'fce674b341e6e8d1237350591719efb1fb39b054ac0174121ad3fa92c95dfac2',
    'kit/confinement/feedback_admin.py': 'e85f29bd3efec5702c42c182d36538f8ffe0ea922224b69877e2b429957c1431',
    'kit/confinement/test_feedback_admin.py': '56d3c7dbd6836e3b44c926dbcb1dd30f61a50a72aeb36d2cb1a2933990c72897',
    'kit/confinement/feedback_admin_crypto.mjs': '169b8e70d59694162760315e50e140507d8e1f8eed29ac6a1efbb0026bbe029b',
    'kit/confinement/test_feedback_admin_crypto.mjs': '35e7109afd8b43eda8541a9c6af9bdc375a19d35ce6932438506fa97f76a0931',
    'kit/confinement/test_feedback_admin_integration.py': '5cd59a4833de05dea5826699e807baac871d0398cdc8c590f1f89c829720b5dd',
    'kit/confinement/test_macos_feedback_output_limits.py': 'b9bdf52adb9504a0bb57ad79553a71f907cd636b53f386a3c8776304b6dbb0ca',
    'kit/confinement/feedback_api.py': 'c2ee2f073493dc07a4801cd75f10554c63b17183523308693177984529b1ca65',
    'kit/confinement/test_feedback_api.py': '2be1551d5ff5aee195db6d5726ce514b401172669cfa42361a43921573eb7181',
    'kit/confinement/feedback_public_audit.py': '888cd166a65b59ab1080419852f49c598a082067a71bb284fd12161484248cea',
    'kit/confinement/test_feedback_public_audit.py': 'c7c3c94c9c85646ea3af2f7035f95da93b5fdaf1afedfe9de89e65f768f73691',
    'kit/confinement/release_provenance.py': '6e9dbe1264623f68d95d01fe4b73c5c3e4d736a784c49c31fe0dea1b0fff8717',
    'kit/confinement/test_confinement_release_provenance.py': '1e630a123396e28e23063842575f780a3a9aaaaf44a3264f431ccdcd4d68c6fa',
    'kit/confinement/role_signer.py': 'd99af1913617fe0d9e24577b5bafa3c9ab9f52cfe50d19aa1e7deef64afd0460',
    'kit/confinement/gate_table.py': '79f31334148550050f4f3ffb51cf0326d88cb10b6f120e73baa567e0b17c04dd',
    'kit/confinement/test_confinement_gate_table.py': '438aa7792edefdfc58338c30b5cf53fb2579e63995db4ab58aaf514079297440',
    'kit/handoff/source_capsule.py': 'a1369abb354f0723bd3cfc3209aa15c4769bfb113b2fe6369023c7f95e4546ac',
    'kit/handoff/test_source_capsule.py': '6ea11945a8e08040b78faa4d4861abdd600901ed048abe22a2edfc3b97bfcd57',
    'kit/handoff/provider_requirements.txt': 'c812f3c3f036921e86568feaa3bc934040b68f3d743072cefce8ea758bd56150',
    'kit/confinement/test_role_signer.py': '31cd7cc4189aeba885da2870c04292423cd72032746d6351ef6ef480f182cc6e',
    'kit/bootstrap/policy_handoff.py': '638e808e95c5c6bc2d6c02f3ed78a0b078e97b14b9fbb5bfdc475a360ec30fe1',
    'kit/bootstrap/test_policy_handoff.py': '089bc886795bbebf8b515a667853f4e63dc13d053d7811161f4ad9785f3accc7',
    'kit/confinement/confinement_public_audit.py': '2c153a935786b5f1d40c7aca689fa3447a8b6bd34dc0a31244799b9b721f7a94',
    'kit/confinement/macos_public_audit.py': '8dd215b1484a01e9c6c6f2a4578e15181eef7195cb6186382ab966291a30bb33',
    'kit/confinement/release_build_verify.py': 'ad9b18d2faaa6e7f408ea854f8483d9d97ebca0a7a2711e57d521203a882d91e',
    'kit/confinement/test_release_build_verify.py': '08c8b7dcb28307d8470cab9675202bcc206492261d20dec70064232c197f2579',
    'kit/bootstrap/test_public_tree.py': 'e724070e9d2fe3a05bdb4a05726043ca98be0d5e9a9c0975e7011e18918a4f8a',
    'kit/confinement/release_evidence.py': '2609b125bf2d3cbde256e2e4229c576fc0de1c5da898faf206807205dee49ae2',
    'kit/confinement/test_confinement_cargo_lock_bootstrap.py': '2cb6f8a133516d647b54c1ae4fbcca52fceaa1793f805b9395e90faa947d066f',
    'kit/confinement/cargo_lock_bootstrap.py': '04e97a7c0b7de07fda93ff208e385d74ef5a12cf73a1439ee16090883934fad8',
    'kit/bootstrap/test_policy_rust.py': '2465451eb33dec7787807d27ae9ef574b7447a52953c2c3f1951003243b6294a',
    'kit/bootstrap/policy_rust.py': '4306a55701a5a04c884b2b21091a6d06307134e3570f0d5d65cb103ff84023ec',
    'kit/bootstrap/policy_npm.py': 'b110b4573b2919003792e05bdcec60a0108f9e2ea1ebc1ce820ff77216271794',
    'kit/bootstrap/test_policy_npm.py': '8893c4a89ab447a8813806afd2b35bbedbc78d530f1c5a1c8bdf67fc55865eed',
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
    '.github/workflows/ci-future-stages.yml': '16f7140d456f057a4681f871d9eb90e185133cb738c6aaf974cd07f633396815',
    '.github/workflows/appium-ci.yml': '961eaa4fc03e0fe687fa437673116e68479af9437dcb69173444ec57098db2d3',
    '.github/workflows/performance-shadow.yml': '9a64b2eb8240c1806e669de1e7a1fa42a3631d9988a205482872d3af68cc9d46',
    'kit/selector/suite_selector.py': '6c9a497566179ae7169717d2d58b6ae9239ed6ff4573de493b8cad55cab8a4fa',
    'kit/selector/test_suite_selector.py': '7c1a4caedcd7fbdcc9b3d08092e3af7ce67ae1409f0d86e3a0421c11e8878a29',
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
PINNED_DEPENDENCY_CHECKS_REPOSITORIES = frozenset((
    "https:" + "//github.com/" + "EmbarkStudios/cargo-deny",
    "https:" + "//github.com/" + "RustSec/rustsec",
    "https:" + "//github.com/" + "mozilla/cargo-vet",
))
PINNED_CARGO_FIXTURE_REGISTRY = "https:" + "//github.com/" + "rust-lang/crates.io-index"
PINNED_CARGO_FIXTURE_LOCKS = frozenset((
    "kit/confinement/fixtures/cargo-deny/issue-910-cycle/Cargo.lock",
    "kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-affected/Cargo.lock",
    "kit/confinement/fixtures/cargo-deny/rustsec-2020-0071-patched/Cargo.lock",
))
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
    dependency_checks_repository_exception = (
        relative_path == PINNED_DEPENDENCY_CHECKS_PATH
        and repository_urls == PINNED_DEPENDENCY_CHECKS_REPOSITORIES
    )
    fixture_registry_exception = (
        relative_path in PINNED_CARGO_FIXTURE_LOCKS
        and repository_urls == {PINNED_CARGO_FIXTURE_REGISTRY}
    )
    if repository_urls and not (
        dependency_checks_repository_exception or fixture_registry_exception
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
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            raise PublicTreeError("file-not-utf8")
        expected_hash = PINNED_FILE_SHA256.get(relative)
        if expected_hash is not None and _pinned_file_hash(relative, payload) != expected_hash:
            raise PublicTreeError("file-hash-mismatch")
        inspect_text(text, pool, relative)
    return tuple(sorted(actual_files))
