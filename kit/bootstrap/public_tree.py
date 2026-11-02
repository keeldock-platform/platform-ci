import hashlib
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
        'kit/confinement/sbom_normalizer.py',
        'kit/confinement/test_sbom_normalizer.py',
        'kit/confinement/npm_admission.py',
        'kit/confinement/test_confinement_npm_admission.py',
        'kit/confinement/cargo_vendor_verify.py',
        'kit/confinement/test_cargo_vendor_verify.py',
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
        ".github/workflows/attestation-role-signer-probe.yml",
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
        ".github/workflows/core-linux-quick-return.yml",
        "core-ci/linux_quick_return.py",
        "core-ci/test_linux_quick_return.py",
        "core-ci/test_separation.py",
        "kit/confinement/rust_license_gate.py",
        "kit/confinement/test_rust_license_gate.py",
        "kit/confinement/native_loopback_profile.py",
        "kit/confinement/test_native_loopback_profile.py",
        "kit/confinement/windows_native_preflight.cs",
        "kit/confinement/windows_native_preflight.ps1",
        "kit/confinement/test_windows_native_preflight.py",
        ".github/workflows/windows-confinement.yml",
        "kit/confinement/windows_confinement.cs",
        "kit/confinement/windows_confinement.ps1",
        "kit/confinement/windows_probe.rs",
        "kit/confinement/test_windows_confinement.py",
        "kit/confinement/confinement_verdict.py",
        "kit/confinement/test_confinement_verdict.py",
        "kit/confinement/attestation_probe.py",
        "kit/confinement/test_attestation_probe.py",
        "kit/confinement/release_provenance.py",
        "kit/confinement/test_confinement_release_provenance.py",
        "kit/confinement/role_signer.py",
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
PINNED_FILE_SHA256 = {
    '.github/workflows/linux-source-admission.yml': '76ed0871d060b63ac0c01f00c3b7909b6e88c794d3ed7527ba18b2e5f07d0ceb',
    'kit/bootstrap/action.yml': '84ed228cc07a343d62e7d7e7188a2d916f7df9a1bd1594aaefe609f2aed9555f',
    'kit/confinement/release_tool_ledger.py': 'e9a4f50f806fad3d5ae7c7323adfc3024eaaa1f564a8725e9ef7281fa01c6657',
    'kit/confinement/release_tool_ledger.json': '2c0004d1e83780d780c501b794a15e6c6928f8aa352dcfab46fe389fe871dc0b',
    'kit/confinement/test_release_tool_ledger.py': '20ef9cfb0f4a64c73e34443c3d726be599c34ac6145df875d1abe8a427de8a4e',
    'kit/confinement/foundation_node_feedback.py': 'bb4959cf3422afe86eaf7e988f5264534c3e56d0f50862a95b76cb0e6903f371',
    'kit/confinement/test_foundation_node_feedback.py': '334db66129e1e8ab15847a68d85ebcf095295e8573b855805ea6523927fd1eef',
    'kit/confinement/native_loopback_profile.py': '5dee8e3f29e1d9178099eeefdec9f7520efe3939ab9b8cae71406b8da48a4ab7',
    'kit/confinement/test_native_loopback_profile.py': 'acbc69ae710ac56931429fdc881a853ceadfaf63327a62aace5e6f1d76e8683d',
    'kit/confinement/linux_harness.py': '066e461ad229d70cd2a270fc95ddcc29e60951da5c7ec5cfdd68e45c4445a8c0',
    'kit/confinement/macos_deny_default.py': 'ff99d93537c4f57d052e87760285537e0b4328685a50746bb9de0191f777243c',
    'kit/confinement/macos_node_contract.py': 'eda5137befeeadfc398c8383b83e35c6e4ddce21a8345e7307d7940fbd45fb87',
    'kit/confinement/test_macos_node_contract.py': 'e324f65bb1f138f7158c72d4f34240d0fda6f85b265b02fcfb2d752f29a564c1',
    'kit/confinement/node_contract_validation.mjs': '5d5c06ef75a7194858b707685b40ab39155f2f0ea0dde1633b286bc2709f5920',
    'kit/confinement/test_node_contract_validation.mjs': '21870604a820e8f10e4b68d33810687af248ae110f4295cd8aa406ca9a406d04',
    'kit/confinement/test_feedback_failure.py': '5cfb9f712e7c44943ca3113a16baa6f2bb0a06d9d4a629fe33b75c5039ec1a26',
    'kit/confinement/feedback_failure.py': '3886eb5d455626f2c95428b674b81aeb4d8a6534333aca29e768e5dd23ccec11',
    '.github/workflows/development-feedback-smoke.yml': '09e058574372baa40016327e8a0da12d130a262a8bd70baba3a38ed10acc3d7a',
    'kit/confinement/development_feedback.mjs': '1a44f0ba3a014f5759375c1c823d8b6dbdd69bb06b008952af5aed71bf6b7dfb',
    'kit/confinement/test_development_feedback.mjs': '77e6414f712ea7bd59bee39443c05f709f6950898c100805ee4aab649db830b7',
    'kit/confinement/feedback_request.py': 'f77d1ebf5b64e757fd25d882594a8dc8e051729dde915745205e51081f7235da',
    'kit/confinement/test_feedback_request.py': 'c4f95387db278fb1ee60bde3729b9195a124bbd61667af7f821bd559eed8c0c0',
    'kit/confinement/feedback_smoke.mjs': 'de814d03e2202d91312879b1a3ef1e280026d8d8dc53836f35c7f4d1bae59bf6',
    'kit/confinement/test_feedback_smoke.mjs': '2498a04a338a01b1e3f510ebd9b66eca970baa1acac7a78286ebcd5b391dbd0d',
    'kit/confinement/feedback_smoke_audit.py': '258e2d745b6fa40b57f45deee6445f80a1e89c25d29425bdda1a561e72da03a4',
    'kit/confinement/test_feedback_smoke_audit.py': 'cf89b9fba919d568d967c8e4c236b255581c4e0f8380c589c24be0ab4338e028',
    '.github/workflows/node-lock-smoke.yml': '56793792e10d9e824d6da55e13181b0bc877440568b1980bde6d3bb695e5a59b',
    'kit/confinement/node_lock_envelope.mjs': 'ff2da2a570fde170a7f91078a15d0821f1df5c651f4f9367592a25ddac94e9c6',
    'kit/confinement/test_node_lock_envelope.mjs': '3d37cdb6ed1362647460376c99bb8e379de323b055b4e976ef42215c1fcba4f5',
    'kit/confinement/node_lock_inventory.mjs': '682f880a03edbd3c91b08dd4c581679cdb5d4ac70e93215044804c6152fc6f69',
    'kit/confinement/node_lock_manifest.mjs': '5517cefa499b1730579ecd28ffeca31ca83da9a76002ec0ca93f9347f314485a',
    'kit/confinement/test_node_lock_manifest.mjs': '5dcd96e8411827bc1d1bd9ec2cf03b3db86776e3e090d92e6efcaf8adbab6d9c',
    'kit/confinement/sbom_normalizer.py': 'd0f686536749239295f3c74f19e3052f7d3807de0f8984525da15d8822c27d3f',
    'kit/confinement/test_sbom_normalizer.py': '422fd582c58692b948d586870381ba7c3025d4b7cd6dc1ce49c3aab95ad10f89',
    'kit/confinement/node_lock_receipt.py': 'ade987d617a6cfe8a8b9f937ea6c17510a639a9ea671437625afeecd0c7e1a63',
    'kit/confinement/test_node_lock_receipt.py': '76163ace7dc4e239c16c993de84da44deaf402e42ba4fccb1a28fd8c28fae6b6',
    '.github/workflows/macos-core-contract.yml': '38c33a1b30bc18378359910af0da73e493026e8105511062f96f6f80fafbe096',
    'kit/confinement/macos_core_contract.py': '025f1955fa43888b6a43bacf4186f6a8efab5e52e3ec1569355dd5e9614f25ac',
    'kit/confinement/test_macos_core_contract.py': '5b65c9958d6de802bfeec7ee750b90a75ed4165deb23b74177e1812fd459a927',
    'kit/confinement/linux_source_build.py': '42e378d80dd872603fe3866f09b29375c2246962095c8ef2ee8b0fedaee77e77',
    'kit/confinement/test_linux_source_build.py': '94e5dae6e7fca75b152221b63bf75f373781f067d3da38cee7742bd271db846f',
    '.github/workflows/core-linux-quick-return.yml': '430644005869bfc47b21e09ca2176754625feee1d11c04de26a3a46d1d74b27e',
    'core-ci/linux_quick_return.py': '1970de7f7c269b191b61a473e4c676b38e87bc8762d86395d27411a1f5bdaf2e',
    'core-ci/test_linux_quick_return.py': 'c19836d30f2f40a60fc7f73e263226e10900b186ac6f2478e3781f634537d772',
    'core-ci/test_separation.py': '70b801a95f267ba5c08b169fc67948f012e8f4d12a08f8121c5c2602622085a8',
    'kit/confinement/rust_license_gate.py': '64ca174535438700f01bc8b4890b6aa752352310e604dcfd55b12bfd20ffc18d',
    'kit/confinement/test_rust_license_gate.py': 'dd5b38878630c4fee418ca514087fd5d577833a2f94abaeb204c9dfed60bd6f8',
    'kit/confinement/cargo_lock_receipt.py': 'e4c1eb774f99c3fea380e8a5bb1ea8b775dbeccbd345bd9c9b7aec51ed823e1d',
    'kit/confinement/test_cargo_lock_receipt.py': 'eb6de33a5bf468f74577031a0592eeab96d7c531cbf95b0773e0e2e36c4b6432',
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
    'kit/confinement/macos_private_validation.py': '32978a9ab4c4d62cfbf40f90b7a35a2ec8b3c1fd14661af748c0d9a209378d9c',
    'kit/confinement/test_macos_private_validation.py': '94c6fc53e4df77dd49fb3fedb7538cdfa6d39975fc5aaf52a8690444b63e3c67',
    'ci/revoked-signer-fingerprints': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    '.github/workflows/capsule-vectors.yml': '7366acdb58988c5675e86268abe268e71f71bc16681ab560ba8e33f37fc9f9f7',
    'kit/confinement/capsule_frame.cs': 'b7de9b0af02e305d23e75ea58daf856a9e51d340b0ccee0920925930ffb1bc84',
    'kit/confinement/capsule_frame.ps1': 'dc889a1e2909a4dedb4733a26afa7f2650182ce82cf4d00931bfdab323320741',
    'kit/confinement/capsule_frame_vectors.json': 'fb0660998011eec479ee01e919510dcd8f88ae5266114d9f82a899b4fa72fb94',
    '.github/workflows/windows-native-preflight.yml': 'da294aadfc0e99cbe109aba90f9fb86df65867cd32d3325d26a9e9a5b035e5bb',
    'kit/confinement/windows_native_preflight.cs': 'ba0f8859db9d8bcc1e4c8274520bcb67a3292cb311f553127e1f29fe13838543',
    'kit/confinement/windows_native_preflight.ps1': '8dbaaaad105c2fe0439dedb1b7c9572b8e7ec74a8db29f8edcab91169b06c58b',
    'kit/confinement/test_windows_native_preflight.py': '07defbc65611505f9107e5cb9186f4e15bbb9616797ff07032b3f314480eea7d',
    'kit/confinement/windows_confinement.cs': 'ea47fcc64028362fae5c290ea4f914e02ac61b0d42f1614dc94f584c1f4e07df',
    'kit/confinement/windows_confinement.ps1': '6598c6a145ab88ad03779102059739c83a086c8ac495d732bbcda5aac8c57a74',
    'kit/confinement/test_windows_confinement.py': '60de4c6214af63d3be8b2f9b0163ef7219639b1edf53c8910b49765b43e31291',
    'kit/confinement/windows_probe.rs': '1a9a98ebc92e8b7681850ddb1ce80d63ebc56d07ad61320b2fedbaafa01fe9ff',
    'kit/confinement/macos_source_reader.py': 'd3fbda5c68ac7d21761e946b0f546607b19c23ccb725e453f3fffef3321c0d70',
    'kit/confinement/test_macos_source_reader.py': 'ed8e9b850f7d3a80346ad4a6efc182b28ff9c22fa669eda241f2c5feb3ccf806',
    '.github/workflows/node-lock-return.yml': 'd8ff50dbe107182819694d22238e4b7d7146d226c8e4e5f756b11ece228bd5e5',
    '.github/workflows/core-rust-format-return.yml': '2fc271cfb7e87e3175e3033eceeda9bedbc4bafca21eae4bd10f69d9f81d413c',
    '.github/workflows/core-build-diagnostic-return.yml': '22d44fd5c3e67319c3a1e99b83a4094e02534a5a2c8b683135e24123a95655c7',
    '.github/workflows/attestation-role-signer-probe.yml': 'ba5154846c0ae90fa3dad7caecf5a0a715336247aae67e4ed1b3c35d1aeac2e3',
    '.github/workflows/windows-source-admission.yml': '9783b15773e7ac970aaf83eabe0a6ac333fca31d258553f2066e8aab7e79ca3a',
    '.github/workflows/lane-h-windows-receiver.yml': '5347fcfdf29c979f7af8c63cee48f77b856fd7cc38d34ad675da75a0b806b448',
    '.github/workflows/lane-h-linux-fetch-encrypt.yml': 'fdd7355a0eabe45248fb497e49b5989645f5e2f31fd134fb6d80ac06cf52f0a7',
    '.github/workflows/lane-h-capsule-attester.yml': 'bdde526a962d01374e2655c8e8c83b786bc004555cb24f411f46eb1f6840a243',
    'kit/confinement/macos_feedback_producer.py': '87cc0f27d9a6af6834c0481baed54aeb223442bbd0373e9f4e7844a3e05f73bb',
    'kit/confinement/test_macos_feedback_producer.py': 'e81d4c4f4aec8ad5cd23b61cf14096f668332d30f790b76f7c8e16b6a0455dad',
    'kit/confinement/feedback_producer_crypto.mjs': 'dd023247587eba82cb631160516641658b88f1c4584c0471247048a8c87be3aa',
    'kit/confinement/test_feedback_producer_crypto.mjs': '2661534fe1d6d41661e6a056dc03c7800dc146d2d042584841a0799123e868e0',
    'kit/confinement/feedback_admin.py': 'fc9da9df3d67b4bf10736cf6240e0bad4b153f4a2a730b8f73a935d0a3b38182',
    'kit/confinement/test_feedback_admin.py': 'a6a17fb1089703f281d4eb7e01580676de43268cdc63364e570a0e48b89bd200',
    'kit/confinement/feedback_admin_crypto.mjs': '205bd0c24c7c57675b4fae124a0bf10ae61d44bf00d53735d92a5b5490095b7a',
    'kit/confinement/test_feedback_admin_crypto.mjs': 'd705361166a158b8bbf9495e3b3a55b3e355df3aab7351762f216f1e64f40659',
    'kit/confinement/test_feedback_admin_integration.py': 'a668a1d799fe7eb10fa174a4a5141e914724968196be055f6a3f7e6b67fc5ae8',
    'kit/confinement/test_macos_feedback_output_limits.py': 'd03c4e508b83c7a6ef7be7e9f402b2b3775d3878306fb1d010e27276625d9f99',
    'kit/confinement/feedback_api.py': 'eeb52bc7cb3f3215b5ca48fa50a810b2870e5ae8dfe590b04427eca5fcca0aac',
    'kit/confinement/test_feedback_api.py': 'fa255339c584697d2329a588a6ab87c50ed3134bd65378d3e73d9a0da94a3f26',
    'kit/confinement/feedback_public_audit.py': '48302d0d3b4a92b41fccf5958396132bf4758bf34dafba2624d616f84a48a6bb',
    'kit/confinement/test_feedback_public_audit.py': '25d3067bc5b1c85236436435c6e7cece563f0e28e14af1aae01e02cd696412c2',
    'kit/confinement/release_provenance.py': '6e9dbe1264623f68d95d01fe4b73c5c3e4d736a784c49c31fe0dea1b0fff8717',
    'kit/confinement/test_confinement_release_provenance.py': '1e630a123396e28e23063842575f780a3a9aaaaf44a3264f431ccdcd4d68c6fa',
    'kit/confinement/role_signer.py': '96422088fe61254850db80801c747731c2c05a854d8c7f4d9453f8bc92d2c569',
    'kit/confinement/test_role_signer.py': '66db6f718456ffd83bbdadd5bfc03f67526107539637ab9bc216a0e6bf671dcb',
    'kit/bootstrap/policy_handoff.py': '5b781c7bbe5c0bf2c6bdc7e2022bbd9b66f6bcf055273ad3edb1439294e5076d',
    'kit/bootstrap/test_policy_handoff.py': '0544070f4012476a03fed541aab9c8ba0c60ab9d2ef94c9882e15e43b4f085ec',
    'kit/confinement/release_build_verify.py': 'ad9b18d2faaa6e7f408ea854f8483d9d97ebca0a7a2711e57d521203a882d91e',
    'kit/confinement/test_release_build_verify.py': '08c8b7dcb28307d8470cab9675202bcc206492261d20dec70064232c197f2579',
    'kit/confinement/cargo_vendor_verify.py': '31d346c8e66eeac9c8625ecc62fb314ff2feb87914a4030f7e8ad138277cbed2',
    'kit/confinement/test_cargo_vendor_verify.py': '6d7a02f56a81d3b9930b7d5d5e9e38334662ccd144b89d0b56597c11a1c394fc',
    'kit/bootstrap/test_public_tree.py': '2808cfe084a60c0ca5db337032c2ced39ebe7f7700a5a4f2798f0bf6bbcce4b7',
    'kit/confinement/release_evidence.py': '2609b125bf2d3cbde256e2e4229c576fc0de1c5da898faf206807205dee49ae2',
    'kit/confinement/test_confinement_cargo_lock_bootstrap.py': '73133ce9967097231a6f2b944fe11f3fc460f7183ff3de61bb5844c2b928ed5c',
    'kit/confinement/cargo_lock_bootstrap.py': '9e138ea3cb8befa770d091f9270e0e523ec7772d6ce5eda06a45d56bc28d17e2',
    'kit/bootstrap/test_policy_rust.py': 'eaaea07d1f0cd284198deca4d6fc6661653cd4b50e5c3929ff63decde595699b',
    'kit/bootstrap/policy_rust.py': '9d1680615e962dec9f1cbcf7e60d1478f428456bcbf76f05431b363701d50f46',
    '.github/workflows/core-rust-lock-return.yml': 'c76fc926d01d64b13c577cce9eb6b8268b9ef61542df6e50525e11120e68a0a0',
    '.github/workflows/core-npm-admission-return.yml': 'd223f706e69f9a615247ed4ec42f5c207c256c164301630d2e2c460bec1512f6',
    'kit/bootstrap/policy_npm.py': 'b90f491d403204afc7193bcb22de9a47faf72e6c06b1926976c041257362aaef',
    'kit/bootstrap/test_policy_npm.py': '54cb41fda7c5104e656c758514aed562264038cf1db5a1c0f7bafad761201182',
    'kit/confinement/npm_admission_bootstrap.py': '2f31450866da8bc9dfe838e747528b9393d979e44f9e2d1e642196c5e590b31a',
    'kit/confinement/test_confinement_npm_admission_bootstrap.py': '890efde013f821686725bd362ac14ea7076d85bac4d9072def5cb03a07aea7ac',
    'kit/confinement/npm_semver.py': '0f6207724ea97a793d9c64175a5e9245f138e0fb4b057ab776c67d1722b1c26f',
    'kit/confinement/test_confinement_npm_semver.py': 'de0caa828a3af80166ee7cd1946276ef251504be8c967bc4b2cac046f8e65395',
    'kit/confinement/test_feedback_request_npm.py': '8b13fad42f732e9029f00ca053febe6298dff2ac688cb2ef1f7f56d3f62d9fbb',
    'kit/confinement/test_macos_feedback_producer_npm.py': '06a75fae1c4a22d598ac10a171934a255bd78eedc391edcb580e54f9f6e064b3',
    'kit/confinement/test_npm_admission_feedback.mjs': '7eff3e88259a7f346002dc415e0477f874b4b8ac75e53adbdbad33738fc83ac1',
    'kit/confinement/test_release_evidence.py': '8157fdaf8f9a691d4bae699eec3b7eb07143cc8f0fef6bed7619ebf45da8c6f3',
    '.github/workflows/baselines-prepare.yml': '970eec0b3be196ab2c0e02f7652a06e186b9ab2f76df704daba53a935af0388d',
    'kit/baselines/baselines_prepare.py': 'b51af2756756c1fe2db08eaa8eb097df58b635bd6caef75f68da013a49e2a2f5',
    'kit/baselines/test_baselines_prepare.py': 'e32265ac4159db206af4e2c6516a370713ae060d32b52e30e6e854e476516a55',
    'kit/bootstrap/policy_baselines.py': '62878db53091a36a743d10e6e3355f7b9bb8227ae763337082608e9935edd8b8',
    'kit/bootstrap/test_policy_baselines.py': '3e9041e973239aaf75c57ada33356b94f422c9941747a45b13f608de65f939aa',
}
PLAN_ID_PATTERN = re.compile(r"(?<![A-Za-z0-9])(?:D|R|H|X|CI|PF|K)[0-9]{1,3}(?![0-9])")
ACTION_VERSION_COMMENT_PATTERN = re.compile(
    r"^\s*uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}\s+"
    + re.escape(chr(35))
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


def inspect_text(text, pool):
    lowered = text.lower()
    if any(
        chr(35) in line and not ACTION_VERSION_COMMENT_PATTERN.fullmatch(line)
        for line in text.splitlines()
    ):
        raise PublicTreeError("comment-present")
    if PLAN_ID_PATTERN.search(text):
        raise PublicTreeError("plan-id-present")
    if PRIVATE_PATH_PATTERN.search(text):
        raise PublicTreeError("absolute-path-present")
    if WINDOWS_PRIVATE_PATH_PATTERN.search(text):
        raise PublicTreeError("absolute-path-present")
    if WINDOWS_UNC_PRIVATE_PATH_PATTERN.search(text):
        raise PublicTreeError("absolute-path-present")
    if REPOSITORY_URL_PATTERN.search(text):
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
        if expected_hash is not None and hashlib.sha256(payload).hexdigest() != expected_hash:
            raise PublicTreeError("file-hash-mismatch")
        inspect_text(text, pool)
    return tuple(sorted(actual_files))
