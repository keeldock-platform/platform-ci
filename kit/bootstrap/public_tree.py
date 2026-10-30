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
        "kit/confinement/windows_confinement_recovery.ps1",
        "kit/confinement/test_windows_confinement.py",
        "kit/confinement/test_windows_confinement_recovery.ps1",
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
    '.github/workflows/linux-source-admission.yml': '65f38177082ee86c7b20f0f56fb3b719041b977fd3f7e9c43d100b7f0d8050b4',
    'kit/bootstrap/action.yml': 'e76dcd46643e3ce6efd810756d14b2db36209fad7c15a2da9bc46373a999ce66',
    'kit/confinement/foundation_node_feedback.py': '2bcba427dfe5efa5601e8755910b5f177d6eb95b882616eb47470df0509c0013',
    'kit/confinement/test_foundation_node_feedback.py': 'e2f2cb361e28a9febb77e36e1fb820d4be4d5d1b1b49f265d663055f3196b5b1',
    'kit/confinement/native_loopback_profile.py': '5dee8e3f29e1d9178099eeefdec9f7520efe3939ab9b8cae71406b8da48a4ab7',
    'kit/confinement/test_native_loopback_profile.py': 'acbc69ae710ac56931429fdc881a853ceadfaf63327a62aace5e6f1d76e8683d',
    'kit/confinement/linux_harness.py': '066e461ad229d70cd2a270fc95ddcc29e60951da5c7ec5cfdd68e45c4445a8c0',
    'kit/confinement/macos_deny_default.py': 'ff99d93537c4f57d052e87760285537e0b4328685a50746bb9de0191f777243c',
    'kit/confinement/macos_node_contract.py': '890cd2891954d4abf7db85ec4295e7aa01c4e2ca3a083ef7537904e3c3c1aeb6',
    'kit/confinement/test_macos_node_contract.py': 'e82debccbaeaba990256babe32dd9ff36dcc8d4542a411b56e67034aff4a293c',
    'kit/confinement/node_contract_validation.mjs': '5d5c06ef75a7194858b707685b40ab39155f2f0ea0dde1633b286bc2709f5920',
    'kit/confinement/test_node_contract_validation.mjs': '21870604a820e8f10e4b68d33810687af248ae110f4295cd8aa406ca9a406d04',
    'kit/confinement/test_feedback_failure.py': 'f7898d7f69af43c61f63ed6b339c581b3c2194f7b0857abb0551f67d26f6b501',
    'kit/confinement/feedback_failure.py': '749d0a6dd81b4f41ea6cf339072e02848c5280c22b366fd65d13fbf6fc8bf763',
    '.github/workflows/development-feedback-smoke.yml': '09e058574372baa40016327e8a0da12d130a262a8bd70baba3a38ed10acc3d7a',
    'kit/confinement/development_feedback.mjs': '6cfcb93f18b2ac9761c3d62e134529bb60dd9b9cca6e6ef31c964168632de546',
    'kit/confinement/test_development_feedback.mjs': '897d15252ff09aee3e9c86c9a2424a64fdf333415e21ef6e7232c0e6f31cde74',
    'kit/confinement/feedback_request.py': '9c829edde3b289ef33ac738edb0aefdd2689ab8f293d3a099c9dec980f13796a',
    'kit/confinement/test_feedback_request.py': '3098946b5cf52fddf9280ab80effff4a4f641570f561e6b91d7b1f79e33bec77',
    'kit/confinement/feedback_smoke.mjs': 'de814d03e2202d91312879b1a3ef1e280026d8d8dc53836f35c7f4d1bae59bf6',
    'kit/confinement/test_feedback_smoke.mjs': '2498a04a338a01b1e3f510ebd9b66eca970baa1acac7a78286ebcd5b391dbd0d',
    'kit/confinement/feedback_smoke_audit.py': 'fefaae55c52b676951efc567b304bbbb07bb2488659c6c3803ac192e31fcde7c',
    'kit/confinement/test_feedback_smoke_audit.py': '4b03a8f9c9d04d247377aab7fa9ca2ef80c759527f3d931798e676c858415793',
    '.github/workflows/node-lock-smoke.yml': '56793792e10d9e824d6da55e13181b0bc877440568b1980bde6d3bb695e5a59b',
    'kit/confinement/node_lock_envelope.mjs': 'cdf113dbafdf43ff08ca14b0dbe1fa7245b4244702ccbc00fa0dbe6c3c21737a',
    'kit/confinement/test_node_lock_envelope.mjs': 'de43ee5be7df6bf5da5b5a738f3d3fcec90a45ed6a5d1b52e4c405005d534c40',
    'kit/confinement/node_lock_inventory.mjs': '682f880a03edbd3c91b08dd4c581679cdb5d4ac70e93215044804c6152fc6f69',
    'kit/confinement/node_lock_manifest.mjs': 'd4562a742e14b5f26d3c602c870c94923ca42710834c99821f8e1e66f6345612',
    'kit/confinement/test_node_lock_manifest.mjs': '3b036521f38678f04d7e7539954a955d148dd46aeb70a5c72bfc9706887f9ec1',
    'kit/confinement/sbom_normalizer.py': 'd0f686536749239295f3c74f19e3052f7d3807de0f8984525da15d8822c27d3f',
    'kit/confinement/test_sbom_normalizer.py': '422fd582c58692b948d586870381ba7c3025d4b7cd6dc1ce49c3aab95ad10f89',
    'kit/confinement/node_lock_receipt.py': 'ade987d617a6cfe8a8b9f937ea6c17510a639a9ea671437625afeecd0c7e1a63',
    'kit/confinement/test_node_lock_receipt.py': '76163ace7dc4e239c16c993de84da44deaf402e42ba4fccb1a28fd8c28fae6b6',
    '.github/workflows/macos-core-contract.yml': '38c33a1b30bc18378359910af0da73e493026e8105511062f96f6f80fafbe096',
    'kit/confinement/macos_core_contract.py': 'ef030c63f9ecfad12007c6f280077d3c7edcca5a68196c005cf314b4c91892bc',
    'kit/confinement/test_macos_core_contract.py': 'c76e5124352b14091c88467d3ddd06071ce675b9b59cc21bb9b42c3036e77d57',
    'kit/confinement/linux_source_build.py': 'a50e20e89dec9539d885a3b7eb850ce9a29b54bf97f32dee3d19c76d743cf47e',
    'kit/confinement/test_linux_source_build.py': '0bd7cf3e8b949e50fd2284b12395d1756bf957698b0c107c35a5fac94e87bb2c',
    'kit/confinement/rust_license_gate.py': '4896e53baf2b0bd8bc8047c69e50c8c72dff11096ca9225bfa9efad71913dfc6',
    'kit/confinement/test_rust_license_gate.py': '5c421d6142948a52704fd9a4db72d0761c167ed6a8fea5bae49b633acf53defa',
    '.github/workflows/macos-rust-toolchain-smoke.yml': 'cdf7068f8887c22958d74f3c2cc0a73c5c8c4c41f4eff0b43e16e47f61e58bb7',
    'kit/confinement/macos_rust_toolchain.py': '215337abbb884ab48089cb813cc078442ea13a5ccb5fc306843bb046230311a3',
    'kit/confinement/test_macos_rust_toolchain.py': '819ff375c5f1a5093bd25ad08ca78a1b68d7221a79686ed7b74d4f9f2b96db37',
    '.github/workflows/macos-rules-bootstrap.yml': 'a91387440f8caceadf8f19f7c87feb3d82377eb3c9e1813de48b518992d48807',
    '.github/workflows/macos-core-bootstrap.yml': '08cf50d62e18e52661befe3153294c2d188b8a980f914437dab7cbd899744b81',
    'kit/confinement/macos_rules_bootstrap.py': '19f10dd7764cb089020cf455c7f96097c12c5e9a747610c2d88e9cded52071ec',
    'kit/confinement/test_macos_rules_bootstrap.py': '984798054872a47f8fe1281b82dba6df03c84b9dcd32d3a6ba4bc63672d17895',
    'kit/confinement/macos_core_bootstrap.py': '0b03235d000b1504848d49215a2bed9c4dec5ee3dd47d26b4177c7fa44c16836',
    'kit/confinement/test_macos_core_bootstrap.py': 'f8e56bde25e64fc691adc25c3288924179797b83c8d6da66ef21c5fad256c38e',
    'kit/confinement/macos_network_observer.py': 'a7cf6cb16e68f00513e9f8ee08d52511619b18bb8edd37205faf907dcf0a98d9',
    'kit/confinement/test_macos_network_observer.py': '0187ffbe5a7b7395b2edc2025a4dd3e4c0adf5a48c881f8878578010d76307a3',
    'kit/confinement/macos_private_validation.py': '7302c741ab76f5f20bd9ce07fd1d452b03d097a0aeae8a6f97e28c69b8466455',
    'kit/confinement/test_macos_private_validation.py': '3feda886a63f410ccb2abda97117640a6ef94fd39e40fa670cc7438948d1cbf6',
    'ci/revoked-signer-fingerprints': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    '.github/workflows/capsule-vectors.yml': '7366acdb58988c5675e86268abe268e71f71bc16681ab560ba8e33f37fc9f9f7',
    'kit/confinement/capsule_frame.cs': 'b7de9b0af02e305d23e75ea58daf856a9e51d340b0ccee0920925930ffb1bc84',
    'kit/confinement/capsule_frame.ps1': 'dc889a1e2909a4dedb4733a26afa7f2650182ce82cf4d00931bfdab323320741',
    'kit/confinement/capsule_frame_vectors.json': 'fb0660998011eec479ee01e919510dcd8f88ae5266114d9f82a899b4fa72fb94',
    '.github/workflows/windows-native-preflight.yml': 'da294aadfc0e99cbe109aba90f9fb86df65867cd32d3325d26a9e9a5b035e5bb',
    'kit/confinement/windows_native_preflight.cs': 'ba0f8859db9d8bcc1e4c8274520bcb67a3292cb311f553127e1f29fe13838543',
    'kit/confinement/windows_native_preflight.ps1': '8dbaaaad105c2fe0439dedb1b7c9572b8e7ec74a8db29f8edcab91169b06c58b',
    'kit/confinement/test_windows_native_preflight.py': '07defbc65611505f9107e5cb9186f4e15bbb9616797ff07032b3f314480eea7d',
    'kit/confinement/windows_confinement.cs': '4eefb220c1276fb586ee913494a022cd82f4c1c8284272d7536262285165b74d',
    'kit/confinement/windows_confinement.ps1': 'b2aeebec8ecbc3cccceb98f40684f786b97463530c073804feb26e2e1675635d',
    'kit/confinement/windows_confinement_recovery.ps1': 'c433b3e6956a5c948410f409ff4072ee0bd1d1860cdc7d02eb3a840ac1bd1dcc',
    'kit/confinement/test_windows_confinement.py': '986c3f72178b748de5ffb678ee99a79b35d444d0af0e07888aeed899c50a3c47',
    'kit/confinement/test_windows_confinement_recovery.ps1': '8145812aa51f0b1b883b6a066fd611df0d02f8796560eb06995a1a3c6214bd8f',
    'kit/confinement/macos_source_reader.py': 'd3fbda5c68ac7d21761e946b0f546607b19c23ccb725e453f3fffef3321c0d70',
    'kit/confinement/test_macos_source_reader.py': 'ed8e9b850f7d3a80346ad4a6efc182b28ff9c22fa669eda241f2c5feb3ccf806',
    '.github/workflows/node-lock-return.yml': '235309cbda1f907b62cb9631cfa902d3d9a20b4a994c6426f7f6de4038ea3929',
    '.github/workflows/core-rust-format-return.yml': '55179c46bc26168f0f08609d8884a4d47a178d85f22c091a928ea55724063eab',
    '.github/workflows/core-build-diagnostic-return.yml': 'd573e553d55f4e017701c20cb6d74cf0348df428e1af64eab5ca9588534b3f70',
    '.github/workflows/attestation-role-signer-probe.yml': 'ba5154846c0ae90fa3dad7caecf5a0a715336247aae67e4ed1b3c35d1aeac2e3',
    '.github/workflows/windows-source-admission.yml': '9783b15773e7ac970aaf83eabe0a6ac333fca31d258553f2066e8aab7e79ca3a',
    '.github/workflows/lane-h-windows-receiver.yml': '5347fcfdf29c979f7af8c63cee48f77b856fd7cc38d34ad675da75a0b806b448',
    '.github/workflows/lane-h-linux-fetch-encrypt.yml': 'fdd7355a0eabe45248fb497e49b5989645f5e2f31fd134fb6d80ac06cf52f0a7',
    '.github/workflows/lane-h-capsule-attester.yml': 'bdde526a962d01374e2655c8e8c83b786bc004555cb24f411f46eb1f6840a243',
    'kit/confinement/macos_feedback_producer.py': '40071bb9fed6a282293f58916eded171165e490cecf85406e740518aa9d603a2',
    'kit/confinement/test_macos_feedback_producer.py': '1574d1a8eab63cad4c22459cd45e95ef425efa9f67787ffc102d1e0fbd3a8dad',
    'kit/confinement/feedback_producer_crypto.mjs': 'c2a9f7906588042685e51bfc95599768968601b7fd1b4e0251a95fa8b1476ffc',
    'kit/confinement/test_feedback_producer_crypto.mjs': 'cbc9b52991f910e14aebb0023f504934093b93677c6bb699a9b845e6eef8d2fe',
    'kit/confinement/feedback_admin.py': '2b5572a8ad661cadb6d8987bbfcb2aac37d338e3641c8a3de7c404963388583f',
    'kit/confinement/test_feedback_admin.py': 'a7c164bd7ee29fa86de02eb04fd1d7008dea5e206f7696509ded6de16bfb487a',
    'kit/confinement/feedback_admin_crypto.mjs': 'ae1afe9048e171b4d97cf2ab5a6ec1ed44e6fc9e36fc25de435898f29fc63eba',
    'kit/confinement/test_feedback_admin_crypto.mjs': 'f327b2b12055909db88e1ce2ad65a27bfd9835b83234da81357ef6b7411344a8',
    'kit/confinement/test_feedback_admin_integration.py': 'a668a1d799fe7eb10fa174a4a5141e914724968196be055f6a3f7e6b67fc5ae8',
    'kit/confinement/feedback_api.py': 'd1f13582e53ee178f53e66be06fb9ce8c1a8cee6db3762aafaf8f96f64faf377',
    'kit/confinement/test_feedback_api.py': 'a748ca0ad084de64bbec47f4d2413f4ae35d6b932d8010847f59cec700f27fae',
    'kit/confinement/feedback_public_audit.py': 'beef023a68e01343c5e8f3e883ba99be75f79924eeaca8fdcaabe9d7401960cb',
    'kit/confinement/test_feedback_public_audit.py': '4a7b822645c7051a4f1999e5961482000a0c58c7c31d9a6ec106a88b8426b5e7',
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
    'kit/bootstrap/test_public_tree.py': 'd2ab71c5eb72011ab6e32f03212061a5e468d0ffb4a3d5bb9a5fe7cad368f278',
    'kit/confinement/release_evidence.py': '2609b125bf2d3cbde256e2e4229c576fc0de1c5da898faf206807205dee49ae2',
    'kit/confinement/test_confinement_cargo_lock_bootstrap.py': '481fe953a5e5c591e087025c616bb041d5850a23f41355147ee14243ff8565b6',
    'kit/confinement/cargo_lock_bootstrap.py': 'bd320006579bc0281e04b1ce681e0c6e5e019d7325ae4a79ac2e360d10bdb704',
    'kit/bootstrap/test_policy_rust.py': 'eaaea07d1f0cd284198deca4d6fc6661653cd4b50e5c3929ff63decde595699b',
    'kit/bootstrap/policy_rust.py': '85e57c3f221047b0bfb520b1e2970c172be0f2595a3ea52b18e7186cf63b37d4',
    '.github/workflows/core-rust-lock-return.yml': '89bda3c7a1cad77acaf39f48bfe53f0ba945656e03ad16f55eb49c17149b65bc',
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
