"""Windows handoff lane workflow validation data.

This lane registers the source-free role-signer workflows and their exact
workflow digests. It must not import the shared policy module.

Lane interface, identical in every lane module:

WORKFLOW_TEMPLATES maps a workflow kind to its exact expected text.
WORKFLOW_SHA256 maps a workflow kind to the expected SHA-256 of its text.
CANDIDATE_WORKFLOWS lists, in order, the path, workflow kind and size-failure
code that the candidate checker validates when the pool is platform.
"""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "windows-source-admission": "6637cfbaaf5a5ae228680984ce39971ab2584dd76f14790c7e6e766aca8c2cbc",
    "lane-h-windows-receiver": "5347fcfdf29c979f7af8c63cee48f77b856fd7cc38d34ad675da75a0b806b448",
    "lane-h-linux-fetch-encrypt": "3cb1e0f2fcd46014839988452bdb50e1a688c7ad9e8a59098a6f7c2de96042f0",
    "lane-h-capsule-attester": "5f3120c996a193bea63111024d285ee4eb9e199a01c4f4d09fee6424471e281e",
    "attestation-role-signer-probe": "dc534b6df944369d24cb59e719acc84fdb5c2329c6d939af7c192a93f318e88c",
}
CANDIDATE_WORKFLOWS = ()
