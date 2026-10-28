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
    "windows-source-admission": "58aa50417238c55c26d18c903479f149ebdb92a4b7fd6bed7253147d35ec340d",
    "lane-h-windows-receiver": "5347fcfdf29c979f7af8c63cee48f77b856fd7cc38d34ad675da75a0b806b448",
    "lane-h-linux-fetch-encrypt": "fdd7355a0eabe45248fb497e49b5989645f5e2f31fd134fb6d80ac06cf52f0a7",
    "lane-h-capsule-attester": "082da71f6caa218b89c688e5c73389b8d0c96d3281121b2b4fd8460db827745e",
    "attestation-role-signer-probe": "e0a39e5d177e9df8ea30420673a02a5009b7211df5d2d0c2d10d5e1a9a617ef8",
}
CANDIDATE_WORKFLOWS = ()
