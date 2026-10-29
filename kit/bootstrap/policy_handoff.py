"""Windows handoff lane workflow validation data.

This lane registers the source-free synthetic handoff and role-signer workflows
with their exact digests. The shared policy module imports this module and
dispatches through its fixed registry. This module must not import shared policy.

Lane interface, identical in every lane module:

WORKFLOW_TEMPLATES maps a workflow kind to its exact expected text.
WORKFLOW_SHA256 maps a workflow kind to the expected SHA-256 of its text.
CANDIDATE_WORKFLOWS lists, in order, the path, workflow kind and size-failure
code that the candidate checker validates when the pool is platform.
"""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "windows-handoff-synthetic": "240c1df7025c6e69c975b4f393ec5f368846cf43552e12f2b965212ce104520a",
    "windows-source-admission": "9783b15773e7ac970aaf83eabe0a6ac333fca31d258553f2066e8aab7e79ca3a",
    "lane-h-windows-receiver": "5347fcfdf29c979f7af8c63cee48f77b856fd7cc38d34ad675da75a0b806b448",
    "lane-h-linux-fetch-encrypt": "fdd7355a0eabe45248fb497e49b5989645f5e2f31fd134fb6d80ac06cf52f0a7",
    "lane-h-capsule-attester": "bdde526a962d01374e2655c8e8c83b786bc004555cb24f411f46eb1f6840a243",
    "attestation-role-signer-probe": "ba5154846c0ae90fa3dad7caecf5a0a715336247aae67e4ed1b3c35d1aeac2e3",
}
CANDIDATE_WORKFLOWS = (
    (
        ".github/workflows/windows-handoff-synthetic.yml",
        "windows-handoff-synthetic",
        "handoff-workflow-too-large",
    ),
)
