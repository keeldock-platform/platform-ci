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
    "windows-source-admission": "b1b0ec4bcc81906cf134cca091facd071b922feed29c372a4ed783d2e9846452",
    "lane-h-windows-receiver": "5347fcfdf29c979f7af8c63cee48f77b856fd7cc38d34ad675da75a0b806b448",
    "lane-h-linux-fetch-encrypt": "fdd7355a0eabe45248fb497e49b5989645f5e2f31fd134fb6d80ac06cf52f0a7",
    "lane-h-capsule-attester": "eed3ce701a4945cecebcc32ddaf9f18e41510ae86def376874f7daafbd0ff716",
    "attestation-role-signer-probe": "ecaedf124a7a2961802c123bed543fbed22799dc6b4f2d835108d180095ff258",
}
CANDIDATE_WORKFLOWS = (
    (
        ".github/workflows/windows-handoff-synthetic.yml",
        "windows-handoff-synthetic",
        "handoff-workflow-too-large",
    ),
)
