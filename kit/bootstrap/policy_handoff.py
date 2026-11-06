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
    "windows-source-admission": "118975166728aed8ee2ecc79c48fb5171f94fe5d4413ff05defaa556892c8273",
    "lane-h-windows-receiver": "52c564f8b52db004f6e89202aff310a9d9b9b6f92e264814027a9e67f0edd772",
    "lane-h-linux-fetch-encrypt": "a23f7cf71baba02cba9d20e49abb0536505930c40b3312d76a4e8fdf6b22f8b1",
    "lane-h-capsule-attester": "192d78328f8bf093a68bef0f1dd323a88772e2929d79c92b24a8864d17c1b48c",
}
CANDIDATE_WORKFLOWS = (
    (
        ".github/workflows/windows-handoff-synthetic.yml",
        "windows-handoff-synthetic",
        "handoff-workflow-too-large",
    ),
)
