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
    "windows-source-admission": "d8109fc807a8a4e2fdd4d753c9a2b8d00b35c190b4c8e70e37048bde6b1c8b25",
    "lane-h-windows-receiver": "124a6a0ee378ccd3fa4ae791f9e9dc6c85776f8ca7b79f8af0f53deb93d3940e",
    "lane-h-linux-fetch-encrypt": "315cef77a9df73249f23ff54db23dbbc30fe00288922c3fad9543afd0412a033",
    "lane-h-capsule-attester": "192d78328f8bf093a68bef0f1dd323a88772e2929d79c92b24a8864d17c1b48c",
}
CANDIDATE_WORKFLOWS = (
    (
        ".github/workflows/windows-handoff-synthetic.yml",
        "windows-handoff-synthetic",
        "handoff-workflow-too-large",
    ),
)
