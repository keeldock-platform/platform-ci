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
    "windows-handoff-synthetic": "b0e648372ab0092b3341f1a53f3f6f03a470b40758b9af38505f71d4559ba06f",
    "windows-source-admission": "ef10b21b69f841f6c2b69bc22497400e89e959fdfd6e24740a24e4b00139b5a8",
    "lane-h-windows-receiver": "a6033b3c5dd1748bd4e55fa0dc4da82e40cd3ccfeee6b0fcc3ba3f88e165bde3",
    "lane-h-linux-fetch-encrypt": "c173b2298dca7757b37a67669ad6ae4abf6eaf32cf1dea94b8b0a17a1c50d423",
    "lane-h-capsule-attester": "192d78328f8bf093a68bef0f1dd323a88772e2929d79c92b24a8864d17c1b48c",
}
CANDIDATE_WORKFLOWS = (
    (
        ".github/workflows/windows-handoff-synthetic.yml",
        "windows-handoff-synthetic",
        "handoff-workflow-too-large",
    ),
)
