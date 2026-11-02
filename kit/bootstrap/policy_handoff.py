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
    "windows-source-admission": "430e128c93d18f729db199990bb3d05ac7c4ffc32b9545ae8b75a327c8dc53d4",
    "lane-h-windows-receiver": "c9e0419443121aa0f35045209ab298a76104bbcf2850ec73b6dbfe82454988c9",
    "lane-h-linux-fetch-encrypt": "8d3ae122392872d11fa497e183c0b6044d37b4ab95b79f65d97dbcd4f11bc14c",
    "lane-h-capsule-attester": "99a4c171a5b574c263a8b0ee7ab6743b932410f737b1eee20981ca0e62f9b9ad",
}
CANDIDATE_WORKFLOWS = (
    (
        ".github/workflows/windows-handoff-synthetic.yml",
        "windows-handoff-synthetic",
        "handoff-workflow-too-large",
    ),
)
