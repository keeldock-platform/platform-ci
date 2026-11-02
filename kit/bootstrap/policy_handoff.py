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
    "windows-source-admission": "f55ac21f52dd5c4f5f3fbccea9399df4f07ea68e5b06802c8da9e875b1259659",
    "lane-h-windows-receiver": "5347fcfdf29c979f7af8c63cee48f77b856fd7cc38d34ad675da75a0b806b448",
    "lane-h-linux-fetch-encrypt": "2385b434657d1dadf7300dbacb36165b58ff8ffe5e6863f34fca5b23bfe1aee3",
    "lane-h-capsule-attester": "99a4c171a5b574c263a8b0ee7ab6743b932410f737b1eee20981ca0e62f9b9ad",
    "attestation-role-signer-probe": "ba5154846c0ae90fa3dad7caecf5a0a715336247aae67e4ed1b3c35d1aeac2e3",
}
CANDIDATE_WORKFLOWS = (
    (
        ".github/workflows/windows-handoff-synthetic.yml",
        "windows-handoff-synthetic",
        "handoff-workflow-too-large",
    ),
)
