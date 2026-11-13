"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "83ee429bc6cad4bf64948dd1cec16f8eb1aed4919d8f066f67a05a1adeae3bbd",
    "devlane-synthetic": "ab25af7770a1515bc0bc67eeba2eb0f57f14104e98d76d5c57882ed78f42617d",
}
CANDIDATE_WORKFLOWS = (
    (
        ".github/workflows/devlane-encrypted.yml",
        "devlane-encrypted",
        "devlane-encrypted-workflow-too-large",
    ),
    (
        ".github/workflows/devlane-synthetic.yml",
        "devlane-synthetic",
        "devlane-synthetic-workflow-too-large",
    ),
)
