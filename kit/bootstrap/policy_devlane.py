"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "5923c23e3ca4b8bcb9f731b3bcf0cca935fb9e1ea5cb2576f3c29766dd78d9b4",
    "devlane-synthetic": "ad283ebf2799536cd19fed58ebda14d9577364ddbd0ec9223d321648b44813af",
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
