"""Retired npm admission workflow lane.

npm dependency safety now runs in ordinary CI from committed package-lock.json files. This
compatibility module intentionally exports an empty lane interface while other platform policy
code is being consumed by older checkouts.
"""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {}
CANDIDATE_WORKFLOWS = ()
