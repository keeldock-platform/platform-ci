"""Windows handoff lane workflow validation data.

This lane module registers no workflows yet. It exists so that the shared
policy module can dispatch to a fixed set of statically imported lane modules,
and so that the handoff lane can add its own templates and digests without
editing any other module. It must not import the shared policy module.

Lane interface, identical in every lane module:

WORKFLOW_TEMPLATES maps a workflow kind to its exact expected text.
WORKFLOW_SHA256 maps a workflow kind to the expected SHA-256 of its text.
CANDIDATE_WORKFLOWS lists, in order, the path, workflow kind and size-failure
code that the candidate checker validates when the pool is platform.
"""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {}
CANDIDATE_WORKFLOWS = ()
