import hashlib
import json
import re
from dataclasses import dataclass


STATEMENT_TYPE_URI = "https://in-toto.io/Statement/v1"
STATEMENT_TYPE_URI_PRIMARY_SOURCE_RECHECK_REQUIRED = True
PREDICATE_TYPE_URI = "https://keeldock.dev/attestation/release-provenance/v1"
PREDICATE_TYPE_URI_PRIMARY_SOURCE_RECHECK_REQUIRED = True
PROFILE_VERSION = "1"
COMPARISON_POLICY_ID = "h70-normalized-v1"
MAX_STATEMENT_BYTES = 262144
MAX_SIGNATURE_BYTES = 16384
MAX_JSON_DEPTH = 32
MAX_JSON_STRUCTURAL_TOKENS = 20000
MAX_SUBJECTS = 256
MAX_COLLECTION_ITEMS = 128
MAX_DYNAMIC_FIELDS = 64
MAX_IDENTIFIER_LENGTH = 128
MAX_VERSION_LENGTH = 64
SAFE_INTEGER_MAX = 9007199254740991
SIGNATURE_DOMAIN_PREFIX = "KeelDock/release/v1/"
PROVENANCE_DOCUMENT_ROLE = "provenance"

IDENTIFIER_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._:/+-]*"
SHA256_PATTERN = r"[0-9a-f]{64}"
REVISION_PATTERN = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
VERSION_PATTERN = r"[A-Za-z0-9][A-Za-z0-9.+_-]*"


class VerificationRefusal(ValueError):
    """A refusal with a stable, input-independent code."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class VerificationResult:
    """The verified profile identity and exact subject names."""

    profile_version: str
    statement_sha256: str
    subject_names: tuple
    signer_role: str
    signer_key_id: str


def _string(pattern, maximum):
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": maximum,
        "pattern": pattern,
    }


def _object(properties, minimum=0, maximum=None, additional=False):
    schema = {
        "type": "object",
        "properties": properties,
        "required": tuple(properties),
        "minProperties": minimum,
        "additionalProperties": additional,
    }
    if maximum is not None:
        schema["maxProperties"] = maximum
    return schema


IDENTIFIER_SCHEMA = _string(IDENTIFIER_PATTERN, MAX_IDENTIFIER_LENGTH)
SHA256_SCHEMA = _string(SHA256_PATTERN, 64)
REVISION_SCHEMA = _string(REVISION_PATTERN, 64)
VERSION_SCHEMA = _string(VERSION_PATTERN, MAX_VERSION_LENGTH)
SOURCE_PIN_SCHEMA = _object(
    {
        "sourceId": IDENTIFIER_SCHEMA,
        "revision": REVISION_SCHEMA,
    }
)
ARTIFACT_EDGE_SCHEMA = _object(
    {
        "name": IDENTIFIER_SCHEMA,
        "sha256": SHA256_SCHEMA,
    }
)
LINUX_SIGNATURE_EDGE_SCHEMA = _object(
    {
        "name": IDENTIFIER_SCHEMA,
        "sha256": SHA256_SCHEMA,
        "artifactName": IDENTIFIER_SCHEMA,
        "artifactSha256": SHA256_SCHEMA,
    }
)
BUILD_SCHEMA = _object(
    {
        "builderId": IDENTIFIER_SCHEMA,
        "outputSetSha256": SHA256_SCHEMA,
    }
)
BUILD_EVIDENCE_SCHEMA = _object(
    {
        "runId": IDENTIFIER_SCHEMA,
        "inputManifestSha256": SHA256_SCHEMA,
        "buildA": BUILD_SCHEMA,
        "buildB": BUILD_SCHEMA,
        "comparison": _object(
            {
                "policyId": {
                    "type": "string",
                    "const": COMPARISON_POLICY_ID,
                },
                "result": {"type": "string", "const": "agree"},
                "digest": SHA256_SCHEMA,
            }
        ),
    }
)
SIGNER_SCHEMA = _object(
    {
        "role": {"type": "string", "const": "release-role"},
        "keyId": IDENTIFIER_SCHEMA,
    }
)
TOOL_PIN_SCHEMA = _object(
    {
        "version": VERSION_SCHEMA,
        "sha256": SHA256_SCHEMA,
    }
)
SBOM_PIN_SCHEMA = _object(
    {
        "format": {"type": "string", "const": "CycloneDX"},
        "schemaVersion": VERSION_SCHEMA,
        "generatorId": IDENTIFIER_SCHEMA,
        "sha256": SHA256_SCHEMA,
    }
)
PINS_SCHEMA = _object(
    {
        "sourcePins": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_COLLECTION_ITEMS,
            "items": SOURCE_PIN_SCHEMA,
        },
        "lockDigests": {
            "type": "object",
            "minProperties": 1,
            "maxProperties": MAX_DYNAMIC_FIELDS,
            "additionalProperties": SHA256_SCHEMA,
        },
        "imageDigests": {
            "type": "object",
            "minProperties": 1,
            "maxProperties": MAX_DYNAMIC_FIELDS,
            "additionalProperties": SHA256_SCHEMA,
        },
        "toolPins": {
            "type": "object",
            "minProperties": 1,
            "maxProperties": MAX_DYNAMIC_FIELDS,
            "additionalProperties": TOOL_PIN_SCHEMA,
        },
        "sbom": SBOM_PIN_SCHEMA,
    }
)
EDGES_SCHEMA = _object(
    {
        "artifacts": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_SUBJECTS,
            "items": ARTIFACT_EDGE_SCHEMA,
        },
        "sbom": ARTIFACT_EDGE_SCHEMA,
        "linuxSignatures": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_COLLECTION_ITEMS,
            "items": LINUX_SIGNATURE_EDGE_SCHEMA,
        },
    }
)
RELEASE_SCHEMA = _object(
    {
        "product": {"type": "string", "const": "keeldock"},
        "channel": {
            "type": "string",
            "enum": ("dev", "uat", "prod"),
        },
        "version": VERSION_SCHEMA,
    }
)
PROFILE_PREDICATE_SCHEMA = _object(
    {
        "profileVersion": {"type": "string", "const": PROFILE_VERSION},
        "release": RELEASE_SCHEMA,
        "buildInputManifestSha256": SHA256_SCHEMA,
        "buildEvidence": BUILD_EVIDENCE_SCHEMA,
        "signer": SIGNER_SCHEMA,
        "pins": PINS_SCHEMA,
        "edges": EDGES_SCHEMA,
    }
)

PREDICATE_PROFILE = {
    "version": PROFILE_VERSION,
    "statementType": STATEMENT_TYPE_URI,
    "predicateType": PREDICATE_TYPE_URI,
    "fields": PROFILE_PREDICATE_SCHEMA,
}

EXPECTED_CONTEXT_SCHEMA = _object(
    {
        "release": RELEASE_SCHEMA,
        "buildInputManifestSha256": SHA256_SCHEMA,
        "buildEvidence": BUILD_EVIDENCE_SCHEMA,
        "signer": SIGNER_SCHEMA,
        "pins": PINS_SCHEMA,
    }
)
RELEASE_MANIFEST_SCHEMA = EDGES_SCHEMA


def _refuse(code):
    raise VerificationRefusal(code)


def _parse_integer(value):
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 16:
        _refuse("number-out-of-range")
    parsed = int(value)
    if parsed < -SAFE_INTEGER_MAX or parsed > SAFE_INTEGER_MAX:
        _refuse("number-out-of-range")
    return parsed


def _reject_number(value):
    _refuse("unsupported-number")


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse("duplicate-key")
        result[key] = value
    return result


def _check_json_bounds(raw):
    depth = 0
    structural_tokens = 0
    inside_string = False
    escaped = False
    for value in raw:
        if inside_string:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                inside_string = False
            continue
        if value == 34:
            inside_string = True
        elif value in (123, 91):
            depth += 1
            structural_tokens += 1
            if depth > MAX_JSON_DEPTH:
                _refuse("nesting-limit")
        elif value in (125, 93):
            depth -= 1
            structural_tokens += 1
        elif value in (44, 58):
            structural_tokens += 1
        if structural_tokens > MAX_JSON_STRUCTURAL_TOKENS:
            _refuse("structure-limit")


def _canonical_string(value):
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        _refuse("invalid-encoding")
    escapes = {
        8: "\\b",
        9: "\\t",
        10: "\\n",
        12: "\\f",
        13: "\\r",
        34: "\\\"",
        92: "\\\\",
    }
    output = ['"']
    for character in value:
        codepoint = ord(character)
        if codepoint in escapes:
            output.append(escapes[codepoint])
        elif codepoint < 32:
            output.append("\\u%04x" % codepoint)
        else:
            output.append(character)
    output.append('"')
    return "".join(output)


def _canonical_json(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if type(value) is int:
        if value < -SAFE_INTEGER_MAX or value > SAFE_INTEGER_MAX:
            _refuse("number-out-of-range")
        return str(value)
    if type(value) is str:
        return _canonical_string(value)
    if type(value) is list:
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if type(value) is dict:
        keys = list(value)
        if any(type(key) is not str for key in keys):
            _refuse("invalid-object-key")
        try:
            keys.sort(key=lambda key: key.encode("utf-16-be", "strict"))
        except UnicodeEncodeError:
            _refuse("invalid-encoding")
        members = []
        for key in keys:
            members.append(
                _canonical_json(key) + ":" + _canonical_json(value[key])
            )
        return "{" + ",".join(members) + "}"
    _refuse("unsupported-value")


def encode_canonical_json(value):
    """Encode the supported JSON subset with canonical key order and escaping."""

    try:
        return _canonical_json(value).encode("utf-8", "strict")
    except RecursionError:
        _refuse("nesting-limit")


def _parse_canonical_json(raw):
    if type(raw) is not bytes:
        _refuse("statement-not-bytes")
    if len(raw) > MAX_STATEMENT_BYTES:
        _refuse("statement-too-large")
    _check_json_bounds(raw)
    try:
        source = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _refuse("invalid-encoding")
    try:
        parsed = json.loads(
            source,
            object_pairs_hook=_object_pairs,
            parse_int=_parse_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except VerificationRefusal:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        _refuse("malformed-json")
    try:
        canonical = encode_canonical_json(parsed)
    except VerificationRefusal:
        raise
    if canonical != raw:
        _refuse("non-canonical-json")
    return parsed


def parse_canonical_statement(statement_bytes):
    """Parse bounded canonical bytes for the supported Statement profile."""

    statement = _parse_canonical_json(statement_bytes)
    if type(statement) is not dict:
        _refuse("malformed-statement")
    required = {"_type", "subject", "predicateType", "predicate"}
    if set(statement) != required:
        extra = set(statement) - required
        if any(_is_forbidden_edge_field(key) for key in extra):
            _refuse("wrong-edge")
        _refuse("unsupported-statement-field")
    if statement["_type"] != STATEMENT_TYPE_URI:
        _refuse("unsupported-statement")
    if statement["predicateType"] != PREDICATE_TYPE_URI:
        _refuse("unsupported-profile")
    if type(statement["subject"]) is not list:
        _refuse("altered-subject")
    if not 1 <= len(statement["subject"]) <= MAX_SUBJECTS:
        _refuse("altered-subject")
    if type(statement["predicate"]) is not dict:
        _refuse("invalid-profile")
    signer = statement["predicate"].get("signer")
    if type(signer) is dict and signer.get("role") != "release-role":
        _refuse("wrong-signer")
    build_evidence = statement["predicate"].get("buildEvidence")
    if type(build_evidence) is not dict or any(
        field not in build_evidence or build_evidence[field] is None
        for field in ("buildA", "buildB")
    ):
        _refuse("missing-build")
    if "edges" in statement["predicate"]:
        _validate_schema(
            statement["predicate"]["edges"],
            EDGES_SCHEMA,
            "predicate.edges",
            "wrong-edge",
        )
    _validate_schema(
        statement["subject"],
        {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_SUBJECTS,
            "items": _object(
                {
                    "name": IDENTIFIER_SCHEMA,
                    "digest": _object({"sha256": SHA256_SCHEMA}),
                }
            ),
        },
        "statement.subject",
        "altered-subject",
    )
    _validate_schema(
        statement["predicate"],
        PROFILE_PREDICATE_SCHEMA,
        "predicate",
        "invalid-profile",
    )
    return statement


def _is_forbidden_edge_field(value):
    if type(value) is not str:
        return False
    normalized = "".join(character.lower() for character in value if character.isalnum())
    if normalized in ("buildinputmanifestsha256", "inputmanifestsha256"):
        return False
    return (
        "latest" in normalized
        or "sequence" in normalized
        or "manifest" in normalized
        or "provenance" in normalized
        or normalized in (
            "em",
            "el",
            "l",
            "m",
            "emsha256",
            "elsha256",
            "lsha256",
            "msha256",
            "emdigest",
            "eldigest",
            "ldigest",
            "mdigest",
        )
    )


def _validate_schema(value, schema, path, error_code):
    kind = schema["type"]
    if kind == "string":
        if type(value) is not str:
            _refuse(error_code)
        if len(value) < schema.get("minLength", 0):
            _refuse(error_code)
        if len(value) > schema.get("maxLength", MAX_STATEMENT_BYTES):
            _refuse(error_code)
        if "const" in schema and value != schema["const"]:
            if path == "predicate.signer.role":
                _refuse("wrong-signer")
            _refuse(error_code)
        if "enum" in schema and value not in schema["enum"]:
            _refuse(error_code)
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            _refuse(error_code)
        return
    if kind == "object":
        if type(value) is not dict:
            _refuse(error_code)
        if len(value) < schema.get("minProperties", 0):
            _refuse(error_code)
        if len(value) > schema.get("maxProperties", MAX_DYNAMIC_FIELDS):
            _refuse(error_code)
        properties = schema.get("properties", {})
        missing = set(schema.get("required", ())) - set(value)
        if missing:
            if path == "predicate" and "buildEvidence" in missing:
                _refuse("missing-build")
            if path == "predicate" and "edges" in missing:
                _refuse("wrong-edge")
            if path.startswith("predicate.buildEvidence"):
                _refuse("missing-build")
            _refuse(error_code)
        for key in value:
            if _is_forbidden_edge_field(key):
                _refuse("wrong-edge")
            if key in properties:
                continue
            additional = schema.get("additionalProperties", False)
            if additional is False:
                _refuse("unknown-field")
            if type(additional) is not dict:
                _refuse(error_code)
            if (
                len(key) > MAX_IDENTIFIER_LENGTH
                or re.fullmatch(IDENTIFIER_PATTERN, key) is None
            ):
                _refuse(error_code)
        for key, child_schema in properties.items():
            if key in value:
                _validate_schema(value[key], child_schema, path + "." + key, error_code)
        additional = schema.get("additionalProperties", False)
        if type(additional) is dict:
            for key, child in value.items():
                if key not in properties:
                    _validate_schema(child, additional, path + "." + key, error_code)
        return
    if kind == "array":
        if type(value) is not list:
            _refuse(error_code)
        if len(value) < schema.get("minItems", 0):
            _refuse(error_code)
        if len(value) > schema.get("maxItems", MAX_COLLECTION_ITEMS):
            _refuse(error_code)
        for index, child in enumerate(value):
            _validate_schema(child, schema["items"], path + "." + str(index), error_code)
        return
    _refuse(error_code)


def _manifest_subjects(release_manifest):
    _validate_schema(
        release_manifest,
        RELEASE_MANIFEST_SCHEMA,
        "releaseManifest",
        "wrong-edge",
    )
    artifacts = release_manifest["artifacts"]
    sbom = release_manifest["sbom"]
    signatures = release_manifest["linuxSignatures"]
    artifact_by_name = {}
    for artifact in artifacts:
        _validate_asset_name(artifact["name"])
        if artifact["name"] in artifact_by_name:
            _refuse("wrong-edge")
        artifact_by_name[artifact["name"]] = artifact["sha256"]
    _validate_asset_name(sbom["name"])
    if sbom["name"] in artifact_by_name:
        _refuse("wrong-edge")
    names = set(artifact_by_name)
    names.add(sbom["name"])
    signature_names = set()
    for signature in signatures:
        _validate_asset_name(signature["name"])
        if signature["name"] in names or signature["name"] in signature_names:
            _refuse("wrong-edge")
        if artifact_by_name.get(signature["artifactName"]) != signature["artifactSha256"]:
            _refuse("wrong-edge")
        signature_names.add(signature["name"])
    subjects = [
        {"name": artifact["name"], "digest": {"sha256": artifact["sha256"]}}
        for artifact in artifacts
    ]
    subjects.append({"name": sbom["name"], "digest": {"sha256": sbom["sha256"]}})
    subjects.extend(
        {"name": signature["name"], "digest": {"sha256": signature["sha256"]}}
        for signature in signatures
    )
    if len(subjects) > MAX_SUBJECTS:
        _refuse("wrong-edge")
    return sorted(subjects, key=lambda item: item["name"])


def _validate_asset_name(name):
    normalized = name.lower()
    if any(token in normalized for token in ("latest", "manifest", "provenance")):
        _refuse("wrong-edge")


def _validate_sorted_unique(values, key, code):
    entries = [value[key] for value in values]
    if entries != sorted(entries) or len(entries) != len(set(entries)):
        _refuse(code)


def _validate_profile_relations(statement, release_manifest):
    predicate = statement["predicate"]
    _validate_sorted_unique(predicate["pins"]["sourcePins"], "sourceId", "invalid-profile")
    _validate_sorted_unique(predicate["edges"]["artifacts"], "name", "wrong-edge")
    _validate_sorted_unique(predicate["edges"]["linuxSignatures"], "name", "wrong-edge")
    expected_subjects = _manifest_subjects(release_manifest)
    if predicate["edges"] != release_manifest:
        _refuse("wrong-edge")
    if predicate["pins"]["sbom"]["sha256"] != predicate["edges"]["sbom"]["sha256"]:
        _refuse("wrong-edge")
    expected_names = [item["name"] for item in expected_subjects]
    actual_names = [item["name"] for item in statement["subject"]]
    if actual_names != expected_names:
        _refuse("wrong-edge")
    if statement["subject"] != expected_subjects:
        _refuse("altered-subject")
    if statement["subject"] != _manifest_subjects(predicate["edges"]):
        _refuse("wrong-edge")


def _validate_expected_context(expected_context):
    _validate_schema(
        expected_context,
        EXPECTED_CONTEXT_SCHEMA,
        "expectedContext",
        "invalid-context",
    )
    evidence = expected_context["buildEvidence"]
    if evidence["inputManifestSha256"] != expected_context["buildInputManifestSha256"]:
        _refuse("invalid-context")


def _validate_allowed_signers(allowed_signers, signer):
    if type(allowed_signers) is not dict or set(allowed_signers) != {"release-role"}:
        _refuse("wrong-signer")
    key_ids = allowed_signers["release-role"]
    if type(key_ids) is not list or not 1 <= len(key_ids) <= 16:
        _refuse("wrong-signer")
    for key_id in key_ids:
        if (
            type(key_id) is not str
            or len(key_id) > MAX_IDENTIFIER_LENGTH
            or re.fullmatch(IDENTIFIER_PATTERN, key_id) is None
        ):
            _refuse("wrong-signer")
    if signer["role"] != "release-role" or signer["keyId"] not in key_ids:
        _refuse("wrong-signer")


def signature_message(statement_bytes, key_id):
    """Build provenance signing bytes for the authorized release-role key."""

    statement = parse_canonical_statement(statement_bytes)
    if type(key_id) is not str:
        _refuse("wrong-signer")
    if len(key_id) > MAX_IDENTIFIER_LENGTH or re.fullmatch(IDENTIFIER_PATTERN, key_id) is None:
        _refuse("wrong-signer")
    signed_payload = {
        "schema": 1,
        "role": PROVENANCE_DOCUMENT_ROLE,
        "key_id": key_id,
        "payload": statement,
    }
    domain = (SIGNATURE_DOMAIN_PREFIX + PROVENANCE_DOCUMENT_ROLE).encode("ascii") + bytes((0,))
    return domain + encode_canonical_json(signed_payload)


def verify_statement(
    statement_bytes,
    release_manifest,
    expected_context,
    allowed_signers,
    signature,
    signature_verifier,
    envelope_role,
    envelope_key_id,
):
    """Verify a Statement against an authenticated manifest projection and run context.

    The caller authenticates and projects the release-set manifest before passing it here.
    The injected verifier checks the provenance-domain message and signature bytes.
    """

    statement = parse_canonical_statement(statement_bytes)
    predicate = statement["predicate"]
    _validate_expected_context(expected_context)
    _validate_profile_relations(statement, release_manifest)
    signer = predicate["signer"]
    if envelope_role != PROVENANCE_DOCUMENT_ROLE or envelope_key_id != signer["keyId"]:
        _refuse("wrong-signer")
    _validate_allowed_signers(allowed_signers, signer)
    if signer != expected_context["signer"]:
        _refuse("wrong-signer")
    if (
        predicate["release"] != expected_context["release"]
        or predicate["buildInputManifestSha256"]
        != expected_context["buildInputManifestSha256"]
        or predicate["buildEvidence"] != expected_context["buildEvidence"]
        or predicate["pins"] != expected_context["pins"]
    ):
        _refuse("stale-build")
    if predicate["buildEvidence"]["inputManifestSha256"] != predicate[
        "buildInputManifestSha256"
    ]:
        _refuse("stale-build")
    if type(signature) is not bytes or not 1 <= len(signature) <= MAX_SIGNATURE_BYTES:
        _refuse("invalid-signature")
    if not callable(getattr(signature_verifier, "verify", None)):
        _refuse("invalid-signature")
    message = signature_message(statement_bytes, envelope_key_id)
    try:
        verified = signature_verifier.verify(message, signature)
    except Exception:
        _refuse("invalid-signature")
    if verified is not True:
        _refuse("invalid-signature")
    return VerificationResult(
        profile_version=PROFILE_VERSION,
        statement_sha256=hashlib.sha256(statement_bytes).hexdigest(),
        subject_names=tuple(item["name"] for item in statement["subject"]),
        signer_role=signer["role"],
        signer_key_id=signer["keyId"],
    )
