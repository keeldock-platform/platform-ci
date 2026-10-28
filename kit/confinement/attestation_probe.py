import argparse
import json
from pathlib import Path


MAX_JSON_BYTES = 1048576
LEAF_SUMMARY_FIELDS = (
    "identity",
    "issuer",
    "sourceRepositoryURI",
    "buildConfigURI",
    "runInvocationURI",
)


def _pairs_without_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate-field")
        value[key] = item
    return value


def load_json(path):
    payload = Path(path).read_bytes()
    if len(payload) > MAX_JSON_BYTES:
        raise ValueError("input-too-large")
    return json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=_pairs_without_duplicates,
    )


def verified_leaf_summary(document):
    if isinstance(document, list):
        if len(document) != 1:
            return None
        document = document[0]
    if not isinstance(document, dict):
        return None
    result = document.get("verificationResult")
    if not isinstance(result, dict):
        return None
    signature = result.get("signature")
    if not isinstance(signature, dict):
        return None
    certificate = signature.get("certificate")
    if not isinstance(certificate, dict):
        return None
    return certificate


def evaluate_mapping(document, expected):
    certificate = verified_leaf_summary(document)
    if certificate is None:
        return "unavailable", ()
    present = tuple(field for field in LEAF_SUMMARY_FIELDS if field in certificate)
    return "unavailable", present


def job_identifier(document, name):
    if not isinstance(document, dict) or not isinstance(document.get("jobs"), list):
        raise ValueError("jobs-unavailable")
    matches = [
        item
        for item in document["jobs"]
        if isinstance(item, dict) and item.get("name") == name
    ]
    if len(matches) != 1:
        raise ValueError("job-not-unique")
    identifier = matches[0].get("id")
    if isinstance(identifier, bool) or not isinstance(identifier, (int, str)):
        raise ValueError("job-id-unavailable")
    if not str(identifier).isdigit():
        raise ValueError("job-id-invalid")
    return str(identifier)


def _print_mapping(document, expected):
    result, fields = evaluate_mapping(document, expected)
    field_text = ",".join(fields) if fields else "none"
    print("mapping=" + result + " leaf_fields=" + field_text)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    job_parser = commands.add_parser("job-id")
    job_parser.add_argument("--jobs-file", required=True)
    job_parser.add_argument("--name", required=True)
    evaluate_parser = commands.add_parser("evaluate")
    evaluate_parser.add_argument("--verified-file", required=True)
    evaluate_parser.add_argument("--audience", required=True)
    evaluate_parser.add_argument("--issuer", required=True)
    evaluate_parser.add_argument("--job-id", required=True)
    evaluate_parser.add_argument("--run-attempt", required=True)
    evaluate_parser.add_argument("--run-id", required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "job-id":
            print(job_identifier(load_json(arguments.jobs_file), arguments.name))
            return 0
        expected = {
            "audience": arguments.audience,
            "issuer": arguments.issuer,
            "job_id": arguments.job_id,
            "run_attempt": arguments.run_attempt,
            "run_id": arguments.run_id,
        }
        _print_mapping(load_json(arguments.verified_file), expected)
        return 0
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        print("mapping=unavailable leaf_fields=none")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
