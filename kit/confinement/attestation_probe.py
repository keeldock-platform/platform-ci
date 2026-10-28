import argparse
import json
from pathlib import Path


MAX_JSON_BYTES = 1048576
CLAIM_ALIASES = {
    "audience": frozenset(("aud", "audience", "audiences")),
    "issuer": frozenset(("iss", "issuer")),
    "job_id": frozenset(("jobid", "checkrunid")),
    "run_attempt": frozenset(("runattempt",)),
    "run_id": frozenset(("runid",)),
}
CLAIM_ORDER = ("audience", "issuer", "job_id", "run_attempt", "run_id")


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


def _normalise_key(value):
    return "".join(character.lower() for character in value if character.isalnum())


def _certificate_documents(document):
    certificates = []
    pending = [document]
    certificate_names = frozenset(("certificate", "certificates", "signingcertificate"))
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                if _normalise_key(key) in certificate_names:
                    if isinstance(item, dict):
                        certificates.append(item)
                    elif isinstance(item, list):
                        certificates.extend(entry for entry in item if isinstance(entry, dict))
                elif isinstance(item, (dict, list)):
                    pending.append(item)
        elif isinstance(value, list):
            pending.extend(value)
    return certificates


def _scalar_values(document, aliases):
    found = []
    pending = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                if _normalise_key(key) in aliases:
                    if isinstance(item, list):
                        found.extend(entry for entry in item if isinstance(entry, (str, int)) and not isinstance(entry, bool))
                    elif isinstance(item, (str, int)) and not isinstance(item, bool):
                        found.append(item)
                if isinstance(item, (dict, list)):
                    pending.append(item)
        elif isinstance(value, list):
            pending.extend(value)
    return found


def _expected_values(expected):
    return {
        "audience": frozenset((expected["audience"],)),
        "issuer": frozenset((expected["issuer"],)),
        "job_id": frozenset((expected["job_id"],)),
        "run_attempt": frozenset((str(expected["run_attempt"]),)),
        "run_id": frozenset((str(expected["run_id"]),)),
    }


def evaluate_mapping(document, expected):
    present = []
    missing = []
    mismatched = []
    accepted = _expected_values(expected)
    certificates = _certificate_documents(document)
    for claim in CLAIM_ORDER:
        values = [
            item
            for certificate in certificates
            for item in _scalar_values(certificate, CLAIM_ALIASES[claim])
        ]
        if not values:
            missing.append(claim)
            continue
        present.append(claim)
        if any(str(value) not in accepted[claim] for value in values):
            mismatched.append(claim)
    if missing:
        return "unavailable", tuple(present)
    if mismatched:
        return "mismatch", tuple(present)
    return "available", tuple(present)


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
    result, claims = evaluate_mapping(document, expected)
    claim_text = ",".join(claims) if claims else "none"
    print("mapping=" + result + " claims=" + claim_text)
    return result


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
            document = load_json(arguments.jobs_file)
            print(job_identifier(document, arguments.name))
            return 0
        document = load_json(arguments.verified_file)
        expected = {
            "audience": arguments.audience,
            "issuer": arguments.issuer,
            "job_id": arguments.job_id,
            "run_attempt": arguments.run_attempt,
            "run_id": arguments.run_id,
        }
        _print_mapping(document, expected)
        return 0
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        print("mapping=unavailable claims=none")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
