import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request


API_ORIGIN = "https://api.github.com"
API_VERSION = "2026-03-10"
TOKEN_ENV = "SOURCE_READER_TOKEN"
REPOSITORY_ID_ENV = "SOURCE_REPOSITORY_ID"
LIST_PATH = "/installation/repositories?per_page=100"
REVOKE_PATH = "/installation/token"
MAX_RESPONSE_BYTES = 65536
REQUEST_TIMEOUT_SECONDS = 15
REPOSITORY_ID_PATTERN = re.compile(r"[1-9][0-9]{0,18}\Z")
SAFE_TOKEN_PATTERN = re.compile(r"[!-~]{1,4096}\Z")
TOKEN_PATTERN = SAFE_TOKEN_PATTERN
FULL_NAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
METADATA_PATH_PATTERN = re.compile(r"/repos/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
REASONS = frozenset((
    "token_unavailable", "arguments_invalid", "token_invalid", "configuration_invalid",
    "repository_list_unavailable", "repository_schema_invalid", "repository_count_invalid",
    "repository_id_invalid", "repository_private_invalid", "repository_permissions_invalid",
    "repository_name_invalid", "metadata_unavailable", "ok", "revocation_unconfirmed",
    "internal_error",
))


def _record(status, reason, repository_scope, metadata, revocation):
    if type(reason) is not str or reason not in REASONS:
        reason = "internal_error"
    return {
        "schema_version": 1,
        "status": status,
        "reason": reason,
        "repository_scope": repository_scope,
        "metadata": metadata,
        "revocation": revocation,
    }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _allowed_request(method, path):
    if method == "GET" and path == LIST_PATH:
        return True
    if method == "DELETE" and path == REVOKE_PATH:
        return True
    return method == "GET" and type(path) is str and METADATA_PATH_PATTERN.fullmatch(path) is not None


def _exchange(method, path, token):
    if not _allowed_request(method, path):
        return None, b""
    if type(token) is not str or SAFE_TOKEN_PATTERN.fullmatch(token) is None:
        return None, b""
    request = urllib.request.Request(
        API_ORIGIN + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "User-Agent": "source-reader-preflight",
            "X-GitHub-Api-Version": API_VERSION,
        },
        method=method,
    )
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        response = opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS)
    except urllib.error.HTTPError as error:
        try:
            return error.code, b""
        finally:
            error.close()
    except Exception:
        return None, b""
    try:
        status = response.getcode()
        if status != 200:
            return status, b""
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if type(body) is not bytes or len(body) > MAX_RESPONSE_BYTES:
            return None, b""
        return status, body
    except Exception:
        return None, b""
    finally:
        response.close()


def _json_object(body):
    if type(body) is not bytes or not body or len(body) > MAX_RESPONSE_BYTES:
        return None
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, ValueError, TypeError):
        return None
    return value if type(value) is dict else None


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _repository_permissions_metadata_shape_is_valid(value):
    permissions = value.get("permissions")
    return permissions is None or type(permissions) is dict


def _repository_entry_diagnostic(body, expected_repository_id):
    value = _json_object(body)
    if value is None or type(value.get("total_count")) is not int:
        return None, "repository_schema_invalid"
    repositories = value.get("repositories")
    if type(repositories) is not list:
        return None, "repository_schema_invalid"
    if value.get("total_count") != 1 or len(repositories) != 1:
        return None, "repository_count_invalid"
    repository = repositories[0]
    if type(repository) is not dict:
        return None, "repository_schema_invalid"
    if type(repository.get("id")) is not int or repository.get("id") != expected_repository_id:
        return None, "repository_id_invalid"
    if repository.get("private") is not True:
        return None, "repository_private_invalid"
    if not _repository_permissions_metadata_shape_is_valid(repository):
        return None, "repository_permissions_invalid"
    full_name = repository.get("full_name")
    if type(full_name) is not str or FULL_NAME_PATTERN.fullmatch(full_name) is None:
        return None, "repository_name_invalid"
    return full_name, None


def _repository_entry(body, expected_repository_id):
    full_name, unused_reason = _repository_entry_diagnostic(body, expected_repository_id)
    return full_name


def _metadata_is_positive(body, expected_repository_id, expected_full_name):
    value = _json_object(body)
    if value is None:
        return False
    return (
        type(value.get("id")) is int
        and value.get("id") == expected_repository_id
        and value.get("private") is True
        and value.get("full_name") == expected_full_name
    )


def _revoke_and_verify(token):
    try:
        status, unused_body = _exchange("DELETE", REVOKE_PATH, token)
        if status != 204:
            return False
        status, unused_body = _exchange("GET", LIST_PATH, token)
        return status == 401
    except BaseException:
        return False


def run(environ=None, preflight_allowed=True):
    environment = os.environ if environ is None else environ
    try:
        token = environment.get(TOKEN_ENV)
        repository_id_text = environment.get(REPOSITORY_ID_ENV)
    except BaseException:
        token = None
        repository_id_text = None
    if environ is None:
        os.environ.pop(TOKEN_ENV, None)

    cleanup_token = token if type(token) is str and SAFE_TOKEN_PATTERN.fullmatch(token) is not None else None
    repository_scope = "unverified"
    metadata = "unverified"
    revocation = "unconfirmed"
    reason = "token_unavailable"

    try:
        if not preflight_allowed:
            reason = "arguments_invalid"
        elif type(token) is not str or TOKEN_PATTERN.fullmatch(token) is None:
            reason = "token_invalid"
        elif type(repository_id_text) is not str or REPOSITORY_ID_PATTERN.fullmatch(repository_id_text) is None:
            reason = "configuration_invalid"
        else:
            expected_repository_id = int(repository_id_text)
            status, body = _exchange("GET", LIST_PATH, token)
            if status != 200:
                reason = "repository_list_unavailable"
            else:
                full_name, scope_reason = _repository_entry_diagnostic(body, expected_repository_id)
                if full_name is None:
                    reason = scope_reason
                else:
                    repository_scope = "verified"
                    metadata_path = "/repos/" + full_name
                    status, body = _exchange("GET", metadata_path, token)
                    if status != 200 or not _metadata_is_positive(body, expected_repository_id, full_name):
                        reason = "metadata_unavailable"
                    else:
                        metadata = "verified"
                        reason = "ok"
    except BaseException:
        reason = "internal_error"

    if cleanup_token is not None:
        if _revoke_and_verify(cleanup_token):
            revocation = "confirmed"
    if reason == "ok" and revocation != "confirmed":
        reason = "revocation_unconfirmed"

    status = "passed" if reason == "ok" and repository_scope == "verified" and metadata == "verified" and revocation == "confirmed" else "refused"
    return _record(status, reason, repository_scope, metadata, revocation)


def main(arguments=None):
    actual_arguments = sys.argv[1:] if arguments is None else arguments
    result = run(preflight_allowed=not actual_arguments)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
