import io
import json
import unittest
from unittest.mock import patch

import macos_source_reader as source_reader


TOKEN = "t" * 80
OLDER_TOKEN = "o" * 40
REPOSITORY_ID = 246813579
FULL_NAME = "owner/project"


def environment(**changes):
    value = {
        source_reader.TOKEN_ENV: TOKEN,
        source_reader.REPOSITORY_ID_ENV: str(REPOSITORY_ID),
    }
    value.update(changes)
    return value


def repository_list(**changes):
    repository = {
        "id": REPOSITORY_ID,
        "full_name": FULL_NAME,
        "private": True,
        "permissions": {
            "pull": True,
            "push": False,
            "admin": False,
        },
    }
    repository.update(changes)
    return json.dumps({"total_count": 1, "repositories": [repository]}).encode("utf-8")


def metadata(**changes):
    value = {
        "id": REPOSITORY_ID,
        "full_name": FULL_NAME,
        "private": True,
    }
    value.update(changes)
    return json.dumps(value).encode("utf-8")


def successful_exchange_sequence():
    return (
        (200, repository_list()),
        (200, metadata()),
        (204, b""),
        (401, b""),
    )


class SourceReaderPreflightTests(unittest.TestCase):
    def test_success_checks_exact_private_repository_and_confirms_revocation(self):
        with patch.object(source_reader, "_exchange", side_effect=successful_exchange_sequence()) as exchange:
            result = source_reader.run(environment())

        self.assertEqual(
            result,
            {
                "schema_version": 1,
                "status": "passed",
                "reason": "ok",
                "repository_scope": "verified",
                "metadata": "verified",
                "revocation": "confirmed",
            },
        )
        calls = exchange.call_args_list
        self.assertEqual([call.args[0] for call in calls], ["GET", "GET", "DELETE", "GET"])
        self.assertEqual([call.args[1] for call in calls], [
            source_reader.LIST_PATH,
            "/repos/" + FULL_NAME,
            source_reader.REVOKE_PATH,
            source_reader.LIST_PATH,
        ])
        self.assertTrue(all(call.args[2] == TOKEN for call in calls))
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertEqual(
            set(result),
            {"schema_version", "status", "reason", "repository_scope", "metadata", "revocation"},
        )

    def test_accepts_opaque_short_and_long_token_formats(self):
        for token in (OLDER_TOKEN, TOKEN):
            with self.subTest(length=len(token)):
                with patch.object(source_reader, "_exchange", side_effect=successful_exchange_sequence()):
                    result = source_reader.run(environment(**{source_reader.TOKEN_ENV: token}))
                self.assertEqual(result["status"], "passed")

    def test_absent_and_null_repository_permission_metadata_are_accepted(self):
        absent = json.loads(repository_list())
        del absent["repositories"][0]["permissions"]
        responses = (
            (200, json.dumps(absent).encode("utf-8")),
            (200, metadata()),
            (204, b""),
            (401, b""),
        )
        with patch.object(source_reader, "_exchange", side_effect=responses):
            absent_result = source_reader.run(environment())

        with patch.object(
            source_reader,
            "_exchange",
            side_effect=((200, repository_list(permissions=None)), (200, metadata()), (204, b""), (401, b"")),
        ):
            null_result = source_reader.run(environment())

        self.assertEqual(absent_result["status"], "passed")
        self.assertEqual(null_result["status"], "passed")

    def test_rejects_repository_scope_mismatch_and_still_revokes(self):
        responses = (
            (200, repository_list(id=REPOSITORY_ID + 1)),
            (204, b""),
            (401, b""),
        )
        with patch.object(source_reader, "_exchange", side_effect=responses) as exchange:
            result = source_reader.run(environment())

        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["reason"], "repository_id_invalid")
        self.assertEqual(result["repository_scope"], "unverified")
        self.assertEqual(result["revocation"], "confirmed")
        self.assertEqual(exchange.call_count, 3)

    def test_rejects_multiple_visible_repositories_and_still_revokes(self):
        response = json.dumps({"total_count": 2, "repositories": [{"id": REPOSITORY_ID}]}).encode("utf-8")
        with patch.object(source_reader, "_exchange", side_effect=((200, response), (204, b""), (401, b""))):
            result = source_reader.run(environment())

        self.assertEqual(result["reason"], "repository_count_invalid")
        self.assertEqual(result["revocation"], "confirmed")

    def test_scope_failures_have_fixed_subreasons_and_keep_the_legacy_parser_closed(self):
        malformed = b'{"total_count":1,"repositories":[]}private-detail'
        invalid_count_shape = json.dumps({"total_count": True, "repositories": []}).encode("utf-8")
        missing_repositories = json.dumps({"total_count": 1}).encode("utf-8")
        invalid_repositories_shape = json.dumps({"total_count": 1, "repositories": {}}).encode("utf-8")
        invalid_repository_row = json.dumps({"total_count": 1, "repositories": ["private-detail"]}).encode("utf-8")
        extra_repository = json.dumps({
            "total_count": 1,
            "repositories": [{"id": REPOSITORY_ID}, {"id": REPOSITORY_ID + 1}],
        }).encode("utf-8")
        invalid_name = repository_list(full_name="opaque-owner/invalid/extra")
        cases = (
            (malformed, "repository_schema_invalid"),
            (invalid_count_shape, "repository_schema_invalid"),
            (missing_repositories, "repository_schema_invalid"),
            (invalid_repositories_shape, "repository_schema_invalid"),
            (invalid_repository_row, "repository_schema_invalid"),
            (extra_repository, "repository_count_invalid"),
            (repository_list(id=REPOSITORY_ID + 1), "repository_id_invalid"),
            (repository_list(private=False), "repository_private_invalid"),
            (repository_list(permissions=[]), "repository_permissions_invalid"),
            (invalid_name, "repository_name_invalid"),
        )
        for body, expected_reason in cases:
            with self.subTest(reason=expected_reason):
                full_name, diagnostic = source_reader._repository_entry_diagnostic(body, REPOSITORY_ID)
                self.assertIsNone(full_name)
                self.assertEqual(diagnostic, expected_reason)
                self.assertIsNone(source_reader._repository_entry(body, REPOSITORY_ID))
                responses = ((200, body), (204, b""), (401, b""))
                with patch.object(source_reader, "_exchange", side_effect=responses) as exchange:
                    result = source_reader.run(environment())
                self.assertEqual(result["reason"], expected_reason)
                self.assertEqual(result["repository_scope"], "unverified")
                self.assertEqual(result["metadata"], "unverified")
                self.assertEqual(result["revocation"], "confirmed")
                self.assertEqual(set(result), {
                    "schema_version", "status", "reason", "repository_scope", "metadata", "revocation",
                })
                self.assertEqual([call.args[0] for call in exchange.call_args_list], ["GET", "DELETE", "GET"])
                self.assertNotIn("opaque-owner/invalid/extra", json.dumps(result))
                self.assertNotIn("private-detail", json.dumps(result))

    def test_accepts_role_permission_metadata_without_treating_it_as_app_scope(self):
        response = repository_list(permissions={"pull": True, "push": True, "admin": True})
        with patch.object(
            source_reader,
            "_exchange",
            side_effect=((200, response), (200, metadata()), (204, b""), (401, b"")),
        ) as exchange:
            result = source_reader.run(environment())

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["repository_scope"], "verified")
        self.assertEqual(result["metadata"], "verified")
        self.assertEqual([call.args[0] for call in exchange.call_args_list], ["GET", "GET", "DELETE", "GET"])

    def test_rejects_nonobject_repository_permission_metadata_and_still_revokes(self):
        for permissions in ([], "pull", True, 1):
            with self.subTest(permission_shape=type(permissions).__name__):
                response = repository_list(permissions=permissions)
                with patch.object(
                    source_reader,
                    "_exchange",
                    side_effect=((200, response), (204, b""), (401, b"")),
                ) as exchange:
                    result = source_reader.run(environment())

                self.assertEqual(result["reason"], "repository_permissions_invalid")
                self.assertEqual(result["revocation"], "confirmed")
                self.assertEqual([call.args[0] for call in exchange.call_args_list], ["GET", "DELETE", "GET"])

    def test_metadata_failure_still_revokes(self):
        responses = (
            (200, repository_list()),
            (404, b"private response"),
            (204, b""),
            (401, b""),
        )
        with patch.object(source_reader, "_exchange", side_effect=responses):
            result = source_reader.run(environment())

        self.assertEqual(result["reason"], "metadata_unavailable")
        self.assertEqual(result["repository_scope"], "verified")
        self.assertEqual(result["metadata"], "unverified")
        self.assertEqual(result["revocation"], "confirmed")
        self.assertNotIn("private response", json.dumps(result))

    def test_a_non_401_after_revoke_is_not_revocation_proof(self):
        for status in (403, 404, None):
            with self.subTest(status=status):
                responses = (
                    (200, repository_list()),
                    (200, metadata()),
                    (204, b""),
                    (status, b""),
                )
                with patch.object(source_reader, "_exchange", side_effect=responses):
                    result = source_reader.run(environment())
                self.assertEqual(result["status"], "refused")
                self.assertEqual(result["reason"], "revocation_unconfirmed")
                self.assertEqual(result["revocation"], "unconfirmed")

    def test_non_204_revoke_is_not_revocation_proof(self):
        with patch.object(
            source_reader,
            "_exchange",
            side_effect=((200, repository_list()), (200, metadata()), (403, b"")),
        ) as exchange:
            result = source_reader.run(environment())

        self.assertEqual(result["reason"], "revocation_unconfirmed")
        self.assertEqual(result["revocation"], "unconfirmed")
        self.assertEqual(exchange.call_count, 3)

    def test_configuration_failure_with_header_safe_token_is_still_revoke_attempted(self):
        with patch.object(source_reader, "_exchange", side_effect=((204, b""), (401, b""))) as exchange:
            result = source_reader.run(environment(**{source_reader.REPOSITORY_ID_ENV: "1/2"}))

        self.assertEqual(result["reason"], "configuration_invalid")
        self.assertEqual(result["revocation"], "confirmed")
        self.assertEqual([call.args[0] for call in exchange.call_args_list], ["DELETE", "GET"])

    def test_exchange_refuses_unlisted_paths_without_opening_network(self):
        with patch.object(source_reader.urllib.request, "build_opener") as build_opener:
            status, body = source_reader._exchange("GET", "https://example.invalid/path", TOKEN)

        self.assertIsNone(status)
        self.assertEqual(body, b"")
        build_opener.assert_not_called()

    def test_exchange_uses_fixed_api_host_and_disables_environment_proxies(self):
        class Response:
            def getcode(self):
                return 204

            def close(self):
                return None

        class Opener:
            def __init__(self):
                self.request = None

            def open(self, request, timeout):
                self.request = request
                return Response()

        opener = Opener()
        with patch.object(source_reader.urllib.request, "build_opener", return_value=opener) as build_opener:
            status, body = source_reader._exchange("DELETE", source_reader.REVOKE_PATH, TOKEN)

        self.assertEqual(status, 204)
        self.assertEqual(body, b"")
        proxy_handler = build_opener.call_args.args[0]
        self.assertIsInstance(proxy_handler, source_reader.urllib.request.ProxyHandler)
        self.assertEqual(proxy_handler.proxies, {})
        self.assertEqual(opener.request.full_url, source_reader.API_ORIGIN + source_reader.REVOKE_PATH)
        self.assertEqual(opener.request.get_method(), "DELETE")
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer " + TOKEN)

    def test_duplicate_json_keys_are_refused(self):
        body = b'{"total_count":1,"total_count":1,"repositories":[]}'
        self.assertIsNone(source_reader._json_object(body))

    def test_extra_cli_arguments_refuse_preflight_but_still_revoke(self):
        environment_values = environment()
        responses = ((204, b""), (401, b""))
        with patch.dict(source_reader.os.environ, environment_values):
            with patch.object(source_reader, "_exchange", side_effect=responses) as exchange:
                with patch.object(source_reader.sys, "stdout", io.StringIO()) as output:
                    exit_code = source_reader.main(["unexpected"])
        self.assertEqual(exit_code, 1)
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertIn('"reason":"arguments_invalid"', output.getvalue())
        self.assertEqual([call.args[0] for call in exchange.call_args_list], ["DELETE", "GET"])

    def test_unexpected_transport_exception_is_sanitized_and_cleanup_is_attempted(self):
        with patch.object(
            source_reader,
            "_exchange",
            side_effect=(RuntimeError("secret response"), (204, b""), (401, b"")),
        ) as exchange:
            result = source_reader.run(environment())

        self.assertEqual(result["reason"], "internal_error")
        self.assertEqual(result["revocation"], "confirmed")
        self.assertNotIn("secret response", json.dumps(result))
        self.assertEqual(exchange.call_count, 3)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
