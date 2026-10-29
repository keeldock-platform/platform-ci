import io
import json
import os
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import linux_settings as settings


__all__ = ["LinuxSettingsTests"]

MAIN = "a" * 40
OTHER = "b" * 40
BASE = "/repos/keeldock-platform/platform-ci"


class Response:
    def __init__(self, status, payload):
        self.status = status
        self.body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False

    def read(self, count):
        return self.body[:count]


class Opener:
    def __init__(self, routes):
        self.routes = routes
        self.requested = []

    def open(self, request, timeout=None):
        path = request.full_url[len(settings.API_ROOT):]
        self.requested.append((path, request.get_header("Authorization"), timeout))
        route = self.routes[path]
        if isinstance(route, BaseException):
            raise route
        status, payload = route
        if status != 200:
            raise urllib.error.HTTPError(request.full_url, status, "status", {}, io.BytesIO(json.dumps(payload).encode()))
        return Response(status, payload)


def ref(name, sha):
    return (200, {"ref": "refs/heads/" + name, "object": {"sha": sha}})


def environ(**changes):
    values = {
        "CI_EVENT_NAME": "workflow_dispatch",
        "CI_REF": "refs/heads/main",
        "CI_REPOSITORY": "keeldock-platform/platform-ci",
        "CI_SHA": MAIN,
        "GITHUB_TOKEN": "test-token-value",
    }
    values.update(changes)
    return values


def routes(untrusted, comparison=None, main=MAIN):
    table = {BASE + "/git/ref/heads/main": ref("main", main), BASE + "/git/ref/heads/untrusted": untrusted}
    if comparison is not None:
        table[BASE + "/compare/" + OTHER + "..." + main] = comparison
    return table


class LinuxSettingsTests(unittest.TestCase):
    def refused(self, values, table):
        with self.assertRaises(settings.SettingsRefusal) as raised:
            settings.settings(values, Opener(table))
        return raised.exception.reason

    def test_fresh_main_with_each_untrusted_state_is_verified(self):
        self.assertEqual(settings.settings(environ(), Opener(routes((404, {})))), "absent")
        self.assertEqual(settings.settings(environ(), Opener(routes(ref("untrusted", MAIN)))), "equal")
        behind = routes(ref("untrusted", OTHER), (200, {"status": "ahead"}))
        self.assertEqual(settings.settings(environ(), Opener(behind)), "behind")
        identical = routes(ref("untrusted", OTHER), (200, {"status": "identical"}))
        self.assertEqual(settings.settings(environ(), Opener(identical)), "equal")

    def test_a_stale_dispatch_sha_is_refused_as_not_fresh(self):
        self.assertEqual(self.refused(environ(), routes((404, {}), main=OTHER)), "freshness")

    def test_untrusted_ahead_diverged_or_unresolvable_is_refused(self):
        for status in ("behind", "diverged", "other"):
            table = routes(ref("untrusted", OTHER), (200, {"status": status}))
            self.assertEqual(self.refused(environ(), table), "untrusted")
        self.assertEqual(self.refused(environ(), routes(ref("untrusted", OTHER), (404, {}))), "untrusted")

    def test_identity_must_be_the_dispatched_main_control_of_the_fixed_repository(self):
        for name, value in (
            ("CI_EVENT_NAME", "push"),
            ("CI_REF", "refs/heads/untrusted"),
            ("CI_REPOSITORY", "someone/else"),
            ("CI_SHA", "A" * 40),
            ("CI_SHA", "short"),
            ("GITHUB_TOKEN", ""),
        ):
            with self.subTest(name=name, value=value):
                self.assertEqual(self.refused(environ(**{name: value}), routes((404, {}))), "identity")

    def test_api_failures_malformed_replies_and_redirects_are_refused(self):
        for table in (
            {BASE + "/git/ref/heads/main": (500, {})},
            {BASE + "/git/ref/heads/main": OSError("down")},
            {BASE + "/git/ref/heads/main": (200, {"ref": "refs/heads/other", "object": {"sha": MAIN}})},
            {BASE + "/git/ref/heads/main": (200, {"ref": "refs/heads/main", "object": {"sha": "xyz"}})},
            {BASE + "/git/ref/heads/main": (200, {"ref": "refs/heads/main"})},
        ):
            self.assertEqual(self.refused(environ(), table), "api")
        self.assertIsNone(settings.NoRedirect().redirect_request(None, None, 302, "x", {}, "http://elsewhere.invalid"))

    def test_requests_use_the_fixed_api_host_bearer_token_and_a_timeout(self):
        opener = Opener(routes((404, {})))
        settings.settings(environ(), opener)
        for path, authorization, timeout in opener.requested:
            self.assertTrue(path.startswith(BASE))
            self.assertEqual(authorization, "Bearer test-token-value")
            self.assertEqual(timeout, 20)
        self.assertEqual(settings.API_ROOT, "https://api.github.com")

    def test_main_prints_closed_lines_and_writes_step_outputs(self):
        with tempfile.TemporaryDirectory() as base:
            path = os.path.join(base, "output")
            out = io.StringIO()
            values = environ(GITHUB_OUTPUT=path)
            with patch("linux_settings.sys.stdout", out):
                self.assertEqual(settings.main(values, Opener(routes(ref("untrusted", MAIN)))), 0)
            self.assertEqual(
                out.getvalue(),
                "linux-source-settings=verified mode=synthetic freshness=current untrusted=equal\n",
            )
            with open(path) as source:
                self.assertEqual(source.read(), "mode=synthetic\nuntrusted=equal\n")
            out = io.StringIO()
            with patch("linux_settings.sys.stdout", out):
                self.assertEqual(settings.main(environ(CI_EVENT_NAME="push"), Opener({})), 1)
            self.assertEqual(out.getvalue(), "linux-source-settings=refused mode=synthetic reason=identity\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
