import json
import os
import re
import sys
import urllib.error
import urllib.request


API_ROOT = "https://api.github.com"
REPOSITORY = "keeldock-platform/platform-ci"
MODE = "synthetic"
MAX_BODY_BYTES = 1048576
SHA_PATTERN = re.compile(r"[a-f0-9]{40}")
REASONS = ("identity", "api", "freshness", "untrusted")
UNTRUSTED_STATES = ("absent", "equal", "behind")
COMPARE_ANCESTOR = ("identical", "ahead")


class SettingsRefusal(Exception):
    def __init__(self, reason):
        if reason not in REASONS:
            reason = "identity"
        super().__init__(reason)
        self.reason = reason


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *arguments, **keywords):
        return None


def fetch(path, token, opener=None):
    request = urllib.request.Request(
        API_ROOT + path,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "kd-linux-settings",
        },
    )
    client = urllib.request.build_opener(NoRedirect()) if opener is None else opener
    try:
        with client.open(request, timeout=20) as response:
            status = response.status
            body = response.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read(MAX_BODY_BYTES + 1)
    except (OSError, urllib.error.URLError):
        raise SettingsRefusal("api")
    if status == 404:
        return None
    if status != 200 or len(body) > MAX_BODY_BYTES:
        raise SettingsRefusal("api")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise SettingsRefusal("api")
    if type(value) is not dict:
        raise SettingsRefusal("api")
    return value


def reference_sha(payload, expected_ref):
    if payload is None:
        return None
    target = payload.get("object")
    if payload.get("ref") != expected_ref or type(target) is not dict:
        raise SettingsRefusal("api")
    sha = target.get("sha")
    if type(sha) is not str or SHA_PATTERN.fullmatch(sha) is None:
        raise SettingsRefusal("api")
    return sha


def validate_identity(environ):
    required = {
        "CI_EVENT_NAME": "workflow_dispatch",
        "CI_REF": "refs/heads/main",
        "CI_REPOSITORY": REPOSITORY,
    }
    for name, value in required.items():
        if environ.get(name) != value:
            raise SettingsRefusal("identity")
    sha = environ.get("CI_SHA", "")
    if SHA_PATTERN.fullmatch(sha) is None or not environ.get("GITHUB_TOKEN"):
        raise SettingsRefusal("identity")
    return sha


def settings(environ, opener=None):
    sha = validate_identity(environ)
    token = environ["GITHUB_TOKEN"]
    base = "/repos/" + REPOSITORY
    live_main = reference_sha(fetch(base + "/git/ref/heads/main", token, opener), "refs/heads/main")
    if live_main != sha:
        raise SettingsRefusal("freshness")
    untrusted = reference_sha(fetch(base + "/git/ref/heads/untrusted", token, opener), "refs/heads/untrusted")
    if untrusted is None:
        return "absent"
    if untrusted == live_main:
        return "equal"
    comparison = fetch(base + "/compare/" + untrusted + "..." + live_main, token, opener)
    if comparison is None or comparison.get("status") not in COMPARE_ANCESTOR:
        raise SettingsRefusal("untrusted")
    return "behind" if comparison["status"] == "ahead" else "equal"


def write_output(environ, state):
    path = environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "at", encoding="ascii") as sink:
        sink.write("mode=" + MODE + chr(10) + "untrusted=" + state + chr(10))


def main(environ=None, opener=None):
    values = os.environ if environ is None else environ
    try:
        state = settings(values, opener)
    except SettingsRefusal as refusal:
        sys.stdout.write("linux-source-settings=refused mode=" + MODE + " reason=" + refusal.reason + chr(10))
        return 1
    write_output(values, state)
    sys.stdout.write(
        "linux-source-settings=verified mode=" + MODE + " freshness=current untrusted=" + state + chr(10)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
