import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.request

import cargo_lock_bootstrap as subject
import cargo_lock_receipt as cargo
import feedback_request


NOW = 1_793_160_000
EXPIRY = NOW + 3600
CHECKSUM = "a" * 64
TARGET = "aarch64-apple-darwin"
OTHER_CHECKSUM = "b" * 64
DAY = 24 * 60 * 60
LOCK_BYTES = (
    "version = 4\n\n"
    "[[package]]\n"
    'name = "contract-root"\n'
    'version = "0.1.0"\n'
    "dependencies = [\n"
    ' "serde",\n'
    "]\n\n"
    "[[package]]\n"
    'name = "serde"\n'
    'version = "1.0.200"\n'
    'source = "' + cargo.REGISTRY_SOURCE + '"\n'
    'checksum = "' + CHECKSUM + '"\n'
).encode("ascii")
CONTEXT = {
    "repository": "owner/repository",
    "workspace_path": ".",
    "source_sha": "a" * 40,
    "base_sha": "b" * 40,
    "base_branch": "develop",
    "reviewed_diff_fingerprint": "d" * 64,
    "dependency_policy_revision": subject.DEPENDENCY_POLICY_REVISION,
    "control_sha": "c" * 40,
    "toolchain_hash": "e" * 64,
}


def _created_at(age_seconds, now=NOW):
    moment = datetime.datetime.fromtimestamp(now - age_seconds, datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".123456+00:00"


class FakeFetcher:
    def __init__(self, *, age=8 * DAY, index_checksum=CHECKSUM, api_checksum=CHECKSUM,
                 index_yanked=False, api_yanked=False, index_version="1.0.200", created_at=None):
        self.calls = []
        self.age = age
        self.index_checksum = index_checksum
        self.api_checksum = api_checksum
        self.index_yanked = index_yanked
        self.api_yanked = api_yanked
        self.index_version = index_version
        self.created_at = created_at

    def index_entry(self, name):
        self.calls.append(("index", name))
        line = {
            "name": name, "vers": self.index_version, "deps": [], "cksum": self.index_checksum,
            "features": {}, "yanked": self.index_yanked,
        }
        return (json.dumps(line, sort_keys=True) + "\n").encode("ascii")

    def version_metadata(self, name, version):
        self.calls.append(("api", name, version))
        created = self.created_at if self.created_at is not None else _created_at(self.age)
        return json.dumps({"version": {
            "crate": name, "num": version, "checksum": self.api_checksum,
            "yanked": self.api_yanked, "created_at": created,
        }}).encode("ascii")


class FakeResponse:
    def __init__(self, data, url, status=200):
        self._data = data
        self._url = url
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False

    def geturl(self):
        return self._url

    def read(self, count):
        return self._data[:count]


class FakeOpener:
    def __init__(self, data=b"{}", final_url=None, status=200, error=None):
        self.requests = []
        self.data = data
        self.final_url = final_url
        self.status = status
        self.error = error

    def open(self, request, timeout=None):
        self.requests.append((request.full_url, timeout, dict(request.header_items())))
        if self.error is not None:
            raise self.error
        url = self.final_url if self.final_url is not None else request.full_url
        return FakeResponse(self.data, url, self.status)


class BootstrapTestCase(unittest.TestCase):
    def assert_refused(self, reason, function, *arguments, **keywords):
        with self.assertRaises(subject.BootstrapRefusal) as raised:
            function(*arguments, **keywords)
        self.assertEqual(raised.exception.reason, reason)
        self.assertEqual(str(raised.exception), reason)

    def receipt(self, lock_bytes=LOCK_BYTES, context=None):
        return subject.build_receipt(lock_bytes, CONTEXT if context is None else context)

    def evidence(self, fetcher, lock_bytes=LOCK_BYTES, receipt_bytes=None, context=None, **overrides):
        values = {
            "run_id": "987654321", "run_attempt": 1, "now": NOW, "expiry": EXPIRY,
            "build_inputs": {}, "fetcher": fetcher, "toolchain_target": TARGET,
        }
        values.update(overrides)
        return subject.build_evidence(
            lock_bytes, self.receipt(lock_bytes) if receipt_bytes is None else receipt_bytes,
            CONTEXT if context is None else context, **values,
        )


class ForcedSettingsTests(BootstrapTestCase):
    def test_forced_config_covers_every_setting_family_and_never_carries_a_token(self):
        items = dict(subject.forced_config_items())
        self.assertFalse([key for key in items if key.startswith("source.")])
        for key in (
            "registry.global-credential-providers", "registry.credential-provider",
            "patch.crates-io",
            "patch.crates-io", "net.offline", "net.git-fetch-with-cli", "http.proxy",
            "http.multiplexing", "http.timeout",
        ):
            with self.subTest(key=key):
                self.assertIn(key, items)
        for triple in subject.TARGET_RUNNER_TRIPLES:
            self.assertEqual(items["target." + triple + ".runner"], "[]")
        self.assertEqual(items["http.proxy"], '""')
        self.assertEqual(items["net.offline"], "false")
        self.assertEqual(items["patch.crates-io"], "{}")
        arguments = subject.bootstrap_config_arguments()
        self.assertEqual(len(arguments), 2 * len(items))
        self.assertEqual(set(arguments[0::2]), {"--config"})
        rendered = " ".join(arguments)
        self.assertTrue(rendered.isascii())
        self.assertNotIn("token=", rendered.replace("cargo:token", ""))

    def test_generate_lockfile_is_the_only_command_and_refuses_relative_paths(self):
        command = subject.generate_lockfile_command("/opt/toolchain/bin/cargo", "/work/project/Cargo.toml")
        self.assertEqual(command[0], "/opt/toolchain/bin/cargo")
        self.assertEqual(command[-3:], ("generate-lockfile", "--manifest-path", "/work/project/Cargo.toml"))
        self.assertEqual(command[1:-3], subject.bootstrap_config_arguments())
        for forbidden in ("build", "run", "test", "check", "fetch", "vendor", "--locked", "--offline"):
            self.assertNotIn(forbidden, command)
        for cargo_path, manifest in (
            ("cargo", "/work/Cargo.toml"), ("/bin/cargo", "work/Cargo.toml"),
            ("/bin/cargo", "/work/Cargo.lock"), ("/bin/cargo", "/work/Cargo.toml\n"),
        ):
            with self.subTest(cargo=cargo_path, manifest=manifest):
                self.assert_refused(
                    "bootstrap_input_invalid", subject.generate_lockfile_command, cargo_path, manifest,
                )


class EnvironmentInjectionTests(BootstrapTestCase):
    def test_inherited_cargo_rustc_proxy_and_transport_variables_never_reach_cargo(self):
        parent = {
            "PATH": "/usr/bin", "HOME": "/elsewhere/home", "LANG": "en_US.UTF-8",
            "CARGO_HOME": "/elsewhere", "CARGO_HTTP_PROXY": "x", "CARGO_BUILD_RUSTFLAGS": "-C x",
            "CARGO_REGISTRIES_CRATES_IO_TOKEN": "x", "RUSTC_WRAPPER": "/tmp/wrapper",
            "RUSTC_BOOTSTRAP": "1", "RUSTUP_TOOLCHAIN": "nightly", "RUSTFLAGS": "-C x",
            "https_proxy": "x", "HTTP_PROXY": "x", "all_proxy": "x", "NO_PROXY": "x",
            "SSL_CERT_FILE": "/tmp/ca", "CURL_CA_BUNDLE": "/tmp/ca", "GIT_ASKPASS": "/tmp/ask",
        }
        names = subject.injected_environment_names(parent)
        self.assertEqual(set(names), set(parent) - {"PATH", "HOME", "LANG"})
        environment = subject.build_cargo_environment(
            parent, cargo_home="/work/cargo-home", home="/work/home", tmpdir="/work/tmp",
            path="/opt/toolchain/bin:/usr/bin:/bin",
        )
        self.assertEqual(set(environment), {"PATH", "HOME", "CARGO_HOME", "TMPDIR", "LANG", "LC_ALL"})
        self.assertEqual(environment["CARGO_HOME"], "/work/cargo-home")
        self.assertEqual(environment["HOME"], "/work/home")
        self.assertEqual(environment["LANG"], "C")
        for name in names:
            if name != "CARGO_HOME":
                self.assertNotIn(name, environment)
        self.assertEqual(subject.injected_environment_names({"PATH": "/usr/bin"}), ())

    def test_environment_values_must_be_absolute_single_line_text(self):
        good = {"cargo_home": "/w/c", "home": "/w/h", "tmpdir": "/w/t", "path": "/usr/bin"}
        subject.build_cargo_environment({}, **good)
        for field, value in (
            ("cargo_home", "relative"), ("home", ""), ("tmpdir", "/w/t\n"), ("path", "/usr/bin\x00"),
            ("home", "/w/" + "a" * 5000),
        ):
            with self.subTest(field=field):
                changed = dict(good)
                changed[field] = value
                self.assert_refused(
                    "bootstrap_environment_refused", subject.build_cargo_environment, {}, **changed,
                )
        self.assert_refused(
            "bootstrap_environment_refused", subject.build_cargo_environment, [], **good,
        )
        self.assert_refused(
            "bootstrap_environment_refused", subject.build_cargo_environment, {1: "x"}, **good,
        )

    def test_cargo_home_must_be_a_fresh_empty_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            fresh = Path(temporary) / "cargo-home"
            fresh.mkdir()
            self.assertTrue(subject.require_fresh_directory(fresh))
            (fresh / "config.toml").write_bytes(b"x")
            self.assert_refused("bootstrap_environment_refused", subject.require_fresh_directory, fresh)
            self.assert_refused(
                "bootstrap_environment_refused", subject.require_fresh_directory, Path(temporary) / "absent",
            )
            link = Path(temporary) / "link"
            os.symlink(str(fresh), str(link))
            self.assert_refused("bootstrap_environment_refused", subject.require_fresh_directory, link)


class CargoConfigRefusalTests(BootstrapTestCase):
    def tree(self, temporary):
        root = Path(temporary) / "work" / "tree"
        (root / "crates" / "api" / "src").mkdir(parents=True)
        (root / "Cargo.toml").write_bytes(b"x")
        (root / "crates" / "api" / "src" / "lib.rs").write_bytes(b"x")
        return root

    def ambient_cargo(self, temporary):
        base = Path(temporary)
        return any(os.path.lexists(parent / ".cargo") for parent in (base,) + tuple(base.parents))

    def without_ambient_cargo(self, temporary):
        base = Path(temporary)
        ambient = (base,) + tuple(base.parents)
        real = os.path.lexists

        def lexists(path):
            candidate = Path(path)
            if candidate.name == ".cargo" and candidate.parent in ambient:
                return False
            return real(path)

        return mock.patch.object(os.path, "lexists", side_effect=lexists)

    def test_clean_tree_is_accepted_when_no_ancestor_has_cargo_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.tree(temporary)
            if self.ambient_cargo(temporary):
                self.assert_refused("bootstrap_config_refused", subject.refuse_cargo_config, root)
            else:
                self.assertTrue(subject.refuse_cargo_config(root))
            with self.without_ambient_cargo(temporary):
                self.assertTrue(subject.refuse_cargo_config(root))

    def test_any_cargo_configuration_in_the_tree_is_refused(self):
        for relative, directory in (
            (".cargo/config.toml", False), (".cargo/config", False), (".cargo", True),
            ("crates/api/.cargo/config.toml", False), (".cargo-extra", True), (".CARGO/config", False),
        ):
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as temporary:
                    root = self.tree(temporary)
                    target = root / relative
                    if directory:
                        target.mkdir(parents=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(b"[http]\nproxy = \"x\"\n")
                    with self.without_ambient_cargo(temporary):
                        self.assert_refused("bootstrap_config_refused", subject.refuse_cargo_config, root)

    def test_cargo_configuration_in_a_parent_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.tree(temporary)
            with self.without_ambient_cargo(temporary):
                self.assertTrue(subject.refuse_cargo_config(root))
            (Path(temporary) / "work" / ".cargo").mkdir()
            (Path(temporary) / "work" / ".cargo" / "config.toml").write_bytes(b"x")
            with self.without_ambient_cargo(temporary):
                self.assert_refused("bootstrap_config_refused", subject.refuse_cargo_config, root)
            self.assert_refused("bootstrap_config_refused", subject.refuse_cargo_config, root)

    def test_an_ambient_ancestor_cargo_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.tree(temporary)
            ambient = Path(temporary)
            real = os.path.lexists

            def lexists(path):
                return Path(path) == ambient / ".cargo" or real(path)

            with mock.patch.object(os.path, "lexists", side_effect=lexists):
                self.assert_refused("bootstrap_config_refused", subject.refuse_cargo_config, root)

    def test_links_and_bad_roots_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.tree(temporary)
            with self.without_ambient_cargo(temporary):
                os.symlink(str(root / "Cargo.toml"), str(root / "linked.toml"))
                self.assert_refused("bootstrap_config_refused", subject.refuse_cargo_config, root)
                self.assert_refused(
                    "bootstrap_config_refused", subject.refuse_cargo_config, Path(temporary) / "absent",
                )
                self.assert_refused("bootstrap_config_refused", subject.refuse_cargo_config, "relative/path")


class LockAndReceiptTests(BootstrapTestCase):
    def test_receipt_is_canonical_pending_and_self_checks_against_the_lock(self):
        receipt_bytes = self.receipt()
        receipt = cargo.decode_receipt(receipt_bytes)
        self.assertEqual(receipt["lock_sha256"], hashlib.sha256(LOCK_BYTES).hexdigest())
        self.assertEqual(
            receipt["packages"],
            [{"name": "serde", "version": "1.0.200", "checksum": CHECKSUM,
              "audit_record_id": subject.PENDING_AUDIT_ID}],
        )
        for field, value in CONTEXT.items():
            self.assertEqual(receipt[field], value)
        self.assertEqual(subject.self_check(LOCK_BYTES, receipt_bytes, CONTEXT), receipt)

    def test_non_crates_io_sources_are_refused(self):
        foreign = (
            "git+" + "https:" + chr(47) * 2 + "example.invalid/crate",
            "registry+" + "https:" + chr(47) * 2 + "example.invalid/index",
            "sparse+" + "https:" + chr(47) * 2 + "example.invalid/",
            "path+file:" + chr(47) * 2 + "/tmp/crate",
        )
        for source in foreign:
            with self.subTest(source=source):
                lock = LOCK_BYTES.replace(cargo.REGISTRY_SOURCE.encode("ascii"), source.encode("ascii"))
                self.assert_refused("bootstrap_source_refused", subject.build_receipt, lock, CONTEXT)
                self.assert_refused("bootstrap_source_refused", subject.parse_lock, lock)
        in_dependency = LOCK_BYTES.replace(
            b' "serde",\n', ('"serde 1.0.200 (git+' + "https:" + chr(47) * 2 + 'example.invalid/crate)",\n').encode("ascii"),
        )
        self.assert_refused("bootstrap_source_refused", subject.parse_lock, in_dependency)

    def test_sparse_and_registry_forms_of_the_fixed_source_are_accepted(self):
        sparse = LOCK_BYTES.replace(
            cargo.REGISTRY_SOURCE.encode("ascii"), cargo.SPARSE_REGISTRY_SOURCE.encode("ascii"),
        )
        receipt = subject.build_receipt(sparse, CONTEXT)
        self.assertEqual(cargo.decode_receipt(receipt)["packages"][0]["name"], "serde")

    def test_locks_without_registry_packages_and_malformed_locks_are_refused(self):
        workspace_only = (
            "version = 4\n\n[[package]]\n"
            'name = "contract-root"\nversion = "0.1.0"\n'
        ).encode("ascii")
        self.assert_refused("bootstrap_lock_refused", subject.build_receipt, workspace_only, CONTEXT)
        for bad in (b"", b"not a lock\n", LOCK_BYTES + b"\xff", LOCK_BYTES.replace(b"version = 4", b"version = 9")):
            with self.subTest(size=len(bad)):
                with self.assertRaises(subject.BootstrapRefusal):
                    subject.build_receipt(bad, CONTEXT)

    def test_internal_registry_names_and_oversize_locks_are_refused(self):
        internal = LOCK_BYTES.replace(b'name = "serde"', ('name = "' + "keeldock" + '-core"').encode("ascii"))
        with self.assertRaises(subject.BootstrapRefusal):
            subject.build_receipt(internal, CONTEXT)
        oversize = LOCK_BYTES + b"\n" * subject.MAX_LOCK_BYTES
        self.assert_refused("bootstrap_payload_too_large", subject.build_receipt, oversize, CONTEXT)

    def test_context_must_be_exactly_the_trusted_fields(self):
        for changed in (
            {key: value for key, value in CONTEXT.items() if key != "control_sha"},
            dict(CONTEXT, extra="x"),
            [],
        ):
            with self.subTest(size=len(changed)):
                self.assert_refused("bootstrap_input_invalid", subject.build_receipt, LOCK_BYTES, changed)


class MismatchBeforeNetworkTests(BootstrapTestCase):
    def test_lock_mismatch_refuses_before_any_registry_request(self):
        receipt_bytes = self.receipt()
        for changed in (
            LOCK_BYTES.replace(CHECKSUM.encode("ascii"), OTHER_CHECKSUM.encode("ascii")),
            LOCK_BYTES + b"\n",
            LOCK_BYTES.replace(b"1.0.200", b"1.0.201"),
        ):
            with self.subTest(size=len(changed)):
                fetcher = FakeFetcher()
                self.assert_refused(
                    "bootstrap_mismatch", self.evidence, fetcher, lock_bytes=changed,
                    receipt_bytes=receipt_bytes,
                )
                self.assertEqual(fetcher.calls, [])

    def test_receipt_mismatch_refuses_before_any_registry_request(self):
        receipt = cargo.decode_receipt(self.receipt())
        variants = []
        for field, value in (
            ("repository", "other/repository"), ("source_sha", "f" * 40), ("base_branch", "main"),
            ("control_sha", "f" * 40), ("toolchain_hash", "f" * 64),
            ("reviewed_diff_fingerprint", "f" * 64), ("workspace_path", "crates/other"),
        ):
            changed = dict(receipt)
            changed[field] = value
            variants.append(cargo.encode_receipt(changed))
        reviewed = json.loads(json.dumps(receipt))
        reviewed["packages"][0]["audit_record_id"] = "audit-serde-1"
        variants.append(cargo.encode_receipt(reviewed))
        wrong_checksum = json.loads(json.dumps(receipt))
        wrong_checksum["packages"][0]["checksum"] = OTHER_CHECKSUM
        variants.append(cargo.encode_receipt(wrong_checksum))
        variants.append(self.receipt() + b" ")
        variants.append(b"{}")
        variants.append(b"")
        for index, receipt_bytes in enumerate(variants):
            with self.subTest(variant=index):
                fetcher = FakeFetcher()
                self.assert_refused("bootstrap_mismatch", self.evidence, fetcher, receipt_bytes=receipt_bytes)
                self.assertEqual(fetcher.calls, [])

    def test_trusted_context_mismatch_refuses_before_any_registry_request(self):
        for field, value in (("source_sha", "f" * 40), ("base_sha", "f" * 40), ("control_sha", "f" * 40)):
            with self.subTest(field=field):
                fetcher = FakeFetcher()
                self.assert_refused(
                    "bootstrap_mismatch", self.evidence, fetcher, context=dict(CONTEXT, **{field: value}),
                    receipt_bytes=self.receipt(),
                )
                self.assertEqual(fetcher.calls, [])

    def test_foreign_source_oversize_and_bad_inputs_refuse_before_any_registry_request(self):
        receipt_bytes = self.receipt()
        foreign = LOCK_BYTES.replace(
            cargo.REGISTRY_SOURCE.encode("ascii"),
            ("git+" + "https:" + chr(47) * 2 + "example.invalid/crate").encode("ascii"),
        )
        cases = (
            ("bootstrap_source_refused", {"lock_bytes": foreign}),
            ("bootstrap_payload_too_large", {"lock_bytes": LOCK_BYTES + b"\n" * subject.MAX_LOCK_BYTES}),
            ("bootstrap_build_input_refused", {"build_inputs": {"LIBSQLITE3_FLAGS": "-DX"}}),
            ("bootstrap_input_invalid", {"run_id": "0"}),
            ("bootstrap_input_invalid", {"run_attempt": 2}),
            ("bootstrap_stale", {"expiry": NOW}),
            ("bootstrap_stale", {"expiry": NOW + subject.MAX_REQUEST_TTL_SECONDS + 1}),
        )
        for reason, overrides in cases:
            with self.subTest(reason=reason, overrides=sorted(overrides)):
                fetcher = FakeFetcher()
                self.assert_refused(
                    reason, self.evidence, fetcher, receipt_bytes=receipt_bytes, **overrides,
                )
                self.assertEqual(fetcher.calls, [])
        self.assert_refused("bootstrap_input_invalid", self.evidence, None, receipt_bytes=receipt_bytes)


class EvidenceTests(BootstrapTestCase):
    def test_evidence_records_index_hash_checksum_and_creation_time_for_each_package(self):
        fetcher = FakeFetcher()
        evidence = self.evidence(fetcher)
        self.assertEqual(fetcher.calls, [("index", "serde"), ("api", "serde", "1.0.200")])
        record = json.loads(evidence)
        self.assertEqual(set(record), set(subject.EVIDENCE_FIELDS))
        self.assertEqual(record["receipt_sha256"], hashlib.sha256(self.receipt()).hexdigest())
        self.assertEqual(record["lock_sha256"], hashlib.sha256(LOCK_BYTES).hexdigest())
        self.assertEqual(record["generated_at"], NOW)
        self.assertEqual(record["expiry"], EXPIRY)
        self.assertEqual(record["build_inputs"], {})
        item = record["packages"][0]
        self.assertEqual(item["checksum"], CHECKSUM)
        self.assertEqual(
            item["index_entry_sha256"], hashlib.sha256(FakeFetcher().index_entry("serde")).hexdigest(),
        )
        self.assertRegex(item["created_at"], r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$")

    def test_a_package_younger_than_seven_full_days_is_refused(self):
        self.assert_refused(
            "bootstrap_package_too_young", self.evidence, FakeFetcher(age=7 * DAY - 1),
        )
        self.assert_refused(
            "bootstrap_package_too_young", self.evidence, FakeFetcher(age=DAY),
        )
        self.assertTrue(self.evidence(FakeFetcher(age=7 * DAY)))

    def test_yanked_packages_are_refused_from_either_registry_source(self):
        self.assert_refused("bootstrap_package_yanked", self.evidence, FakeFetcher(index_yanked=True))
        self.assert_refused("bootstrap_package_yanked", self.evidence, FakeFetcher(api_yanked=True))

    def test_registry_evidence_that_disagrees_with_the_lock_is_refused(self):
        for fetcher in (
            FakeFetcher(index_checksum=OTHER_CHECKSUM),
            FakeFetcher(api_checksum=OTHER_CHECKSUM),
            FakeFetcher(index_version="1.0.199"),
            FakeFetcher(created_at="not a time"),
            FakeFetcher(created_at=_created_at(-2 * DAY)),
            FakeFetcher(created_at="2026-02-30T00:00:00+00:00"),
            FakeFetcher(created_at="2026-02-01T00:00:00+02:00"),
        ):
            with self.subTest(calls=len(fetcher.calls)):
                self.assert_refused("bootstrap_evidence_invalid", self.evidence, fetcher)

    def test_fetcher_results_must_be_bytes(self):
        class BadFetcher(FakeFetcher):
            def index_entry(self, name):
                return "not bytes"

        self.assert_refused("bootstrap_evidence_invalid", self.evidence, BadFetcher())


class RegistryFetcherTests(BootstrapTestCase):
    def test_index_paths_follow_the_sparse_layout(self):
        self.assertEqual(subject.index_path("a"), "/1/a")
        self.assertEqual(subject.index_path("Ab"), "/2/ab")
        self.assertEqual(subject.index_path("abc"), "/3/a/abc")
        self.assertEqual(subject.index_path("serde"), "/se/rd/serde")
        for bad in ("", "../x", "a/b", "-a", "a b", "a" * 65, 1):
            with self.subTest(name=bad):
                self.assert_refused("bootstrap_input_invalid", subject.index_path, bad)

    def test_requests_use_only_the_two_fixed_origins_without_a_proxy(self):
        opener = FakeOpener(b"payload")
        fetcher = subject.RegistryFetcher(opener)
        self.assertEqual(fetcher.index_entry("serde"), b"payload")
        self.assertEqual(fetcher.version_metadata("serde", "1.0.200"), b"payload")
        self.assertEqual(
            [item[0] for item in opener.requests],
            [
                "https:" + chr(47) * 2 + "index.crates.io/se/rd/serde",
                "https:" + chr(47) * 2 + "crates.io/api/v1/crates/serde/1.0.200",
            ],
        )
        for unused_url, timeout, headers in opener.requests:
            self.assertEqual(timeout, subject.FETCH_TIMEOUT_SECONDS)
            self.assertEqual(headers.get("User-agent"), subject.USER_AGENT)
        default = subject.RegistryFetcher()
        self.assertIsInstance(default._proxy_handler, urllib.request.ProxyHandler)
        self.assertEqual(default._proxy_handler.proxies, {})
        self.assertEqual(
            [handler for handler in default._opener.handlers
             if isinstance(handler, urllib.request.ProxyHandler) and handler.proxies],
            [],
        )
        self.assertFalse(any(
            hasattr(handler, "https_open") and isinstance(handler, urllib.request.ProxyHandler)
            for handler in default._opener.handlers
        ))
        self.assertTrue(any(isinstance(handler, subject._NoRedirect) for handler in default._opener.handlers))

    def test_redirects_errors_bad_status_and_oversize_bodies_are_refused(self):
        self.assertIsNone(subject._NoRedirect().redirect_request(None, None, 302, "Found", {}, "x"))
        cases = (
            FakeOpener(final_url="https:" + chr(47) * 2 + "elsewhere.invalid/x"),
            FakeOpener(status=301),
            FakeOpener(b""),
            FakeOpener(b"x" * (subject.MAX_INDEX_ENTRY_BYTES + 1)),
            FakeOpener(error=urllib.error.URLError("refused")),
            FakeOpener(error=OSError("down")),
        )
        for opener in cases:
            with self.subTest(requests=len(opener.requests)):
                self.assert_refused(
                    "bootstrap_network_refused", subject.RegistryFetcher(opener).index_entry, "serde",
                )
        self.assert_refused(
            "bootstrap_network_refused",
            subject.RegistryFetcher(FakeOpener(b"x" * (subject.MAX_API_BYTES + 1))).version_metadata,
            "serde", "1.0.200",
        )
        self.assert_refused(
            "bootstrap_input_invalid", subject.RegistryFetcher(FakeOpener()).version_metadata,
            "serde", "../1",
        )


class BundleTests(BootstrapTestCase):
    def produce(self, **overrides):
        values = {
            "run_id": "987654321", "run_attempt": 1, "now": NOW, "expiry": EXPIRY,
            "build_inputs": {}, "fetcher": FakeFetcher(), "toolchain_target": TARGET,
        }
        values.update(overrides)
        return subject.produce_bundle(LOCK_BYTES, CONTEXT, **values)

    def test_bundle_round_trips_and_re_verifies(self):
        bundle = self.produce()
        lock_bytes, receipt_bytes, evidence_bytes = subject.verify_bundle(bundle, CONTEXT, now=NOW + 60)
        self.assertEqual(lock_bytes, LOCK_BYTES)
        self.assertEqual(receipt_bytes, self.receipt())
        self.assertEqual(subject.decode_bundle(bundle), (lock_bytes, receipt_bytes, evidence_bytes))
        record = json.loads(bundle)
        self.assertEqual(sorted(record), ["evidence_b64", "lock_b64", "receipt_b64", "schema_version"])
        self.assertEqual(bundle, json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii"))
        self.assertFalse(bundle.endswith(b"\n"))

    def test_a_stale_or_replayed_bundle_is_refused_at_verification(self):
        bundle = self.produce()
        self.assert_refused("bootstrap_stale", subject.verify_bundle, bundle, CONTEXT, now=EXPIRY)
        self.assert_refused("bootstrap_stale", subject.verify_bundle, bundle, CONTEXT, now=EXPIRY + DAY)
        self.assert_refused("bootstrap_stale", subject.verify_bundle, bundle, CONTEXT, now=NOW - 3600)
        self.assert_refused(
            "bootstrap_mismatch", subject.verify_bundle, bundle, dict(CONTEXT, source_sha="f" * 40), now=NOW,
        )

    def test_oversize_payloads_are_refused_at_every_member_and_at_the_bundle(self):
        evidence = self.evidence(FakeFetcher())
        receipt = self.receipt()
        self.assert_refused(
            "bootstrap_payload_too_large", subject.encode_bundle,
            b"x" * (subject.MAX_LOCK_BYTES + 1), receipt, evidence,
        )
        self.assert_refused(
            "bootstrap_payload_too_large", subject.encode_bundle,
            LOCK_BYTES, b"x" * (subject.MAX_RECEIPT_BYTES + 1), evidence,
        )
        self.assert_refused(
            "bootstrap_payload_too_large", subject.encode_bundle,
            LOCK_BYTES, receipt, b"x" * (subject.MAX_EVIDENCE_BYTES + 1),
        )
        self.assert_refused(
            "bootstrap_payload_too_large", subject.decode_bundle, b"x" * (subject.MAX_BUNDLE_BYTES + 1),
        )
        maximum = subject.encode_bundle(
            b"x" * subject.MAX_LOCK_BYTES, b"x" * subject.MAX_RECEIPT_BYTES,
            b"x" * subject.MAX_EVIDENCE_BYTES,
        )
        self.assertLessEqual(len(maximum), subject.MAX_BUNDLE_BYTES)
        oversize_member = {
            "schema_version": 1,
            "lock_b64": base64.b64encode(b"x" * (subject.MAX_LOCK_BYTES + 1)).decode("ascii"),
            "receipt_b64": base64.b64encode(receipt).decode("ascii"),
            "evidence_b64": base64.b64encode(evidence).decode("ascii"),
        }
        self.assert_refused(
            "bootstrap_payload_too_large", subject.decode_bundle,
            json.dumps(oversize_member, sort_keys=True, separators=(",", ":")).encode("ascii"),
        )

    def test_non_canonical_bundles_are_refused(self):
        bundle = self.produce()
        record = json.loads(bundle)
        variants = (
            bundle + b"\n",
            b" " + bundle,
            json.dumps(record, sort_keys=False, indent=1).encode("ascii"),
            json.dumps(dict(record, extra="AAAA"), sort_keys=True, separators=(",", ":")).encode("ascii"),
            json.dumps(dict(record, schema_version=2), sort_keys=True, separators=(",", ":")).encode("ascii"),
            json.dumps(dict(record, lock_b64="AAA"), sort_keys=True, separators=(",", ":")).encode("ascii"),
            json.dumps(dict(record, lock_b64=""), sort_keys=True, separators=(",", ":")).encode("ascii"),
            b"{}", b"[]", b"", b"\xff",
        )
        for index, variant in enumerate(variants):
            with self.subTest(variant=index):
                with self.assertRaises(subject.BootstrapRefusal):
                    subject.decode_bundle(variant)

    def test_tampered_evidence_is_refused(self):
        bundle = self.produce()
        lock_bytes, receipt_bytes, evidence_bytes = subject.decode_bundle(bundle)
        record = json.loads(evidence_bytes)
        for field, value in (
            ("receipt_sha256", "f" * 64), ("lock_sha256", "f" * 64), ("index_origin", "other"),
            ("minimum_age_seconds", 1), ("run_attempt", 2), ("toolchain_target", "bad"), ("build_inputs", {"LIBSQLITE3_FLAGS": "x"}),
        ):
            with self.subTest(field=field):
                changed = json.dumps(dict(record, **{field: value}), sort_keys=True,
                                     separators=(",", ":")).encode("ascii")
                with self.assertRaises(subject.BootstrapRefusal):
                    subject.validate_evidence(changed, receipt_bytes, lock_bytes, now=NOW)
        young = json.loads(evidence_bytes)
        young["packages"][0]["created_at"] = _created_at(DAY).split(".")[0] + "Z"
        self.assert_refused(
            "bootstrap_package_too_young", subject.validate_evidence,
            json.dumps(young, sort_keys=True, separators=(",", ":")).encode("ascii"),
            receipt_bytes, lock_bytes, now=NOW,
        )
        self.assert_refused(
            "bootstrap_evidence_invalid", subject.validate_evidence, evidence_bytes + b" ",
            receipt_bytes, lock_bytes, now=NOW,
        )
        self.assert_refused(
            "bootstrap_payload_too_large", subject.validate_evidence,
            b"x" * (subject.MAX_EVIDENCE_BYTES + 1), receipt_bytes, lock_bytes, now=NOW,
        )


class BuildInputPlaceholderTests(BootstrapTestCase):
    def test_the_allowlist_is_empty_and_matches_the_profile(self):
        self.assertEqual(subject.BUILD_INPUT_ALLOWLIST, ())
        profile = feedback_request.PROFILE_BY_KIND["cargo_lock"]
        self.assertEqual(profile["build_inputs"], subject.BUILD_INPUT_ALLOWLIST)
        self.assertEqual(subject.validate_build_inputs({}), {})

    def test_anything_not_allowlisted_is_refused(self):
        for inputs in (
            {"LIBSQLITE3_FLAGS": "-DSQLITE_ENABLE_FTS5"}, {"CC": "/tmp/cc"}, {"RUSTFLAGS": "-C x"},
            {"": "x"}, {1: "x"}, [], None, "LIBSQLITE3_FLAGS",
        ):
            with self.subTest(inputs=repr(inputs)):
                self.assert_refused("bootstrap_build_input_refused", subject.validate_build_inputs, inputs)

    def test_an_allowlisted_name_still_needs_a_bounded_printable_ascii_value(self):
        allowed = ("LIBSQLITE3_FLAGS",)
        self.assertEqual(
            subject.validate_build_inputs({"LIBSQLITE3_FLAGS": "-DX"}, allowed), {"LIBSQLITE3_FLAGS": "-DX"},
        )
        for value in ("", "a" * 257, "line\nbreak", "caf" + chr(233), 1):
            with self.subTest(value=repr(value)):
                self.assert_refused(
                    "bootstrap_build_input_refused", subject.validate_build_inputs,
                    {"LIBSQLITE3_FLAGS": value}, allowed,
                )
        self.assert_refused(
            "bootstrap_build_input_refused", subject.validate_build_inputs,
            {"LIBSQLITE3_FLAGS": "x", "OTHER": "y"}, allowed,
        )


class ProfileLimitTests(BootstrapTestCase):
    def test_module_limits_equal_the_registered_profile_and_never_reuse_the_node_limit(self):
        profile = feedback_request.PROFILE_BY_KIND["cargo_lock"]
        self.assertEqual(subject.MAX_BUNDLE_BYTES, profile["max_payload_bytes"])
        self.assertEqual(subject.MAX_LOCK_BYTES, feedback_request.CARGO_LOCK_MAX_LOCK_BYTES)
        self.assertEqual(subject.MAX_RECEIPT_BYTES, feedback_request.CARGO_LOCK_MAX_RECEIPT_BYTES)
        self.assertEqual(subject.MAX_EVIDENCE_BYTES, feedback_request.CARGO_LOCK_MAX_EVIDENCE_BYTES)
        self.assertEqual(subject.MAX_PACKAGES, feedback_request.CARGO_LOCK_MAX_PACKAGES)
        node_limit = feedback_request.PROFILE_BY_KIND["lock"]["max_payload_bytes"]
        self.assertLess(profile["max_payload_bytes"], node_limit)

    def test_more_than_the_package_limit_is_refused(self):
        lines = ["version = 4\n"]
        for index in range(subject.MAX_PACKAGES + 1):
            lines.append(
                '\n[[package]]\nname = "crate-' + str(index) + '"\nversion = "1.0.0"\n'
                'source = "' + cargo.REGISTRY_SOURCE + '"\nchecksum = "' + CHECKSUM + '"\n'
            )
        lock = "".join(lines).encode("ascii")
        self.assertLessEqual(len(lock), subject.MAX_LOCK_BYTES)
        self.assert_refused("bootstrap_lock_refused", subject.build_receipt, lock, CONTEXT)


MEMBERS = ("crates/host/api", "crates/host/mock", "crates/host/conformance")
HASH = "\x23"
ROOT_MANIFEST = (
    "[workspace]\n"
    'members = [\n  "crates/host/api",\n  "crates/host/mock",\n  "crates/host/conformance",\n]\n'
    'resolver = "2"\n\n[workspace.dependencies]\nserde = "=1.0.200"\n'
)
API_MANIFEST = (
    HASH + " a comment\n"
    '[package]\nname = "host-api"\nversion = "0.1.0"\nedition = "2024"\n\n'
    "[dependencies]\n"
    'serde = { version = "=1.0.200", features = [\n  "derive",\n], default-features = false }\n'
    'shared = { workspace = true }\n'
)
MOCK_MANIFEST = (
    '[package]\nname = "host-mock"\nversion = "0.1.0"\nedition = "2024"\n\n'
    '[dependencies]\nhost-api = { path = "../api", version = "=0.1.0" }\n\n'
    '[dev-dependencies]\nserde_json = "=1.0.100"\n\n'
    '[build-dependencies]\ncc = "=1.0.83"\n\n'
    "[target.'cfg(unix)'.dependencies]\nlibc = \"=0.2.150\"\n"
)
CONFORMANCE_MANIFEST = (
    '[package]\nname = "host-conformance"\nversion = "0.1.0"\nedition = "2024"\n\n'
    '[dependencies.host-mock]\npath = "../mock"\n'
)


CONTRACT_MEMBERS = ("crates/host/api", "crates/host/mock", "crates/host/conformance", "crates/kernel/i18n")
CONTRACT_EXCLUDE = (
    "crates/host/core", "crates/host/registry", "crates/host/extensions", "crates/host/links",
    "crates/host/mcp", "crates/host/mcp-host", "crates/host/mcp-shim", "crates/host/settings-schema",
    "crates/services", "crates/apps", "apps",
)
PRIVATE_PREFIX = "keeldock" + "-"


def _contract_root(exclude=CONTRACT_EXCLUDE):
    listing = "".join('    "' + item + '",\n' for item in exclude)
    return (
        "[workspace]\n"
        'resolver = "3"\n'
        "members = [\n"
        '    "crates/host/api",\n    "crates/host/mock",\n    "crates/host/conformance",\n'
        '    "crates/kernel/i18n",\n'
        "]\n"
        "exclude = [\n" + listing + "]\n\n"
        "[workspace.package]\n"
        'version = "0.1.0"\nedition = "2024"\nrust-version = "1.99.1"\npublish = false\n\n'
        "[workspace.dependencies]\n"
        + PRIVATE_PREFIX + 'host-api = { path = "crates/host/api" }\n'
        + PRIVATE_PREFIX + 'host-mock = { path = "crates/host/mock" }\n\n'
        "[workspace.lints.rust]\n"
        'unsafe_code = "forbid"\nunsafe_op_in_unsafe_fn = "deny"\nmissing_docs = "warn"\n'
        'unreachable_pub = "warn"\nwarnings = "deny"\n\n'
        "[workspace.lints.clippy]\n"
        'all = { level = "warn", priority = -1 }\nunwrap_used = "deny"\nexpect_used = "deny"\n'
        'panic = "deny"\nindexing_slicing = "deny"\ncast_possible_truncation = "deny"\n'
        'undocumented_unsafe_blocks = "deny"\n'
    )


def _contract_member(name, description, dependencies="", dev_dependencies=""):
    return (
        '[package]\nname = "' + PRIVATE_PREFIX + name + '"\n'
        'description = "' + description + '"\n'
        "version.workspace = true\nedition.workspace = true\n"
        "rust-version.workspace = true\npublish.workspace = true\n\n"
        "[dependencies]\n" + dependencies + "\n"
        + ("[dev-dependencies]\n" + dev_dependencies + "\n" if dev_dependencies else "")
        + "[lints]\nworkspace = true\n"
    )


def _contract_manifests(root=None):
    host_api = PRIVATE_PREFIX + "host-api = { workspace = true }\n"
    host_mock = PRIVATE_PREFIX + "host-mock = { workspace = true }\n"
    first_batch = (
        'serde = { version = "=1.0.229", default-features = false, features = ["derive", "std"] }\n'
        'serde_json = { version = "=1.0.154", default-features = false, features = ["std"] }\n'
        'schemars = { version = "=1.2.3", default-features = false, features = ["derive", "std"] }\n'
    )
    return {
        "Cargo.toml": (_contract_root() if root is None else root).encode("utf-8"),
        "crates/host/api/Cargo.toml": _contract_member(
            "host-api", "KeelDock L1 host API: the stable contract between the host and its tools.",
            first_batch,
        ).encode("utf-8"),
        "crates/host/mock/Cargo.toml": _contract_member(
            "host-mock", "KeelDock mock host: an honest in-memory host for tool contract tests.", host_api,
        ).encode("utf-8"),
        "crates/host/conformance/Cargo.toml": _contract_member(
            "host-conformance", "KeelDock conformance suite written against the host API traits.",
            host_api, host_mock,
        ).encode("utf-8"),
        "crates/kernel/i18n/Cargo.toml": _contract_member(
            "kernel-i18n",
            "KeelDock shared kernel contract for localized message keys, patterns and catalogues.",
        ).encode("utf-8"),
    }


def _manifests(api=API_MANIFEST, root=ROOT_MANIFEST):
    return {
        "Cargo.toml": root.encode("utf-8"),
        "crates/host/api/Cargo.toml": api.encode("utf-8"),
        "crates/host/mock/Cargo.toml": MOCK_MANIFEST.encode("utf-8"),
        "crates/host/conformance/Cargo.toml": CONFORMANCE_MANIFEST.encode("utf-8"),
    }


class ManifestCheckTests(BootstrapTestCase):
    def test_pinned_registry_and_member_path_dependencies_are_accepted(self):
        names = subject.check_manifests(_manifests(), MEMBERS)
        self.assertEqual(names, frozenset(("host-api", "host-mock", "host-conformance")))

    def test_every_non_pinned_or_non_member_dependency_form_is_refused(self):
        git = "https:" + chr(47) * 2 + "example.invalid/crate"
        dependencies = (
            'a = { git = "' + git + '" }',
            'a = { git = "' + git + '", rev = "abc" }',
            'a = { version = "=1.0.0", registry = "other" }',
            'a = { version = "=1.0.0", registry-index = "' + git + '" }',
            'a = { path = "../../outside" }',
            'a = { path = "/etc/crate" }',
            'a = { path = "../other" }',
            'a = { path = "../api/.." }',
            'a = "1.0.0"',
            'a = "^1.0.0"',
            'a = "=1.0"',
            'a = "*"',
            'a = { version = "1.0.0" }',
            'a = { features = ["x"] }',
            'a = { version = "=1.0.0", artifact = "bin" }',
            'a = { workspace = true, version = "=1.0.0" }',
            'a = { workspace = false }',
            'a = { version = "=1.0.0", optional = "yes" }',
            'a = { version = "=1.0.0", features = [1] }',
            'a = 3',
            "a.git = '" + git + "'",
            'a = { version = "=1.0.0", package = "../x" }',
        )
        for line in dependencies:
            with self.subTest(dependency=line):
                with self.assertRaises(subject.BootstrapRefusal) as raised:
                    subject.check_manifests(
                        _manifests(api='[package]\nname = "host-api"\nedition = "2024"\n\n[dependencies]\n' + line + "\n"),
                        MEMBERS,
                    )
                self.assertEqual(raised.exception.reason, "bootstrap_manifest_refused")

    def test_dependency_tables_of_every_kind_are_checked(self):
        git = "https:" + chr(47) * 2 + "example.invalid/crate"
        bad = 'a = { git = "' + git + '" }\n'
        sections = (
            "[dev-dependencies]\n" + bad,
            "[build-dependencies]\n" + bad,
            "[target.'cfg(unix)'.dependencies]\n" + bad,
            "[target.'cfg(target_os = \"linux\")'.dev-dependencies]\n" + bad,
            "[target.x86_64-pc-windows-msvc.build-dependencies]\n" + bad,
            "[dependencies.a]\ngit = \"" + git + "\"\n",
            "[workspace.dependencies]\n" + bad,
            "[dependencies]\n\n[dependencies.a]\nversion = \"1.0.0\"\n",
        )
        for section in sections:
            with self.subTest(section=section):
                with self.assertRaises(subject.BootstrapRefusal):
                    subject.check_manifests(
                        _manifests(api='[package]\nname = "host-api"\nedition = "2024"\n\n' + section), MEMBERS,
                    )
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_manifests(_manifests(root=ROOT_MANIFEST + bad), MEMBERS)
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_manifests(
                _manifests(root=ROOT_MANIFEST.replace("[workspace.dependencies]\n", "[workspace.dependencies]\n" + bad)),
                MEMBERS,
            )

    def test_patch_replace_and_source_sections_are_refused_in_any_manifest(self):
        git = "https:" + chr(47) * 2 + "example.invalid/crate"
        sections = (
            "[patch.crates-io]\na = { git = \"" + git + "\" }\n",
            "[patch.\"" + git + "\"]\na = { path = \"/abs\" }\n",
            "[patch.crates-io]\n",
            "[replace]\n",
            "[replace.\"a:1.0.0\"]\ngit = \"" + git + "\"\n",
            "[source.crates-io]\nreplace-with = \"x\"\n",
            "[source.x]\ndirectory = \"/tmp/x\"\n",
            "patch.crates-io.a = { path = \"/abs\" }\n",
            "[workspace.patch.crates-io]\n",
            "[target.'cfg(unix)'.patch.crates-io]\n",
        )
        for section in sections:
            for position in ("root", "member"):
                with self.subTest(section=section, position=position):
                    with self.assertRaises(subject.BootstrapRefusal) as raised:
                        if position == "root":
                            subject.check_manifests(_manifests(root=section + ROOT_MANIFEST), MEMBERS)
                        else:
                            subject.check_manifests(
                                _manifests(api=section + API_MANIFEST),
                                MEMBERS,
                            )
                    self.assertEqual(raised.exception.reason, "bootstrap_manifest_refused")

    def test_anything_that_cannot_be_parsed_fails_closed(self):
        broken = (
            '[package]\nname = "unterminated\n',
            '[package]\nname = """multi\nline"""\n',
            "[package]\nname = 'a\\b'\n",
            "[package]\nname = 1979-05-27\n",
            "[package]\nname = \n",
            "[package]\nname = \"a\" extra\n",
            '[package]\nname = "a"\nname = "b"\n',
            "[package]\nname = \"a\"\n[package]\nversion = \"1\"\n",
            "[dependencies]\na = { version = \"=1.0.0\"\n",
            "[dependencies\na = \"=1.0.0\"\n",
            "[dependencies]\na b = \"=1.0.0\"\n",
            "[[dependencies]]\n",
            "[[bin]]\nname = \"a\"\n[bin.extra]\n",
            "[package]\nname = [[[[[[[[[[1]]]]]]]]]]\n",
            "[package]\nversion = \"1\"\n",
            "[package]\nname = 7\n",
        )
        for text in broken:
            with self.subTest(text=text):
                with self.assertRaises(subject.BootstrapRefusal) as raised:
                    subject.check_manifests(_manifests(api=text), MEMBERS)
                self.assertEqual(raised.exception.reason, "bootstrap_manifest_refused")
        for data in (b"", b"\xff\xfe", b"x" * (subject.MAX_MANIFEST_BYTES + 1), b"a = 1\n" * (subject.MAX_MANIFEST_LINES + 1), None):
            with self.subTest(size=len(data) if data is not None else -1):
                manifests = _manifests()
                manifests["crates/host/api/Cargo.toml"] = data
                with self.assertRaises(subject.BootstrapRefusal):
                    subject.check_manifests(manifests, MEMBERS)

    def test_manifest_set_must_be_the_root_and_fixed_members_only(self):
        for mutate in (
            lambda m: m.pop("Cargo.toml"),
            lambda m: m.update({"crates/other/Cargo.toml": b"[package]\nname = \"x\"\n"}),
            lambda m: m.update({"../Cargo.toml": b""}),
            lambda m: m.update({"crates/host/api/Cargo.lock": b""}),
            lambda m: m.clear(),
        ):
            manifests = _manifests()
            mutate(manifests)
            with self.subTest(keys=sorted(manifests)):
                with self.assertRaises(subject.BootstrapRefusal):
                    subject.check_manifests(manifests, MEMBERS)
        for manifests, members in ((None, MEMBERS), ([], MEMBERS), (_manifests(), "crates/host/api")):
            with self.assertRaises(subject.BootstrapRefusal):
                subject.check_manifests(manifests, members)
        duplicate = _manifests()
        duplicate["crates/host/mock/Cargo.toml"] = API_MANIFEST.encode("utf-8")
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_manifests(duplicate, MEMBERS)

    def assert_manifest_refused(self, manifests):
        with self.assertRaises(subject.BootstrapRefusal) as raised:
            subject.check_manifests(manifests, MEMBERS)
        self.assertEqual(raised.exception.reason, "bootstrap_manifest_refused")

    def test_underscore_dependency_tables_are_refused_at_top_level(self):
        git = "https:" + chr(47) * 2 + "example.invalid/crate"
        for table in ("dev_dependencies", "build_dependencies"):
            for body in ('a = { git = "' + git + '" }\n', 'a = "=1.0.0"\n'):
                with self.subTest(table=table, body=body):
                    self.assert_manifest_refused(_manifests(api=API_MANIFEST + "\n[" + table + "]\n" + body))

    def test_underscore_dependency_tables_are_refused_under_target_tables(self):
        git = "https:" + chr(47) * 2 + "example.invalid/crate"
        for header in (
            "[target.'cfg(unix)'.dev_dependencies]",
            "[target.'cfg(unix)'.build_dependencies]",
            "[target.x86_64-pc-windows-msvc.dev_dependencies]",
            "[target.x86_64-pc-windows-msvc.build_dependencies]",
            "[target.'cfg(unix)'.unknown]",
        ):
            with self.subTest(header=header):
                self.assert_manifest_refused(
                    _manifests(api=API_MANIFEST + "\n" + header + '\na = { git = "' + git + '" }\n')
                )

    def test_project_and_other_unknown_tables_are_refused(self):
        for section in (
            '[project]\nname = "host-api"\nedition = "2024"\n',
            '[badges]\nmaintenance = "x"\n',
            "[unknown]\na = 1\n",
            "[cargo-features]\n",
            "unknown_key = 1\n",
        ):
            with self.subTest(section=section):
                self.assert_manifest_refused(_manifests(api=API_MANIFEST + "\n" + section))
        self.assert_manifest_refused(
            _manifests(api='[project]\nname = "host-api"\nedition = "2024"\n')
        )

    def test_every_package_must_declare_edition_2024(self):
        base = '[package]\nname = "host-api"\nversion = "0.1.0"\n'
        for api in (
            base,
            base + 'edition = "2021"\n',
            base + 'edition = "2018"\n',
            base + "edition = 2024\n",
            base + 'edition = "2025"\n',
            base + 'edition = { workspace = false }\n',
            base + "edition.workspace = true\n",
        ):
            with self.subTest(api=api):
                self.assert_manifest_refused(_manifests(api=api))
        mock = dict(_manifests())
        mock["crates/host/mock/Cargo.toml"] = MOCK_MANIFEST.replace('edition = "2024"\n', "").encode("utf-8")
        self.assert_manifest_refused(mock)

    def test_edition_may_be_inherited_only_from_a_workspace_edition_2024(self):
        inherited = '[package]\nname = "host-api"\nversion = "0.1.0"\nedition.workspace = true\n'
        shared = ROOT_MANIFEST + '\n[workspace.package]\nedition = "2024"\n'
        self.assertEqual(
            subject.check_manifests(_manifests(api=inherited, root=shared), MEMBERS),
            frozenset(("host-api", "host-mock", "host-conformance")),
        )
        for root in (
            ROOT_MANIFEST,
            ROOT_MANIFEST + '\n[workspace.package]\nedition = "2021"\n',
            ROOT_MANIFEST + "\n[workspace.package]\nversion = \"0.1.0\"\n",
        ):
            with self.subTest(root=root):
                self.assert_manifest_refused(_manifests(api=inherited, root=root))

    def test_package_workspace_key_is_refused(self):
        for key in ('workspace = "../.."', 'workspace = "."', "workspace = true"):
            with self.subTest(key=key):
                self.assert_manifest_refused(_manifests(api=API_MANIFEST.replace(
                    'edition = "2024"\n', 'edition = "2024"\n' + key + "\n", 1,
                )))

    def test_workspace_members_must_be_exactly_the_fixed_members(self):
        def root_with(members):
            return ROOT_MANIFEST.replace(
                '  "crates/host/conformance",\n', "".join('  "' + item + '",\n' for item in members[2:]),
            ).replace('  "crates/host/mock",\n', '  "' + members[1] + '",\n').replace(
                '  "crates/host/api",\n', '  "' + members[0] + '",\n',
            )

        for members in (
            ("crates/host/api", "crates/host/mock"),
            ("crates/host/api", "crates/host/mock", "crates/host/conformance", "crates/host/extra"),
            ("crates/host/api", "crates/host/api", "crates/host/mock"),
            ("crates/host/*", "crates/host/mock", "crates/host/conformance"),
            ("crates/host/api", "crates/host/mock", "crates/other"),
        ):
            with self.subTest(members=members):
                self.assert_manifest_refused(_manifests(root=root_with(members)))
        for root in (
            ROOT_MANIFEST.replace("members =", "unlisted ="),
            ROOT_MANIFEST.replace(ROOT_MANIFEST.split("\n\n", 1)[0], '[workspace]\nmembers = "crates/host/api"'),
            '[package]\nname = "host-root"\nedition = "2024"\n',
        ):
            with self.subTest(root=root):
                self.assert_manifest_refused(_manifests(root=root))
        member_workspace = _manifests(api=API_MANIFEST + "\n[workspace]\nmembers = []\n")
        self.assert_manifest_refused(member_workspace)

    def test_exclude_and_default_members_are_refused_unless_they_match_the_fixed_expectation(self):
        listing = '[\n  "crates/host/api",\n  "crates/host/mock",\n  "crates/host/conformance",\n]'
        accepted = (
            ROOT_MANIFEST.replace('resolver = "2"', 'resolver = "2"\nexclude = []'),
            ROOT_MANIFEST.replace('resolver = "2"', 'resolver = "2"\ndefault-members = ' + listing),
        )
        for root in accepted:
            with self.subTest(root=root):
                self.assertTrue(subject.check_manifests(_manifests(root=root), MEMBERS))
        refused = (
            ROOT_MANIFEST.replace('resolver = "2"', 'resolver = "2"\nexclude = ["crates/host/api"]'),
            ROOT_MANIFEST.replace('resolver = "2"', 'resolver = "2"\nexclude = "x"'),
            ROOT_MANIFEST.replace('resolver = "2"', 'resolver = "2"\ndefault-members = ["crates/host/api"]'),
            ROOT_MANIFEST.replace('resolver = "2"', 'resolver = "2"\ndefault-members = []'),
            ROOT_MANIFEST.replace('resolver = "2"', 'resolver = "2"\ndefault-members = ["../x"]'),
            ROOT_MANIFEST.replace('resolver = "2"', 'resolver = "2"\ndefault-members = "crates/host/api"'),
            ROOT_MANIFEST.replace('resolver = "2"', 'resolver = "2"\npatch = 1'),
        )
        for root in refused:
            with self.subTest(root=root):
                self.assert_manifest_refused(_manifests(root=root))

    def test_contract_workspace_exclude_list_is_accepted_with_the_four_members(self):
        names = subject.check_manifests(_contract_manifests(), CONTRACT_MEMBERS)
        self.assertEqual(names, frozenset(
            (PRIVATE_PREFIX + "host-api", PRIVATE_PREFIX + "host-mock",
             PRIVATE_PREFIX + "host-conformance", PRIVATE_PREFIX + "kernel-i18n"),
        ))
        for exclude in ((), ("apps",), CONTRACT_EXCLUDE[:3], tuple("dir" + str(index) for index in range(64))):
            with self.subTest(exclude=exclude):
                root = _contract_root(exclude)
                self.assertTrue(subject.check_manifests(_contract_manifests(root), CONTRACT_MEMBERS))

    def test_contract_workspace_accepts_only_the_exact_first_batch_member_pins(self):
        manifests = _contract_manifests()
        names = subject.check_manifests(manifests, CONTRACT_MEMBERS)
        self.assertEqual(len(names), 4)
        path = "crates/host/api/Cargo.toml"
        for old, new in (
            ('version = "=1.0.229"', 'version = "^1.0.229"'),
            ('features = ["derive", "std"]', 'features = ["derive"]'),
            ('serde_json = { version = "=1.0.154"', 'extra = { version = "=1.0.154"'),
        ):
            changed = dict(manifests)
            changed[path] = manifests[path].replace(old.encode("ascii"), new.encode("ascii"), 1)
            with self.subTest(old=old, new=new):
                with self.assertRaises(subject.BootstrapRefusal):
                    subject.check_manifests(changed, CONTRACT_MEMBERS)

    def test_contract_workspace_refuses_registry_pins_in_other_members_or_root(self):
        manifests = _contract_manifests()
        mock_path = "crates/host/mock/Cargo.toml"
        changed = dict(manifests)
        changed[mock_path] = manifests[mock_path].replace(
            b"[dependencies]\n", b'[dependencies]\nserde = "=1.0.229"\n', 1,
        )
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_manifests(changed, CONTRACT_MEMBERS)
        root_path = "Cargo.toml"
        changed = dict(manifests)
        changed[root_path] = manifests[root_path].replace(
            b"[workspace.dependencies]\n",
            b'[workspace.dependencies]\nserde = "=1.0.229"\n', 1,
        )
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_manifests(changed, CONTRACT_MEMBERS)

    def test_workspace_exclude_entries_must_be_normalized_paths_outside_the_members(self):
        base = _contract_root()
        start = base.index("exclude = [")
        end = base.index("]\n", start) + 1
        refused = (
            '["/crates/host/core"]',
            '["crates/host\\\\core"]',
            '["crates/./host/core"]',
            '["crates/host/./core"]',
            '["."]',
            '["crates/../host/core"]',
            '[".."]',
            '["../crates/host/core"]',
            '["crates/host/api"]',
            '["crates/kernel/i18n"]',
            '["crates/host"]',
            '["crates"]',
            '["crates/kernel"]',
            '["crates/host/core", "crates/host/core"]',
            '[""]',
            '["crates//host/core"]',
            '["crates/host/core/"]',
            '["crates/host/co re"]',
            "[\"crates/host/c" + chr(246) + "re\"]",
            "[1]",
            "[true]",
            '[["crates/host/core"]]',
            '[{ path = "crates/host/core" }]',
            '"crates/host/core"',
            "1",
            "[" + ", ".join('"dir' + str(index) + '"' for index in range(65)) + "]",
        )
        for text in refused:
            with self.subTest(exclude=text):
                root = base[:start] + "exclude = " + text + base[end:]
                with self.assertRaises(subject.BootstrapRefusal) as raised:
                    subject.check_manifests(_contract_manifests(root), CONTRACT_MEMBERS)
                self.assertEqual(raised.exception.reason, "bootstrap_manifest_refused")

    def test_sourceless_lock_packages_must_be_exactly_the_workspace_packages(self):
        self.assertTrue(subject.check_lock_members(LOCK_BYTES, frozenset(("contract-root",))))
        for names in (frozenset(), frozenset(("other",)), frozenset(("contract-root", "extra")), ["contract-root"]):
            with self.subTest(names=repr(names)):
                self.assert_refused("bootstrap_lock_refused", subject.check_lock_members, LOCK_BYTES, names)
        with_path = LOCK_BYTES + b'\n[[package]]\nname = "stray"\nversion = "0.1.0"\n'
        self.assert_refused(
            "bootstrap_lock_refused", subject.check_lock_members, with_path, frozenset(("contract-root",)),
        )

    def test_a_bad_toolchain_target_refuses_before_any_registry_request(self):
        for target in ("", "darwin", None, "AArch64-apple-darwin"):
            with self.subTest(target=target):
                fetcher = FakeFetcher()
                self.assert_refused(
                    "bootstrap_input_invalid", self.evidence, fetcher, toolchain_target=target,
                    receipt_bytes=self.receipt(),
                )
                self.assertEqual(fetcher.calls, [])
        self.assertEqual(json.loads(self.evidence(FakeFetcher()))["toolchain_target"], TARGET)


RUNTIME_MEMBERS = subject.HOST_API_POLICY_RUNTIME_REQUIRED_MEMBER_ROOTS
RUNTIME_WAVE_70A_MEMBERS = subject.HOST_API_POLICY_RUNTIME_WAVE_70A_REQUIRED_MEMBER_ROOTS
RUNTIME_WAVE_70B_MEMBERS = subject.HOST_API_POLICY_RUNTIME_WAVE_70B_REQUIRED_MEMBER_ROOTS
RUNTIME_API_NAME = subject.HOST_API_POLICY_API_PACKAGE
RUNTIME_BASE_MEMBERS = subject.HOST_API_POLICY_RUNTIME_BASE_MEMBER_ROOTS
RUNTIME_ROOT = (
    "[workspace]\nresolver = \"3\"\nmembers = [\n"
    + "".join('    "' + root[len("runtime/"):] + '",\n' for root in RUNTIME_MEMBERS)
    + "]\n\n[workspace.package]\nversion = \"0.1.0\"\nedition = \"2024\"\n"
    + "\n[workspace.dependencies]\n" + RUNTIME_API_NAME + ' = { path = "../crates/host/api" }\n'
)
RUNTIME_BASE_ROOT = (
    "[workspace]\nresolver = \"3\"\nmembers = [\n"
    + "".join('    "' + root[len("runtime/"):] + '",\n' for root in RUNTIME_BASE_MEMBERS)
    + "]\n\n[workspace.package]\nversion = \"0.1.0\"\nedition = \"2024\"\n"
    + "\n[workspace.dependencies]\n"
    + "".join(
        name + ' = { path = "' + spec["path"] + '" }\n'
        for name, spec in subject.HOST_API_POLICY_RUNTIME_BASE_WORKSPACE_DEPENDENCIES.items()
    )
)


def _runtime_member(root, name=None, extra="", package_extra=""):
    package_name = name or root.rsplit("/", 1)[-1]
    consumer = root in subject.HOST_API_POLICY_RUNTIME_CONSUMER_ROOTS or (
        root == subject.HOST_API_POLICY_OPTIONAL_SYNC_FORMAT_ROOT
    )
    dependency = (
        "\n[dependencies]\n" + RUNTIME_API_NAME + " = { workspace = true }\n"
        if consumer else ""
    )
    return (
        '[package]\nname = "' + package_name + '"\n'
        "version.workspace = true\nedition.workspace = true\n" + package_extra + dependency + extra
    )


def _runtime_manifests(root=RUNTIME_ROOT, package_extra="", members=None):
    if members is None:
        members = RUNTIME_MEMBERS
        if subject.HOST_API_POLICY_OPTIONAL_SYNC_FORMAT_ROOT[len("runtime/"):] in root:
            members = members + subject.HOST_API_POLICY_RUNTIME_OPTIONAL_MEMBER_ROOTS
    manifests = {"runtime/Cargo.toml": root.encode("utf-8")}
    for member in members:
        name = (member.rsplit("/", 2)[-2] if member in subject.RUNTIME_APP_TAURI_ROOTS
                else member.rsplit("/", 1)[-1])
        manifests[member + "/Cargo.toml"] = _runtime_member(
            member, name=name, package_extra=package_extra if member == RUNTIME_MEMBERS[0] else "",
        ).encode("utf-8")
    return manifests


def _runtime_profile_root(members):
    wave70 = set(subject.RUNTIME_APP_TAURI_ROOTS).issubset(members)
    api_spec = (
        ' = { path = "../crates/host/api", version = "=0.2.0" }\n'
        if wave70 else ' = { path = "../crates/host/api" }\n'
    )
    return (
        "[workspace]\nresolver = \"3\"\nmembers = [\n"
        + "".join('    "' + root[len("runtime/"):] + '",\n' for root in members)
        + "]\n\n[workspace.package]\nversion = \"0.1.0\"\nedition = \"2024\"\n"
        + "\n[workspace.dependencies]\n" + RUNTIME_API_NAME + api_spec
    )


class RuntimeWorkspaceTests(BootstrapTestCase):
    def check(self, manifests, members=RUNTIME_MEMBERS, workspace="runtime"):
        return subject.check_manifests(manifests, members, workspace)

    def assert_refused(self, manifests, members=RUNTIME_MEMBERS, workspace="runtime"):
        with self.assertRaises(subject.BootstrapRefusal) as raised:
            subject.check_manifests(manifests, members, workspace)
        self.assertIn(raised.exception.reason, ("bootstrap_manifest_refused", "bootstrap_input_invalid"))


    def test_selector_maps_only_to_the_two_fixed_roots(self):
        self.assertEqual(subject.workspace_root_manifest("contract"), "Cargo.toml")
        self.assertEqual(subject.workspace_root_manifest("runtime"), "runtime/Cargo.toml")
        self.assertEqual(subject.workspace_directory("runtime"), "runtime")
        for value in ("", "other", "runtime/..", "../runtime", "/runtime", "Runtime", None, 1, b"runtime"):
            with self.subTest(value=value), self.assertRaises(subject.BootstrapRefusal):
                subject.workspace_directory(value)

    def test_runtime_manifests_with_plain_inside_members_are_accepted(self):
        expected = {root.rsplit("/", 1)[-1] for root in RUNTIME_MEMBERS}
        expected.add(RUNTIME_API_NAME)
        self.assertEqual(self.check(_runtime_manifests()), frozenset(expected))

    def test_the_pre_batch_seven_runtime_profile_remains_admitted_without_an_api_edge(self):
        manifests = _runtime_manifests(root=RUNTIME_BASE_ROOT, members=RUNTIME_BASE_MEMBERS)
        expected = {root.rsplit("/", 1)[-1] for root in RUNTIME_BASE_MEMBERS}
        self.assertEqual(self.check(manifests, members=RUNTIME_BASE_MEMBERS), frozenset(expected))
        altered_root = RUNTIME_BASE_ROOT + RUNTIME_API_NAME + ' = { path = "../crates/host/api" }\n'
        altered = _runtime_manifests(root=altered_root, members=RUNTIME_BASE_MEMBERS)
        self.assert_refused(altered, members=RUNTIME_BASE_MEMBERS)

    def test_runtime_profile_accepts_each_required_consumer_and_optional_sync_format(self):
        manifests = _runtime_manifests()
        for root in subject.HOST_API_POLICY_RUNTIME_BASE_CONSUMER_ROOTS:
            with self.subTest(root=root):
                self.assertEqual(
                    manifests[root + "/Cargo.toml"].count(RUNTIME_API_NAME.encode("ascii")), 1,
                )
        optional_members = RUNTIME_MEMBERS + subject.HOST_API_POLICY_RUNTIME_OPTIONAL_MEMBER_ROOTS
        optional_root = RUNTIME_ROOT.replace(
            "]\n\n[workspace.package]",
            '    "crates/services/sync-format",\n]\n\n[workspace.package]',
        )
        optional_manifests = _runtime_manifests(root=optional_root, members=optional_members)
        expected = {root.rsplit("/", 1)[-1] for root in optional_members}
        expected.add(RUNTIME_API_NAME)
        self.assertEqual(self.check(optional_manifests, optional_members), frozenset(expected))

    def test_wave_70a_and_70b_profiles_admit_only_exact_members_and_api_edges(self):
        for members in (RUNTIME_WAVE_70A_MEMBERS, RUNTIME_WAVE_70B_MEMBERS):
            with self.subTest(member_count=len(members)):
                manifests = _runtime_manifests(
                    root=_runtime_profile_root(members), members=members,
                )
                expected = {
                    (root.rsplit("/", 2)[-2] if root in subject.RUNTIME_APP_TAURI_ROOTS
                     else root.rsplit("/", 1)[-1])
                    for root in members
                }
                expected.add(RUNTIME_API_NAME)
                self.assertEqual(self.check(manifests, members=members), frozenset(expected))
                for root in subject.HOST_API_POLICY_RUNTIME_CONSUMER_ROOTS:
                    if root in members:
                        self.assertEqual(
                            manifests[root + "/Cargo.toml"].count(RUNTIME_API_NAME.encode("ascii")),
                            1,
                        )
        without_mobile = tuple(
            root for root in RUNTIME_WAVE_70A_MEMBERS
            if root != subject.RUNTIME_WAVE_70A_NEW_CONSUMER_ROOTS[-1]
        )
        self.assert_refused(
            _runtime_manifests(root=_runtime_profile_root(without_mobile), members=without_mobile),
            members=without_mobile,
        )

    def test_wave_70_member_cannot_drop_or_redirect_its_direct_api_edge(self):
        members = RUNTIME_WAVE_70B_MEMBERS
        manifests = _runtime_manifests(root=_runtime_profile_root(members), members=members)
        target = subject.RUNTIME_WAVE_70_CRATE_ROOTS[0] + "/Cargo.toml"
        manifests[target] = manifests[target].replace(
            (RUNTIME_API_NAME + ' = { workspace = true }').encode("ascii"), b"", 1,
        )
        self.assert_refused(manifests, members=members)

    def test_runtime_profile_refuses_missing_or_extra_required_roots(self):
        for members in ((), RUNTIME_MEMBERS[:-1], RUNTIME_MEMBERS + ("runtime/crates/services/other",)):
            with self.subTest(members=members):
                self.assert_refused(_runtime_manifests(), members=members)

    def test_runtime_tree_checker_accepts_production_frontend_and_path_member_shapes(self):
        roots = (
            "runtime/crates/host/core",
            "runtime/apps/test-shell-desktop/src-tauri",
            "runtime/apps/test-shell-mobile/src-tauri",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            runtime.mkdir()
            (runtime / "apps/test-shell-desktop/web/src").mkdir(parents=True)
            (runtime / "apps/test-shell-desktop/web/src/App.tsx").write_text(
                "export default function App() { return null; }\n", encoding="ascii",
            )
            (runtime / "apps/test-shell-mobile/web/src").mkdir(parents=True)
            (runtime / "apps/test-shell-mobile/web/src/App.tsx").write_text(
                "export default function App() { return null; }\n", encoding="ascii",
            )
            (runtime / "packages/host-ui/src").mkdir(parents=True)
            (runtime / "packages/host-ui/src/index.ts").write_text(
                "export const hostUi = true;\n", encoding="ascii",
            )
            for member in roots:
                crate = root / member
                (crate / "src").mkdir(parents=True)
                (crate / "Cargo.toml").write_text("[package]\n", encoding="ascii")
                (crate / "src/lib.rs").write_text("pub fn checked() {}\n", encoding="ascii")
            shapes = (
                tuple(Path(member) for member in roots),
                roots,
                tuple(tuple(member.split("/")) for member in roots),
            )
            for shape in shapes:
                with self.subTest(shape=shape):
                    subject._validate_runtime_profile_tree_files(root, shape, frozenset())

            invalid = runtime / "packages/host-ui/src/unsafe.md"
            invalid.write_text("not an admitted frontend source\n", encoding="ascii")
            with self.assertRaises(subject.BootstrapRefusal):
                subject._validate_runtime_profile_tree_files(
                    root, tuple(Path(member) for member in roots), frozenset(),
                )

    def test_runtime_and_contract_manifests_never_satisfy_each_other(self):
        self.assert_refused(_runtime_manifests(), workspace="contract")
        self.assert_refused(_contract_manifests(), members=CONTRACT_MEMBERS, workspace="runtime")
        self.assert_refused({"Cargo.toml": RUNTIME_ROOT.encode("utf-8")}, workspace="runtime")

    def test_windows_runtime_profile_refuses_orphan_member_manifests_and_locks(self):
        for filename in ("Cargo.toml", "Cargo.lock"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                orphan = Path(temporary) / "runtime" / "crates" / "orphan" / filename
                orphan.parent.mkdir(parents=True)
                orphan.write_text("orphan\n", encoding="ascii")
                with self.assertRaises(subject.BootstrapRefusal):
                    subject.validate_runtime_profile_source_tree(temporary)

    @staticmethod
    def _write_batch_seven_tree(root):
        for crate_root in subject.RUNTIME_BATCH_SEVEN_CRATE_ROOTS:
            directory = root / crate_root
            (directory / "src/modules").mkdir(parents=True)
            (directory / "tests").mkdir()
            (directory / "Cargo.toml").write_text("[package]\n", encoding="ascii")
            (directory / "README.md").write_text("Crate overview.\n", encoding="ascii")
            (directory / "CONTRACT.md").write_text("Crate contract.\n", encoding="ascii")
            (directory / "CHANGELOG.md").write_text("Initial crate release.\n", encoding="ascii")
            (directory / "src/lib.rs").write_text("pub fn crate_api() {}\n", encoding="ascii")
            (directory / "src/modules/mod.rs").write_text("pub fn module() {}\n", encoding="ascii")
            (directory / "tests/runtime.rs").write_text("fn works() {}\n", encoding="ascii")

    @unittest.skipUnless(sys.platform.startswith("linux"), "linux_source_build needs POSIX-only modules")
    def test_batch_seven_runtime_tree_admits_full_crates_and_refuses_unlisted_paths(self):
        import linux_source_build

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self._write_batch_seven_tree(root)
            subject._validate_runtime_batch_seven_crate_trees(root)
            descriptor = linux_source_build._open_source_root(root)
            try:
                linux_source_build._check_d145_runtime_batch_seven_tree(descriptor)
            finally:
                os.close(descriptor)

        cases = (
            ("runtime/crates/host/core/build.rs", "fn build() {}\n"),
            ("runtime/crates/services/notifications/src/data.json", "{}\n"),
            ("runtime/crates/host/registry/src/README.md", "Nested doc.\n"),
            ("runtime/crates/services/other/README.md", "Unlisted service.\n"),
        )
        for relative, contents in cases:
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                self._write_batch_seven_tree(root)
                extra = root / relative
                extra.parent.mkdir(parents=True, exist_ok=True)
                extra.write_text(contents, encoding="ascii")
                with self.assertRaises(subject.BootstrapRefusal):
                    subject._validate_runtime_batch_seven_crate_trees(root)
                descriptor = linux_source_build._open_source_root(root)
                try:
                    with self.assertRaises(linux_source_build.SourceBuildRefusal):
                        linux_source_build._check_d145_runtime_batch_seven_tree(descriptor)
                finally:
                    os.close(descriptor)

    @unittest.skipUnless(sys.platform.startswith("linux"), "linux_source_build needs POSIX-only modules")
    def test_batch_seven_changelog_is_required_for_each_crate_and_admitted_at_the_root(self):
        import linux_source_build

        for crate_root in subject.RUNTIME_BATCH_SEVEN_CRATE_ROOTS:
            with self.subTest(crate_root=crate_root), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                self._write_batch_seven_tree(root)
                changelog = root / crate_root / "CHANGELOG.md"
                subject._validate_runtime_batch_seven_crate_trees(root)
                descriptor = linux_source_build._open_source_root(root)
                try:
                    linux_source_build._check_d145_runtime_batch_seven_tree(descriptor)
                finally:
                    os.close(descriptor)

                changelog.unlink()
                with self.assertRaises(subject.BootstrapRefusal):
                    subject._validate_runtime_batch_seven_crate_trees(root)
                descriptor = linux_source_build._open_source_root(root)
                try:
                    with self.assertRaises(linux_source_build.SourceBuildRefusal):
                        linux_source_build._check_d145_runtime_batch_seven_tree(descriptor)
                finally:
                    os.close(descriptor)

    def test_runtime_members_must_be_fixed_paths_inside_the_runtime_crates_directory(self):
        for member in (
            "crates/host/api", "packages/x", "runtime/x", "runtime/crates/x", "runtime/apps/x",
            "runtime/crates/a/b/c", "runtime/crates/A/b", "runtime/crates/../crates/a/b",
            "crates/test-fixtures/tool-a", "/runtime/crates/a/b",
        ):
            with self.subTest(member=member):
                self.assert_refused(_runtime_manifests(), members=(member,))

    def test_runtime_member_list_must_match_exactly(self):
        for root in (
            RUNTIME_ROOT.replace('    "crates/test-fixtures/tool-b",\n', ""),
            RUNTIME_ROOT.replace("tool-b", "tool-c"),
            RUNTIME_ROOT.replace('"crates/', '"runtime/crates/'),
            RUNTIME_ROOT.replace("]\n\n", ']\nexclude = ["x"]\n\n', 1),
            RUNTIME_ROOT.replace("]\n\n", ']\ndefault-members = ["crates/test-fixtures/tool-a"]\n\n', 1),
        ):
            with self.subTest(root=root):
                self.assert_refused(_runtime_manifests(root=root))

    def test_any_parent_segment_or_package_workspace_key_is_refused_in_runtime_manifests(self):
        for root in (
            RUNTIME_ROOT.replace('"crates/test-fixtures/tool-a"', '"../runtime/crates/test-fixtures/tool-a"'),
            RUNTIME_ROOT.replace('"crates/test-fixtures/tool-a"', '"crates/../crates/test-fixtures/tool-a"'),
            RUNTIME_ROOT.replace('../crates/host/api', '../runtime/crates/test-fixtures/tool-a'),
            RUNTIME_ROOT.replace(RUNTIME_API_NAME + ' = { path = "../crates/host/api" }',
                                 'api = { package = "host-api", path = "../crates/host/api" }'),
        ):
            with self.subTest(root=root):
                self.assert_refused(_runtime_manifests(root=root))
        for package_extra in (
            'workspace = "../../../../runtime"\n', 'workspace = "."\n', 'workspace = "../.."\n',
        ):
            with self.subTest(package_extra=package_extra):
                self.assert_refused(_runtime_manifests(package_extra=package_extra))
        manifests = _runtime_manifests()
        manifests[RUNTIME_MEMBERS[0] + "/Cargo.toml"] = _runtime_member(
            RUNTIME_MEMBERS[0], extra='\n[dependencies]\nb = { path = "../tool-b" }\n',
        ).encode("utf-8")
        self.assert_refused(manifests)
        with_package = _runtime_manifests(root=RUNTIME_ROOT + '\n[package]\nname = "x"\nedition = "2024"\n')
        self.assert_refused(with_package)

    def test_runtime_foreign_dependency_forms_are_refused(self):
        git = "https:" + chr(47) * 2 + "example.invalid/crate"
        for dependency in ('a = { git = "' + git + '" }', 'a = "1.0.0"'):
            manifests = _runtime_manifests()
            manifests[RUNTIME_MEMBERS[0] + "/Cargo.toml"] = (
                _runtime_member(RUNTIME_MEMBERS[0], extra="\n[dependencies]\n" + dependency + "\n")
            ).encode("utf-8")
            with self.subTest(dependency=dependency):
                self.assert_refused(manifests)

    def test_runtime_profile_refuses_wrong_api_identity_and_dependency_sections(self):
        for table in ("dev-dependencies", "build-dependencies", "target.'cfg(unix)'.dependencies"):
            manifests = _runtime_manifests()
            member = subject.HOST_API_POLICY_RUNTIME_CONSUMER_ROOTS[0]
            manifests[member + "/Cargo.toml"] += (
                ("\n[" + table + "]\n" if not table.startswith("target.") else "\n[" + table + "]\n")
                + RUNTIME_API_NAME + " = { workspace = true }\n"
            ).encode("utf-8")
            with self.subTest(table=table):
                self.assert_refused(manifests)
        for dependency in (
            'host_api = { package = "host-api", workspace = true }',
            RUNTIME_API_NAME + ' = { path = "../crates/host/api" }',
            RUNTIME_API_NAME + ' = { workspace = true, package = "host-api" }',
        ):
            manifests = _runtime_manifests()
            member = subject.HOST_API_POLICY_RUNTIME_CONSUMER_ROOTS[0]
            original = _runtime_member(member)
            manifests[member + "/Cargo.toml"] = (
                original.replace(RUNTIME_API_NAME + " = { workspace = true }", dependency)
            ).encode("utf-8")
            with self.subTest(dependency=dependency):
                self.assert_refused(manifests)

    def test_runtime_lock_check_requires_exact_sourceless_members(self):
        packages = {root.rsplit("/", 1)[-1] for root in RUNTIME_MEMBERS} | {RUNTIME_API_NAME}
        lock = "version = 4\n\n" + "\n\n".join(
            '[[package]]\nname = "' + name + '"\nversion = "0.1.0"' for name in sorted(packages)
        ) + "\n"
        lock = lock.encode("ascii")
        self.assertTrue(subject.check_lock_members(lock, frozenset(packages)))
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_lock_members(lock, frozenset(packages - {RUNTIME_API_NAME}))
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_lock_members(lock, frozenset(packages | {"extra"}))

    def test_runtime_lock_check_refuses_extra_registry_packages_and_duplicate_local_versions(self):
        packages = {root.rsplit("/", 1)[-1] for root in RUNTIME_MEMBERS} | {RUNTIME_API_NAME}
        rows = [
            '[[package]]\nname = "' + name + '"\nversion = "0.1.0"'
            for name in sorted(packages)
        ]
        registry_row = (
            '[[package]]\nname = "extra"\nversion = "1.0.0"\nsource = "'
            + subject.cargo.REGISTRY_SOURCE + '"\nchecksum = "' + "a" * 64 + '"'
        )
        extra = ("version = 4\n\n" + "\n\n".join(rows + [registry_row]) + "\n").encode("ascii")
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_lock_members(extra, frozenset(packages))
        duplicate = (
            "version = 4\n\n" + "\n\n".join(rows + [
                '[[package]]\nname = "' + RUNTIME_API_NAME + '"\nversion = "0.2.0"',
            ]) + "\n"
        ).encode("ascii")
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_lock_members(duplicate, frozenset(packages))

    def test_runtime_lock_edges_must_come_from_manifests_and_accept_implicit_registry_source(self):
        manifests = _runtime_manifests()
        consumer = subject.HOST_API_POLICY_RUNTIME_CONSUMER_ROOTS[0]
        manifests[consumer + "/Cargo.toml"] = _runtime_member(
            consumer, extra='serde = "=1.0.200"\n',
        ).encode("utf-8")
        names = {root.rsplit("/", 1)[-1] for root in RUNTIME_MEMBERS} | {RUNTIME_API_NAME}
        identities = {(name, "0.1.0") for name in names}
        rules = subject.manifest_dependency_rules(manifests, subject.RUNTIME_WORKSPACE)
        rules[RUNTIME_API_NAME] = {}
        local_rows = []
        for name in sorted(names):
            row = '[[package]]\nname = "' + name + '"\nversion = "0.1.0"\n'
            dependencies = []
            if name == consumer.rsplit("/", 1)[-1]:
                dependencies.extend((RUNTIME_API_NAME + " 0.1.0", "serde 1.0.200"))
            elif name in {root.rsplit("/", 1)[-1]
                          for root in subject.HOST_API_POLICY_RUNTIME_CONSUMER_ROOTS[1:]}:
                dependencies.append(RUNTIME_API_NAME + " 0.1.0")
            if dependencies:
                row += "dependencies = [\n" + "".join(' "' + item + '",\n' for item in dependencies) + "]\n"
            local_rows.append(row)
        checksum = "a" * 64
        serde = (
            '[[package]]\nname = "serde"\nversion = "1.0.200"\nsource = "'
            + subject.cargo.REGISTRY_SOURCE + '"\nchecksum = "' + checksum + '"\n'
        )
        lock = ("version = 4\n\n" + "\n".join(local_rows) + serde).encode("ascii")
        self.assertTrue(subject.check_lock_members(
            lock, frozenset(names), identities, rules,
        ))
        injected = lock.replace(
            b'"serde 1.0.200",\n', b'"serde 1.0.200",\n "extra 1.0.0",\n', 1,
        ).replace(
            b'[[package]]\nname = "serde"',
            ('[[package]]\nname = "extra"\nversion = "1.0.0"\nsource = "'
             + subject.cargo.REGISTRY_SOURCE + '"\nchecksum = "' + checksum + '"\n\n'
             + '[[package]]\nname = "serde"').encode("ascii"),
            1,
        )
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_lock_members(
                injected, frozenset(names), identities, rules,
            )


class RuntimeSourceInventoryTests(BootstrapTestCase):
    def _inventory(self, root, source_sha):
        paths = subject._source_inventory_required_paths(root)
        rows = []
        for path in sorted(paths):
            payload = (root / path).read_bytes()
            fields = {
                "path": path,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "owner": "9.5",
                "package": "test-shell",
                "target": "all-platforms",
                "generator": "",
                "generator_version": "",
                "provenance": "",
            }
            rows.append("[[files]]\n" + "".join(
                key + ' = "' + fields[key] + '"\n'
                for key in ("path", "sha256", "owner", "package", "target",
                            "generator", "generator_version", "provenance")
            ))
        payload = ("schema_version = 1\n" + "".join(rows)).encode("ascii")
        inventory = root / subject.SOURCE_INVENTORY_PATH
        inventory.parent.mkdir(parents=True, exist_ok=True)
        inventory.write_bytes(payload)
        return payload

    def _candidate(self, root):
        for app in ("test-shell-desktop", "test-shell-mobile"):
            tauri = root / "runtime" / "apps" / app / "src-tauri"
            tauri.mkdir(parents=True)
            (tauri / "tauri.conf.json").write_text("{}\n", encoding="ascii")
        service = root / "runtime" / "crates" / "services" / "log"
        service.mkdir(parents=True)

    def test_inventory_is_sorted_and_matches_exact_non_crate_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            source_sha = "a" * 40
            payload = self._inventory(root, source_sha)
            self.assertEqual(
                [row["path"] for row in subject.parse_runtime_source_inventory(payload, source_sha)[0]],
                sorted(subject._source_inventory_required_paths(root)),
            )
            self.assertTrue(subject.validate_runtime_source_inventory(root, source_sha))
            self.assertEqual(
                subject.parse_runtime_source_inventory(payload, "b" * 40)[0],
                subject.parse_runtime_source_inventory(payload, source_sha)[0],
            )

    def test_inventory_refuses_changed_digest_and_unlisted_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            source_sha = "c" * 40
            self._inventory(root, source_sha)
            (root / "runtime/apps/test-shell-mobile/src-tauri/tauri.conf.json").write_text(
                "{\"changed\":true}\n", encoding="ascii",
            )
            with self.assertRaises(subject.BootstrapRefusal):
                subject.validate_runtime_source_inventory(root, source_sha)
            (root / "runtime/apps/test-shell-desktop/src-tauri/native-resource.bin").write_bytes(b"x")
            with self.assertRaises(subject.BootstrapRefusal):
                subject.validate_runtime_source_inventory(root, source_sha)

    def test_inventory_generated_provenance_is_all_or_none(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            source_sha = "d" * 40
            payload = self._inventory(root, source_sha)
            corrupted = payload.replace(b'generator = ""', b'generator = "xtask"', 1)
            with self.assertRaises(subject.BootstrapRefusal):
                subject.parse_runtime_source_inventory(corrupted, source_sha)

    def test_inventoried_build_script_stays_refused_without_source_bound_r132_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._candidate(root)
            build_script = root / "runtime/crates/host/core/build.rs"
            build_script.parent.mkdir(parents=True, exist_ok=True)
            build_script.write_text("fn main() {}\n", encoding="ascii")
            source_sha = "e" * 40
            payload = self._inventory(root, source_sha)
            digest = hashlib.sha256(build_script.read_bytes()).hexdigest()
            with self.assertRaises(subject.BootstrapRefusal):
                subject.parse_runtime_source_inventory(payload, source_sha)
            rows, unused = subject.parse_runtime_source_inventory(
                payload, source_sha,
                build_script_reviews=(("runtime/crates/host/core/build.rs", digest, source_sha),),
            )
            self.assertIn("runtime/crates/host/core/build.rs", {row["path"] for row in rows})
            with self.assertRaises(subject.BootstrapRefusal):
                subject.validate_runtime_source_inventory(root, source_sha)

    def test_build_script_filename_casing_is_refused_without_a_review(self):
        for filename in ("BUILD.RS", "Build.rs"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self._candidate(root)
                build_script = root / "runtime" / "crates" / "host" / "core" / filename
                build_script.parent.mkdir(parents=True, exist_ok=True)
                build_script.write_text("fn main() {}\n", encoding="ascii")
                source_sha = "f" * 40
                payload = self._inventory(root, source_sha)
                digest = hashlib.sha256(build_script.read_bytes()).hexdigest()
                for reviews in ((), ((build_script.relative_to(root).as_posix(), digest,
                                      source_sha),)):
                    with self.subTest(reviewed=bool(reviews)), self.assertRaises(
                            subject.BootstrapRefusal):
                        subject.parse_runtime_source_inventory(
                            payload, source_sha, build_script_reviews=reviews,
                        )

    def test_build_script_casefold_collisions_are_ambiguous(self):
        rows = []
        for index, path in enumerate((
                "runtime/crates/host/core/BUILD.RS",
                "runtime/crates/host/core/build.rs")):
            fields = {
                "path": path,
                "sha256": str(index + 1) * 64,
                "owner": "9.5",
                "package": "test-shell",
                "target": "all-platforms",
                "generator": "",
                "generator_version": "",
                "provenance": "",
            }
            rows.append("[[files]]\n" + "".join(
                key + ' = "' + fields[key] + '"\n'
                for key in ("path", "sha256", "owner", "package", "target",
                            "generator", "generator_version", "provenance")
            ))
        payload = ("schema_version = 1\n" + "".join(rows)).encode("ascii")
        with self.assertRaises(subject.BootstrapRefusal):
            subject.parse_runtime_source_inventory(payload, "1" * 40)

    def test_unicode_normalized_build_script_alias_is_refused(self):
        filename = "\uFF22UILD.RS"
        self.assertTrue(subject._is_build_script_name(filename))
        payload = (
            'schema_version = 1\n[[files]]\npath = "runtime/crates/host/core/'
            + filename + '"\n'
        ).encode("utf-8")
        with self.assertRaises(subject.BootstrapRefusal):
            subject.parse_runtime_source_inventory(payload, "2" * 40)


class ContractWorkspaceUnchangedTests(BootstrapTestCase):
    def test_default_selector_is_the_contract_workspace(self):
        self.assertEqual(
            subject.check_manifests(_contract_manifests(), CONTRACT_MEMBERS),
            subject.check_manifests(_contract_manifests(), CONTRACT_MEMBERS, "contract"),
        )
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_manifests(_contract_manifests(), CONTRACT_MEMBERS, "other")

    def test_contract_package_workspace_key_is_still_refused(self):
        manifests = _contract_manifests()
        manifests["crates/host/api/Cargo.toml"] = (

            _contract_member("host-api", "Synthetic.").replace(
                "[package]\n", '[package]\nworkspace = "../../.."\n', 1,
            )
        ).encode("utf-8")
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_manifests(manifests, CONTRACT_MEMBERS)

    def test_wave70_contract_xtask_demo_and_registry_lock_are_exact_and_reachable(self):
        root = _contract_root().replace(
            '    "crates/kernel/i18n",\n',
            '    "crates/kernel/i18n",\n'
            '    "tools/xtask",\n'
            '    "crates/host/conformance/fixtures/demo-tool",\n',
        ).replace('version = "0.1.0"', 'version = "0.2.0"', 1)
        members = subject.CONTRACT_WAVE_70B_MEMBERS
        manifests = _contract_manifests(root)
        manifests[subject.CONTRACT_XTASK_MEMBER + "/Cargo.toml"] = _contract_member(
            "xtask", "KeelDock workspace task runner.",
            PRIVATE_PREFIX + 'host-api = { path = "../../crates/host/api" }\n',
        ).encode("utf-8")
        manifests[subject.CONTRACT_DEMO_MEMBER + "/Cargo.toml"] = _contract_member(
            "demo-tool", "API-only contract demo fixture.",
            PRIVATE_PREFIX + 'host-api = { path = "../../../api", version = "=0.2.0" }\n',
        ).encode("utf-8")
        names = subject.check_manifests(manifests, members)
        identities = subject.manifest_package_identities(manifests)
        rules = subject.manifest_dependency_rules(manifests)
        self.assertIn("keeldock" + "-xtask", names)
        self.assertIn("keeldock" + "-demo-tool", names)
        self.assertIn(("keeldock" + "-host-api", "0.2.0"), identities)

        registry_source = cargo.REGISTRY_SOURCE
        local_dependencies = {
            "keeldock" + "-host-mock": ("keeldock" + "-host-api 0.2.0",),
            "keeldock" + "-host-conformance": (
                "keeldock" + "-host-api 0.2.0", "keeldock" + "-host-mock 0.2.0",
            ),
            "keeldock" + "-xtask": ("keeldock" + "-host-api 0.2.0",),
            "keeldock" + "-demo-tool": ("keeldock" + "-host-api 0.2.0",),
            "keeldock" + "-host-api": (
                "schemars 1.2.3 (" + registry_source + ")",
                "serde 1.0.229 (" + registry_source + ")",
                "serde_json 1.0.154 (" + registry_source + ")",
            ),
        }
        rows = []
        for name in sorted(names):
            row = '\n[[package]]\nname = "' + name + '"\nversion = "0.2.0"\n'
            dependencies = local_dependencies.get(name, ())
            if dependencies:
                row += "dependencies = [\n" + "".join(
                    ' "' + dependency + '",\n' for dependency in dependencies
                ) + "]\n"
            rows.append(row)
        for name, version in (("schemars", "1.2.3"), ("serde", "1.0.229"),
                              ("serde_json", "1.0.154")):
            rows.append(
                '\n[[package]]\nname = "' + name + '"\nversion = "' + version
                + '"\nsource = "' + registry_source + '"\nchecksum = "' + "a" * 64 + '"\n'
            )
        lock = ("version = 4\n" + "".join(rows)).encode("ascii")
        self.assertTrue(subject.check_lock_members(lock, names, identities, rules))

        altered_lock = lock.replace(
            b"serde 1.0.229 (registry+https:" + b"/" * 2 + b"github.com/rust-lang/crates.io-index)",
            b"serde 1.0.228 (registry+https:" + b"/" * 2 + b"github.com/rust-lang/crates.io-index)",
        )
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_lock_members(altered_lock, names, identities, rules)
        with self.assertRaises(subject.BootstrapRefusal):
            subject.check_manifests(
                manifests, subject.CONTRACT_WAVE_70A_MEMBERS,
            )


if __name__ == "__main__":
    unittest.main()
