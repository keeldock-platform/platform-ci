import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
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
HASH = chr(35)
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
    return {
        "Cargo.toml": (_contract_root() if root is None else root).encode("utf-8"),
        "crates/host/api/Cargo.toml": _contract_member(
            "host-api", "KeelDock L1 host API: the stable contract between the host and its tools.",
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


if __name__ == "__main__":
    unittest.main()
