import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import urllib.error
import urllib.request

import cargo_lock_bootstrap as subject
import cargo_lock_receipt as cargo
import feedback_request


NOW = 1_793_160_000
EXPIRY = NOW + 3600
CHECKSUM = "a" * 64
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
            "build_inputs": {}, "fetcher": fetcher,
        }
        values.update(overrides)
        return subject.build_evidence(
            lock_bytes, self.receipt(lock_bytes) if receipt_bytes is None else receipt_bytes,
            CONTEXT if context is None else context, **values,
        )


class ForcedSettingsTests(BootstrapTestCase):
    def test_forced_config_covers_every_setting_family_and_never_carries_a_token(self):
        items = dict(subject.forced_config_items())
        for key in (
            "registry.global-credential-providers", "registry.credential-provider",
            "source.crates-io.replace-with", "source.fixed-crates-io.registry",
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
        self.assertEqual(items["source.fixed-crates-io.registry"], json.dumps(cargo.SPARSE_REGISTRY_SOURCE))
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

    def test_clean_tree_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertTrue(subject.refuse_cargo_config(self.tree(temporary)))

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
                    self.assert_refused("bootstrap_config_refused", subject.refuse_cargo_config, root)

    def test_cargo_configuration_in_a_parent_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.tree(temporary)
            (Path(temporary) / "work" / ".cargo").mkdir()
            (Path(temporary) / "work" / ".cargo" / "config.toml").write_bytes(b"x")
            self.assert_refused("bootstrap_config_refused", subject.refuse_cargo_config, root)

    def test_links_and_bad_roots_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.tree(temporary)
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
        proxies = [
            handler for handler in default._opener.handlers
            if isinstance(handler, urllib.request.ProxyHandler)
        ]
        self.assertEqual([handler.proxies for handler in proxies], [{}])
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
            "build_inputs": {}, "fetcher": FakeFetcher(),
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
            ("minimum_age_seconds", 1), ("run_attempt", 2), ("build_inputs", {"LIBSQLITE3_FLAGS": "x"}),
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


if __name__ == "__main__":
    unittest.main()
