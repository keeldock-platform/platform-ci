import base64
import datetime
import hashlib
import io
import json
import sys
import tarfile
import unittest
import urllib.error

import npm_admission as adm
import npm_admission_bootstrap as subject


NOW = 1_800_000_000
EXPIRY = NOW + 3600
OLD = "2026-06-01T12:00:00.000Z"
ROOT_VERSION = "0.1.0"
DIRECT = (("alpha-pkg", "1.0.0"), ("beta-pkg", "2.0.0"))
TRANSITIVE = (("gamma-pkg", "3.1.0"),)
OVERRIDE = (("lightningcss", "1.33.0"),)
ALL_PACKAGES = DIRECT + TRANSITIVE + OVERRIDE
DEFAULT_ATTESTED = {"alpha-pkg": True, "beta-pkg": False, "gamma-pkg": False, "lightningcss": False}


def _sri(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")


def _iso(epoch):
    moment = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _tarball(name, version, licence="MIT", scripts=None, binary=False):
    fields = {"name": name, "version": version, "scripts": scripts or {}}
    if licence is not None:
        fields["license"] = licence
    manifest = _json(fields)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        directory = tarfile.TarInfo("package/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        members = [("package/package.json", manifest)]
        if scripts:
            members.append(("package/install.js", b"synthetic script"))
        if binary:
            members.append(("package/binding.node", b"\x7fELFsynthetic"))
        for path, content in members:
            info = tarfile.TarInfo(path)
            info.mode = 0o644
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def _workspace_name(path):
    return subject.SCOPE + path.rsplit("/", 1)[-1]


class FakeFetcher:
    def __init__(self, packuments, archives, advisory):
        self.packuments = packuments
        self.archives = archives
        self.advisory = advisory
        self.calls = []

    def packument(self, name):
        self.calls.append(("packument", name))
        return self.packuments[name]

    def tarball(self, name, version):
        self.calls.append(("tarball", name, version))
        return self.archives[(name, version)]

    def advisories(self, body):
        self.calls.append(("advisories", body))
        return self.advisory


class World:
    def __init__(self, *, published=None, registry_license=None, archive_license=None,
                 deprecated=(), advisory=b"{}", attested=None, table_published=None,
                 table_attested=None, extra_rows=(), dist_integrity=None, table_licence=None,
                 policy_epoch_ms=None, elections=None, allowlist=None, allows=None,
                 singletons=("alpha-pkg", "lightningcss"), layout="wide", policy_extra=None):
        self.policy_epoch_ms = (NOW - 3600) * 1000 if policy_epoch_ms is None else policy_epoch_ms
        self.elections = elections or {}
        self.allowlist = ["MIT", "ISC"] if allowlist is None else allowlist
        self.allows = allows or []
        self.singletons = list(singletons)
        self.layout = layout
        self.policy_extra = policy_extra or {}
        self.published = published or {}
        self.registry_license = registry_license or {}
        self.archive_license = archive_license or {}
        self.attested = dict(DEFAULT_ATTESTED, **(attested or {}))
        self.table_attested = dict(self.attested, **(table_attested or {}))
        self.table_published = table_published or {}
        self.table_licence = table_licence or {}
        self.dist_integrity = dist_integrity or {}
        self.deprecated = set(deprecated)
        self.advisory = advisory
        self.extra_rows = tuple(extra_rows)
        self.archives = {}
        self.integrity = {}
        for name, version in ALL_PACKAGES:
            data = _tarball(name, version, licence=self.archive_license.get(
                name, self.registry_license.get(name, "MIT")))
            self.archives[(name, version)] = data
            self.integrity[name] = _sri(data)
        self.lock_dict = self._lock()
        self.lock_bytes = _json(self.lock_dict) + b"\n"
        self.files = self._files()
        self.context = {
            "repository": "owner/name", "filing": subject.DEFAULT_FILING,
            "source_sha": "a" * 40, "base_sha": "b" * 40, "base_branch": "develop",
            "reviewed_diff_fingerprint": "c" * 64, "control_sha": "d" * 40,
        }

    def published_of(self, name):
        return self.published.get(name, OLD)

    def licence_of(self, name):
        return self.registry_license.get(name, "MIT")

    def _lock(self):
        packages = {
            "": {
                "name": subject.ROOT_NAME, "version": ROOT_VERSION, "workspaces": ["packages/*"],
                "devDependencies": dict(DIRECT),
                "engines": {"node": subject.NODE_VERSION, "npm": subject.NPM_VERSION},
            },
        }
        for link, path in subject.workspace_links().items():
            packages[link] = {"resolved": path, "link": True}
            packages[path] = {"name": _workspace_name(path), "version": ROOT_VERSION}
        for name, version in ALL_PACKAGES:
            entry = {
                "version": version, "resolved": adm._canonical_tarball_url(name, version),
                "integrity": self.integrity[name], "dev": True, "license": self.licence_of(name),
            }
            if name == "alpha-pkg":
                entry["peerDependencies"] = {"beta-pkg": "^2.0.0"}
            packages["node_modules/" + name] = entry
        return {
            "name": subject.ROOT_NAME, "version": ROOT_VERSION, "lockfileVersion": 3,
            "requires": True, "packages": packages,
        }

    def _rows(self):
        rows = []
        for name, version in DIRECT + OVERRIDE + self.extra_rows:
            rows.append((
                name, version, self.table_published.get(name, self.published_of(name)),
                self.integrity.get(name, _sri(name.encode("ascii"))),
                self.table_licence.get(name, self.licence_of(name)),
                self.table_attested.get(name, False),
            ))
        return rows

    def request_doc(self):
        if self.layout == "wide":
            columns = [
                "Package", "Version", "Latest", "Published (UTC)", "Cooled at (UTC)",
                "dist.integrity (SRI)", "dist.shasum", "Licence", "Hooks", "Deps / Opt", "Peers",
                "Attest", "Publisher", "Deprecated",
            ]
        else:
            columns = [
                "Package", "Version", "Published (UTC)", "dist.integrity (SRI)", "Canonical tarball",
                "Licence", "Lifecycle hooks", "Attestations", "Publisher",
            ]
        lines = [
            "Registry facts", "", subject.REQUEST_START,
            "| " + " | ".join(columns) + " |",
            "| " + " | ".join("---" for unused in columns) + " |",
        ]
        for name, version, published, integrity, licence, attested in self._rows():
            shasum = hashlib.sha1(self.archives.get((name, version), b"x")).hexdigest()
            if self.layout == "wide":
                cells = [
                    name, version, version, published, "cooled", integrity, shasum, licence, "none",
                    "0 / 0", "{}", "yes" if attested else "no", "publisher-a", "no",
                ]
            else:
                cells = [
                    name, version, published, integrity, adm._canonical_tarball_url(name, version),
                    licence, "{}", "yes" if attested else "no", "publisher-a",
                ]
            lines.append("| " + " | ".join(cells) + " |")
        lines.extend((subject.REQUEST_END, ""))
        return "\n".join(lines).encode("utf-8")

    def policy(self):
        value = {
            "schema_version": 1, "policy_epoch_ms": self.policy_epoch_ms, "direct": dict(DIRECT),
            "singleton_names": self.singletons, "internal_names": [],
            "licence_allowlist": self.allowlist, "licence_elections": self.elections,
            "development_advisory_allows": self.allows,
        }
        value.update(self.policy_extra)
        return value

    def _files(self):
        root = {
            "name": subject.ROOT_NAME, "version": ROOT_VERSION, "private": True,
            "packageManager": "npm@" + subject.NPM_VERSION,
            "engines": {"node": subject.NODE_VERSION, "npm": subject.NPM_VERSION},
            "workspaces": ["packages/*"],
            "scripts": {"typecheck": "run typecheck", "test": "run test"},
            "devDependencies": dict(DIRECT),
            "overrides": dict(OVERRIDE),
        }
        files = {
            ".node-version": subject.NODE_VERSION_BYTES,
            ".npmrc": subject.NPMRC_BYTES,
            subject.POLICY_FILE: _json(self.policy()) + b"\n",
            "package.json": _json(root) + b"\n",
            subject.FILINGS[subject.DEFAULT_FILING]["request_doc"]: self.request_doc(),
        }
        for path in subject.WORKSPACE_PATHS:
            files[path + "/package.json"] = _json({
                "name": _workspace_name(path), "version": ROOT_VERSION, "type": "module",
                "scripts": {"test": "run test"},
            }) + b"\n"
        return files

    def plan(self):
        return subject.check_inputs(self.files, subject.DEFAULT_FILING)

    def packuments(self):
        result = {}
        for name, version in ALL_PACKAGES:
            manifest = {
                "name": name, "version": version, "license": self.licence_of(name),
                "_npmUser": {"name": "publisher-a"},
                "dist": {
                    "integrity": self.dist_integrity.get(name, self.integrity[name]),
                    "tarball": adm._canonical_tarball_url(name, version),
                    "shasum": hashlib.sha1(self.archives[(name, version)]).hexdigest(),
                },
            }
            if self.attested[name]:
                manifest["dist"]["attestations"] = {"provenance": {"predicateType": "slsa"}}
            if name in self.deprecated:
                manifest["deprecated"] = "use something else"
            result[name] = _json({
                "name": name, "readme": "x" * 20000,
                "versions": {version: manifest},
                "time": {"created": OLD, version: self.published_of(name)},
            })
        return result

    def fetcher(self):
        return FakeFetcher(self.packuments(), self.archives, self.advisory)

    def bundle(self, **keywords):
        options = dict(run_id="123456", run_attempt=1, now=NOW, expiry=EXPIRY,
                       fetcher=self.fetcher(), clock=lambda: NOW + 5)
        options.update(keywords)
        return subject.produce_bundle(self.lock_bytes, self.plan(), self.context, **options)


class RefusalAssertions(unittest.TestCase):
    def assert_refused(self, reason, function, *arguments, **keywords):
        with self.assertRaises(subject.BootstrapRefusal) as raised:
            function(*arguments, **keywords)
        self.assertEqual(raised.exception.reason, reason)
        self.assertEqual(str(raised.exception), reason)


class RefusalTests(RefusalAssertions):
    def test_unknown_reasons_collapse_to_the_generic_input_reason(self):
        self.assertEqual(subject.BootstrapRefusal("anything").reason, "npm_input_invalid")
        self.assertEqual(subject.BootstrapRefusal("npm_stale").reason, "npm_stale")

    def test_shared_helper_refusals_are_mapped_to_bootstrap_reasons(self):
        for source, expected in (
            ("npm_lock_invalid", "npm_lock_refused"),
            ("npm_archive_invalid", "npm_archive_refused"),
            ("npm_material_invalid", "npm_manifest_refused"),
        ):
            with self.subTest(source=source):
                def failing(reason=source):
                    raise adm.Refusal(reason)
                self.assert_refused(expected, subject._call_adm, failing)


class RequestDocumentTests(RefusalAssertions):
    def test_the_filed_table_is_read_into_rows(self):
        world = World()
        rows = subject.parse_request_doc(world.request_doc())
        self.assertEqual(
            sorted(rows), sorted(DIRECT + OVERRIDE),
        )
        row = rows[("alpha-pkg", "1.0.0")]
        self.assertEqual(row["published"], OLD)
        self.assertEqual(row["licence"], "MIT")
        self.assertIs(row["attested"], True)
        self.assertEqual(len(row["shasum"]), 40)

    def test_the_table_is_read_by_header_name_in_either_layout(self):
        wide = subject.parse_request_doc(World(layout="wide").request_doc())
        narrow = subject.parse_request_doc(World(layout="narrow").request_doc())
        self.assertEqual(sorted(wide), sorted(narrow))
        self.assertIsNotNone(wide[("beta-pkg", "2.0.0")]["shasum"])
        self.assertIsNone(narrow[("beta-pkg", "2.0.0")]["shasum"])
        doc = World().request_doc().decode("utf-8")
        for changed in (
            doc.replace("| Licence |", "| Licence | Licence |", 1),
            doc.replace("| Licence |", "| Other |", 1),
            doc.replace("| Attest |", "| Attest | Attestations |", 1),
            doc.replace("| dist.shasum |", "| dist.shasum | x |", 1),
        ):
            with self.subTest(changed=changed[:0]):
                self.assertNotEqual(changed, doc)
                self.assert_refused("npm_request_refused", subject.parse_request_doc, changed.encode("utf-8"))
        bad_shasum = doc.replace(
            wide[("alpha-pkg", "1.0.0")]["integrity"] + " | ", wide[("alpha-pkg", "1.0.0")]["integrity"] + " | zz", 1,
        )
        self.assert_refused("npm_request_refused", subject.parse_request_doc, bad_shasum.encode("utf-8"))

    def test_marker_header_row_and_cell_changes_are_refused(self):
        doc = World().request_doc().decode("utf-8")
        start = subject.REQUEST_START
        end = subject.REQUEST_END
        header = doc.split(start)[1].strip().split("\n")[0]
        mutations = (
            doc.replace(start, "", 1),
            doc.replace(end, "", 1),
            doc + start,
            doc.replace(header, header.replace("Licence", "License"), 1),
            doc.replace("| --- |", "| -- |", 1),
            doc.replace("| yes |", "| maybe |", 1) if "| yes |" in doc else doc.replace("| no |", "| maybe |", 1),
            doc.replace("sha512-", "sha256-", 1),
            doc.replace("1.0.0 |", "1.0 |", 1),
            doc.replace("2026-06-01T12:00:00.000Z", "yesterday", 1),
            doc.replace(" | publisher-a | no |", " | publisher-a |", 1),
        )
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(changed, doc)
                self.assert_refused(
                    "npm_request_refused", subject.parse_request_doc, changed.encode("utf-8"),
                )

    def test_a_duplicate_row_and_a_foreign_tarball_are_refused(self):
        doc = World().request_doc().decode("utf-8")
        first_row = next(line for line in doc.split("\n") if line.startswith("| alpha-pkg "))
        duplicated = doc.replace(subject.REQUEST_END, first_row + "\n" + subject.REQUEST_END, 1)
        self.assertNotEqual(duplicated, doc)
        self.assert_refused("npm_request_refused", subject.parse_request_doc, duplicated.encode("utf-8"))
        canonical = adm._canonical_tarball_url("alpha-pkg", "1.0.0")
        foreign = World(layout="narrow").request_doc().decode("utf-8").replace(
            canonical, canonical.replace("registry.npmjs.org", "example.invalid"), 1,
        )
        self.assert_refused("npm_request_refused", subject.parse_request_doc, foreign.encode("utf-8"))

    def test_size_and_type_limits(self):
        self.assert_refused("npm_request_refused", subject.parse_request_doc, b"")
        self.assert_refused("npm_request_refused", subject.parse_request_doc, "x")
        self.assert_refused(
            "npm_request_refused", subject.parse_request_doc, b"x" * (subject.MAX_REQUEST_DOC_BYTES + 1),
        )
        self.assert_refused("npm_request_refused", subject.parse_request_doc, b"\xff\xfe")


class InputTests(RefusalAssertions):
    def mutated(self, path, change):
        world = World()
        files = dict(world.files)
        manifest = json.loads(files[path].decode("ascii"))
        change(manifest)
        files[path] = _json(manifest) + b"\n"
        return files

    def test_a_good_filing_yields_the_immutable_plan(self):
        plan = World().plan()
        self.assertEqual(plan["filing"], subject.DEFAULT_FILING)
        self.assertEqual(plan["direct"], dict(DIRECT))
        self.assertEqual(plan["overrides"], dict(OVERRIDE))
        self.assertEqual([item["path"] for item in plan["workspaces"]], list(subject.WORKSPACE_PATHS))
        self.assertEqual(plan["root"]["devDependencies"], dict(DIRECT))
        self.assertRegex(plan["inputs_sha256"], r"[a-f0-9]{64}\Z")
        self.assertRegex(plan["request_doc_sha256"], r"[a-f0-9]{64}\Z")
        self.assertEqual(plan["inputs_sha256"], World().plan()["inputs_sha256"])

    def test_inputs_are_fixed_paths_and_the_project_never_gets_the_request_table(self):
        paths = subject.input_paths(subject.DEFAULT_FILING)
        self.assertEqual(paths[:3], (".node-version", ".npmrc", "package.json"))
        self.assertIn(subject.FILINGS[subject.DEFAULT_FILING]["request_doc"], paths)
        project = subject.project_paths(subject.DEFAULT_FILING)
        doc = subject.FILINGS[subject.DEFAULT_FILING]["request_doc"]
        self.assertEqual(set(paths) - set(project), {doc, subject.POLICY_FILE})
        self.assert_refused("npm_input_invalid", subject.input_paths, "other-filing")
        self.assert_refused("npm_input_invalid", subject.input_paths, None)

    def test_missing_extra_empty_or_non_bytes_files_are_refused(self):
        world = World()
        short = dict(world.files)
        del short["package.json"]
        extra = dict(world.files, **{"extra.json": b"{}"})
        empty = dict(world.files, **{"package.json": b""})
        text = dict(world.files, **{"package.json": "{}"})
        for files in (short, extra, empty, text, None, []):
            with self.subTest(files=type(files).__name__):
                self.assert_refused("npm_input_invalid", subject.check_inputs, files, subject.DEFAULT_FILING)

    def test_node_version_and_npm_settings_must_match_exactly(self):
        world = World()
        for path, value in (
            (".node-version", b"24.22.2\n"), (".node-version", b"24.22.1"),
            (".npmrc", subject.NPMRC_BYTES + b"registry=other\n"), (".npmrc", b"ignore-scripts=false\n"),
        ):
            with self.subTest(path=path, value=value):
                files = dict(world.files, **{path: value})
                self.assert_refused("npm_manifest_refused", subject.check_inputs, files, subject.DEFAULT_FILING)

    def test_root_manifest_shape_is_closed(self):
        changes = (
            lambda manifest: manifest.update({"resolutions": {}}),
            lambda manifest: manifest.update({"name": "other"}),
            lambda manifest: manifest.update({"private": False}),
            lambda manifest: manifest.update({"packageManager": "npm@11.0.0"}),
            lambda manifest: manifest.update({"engines": {"node": "24.22.1"}}),
            lambda manifest: manifest.update({"workspaces": ["packages/*", "extra/*"]}),
            lambda manifest: manifest["scripts"].update({"postinstall": "run x"}),
            lambda manifest: manifest["scripts"].update({"prepare": "run x"}),
            lambda manifest: manifest["devDependencies"].update({"alpha-pkg": "^1.0.0"}),
            lambda manifest: manifest["devDependencies"].update({"alpha-pkg": "latest"}),
            lambda manifest: manifest["devDependencies"].update({"alpha-pkg": "npm:other@1.0.0"}),
            lambda manifest: manifest["devDependencies"].update({"alpha-pkg": "1.0.0+build"}),
            lambda manifest: manifest["devDependencies"].update({"Bad_Name": "1.0.0"}),
            lambda manifest: manifest["devDependencies"].update({subject.SCOPE + "x": "1.0.0"}),
            lambda manifest: manifest.update({"overrides": {"lightningcss": "1.32.0"}}),
            lambda manifest: manifest.update({"overrides": {"lightningcss": "1.33.0", "other": "1.0.0"}}),
            lambda manifest: manifest.pop("overrides"),
            lambda manifest: manifest.update({"overrides": {"lightningcss": {"x": "1.33.0"}}}),
        )
        for index, change in enumerate(changes):
            with self.subTest(change=index):
                files = self.mutated("package.json", change)
                self.assert_refused("npm_manifest_refused", subject.check_inputs, files, subject.DEFAULT_FILING)

    def test_duplicate_keys_and_invalid_json_are_refused(self):
        world = World()
        for payload in (b'{"name":"a","name":"b"}', b"not json", b"[]", b"\xef\xbb\xbf{}"):
            with self.subTest(payload=payload):
                files = dict(world.files, **{"package.json": payload})
                self.assert_refused("npm_manifest_refused", subject.check_inputs, files, subject.DEFAULT_FILING)

    def test_workspace_manifest_shape_is_closed_and_pins_must_agree_with_the_root(self):
        path = subject.WORKSPACE_PATHS[0] + "/package.json"
        for index, change in enumerate((
            lambda manifest: manifest.update({"name": "other"}),
            lambda manifest: manifest.update({"bin": "x"}),
            lambda manifest: manifest["scripts"].update({"install": "run"}),
            lambda manifest: manifest.update({"dependencies": {"alpha-pkg": "1.0.1"}}),
            lambda manifest: manifest.update({"dependencies": {"alpha-pkg": "~1.0.0"}}),
            lambda manifest: manifest.update({"version": "latest"}),
        )):
            with self.subTest(change=index):
                files = self.mutated(path, change)
                self.assert_refused("npm_manifest_refused", subject.check_inputs, files, subject.DEFAULT_FILING)

    def test_a_workspace_pin_equal_to_the_root_pin_is_accepted(self):
        path = subject.WORKSPACE_PATHS[0] + "/package.json"
        files = self.mutated(path, lambda manifest: manifest.update({"dependencies": {"alpha-pkg": "1.0.0"}}))
        plan = subject.check_inputs(files, subject.DEFAULT_FILING)
        self.assertEqual(plan["workspaces"][0]["dependencies"], {"alpha-pkg": "1.0.0"})
        self.assertEqual(plan["direct"], dict(DIRECT))

    def test_every_direct_pin_and_override_needs_a_filed_row(self):
        world = World()
        doc_path = subject.FILINGS[subject.DEFAULT_FILING]["request_doc"]
        text = world.files[doc_path].decode("utf-8")
        for name in ("alpha-pkg", "lightningcss"):
            lines = [line for line in text.split("\n") if not line.startswith("| " + name + " ")]
            files = dict(world.files, **{doc_path: "\n".join(lines).encode("utf-8")})
            with self.subTest(name=name):
                self.assert_refused("npm_request_mismatch", subject.check_inputs, files, subject.DEFAULT_FILING)

    def test_the_policy_direct_set_must_equal_the_root_dependency_union(self):
        world = World()
        files = dict(world.files)
        manifest = json.loads(files["package.json"].decode("ascii"))
        manifest["devDependencies"]["delta-pkg"] = "4.0.0"
        files["package.json"] = _json(manifest) + b"\n"
        self.assert_refused("npm_policy_refused", subject.check_inputs, files, subject.DEFAULT_FILING)
        files = dict(world.files)
        manifest = json.loads(files["package.json"].decode("ascii"))
        manifest["devDependencies"]["alpha-pkg"] = "1.0.1"
        files["package.json"] = _json(manifest) + b"\n"
        self.assert_refused("npm_policy_refused", subject.check_inputs, files, subject.DEFAULT_FILING)


class CommandTests(RefusalAssertions):
    PATHS = dict(node="/n/bin/node", npm="/n/lib/npm-cli.js", user="/s/user.npmrc", glob="/s/global.npmrc")

    def command(self, **changes):
        values = dict(self.PATHS, cutoff=1_792_000_000_000)
        values.update(changes)
        return subject.resolve_command(
            values["node"], values["npm"], values["cutoff"], values["user"], values["glob"],
        )

    def test_the_resolver_command_is_one_package_lock_only_run_with_every_guard(self):
        command = self.command()
        self.assertEqual(command[:2], ("/n/bin/node", "/n/lib/npm-cli.js"))
        for flag in (
            "--registry=" + subject.REGISTRY_URL, "--userconfig=/s/user.npmrc",
            "--globalconfig=/s/global.npmrc", "--ignore-scripts", "--audit=false", "--fund=false",
            "--fetch-retries=0", "--no-update-notifier", "--strict-peer-deps", "--min-release-age=7",
            "--before=2026-10-14T17:46:40.000Z",
        ):
            with self.subTest(flag=flag):
                self.assertIn(flag, command)
        self.assertEqual(
            command[-4:], ("install", "--package-lock-only", "--workspaces=true", "--include-workspace-root"),
        )
        self.assertEqual(len([part for part in command if part.startswith("--before=")]), 1)

    def test_relative_paths_equal_configs_and_bad_cutoffs_are_refused(self):
        for changes in (
            {"node": "node"}, {"npm": "npm-cli.js"}, {"user": "user.npmrc"}, {"glob": "global.npmrc"},
            {"glob": "/s/user.npmrc"}, {"cutoff": 0}, {"cutoff": "1"}, {"cutoff": None},
            {"node": "/n/\nnode"},
        ):
            with self.subTest(changes=changes):
                self.assert_refused("npm_environment_refused", self.command, **changes)

    def test_the_cutoff_is_seven_full_days_before_the_policy_time(self):
        self.assertEqual(subject.policy_cutoff_ms(NOW * 1000), NOW * 1000 - 7 * 24 * 3600 * 1000)
        for value in (0, -1, "1", None):
            with self.subTest(value=value):
                self.assert_refused("npm_input_invalid", subject.policy_cutoff_ms, value)

    @unittest.skipUnless(sys.platform != "win32", "the macOS npm environment path test requires POSIX paths")
    def test_the_environment_is_built_from_fixed_values_only(self):
        environment = subject.build_npm_environment(
            "/n/bin/node", home="/s/home", tmpdir="/s/tmp", cache="/s/cache",
            user_config="/s/user.npmrc", global_config="/s/global.npmrc", node_options="--x",
        )
        self.assertEqual(environment["PATH"], "/n/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertEqual(environment["npm_config_registry"], subject.REGISTRY_URL)
        self.assertEqual(environment["npm_config_ignore_scripts"], "true")
        self.assertEqual(environment["NODE_OPTIONS"], "--x")
        for key in environment:
            self.assertNotIn("TOKEN", key.upper())
        self.assert_refused(
            "npm_environment_refused", subject.build_npm_environment, "/n/bin/node", home="home",
            tmpdir="/s/tmp", cache="/s/cache", user_config="/s/u", global_config="/s/g", node_options="--x",
        )
        self.assert_refused(
            "npm_environment_refused", subject.build_npm_environment, "/n/bin/node", home="/s/home",
            tmpdir="/s/tmp", cache="/s/cache", user_config="/s/u", global_config="/s/g", node_options="",
        )

    def test_inherited_variables_that_could_steer_npm_are_named(self):
        parent = {
            "PATH": "/usr/bin", "NPM_TOKEN": "x", "npm_config_registry": "x", "NODE_OPTIONS": "x",
            "HTTPS_PROXY": "x", "no_proxy": "x", "GIT_SSH": "x", "HOME": "/h", "SSL_CERT_FILE": "x",
        }
        self.assertEqual(
            subject.injected_environment_names(parent),
            ("GIT_SSH", "HTTPS_PROXY", "NODE_OPTIONS", "NPM_TOKEN", "SSL_CERT_FILE", "no_proxy", "npm_config_registry"),
        )
        self.assert_refused("npm_environment_refused", subject.injected_environment_names, [])


class LockTests(RefusalAssertions):
    def encode(self, lock):
        return _json(lock) + b"\n"

    def check(self, change):
        world = World()
        lock = json.loads(json.dumps(world.lock_dict))
        change(lock)
        return subject.check_lock(self.encode(lock), world.plan())

    def test_the_resolved_lock_is_accepted_and_its_entries_are_listed_in_path_order(self):
        world = World()
        lock, entries = subject.check_lock(world.lock_bytes, world.plan())
        self.assertEqual(lock["name"], subject.ROOT_NAME)
        paths = [path for path, entry in entries]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(sorted(entry["name"] for path, entry in entries), sorted(name for name, version in ALL_PACKAGES))

    def test_oversize_and_non_lock_input_is_refused(self):
        plan = World().plan()
        self.assert_refused("npm_lock_refused", subject.check_lock, b"", plan)
        self.assert_refused("npm_lock_refused", subject.check_lock, "text", plan)
        self.assert_refused("npm_payload_too_large", subject.check_lock, b"x" * (subject.MAX_LOCK_BYTES + 1), plan)
        self.assert_refused("npm_lock_refused", subject.check_lock, b"{}", plan)
        self.assert_refused("npm_lock_refused", subject.check_lock, b"[1]", plan)

    def test_root_and_workspace_entries_must_agree_with_the_manifests(self):
        for index, change in enumerate((
            lambda lock: lock["packages"][""].update({"devDependencies": {"alpha-pkg": "1.0.0"}}),
            lambda lock: lock["packages"][""].update({"engines": {"node": "24.22.1", "npm": "11.0.0"}}),
            lambda lock: lock["packages"][""].update({"dependencies": {"alpha-pkg": "1.0.0"}}),
            lambda lock: lock["packages"][""].update({"workspaces": ["other/*"]}),
            lambda lock: lock.update({"name": "other"}),
            lambda lock: lock.update({"version": "9.9.9"}),
            lambda lock: lock["packages"]["packages/host-api"].update({"version": "9.9.9"}),
            lambda lock: lock["packages"]["packages/kernel-i18n"].update({"dependencies": {"alpha-pkg": "1.0.0"}}),
        )):
            with self.subTest(change=index):
                with self.assertRaises(subject.BootstrapRefusal) as raised:
                    self.check(change)
                self.assertEqual(raised.exception.reason, "npm_lock_refused")

    def test_a_missing_workspace_link_or_an_unexpected_one_is_refused(self):
        links = subject.workspace_links()
        link = sorted(links)[0]
        for index, change in enumerate((
            lambda lock: lock["packages"].pop(link),
            lambda lock: lock["packages"].update({
                "node_modules/other-link": {"resolved": "packages/other", "link": True},
            }),
        )):
            with self.subTest(change=index):
                with self.assertRaises(subject.BootstrapRefusal) as raised:
                    self.check(change)
                self.assertEqual(raised.exception.reason, "npm_lock_refused")

    def test_direct_pins_must_be_hoisted_exactly_once_at_the_pinned_version(self):
        world = World()
        for index, change in enumerate((
            lambda lock: lock["packages"].pop("node_modules/alpha-pkg"),
            lambda lock: lock["packages"]["node_modules/alpha-pkg"].update({"version": "1.0.1"}),
            lambda lock: lock["packages"].update({
                "node_modules/gamma-pkg/node_modules/alpha-pkg":
                    dict(lock["packages"]["node_modules/alpha-pkg"]),
            }),
            lambda lock: lock["packages"].update({
                "node_modules/beta-pkg/node_modules/alpha-pkg":
                    dict(lock["packages"].pop("node_modules/alpha-pkg")),
            }),
        )):
            with self.subTest(change=index):
                with self.assertRaises(subject.BootstrapRefusal) as raised:
                    self.check(change)
                self.assertIn(raised.exception.reason, ("npm_lock_refused",))
        self.assertTrue(world.plan())

    def test_an_override_needs_one_lock_entry_at_its_pinned_version(self):
        for index, change in enumerate((
            lambda lock: lock["packages"].pop("node_modules/lightningcss"),
            lambda lock: lock["packages"]["node_modules/lightningcss"].update({"version": "1.32.0"}),
            lambda lock: lock["packages"].update({
                "node_modules/gamma-pkg/node_modules/lightningcss":
                    dict(lock["packages"]["node_modules/lightningcss"]),
            }),
        )):
            with self.subTest(change=index):
                with self.assertRaises(subject.BootstrapRefusal) as raised:
                    self.check(change)
                self.assertEqual(raised.exception.reason, "npm_lock_refused")

    def test_unsafe_sources_names_and_bundled_trees_are_refused_by_the_shared_parser(self):
        for index, change in enumerate((
            lambda lock: lock["packages"]["node_modules/gamma-pkg"].update({"resolved": "git+ssh://host/x.git"}),
            lambda lock: lock["packages"]["node_modules/gamma-pkg"].pop("integrity"),
            lambda lock: lock["packages"]["node_modules/gamma-pkg"].update({"inBundle": True}),
            lambda lock: lock["packages"].update({
                "node_modules/" + subject.SCOPE + "evil": dict(lock["packages"]["node_modules/gamma-pkg"]),
            }),
            lambda lock: lock["packages"]["node_modules/gamma-pkg"].update({"hasShrinkwrap": True}),
        )):
            with self.subTest(change=index):
                with self.assertRaises(subject.BootstrapRefusal) as raised:
                    self.check(change)
                self.assertEqual(raised.exception.reason, "npm_lock_refused")


class PeerTests(RefusalAssertions):
    def tree(self, peers, meta=None, extra=None, path="node_modules/a"):
        packages = {
            path: {"version": "1.0.0", "peerDependencies": peers},
            "node_modules/react": {"version": "19.3.1"},
            "node_modules/old": {"version": "17.0.0"},
        }
        if meta is not None:
            packages[path]["peerDependenciesMeta"] = meta
        packages.update(extra or {})
        return {"packages": packages}, [(path, packages[path])]

    def test_satisfied_peers_are_counted(self):
        lock, entries = self.tree({"react": "^18 || ^19", "old": ">=17"})
        self.assertEqual(subject.check_peers(lock, entries), {"verified": 2, "optional_missing": 0})

    def test_a_missing_required_peer_an_out_of_range_peer_and_an_unparsable_range_are_refused(self):
        for peers in ({"absent": "^1"}, {"react": "^18"}, {"react": "latest"}, {"react": "npm:x@1"}):
            with self.subTest(peers=peers):
                lock, entries = self.tree(peers)
                self.assert_refused("npm_peer_refused", subject.check_peers, lock, entries)

    def test_optional_peers_may_be_absent_but_never_out_of_range(self):
        lock, entries = self.tree({"absent": "^1"}, meta={"absent": {"optional": True}})
        self.assertEqual(subject.check_peers(lock, entries), {"verified": 0, "optional_missing": 1})
        lock, entries = self.tree({"react": "^18"}, meta={"react": {"optional": True}})
        self.assert_refused("npm_peer_refused", subject.check_peers, lock, entries)

    def test_peers_resolve_through_the_nearest_enclosing_node_modules_directory(self):
        nested = "node_modules/host/node_modules/a"
        lock, entries = self.tree(
            {"react": "^18"}, path=nested,
            extra={"node_modules/host/node_modules/react": {"version": "18.3.0"}},
        )
        self.assertEqual(subject.check_peers(lock, entries)["verified"], 1)
        scoped = "node_modules/@scope/a"
        lock, entries = self.tree({"react": "^19"}, path=scoped)
        self.assertEqual(subject.check_peers(lock, entries)["verified"], 1)

    def test_a_peer_that_resolves_to_a_link_uses_the_linked_manifest_version(self):
        lock, entries = self.tree(
            {"ws": ">=1"},
            extra={
                "node_modules/ws": {"resolved": "packages/ws", "link": True},
                "packages/ws": {"name": "ws", "version": "2.0.0"},
            },
        )
        self.assertEqual(subject.check_peers(lock, entries)["verified"], 1)


class LicenceTests(RefusalAssertions):
    def test_licence_fields_are_normalised(self):
        self.assertEqual(subject.licence_text("MIT"), "MIT")
        self.assertEqual(subject.licence_text(" MIT "), "MIT")
        self.assertEqual(subject.licence_text({"type": "ISC", "url": "x"}), "ISC")
        self.assertEqual(subject.licence_text([{"type": "MIT"}]), "MIT")
        self.assertEqual(subject.licence_text([{"type": "MIT"}, {"type": "Apache-2.0"}]), "(MIT OR Apache-2.0)")
        for value in (None, "", "   ", 5, {}, {"type": 5}, [], [{"url": "x"}], "caf" + chr(0xE9), "x" * 300, "a\nb"):
            with self.subTest(value=value):
                self.assertIsNone(subject.licence_text(value))

    def plan(self, allowlist=None, elections=None):
        return {
            "licence_allowlist": frozenset(subject.BUILTIN_LICENCES if allowlist is None else allowlist),
            "licence_elections": elections or {},
        }

    def test_every_decided_licence_is_allowed_and_conditional_ones_are_flagged(self):
        for licence in (
            "MIT", "Apache-2.0", "MPL-2.0", "OFL-1.1", "ISC", "BSD-2-Clause", "BSD-3-Clause", "MIT-0",
            "BlueOak-1.0.0", "CC0-1.0", "Unicode-3.0",
        ):
            with self.subTest(licence=licence):
                expected = [licence] if licence in ("MPL-2.0", "OFL-1.1") else []
                self.assertEqual(subject.resolve_licence("pkg", licence, self.plan()), (licence, expected))
        self.assertEqual(len(subject.BUILTIN_LICENCES), 11)

    def test_licences_outside_the_allowlist_are_refused_with_no_wildcards_or_other_forms(self):
        for value in (
            None, "", "UNLICENSED", "SEE LICENSE IN LICENSE.md", "GPL-3.0-only", "LGPL-2.1", "AGPL-3.0",
            "CC-BY-4.0", "BSD", "mit", "MIT*", "MIT+", "Apache-2.0 AND MIT", "(MIT AND CC0-1.0)",
            "(MIT OR CC0-1.0 OR ISC)", "((MIT OR CC0-1.0))", "MIT OR", "OR MIT", "(MIT OR CC0-1.0",
            "MIT WITH Exception", "Apache-2.0 OR", "(MIT OR  CC0-1.0)",
        ):
            with self.subTest(value=value):
                self.assert_refused("npm_licence_refused", subject.resolve_licence, "pkg", value, self.plan())

    def test_cc_by_is_allowed_only_for_caniuse_lite(self):
        plan = self.plan()
        self.assertEqual(subject.resolve_licence("caniuse-lite", "CC-BY-4.0", plan), ("CC-BY-4.0", ["CC-BY-4.0"]))
        for name in ("other-pkg", "caniuse-lite-fork", "caniuse"):
            with self.subTest(name=name):
                self.assert_refused("npm_licence_refused", subject.resolve_licence, name, "CC-BY-4.0", plan)

    def test_an_expression_needs_a_recorded_election_naming_one_of_its_two_licences(self):
        expression = "(MIT OR CC0-1.0)"
        bare = "MIT OR CC0-1.0"
        for text in (expression, bare):
            with self.subTest(text=text):
                self.assert_refused("npm_licence_refused", subject.resolve_licence, "type-fest", text, self.plan())
                self.assertEqual(
                    subject.resolve_licence("type-fest", text, self.plan(elections={"type-fest": "CC0-1.0"})),
                    ("CC0-1.0", []),
                )
                self.assertEqual(
                    subject.resolve_licence("type-fest", text, self.plan(elections={"type-fest": "MIT"})),
                    ("MIT", []),
                )
        self.assertEqual(
            subject.resolve_licence(
                "dompurify", "(MPL-2.0 OR Apache-2.0)", self.plan(elections={"dompurify": "Apache-2.0"}),
            ),
            ("Apache-2.0", []),
        )
        self.assertEqual(
            subject.resolve_licence(
                "dompurify", "(MPL-2.0 OR Apache-2.0)", self.plan(elections={"dompurify": "MPL-2.0"}),
            ),
            ("MPL-2.0", ["MPL-2.0"]),
        )

    def test_an_election_must_name_a_licence_of_the_expression_that_is_allowed(self):
        for elected in ("ISC", "Apache-2.0", "", "MIT OR CC0-1.0"):
            with self.subTest(elected=elected):
                self.assert_refused(
                    "npm_licence_refused", subject.resolve_licence, "type-fest", "(MIT OR CC0-1.0)",
                    self.plan(elections={"type-fest": elected}),
                )
        narrow = self.plan(allowlist=("MIT",), elections={"type-fest": "CC0-1.0"})
        self.assert_refused("npm_licence_refused", subject.resolve_licence, "type-fest", "(MIT OR CC0-1.0)", narrow)
        gpl = self.plan(elections={"x": "GPL-3.0-only"})
        self.assert_refused("npm_licence_refused", subject.resolve_licence, "x", "(MIT OR GPL-3.0-only)", gpl)

    def test_an_election_for_a_package_without_an_expression_is_refused(self):
        self.assert_refused(
            "npm_licence_refused", subject.resolve_licence, "alpha-pkg", "MIT",
            self.plan(elections={"alpha-pkg": "MIT"}),
        )
        plan = self.plan(elections={"type-fest": "MIT"})
        packages = [{"name": "alpha-pkg", "licence": "MIT", "licence_elected": "MIT"}]
        self.assert_refused("npm_licence_refused", subject.check_elections_used, plan, packages)
        packages.append({"name": "type-fest", "licence": "(MIT OR CC0-1.0)", "licence_elected": "MIT"})
        subject.check_elections_used(plan, packages)
        self.assert_refused("npm_licence_refused", subject.check_elections_used, self.plan(), packages)


class PolicyTests(RefusalAssertions):
    def policy(self, **changes):
        value = World().policy()
        for key, change in changes.items():
            if change is None:
                value.pop(key, None)
            else:
                value[key] = change
        return _json(value)

    def test_a_good_policy_is_read_as_inert_data(self):
        policy = subject.parse_policy(self.policy())
        self.assertEqual(policy["direct"], dict(DIRECT))
        self.assertEqual(policy["licence_allowlist"], frozenset(("MIT", "ISC")))
        self.assertEqual(policy["licence_elections"], {})
        self.assertEqual(policy["singleton_names"], frozenset(("alpha-pkg", "lightningcss")))
        scoped = subject.parse_policy(self.policy(licence_elections={"caniuse-lite": "CC-BY-4.0"}))
        self.assertEqual(scoped["licence_elections"], {"caniuse-lite": "CC-BY-4.0"})

    def test_the_field_set_is_exactly_the_eight_documented_fields(self):
        self.assertEqual(sorted(subject.POLICY_FIELDS), sorted((
            "schema_version", "policy_epoch_ms", "direct", "singleton_names", "internal_names",
            "licence_allowlist", "licence_elections", "development_advisory_allows",
        )))
        for field in sorted(subject.POLICY_FIELDS):
            with self.subTest(missing=field):
                self.assert_refused("npm_policy_refused", subject.parse_policy, self.policy(**{field: None}))
        self.assert_refused("npm_policy_refused", subject.parse_policy, self.policy(unknown_field=1))

    def test_scalar_and_list_fields_are_strictly_typed_and_bounded(self):
        for changes in (
            {"schema_version": 2}, {"schema_version": True}, {"policy_epoch_ms": 0}, {"policy_epoch_ms": "1"},
            {"policy_epoch_ms": 1.5}, {"direct": []}, {"direct": {"alpha-pkg": "^1.0.0"}},
            {"direct": {"Bad_Name": "1.0.0"}}, {"singleton_names": {}}, {"singleton_names": ["a", "a"]},
            {"singleton_names": ["Bad Name"]}, {"internal_names": "x"}, {"licence_allowlist": []},
            {"licence_allowlist": ["MIT", "MIT"]}, {"licence_allowlist": ["MIT*"]},
            {"licence_allowlist": ["MIT", 5]}, {"development_advisory_allows": {}},
        ):
            with self.subTest(changes=changes):
                self.assert_refused("npm_policy_refused", subject.parse_policy, self.policy(**changes))
        for data in (b"", b"[]", b"not json", b'{"schema_version":1,"schema_version":1}'):
            with self.subTest(data=data):
                self.assert_refused("npm_policy_refused", subject.parse_policy, data)
        self.assert_refused("npm_policy_refused", subject.parse_policy, b"x" * (subject.MAX_POLICY_BYTES + 1))

    def test_the_allowlist_can_only_narrow_the_decided_licence_set(self):
        for licence in ("CC-BY-4.0", "GPL-3.0-only", "BSD-4-Clause", "(MIT OR CC0-1.0)"):
            with self.subTest(licence=licence):
                self.assert_refused(
                    "npm_policy_refused", subject.parse_policy, self.policy(licence_allowlist=["MIT", licence]),
                )
        subject.parse_policy(self.policy(licence_allowlist=sorted(subject.BUILTIN_LICENCES)))

    def test_elections_are_a_bounded_name_to_identifier_map_naming_permitted_licences(self):
        for elections in (
            [], "x", {"alpha-pkg": 5}, {"alpha-pkg": ""}, {"Bad Name": "MIT"}, {"alpha-pkg": "GPL-3.0-only"},
            {"alpha-pkg": "CC-BY-4.0"}, {"alpha-pkg": "MIT OR ISC"}, {"alpha-pkg": "(MIT)"},
            {"alpha-pkg": "Apache-2.0"},
            {"name%d" % index: "MIT" for index in range(257)},
        ):
            with self.subTest(elections=elections):
                self.assert_refused(
                    "npm_policy_refused", subject.parse_policy, self.policy(licence_elections=elections),
                )
        subject.parse_policy(self.policy(licence_allowlist=["MIT", "Apache-2.0"], licence_elections={"dompurify": "Apache-2.0"}))

    def test_advisory_allow_records_are_exact(self):
        good = {
            "name": "alpha-pkg", "advisory_id": "GHSA-aaaa-bbbb", "consumers": ["alpha-pkg"],
            "justification_sha256": "a" * 64, "expires_at_ms": 5, "removal_condition": "upgrade",
        }
        policy = subject.parse_policy(self.policy(development_advisory_allows=[good]))
        self.assertEqual(policy["advisory_allows"][0]["consumers"], ("alpha-pkg",))
        for change in (
            {"extra": 1}, {"name": "Bad Name"}, {"advisory_id": ""}, {"advisory_id": "-x"}, {"consumers": []},
            {"consumers": ["a", "a"]}, {"consumers": "alpha-pkg"}, {"justification_sha256": "A" * 64},
            {"expires_at_ms": 0}, {"expires_at_ms": "5"}, {"removal_condition": "has space"},
        ):
            with self.subTest(change=change):
                self.assert_refused(
                    "npm_policy_refused", subject.parse_policy,
                    self.policy(development_advisory_allows=[dict(good, **change)]),
                )
        self.assert_refused(
            "npm_policy_refused", subject.parse_policy,
            self.policy(development_advisory_allows=[{k: v for k, v in good.items() if k != "name"}]),
        )

    def test_internal_names_ban_direct_pins_in_the_manifests_and_the_policy(self):
        world = World(policy_extra={"internal_names": ["alpha-pkg"]})
        self.assert_refused("npm_policy_refused", world.plan)


class FakeResponse:
    def __init__(self, status, body, url):
        self.status = status
        self.body = body
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False

    def geturl(self):
        return self.url

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


class FakeOpener:
    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request.full_url, request.get_method(), request.data, timeout))
        entry = self.routes.get(request.full_url)
        if entry is None:
            raise urllib.error.URLError("unreachable")
        return FakeResponse(*entry)


class FetcherTests(RefusalAssertions):
    def url(self, path):
        return subject.REGISTRY_URL[:-1] + path

    def test_packuments_archives_and_advisories_use_the_exact_fixed_origin_urls(self):
        archive_url = adm._canonical_tarball_url("@scope/pkg", "1.0.0")
        opener = FakeOpener({
            self.url("/@scope%2Fpkg"): (200, b"{}", self.url("/@scope%2Fpkg")),
            self.url("/plain"): (200, b"{}", self.url("/plain")),
            archive_url: (200, b"archive", archive_url),
            self.url(subject.ADVISORY_PATH): (200, b"{}", self.url(subject.ADVISORY_PATH)),
        })
        fetcher = subject.RegistryFetcher(opener=opener)
        self.assertEqual(fetcher.packument("@scope/pkg"), b"{}")
        self.assertEqual(fetcher.packument("plain"), b"{}")
        self.assertEqual(fetcher.tarball("@scope/pkg", "1.0.0"), b"archive")
        self.assertEqual(fetcher.advisories(b'{"plain":["1.0.0"]}'), b"{}")
        methods = [(url, method, data) for url, method, data, timeout in opener.requests]
        self.assertEqual(methods[0], (self.url("/@scope%2Fpkg"), "GET", None))
        self.assertEqual(methods[3], (self.url(subject.ADVISORY_PATH), "POST", b'{"plain":["1.0.0"]}'))
        self.assertTrue(all(timeout == subject.FETCH_TIMEOUT_SECONDS for url, method, data, timeout in opener.requests))
        self.assertEqual(fetcher.requests_made, 4)

    def test_default_opener_blocks_proxies_and_redirects(self):
        fetcher = subject.RegistryFetcher()
        handlers = [type(handler).__name__ for handler in fetcher._opener.handlers]
        self.assertNotIn("ProxyHandler", handlers)
        self.assertIn("_NoRedirect", handlers)
        self.assertFalse([handler for handler in fetcher._opener.handlers if hasattr(handler, "proxies")])
        redirect = subject._NoRedirect()
        self.assertIsNone(redirect.redirect_request(None, None, 302, "Found", {}, subject.REGISTRY_URL + "other"))

    def test_redirected_failed_empty_oversize_and_unreachable_answers_are_refused(self):
        path = "/plain"
        for status, body, final in (
            (200, b"{}", self.url("/elsewhere")), (404, b"{}", self.url(path)), (200, b"", self.url(path)),
            (200, b"x" * 11, self.url(path)), (301, b"{}", self.url(path)),
        ):
            with self.subTest(status=status, size=len(body), final=final):
                fetcher = subject.RegistryFetcher(opener=FakeOpener({self.url(path): (status, body, final)}))
                self.assert_refused("npm_network_refused", fetcher._exchange, path, 10, "application/json")
        fetcher = subject.RegistryFetcher(opener=FakeOpener({}))
        self.assert_refused("npm_network_refused", fetcher._exchange, path, 10, "application/json")

    def test_paths_with_queries_fragments_or_other_shapes_are_refused(self):
        fetcher = subject.RegistryFetcher(opener=FakeOpener({}))
        for path in ("plain", "/a?b=1", "/a" + chr(35) + "b", "/" + "x" * 1100, None):
            with self.subTest(path=path):
                self.assert_refused("npm_network_refused", fetcher._exchange, path, 10, "application/json")

    def test_the_request_budget_and_the_deadline_are_enforced(self):
        opener = FakeOpener({self.url("/plain"): (200, b"{}", self.url("/plain"))})
        fetcher = subject.RegistryFetcher(opener=opener)
        fetcher.requests_made = subject.MAX_REQUESTS
        self.assert_refused("npm_network_refused", fetcher._exchange, "/plain", 10, "application/json")
        expired = subject.RegistryFetcher(opener=opener, deadline=0.0)
        self.assert_refused("npm_stale", expired._exchange, "/plain", 10, "application/json")
        self.assertEqual(opener.requests, [])

    def test_invalid_names_versions_and_bodies_are_refused_before_any_request(self):
        opener = FakeOpener({})
        fetcher = subject.RegistryFetcher(opener=opener)
        self.assert_refused("npm_input_invalid", fetcher.packument, "Bad Name")
        self.assert_refused("npm_input_invalid", fetcher.packument, subject.SCOPE + "internal")
        self.assert_refused("npm_input_invalid", fetcher.tarball, "plain", "^1.0.0")
        self.assert_refused("npm_input_invalid", fetcher.tarball, "plain", "1.0.0+build")
        self.assert_refused("npm_input_invalid", fetcher.advisories, b"")
        self.assertEqual(opener.requests, [])


class AdvisoryTests(RefusalAssertions):
    INVENTORY = {"alpha-pkg": ["1.0.0"], "beta-pkg": ["2.0.0", "2.1.0"]}

    def answer(self, value):
        return json.dumps(value).encode("ascii")

    def test_an_empty_answer_is_clear(self):
        self.assertEqual(subject.check_advisories(b"{}", self.INVENTORY), [])
        self.assertEqual(subject.check_advisories(self.answer({"alpha-pkg": []}), self.INVENTORY), [])

    DIRECT_NAMES = {"alpha-pkg": "1.0.0", "beta-pkg": "2.0.0"}

    def allow(self, name, advisory_id, consumers=("alpha-pkg",), expires=10 ** 15):
        return {
            "name": name, "advisory_id": advisory_id, "consumers": tuple(consumers),
            "justification_sha256": "a" * 64, "expires_at_ms": expires, "removal_condition": "upgrade",
        }

    def check(self, value, allows=(), now_ms=1000):
        return subject.check_advisories(self.answer(value), self.INVENTORY, allows, self.DIRECT_NAMES, now_ms)

    def test_an_unallowed_advisory_of_any_severity_blocks_the_proposal(self):
        for severity in ("info", "low", "moderate", "high", "critical"):
            with self.subTest(severity=severity):
                self.assert_refused("npm_advisory_blocked", self.check, {
                    "alpha-pkg": [{"id": 1, "severity": severity, "vulnerable_versions": "<2.0.0"}],
                })
        self.assertEqual(self.check({
            "alpha-pkg": [{"id": 1, "severity": "critical", "vulnerable_versions": ">=9.0.0"}],
        }), [])

    def test_only_locked_versions_inside_a_range_are_findings_and_need_an_allow(self):
        answer = {
            "alpha-pkg": [{"id": 7, "severity": "moderate", "vulnerable_versions": "<1.5.0", "title": "t"}],
            "beta-pkg": [{"id": "x1", "severity": "low", "vulnerable_versions": ">=2.1.0 <3.0.0"}],
        }
        allows = (self.allow("alpha-pkg", "7"), self.allow("beta-pkg", "x1", consumers=("beta-pkg", "alpha-pkg")))
        found = self.check(answer, allows)
        self.assertEqual([(item["name"], item["version"], item["advisory_id"]) for item in found], [
            ("alpha-pkg", "1.0.0", "7"), ("beta-pkg", "2.1.0", "x1"),
        ])
        self.assertEqual(found[0]["allow_justification_sha256"], "a" * 64)
        self.assertEqual(found[0]["allow_removal_condition"], "upgrade")
        self.assertEqual(self.check({
            "alpha-pkg": [{"id": 1, "severity": "moderate", "vulnerable_versions": ">=2.0.0"}],
        }), [])

    def test_an_allow_must_match_name_id_expiry_and_direct_consumers(self):
        answer = {"alpha-pkg": [{"id": 7, "github_advisory_id": "GHSA-aaaa", "severity": "low",
                                 "vulnerable_versions": "<2.0.0"}]}
        self.assertEqual(len(self.check(answer, (self.allow("alpha-pkg", "GHSA-aaaa"),))), 1)
        for allows in (
            (self.allow("beta-pkg", "7"),),
            (self.allow("alpha-pkg", "8"),),
            (self.allow("alpha-pkg", "7", expires=1000),),
            (self.allow("alpha-pkg", "7", expires=999),),
            (self.allow("alpha-pkg", "7", consumers=("transitive-pkg",)),),
            (self.allow("alpha-pkg", "7", consumers=("alpha-pkg", "transitive-pkg")),),
        ):
            with self.subTest(allows=allows):
                self.assert_refused("npm_advisory_blocked", self.check, answer, allows)

    def test_malformed_answers_are_refused(self):
        valid = {"id": 1, "severity": "low", "vulnerable_versions": "<2.0.0"}
        for value in (
            b"not json", b"[]", b"", self.answer({"unrequested": [valid]}), self.answer({"alpha-pkg": {}}),
            self.answer({"alpha-pkg": [dict(valid, vulnerable_versions="latest")]}),
            self.answer({"alpha-pkg": [dict(valid, vulnerable_versions="")]}),
            self.answer({"alpha-pkg": [{k: v for k, v in valid.items() if k != "vulnerable_versions"}]}),
            self.answer({"alpha-pkg": [dict(valid, severity="weird")]}),
            self.answer({"alpha-pkg": [dict(valid, id=None)]}),
            self.answer({"alpha-pkg": [dict(valid, name="other")]}),
            self.answer({"alpha-pkg": ["text"]}),
        ):
            with self.subTest(value=value):
                self.assert_refused("npm_advisory_invalid", subject.check_advisories, value, self.INVENTORY)

    def test_too_many_findings_are_refused(self):
        items = [{"id": index, "severity": "low", "vulnerable_versions": "<2.0.0"}
                 for index in range(subject.MAX_FINDINGS + 1)]
        allows = tuple(self.allow("alpha-pkg", str(index)) for index in range(subject.MAX_FINDINGS + 1))
        self.assert_refused("npm_payload_too_large", self.check, {"alpha-pkg": items}, allows)


class BundleTests(RefusalAssertions):
    def test_a_good_proposal_produces_one_verified_bundle(self):
        world = World()
        bundle = world.bundle()
        lock_bytes, receipt_bytes, evidence_bytes = subject.decode_bundle(bundle)
        self.assertEqual(lock_bytes, world.lock_bytes)
        receipt = json.loads(receipt_bytes.decode("ascii"))
        evidence = json.loads(evidence_bytes.decode("ascii"))
        self.assertEqual(receipt["record_type"], subject.RECORD_TYPE)
        self.assertEqual(receipt["context"], world.context)
        self.assertEqual(receipt["lock_sha256"], hashlib.sha256(world.lock_bytes).hexdigest())
        self.assertEqual(
            [item["name"] for item in receipt["packages"]],
            ["alpha-pkg", "beta-pkg", "gamma-pkg", "lightningcss"],
        )
        self.assertTrue(all(item["audit_record_id"] == subject.PENDING_AUDIT_ID for item in receipt["packages"]))
        self.assertEqual(evidence["receipt_sha256"], hashlib.sha256(receipt_bytes).hexdigest())
        self.assertEqual(evidence["lock_sha256"], receipt["lock_sha256"])
        self.assertEqual(evidence["totals"]["packages"], 4)
        self.assertEqual(evidence["totals"]["distinct_names"], 4)
        self.assertEqual(evidence["totals"]["unattested_packages"], 3)
        self.assertEqual(evidence["totals"]["peer_checks"], 1)
        self.assertEqual(evidence["advisory"]["status"], "clear")
        self.assertEqual(evidence["advisory"]["fetched_at"], NOW + 5)
        self.assertEqual(evidence["advisory"]["valid_until"], NOW + 5 + 24 * 3600)
        self.assertEqual(evidence["attestation_verification"], "not_performed")
        self.assertEqual(evidence["policy_epoch_ms"], (NOW - 3600) * 1000)
        self.assertEqual(evidence["cutoff_epoch_ms"], (NOW - 3600) * 1000 - 7 * 24 * 3600 * 1000)
        self.assertEqual([item["direct"] for item in evidence["packages"]], [True, True, False, False])
        alpha = evidence["packages"][0]
        self.assertEqual((alpha["licence"], alpha["attested"], alpha["publisher"]), ("MIT", True, "publisher-a"))
        self.assertEqual(alpha["install_scripts"], [])
        self.assertGreater(alpha["age_days"], 7)
        subject.verify_bundle(bundle, world.plan(), world.context, now=NOW)

    def test_each_name_is_fetched_once_and_archives_in_name_order(self):
        world = World()
        fetcher = world.fetcher()
        world.bundle(fetcher=fetcher)
        names = [call[1] for call in fetcher.calls if call[0] == "packument"]
        self.assertEqual(names, sorted(set(names)))
        self.assertEqual(len([call for call in fetcher.calls if call[0] == "tarball"]), 4)
        self.assertEqual(fetcher.calls[-1][0], "advisories")
        self.assertEqual(json.loads(fetcher.calls[-1][1].decode("ascii"))["alpha-pkg"], ["1.0.0"])

    def test_lifecycle_scripts_and_native_binaries_are_recorded_not_run(self):
        world = World()
        data = _tarball("gamma-pkg", "3.1.0", scripts={"install": "node install.js"}, binary=True)
        world.archives[("gamma-pkg", "3.1.0")] = data
        world.integrity["gamma-pkg"] = _sri(data)
        world.lock_dict = world._lock()
        world.lock_bytes = _json(world.lock_dict) + b"\n"
        evidence = json.loads(subject.decode_bundle(world.bundle())[2].decode("ascii"))
        gamma = [item for item in evidence["packages"] if item["name"] == "gamma-pkg"][0]
        self.assertEqual(gamma["install_scripts"], ["install"])
        self.assertEqual(gamma["native_count"], 1)
        self.assertEqual(gamma["native_sample"], ["package/binding.node"])
        self.assertEqual(evidence["totals"]["install_script_packages"], 1)
        self.assertEqual(evidence["totals"]["native_packages"], 1)

    def test_allowed_advisory_findings_are_returned_with_the_evidence(self):
        advisory = json.dumps({"gamma-pkg": [
            {"id": 5, "severity": "moderate", "vulnerable_versions": "<4.0.0"},
        ]}).encode("ascii")
        allow = {
            "name": "gamma-pkg", "advisory_id": "5", "consumers": ["alpha-pkg"],
            "justification_sha256": "b" * 64, "expires_at_ms": (NOW + 86400) * 1000,
            "removal_condition": "upgrade-gamma",
        }
        self.refused("npm_advisory_blocked", advisory=advisory)
        evidence = json.loads(subject.decode_bundle(
            World(advisory=advisory, allows=[allow]).bundle())[2].decode("ascii"))
        self.assertEqual(evidence["advisory"]["status"], "allowed_findings")
        self.assertEqual(evidence["advisory"]["finding_count"], 1)
        self.assertEqual(evidence["advisory"]["findings"][0]["allow_justification_sha256"], "b" * 64)

    def test_the_policy_licence_rules_apply_to_every_locked_package(self):
        self.refused("npm_licence_refused", registry_license={"gamma-pkg": "CC-BY-4.0"})
        self.refused("npm_licence_refused", registry_license={"gamma-pkg": "(MIT OR CC0-1.0)"})
        self.refused("npm_licence_refused", registry_license={"gamma-pkg": "MIT"}, elections={"gamma-pkg": "MIT"})
        self.refused("npm_policy_refused", registry_license={"gamma-pkg": "(MIT OR CC0-1.0)"},
                     elections={"gamma-pkg": "GPL-3.0-only"})
        world = World(registry_license={"gamma-pkg": "(MIT OR CC0-1.0)"}, elections={"gamma-pkg": "CC0-1.0"},
                      allowlist=["MIT", "CC0-1.0"])
        evidence = json.loads(subject.decode_bundle(world.bundle())[2].decode("ascii"))
        gamma = evidence["packages"][2]
        self.assertEqual((gamma["licence"], gamma["licence_elected"]), ("(MIT OR CC0-1.0)", "CC0-1.0"))
        isc = World(registry_license={"gamma-pkg": "ISC"})
        self.assertEqual(json.loads(subject.decode_bundle(isc.bundle())[2].decode("ascii"))["packages"][2]["licence"], "ISC")

    def test_the_filing_time_must_be_in_the_past_and_at_most_one_day_old(self):
        world = World()
        self.assert_refused("npm_stale", world.bundle, now=NOW + 24 * 3600, expiry=NOW + 25 * 3600)
        self.assert_refused("npm_stale", world.bundle, now=NOW - 7200, expiry=NOW)
        future = World(policy_epoch_ms=(NOW + 3600) * 1000)
        self.assert_refused("npm_stale", future.bundle)
        plan = world.plan()
        self.assert_refused("npm_stale", subject.check_policy_time, plan, 0)
        self.assertEqual(subject.check_policy_time(plan, NOW), NOW - 3600)


    def refused(self, reason, **world_arguments):
        world = World(**world_arguments)
        self.assert_refused(reason, world.bundle)

    def test_a_young_version_is_refused_even_when_the_filed_row_agrees(self):
        young = _iso(NOW - 3 * 86400)
        self.refused("npm_package_too_young", published={"beta-pkg": young})
        self.refused("npm_package_too_young", published={"gamma-pkg": _iso(NOW - 3600 - 7 * 86400 + 1)})
        evidence = json.loads(subject.decode_bundle(
            World(published={"gamma-pkg": _iso(NOW - 3600 - 7 * 86400)}).bundle())[2].decode("ascii"))
        self.assertEqual(evidence["packages"][2]["age_days"], 7)

    def test_a_publish_time_in_the_future_is_refused(self):
        self.refused("npm_evidence_invalid", published={"gamma-pkg": _iso(NOW + 3600)})

    def test_registry_integrity_must_match_the_lock(self):
        wrong = "sha512-" + base64.b64encode(b"x" * 64).decode("ascii")
        self.refused("npm_integrity_mismatch", dist_integrity={"gamma-pkg": wrong})

    def test_a_tampered_archive_is_refused_by_the_shared_archive_checks(self):
        world = World()
        world.archives[("gamma-pkg", "3.1.0")] = _tarball("gamma-pkg", "3.1.0", licence="ISC")
        self.assert_refused("npm_archive_refused", world.bundle)

    def test_licences_must_agree_between_lock_registry_and_archive_and_be_admissible(self):
        self.refused("npm_licence_refused", archive_license={"gamma-pkg": "Apache-2.0"},
                     registry_license={"gamma-pkg": "MIT"})
        self.refused("npm_licence_refused", registry_license={"gamma-pkg": "GPL-3.0-only"},
                     table_licence={"gamma-pkg": "GPL-3.0-only"})
        self.refused("npm_licence_refused", registry_license={"gamma-pkg": "UNLICENSED"})

    def test_the_filed_table_must_match_the_registry_for_every_row(self):
        self.refused("npm_request_mismatch", table_published={"alpha-pkg": "2026-06-01T12:00:00.001Z"})
        self.refused("npm_request_mismatch", table_attested={"alpha-pkg": False})
        self.refused("npm_request_mismatch", table_attested={"beta-pkg": True})
        self.refused("npm_request_mismatch", table_licence={"beta-pkg": "ISC"})
        self.refused("npm_request_mismatch", extra_rows=(("delta-pkg", "4.0.0"),))

    def test_deprecated_direct_pins_are_refused_but_transitive_ones_are_recorded(self):
        self.refused("npm_package_deprecated", deprecated={"alpha-pkg"})
        evidence = json.loads(subject.decode_bundle(World(deprecated={"gamma-pkg"}).bundle())[2].decode("ascii"))
        self.assertEqual([item["deprecated"] for item in evidence["packages"]], [False, False, True, False])

    def test_a_blocking_advisory_stops_the_bundle(self):
        advisory = json.dumps({"alpha-pkg": [
            {"id": 9, "severity": "high", "vulnerable_versions": "<2.0.0"},
        ]}).encode("ascii")
        self.refused("npm_advisory_blocked", advisory=advisory)

    def test_run_identity_and_times_are_checked(self):
        world = World()
        self.assert_refused("npm_stale", world.bundle, expiry=NOW)
        self.assert_refused("npm_stale", world.bundle, expiry=NOW + 24 * 3600 + 1)
        self.assert_refused("npm_stale", world.bundle, now=0)
        self.assert_refused("npm_input_invalid", world.bundle, run_attempt=2)
        self.assert_refused("npm_input_invalid", world.bundle, run_id="0123")
        self.assert_refused("npm_input_invalid", world.bundle, fetcher=None)
        self.assert_refused("npm_stale", world.bundle, clock=lambda: NOW - 10_000)

    def test_the_trusted_context_is_closed(self):
        world = World()
        for context in (
            dict(world.context, extra="x"), {k: v for k, v in world.context.items() if k != "filing"},
            dict(world.context, repository=""), dict(world.context, repository="caf" + chr(0xE9)), None,
        ):
            with self.subTest(context=context):
                self.assert_refused(
                    "npm_input_invalid", subject.produce_bundle, world.lock_bytes, world.plan(), context,
                    run_id="1", run_attempt=1, now=NOW, expiry=EXPIRY, fetcher=world.fetcher(),
                )
        other = dict(world.context, filing="other-filing")
        self.assert_refused(
            "npm_input_invalid", subject.produce_bundle, world.lock_bytes, world.plan(), other,
            run_id="1", run_attempt=1, now=NOW, expiry=EXPIRY, fetcher=world.fetcher(),
            clock=lambda: NOW + 5,
        )

    def test_the_proposal_never_exceeds_its_own_profile_limits(self):
        self.assertLessEqual(subject.MAX_BUNDLE_BYTES, 4 * 1024 * 1024 - 64 * 1024)

        def encoded(size):
            return 4 * ((size + 2) // 3)

        total = (
            encoded(subject.MAX_LOCK_BYTES) + encoded(subject.MAX_RECEIPT_BYTES)
            + encoded(subject.MAX_EVIDENCE_BYTES) + 256
        )
        self.assertLessEqual(total, subject.MAX_BUNDLE_BYTES)
        self.assertLess(subject.MAX_LOCK_BYTES, adm.MAX_LOCK_BYTES)


class BundleCodecTests(RefusalAssertions):
    def test_the_codec_round_trips_and_refuses_everything_else(self):
        members = (b"lock\n", b"receipt", b"evidence")
        bundle = subject.encode_bundle(*members)
        self.assertEqual(subject.decode_bundle(bundle), members)
        parsed = json.loads(bundle.decode("ascii"))
        for changed in (
            json.dumps(parsed).encode("ascii"),
            json.dumps(dict(parsed, extra="x"), sort_keys=True, separators=(",", ":")).encode("ascii"),
            json.dumps(dict(parsed, schema_version=2), sort_keys=True, separators=(",", ":")).encode("ascii"),
            json.dumps(dict(parsed, lock_b64="!!!"), sort_keys=True, separators=(",", ":")).encode("ascii"),
            json.dumps(dict(parsed, lock_b64=""), sort_keys=True, separators=(",", ":")).encode("ascii"),
            b"", b"not json", None, "text",
        ):
            with self.subTest(changed=changed):
                self.assert_refused("npm_input_invalid", subject.decode_bundle, changed)
        self.assert_refused("npm_payload_too_large", subject.decode_bundle, b"x" * (subject.MAX_BUNDLE_BYTES + 1))

    def test_each_member_is_bounded_by_its_own_limit(self):
        self.assert_refused("npm_payload_too_large", subject.encode_bundle, b"x" * (subject.MAX_LOCK_BYTES + 1), b"r", b"e")
        self.assert_refused("npm_payload_too_large", subject.encode_bundle, b"l", b"x" * (subject.MAX_RECEIPT_BYTES + 1), b"e")
        self.assert_refused("npm_payload_too_large", subject.encode_bundle, b"l", b"r", b"x" * (subject.MAX_EVIDENCE_BYTES + 1))
        for members in ((b"", b"r", b"e"), (b"l", None, b"e"), (b"l", b"r", "e")):
            with self.subTest(members=members):
                self.assert_refused("npm_input_invalid", subject.encode_bundle, *members)


class VerificationTests(RefusalAssertions):
    def setUp(self):
        self.world = World()
        self.plan = self.world.plan()
        self.bundle = self.world.bundle()
        self.lock_bytes, self.receipt_bytes, self.evidence_bytes = subject.decode_bundle(self.bundle)

    def test_an_expired_or_premature_evidence_record_is_stale(self):
        subject.verify_bundle(self.bundle, self.plan, self.world.context, now=EXPIRY - 1)
        self.assert_refused("npm_stale", subject.verify_bundle, self.bundle, self.plan, self.world.context, now=EXPIRY)
        self.assert_refused("npm_stale", subject.verify_bundle, self.bundle, self.plan, self.world.context, now=NOW - 1000)

    def rewrite(self, receipt=None, evidence=None, lock=None):
        return subject.encode_bundle(
            lock if lock is not None else self.lock_bytes,
            _json(receipt) if receipt is not None else self.receipt_bytes,
            _json(evidence) if evidence is not None else self.evidence_bytes,
        )

    def test_receipt_tampering_is_detected(self):
        receipt = json.loads(self.receipt_bytes.decode("ascii"))
        for index, change in enumerate((
            lambda value: value.update({"inputs_sha256": "0" * 64}),
            lambda value: value.update({"request_doc_sha256": "0" * 64}),
            lambda value: value.update({"lock_sha256": "0" * 64}),
            lambda value: value["context"].update({"source_sha": "e" * 40}),
            lambda value: value["packages"][0].update({"sha256": "0" * 64}),
            lambda value: value["packages"][0].update({"audit_record_id": "approved"}),
            lambda value: value["packages"].pop(),
            lambda value: value.update({"archive_set_sha256": "0" * 64}),
            lambda value: value.update({"package_set_sha256": "0" * 64}),
            lambda value: value.update({"extra": 1}),
            lambda value: value.update({"record_type": "other"}),
        )):
            with self.subTest(change=index):
                changed = json.loads(json.dumps(receipt))
                change(changed)
                bundle = self.rewrite(receipt=changed)
                with self.assertRaises(subject.BootstrapRefusal) as raised:
                    subject.verify_bundle(bundle, self.plan, self.world.context, now=NOW)
                self.assertEqual(raised.exception.reason, "npm_evidence_invalid")

    def test_evidence_tampering_is_detected(self):
        evidence = json.loads(self.evidence_bytes.decode("ascii"))
        cases = (
            (lambda value: value.update({"receipt_sha256": "0" * 64}), "npm_evidence_invalid"),
            (lambda value: value.update({"lock_sha256": "0" * 64}), "npm_evidence_invalid"),
            (lambda value: value.update({"inputs_sha256": "0" * 64}), "npm_evidence_invalid"),
            (lambda value: value.update({"registry_origin": "example.invalid"}), "npm_evidence_invalid"),
            (lambda value: value.update({"attestation_verification": "verified"}), "npm_evidence_invalid"),
            (lambda value: value.update({"minimum_age_seconds": 1}), "npm_evidence_invalid"),
            (lambda value: value.update({"extra": 1}), "npm_evidence_invalid"),
            (lambda value: value["packages"].pop(), "npm_evidence_invalid"),
            (lambda value: value["packages"][0].update({"sha256": "0" * 64}), "npm_evidence_invalid"),
            (lambda value: value["packages"][0].update({"licence": "GPL-3.0-only"}), "npm_licence_refused"),
            (lambda value: value["packages"][0].update({"published": _iso(NOW - 86400)}), "npm_package_too_young"),
            (lambda value: value["advisory"].update({"status": "findings_present"}), "npm_evidence_invalid"),
            (lambda value: value["advisory"].update({"valid_until": 1}), "npm_evidence_invalid"),
            (lambda value: value["advisory"].update({"endpoint": "other"}), "npm_evidence_invalid"),
            (lambda value: value["advisory"].update({
                "status": "findings_present", "finding_count": 1,
                "findings": [{"name": "a", "version": "1.0.0", "severity": "high",
                              "advisory_id": "1", "range": "<2.0.0"}],
            }), "npm_evidence_invalid"),
            (lambda value: value.update({"policy_epoch_ms": 1}), "npm_stale"),
            (lambda value: value.update({"cutoff_epoch_ms": 1}), "npm_stale"),
            (lambda value: value.update({"run_attempt": 2}), "npm_input_invalid"),
        )
        for index, (change, reason) in enumerate(cases):
            with self.subTest(change=index):
                changed = json.loads(json.dumps(evidence))
                change(changed)
                bundle = self.rewrite(evidence=changed)
                with self.assertRaises(subject.BootstrapRefusal) as raised:
                    subject.verify_bundle(bundle, self.plan, self.world.context, now=NOW)
                self.assertEqual(raised.exception.reason, reason)

    def test_a_different_lock_or_plan_or_context_does_not_verify(self):
        other_lock = json.loads(self.lock_bytes.decode("ascii"))
        other_lock["packages"]["node_modules/gamma-pkg"]["dev"] = False
        changed_lock = self.rewrite(lock=_json(other_lock) + b"\n")
        with self.assertRaises(subject.BootstrapRefusal):
            subject.verify_bundle(changed_lock, self.plan, self.world.context, now=NOW)
        files = dict(self.world.files)
        manifest = json.loads(files["package.json"].decode("ascii"))
        manifest["version"] = "0.2.0"
        files["package.json"] = _json(manifest) + b"\n"
        with self.assertRaises(subject.BootstrapRefusal):
            subject.verify_bundle(
                self.bundle, subject.check_inputs(files, subject.DEFAULT_FILING), self.world.context, now=NOW,
            )
        with self.assertRaises(subject.BootstrapRefusal):
            subject.verify_bundle(self.bundle, self.plan, dict(self.world.context, base_sha="e" * 40), now=NOW)


class SiblingLoadTests(unittest.TestCase):
    def test_the_shared_helpers_are_the_reviewed_sibling_modules(self):
        self.assertIs(subject.adm, adm)
        self.assertTrue(callable(subject.semver.satisfies))
        self.assertEqual(subject.workspace_links(), {
            "node_modules/" + subject.SCOPE + "host-api": "packages/host-api",
            "node_modules/" + subject.SCOPE + "kernel-i18n": "packages/kernel-i18n",
        })

    def test_the_default_filing_is_registered_with_the_request_profile(self):
        import feedback_request
        self.assertIn(subject.DEFAULT_FILING, feedback_request.NPM_FILING_SELECTORS)
        self.assertEqual(feedback_request.NPM_DEFAULT_FILING, subject.DEFAULT_FILING)
        self.assertEqual(feedback_request.NPM_ADMISSION_MAX_PAYLOAD_BYTES, subject.MAX_BUNDLE_BYTES)
        self.assertEqual(feedback_request.NPM_ADMISSION_MAX_LOCK_BYTES, subject.MAX_LOCK_BYTES)
        self.assertEqual(feedback_request.NPM_ADMISSION_MAX_RECEIPT_BYTES, subject.MAX_RECEIPT_BYTES)
        self.assertEqual(feedback_request.NPM_ADMISSION_MAX_EVIDENCE_BYTES, subject.MAX_EVIDENCE_BYTES)
        self.assertEqual(feedback_request.NPM_ADMISSION_MAX_PACKAGES, subject.MAX_PACKAGES)


if __name__ == "__main__":
    unittest.main()
