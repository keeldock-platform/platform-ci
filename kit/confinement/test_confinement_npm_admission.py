import base64
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
import tempfile
import unittest
import unittest.mock

import npm_admission as subject


ROLLODOWN_BINDINGS = (
    "@rolldown/binding-android-arm64",
    "@rolldown/binding-darwin-arm64",
    "@rolldown/binding-darwin-x64",
    "@rolldown/binding-freebsd-x64",
    "@rolldown/binding-linux-arm-gnueabihf",
    "@rolldown/binding-linux-arm64-gnu",
    "@rolldown/binding-linux-arm64-musl",
    "@rolldown/binding-linux-x64-gnu",
    "@rolldown/binding-linux-x64-musl",
    "@rolldown/binding-openharmony-arm64",
    "@rolldown/binding-riscv64-gnu",
    "@rolldown/binding-wasm32-wasi",
    "@rolldown/binding-win32-arm64-msvc",
    "@rolldown/binding-win32-ia32-msvc",
    "@rolldown/binding-win32-x64-msvc",
)
LIGHTNING_BINDINGS = (
    "lightningcss-android-arm64",
    "lightningcss-darwin-arm64",
    "lightningcss-darwin-x64",
    "lightningcss-freebsd-x64",
    "lightningcss-linux-arm-gnueabihf",
    "lightningcss-linux-arm64-gnu",
    "lightningcss-linux-arm64-musl",
    "lightningcss-linux-x64-gnu",
    "lightningcss-linux-x64-musl",
    "lightningcss-win32-arm64-msvc",
    "lightningcss-win32-x64-msvc",
)


def _sri(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")


def _node_modules_path(name):
    return "node_modules/" + name


def _tarball(name, version, scripts=None, binary=False, extra=(), gypfile=None):
    manifest_fields = {"name": name, "version": version, "scripts": scripts or {}}
    if gypfile is not None:
        manifest_fields["gypfile"] = gypfile
    manifest = json.dumps(
        manifest_fields,
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        directory = tarfile.TarInfo("package/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        directory.size = 0
        archive.addfile(directory)
        files = [("package/package.json", manifest)]
        if scripts:
            files.append(("package/install.js", b"synthetic script"))
        if binary:
            files.append(("package/binding.node", b"\x7fELFsynthetic"))
        files.extend(extra)
        for path, content in files:
            info = tarfile.TarInfo(path)
            info.mode = 0o644
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def _rooted_tarball(root, name="sample", version="1.0.0", extra=(), with_directory=True):
    manifest = json.dumps(
        {"name": name, "version": version, "scripts": {}}, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        if with_directory:
            directory = tarfile.TarInfo(root + "/")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            archive.addfile(directory)
        for path, content in ((root + "/package.json", manifest),) + tuple(extra):
            info = tarfile.TarInfo(path)
            info.mode = 0o644
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def _tar_with_members(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        directory = tarfile.TarInfo("package/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        for member, data in members:
            if member.isfile():
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            else:
                archive.addfile(member)
    return output.getvalue()


def _fixture():
    registry = []
    for name in ROLLODOWN_BINDINGS:
        registry.append((name, "1.2.14", False, True))
    for name in LIGHTNING_BINDINGS:
        registry.append((name, "1.33.0", False, True))
    registry.append(("fsevents", "2.3.3", True, False))
    registry.extend((("rolldown", "1.2.14", False, False), ("lightningcss", "1.33.0", False, False)))
    registry.extend(("sample-package-%02d" % index, "1.0.0", False, False) for index in range(32))
    packages = {
        "": {
            "name": "sample-root",
            "version": "1.0.0",
            "workspaces": ["packages/*"],
        },
        "packages/host-api": {
            "name": "@" + "keeldock" + "/host-api",
            "version": "1.0.0",
        },
    }
    workspace_link = "node_modules/" + "@" + "keeldock" + "/host-api"
    packages[workspace_link] = {"resolved": "packages/host-api", "link": True}
    archives = {}
    for name, version, has_script, binary in registry:
        scripts = {"install": "node install.js"} if has_script else {}
        data = _tarball(name, version, scripts=scripts, binary=binary)
        path = _node_modules_path(name)
        packages[path] = {
            "version": version,
            "resolved": subject._canonical_tarball_url(name, version),
            "integrity": _sri(data),
        }
        if has_script:
            packages[path]["hasInstallScript"] = True
        archives[path] = data
    lock = {
        "name": "sample-root",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": packages,
    }
    lock_bytes = json.dumps(lock, sort_keys=True, separators=(",", ":")).encode("ascii")
    workspace_manifest = json.dumps(
        {"name": "@" + "keeldock" + "/host-api", "version": "1.0.0"},
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    material_files = {
        ".node-version": b"24.22.1\n",
        ".npmrc": b"engine-strict=true\nignore-scripts=true\n",
        "package.json": b'{"name":"sample-root","version":"1.0.0"}\n',
        "package-lock.json": lock_bytes,
        "packages/host-api/package.json": workspace_manifest,
        "dependency-policy.json": b'{"packages":{}}\n',
    }
    return lock, lock_bytes, archives, material_files


def _ledger_context():
    return {
        "repository_id": "123456",
        "source_sha": "a" * 40,
        "base_sha": "b" * 40,
        "base_branch": "develop",
        "reviewed_diff_sha256": "c" * 64,
        "control_sha": "d" * 40,
    }


def _run_context():
    return {
        **_ledger_context(),
        "proof_phase": "native-proof",
        "platform": "linux",
        "job": "native-linux",
        "run_id": "456789",
        "run_attempt": 1,
        "recipient_key_fingerprint": "e" * 64,
        "issued_at": 1000,
        "expires_at": 2000,
    }


def _admission_record(fixture=None):
    unused_lock, lock_bytes, archives, material_files = fixture or _fixture()
    identities = subject.verify_archive_set(lock_bytes, archives)
    lock_digest = hashlib.sha256(lock_bytes).hexdigest()
    return {
        "schema_version": subject.SCHEMA_VERSION,
        "record_type": "npm-admission-ledger-record",
        "admission_id": "admission-1",
        "context": _ledger_context(),
        "material_sha256": subject.compute_material_digest(material_files),
        "lock_sha256": lock_digest,
        "archive_set_sha256": subject.archive_set_digest(identities),
        "package_set_sha256": subject.package_set_digest(lock_digest, identities),
        "archive_identities": identities,
        "archive_audit_store_sha256": "1" * 64,
        "native_specification_sha256": "2" * 64,
        "proof_results_sha256": "3" * 64,
        "browser_set_id": "",
        "browser_inventory_sha256": "0" * 64,
        "security_review_sha256": "4" * 64,
        "frontend_review_sha256": "5" * 64,
        "owner_approval_sha256": "6" * 64,
        "created_at": 900,
    }


def _run_receipt(record):
    return {
        "schema_version": subject.SCHEMA_VERSION,
        "record_type": "npm-run-receipt",
        "receipt_id": "7" * 64,
        "context": _run_context(),
        "authorization": subject.admission_authorization(record),
    }


class NpmAdmissionTests(unittest.TestCase):
    def assert_refused(self, operation, reason=None):
        with self.assertRaises(subject.Refusal) as raised:
            operation()
        if reason is not None:
            self.assertEqual(raised.exception.reason, reason)
        self.assertNotIn("package.json", str(raised.exception))

    def test_synthetic_lock_has_the_documented_64_entries_and_optional_packages(self):
        lock, lock_bytes, unused_archives, unused_material = _fixture()
        parsed = subject.parse_lock(lock_bytes)
        self.assertEqual(parsed["lockfileVersion"], 3)
        self.assertEqual(len(parsed["packages"]), 64)
        entries = subject.registry_entries(lock_bytes)
        self.assertEqual(len(entries), 61)
        by_name = {entry.get("name", path.rsplit("/", 1)[-1]): entry for path, entry in entries}
        self.assertEqual(sum(name.startswith("@rolldown/binding-") for name in by_name), 15)
        self.assertEqual(sum(name.startswith("lightningcss-") for name in by_name), 11)
        self.assertEqual(
            {entry["version"] for name, entry in by_name.items()
             if name.startswith("@rolldown/binding-")},
            {"1.2.14"},
        )
        self.assertEqual(
            {entry["version"] for name, entry in by_name.items()
             if name.startswith("lightningcss-")},
            {"1.33.0"},
        )
        self.assertEqual(by_name["fsevents"]["version"], "2.3.3")
        self.assertTrue(by_name["fsevents"]["hasInstallScript"])
        self.assertEqual(lock["packages"]["node_modules/rolldown"]["version"], "1.2.14")
        self.assertEqual(lock["packages"]["node_modules/lightningcss"]["version"], "1.33.0")

    def test_lock_requires_version_three_exact_sha512_and_canonical_registry_urls(self):
        lock, unused_bytes, unused_archives, unused_material = _fixture()
        lock["lockfileVersion"] = 2
        wrong_version = json.dumps(lock).encode("ascii")
        self.assert_refused(lambda: subject.parse_lock(wrong_version), "npm_lock_invalid")

        lock, unused_bytes, unused_archives, unused_material = _fixture()
        path = "node_modules/fsevents"
        lock["packages"][path]["integrity"] = "sha1-" + ("a" * 28)
        self.assert_refused(
            lambda: subject.parse_lock(json.dumps(lock).encode("ascii")), "npm_lock_invalid",
        )

        for resolved in (
            "http:" + chr(47) * 2 + "registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
            "https:" + chr(47) * 2 + "other.invalid/fsevents/-/fsevents-2.3.3.tgz",
            "file:./fsevents.tgz",
            "git+https:" + chr(47) * 2 + "code.invalid/fsevents.git",
            "https:" + chr(47) * 2 + "registry.npmjs.org/fsevents/-/other.tgz?redirect=1",
        ):
            lock, unused_bytes, unused_archives, unused_material = _fixture()
            lock["packages"][path]["resolved"] = resolved
            raw = json.dumps(lock).encode("ascii")
            self.assert_refused(lambda raw=raw: subject.parse_lock(raw), "npm_lock_invalid")

    def test_lock_refuses_unsupported_dependency_specs_and_non_workspace_links(self):
        for spec in (
            "https:" + chr(47) * 2 + "bad.invalid/a.tgz",
            "http:" + chr(47) * 2 + "bad.invalid/a.tgz",
            "git+https:" + chr(47) * 2 + "bad.invalid/repo.git",
            "file:../archive.tgz",
            "link:../workspace",
            "npm:other-package@1.0.0",
        ):
            lock, unused_bytes, unused_archives, unused_material = _fixture()
            lock["packages"][""]["dependencies"] = {"sample-package-00": spec}
            raw = json.dumps(lock).encode("ascii")
            self.assert_refused(lambda raw=raw: subject.parse_lock(raw), "npm_lock_invalid")

        lock, unused_bytes, unused_archives, unused_material = _fixture()
        link_path = "node_modules/" + "@" + "keeldock" + "/host-api"
        lock["packages"][link_path]["resolved"] = "file:packages/host-api"
        self.assert_refused(
            lambda: subject.parse_lock(json.dumps(lock).encode("ascii")), "npm_lock_invalid",
        )

        lock, unused_bytes, unused_archives, unused_material = _fixture()
        lock["packages"]["packages/host-api"]["name"] = "sample-host-api"
        self.assert_refused(
            lambda: subject.parse_lock(json.dumps(lock).encode("ascii")), "npm_lock_invalid",
        )

        lock, unused_bytes, unused_archives, unused_material = _fixture()
        lock["packages"]["node_modules/sample-package-00"]["link"] = True
        self.assert_refused(
            lambda: subject.parse_lock(json.dumps(lock).encode("ascii")), "npm_lock_invalid",
        )

    def test_lock_bans_internal_registry_names_at_every_level(self):
        unused_lock, lock_bytes, unused_archives, unused_material = _fixture()
        self.assert_refused(
            lambda: subject.parse_lock(lock_bytes, internal_names=("sample-package-00",)),
            "npm_lock_invalid",
        )

        lock, unused_bytes, unused_archives, unused_material = _fixture()
        old_path = "node_modules/sample-package-00"
        entry = lock["packages"].pop(old_path)
        private_name = "keeldock" + "-" + "private"
        new_path = "node_modules/" + private_name
        entry["resolved"] = subject._canonical_tarball_url(private_name, entry["version"])
        lock["packages"][new_path] = entry
        self.assert_refused(
            lambda: subject.parse_lock(json.dumps(lock).encode("ascii")), "npm_lock_invalid",
        )

        lock, unused_bytes, unused_archives, unused_material = _fixture()
        lock["packages"]["node_modules/sample-package-00"]["dependencies"] = {
            "@" + "keeldock" + "/internal-module": "1.0.0",
        }
        self.assert_refused(
            lambda: subject.parse_lock(json.dumps(lock).encode("ascii")), "npm_lock_invalid",
        )

    def test_lock_refuses_bundled_package_metadata(self):
        for field, value in (
                ("inBundle", True),
                ("bundledDependencies", ["sample-package-01"]),
                ("bundleDependencies", ["sample-package-01"])):
            with self.subTest(field=field):
                lock, unused_bytes, unused_archives, unused_material = _fixture()
                lock["packages"]["node_modules/sample-package-00"][field] = value
                raw = json.dumps(lock).encode("ascii")
                self.assert_refused(lambda: subject.parse_lock(raw), "npm_lock_invalid")

        lock, unused_bytes, unused_archives, unused_material = _fixture()
        lock["packages"]["node_modules/sample-package-00"].update({
            "inBundle": False, "bundledDependencies": [],
        })
        parsed = subject.parse_lock(json.dumps(lock).encode("ascii"))
        self.assertEqual(
            parsed["packages"]["node_modules/sample-package-00"]["inBundle"], False,
        )

    def test_lock_parser_rejects_duplicate_keys_depth_and_oversized_input(self):
        self.assert_refused(
            lambda: subject.parse_lock(b'{"name":"a","name":"b"}'), "npm_lock_invalid",
        )
        deep = b"{" + (b'"x":{' * (subject.MAX_JSON_DEPTH + 2)) + b'"x":0' + (b"}" * (subject.MAX_JSON_DEPTH + 3))
        self.assert_refused(lambda: subject.parse_lock(deep), "npm_lock_invalid")
        self.assert_refused(
            lambda: subject.parse_lock(b" " * (subject.MAX_LOCK_BYTES + 1)), "npm_lock_invalid",
        )

    def test_material_identity_uses_exact_path_inventory_and_path_order(self):
        unused_lock, unused_bytes, unused_archives, material = _fixture()
        first = subject.compute_material_digest(material)
        reversed_material = dict(reversed(list(material.items())))
        self.assertEqual(first, subject.compute_material_digest(reversed_material))
        changed = dict(material)
        changed[".npmrc"] += b"audit=false\n"
        self.assertNotEqual(first, subject.compute_material_digest(changed))
        missing = dict(material)
        del missing["dependency-policy.json"]
        self.assert_refused(lambda: subject.compute_material_digest(missing), "npm_material_invalid")
        extra = dict(material)
        extra["receipt.json"] = b"not material"
        self.assert_refused(lambda: subject.compute_material_digest(extra), "npm_material_invalid")

    def test_tarball_integrity_and_classification_cover_scripts_and_native_bindings(self):
        unused_lock, lock_bytes, archives, unused_material = _fixture()
        identities = subject.verify_archive_set(lock_bytes, archives)
        self.assertEqual(len(identities), 61)
        by_path = {identity["path"]: identity for identity in identities}
        entries_by_path = dict(subject.registry_entries(lock_bytes))
        fsevents_path = "node_modules/fsevents"
        script_report = subject.verify_tarball(
            entries_by_path[fsevents_path], archives[fsevents_path],
        )
        self.assertEqual(script_report["install_scripts"], ("install",))
        self.assertEqual(script_report["implicit_install_scripts"], ())
        rolldown_path = "node_modules/" + ROLLODOWN_BINDINGS[0]
        binding_report = subject.verify_tarball(
            entries_by_path[rolldown_path], archives[rolldown_path],
        )
        self.assertIn("package/binding.node", binding_report["native_binaries"])
        self.assertEqual(by_path[fsevents_path]["version"], "2.3.3")

        lifecycle_names = ("preinstall", "install", "postinstall", "prepare")
        lifecycle_data = _tarball(
            "sample-lifecycle", "1.0.0", scripts={name: "synthetic" for name in lifecycle_names},
        )
        lifecycle_entry = {
            "name": "sample-lifecycle",
            "version": "1.0.0",
            "integrity": _sri(lifecycle_data),
        }
        lifecycle_report = subject.verify_tarball(lifecycle_entry, lifecycle_data)
        self.assertEqual(lifecycle_report["install_scripts"], lifecycle_names)

    def test_binding_gyp_classifies_implicit_install_only_at_archive_root(self):
        data = _tarball("sample", "1.0.0", extra=(("package/binding.gyp", b"{}"),))
        entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(data)}
        report = subject.verify_tarball(entry, data)
        self.assertEqual(report["install_scripts"], ("install",))
        self.assertEqual(report["implicit_install_scripts"], ("install",))

        preinstall_data = _tarball(
            "sample", "1.0.0", scripts={"preinstall": "synthetic"},
            extra=(("package/binding.gyp", b"{}"),),
        )
        preinstall_entry = dict(entry, integrity=_sri(preinstall_data))
        preinstall_report = subject.verify_tarball(preinstall_entry, preinstall_data)
        self.assertEqual(preinstall_report["install_scripts"], ("preinstall",))
        self.assertEqual(preinstall_report["implicit_install_scripts"], ())

        nested_data = _tarball("sample", "1.0.0", extra=(("package/assets/binding.gyp", b"{}"),))
        nested_entry = dict(entry, integrity=_sri(nested_data))
        nested_report = subject.verify_tarball(nested_entry, nested_data)
        self.assertEqual(nested_report["install_scripts"], ())
        self.assertEqual(nested_report["implicit_install_scripts"], ())

    def test_binding_gyp_uses_command_truthiness_and_gypfile_flag(self):
        for script in ("preinstall", "install"):
            with self.subTest(script=script):
                data = _tarball(
                    "sample", "1.0.0", scripts={script: ""},
                    extra=(("package/binding.gyp", b"{}"),),
                )
                entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(data)}
                report = subject.verify_tarball(entry, data)
                self.assertEqual(report["install_scripts"], ("install",))
                self.assertEqual(report["implicit_install_scripts"], ("install",))

        disabled_data = _tarball(
            "sample", "1.0.0", extra=(("package/binding.gyp", b"{}"),),
            gypfile=False,
        )
        disabled_entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(disabled_data)}
        disabled_report = subject.verify_tarball(disabled_entry, disabled_data)
        self.assertEqual(disabled_report["install_scripts"], ())
        self.assertEqual(disabled_report["implicit_install_scripts"], ())

    def test_tarball_refuses_bundled_package_tree(self):
        private_name = "keeldock" + "-" + "private"
        nested_manifest = json.dumps({
            "name": private_name,
            "version": "1.0.0",
            "scripts": {"install": "synthetic"},
        }, sort_keys=True, separators=(",", ":")).encode("ascii")
        data = _tarball(
            "sample", "1.0.0",
            extra=(("package/node_modules/" + private_name + "/package.json", nested_manifest),),
        )
        entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(data)}
        self.assert_refused(lambda: subject.verify_tarball(entry, data), "npm_archive_invalid")
        ordinary_data = _tarball("sample", "1.0.0", extra=(("package/assets/data", b"safe"),))
        ordinary_entry = dict(entry, integrity=_sri(ordinary_data))
        self.assertEqual(subject.verify_tarball(ordinary_entry, ordinary_data)["install_scripts"], ())

    def test_tarball_refuses_bad_integrity_and_package_manifest_identity(self):
        data = _tarball("sample", "1.0.0")
        entry = {
            "name": "sample",
            "version": "1.0.0",
            "integrity": _sri(data),
            "resolved": subject._canonical_tarball_url("sample", "1.0.0"),
        }
        self.assertTrue(subject.verify_tarball(entry, data)["sha256"])
        self.assert_refused(lambda: subject.verify_tarball(entry, data + b"x"), "npm_archive_invalid")
        wrong_manifest = _tarball("other", "1.0.0")
        wrong_entry = dict(entry)
        wrong_entry["integrity"] = _sri(wrong_manifest)
        self.assert_refused(
            lambda: subject.verify_tarball(wrong_entry, wrong_manifest), "npm_archive_invalid",
        )

    def test_tar_preflight_refuses_traversal_absolute_links_and_devices(self):
        cases = []
        for path in ("package/../escape", "/package/absolute", "package//empty"):
            member = tarfile.TarInfo(path)
            cases.append(_tar_with_members(((member, b"bad"),)))
        symlink = tarfile.TarInfo("package/symlink")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "../outside"
        cases.append(_tar_with_members(((symlink, b""),)))
        hardlink = tarfile.TarInfo("package/hardlink")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "package/package.json"
        cases.append(_tar_with_members(((hardlink, b""),)))
        device = tarfile.TarInfo("package/device")
        device.type = tarfile.CHRTYPE
        device.devmajor = 1
        device.devminor = 2
        cases.append(_tar_with_members(((device, b""),)))
        for data in cases:
            entry = {
                "name": "sample",
                "version": "1.0.0",
                "integrity": _sri(data),
            }
            self.assert_refused(
                lambda data=data, entry=entry: subject.verify_tarball(entry, data),
                "npm_archive_invalid",
            )

    def test_tar_preflight_checks_raw_directory_slashes(self):
        valid_data = _tarball("sample", "1.0.0")
        entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(valid_data)}
        self.assertEqual(subject.verify_tarball(entry, valid_data)["file_count"], 1)

        directory = tarfile.TarInfo("package/directory/")
        directory.type = tarfile.DIRTYPE
        no_slash = bytearray(directory.tobuf(format=tarfile.USTAR_FORMAT))
        no_slash[len("package/directory")] = 0
        no_slash[148:156] = b"        "
        no_slash[148:156] = ("%06o\x00 " % sum(no_slash)).encode("ascii")

        double_slash = tarfile.TarInfo("package/directory//")
        double_slash.type = tarfile.DIRTYPE
        legacy_directory = tarfile.TarInfo("package/legacy/")
        legacy_directory.type = tarfile.AREGTYPE
        subject._preflight_tar_headers(bytes(no_slash) + bytes(1024))
        for header in (
                double_slash.tobuf(format=tarfile.USTAR_FORMAT),
                legacy_directory.tobuf(format=tarfile.USTAR_FORMAT)):
            raw = header + bytes(1024)
            self.assert_refused(
                lambda raw=raw: subject._preflight_tar_headers(raw), "npm_archive_invalid",
            )

    def test_tar_preflight_checks_prefixed_directory_path(self):
        manifest = b'{"name":"sample","version":"1.0.0"}'
        manifest_member = tarfile.TarInfo("package/package.json")
        directory = tarfile.TarInfo("package/dir/")
        directory.type = tarfile.DIRTYPE
        base = gzip.decompress(_tar_with_members((
            (manifest_member, manifest), (directory, b""),
        )))
        directory_offset = 1024 + (((len(manifest) + 511) // 512) * 512)

        def prefixed_archive(prefix, name):
            raw = bytearray(base)
            header = bytearray(raw[directory_offset:directory_offset + 512])
            header[:100] = name.encode("ascii").ljust(100, b"\x00")
            header[345:500] = prefix.encode("ascii").ljust(155, b"\x00")
            header[148:156] = b"        "
            header[148:156] = ("%06o\x00 " % sum(header)).encode("ascii")
            raw[directory_offset:directory_offset + 512] = header
            return gzip.compress(bytes(raw), mtime=0)

        valid_data = prefixed_archive("package", "dir/")
        valid_entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(valid_data)}
        self.assertEqual(subject.verify_tarball(valid_entry, valid_data)["file_count"], 1)

        invalid_data = prefixed_archive("package/dir/", "/")
        invalid_entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(invalid_data)}
        self.assert_refused(
            lambda: subject._preflight_tar_headers(gzip.decompress(invalid_data)),
            "npm_archive_invalid",
        )
        self.assert_refused(
            lambda: subject.verify_tarball(invalid_entry, invalid_data), "npm_archive_invalid",
        )

    def test_tar_preflight_refuses_case_collisions_and_oversized_header(self):
        upper = tarfile.TarInfo("package/Binding.node")
        lower = tarfile.TarInfo("package/binding.node")
        collision_data = _tar_with_members(((upper, b"a"), (lower, b"b")))
        collision_entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(collision_data)}
        self.assert_refused(
            lambda: subject.verify_tarball(collision_entry, collision_data), "npm_archive_invalid",
        )

        oversized = tarfile.TarInfo("package/too-large")
        oversized.size = subject.MAX_PACKAGE_UNPACKED_BYTES + 1
        raw_tar = oversized.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024)
        oversized_data = gzip.compress(raw_tar)
        oversized_entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(oversized_data)}
        self.assert_refused(
            lambda: subject.verify_tarball(oversized_entry, oversized_data), "npm_archive_invalid",
        )

    def test_tar_preflight_refuses_windows_path_aliases(self):
        for path in (
                "package/package.json.",
                "package/package.json ",
                "package/file:stream",
                "package/CON",
                "package/NUL.txt",
                "package/CLOCK$.txt",
                "package/dir/LPT1.cfg",
                "package/PROGRA~1.TXT",
                "package/file?name"):
            with self.subTest(path=path):
                data = _tarball("sample", "1.0.0", extra=((path, b"synthetic"),))
                entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(data)}
                self.assert_refused(
                    lambda: subject.verify_tarball(entry, data), "npm_archive_invalid",
                )
        data = _tarball("sample", "1.0.0", extra=(("package/file-name", b"synthetic"),))
        entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(data)}
        self.assertEqual(subject.verify_tarball(entry, data)["file_count"], 2)

    def test_tar_preflight_refuses_non_ascii_aliases_in_every_component(self):
        for paths in (
                ("package/file.js", "package/f\u0131le.js"),
                ("package/b\u0131nding.gyp",),
                ("package/f\u0131les/data",)):
            with self.subTest(paths=paths):
                data = _tarball("sample", "1.0.0", extra=tuple(
                    (path, b"synthetic") for path in paths
                ))
                entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(data)}
                self.assert_refused(
                    lambda: subject.verify_tarball(entry, data), "npm_archive_invalid",
                )
        data = _tarball("sample", "1.0.0", extra=(("package/files/data", b"synthetic"),))
        entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(data)}
        self.assertEqual(subject.verify_tarball(entry, data)["file_count"], 2)

    def test_native_magic_is_classified_without_filename_extension(self):
        data = _tarball("sample", "1.0.0", extra=(("package/content.bin", b"MZsynthetic"),))
        entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(data)}
        report = subject.verify_tarball(entry, data)
        self.assertIn("package/content.bin", report["native_binaries"])

    def test_fat64_native_magic_is_classified_without_filename_extension(self):
        data = _tarball("sample", "1.0.0", extra=(
            ("package/fat64-big", b"\xca\xfe\xba\xbfsynthetic"),
            ("package/fat64-little", b"\xbf\xba\xfe\xcasynthetic"),
        ))
        entry = {"name": "sample", "version": "1.0.0", "integrity": _sri(data)}
        report = subject.verify_tarball(entry, data)
        self.assertEqual(report["native_binaries"], (
            "package/fat64-big", "package/fat64-little",
        ))

    def test_bounded_descriptor_read_refuses_links_and_returns_verified_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = os.path.join(temporary, "sample.tgz")
            data = _tarball("sample", "1.0.0")
            with open(path, "wb") as output:
                output.write(data)
            self.assertEqual(subject.read_bounded_file(path), data)
            link = os.path.join(temporary, "linked.tgz")
            try:
                os.symlink(path, link)
            except (AttributeError, NotImplementedError, OSError):
                return
            self.assert_refused(lambda: subject.read_bounded_file(link), "npm_archive_invalid")

    def test_admission_record_and_run_receipt_bind_context_lock_material_and_archives(self):
        fixture = _fixture()
        unused_lock, lock_bytes, archives, material = fixture
        record = _admission_record(fixture)
        encoded_record = subject.encode_admission_record(record)
        self.assertEqual(subject.decode_admission_record(encoded_record), record)
        self.assertTrue(subject.verify_admission_record(
            encoded_record, lock_bytes, material, archives, _ledger_context(),
        ))

        receipt = _run_receipt(record)
        encoded_receipt = subject.encode_run_receipt(receipt)
        self.assertEqual(subject.decode_run_receipt(encoded_receipt), receipt)
        self.assertTrue(subject.verify_run_receipt(
            encoded_receipt, lock_bytes, material, archives,
            _run_context(), subject.admission_authorization(encoded_record), now=1500,
        ))

    def test_receipt_verification_refuses_changed_context_lock_archive_and_expiry(self):
        fixture = _fixture()
        unused_lock, lock_bytes, archives, material = fixture
        record = _admission_record(fixture)
        encoded_record = subject.encode_admission_record(record)
        receipt = _run_receipt(record)
        encoded_receipt = subject.encode_run_receipt(receipt)

        changed_context = dict(_run_context())
        changed_context["source_sha"] = "f" * 40
        self.assert_refused(lambda: subject.verify_run_receipt(
            encoded_receipt, lock_bytes, material, archives,
            changed_context, subject.admission_authorization(encoded_record), now=1500,
        ), "npm_context_mismatch")

        changed_lock = lock_bytes.replace(b"1.0.0", b"1.0.1", 1)
        changed_material = dict(material)
        changed_material["package-lock.json"] = changed_lock
        self.assert_refused(lambda: subject.verify_run_receipt(
            encoded_receipt, changed_lock, changed_material, archives,
            _run_context(), subject.admission_authorization(encoded_record), now=1500,
        ), "npm_context_mismatch")

        changed_archives = dict(archives)
        changed_archives["node_modules/fsevents"] = b"changed bytes"
        self.assert_refused(lambda: subject.verify_run_receipt(
            encoded_receipt, lock_bytes, material, changed_archives,
            _run_context(), subject.admission_authorization(encoded_record), now=1500,
        ), "npm_archive_invalid")

        self.assert_refused(lambda: subject.verify_run_receipt(
            encoded_receipt, lock_bytes, material, archives,
            _run_context(), subject.admission_authorization(encoded_record), now=2000,
        ), "npm_context_mismatch")

    def test_run_receipt_supports_a_scoped_permit_before_durable_admission(self):
        fixture = _fixture()
        unused_lock, lock_bytes, archives, material = fixture
        record = _admission_record(fixture)
        receipt = _run_receipt(record)
        authorization = dict(receipt["authorization"])
        authorization["authorization_type"] = "permit"
        authorization["authorization_id"] = "permit-1"
        receipt["authorization"] = authorization
        encoded_receipt = subject.encode_run_receipt(receipt)
        self.assertTrue(subject.verify_run_receipt(
            encoded_receipt, lock_bytes, material, archives,
            _run_context(), authorization, now=1500,
        ))

    def test_receipt_serialization_is_canonical_and_rejects_duplicate_fields(self):
        fixture = _fixture()
        record = _admission_record(fixture)
        encoded = subject.encode_admission_record(record)
        self.assert_refused(
            lambda: subject.decode_admission_record(b" " + encoded), "npm_receipt_invalid",
        )
        duplicate = b'{"schema_version":1,"schema_version":1}'
        self.assert_refused(
            lambda: subject.decode_admission_record(duplicate), "npm_receipt_invalid",
        )
        malformed = dict(record)
        malformed["unexpected"] = True
        self.assert_refused(
            lambda: subject.encode_admission_record(malformed), "npm_receipt_invalid",
        )

    def test_offline_install_arguments_and_environment_are_fixed_and_allowlisted(self):
        self.assertEqual(
            subject.build_offline_install_arguments(),
            ("ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund"),
        )
        runtime_bin = os.path.join(os.path.abspath(os.sep), "pinned-node", "bin")
        scratch_root = os.path.join(os.path.abspath(os.sep), "tmp", "npm-run")
        inherited = {
            "LANG": "C.UTF-8",
            "PATH": "/untrusted/path",
            "HTTP_PROXY": "http://proxy.invalid",
            "npm_config_registry": "https://registry.invalid/",
        }
        if os.name == "nt":
            inherited["SystemRoot"] = os.environ.get("SystemRoot", os.environ.get("SYSTEMROOT", "C:\\Windows"))
        environment = subject.build_offline_install_environment(
            runtime_bin, scratch_root, inherited,
        )
        self.assertEqual(environment["LANG"], "C.UTF-8")
        self.assertTrue(environment["PATH"].startswith(runtime_bin))
        self.assertEqual(environment["npm_config_offline"], "true")
        self.assertEqual(environment["npm_config_ignore_scripts"], "true")
        self.assertNotIn("HTTP_PROXY", environment)
        self.assertNotIn("npm_config_registry", environment)
        self.assertNotIn("/untrusted/path", environment["PATH"])


class NpmLockDetailTests(unittest.TestCase):
    PATH = "node_modules/sample-package-00"

    def refusal(self, change=None, **keywords):
        lock, unused_bytes, unused_archives, unused_material = _fixture()
        if change is not None:
            change(lock)
        raw = json.dumps(lock).encode("ascii")
        with self.assertRaises(subject.Refusal) as raised:
            subject.parse_lock(raw, **keywords)
        error = raised.exception
        self.assertEqual((error.reason, str(error)), ("npm_lock_invalid", "npm_lock_invalid"))
        self.assertIsNotNone(error.detail)
        self.assertLessEqual(len(error.detail), subject.DETAIL_MAX_BYTES)
        self.assertTrue(error.detail.isascii())
        self.assertIsNotNone(subject.DETAIL_RE.match(error.detail))
        return error.detail

    def entry(self, **fields):
        return lambda lock: lock["packages"][self.PATH].update(fields)

    def test_the_lock_level_refusals_name_their_check(self):
        self.assertEqual(self.refusal(lambda lock: lock.update({"extra": 1})), "root_fields")
        self.assertEqual(self.refusal(lambda lock: lock.update({"lockfileVersion": 2})), "lockfile_version")
        self.assertEqual(self.refusal(lambda lock: lock.update({"lockfileVersion": True})), "lockfile_version")
        self.assertEqual(self.refusal(lambda lock: lock.update({"name": "Bad Name"})), "root_name")
        self.assertEqual(self.refusal(lambda lock: lock.update({"version": "x"})), "root_version")
        self.assertEqual(self.refusal(lambda lock: lock.update({"requires": False})), "root_requires")
        self.assertEqual(self.refusal(internal_names=7), "internal_names")
        self.assertEqual(self.refusal(internal_names=("Bad Name",)), "internal_names")
        self.assertEqual(self.refusal(workspace_links={}), "link_config")
        self.assertEqual(self.refusal(workspace_links=[]), "link_config")
        self.assertEqual(
            self.refusal(workspace_links={"node_modules/a": "other/a"}), "link_config:node_modules/a",
        )
        self.assertEqual(self.refusal(lambda lock: lock.update({"packages": []})), "packages_shape")
        self.assertEqual(self.refusal(lambda lock: lock["packages"].pop("")), "packages_shape")

    def test_the_input_and_json_refusals_name_their_check(self):
        for raw, token in (
            (b"", "json_size"), (b"{", "json_decode"), (b'{"a":1,"a":2}', "json_decode"),
            (b'{"a":1.5}', "json_decode"), (b'{"a":NaN}', "json_decode"),
            (b"\xef\xbb\xbf{}", "json_bom"), (b'{"__proto__":1}', "json_key"),
            (b'{"a":' + b"9" * 17 + b"}", "json_decode"),
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(subject.Refusal) as raised:
                    subject.parse_lock(raw)
                self.assertEqual(raised.exception.detail, token)
                self.assertEqual(raised.exception.reason, "npm_lock_invalid")
        with self.assertRaises(subject.Refusal) as raised:
            subject.parse_lock(b" " * (subject.MAX_LOCK_BYTES + 1))
        self.assertEqual(raised.exception.detail, "lock_size")
        with self.assertRaises(subject.Refusal) as raised:
            subject.parse_lock("text")
        self.assertEqual(raised.exception.detail, "lock_size")
        with self.assertRaises(subject.Refusal) as raised:
            subject.registry_entries("text")
        self.assertEqual(raised.exception.detail, "lock_type")
        deep = b"{" + (b'"x":{' * (subject.MAX_JSON_DEPTH + 2)) + b'"x":0' + (b"}" * (subject.MAX_JSON_DEPTH + 3))
        with self.assertRaises(subject.Refusal) as raised:
            subject.parse_lock(deep)
        self.assertIn(raised.exception.detail, ("json_limits", "json_decode"))
        with self.assertRaises(subject.Refusal) as raised:
            subject._integrity_bytes("sha1-x")
        self.assertEqual(raised.exception.detail, "integrity_bytes")

    def test_the_entry_shape_refusals_name_the_lock_path_and_the_field(self):
        path = self.PATH
        self.assertEqual(
            self.refusal(lambda lock: lock["packages"].update({"weird/path": {}})), "entry_path:weird/path",
        )
        self.assertEqual(
            self.refusal(lambda lock: lock["packages"].update({"node_modules/a b": {}})),
            "entry_path:invalid_name",
        )
        self.assertEqual(self.refusal(lambda lock: lock["packages"].update({path: "x"})), "entry_shape:" + path)
        self.assertEqual(self.refusal(self.entry(bogus=1)), "entry_key:" + path + ":bogus")
        self.assertEqual(
            self.refusal(lambda lock: lock["packages"][path].update({"a b\nc": 1})),
            "entry_key:" + path + ":invalid_name",
        )
        self.assertEqual(
            self.refusal(lambda lock: lock["packages"][""].update({"bogus": 1})), "entry_key:root:bogus",
        )
        self.assertEqual(self.refusal(self.entry(optional="yes")), "entry_bool:" + path + ":optional")
        self.assertEqual(self.refusal(self.entry(inBundle=True)), "entry_inbundle:" + path)
        self.assertEqual(self.refusal(self.entry(peerDependenciesMeta=[])), "peer_meta:" + path)
        self.assertEqual(
            self.refusal(self.entry(peerDependenciesMeta={"a": {"other": True}})), "peer_meta:" + path + ":a",
        )
        self.assertEqual(self.refusal(self.entry(workspaces="x")), "workspaces_shape:" + path)
        self.assertEqual(self.refusal(self.entry(workspaces=["../x"])), "workspaces_path:" + path)
        self.assertEqual(self.refusal(self.entry(os="linux")), "entry_list:" + path + ":os")
        self.assertEqual(self.refusal(self.entry(cpu=[1])), "entry_list:" + path + ":cpu")
        self.assertEqual(
            self.refusal(self.entry(bundledDependencies=["a"])), "bundled_deps:" + path + ":bundledDependencies",
        )
        self.assertEqual(self.refusal(self.entry(engines=["node >= 14"])), "engines_shape:" + path)
        self.assertEqual(self.refusal(self.entry(engines={"node": 14})), "engines_shape:" + path)
        self.assertEqual(self.refusal(self.entry(bin=7)), "bin_shape:" + path)
        self.assertEqual(self.refusal(self.entry(bin={"x": "../y"})), "bin_value:" + path)
        self.assertEqual(self.refusal(self.entry(license=7)), "entry_text:" + path + ":license")
        self.assertEqual(self.refusal(self.entry(deprecated=["x"])), "entry_text:" + path + ":deprecated")
        self.assertEqual(self.refusal(self.entry(funding=7)), "funding_shape:" + path)

    def test_the_dependency_refusals_name_the_path_field_and_dependency_and_the_spec_scheme(self):
        path = self.PATH

        def spec(field, name, value):
            return lambda lock: lock["packages"][path].update({field: {name: value}})

        prefix = "dep_spec:" + path + ":dependencies:"
        self.assertEqual(
            self.refusal(spec("dependencies", "string-width-cjs", "npm:string-width@^4.2.0")),
            prefix + "string-width-cjs scheme:npm",
        )
        for value, scheme in (
            ("git+https:" + chr(47) * 2 + "x.invalid/r.git", "git"), ("file:../x", "file"),
            ("link:../x", "link"), ("https:" + chr(47) * 2 + "x.invalid/a.tgz", "https"),
            ("workspace:*", "workspace"), ("a$b", "none"), ("x" * 200, "none"), ("a:b@c", "a"),
            ("1:" + "a", "other"), (7, "other"),
        ):
            with self.subTest(spec=value):
                self.assertEqual(
                    self.refusal(spec("dependencies", "dep-a", value)), prefix + "dep-a scheme:" + scheme,
                )
        self.assertEqual(
            self.refusal(spec("peerDependencies", "dep-a", "npm:x@1")),
            "dep_spec:" + path + ":peerDependencies:dep-a scheme:npm",
        )
        self.assertEqual(
            self.refusal(lambda lock: lock["packages"][""].update({"dependencies": {"a": "file:x"}})),
            "dep_spec:root:dependencies:a scheme:file",
        )
        self.assertEqual(
            self.refusal(spec("dependencies", "Bad Name", "1.0.0")), "dep_name:" + path + ":dependencies:invalid_name",
        )
        self.assertEqual(
            self.refusal(spec("dependencies", "@" + "keeldock" + "/x", "1.0.0")),
            "dep_internal:" + path + ":dependencies:@" + "keeldock" + "/x",
        )
        self.assertEqual(self.refusal(self.entry(dependencies=[])), "dep_map:" + path + ":dependencies")
        self.assertEqual(
            self.refusal(self.entry(optionalDependencies={"d%d" % index: "1.0.0" for index in range(513)})),
            "dep_map:" + path + ":optionalDependencies",
        )

    def test_the_registry_workspace_and_link_refusals_name_the_lock_path(self):
        path = self.PATH
        link = "node_modules/" + "@" + "keeldock" + "/host-api"
        self.assertEqual(self.refusal(self.entry(link=True)), "entry_link:" + path)
        self.assertEqual(self.refusal(self.entry(version="x")), "entry_version:" + path)
        self.assertEqual(
            self.refusal(lambda lock: lock["packages"][path].pop("version")), "entry_version:" + path,
        )
        self.assertEqual(self.refusal(self.entry(integrity="sha1-abc")), "integrity:" + path)
        self.assertEqual(
            self.refusal(lambda lock: lock["packages"][path].pop("integrity")), "integrity:" + path,
        )
        self.assertEqual(self.refusal(self.entry(name="string-width")), "entry_name:" + path)
        self.assertEqual(
            self.refusal(self.entry(name="string-width-cjs", resolved="x")), "entry_name:" + path,
        )
        self.assertEqual(self.refusal(internal_names=("sample-package-00",)), "entry_internal:" + path)
        self.assertEqual(self.refusal(self.entry(resolved="file:x.tgz")), "resolved_url:" + path)
        self.assertEqual(self.refusal(self.entry(resolved=7)), "resolved_url:" + path)
        self.assertEqual(
            self.refusal(lambda lock: lock["packages"][""].update({"name": "other-root"})), "root_entry",
        )
        self.assertEqual(
            self.refusal(lambda lock: lock["packages"][""].update({"link": True})), "root_entry",
        )
        self.assertEqual(
            self.refusal(lambda lock: lock["packages"]["packages/host-api"].update({"name": "x"})),
            "workspace_entry:packages/host-api",
        )
        self.assertEqual(
            self.refusal(lambda lock: lock["packages"].pop("packages/host-api")),
            "workspace_entry:packages/host-api",
        )
        self.assertEqual(
            self.refusal(lambda lock: lock["packages"][link].update({"resolved": "file:packages/host-api"})),
            "link_entry:" + link,
        )
        self.assertEqual(self.refusal(lambda lock: lock["packages"].pop(link)), "link_entry:" + link)

    def test_a_long_or_hostile_name_is_replaced_or_shortened_and_never_echoed(self):
        path = "node_modules/" + "a" * 100
        lock_change = lambda lock: lock["packages"].update({path: {"bogus": 1}})
        self.assertEqual(self.refusal(lock_change), "entry_key:" + path + ":bogus")
        long_path = "node_modules/" + "a" * 213
        detail = self.refusal(lambda lock: lock["packages"].update({long_path: {"x" * 214: 1}}))
        self.assertLessEqual(len(detail), subject.DETAIL_MAX_BYTES)
        self.assertTrue(detail.startswith("entry_key:"))
        for hostile in ("caf" + chr(233), "a" + chr(0x202e) + "b", "a\x00b", "a:b", "a b", "x" * 215):
            with self.subTest(key=hostile):
                lock, unused_bytes, unused_archives, unused_material = _fixture()
                lock["packages"][self.PATH][hostile] = 1
                with self.assertRaises(subject.Refusal) as raised:
                    subject.parse_lock(json.dumps(lock).encode("ascii"))
                self.assertEqual(raised.exception.detail, "entry_key:" + self.PATH + ":invalid_name")
                self.assertEqual(str(raised.exception), "npm_lock_invalid")

    def test_build_detail_bounds_every_shape_and_keeps_the_grammar(self):
        build = subject.build_detail
        self.assertEqual(build("a_b"), "a_b")
        self.assertEqual(build("a", ("p", "q"), count=3, scheme="npm"), "a:p:q count:3 scheme:npm")
        self.assertEqual(build("a", ("p",), scheme="NPM"), "a:p scheme:other")
        self.assertEqual(build("a", ("p",), scheme=7), "a:p scheme:other")
        self.assertEqual(build("a", ("p",), versions=["1.0.0", "x y", 7]), "a:p found:1.0.0,invalid,invalid")
        for token in ("", "Bad", "a b", "a\nb", "x" * 33, None, 3, "caf" + chr(233)):
            with self.subTest(token=token):
                self.assertIsNone(build(token))
        self.assertIsNone(build("a", ("p",) * 7))
        self.assertIsNone(build("a", "pq"))
        self.assertEqual(build("a", ("p", 7, None, "")), "a:p:invalid_name:invalid_name:invalid_name")
        short = build("a", ("x" * 214,) * 3, scheme="npm")
        self.assertLessEqual(len(short), subject.DETAIL_MAX_BYTES)
        self.assertIsNotNone(subject.DETAIL_RE.match(short))
        self.assertIn(":..." + "x" * 57, short)
        for count in range(0, 14):
            for version_length in (1, 2, 40, 63, 64, 65):
                text = build("singleton_duplicate", ("@scope/" + "a" * 150,), ["1." + "9" * (version_length - 2)] * count)
                self.assertLessEqual(len(text), subject.DETAIL_MAX_BYTES)
                self.assertIsNotNone(subject.DETAIL_RE.match(text))
                self.assertLessEqual(text.count(",") + 1, subject.DETAIL_MAX_VERSIONS)
                found = text.partition(" found:")[2]
                if found:
                    for version in found.split(","):
                        self.assertIsNotNone(re.match(r"[0-9A-Za-z.+-]{1,64}\Z", version))

    def test_a_refusal_keeps_its_public_reason_and_drops_an_unsafe_detail(self):
        for bad in ("a\nb", "caf" + chr(233), "x" * 513, "a b", " a", "A", "", 7, b"x", ["a"]):
            with self.subTest(detail=bad):
                error = subject.Refusal("npm_receipt_invalid", bad)
                self.assertIsNone(error.detail)
                self.assertEqual((error.reason, str(error), error.args), ("npm_receipt_invalid",) * 2 + (("npm_receipt_invalid",),))
        error = subject.Refusal("not_a_reason", "root_fields")
        self.assertEqual((error.reason, str(error), error.detail), ("npm_lock_invalid", "npm_lock_invalid", "root_fields"))
        self.assertIsNone(subject.Refusal().detail)


class NpmInertBundledTests(unittest.TestCase):
    PATH = "node_modules/sample-package-00"
    BUNDLED = ["@scope-a/runtime", "plain-lib"]

    def parse(self, **fields):
        lock, unused_bytes, unused_archives, unused_material = _fixture()
        lock["packages"][self.PATH].update(fields)
        return subject.parse_lock(json.dumps(lock).encode("ascii"))

    def refusal_detail(self, **fields):
        with self.assertRaises(subject.Refusal) as raised:
            self.parse(**fields)
        self.assertEqual(raised.exception.reason, "npm_lock_invalid")
        return raised.exception.detail

    def inert(self, **fields):
        values = {"optional": True, "cpu": ["wasm32"], "bundleDependencies": list(self.BUNDLED)}
        values.update(fields)
        return values

    def test_the_optional_wasm32_entry_with_bundled_dependencies_is_admitted(self):
        parsed = self.parse(**self.inert())
        self.assertEqual(parsed["packages"][self.PATH]["cpu"], ["wasm32"])
        self.assertEqual(
            self.refusal_detail(**self.inert(optional=False, devOptional=True)),
            "bundled_deps:" + self.PATH + ":bundleDependencies",
        )
        self.assertEqual(
            self.refusal_detail(devOptional=True, cpu=["wasm32"], bundleDependencies=["plain-lib"]),
            "bundled_deps:" + self.PATH + ":bundleDependencies",
        )
        parsed = self.parse(**self.inert(bundledDependencies=["plain-lib"], bundleDependencies=["x-lib"]))
        self.assertEqual(parsed["packages"][self.PATH]["bundledDependencies"], ["plain-lib"])

    def test_each_inert_condition_failing_still_refuses_with_the_same_detail(self):
        expected = "bundled_deps:" + self.PATH + ":bundleDependencies"
        cases = {
            "not optional": self.inert(optional=False),
            "optional absent": {"cpu": ["wasm32"], "bundleDependencies": list(self.BUNDLED)},
            "cpu absent": {"optional": True, "bundleDependencies": list(self.BUNDLED)},
            "cpu empty": self.inert(cpu=[]),
            "x64": self.inert(cpu=["x64"]),
            "arm64": self.inert(cpu=["arm64"]),
            "ia32": self.inert(cpu=["ia32"]),
            "arm": self.inert(cpu=["arm"]),
            "mixed": self.inert(cpu=["wasm32", "x64"]),
            "negated": self.inert(cpu=["!wasm32"]),
            "negated host": self.inert(cpu=["!x64"]),
            "unknown token": self.inert(cpu=["quantum"]),
            "any token": self.inert(cpu=["any"]),
            "invalid name": self.inert(bundleDependencies=["Bad Name"]),
            "uppercase name": self.inert(bundleDependencies=["UPPER"]),
            "path name": self.inert(bundleDependencies=["../evil"]),
            "too many names": self.inert(bundleDependencies=["lib-%02d" % item for item in range(65)]),
        }
        for label, fields in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.refusal_detail(**fields), expected)

    def test_bundled_name_bounds_refuse(self):
        sixty_four = ["lib-%02d" % item for item in range(64)]
        self.assertEqual(
            self.parse(**self.inert(bundleDependencies=sixty_four))["packages"][self.PATH]["cpu"],
            ["wasm32"],
        )
        self.assertIsNotNone(self.refusal_detail(**self.inert(bundleDependencies=["a" * 129])))

    def child_lock(self, parent=None, children=None, extra=None):
        lock, unused_bytes, unused_archives, unused_material = _fixture()
        lock["packages"][self.PATH].update(self.inert() if parent is None else parent)
        if children is None:
            children = {name: {"version": "1.2.3", "inBundle": True, "optional": True, "dev": True}
                        for name in self.BUNDLED}
        for name, entry in children.items():
            lock["packages"][self.PATH + "/node_modules/" + name] = entry
        for path, entry in (extra or {}).items():
            lock["packages"][path] = entry
        return json.dumps(lock).encode("ascii")

    def child_refusal(self, raw):
        with self.assertRaises(subject.Refusal) as raised:
            subject.parse_lock(raw)
        self.assertEqual(raised.exception.reason, "npm_lock_invalid")
        return raised.exception.detail

    def test_bundled_children_marked_in_bundle_are_admitted_and_never_fetched(self):
        raw = self.child_lock()
        parsed = subject.parse_lock(raw)
        for name in self.BUNDLED:
            self.assertTrue(parsed["packages"][self.PATH + "/node_modules/" + name]["inBundle"])
        paths = [path for path, unused in subject.registry_entries(raw)]
        self.assertIn(self.PATH, paths)
        for name in self.BUNDLED:
            self.assertNotIn(self.PATH + "/node_modules/" + name, paths)
        self.assertEqual(len(paths), len(subject.registry_entries(self.child_lock(children={}))))

    def test_a_lock_without_bundled_child_entries_is_still_admitted(self):
        self.assertIn(self.PATH, [path for path, unused in subject.registry_entries(self.child_lock(children={}))])

    def test_in_bundle_children_under_a_parent_that_is_not_inert_refuse(self):
        for label, parent in {
            "not optional": self.inert(optional=False),
            "dev optional only": self.inert(optional=False, devOptional=True),
            "host cpu": self.inert(cpu=["x64"]),
            "mixed cpu": self.inert(cpu=["wasm32", "arm64"]),
            "no bundle list": {"optional": True, "cpu": ["wasm32"]},
        }.items():
            with self.subTest(case=label):
                self.assertIsNotNone(self.child_refusal(self.child_lock(parent=parent)))
        detail = self.child_refusal(self.child_lock(parent={"optional": True, "cpu": ["wasm32"]}))
        self.assertEqual(detail, "entry_inbundle:" + self.PATH + "/node_modules/@scope-a/runtime")
        orphan = {"node_modules/plain-lib": {"version": "1.2.3", "inBundle": True}}
        self.assertEqual(
            self.child_refusal(self.child_lock(children={}, extra=orphan)),
            "entry_inbundle:node_modules/plain-lib",
        )

    def test_an_undeclared_bundled_child_refuses(self):
        children = {"left-pad": {"version": "1.2.3", "inBundle": True}}
        self.assertEqual(
            self.child_refusal(self.child_lock(children=children)),
            "entry_inbundle:" + self.PATH + "/node_modules/left-pad",
        )

    def test_a_bundled_child_must_be_marked_optional(self):
        for label, flags in {
            "absent": {}, "false": {"optional": False}, "dev optional only": {"devOptional": True},
            "string": {"optional": "true"},
        }.items():
            children = {name: dict({"version": "1.2.3", "inBundle": True}, **flags) for name in self.BUNDLED}
            with self.subTest(case=label):
                self.assertTrue(
                    self.child_refusal(self.child_lock(children=children)).startswith(
                        "entry_inbundle:" + self.PATH + "/node_modules/"),
                )
        one_unmarked = {name: {"version": "1.2.3", "inBundle": True, "optional": True} for name in self.BUNDLED}
        del one_unmarked[self.BUNDLED[-1]]["optional"]
        self.assertEqual(
            self.child_refusal(self.child_lock(children=one_unmarked)),
            "entry_inbundle:" + self.PATH + "/node_modules/" + self.BUNDLED[-1],
        )

    def test_a_bundled_child_with_a_source_script_link_or_bad_shape_refuses(self):
        for label, extra in {
            "resolved": {"resolved": "https://registry.npmjs.org/plain-lib/-/plain-lib-1.2.3.tgz"},
            "integrity": {"integrity": "sha512-" + "A" * 86 + "=="},
            "link": {"link": True},
            "install script": {"hasInstallScript": True},
            "nested bundle list": {"bundleDependencies": ["plain-lib"]},
            "bad version": {"version": "^1.2.3"},
            "no version": {"version": None},
            "other name": {"name": "other-lib"},
        }.items():
            with self.subTest(case=label):
                child = {"version": "1.2.3", "inBundle": True}
                child.update(extra)
                if extra.get("version", 0) is None:
                    del child["version"]
                self.assertIsNotNone(self.child_refusal(self.child_lock(children={"plain-lib": child})))

    def test_nested_bundled_children_of_a_bundled_child_refuse(self):
        deeper = {
            self.PATH + "/node_modules/plain-lib/node_modules/plain-lib": {"version": "1.2.3", "inBundle": True},
        }
        raw = self.child_lock(extra=deeper)
        self.assertEqual(
            self.child_refusal(raw),
            "entry_inbundle:" + self.PATH + "/node_modules/plain-lib/node_modules/plain-lib",
        )
        scoped = {
            self.PATH + "/node_modules/@scope-a/runtime/node_modules/plain-lib": {"version": "1.2.3", "inBundle": True},
        }
        self.assertIsNotNone(self.child_refusal(self.child_lock(extra=scoped)))

    def test_a_bundled_child_may_not_use_an_internal_name(self):
        raw = self.child_lock()
        with self.assertRaises(subject.Refusal):
            subject.parse_lock(raw, internal_names=("plain-lib",))

    def _inert_entry(self, data, **fields):
        entry = {
            "name": "sample", "version": "1.0.0", "integrity": _sri(data),
            "optional": True, "cpu": ["wasm32"], "bundleDependencies": list(self.BUNDLED),
        }
        entry.update(fields)
        return entry

    def _bundled_tarball(self, extra=()):
        members = (
            ("package/node_modules/plain-lib/package.json", b"{}"),
            ("package/node_modules/@scope-a/runtime/index.js", b"synthetic"),
        )
        return _tarball("sample", "1.0.0", extra=members + tuple(extra))

    def test_the_archive_of_an_inert_entry_may_carry_its_declared_bundled_tree(self):
        data = self._bundled_tarball()
        report = subject.verify_tarball(self._inert_entry(data), data)
        self.assertEqual(report["file_count"], 3)

    def test_the_archive_tree_is_refused_unless_the_entry_is_inert(self):
        data = self._bundled_tarball()
        for label, fields in (
                ("x64", {"cpu": ["x64"]}), ("mixed", {"cpu": ["wasm32", "arm64"]}),
                ("not optional", {"optional": False}), ("no cpu", {"cpu": None})):
            with self.subTest(case=label):
                entry = self._inert_entry(data, **fields)
                if fields.get("cpu", 0) is None:
                    del entry["cpu"]
                with self.assertRaises(subject.Refusal) as raised:
                    subject.verify_tarball(entry, data)
                self.assertEqual(raised.exception.reason, "npm_archive_invalid")
        plain = {"name": "sample", "version": "1.0.0", "integrity": _sri(data)}
        with self.assertRaises(subject.Refusal):
            subject.verify_tarball(plain, data)

    def test_the_archive_tree_must_match_the_declared_names_and_stay_flat(self):
        for path in (
                "package/node_modules/other-lib/package.json",
                "package/node_modules/plain-lib/node_modules/inner/package.json",
                "package/node_modules/@scope-a/other/index.js",
                "package/node_modules/plain-lib",
                "package/lib/node_modules/plain-lib/package.json"):
            with self.subTest(path=path):
                data = _tarball("sample", "1.0.0", extra=((path, b"synthetic"),))
                with self.assertRaises(subject.Refusal) as raised:
                    subject.verify_tarball(self._inert_entry(data), data)
                self.assertEqual(raised.exception.reason, "npm_archive_invalid")

    def test_an_inert_archive_keeps_every_other_archive_check(self):
        data = self._bundled_tarball()
        entry = self._inert_entry(data, integrity=_sri(b"other"))
        with self.assertRaises(subject.Refusal):
            subject.verify_tarball(entry, data)
        escaping = _tarball("sample", "1.0.0", extra=(("package/../escape", b"x"),))
        with self.assertRaises(subject.Refusal):
            subject.verify_tarball(self._inert_entry(escaping), escaping)


ACUTE = chr(0xE9)
BIDI = chr(0x202E)
CYRILLIC = chr(0x430) + "b" + chr(0x441)
SUPERSCRIPT_TWO = chr(0xB2)
SUPERSCRIPT_ONE = chr(0xB9)


class NpmArchiveDetailTests(unittest.TestCase):
    SUBJECT = "sample@1.0.0"

    def entry(self, data, **fields):
        value = {"name": "sample", "version": "1.0.0", "integrity": _sri(data)}
        value.update(fields)
        return value

    def refusal(self, data, **fields):
        with self.assertRaises(subject.Refusal) as raised:
            subject.verify_tarball(self.entry(data, **fields), data)
        error = raised.exception
        self.assertEqual((error.reason, str(error)), ("npm_archive_invalid", "npm_archive_invalid"))
        self.assertIsNotNone(error.detail)
        self.assertLessEqual(len(error.detail), subject.DETAIL_MAX_BYTES)
        self.assertTrue(error.detail.isascii())
        self.assertIsNotNone(subject.DETAIL_RE.match(error.detail))
        return error.detail

    def member_tar(self, info, content=b""):
        return _tar_with_members(((info, content),))

    def test_a_refused_member_name_is_shown_with_its_rule_and_index(self):
        for path, rule in (
            ("package/a~b.js", "tilde"), ("package/lib/aux.js", "reserved_name"),
            ("package/lib/con", "reserved_name"), ("package/lib/lpt3.txt", "reserved_name"),
            ("package/trail.", "trailing_dot"), ("package/dir/../x", "dot_segment"),
            ("package/./x", "dot_segment"), ("package//x", "empty_segment"),
        ):
            with self.subTest(path=path):
                data = _tarball("sample", "1.0.0", extra=((path, b"x"),))
                self.assertEqual(
                    self.refusal(data), "archive_path:" + self.SUBJECT + ":" + rule + ":" + path + " index:2",
                )

    def test_a_member_name_outside_the_shared_grammar_is_never_echoed(self):
        for path, rule in (
            ("package/a\nb", "control_char"), ("package/caf" + ACUTE + ".js", "non_ascii"),
            ("package/a" + BIDI + "b", "non_ascii"), ("package/<script>", "bad_char"),
            ("package/with space/x:y", "bad_char"), ("package/a\\b", "backslash"),
            ("package/" + CYRILLIC, "non_ascii"), ("package/trail ", "trailing_space"),
            ("package/a:b", "bad_char"), ("package/a|b", "bad_char"),
        ):
            with self.subTest(path=path):
                data = _tarball("sample", "1.0.0", extra=((path, b"x"),))
                detail = self.refusal(data)
                self.assertEqual(
                    detail, "archive_path:" + self.SUBJECT + ":" + rule + ":unrepresentable index:2",
                )
                self.assertNotIn("script", detail)
                self.assertNotIn("\n", detail)
                self.assertNotIn(BIDI, detail)
                self.assertTrue(detail.isascii())

    def test_a_long_member_name_is_replaced_by_its_index(self):
        path = "package/" + "d" * 50 + "/" + "a" * 60 + "~"
        data = _tarball("sample", "1.0.0", extra=((path, b"x"),))
        self.assertEqual(
            self.refusal(data), "archive_path:" + self.SUBJECT + ":tilde:unrepresentable index:2",
        )
        shown = "package/" + "d" * 40 + "/" + "a" * 40 + "~"
        self.assertLessEqual(len(shown), subject.ARCHIVE_MEMBER_NAME_LIMIT)
        data = _tarball("sample", "1.0.0", extra=((shown, b"x"),))
        self.assertEqual(self.refusal(data), "archive_path:" + self.SUBJECT + ":tilde:" + shown + " index:2")

    def test_a_member_type_other_than_a_file_or_directory_is_named(self):
        for kind, name in (
            (tarfile.SYMTYPE, "symlink"), (tarfile.LNKTYPE, "hardlink"), (tarfile.CHRTYPE, "chardevice"),
            (tarfile.BLKTYPE, "blockdevice"), (tarfile.FIFOTYPE, "fifo"),
        ):
            with self.subTest(kind=name):
                info = tarfile.TarInfo("package/special")
                info.type = kind
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    info.linkname = "package/package.json"
                data = self.member_tar(info)
                self.assertEqual(
                    self.refusal(data),
                    "archive_member_type:" + self.SUBJECT + ":" + name + ":package/special index:1",
                )

    def test_a_pax_header_member_is_named_by_its_type(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
            info = tarfile.TarInfo("package/caf" + ACUTE + ".js")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        detail = self.refusal(output.getvalue())
        self.assertTrue(detail.startswith("archive_member_type:" + self.SUBJECT + ":pax_header:"))
        self.assertTrue(detail.endswith(" index:0"))

    def test_a_non_package_root_a_nested_node_modules_and_duplicates_are_named(self):
        data = _tarball("sample", "1.0.0", extra=(("other/x.js", b"x"),))
        self.assertEqual(self.refusal(data), "archive_root:" + self.SUBJECT + ":other index:2")
        data = _tarball("sample", "1.0.0", extra=(("package/lib/node_modules/x/y.js", b"x"),))
        self.assertEqual(
            self.refusal(data),
            "archive_path:" + self.SUBJECT + ":node_modules:package/lib/node_modules/x/y.js index:2",
        )
        data = _tarball("sample", "1.0.0", extra=(("package/a.js", b"x"), ("package/a.js", b"y")))
        self.assertEqual(
            self.refusal(data), "archive_path:" + self.SUBJECT + ":duplicate:package/a.js index:3",
        )
        data = _tarball("sample", "1.0.0", extra=(("package/A.js", b"x"), ("package/a.js", b"y")))
        self.assertEqual(
            self.refusal(data), "archive_path:" + self.SUBJECT + ":case_collision:package/a.js index:3",
        )
        data = _tarball("sample", "1.0.0", extra=(("package/a", b"x"), ("package/a/b", b"y")))
        self.assertEqual(
            self.refusal(data), "archive_path:" + self.SUBJECT + ":file_parent:package/a/b index:3",
        )
        data = _tarball("sample", "1.0.0", extra=(("package/a b", b"x"), ("package/a b/c", b"y")))
        self.assertEqual(
            self.refusal(data),
            "archive_path:" + self.SUBJECT + ":file_parent:unrepresentable index:3",
        )

    def accepted(self, data, **fields):
        return subject.verify_tarball(self.entry(data, **fields), data)

    def test_a_single_top_level_directory_of_any_name_is_the_archive_root(self):
        for root in ("package", "aria-query", "node", "Types", "a.b", "x_y", "@scope"):
            with self.subTest(root=root):
                data = _rooted_tarball(root, extra=((root + "/index.d.ts", b"export {};"),))
                report = self.accepted(data)
                self.assertEqual((report["name"], report["version"]), ("sample", "1.0.0"))
                self.assertEqual(report["file_count"], 2)
                self.assertEqual(report["install_scripts"], ())
        data = _rooted_tarball("aria-query", with_directory=False)
        self.assertEqual(self.accepted(data)["file_count"], 1)

    def test_every_other_archive_rule_applies_relative_to_the_chosen_root(self):
        data = _rooted_tarball("aria-query", extra=(("aria-query/binding.gyp", b"{}"),))
        self.assertEqual(self.accepted(data)["implicit_install_scripts"], ("install",))
        data = _rooted_tarball("aria-query", extra=(("aria-query/lib/binding.gyp", b"{}"),))
        self.assertEqual(self.accepted(data)["implicit_install_scripts"], ())
        data = _rooted_tarball("aria-query", extra=(("aria-query/lib/node_modules/x/y.js", b"x"),))
        self.assertEqual(
            self.refusal(data),
            "archive_path:" + self.SUBJECT + ":node_modules:aria-query/lib/node_modules/x/y.js index:2",
        )
        data = _rooted_tarball("aria-query", extra=(("aria-query/a.js", b"x"), ("aria-query/a.js", b"y")))
        self.assertEqual(
            self.refusal(data), "archive_path:" + self.SUBJECT + ":duplicate:aria-query/a.js index:3",
        )
        data = _rooted_tarball("aria-query", name="other")
        self.assertEqual(self.refusal(data), "archive_manifest:" + self.SUBJECT + ":name_mismatch")
        renamed = _rooted_tarball("aria-query", extra=(("package/package.json", b"{}"),))
        self.assertEqual(
            self.refusal(renamed), "archive_root:" + self.SUBJECT + ":package index:2",
        )

    def test_node_modules_is_allowed_only_below_a_first_level_test_directory(self):
        for path in (
            "package/test/resolver/symlinked/_/node_modules/foo.js",
            "package/test/shadowed_core/node_modules/util/index.js",
            "package/tests/node_modules/x.js",
            "package/__tests__/a/node_modules/x.js",
            "package/fixtures/node_modules/x.js",
            "package/__fixtures__/node_modules/x.js",
            "package/example/node_modules/x.js",
            "package/examples/a/b/node_modules/x/y.js",
        ):
            with self.subTest(path=path):
                report = self.accepted(_rooted_tarball("package", extra=((path, b"x"),)))
                self.assertEqual(report["install_scripts"], ())
        data = _rooted_tarball("package", extra=(
            ("package/test/resolver/symlinked/_/node_modules/foo.js", b"x"),
            ("package/test/shadowed_core/node_modules/util/index.js", b"x"),
        ))
        self.assertEqual(self.accepted(data)["file_count"], 3)

    def test_node_modules_elsewhere_or_with_other_spellings_still_refuses(self):
        for path, index in (
            ("package/node_modules/x.js", 2),
            ("package/lib/node_modules/x.js", 2),
            ("package/test/../node_modules/x.js", 2),
            ("package/Test/node_modules/x.js", 2),
            ("package/TEST/node_modules/x.js", 2),
            ("package/test/Node_Modules/x.js", 2),
            ("package/test/a/NODE_MODULES/x.js", 2),
            ("package/testing/node_modules/x.js", 2),
            ("package/lib/test/node_modules/x.js", 2),
        ):
            with self.subTest(path=path):
                detail = self.refusal(_rooted_tarball("package", extra=((path, b"x"),)))
                self.assertTrue(detail.startswith("archive_path:" + self.SUBJECT + ":"), detail)
                self.assertIn(":node_modules:" if ".." not in path else ":dot_segment:", detail)
        data = _rooted_tarball("package", extra=(("package/node_modules/x.js", b"x"),))
        self.assertEqual(
            self.refusal(data),
            "archive_path:" + self.SUBJECT + ":node_modules:package/node_modules/x.js index:2",
        )
        data = _rooted_tarball("package", extra=(("package/lib/node_modules/x.js", b"x"),))
        self.assertEqual(
            self.refusal(data),
            "archive_path:" + self.SUBJECT + ":node_modules:package/lib/node_modules/x.js index:2",
        )
        data = _rooted_tarball("node_modules", extra=(("node_modules/test/x.js", b"x"),))
        self.assertTrue(self.refusal(data).startswith("archive_root:"))
        self.assertFalse(subject._test_tree_node_modules_allowed(["package", "node_modules"]))
        self.assertFalse(subject._test_tree_node_modules_allowed(["package", "node_modules", "x"]))

    def test_a_nested_manifest_under_a_test_node_modules_is_a_plain_file(self):
        nested = b'{"name":"evil","version":"9.9.9","scripts":{"install":"synthetic"}}'
        data = _rooted_tarball(
            "package", extra=(("package/test/node_modules/evil/package.json", nested),),
        )
        report = self.accepted(data)
        self.assertEqual((report["name"], report["version"]), ("sample", "1.0.0"))
        self.assertEqual(report["install_scripts"], ())
        data = _rooted_tarball(
            "package", extra=(("package/test/node_modules/evil/binding.gyp", b"{}"),),
        )
        self.assertEqual(self.accepted(data)["implicit_install_scripts"], ())

    def test_mixed_archive_roots_refuse_with_the_same_token(self):
        data = _rooted_tarball("aria-query", extra=(("other/x.js", b"x"),))
        self.assertEqual(self.refusal(data), "archive_root:" + self.SUBJECT + ":other index:2")
        data = _rooted_tarball("aria-query", extra=(("package/x.js", b"x"),))
        self.assertEqual(self.refusal(data), "archive_root:" + self.SUBJECT + ":package index:2")
        data = _rooted_tarball("aria-query", extra=(("Aria-Query/x.js", b"x"),))
        self.assertEqual(self.refusal(data), "archive_root:" + self.SUBJECT + ":Aria-Query index:2")

    def test_a_node_modules_root_refuses(self):
        for root in ("node_modules", "Node_Modules"):
            with self.subTest(root=root):
                data = _rooted_tarball(root)
                self.assertEqual(self.refusal(data), "archive_root:" + self.SUBJECT + ":" + root + " index:0")

    def test_a_member_at_the_top_level_refuses(self):
        data = _tarball("sample", "1.0.0", extra=(("top.js", b"x"),))
        self.assertEqual(self.refusal(data), "archive_root:" + self.SUBJECT + ":top.js index:2")
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo("package.json")
            info.size = 2
            archive.addfile(info, io.BytesIO(b"{}"))
        self.assertEqual(
            self.refusal(output.getvalue()),
            "archive_path:" + self.SUBJECT + ":root_file:package.json index:0",
        )

    def test_the_gzip_and_tar_framing_refusals_name_their_check(self):
        self.assertEqual(self.refusal(b"plain bytes"), "archive_gzip:" + self.SUBJECT + ":not_gzip")
        broken = b"\x1f\x8b" + b"garbage garbage"
        self.assertEqual(self.refusal(broken), "archive_gzip:" + self.SUBJECT + ":corrupt")
        short = gzip.compress(b"x" * 100)
        self.assertEqual(self.refusal(short), "archive_tar:" + self.SUBJECT + ":shape")
        valid = gzip.decompress(_tarball("sample", "1.0.0"))
        garbled = bytearray(valid)
        garbled[148:156] = b"zzzzzzz\x00"
        self.assertEqual(
            self.refusal(gzip.compress(bytes(garbled))),
            "archive_tar:" + self.SUBJECT + ":octal_checksum index:0",
        )
        wrong = bytearray(valid)
        wrong[0:1] = b"q"
        self.assertEqual(
            self.refusal(gzip.compress(bytes(wrong))), "archive_tar:" + self.SUBJECT + ":checksum index:0",
        )
        trailing = valid + b"junk" + bytes(508)
        self.assertEqual(
            self.refusal(gzip.compress(trailing)), "archive_tar:" + self.SUBJECT + ":trailing_data",
        )
        self.assertEqual(
            self.refusal(gzip.compress(valid[:1536])), "archive_tar:" + self.SUBJECT + ":no_end",
        )

    def test_the_size_and_count_refusals_name_their_check(self):
        data = _tarball("sample", "1.0.0")
        with unittest.mock.patch.object(subject, "MAX_TARBALL_BYTES", 10):
            self.assertEqual(self.refusal(data), "archive_size:" + self.SUBJECT + ":tarball")
        with unittest.mock.patch.object(subject, "MAX_TAR_BYTES", 10):
            self.assertEqual(self.refusal(data), "archive_size:" + self.SUBJECT + ":tar")
        with unittest.mock.patch.object(subject, "MAX_ARCHIVE_FILES", 1):
            self.assertEqual(self.refusal(data), "archive_count:" + self.SUBJECT + ":members index:1")
        with unittest.mock.patch.object(subject, "MAX_PACKAGE_UNPACKED_BYTES", 5):
            self.assertEqual(self.refusal(data), "archive_size:" + self.SUBJECT + ":member index:1")
        bigger = _tarball("sample", "1.0.0", extra=(("package/a.js", b"x" * 100),))
        with unittest.mock.patch.object(subject, "MAX_PACKAGE_UNPACKED_BYTES", 120):
            self.assertEqual(self.refusal(bigger), "archive_size:" + self.SUBJECT + ":unpacked index:2")
        oversized = tarfile.TarInfo("package/too-large")
        oversized.size = subject.MAX_PACKAGE_UNPACKED_BYTES + 1
        raw_tar = oversized.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024)
        self.assertEqual(
            self.refusal(gzip.compress(raw_tar)), "archive_size:" + self.SUBJECT + ":member index:0",
        )

    def test_the_integrity_and_input_refusals_name_their_check(self):
        data = _tarball("sample", "1.0.0")
        self.assertEqual(
            self.refusal(data, integrity=_sri(b"other")), "integrity_mismatch:" + self.SUBJECT + ":archive",
        )
        self.assertEqual(
            self.refusal(b"", integrity=_sri(b"x")), "archive_input:" + self.SUBJECT + ":tarball_empty",
        )
        self.assertEqual(
            self.refusal(data, resolved="https://example.invalid/x.tgz"),
            "archive_input:" + self.SUBJECT + ":resolved",
        )
        with self.assertRaises(subject.Refusal) as raised:
            subject.verify_tarball(self.entry(data), data, internal_names=("sample",))
        self.assertEqual(raised.exception.detail, "archive_input:" + self.SUBJECT + ":internal")
        with self.assertRaises(subject.Refusal) as raised:
            subject.verify_tarball({"name": "sample"}, data)
        self.assertEqual(raised.exception.detail, "archive_input:unknown:entry_shape")
        self.assertEqual(self.refusal(data, name="Bad Name"), "archive_input:Bad_Name@1.0.0:name")
        self.assertEqual(self.refusal(data, version="x"), "archive_input:sample@x:version")

    def test_archive_manifests_keep_json_floats_as_opaque_text_and_nothing_else_does(self):
        loaded = subject._load_json(b'{"a":1.5,"b":[3.5,10]}', 100, "npm_archive_invalid", opaque_numbers=True)
        self.assertEqual(loaded, {"a": "1.5", "b": ["3.5", 10]})
        with self.assertRaises(subject.Refusal) as raised:
            subject._load_json(b'{"a":1.5}', 100, "npm_lock_invalid")
        self.assertEqual(raised.exception.reason, "npm_lock_invalid")
        data = self.member_tar(
            tarfile.TarInfo("package/package.json"),
            b'{"name":"sample","version":"1.0.0","testling":{"browsers":{"ff":[3.5,10]}}}',
        )
        self.assertEqual(subject.verify_tarball(self.entry(data), data)["file_count"], 1)

    def test_a_float_is_opaque_text_that_exact_type_checks_refuse(self):
        self.assertIs(type(subject._load_json(b'{"a":1.5}', 100, "npm_archive_invalid", opaque_numbers=True)["a"]), subject.OpaqueNumber)
        self.assertTrue(issubclass(subject.OpaqueNumber, str))
        self.assertIsNot(subject.OpaqueNumber, str)
        for text, token in (
            ('{"name":"sample","version":"1.0.0","scripts":{"install":1.5}}', "scripts_value"),
            ('{"name":"sample","version":"1.0.0","scripts":{"postinstall":2.5e3}}', "scripts_value"),
            ('{"name":1.5,"version":"1.0.0"}', "name_mismatch"),
            ('{"name":"sample","version":1.5}', "version_mismatch"),
            ('{"name":"sample","version":"1.0.0","x":1.' + "1" * 9000 + "}", "json_string"),
        ):
            with self.subTest(token=token, text=text[:40]):
                data = self.member_tar(tarfile.TarInfo("package/package.json"), text.encode("ascii"))
                self.assertEqual(self.refusal(data), "archive_manifest:" + self.SUBJECT + ":" + token)
        data = self.member_tar(
            tarfile.TarInfo("package/package.json"),
            b'{"name":"sample","version":"1.0.0","scripts":{"test":"run"},"x":1.5}',
        )
        self.assertEqual(subject.verify_tarball(self.entry(data), data)["install_scripts"], ())

    def test_entry_points_that_name_a_node_modules_path_refuse(self):
        template = '{"name":"sample","version":"1.0.0",%s}'
        for fields in (
            '"main":"node_modules/x/index.js"',
            '"main":"./test/node_modules/a.js"',
            '"module":"lib\\\\Node_Modules\\\\a.js"',
            '"browser":"NODE_MODULES/x.js"',
            '"bin":"bin/../node_modules/.bin/x"',
            '"bin":{"x":"node_modules/x/cli.js"}',
            '"exports":{".":{"import":"./node_modules/x/index.mjs"}}',
            '"exports":["./a.js","./node_modules/b.js"]',
            '"types":"node_modules/@types/x/index.d.ts"',
            '"typings":"test/node_modules/x.d.ts"',
        ):
            with self.subTest(fields=fields):
                data = self.member_tar(tarfile.TarInfo("package/package.json"), (template % fields).encode("ascii"))
                self.assertEqual(self.refusal(data), "archive_manifest:" + self.SUBJECT + ":entry_node_modules")
        for fields in (
            '"main":"lib/index.js"',
            '"main":"lib/node_modulesx/a.js"',
            '"main":"my_node_modules/a.js"',
            '"exports":{"./node_modules":"./lib/modules.js"}',
            '"bin":{"node_modules":"bin/cli.js"}',
            '"description":"uses node_modules/is-fine"',
            '"files":["node_modules/not-an-entry"]',
        ):
            with self.subTest(allowed=fields):
                data = self.member_tar(tarfile.TarInfo("package/package.json"), (template % fields).encode("ascii"))
                self.assertEqual(subject.verify_tarball(self.entry(data), data)["install_scripts"], ())

    def test_a_native_binary_under_an_admitted_test_node_modules_is_still_reported(self):
        data = _rooted_tarball("package", extra=(
            ("package/test/node_modules/x/addon.node", b"synthetic"),
            ("package/test/node_modules/x/blob.bin", b"\x7fELF" + bytes(8)),
            ("package/test/node_modules/x/plain.js", b"synthetic"),
        ))
        self.assertEqual(self.accepted(data)["native_binaries"], (
            "package/test/node_modules/x/addon.node", "package/test/node_modules/x/blob.bin",
        ))

    def test_the_manifest_refusals_name_their_check(self):
        other_name = _tarball("other", "1.0.0")
        self.assertEqual(self.refusal(other_name), "archive_manifest:" + self.SUBJECT + ":name_mismatch")
        other_version = _tarball("sample", "2.0.0")
        self.assertEqual(self.refusal(other_version), "archive_manifest:" + self.SUBJECT + ":version_mismatch")
        no_manifest = self.member_tar(tarfile.TarInfo("package/readme.txt"), b"x")
        self.assertEqual(self.refusal(no_manifest), "archive_manifest:" + self.SUBJECT + ":missing")
        for text, token in (
            ('{"name":"sample","version":"1.0.0","x":NaN}', "json_decode"),
            ('{"name":"sample","version":"1.0.0","x":Infinity}', "json_decode"),
            ('{"name":"sample","version":"1.0.0","x":1,"x":2}', "json_decode"),
            ('{"name":"sample","version":"1.0.0","scripts":[]}', "scripts_shape"),
            ('{"name":"sample","version":"1.0.0","scripts":{"a":1}}', "scripts_value"),
            ("[]", "shape"),
            ('{"name":"sample","version":"1.0.0","x":"' + "y" * 9000 + '"}', "json_string"),
        ):
            with self.subTest(token=token):
                data = self.member_tar(tarfile.TarInfo("package/package.json"), text.encode("ascii"))
                self.assertEqual(self.refusal(data), "archive_manifest:" + self.SUBJECT + ":" + token)

    def test_a_long_package_subject_is_shortened_and_the_whole_detail_stays_bounded(self):
        name = "a" * 214
        version = "1.0.0-" + "b" * 100
        data = _tarball(name, version, extra=(("package/a~b", b"x"),))
        with self.assertRaises(subject.Refusal) as raised:
            subject.verify_tarball({"name": name, "version": version, "integrity": _sri(data)}, data)
        detail = raised.exception.detail
        self.assertIsNotNone(detail)
        self.assertLessEqual(len(detail), subject.DETAIL_MAX_BYTES)
        self.assertIsNotNone(subject.DETAIL_RE.match(detail))
        self.assertIn("a" * 57 + "...@1.0.0-", detail)
        self.assertEqual(raised.exception.reason, "npm_archive_invalid")

    def test_the_classifier_agrees_with_the_safe_path_rule_for_every_sample(self):
        samples = (
            "", "package/x", "package/a b", "package/a~b", "package/con", "package/COM1.txt",
            "package/lpt" + SUPERSCRIPT_TWO, "package/nul.", "package/a.", "package/a ", "/abs", "a\\b",
            "a//b", "a/./b", "a/../b", "package/" + "a" * 600, "caf" + ACUTE, "tab\tname", "package/<a>",
            'package/a"b', "package/a|b", "package/a?b", "package/a*b", "package/a:b",
            "package/.hidden", "package/..x", "package/x.y.z", "package/CON.d.ts", "package/conin$",
            "package/lib/clock$", "package/com0", "package/com9.js", "package/lpt" + SUPERSCRIPT_ONE,
            None, 5, b"x",
        )
        rules = set()
        for value in samples:
            with self.subTest(value=value):
                rule = subject._archive_path_rule(value)
                self.assertEqual(rule is None, subject._safe_relative_archive_path(value))
                rules.add(rule)
        self.assertTrue({
            "empty", "backslash", "absolute", "too_long", "non_ascii", "control_char", "empty_segment",
            "dot_segment", "trailing_dot", "trailing_space", "tilde", "bad_char", "reserved_name", None,
        }.issubset(rules))

    def test_the_shared_detail_helpers_bound_every_value(self):
        self.assertEqual(subject.detail_text("MIT"), "MIT")
        self.assertEqual(subject.detail_text("(MIT OR GPL)"), "_MIT_OR_GPL_")
        self.assertEqual(subject.detail_text("GPL-2.0+", 64, subject.DETAIL_FIELD_CHAR_RE), "GPL-2.0+")
        self.assertEqual(subject.detail_text(""), "empty")
        self.assertEqual(subject.detail_text(None), "invalid")
        long_text = subject.detail_text("a" * 500, 64)
        self.assertEqual((len(long_text), long_text[-3:]), (64, "..."))
        shortened = subject.package_subject("a" * 214, "1.0.0+" + "b" * 90)
        self.assertEqual(shortened.count("@"), 1)
        self.assertLessEqual(len(shortened), 81)
        text = subject.build_detail("archive_path", ("p@1.0.0", "tilde"), fields=(("index", 7), ("id", "A+b:c")))
        self.assertEqual(text, "archive_path:p@1.0.0:tilde index:7 id:A+b:c")
        self.assertIsNotNone(subject.DETAIL_RE.match(text))
        hostile = subject.build_detail("a", ("p",), fields=(("Bad", 1), ("index", -1), ("id", "a b"), ("x", True)))
        self.assertEqual(hostile, "a:p index:invalid id:invalid x:invalid")
        self.assertIsNone(subject.build_detail("a", ("p",), fields=7))
        self.assertIsNone(subject.build_detail("a", ("p",), fields=(("id", "x" * 512),) * 3))


if __name__ == "__main__":
    unittest.main()
