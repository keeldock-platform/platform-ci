import base64
import gzip
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest

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


def _tarball(name, version, scripts=None, binary=False, extra=()):
    manifest = json.dumps(
        {"name": name, "version": version, "scripts": scripts or {}},
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


if __name__ == "__main__":
    unittest.main()
