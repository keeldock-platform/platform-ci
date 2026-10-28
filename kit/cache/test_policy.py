import base64
import hashlib
import json
import unittest
import zlib
from dataclasses import replace
from unittest.mock import patch

import policy


SLOT_A = "abcdefghijklmnop"
SLOT_B = "bcdefghijklmnopq"
REPOSITORY = "origin/platform-ci"
TOOLS = {"rust": "1.80.1", "node": "20.16.0", "npm": "10.8.1"}
MAIN = "refs/heads/main"
UNTRUSTED = "refs/heads/untrusted"


def _cargo_source():
    return "registry+" + "https:" + "/" * 2 + "github.com/rust-lang/crates.io-index"


def _lock_fixtures():
    cargo_bytes = b"public cargo archive"
    npm_bytes = b"public npm archive"
    cargo_digest = hashlib.sha256(cargo_bytes).hexdigest()
    npm_integrity = "sha512-" + base64.b64encode(hashlib.sha512(npm_bytes).digest()).decode("ascii")
    cargo_lock = (
        "version = 4\n\n"
        "[[package]]\n"
        "name = \"sample-crate\"\n"
        "version = \"1.2.3\"\n"
        "source = \"" + _cargo_source() + "\"\n"
        "checksum = \"" + cargo_digest + "\"\n"
    )
    npm_lock = json.dumps({
        "name": "workspace-fixture",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "workspace-fixture", "version": "1.0.0"},
            "node_modules/sample-npm": {
                "version": "2.3.4",
                "resolved": "https://registry.npmjs.org/sample-npm/-/sample-npm-2.3.4.tgz",
                "integrity": npm_integrity,
            },
        },
    })
    projection = policy.project_public_locks(cargo_lock, npm_lock)
    payloads = {
        ("cargo", "sample-crate"): cargo_bytes,
        ("npm", "sample-npm"): npm_bytes,
    }
    stager = policy.BoundedArchiveStager()
    archives = tuple(_archive(record, payloads[(record.manager, record.package)], stager=stager)
                     for record in projection.records)
    return cargo_lock, npm_lock, projection, archives


def _archive(record, payload, stager=None, **changes):
    result = (stager or policy.BoundedArchiveStager()).stage(_claim(record), (payload,))
    return replace(result, **changes) if changes else result


def _claim(record, **changes):
    claim = policy.CacheArchiveClaim(
        record.archive_path, record.manager, record.package, record.version,
        record.registry, record.archive_origin, record.digest_algorithm,
        record.digest_value, "file", "public-archive",
    )
    return replace(claim, **changes) if changes else claim


def _expectation(projection, source_slot=SLOT_A, visible=(MAIN, UNTRUSTED), trusted=(MAIN,),
                 toolchains=None, read_mode=True, confinement=True, protected_root=True):
    return policy.RestoreExpectation(
        REPOSITORY,
        source_slot,
        "linux",
        "x86_64",
        TOOLS if toolchains is None else toolchains,
        projection,
        tuple(visible),
        tuple(trusted),
        cache_read_mode_proved=read_mode,
        confinement_profile_approved=confinement,
        protected_root_custody_proved=protected_root,
    )


def _entry(projection, archives, expectation=None, **changes):
    expectation = expectation or _expectation(projection)
    result = policy.CacheEntry(
        expectation.key,
        expectation.schema,
        expectation.repository,
        expectation.source_slot,
        expectation.operating_system,
        expectation.architecture,
        policy.toolchain_identity_digest(expectation.toolchains),
        projection.digest,
        MAIN,
        sum(len(item.data) for item in archives),
        len(archives),
        tuple(archives),
    )
    return replace(result, **changes) if changes else result


class PublicLockProjectionTests(unittest.TestCase):
    def test_projection_contains_only_public_lock_identity(self):
        cargo_lock, npm_lock, projection, _ = _lock_fixtures()
        self.assertEqual(len(projection.records), 2)
        self.assertEqual(projection.managers, frozenset(("cargo", "npm")))
        values = json.loads(projection.canonical_bytes.decode("ascii"))
        self.assertEqual(
            set(values[0]),
            {"registry", "package", "version", "archive_digest", "format"},
        )
        self.assertNotIn("source_sha", projection.canonical_bytes.decode("ascii"))
        self.assertNotIn("private", projection.canonical_bytes.decode("ascii").lower())
        self.assertNotIn(_cargo_source(), projection.canonical_bytes.decode("ascii"))
        self.assertIn("sample-npm", npm_lock)

    def test_local_cargo_workspace_package_is_not_a_registry_archive(self):
        cargo_lock, npm_lock, _, _ = _lock_fixtures()
        cargo_lock += (
            "\n[[package]]\n"
            "name = \"workspace-root\"\n"
            "version = \"0.1.0\"\n"
        )
        projection = policy.project_public_locks(cargo_lock, npm_lock)
        self.assertEqual(len(projection.records), 2)
        self.assertNotIn("workspace-root", projection.canonical_bytes.decode("ascii"))

    def test_repeated_public_lock_record_is_deduplicated_and_conflict_is_refused(self):
        _, _, projection, _ = _lock_fixtures()
        repeated = policy.PublicLockProjection.from_records(projection.records + (projection.records[0],))
        self.assertEqual(repeated.records, projection.records)
        cargo = next(record for record in projection.records if record.manager == "cargo")
        conflict = replace(cargo, digest_value="0" * 64)
        with self.assertRaisesRegex(policy.CachePolicyError, "duplicate-lock-conflict"):
            policy.PublicLockProjection.from_records((cargo, conflict))

    def test_record_constructor_cannot_bypass_registry_allowlists(self):
        _, _, projection, _ = _lock_fixtures()
        cargo = next(record for record in projection.records if record.manager == "cargo")
        with self.assertRaisesRegex(policy.CachePolicyError, "registry-not-allowed"):
            policy.PublicLockProjection.from_records((replace(cargo, registry="https://packages.invalid"),))

    def test_unknown_git_or_private_cargo_origin_is_refused(self):
        cargo_lock, npm_lock, _, _ = _lock_fixtures()
        changed = cargo_lock.replace("registry+", "git+")
        with self.assertRaisesRegex(policy.CachePolicyError, "lock-source-type"):
            policy.project_public_locks(changed, npm_lock)

    def test_non_allowlisted_cargo_registry_is_refused(self):
        cargo_lock, npm_lock, _, _ = _lock_fixtures()
        changed = cargo_lock.replace("rust-lang/crates.io-index", "unknown/registry")
        with self.assertRaisesRegex(policy.CachePolicyError, "registry-origin"):
            policy.project_public_locks(changed, npm_lock)

    def test_private_product_package_names_are_never_projected(self):
        cargo_lock, _, _, _ = _lock_fixtures()
        private_crate = "keel" + "dock" + "-private-crate"
        with self.assertRaisesRegex(policy.CachePolicyError, "private-package"):
            policy.project_public_locks(cargo_lock.replace("sample-crate", private_crate))
        private_scope = "@" + "keel" + "dock/"
        private_name = private_scope + "private-package"
        document = {
            "packages": {
                "": {},
                "node_modules/" + private_name: {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/" + private_name + "/-/private-1.0.0.tgz",
                    "integrity": "sha512-" + base64.b64encode(hashlib.sha512(b"private").digest()).decode("ascii"),
                },
            }
        }
        with self.assertRaisesRegex(policy.CachePolicyError, "private-package"):
            policy.project_public_locks(None, json.dumps(document))

    def test_non_allowlisted_and_local_npm_origins_are_refused(self):
        _, npm_lock, _, _ = _lock_fixtures()
        untrusted = npm_lock.replace("registry.npmjs.org", "packages.invalid")
        with self.assertRaisesRegex(policy.CachePolicyError, "registry-not-allowed"):
            policy.project_public_locks(None, untrusted)
        local = npm_lock.replace(
            "https://registry.npmjs.org/sample-npm/-/sample-npm-2.3.4.tgz",
            "file:../sample-npm.tgz",
        )
        with self.assertRaisesRegex(policy.CachePolicyError, "npm-resolved"):
            policy.project_public_locks(None, local)

    def test_weak_or_missing_npm_integrity_is_refused(self):
        _, npm_lock, _, _ = _lock_fixtures()
        weak = npm_lock.replace("sha512-", "sha1-")
        with self.assertRaisesRegex(policy.CachePolicyError, "npm-integrity"):
            policy.project_public_locks(None, weak)

    def test_scoped_npm_package_name_is_projected_without_path_ambiguity(self):
        payload = b"scoped package bytes"
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
        document = {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/@sample/scope": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/@sample/scope/-/scope-1.0.0.tgz",
                    "integrity": integrity,
                },
            },
        }
        projection = policy.project_public_locks(None, json.dumps(document))
        self.assertEqual(projection.records[0].package, "@sample/scope")

    def test_cargo_registry_path_is_not_collapsed_to_its_origin(self):
        cargo_lock, npm_lock, _, _ = _lock_fixtures()
        changed = cargo_lock.replace("crates.io-index", "registry/path")
        with self.assertRaisesRegex(policy.CachePolicyError, "registry-origin"):
            policy.project_public_locks(changed, npm_lock)

    def test_cargo_registry_alias_rejects_unapproved_port(self):
        cargo_lock, npm_lock, _, _ = _lock_fixtures()
        changed = cargo_lock.replace("github.com/", "github.com:444/")
        with self.assertRaisesRegex(policy.CachePolicyError, "origin-port"):
            policy.project_public_locks(changed, npm_lock)
        for suffix in (":", ":0443"):
            with self.subTest(suffix=suffix):
                malformed = cargo_lock.replace("github.com/", "github.com" + suffix + "/")
                with self.assertRaisesRegex(policy.CachePolicyError, "registry-origin"):
                    policy.project_public_locks(malformed, npm_lock)
        approved = cargo_lock.replace("github.com/", "github.com:443/")
        self.assertEqual(policy.project_public_locks(approved, npm_lock).digest,
                         policy.project_public_locks(cargo_lock, npm_lock).digest)

    def test_npm_integrity_algorithms_use_matching_digest_representations(self):
        _, npm_lock, _, _ = _lock_fixtures()
        payload = b"public npm archive"
        for algorithm in ("sha256", "sha384", "sha512"):
            with self.subTest(algorithm=algorithm):
                document = json.loads(npm_lock)
                integrity = algorithm + "-" + base64.b64encode(
                    hashlib.new(algorithm, payload).digest()
                ).decode("ascii")
                document["packages"]["node_modules/sample-npm"]["integrity"] = integrity
                projection = policy.project_public_locks(None, json.dumps(document))
                record = projection.records[0]
                self.assertEqual(record.digest_algorithm, algorithm)
                if algorithm == "sha256":
                    self.assertEqual(record.digest_value, hashlib.sha256(payload).hexdigest())
                archives = (_archive(record, payload),)
                self.assertEqual(set(policy._verify_archives(archives, projection)[0]),
                                 {record.archive_path})
                wrong_algorithm = "sha384" if algorithm == "sha256" else "sha256"
                with self.assertRaisesRegex(policy.CachePolicyError, "archive-digest-algorithm"):
                    policy._verify_archives((replace(archives[0], digest_algorithm=wrong_algorithm),),
                                            projection)
        document = json.loads(npm_lock)
        document["packages"]["node_modules/sample-npm"]["integrity"] = (
            "sha384-" + base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
        )
        with self.assertRaisesRegex(policy.CachePolicyError, "npm-integrity"):
            policy.project_public_locks(None, json.dumps(document))

    def test_projection_record_and_output_limits_choose_cold_without_seed(self):
        cargo_lock, _, _, _ = _lock_fixtures()
        within_bound = policy.decide_public_projection(cargo_lock)
        self.assertTrue(within_bound.seed_allowed)
        self.assertTrue(within_bound.cache_read_allowed)
        self.assertFalse(within_bound.cold_required)
        self.assertIsNotNone(within_bound.projection)
        base = cargo_lock[cargo_lock.index("[[package]]"):]
        records = "".join(base.replace("sample-crate", "p" + str(index).zfill(4) + "x" * 180)
                          for index in range(policy.MAX_PROJECTION_RECORDS))
        decision = policy.decide_public_projection(records)
        self.assertEqual(decision.reason, "projection-output-limit")
        self.assertIsNone(decision.projection)
        self.assertFalse(decision.seed_allowed)
        self.assertFalse(decision.cache_read_allowed)
        self.assertTrue(decision.cold_required)
        overflow = "".join(base.replace("sample-crate", "p" + str(index))
                           for index in range(policy.MAX_PROJECTION_RECORDS + 1))
        self.assertEqual(policy.decide_public_projection(overflow).reason,
                         "projection-record-limit")


class CacheKeyTests(unittest.TestCase):
    def test_key_is_exact_and_binds_every_public_dimension(self):
        _, _, projection, _ = _lock_fixtures()
        key = policy.build_cache_key(SLOT_A, "linux", "x86_64", TOOLS, projection)
        self.assertEqual(key.split("."), [
            policy.SCHEMA,
            SLOT_A,
            "linux",
            "x86_64",
            policy.toolchain_identity_digest(TOOLS),
            projection.digest,
        ])
        self.assertNotIn("a" * 40, key)
        self.assertNotIn(MAIN, key)
        self.assertNotIn("attempt", key)
        self.assertEqual(key, policy.build_cache_key(SLOT_A, "linux", "x86_64", TOOLS, projection))
        self.assertNotEqual(key, policy.build_cache_key(SLOT_B, "linux", "x86_64", TOOLS, projection))
        self.assertNotEqual(key, policy.build_cache_key(SLOT_A, "windows", "x86_64", TOOLS, projection))
        self.assertNotEqual(key, policy.build_cache_key(SLOT_A, "linux", "arm64", TOOLS, projection))
        self.assertNotEqual(key, policy.build_cache_key(SLOT_A, "linux", "x86_64", {"rust": "1.80.2"}, projection))
        self.assertNotEqual(key, policy.build_cache_key(SLOT_A, "linux", "x86_64", TOOLS, projection, "public-v2"))
        changed_lock = "[[package]]\nname = \"changed\"\nversion = \"1.0.0\"\n"
        changed_projection = policy.project_public_locks(changed_lock)
        self.assertNotEqual(key, policy.build_cache_key(SLOT_A, "linux", "x86_64", TOOLS, changed_projection))

    def test_private_names_and_invalid_slots_cannot_become_key_components(self):
        _, _, projection, _ = _lock_fixtures()
        for slot in ("origin-repository-name", "A" * 16, "short"):
            with self.subTest(slot=slot):
                with self.assertRaisesRegex(policy.CachePolicyError, "source-slot"):
                    policy.build_cache_key(slot, "linux", "x86_64", TOOLS, projection)
        for operating_system, architecture, schema, code in (
            ("linux.main", "x86_64", policy.SCHEMA, "operating-system"),
            ("linux", "x86.64", policy.SCHEMA, "architecture"),
            ("linux", "x86_64", "public.v1", "cache-schema"),
        ):
            with self.subTest(os=operating_system, architecture=architecture, schema=schema):
                with self.assertRaises(policy.CachePolicyError) as raised:
                    policy.build_cache_key(SLOT_A, operating_system, architecture, TOOLS, projection, schema)
                self.assertEqual(raised.exception.code, code)


class RestoreVerifierTests(unittest.TestCase):
    def setUp(self):
        _, _, self.projection, self.archives = _lock_fixtures()
        self.expectation = _expectation(self.projection)
        self.entry = _entry(self.projection, self.archives, self.expectation)

    def test_exact_entry_is_digest_checked_copied_and_returned_read_only(self):
        restored = policy.verify_restore(self.entry, self.expectation)
        self.assertEqual(set(restored), {item.path for item in self.archives})
        self.assertTrue(all(type(value) is bytes for value in restored.values()))
        with self.assertRaises(TypeError):
            restored["archives/cargo/extra.archive"] = b"changed"

    def test_key_schema_repository_slot_platform_toolchain_and_lock_mismatches_fail(self):
        cases = (
            (replace(self.entry, key="wrong"), "key-mismatch"),
            (replace(self.entry, schema="other"), "schema-mismatch"),
            (replace(self.entry, repository="other/repository"), "repository-mismatch"),
            (replace(self.entry, source_slot=SLOT_B), "source-slot-mismatch"),
            (replace(self.entry, operating_system="windows"), "operating-system-mismatch"),
            (replace(self.entry, architecture="arm64"), "architecture-mismatch"),
            (replace(self.entry, toolchain_digest="0" * 64), "toolchain-mismatch"),
            (replace(self.entry, projection_digest="0" * 64), "projection-mismatch"),
        )
        for entry, code in cases:
            with self.subTest(code=code):
                with self.assertRaisesRegex(policy.CachePolicyError, code):
                    policy.verify_restore(entry, self.expectation)

    def test_unknown_or_shadowing_provider_scope_fails_closed(self):
        invisible = replace(self.entry, scope="refs/heads/not-visible")
        with self.assertRaisesRegex(policy.CachePolicyError, "scope-not-visible"):
            policy.verify_restore(invisible, self.expectation)
        shadow = replace(self.entry, scope=UNTRUSTED)
        with self.assertRaisesRegex(policy.CachePolicyError, "untrusted-scope"):
            policy.verify_restore(shadow, self.expectation)

    def test_cache_read_confinement_and_protected_root_proofs_gate_restore(self):
        for field in (
            "cache_read_mode_proved",
            "confinement_profile_approved",
            "protected_root_custody_proved",
        ):
            with self.subTest(field=field):
                expectation = replace(self.expectation, **{field: False})
                with self.assertRaisesRegex(policy.CachePolicyError, "restore-authority-unproved"):
                    policy.verify_restore(self.entry, expectation)
                decision = policy.decide_restore(self.entry, expectation)
                self.assertEqual(decision.status, "cold-required")

    def test_changed_archive_bytes_and_wrong_digest_are_refused(self):
        first = self.archives[0]
        changed = replace(first, data=first.data + b"changed")
        entry = _entry(self.projection, (changed,) + self.archives[1:], self.expectation)
        with self.assertRaisesRegex(policy.CachePolicyError, "archive-bytes-digest"):
            policy.verify_restore(entry, self.expectation)
        wrong_claim = replace(first, digest_value="0" * 64)
        entry = _entry(self.projection, (wrong_claim,) + self.archives[1:], self.expectation)
        with self.assertRaisesRegex(policy.CachePolicyError, "archive-digest"):
            policy.verify_restore(entry, self.expectation)

    def test_wrong_registry_origin_and_package_identity_are_refused(self):
        first = self.archives[0]
        cases = (
            (replace(first, origin="https://packages.invalid"), "archive-origin"),
            (replace(first, registry="https://packages.invalid"), "archive-registry"),
            (replace(first, package="unexpected"), "archive-package"),
            (replace(first, manager="unexpected"), "archive-manager"),
        )
        for member, code in cases:
            with self.subTest(code=code):
                entry = _entry(self.projection, (member,) + self.archives[1:], self.expectation)
                with self.assertRaisesRegex(policy.CachePolicyError, code):
                    policy.verify_restore(entry, self.expectation)

    def test_absolute_traversal_duplicate_link_reparse_and_special_paths_fail(self):
        first = self.archives[0]
        paths = (
            ("/absolute", "archive-path-absolute"),
            ("../escape", "archive-path-traversal"),
            ("archives\\escape", "archive-path-backslash"),
            ("archives/cargo/CON.archive", "archive-path-reserved"),
        )
        for path, expected_code in paths:
            with self.subTest(path=path):
                member = replace(first, path=path)
                entry = _entry(self.projection, (member,) + self.archives[1:], self.expectation)
                with self.assertRaises(policy.CachePolicyError) as raised:
                    policy.verify_restore(entry, self.expectation)
                self.assertEqual(raised.exception.code, expected_code)
        for kind in ("symlink", "hardlink", "reparse", "special"):
            with self.subTest(kind=kind):
                member = replace(first, kind=kind)
                entry = _entry(self.projection, (member,) + self.archives[1:], self.expectation)
                with self.assertRaisesRegex(policy.CachePolicyError, "archive-entry-kind"):
                    policy.verify_restore(entry, self.expectation)

    def test_case_equivalent_paths_and_duplicate_manifest_entries_fail(self):
        first = self.archives[0]
        case_twin = replace(first, path=first.path.upper())
        with self.assertRaisesRegex(policy.CachePolicyError, "archive-path-collision"):
            policy.verify_restore(
                _entry(self.projection, (first, case_twin) + self.archives[1:], self.expectation),
                self.expectation,
            )
        with self.assertRaisesRegex(policy.CachePolicyError, "archive-path-collision"):
            policy.verify_restore(
                _entry(self.projection, (first, first) + self.archives[1:], self.expectation),
                self.expectation,
            )

    def test_entry_and_manifest_size_and_file_count_limits_fail(self):
        with self.assertRaisesRegex(policy.CachePolicyError, "entry-size-limit"):
            policy.verify_restore(replace(self.entry, reported_size=policy.ENTRY_LIMIT + 1), self.expectation)
        with self.assertRaises(policy.CachePolicyError) as mismatched:
            policy.verify_restore(replace(self.entry, file_count=len(self.archives) + 1),
                                  self.expectation)
        self.assertEqual(mismatched.exception.code, "entry-file-count")
        too_many = (self.archives[0],) * (policy.MAX_FILES + 1)
        oversized_manifest = replace(
            self.entry, archives=too_many, file_count=len(too_many),
            reported_size=len(too_many) * len(self.archives[0].data),
        )
        with patch.object(policy, "_verify_archives", side_effect=AssertionError("archive fallback reached")):
            with self.assertRaises(policy.CachePolicyError) as declared_limit:
                policy.verify_restore(oversized_manifest, self.expectation)
        self.assertEqual(declared_limit.exception.code, "entry-file-count")
        with self.assertRaises(policy.CachePolicyError) as manifest_limit:
            policy._verify_archives(too_many, self.projection)
        self.assertEqual(manifest_limit.exception.code, "archive-file-count")
        with self.assertRaisesRegex(policy.CachePolicyError, "archive-size-limit"):
            policy._verify_archives(self.archives, self.projection, max_bytes=1)

    def test_staging_bounds_payload_before_hash_and_rejects_compressed_bomb(self):
        first = self.projection.records[0]
        with self.assertRaisesRegex(policy.CachePolicyError, "archive-size-limit"):
            policy.BoundedArchiveStager(max_bytes=1).stage(_claim(first), (b"too large",))
        bomb = zlib.compress(b"x" * 8192)
        with self.assertRaisesRegex(policy.CachePolicyError, "archive-size-limit"):
            policy.BoundedArchiveStager(max_bytes=1024).stage(_claim(first), (bomb,), compression="zlib")
        valid = policy.BoundedArchiveStager().stage(
            _claim(first), (zlib.compress(self.archives[0].data),), compression="zlib"
        )
        self.assertEqual(valid.data, self.archives[0].data)
        limited = policy.BoundedArchiveStager(max_files=1)
        limited.stage(_claim(first), (self.archives[0].data,))
        with self.assertRaisesRegex(policy.CachePolicyError, "staging-file-limit"):
            limited.stage(_claim(first), (self.archives[0].data,))
        with self.assertRaisesRegex(policy.CachePolicyError, "archive-path"):
            policy.BoundedArchiveStager().stage(_claim(first, path="../escape"), (b"payload",))
        with self.assertRaisesRegex(policy.CachePolicyError, "archive-entry-kind"):
            policy.BoundedArchiveStager().stage(_claim(first, kind="symlink"), (b"payload",))
        with self.assertRaisesRegex(policy.CachePolicyError, "resolver-metadata-cached"):
            policy.BoundedArchiveStager().stage(
                _claim(first, payload_class="resolver-metadata"), (b"payload",)
            )
        wrong_origin = policy.BoundedArchiveStager().stage(
            _claim(first, origin="https://packages.invalid"), (self.archives[0].data,)
        )
        with self.assertRaisesRegex(policy.CachePolicyError, "archive-origin"):
            policy.verify_restore(_entry(self.projection, (wrong_origin,) + self.archives[1:]),
                                  self.expectation)
        with self.assertRaisesRegex(policy.CachePolicyError, "archive-not-staged"):
            policy._verify_archives((replace(self.archives[0], staging_token=None),),
                                    self.projection)
        oversized = replace(self.archives[0], data=b"too large")
        with patch.object(policy, "_digest_matches", side_effect=AssertionError("hashed before limit")):
            with self.assertRaisesRegex(policy.CachePolicyError, "archive-size-limit"):
                policy._verify_archives((oversized,), self.projection, max_bytes=1)
            protected = {archive.path: archive.data for archive in self.archives}
            with self.assertRaisesRegex(policy.CachePolicyError, "protected-copy-size-limit"):
                policy._recheck_copy(self.projection, protected, max_bytes=1)

    def test_any_cached_resolver_metadata_is_rejected(self):
        with self.assertRaisesRegex(policy.CachePolicyError, "resolver-metadata-cached"):
            policy.verify_restore(replace(self.entry, resolver_metadata=(b"index",)), self.expectation)
        first = self.archives[0]
        resolver_file = replace(first, payload_class="resolver-metadata")
        with self.assertRaisesRegex(policy.CachePolicyError, "resolver-metadata-cached"):
            policy.verify_restore(
                _entry(self.projection, (resolver_file,) + self.archives[1:], self.expectation),
                self.expectation,
            )

    def test_protected_copy_recheck_rejects_tampering(self):
        restored = dict(policy.verify_restore(self.entry, self.expectation))
        first_path = next(iter(restored))
        restored[first_path] += b"changed after copy"
        with self.assertRaisesRegex(policy.CachePolicyError, "protected-copy-digest"):
            policy.verify_protected_copy(self.projection, restored)

    def test_repeated_corruption_quarantines_and_requests_reviewed_cleanup(self):
        first = policy.record_corrupt_entry(0)
        self.assertFalse(first.cache_usable)
        self.assertFalse(first.quarantine)
        self.assertFalse(first.reviewed_cleanup_request)
        repeated = policy.record_corrupt_entry(first.failures)
        self.assertFalse(repeated.cache_usable)
        self.assertTrue(repeated.quarantine)
        self.assertTrue(repeated.reviewed_cleanup_request)


class ColdFallbackTests(unittest.TestCase):
    def setUp(self):
        _, _, self.projection, self.archives = _lock_fixtures()
        self.expectation = _expectation(self.projection)
        metadata = tuple(
            policy.ResolverMetadata(manager, origin, b"fresh metadata")
            for manager, origin in (
                ("cargo", "https://index.crates.io"),
                ("npm", "https://registry.npmjs.org"),
            )
        )
        self.cold = policy.ColdPreparation(self.archives, metadata, True, True)

    def test_verified_hit_requires_fresh_allowlisted_resolver_preparation(self):
        entry = _entry(self.projection, self.archives, self.expectation)
        missing = policy.decide_restore(entry, self.expectation)
        self.assertEqual((missing.status, missing.reason),
                         ("cold-required", "resolver-preparation-missing"))
        self.assertFalse(missing.verified)
        fresh = policy.FreshResolverPreparation(self.cold.resolver_metadata, True, True)
        hit = policy.decide_restore(entry, self.expectation, resolver_preparation=fresh)
        self.assertEqual((hit.status, hit.reason), ("cache", "verified-hit"))
        self.assertTrue(hit.verified)
        self.assertEqual(hit.resolver_metadata, fresh.resolver_metadata)
        supplied_cold = policy.decide_restore(entry, self.expectation, self.cold)
        self.assertEqual(supplied_cold.status, "cache")
        self.assertEqual(supplied_cold.resolver_metadata, self.cold.resolver_metadata)
        without_metadata = replace(fresh, resolver_metadata=())
        rejected = policy.decide_restore(entry, self.expectation,
                                         resolver_preparation=without_metadata)
        self.assertEqual((rejected.status, rejected.reason),
                         ("cold-required", "resolver-metadata-missing"))
        cached = replace(fresh.resolver_metadata[0], from_cache=True)
        with_cached = replace(fresh, resolver_metadata=(cached, fresh.resolver_metadata[1]))
        rejected = policy.decide_restore(entry, self.expectation, resolver_preparation=with_cached)
        self.assertEqual((rejected.status, rejected.reason),
                         ("cold-required", "resolver-metadata-cached"))
        wrong_origin = replace(fresh.resolver_metadata[0], origin="https://packages.invalid")
        with_wrong_origin = replace(fresh, resolver_metadata=(wrong_origin, fresh.resolver_metadata[1]))
        rejected = policy.decide_restore(entry, self.expectation,
                                         resolver_preparation=with_wrong_origin)
        self.assertEqual((rejected.status, rejected.reason),
                         ("cold-required", "resolver-origin"))
        crossed = replace(fresh.resolver_metadata[0], origin="https://registry.npmjs.org")
        with_crossed_origin = replace(fresh, resolver_metadata=(crossed, fresh.resolver_metadata[1]))
        rejected = policy.decide_restore(entry, self.expectation,
                                         resolver_preparation=with_crossed_origin)
        self.assertEqual((rejected.status, rejected.reason),
                         ("cold-required", "resolver-origin"))
        not_ready = replace(fresh, offline_ready=False)
        rejected = policy.decide_restore(entry, self.expectation, resolver_preparation=not_ready)
        self.assertEqual((rejected.status, rejected.reason),
                         ("cold-required", "resolver-setup-incomplete"))
        fallback = policy.decide_restore(entry, self.expectation, self.cold,
                                         resolver_preparation=with_cached)
        self.assertEqual(fallback.status, "cold")
        self.assertTrue(fallback.verified)

    def test_shadowed_or_missing_cache_uses_verified_cold_archives_and_fresh_metadata(self):
        _, _, projection, _ = _lock_fixtures()
        entry = _entry(projection, self.archives, self.expectation, scope=UNTRUSTED)
        decision = policy.decide_restore(entry, self.expectation, self.cold)
        self.assertEqual((decision.status, decision.reason), ("cold", "untrusted-scope"))
        self.assertFalse(decision.cache_hit)
        self.assertTrue(decision.verified)
        self.assertEqual(len(decision.resolver_metadata), 2)
        missing = policy.decide_restore(None, self.expectation, self.cold)
        self.assertEqual((missing.status, missing.reason), ("cold", "cache-miss"))

    def test_cold_path_requires_all_archives_fresh_resolver_data_and_offline_readiness(self):
        no_resolver = replace(self.cold, resolver_metadata=())
        self.assertEqual(policy.decide_restore(None, self.expectation, no_resolver).status, "fail")
        cached = replace(self.cold.resolver_metadata[0], from_cache=True)
        bad_source = replace(self.cold, resolver_metadata=(cached, self.cold.resolver_metadata[1]))
        self.assertEqual(policy.decide_restore(None, self.expectation, bad_source).status, "fail")
        bad_origin = replace(self.cold.resolver_metadata[0], origin="https://packages.invalid")
        bad_source = replace(self.cold, resolver_metadata=(bad_origin, self.cold.resolver_metadata[1]))
        self.assertEqual(policy.decide_restore(None, self.expectation, bad_source).status, "fail")
        unverified = replace(self.cold, trusted_setup_complete=False)
        self.assertEqual(policy.decide_restore(None, self.expectation, unverified).status, "fail")
        changed = replace(self.archives[0], data=b"changed")
        bad_archive = replace(self.cold, archives=(changed,) + self.archives[1:])
        self.assertEqual(policy.decide_restore(None, self.expectation, bad_archive).status, "fail")

    def test_invalid_cache_without_a_verified_cold_input_is_cold_required(self):
        entry = _entry(self.projection, self.archives, self.expectation, key="wrong")
        decision = policy.decide_restore(entry, self.expectation)
        self.assertEqual((decision.status, decision.reason), ("cold-required", "key-mismatch"))
        self.assertFalse(decision.verified)

    def test_skipped_capacity_admission_leaves_a_verified_cold_run(self):
        skipped = policy.admit_save(
            _inventory(complete=False),
            (SLOT_A, SLOT_B),
            SLOT_A,
            "linux",
            "x86_64",
            "not-saved",
            100,
            True,
            True,
        )
        self.assertFalse(skipped.admitted)
        decision = policy.decide_restore(None, self.expectation, self.cold)
        self.assertEqual(decision.status, "cold")
        self.assertTrue(decision.verified)


class ProviderScopeTests(unittest.TestCase):
    def test_main_and_untrusted_lookup_order_is_exact(self):
        main = policy.ScopeContext("origin", MAIN, MAIN)
        untrusted = policy.ScopeContext("origin", UNTRUSTED, MAIN)
        self.assertEqual(policy.provider_lookup_scopes(main), (MAIN,))
        self.assertEqual(policy.provider_lookup_scopes(untrusted), (UNTRUSTED, MAIN))

    def test_pull_request_can_read_base_cache_but_writes_stay_on_merge_ref(self):
        merge = "refs/pull/17/merge"
        pull = policy.ScopeContext("origin", merge, MAIN, merge, MAIN)
        self.assertEqual(policy.provider_lookup_scopes(pull), (merge, MAIN))
        self.assertEqual(policy.provider_write_scope(pull), merge)
        self.assertNotEqual(policy.provider_write_scope(pull), MAIN)

    def test_fork_repository_uses_its_own_cache_namespace(self):
        origin = policy.ScopeContext("origin", UNTRUSTED, MAIN)
        fork = policy.ScopeContext("fork-owner/project", UNTRUSTED, MAIN, independent_fork=True)
        self.assertEqual(policy.provider_lookup_scopes(origin), (UNTRUSTED, MAIN))
        self.assertEqual(
            policy.provider_lookup_scopes(fork),
            ("fork-owner/project:" + UNTRUSTED, "fork-owner/project:" + MAIN),
        )
        self.assertNotEqual(policy.provider_write_scope(origin), policy.provider_write_scope(fork))

    def test_dispatch_requires_origin_repository_and_allowed_control_ref(self):
        allowed = (MAIN, UNTRUSTED)
        self.assertTrue(policy.validate_dispatch_origin(REPOSITORY, REPOSITORY, MAIN, allowed))
        self.assertFalse(policy.validate_dispatch_origin(REPOSITORY, "fork/project", MAIN, allowed))
        self.assertFalse(policy.validate_dispatch_origin(REPOSITORY, REPOSITORY, "refs/heads/other", allowed))

    def test_dispatch_is_once_per_sha_unless_reasoned_and_has_one_slow_watcher(self):
        source_sha = "a" * 40
        self.assertTrue(policy.validate_dispatch_attempt(source_sha, (), False, 1, 300))
        self.assertFalse(policy.validate_dispatch_attempt(source_sha, (source_sha,), False, 1, 300))
        self.assertTrue(policy.validate_dispatch_attempt(source_sha, (source_sha,), True, 1, 300))
        self.assertFalse(policy.validate_dispatch_attempt(source_sha, (), False, 2, 300))
        self.assertFalse(policy.validate_dispatch_attempt(source_sha, (), False, 1, 299))


class JobAuthorityTests(unittest.TestCase):
    def test_projection_seed_worker_and_cleaner_capabilities_are_separate(self):
        self.assertTrue(policy.authorize_job_action("projection", MAIN, "source_read"))
        self.assertFalse(policy.authorize_job_action("projection", MAIN, "cache_restore"))
        self.assertFalse(policy.authorize_job_action("projection", MAIN, "candidate_execute"))
        self.assertTrue(policy.authorize_job_action("seed", MAIN, "cache_save"))
        self.assertTrue(policy.authorize_job_action("seed", MAIN, "cache_reserve"))
        self.assertFalse(policy.authorize_job_action("seed", MAIN, "source_read"))
        self.assertFalse(policy.authorize_job_action("seed", MAIN, "candidate_execute"))
        self.assertFalse(policy.authorize_job_action("seed", UNTRUSTED, "cache_save"))
        self.assertTrue(policy.authorize_job_action("worker", UNTRUSTED, "cache_restore"))
        self.assertTrue(policy.authorize_job_action("worker", MAIN, "candidate_execute"))
        self.assertFalse(policy.authorize_job_action("worker", UNTRUSTED, "cache_save"))
        self.assertFalse(policy.authorize_job_action("worker", UNTRUSTED, "cache_delete"))
        self.assertFalse(policy.authorize_job_action("worker", UNTRUSTED, "post_job_save"))
        self.assertTrue(policy.authorize_job_action("cleaner", MAIN, "cache_delete"))
        self.assertFalse(policy.authorize_job_action("cleaner", MAIN, "cache_restore"))
        self.assertFalse(policy.authorize_job_action("cleaner", MAIN, "candidate_execute"))

    def test_project_process_cannot_use_job_scoped_cache_or_api_authority(self):
        for action in (
            "cache_restore", "cache_save", "cache_reserve", "cache_delete", "post_job_save",
            "actions_api_delete", "source_read", "github_token",
        ):
            with self.subTest(action=action):
                self.assertFalse(policy.authorize_job_action("worker", MAIN, action, candidate_process=True))

    def test_cleaner_is_source_free_and_has_only_repository_actions_write(self):
        self.assertTrue(policy.validate_cleaner_authority(
            MAIN, "repository", "write", "none", False, False, False
        ))
        self.assertFalse(policy.validate_cleaner_authority(
            MAIN, "organization", "write", "none", False, False, False
        ))
        self.assertFalse(policy.validate_cleaner_authority(
            MAIN, "repository", "read", "none", False, False, False
        ))
        self.assertFalse(policy.validate_cleaner_authority(
            MAIN, "repository", "write", "read", False, False, False
        ))
        self.assertFalse(policy.validate_cleaner_authority(
            MAIN, "repository", "write", "none", True, False, False
        ))
        self.assertFalse(policy.validate_cleaner_authority(
            MAIN, "repository", "write", "none", False, True, False
        ))
        self.assertFalse(policy.validate_cleaner_authority(
            MAIN, "repository", "write", "none", False, False, True
        ))


class ConfinementGateTests(unittest.TestCase):
    def _evidence(self, operating_system="linux", profiles=None):
        return policy.ConfinementEvidence(
            operating_system,
            tuple((operating_system,) if profiles is None else profiles),
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
        )

    def test_whole_candidate_invocation_needs_an_approved_profile_and_every_boundary(self):
        for command in policy.EXECUTION_CLASSES:
            with self.subTest(command=command):
                self.assertTrue(policy.candidate_execution_admitted(command, self._evidence()))
        evidence = self._evidence("macos", ("linux", "windows"))
        self.assertFalse(policy.candidate_execution_admitted("generator", evidence))
        for field in (
            "whole_invocation_covered",
            "network_denied",
            "secret_access_denied",
            "output_bounded",
            "workflow_commands_blocked",
            "runner_paths_blocked",
            "cache_api_blocked",
            "process_tree_contained",
        ):
            with self.subTest(field=field):
                self.assertFalse(policy.candidate_execution_admitted(
                    "cargo-startup", replace(self._evidence(), **{field: False})
                ))

    def test_every_attack_class_is_denied_when_its_control_is_missing(self):
        controls = {
            "network": "network_denied",
            "private-canary-output": "secret_access_denied",
            "workflow-command": "workflow_commands_blocked",
            "runner-summary-output-artifact": "runner_paths_blocked",
            "cache-api": "cache_api_blocked",
            "survivor-process": "process_tree_contained",
        }
        for command in policy.EXECUTION_CLASSES:
            for attempt in policy.CONFINEMENT_ATTEMPTS:
                with self.subTest(command=command, attempt=attempt):
                    evidence = replace(self._evidence(), **{controls[attempt]: False})
                    self.assertFalse(policy.candidate_execution_admitted(command, evidence))

    def test_command_class_and_operating_system_are_bounded(self):
        with self.assertRaisesRegex(policy.CachePolicyError, "candidate-command-class"):
            policy.candidate_execution_admitted("unlisted-command", self._evidence())
        with self.assertRaisesRegex(policy.CachePolicyError, "confinement-os"):
            policy.candidate_execution_admitted("generator", self._evidence("other-os"))


class OverlayCustodyTests(unittest.TestCase):
    def _evidence(self, **changes):
        vendor = (policy.TreeEntry("vendor/cargo/sample/lib.rs", b"trusted bytes", "file", 420),)
        values = {
            "trusted_vendor": vendor,
            "staged_vendor": vendor,
            "promoted_vendor": vendor,
            "expected_pin_sha": "a" * 40,
            "actual_pin_sha": "a" * 40,
            "expected_patches": (("sample", "vendor/cargo/sample"),),
            "staged_patches": (("sample", "vendor/cargo/sample"),),
            "expected_file_overrides": (("sample-npm", "vendor/npm/sample-npm"),),
            "staged_file_overrides": (("sample-npm", "vendor/npm/sample-npm"),),
            "expected_lock_sources": (("sample", "registry+https://index.crates.io"),),
            "staged_lock_sources": (("sample", "registry+https://index.crates.io"),),
            "stable_during_hashing": True,
            "protected_after_promotion": True,
            "alternate_configuration_sources": False,
        }
        values.update(changes)
        return policy.OverlayEvidence(**values)

    def test_actual_staged_and_promoted_vendor_hashes_match_trusted_checkout(self):
        result = policy.validate_overlay(self._evidence())
        self.assertEqual(result["trusted_tree_digest"], result["staged_tree_digest"])
        self.assertEqual(result["staged_tree_digest"], result["promoted_tree_digest"])

    def test_altered_vendor_bytes_with_unchanged_pin_and_wrong_trusted_tree_fail(self):
        changed = (policy.TreeEntry("vendor/cargo/sample/lib.rs", b"altered bytes", "file", 420),)
        with self.assertRaisesRegex(policy.CachePolicyError, "staged-vendor-mismatch"):
            policy.validate_overlay(self._evidence(staged_vendor=changed))
        with self.assertRaisesRegex(policy.CachePolicyError, "pin-identity"):
            policy.validate_overlay(self._evidence(actual_pin_sha="b" * 40))
        wrong_trusted = (policy.TreeEntry("vendor/cargo/sample/lib.rs", b"wrong checkout", "file", 420),)
        with self.assertRaisesRegex(policy.CachePolicyError, "staged-vendor-mismatch"):
            policy.validate_overlay(self._evidence(trusted_vendor=wrong_trusted))

    def test_missing_duplicate_or_external_overrides_fail(self):
        with self.assertRaisesRegex(policy.CachePolicyError, "patch-manifest"):
            policy.validate_overlay(self._evidence(staged_patches=()))
        with self.assertRaisesRegex(policy.CachePolicyError, "patch-path-duplicate"):
            policy.validate_overlay(self._evidence(
                staged_patches=(("sample", "vendor/cargo/sample"), ("sample", "vendor/cargo/sample"))
            ))
        with self.assertRaisesRegex(policy.CachePolicyError, "file-override-manifest"):
            policy.validate_overlay(self._evidence(staged_file_overrides=()))
        with self.assertRaisesRegex(policy.CachePolicyError, "archive-path"):
            policy.validate_overlay(self._evidence(
                expected_patches=(("sample", "../../outside"),),
                staged_patches=(("sample", "../../outside"),),
            ))

    def test_lock_mismatch_case_collision_and_hash_race_fail(self):
        with self.assertRaisesRegex(policy.CachePolicyError, "lock-source-mismatch"):
            policy.validate_overlay(self._evidence(staged_lock_sources=(("sample", "path:vendor/other"),)))
        collision = (
            policy.TreeEntry("vendor/pkg/A", b"one"),
            policy.TreeEntry("vendor/pkg/a", b"two"),
        )
        with self.assertRaisesRegex(policy.CachePolicyError, "tree-path-collision"):
            policy.validate_overlay(self._evidence(trusted_vendor=collision, staged_vendor=collision,
                                                   promoted_vendor=collision))
        with self.assertRaisesRegex(policy.CachePolicyError, "tree-mutated-during-hash"):
            policy.validate_overlay(self._evidence(stable_during_hashing=False))

    def test_post_verification_mutation_and_alternate_configuration_fail(self):
        changed = (policy.TreeEntry("vendor/cargo/sample/lib.rs", b"changed", "file", 420),)
        with self.assertRaisesRegex(policy.CachePolicyError, "promoted-vendor-mismatch"):
            policy.validate_overlay(self._evidence(promoted_vendor=changed))
        with self.assertRaisesRegex(policy.CachePolicyError, "promoted-vendor-mutable"):
            policy.validate_overlay(self._evidence(protected_after_promotion=False))
        with self.assertRaisesRegex(policy.CachePolicyError, "alternate-configuration"):
            policy.validate_overlay(self._evidence(alternate_configuration_sources=True))
        for path in ("vendor", "pin", "lock", "config"):
            with self.subTest(path=path):
                denied = self._evidence(mutation_attempts=(path,), blocked_mutations=(path,))
                self.assertTrue(policy.validate_overlay(denied))
                allowed = self._evidence(mutation_attempts=(path,), blocked_mutations=())
                with self.assertRaisesRegex(policy.CachePolicyError, "promoted-mutation-allowed"):
                    policy.validate_overlay(allowed)

    def test_non_file_vendor_entries_and_invalid_modes_fail(self):
        for entry, code in (
            (policy.TreeEntry("vendor/pkg/link", b"target", "symlink", 511), "tree-entry-kind"),
            (policy.TreeEntry("vendor/pkg/file", b"value", "file", 8192), "tree-entry-mode"),
            (policy.TreeEntry("external/pkg/file", b"value"), "tree-path-external"),
        ):
            with self.subTest(code=code):
                tree = (entry,)
                evidence = self._evidence(trusted_vendor=tree, staged_vendor=tree, promoted_vendor=tree)
                with self.assertRaisesRegex(policy.CachePolicyError, code):
                    policy.validate_overlay(evidence)


def _cache_record(cache_id, source_slot=SLOT_A, key=None, os_name="linux", architecture="x86_64",
                  projection="a" * 64, size=1, last_access=1, scope=MAIN):
    return policy.CacheRecord(
        cache_id,
        source_slot,
        key or "key-" + cache_id,
        os_name,
        architecture,
        projection,
        size,
        last_access,
        scope,
    )


def _inventory(entries=(), complete=True, requests=1, fresh=True):
    return policy.CacheInventory(tuple(entries), complete, requests, fresh)


class CapacityAdmissionTests(unittest.TestCase):
    def test_repository_entry_idle_and_source_limits_use_fixed_bytes(self):
        self.assertEqual(policy.REPOSITORY_LIMIT, 3 * 1024 * 1024 * 1024)
        self.assertEqual(policy.ENTRY_LIMIT, 512 * 1024 * 1024)
        self.assertEqual(policy.IDLE_RETIREMENT_SECONDS, 14 * 24 * 60 * 60)
        self.assertEqual(policy._source_limit(2), 1024 * 1024 * 1024)
        self.assertEqual(policy._source_limit(4), (3 * 1024 * 1024 * 1024) // 4)
        self.assertEqual(policy._source_limit(8), (3 * 1024 * 1024 * 1024) // 8)

    def test_reservation_admits_only_proved_bounded_capacity(self):
        slots = (SLOT_A, SLOT_B)
        decision = policy.admit_save(
            _inventory(), slots, SLOT_A, "linux", "x86_64", "new-key", 100,
            True, True,
        )
        self.assertTrue(decision.admitted)
        self.assertEqual(decision.reason, "reserved")
        self.assertEqual(decision.reservation_bytes, 100)
        self.assertEqual(decision.concurrency_group, policy.CONCURRENCY_GROUP)
        self.assertFalse(decision.cancel_in_progress)

    def test_unproved_unknown_oversized_or_nonpositive_reservations_skip(self):
        slots = (SLOT_A, SLOT_B)
        cases = (
            (_inventory(complete=False), slots, SLOT_A, 100, True, True, "inventory-incomplete"),
            (_inventory(fresh=False), slots, SLOT_A, 100, True, True, "inventory-stale"),
            (_inventory(), slots, SLOT_A, 100, False, True, "reservation-unproved"),
            (_inventory(), slots, SLOT_A, 100, True, False, "reservation-unproved"),
            (_inventory(), slots, "unknown-source-slot", 100, True, True, "source-slot-unknown"),
            (_inventory(), slots, SLOT_A, 0, True, True, "reservation-invalid"),
            (_inventory(), slots, SLOT_A, policy.ENTRY_LIMIT + 1, True, True, "entry-limit"),
        )
        for inventory, source_slots, slot, amount, proven, overhead, reason in cases:
            with self.subTest(reason=reason):
                decision = policy.admit_save(
                    inventory, source_slots, slot, "linux", "x86_64", "new-key", amount,
                    proven, overhead,
                )
                self.assertFalse(decision.admitted)
                self.assertEqual(decision.reason, reason)

    def test_cleanup_backlog_and_concurrent_maintenance_skip_seed(self):
        slots = (SLOT_A, SLOT_B)
        for backlog, concurrent, expected in ((True, False, "cleanup-backlog"),
                                              (False, True, "maintenance-concurrent")):
            with self.subTest(expected=expected):
                decision = policy.admit_save(
                    _inventory(), slots, SLOT_A, "linux", "x86_64", "new-key", 10,
                    True, True, cleanup_backlog=backlog, maintenance_in_progress=concurrent,
                )
                self.assertFalse(decision.admitted)
                self.assertEqual(decision.reason, expected)

    def test_source_and_repository_caps_count_each_scope_entry_in_full(self):
        slots = (SLOT_A, SLOT_B, "cdefghijklmnopqr", "defghijklmnopqrs")
        under_source = _inventory((_cache_record("source-use", SLOT_A, size=700 * 1024 * 1024),))
        source_decision = policy.admit_save(
            under_source, slots, SLOT_A, "linux", "x86_64", "new-key", 100 * 1024 * 1024,
            True, True,
        )
        self.assertEqual(source_decision.reason, "source-capacity")

        entries = tuple(
            _cache_record("existing-" + str(index), slots[index], key="identical-content",
                          size=1024 * 1024 * 1024)
            for index in range(4)
        )
        repository_decision = policy.admit_save(
            _inventory(entries), slots, SLOT_A, "windows", "arm64", "new-key", 1, True, True,
        )
        self.assertEqual(repository_decision.reason, "repository-capacity")

    def test_partition_key_limit_and_existing_key_do_not_reserve_again(self):
        entries = (
            _cache_record("one", key="one"),
            _cache_record("two", key="two"),
        )
        limited = policy.admit_save(
            _inventory(entries), (SLOT_A, SLOT_B), SLOT_A, "linux", "x86_64", "three", 1, True, True,
        )
        self.assertEqual(limited.reason, "partition-key-limit")
        existing = policy.admit_save(
            _inventory((entries[0],)), (SLOT_A, SLOT_B), SLOT_A, "linux", "x86_64", "one", 1,
            True, True,
        )
        self.assertEqual(existing.reason, "already-present")

    def test_provider_size_over_reservation_freezes_future_saves(self):
        within = policy.reconcile_save(100, 100)
        self.assertFalse(within.freeze_saves)
        exceeded = policy.reconcile_save(100, 101)
        self.assertTrue(exceeded.freeze_saves)
        self.assertEqual(exceeded.reason, "reservation-exceeded")
        oversize = policy.reconcile_save(policy.ENTRY_LIMIT + 5, policy.ENTRY_LIMIT + 5)
        self.assertTrue(oversize.freeze_saves)
        existing = _cache_record("oversized", size=policy.ENTRY_LIMIT + 1)
        admission = policy.admit_save(
            _inventory((existing,)), (SLOT_A, SLOT_B), SLOT_B, "linux", "x86_64",
            "new-key", 1, True, True,
        )
        self.assertEqual(admission.reason, "entry-over-limit-inventory")


class CleanupPlannerTests(unittest.TestCase):
    def test_retired_superseded_and_fourteen_day_idle_entries_are_candidates(self):
        now = 50_000_000
        entries = (
            _cache_record("orphan", SLOT_B, last_access=now - 1),
            _cache_record("old-projection", SLOT_A, projection="b" * 64, last_access=now - 2),
            _cache_record("idle", SLOT_A, projection="a" * 64,
                          last_access=now - policy.IDLE_RETIREMENT_SECONDS),
            _cache_record("warm", SLOT_A, projection="a" * 64, last_access=now - 10),
        )
        plan = policy.plan_cleanup(
            _inventory(entries), now, (SLOT_A,), {(SLOT_A, "linux", "x86_64"): "a" * 64}
        )
        reasons = dict(plan.deletions)
        self.assertEqual(reasons, {
            "orphan": "orphaned-source",
            "old-projection": "superseded",
            "idle": "idle",
        })
        self.assertNotIn("warm", reasons)
        self.assertFalse(plan.backlog)

    def test_unexpected_branch_shadow_is_a_cleanup_candidate(self):
        now = 55_000_000
        shadow = _cache_record("shadow", scope=UNTRUSTED, last_access=now - 1)
        plan = policy.plan_cleanup(
            _inventory((shadow,)), now, (SLOT_A,),
            {(SLOT_A, "linux", "x86_64"): "a" * 64},
        )
        self.assertEqual(plan.deletions, (("shadow", "non-main-scope"),))

    def test_cleanup_never_exceeds_twenty_five_requests_and_reports_backlog(self):
        now = 60_000_000
        entries = tuple(
            _cache_record("idle-" + str(index), last_access=now - policy.IDLE_RETIREMENT_SECONDS)
            for index in range(30)
        )
        plan = policy.plan_cleanup(
            _inventory(entries, requests=1), now, (SLOT_A,),
            {(SLOT_A, "linux", "x86_64"): "a" * 64},
        )
        self.assertEqual(plan.requests_used, 25)
        self.assertEqual(len(plan.deletions), 24)
        self.assertTrue(plan.backlog)

    def test_incomplete_inventory_and_list_request_exhaustion_delete_nothing(self):
        now = 70_000_000
        old = _cache_record("old", last_access=now - policy.IDLE_RETIREMENT_SECONDS)
        incomplete = policy.plan_cleanup(
            _inventory((old,), complete=False), now, (SLOT_A,), {}
        )
        self.assertEqual(incomplete.deletions, ())
        self.assertTrue(incomplete.backlog)
        stale = policy.plan_cleanup(
            _inventory((old,), fresh=False), now, (SLOT_A,), {}
        )
        self.assertEqual(stale.deletions, ())
        self.assertTrue(stale.backlog)
        exhausted = policy.plan_cleanup(
            _inventory((old,), requests=25), now, (SLOT_A,), {}, request_limit=25
        )
        self.assertEqual(exhausted.deletions, ())
        self.assertTrue(exhausted.backlog)

    def test_repository_source_and_partition_budgets_select_cleanup_victims(self):
        now = 80_000_000
        slots = (SLOT_A, SLOT_B)
        duplicate_payload_entries = tuple(
            _cache_record("source-" + slot_name + "-" + str(index), slot,
                          key="same-archive-" + str(index), size=400 * 1024 * 1024,
                          last_access=now - 1)
            for slot_name, slot in (("a", SLOT_A), ("b", SLOT_B)) for index in range(3)
        )
        plan = policy.plan_cleanup(
            _inventory(duplicate_payload_entries), now, slots, {},
        )
        self.assertEqual(len(plan.deletions), 2)
        self.assertEqual({reason for _, reason in plan.deletions}, {"source-over-budget"})

        partition_entries = tuple(
            _cache_record("key-" + str(index), key="key-" + str(index), last_access=now - 1)
            for index in range(3)
        )
        partition_plan = policy.plan_cleanup(
            _inventory(partition_entries), now, slots, {},
        )
        self.assertIn(("key-0", "partition-over-limit"), partition_plan.deletions)

    def test_entry_above_ceiling_is_retired_even_when_recent_and_under_source_budget(self):
        now = 81_000_000
        oversized = _cache_record("oversized", size=policy.ENTRY_LIMIT + 1,
                                  last_access=now - 1)
        plan = policy.plan_cleanup(_inventory((oversized,)), now, (SLOT_A,), {})
        self.assertEqual(plan.deletions, (("oversized", "entry-over-limit"),))

    def test_cleaner_is_source_free_serialized_and_endpoint_limited(self):
        plan = policy.plan_cleanup(_inventory(), 1, (SLOT_A,), {})
        self.assertEqual(plan.concurrency_group, policy.CONCURRENCY_GROUP)
        self.assertFalse(plan.cancel_in_progress)
        self.assertEqual(plan.cache_mode, "none")
        self.assertFalse(plan.source_read)
        self.assertFalse(plan.candidate_execution)
        self.assertEqual(plan.actions_permission, "write")
        self.assertEqual(plan.allowed_operations, (
            policy.CACHE_LIST_ENDPOINT,
            policy.CACHE_DELETE_ENDPOINT,
        ))

    def test_rate_limit_forbidden_differs_from_permission_forbidden(self):
        self.assertEqual(policy.classify_api_failure(403, {
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": "2000000000",
        }), "wait-until-reset")
        self.assertEqual(policy.classify_api_failure(403, {"X-RateLimit-Remaining": "7"}),
                         "authorization-defect")
        self.assertEqual(policy.classify_api_failure(404, {}), "not-rate-limit-403")


class ColdWarmComparisonTests(unittest.TestCase):
    def test_output_must_match_and_runner_costs_are_reported(self):
        same = "a" * 64
        result = policy.compare_cold_warm(same, same, 100.0, 50.0, 4.0, 2.0)
        self.assertTrue(result.output_equal)
        self.assertEqual(result.cold_runner_minutes, 4.0)
        different = policy.compare_cold_warm(same, "b" * 64, 100.0, 50.0, 4.0, 2.0)
        self.assertFalse(different.output_equal)
        with self.assertRaisesRegex(policy.CachePolicyError, "performance-metrics"):
            policy.compare_cold_warm(same, same, -1, 1, 1, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

