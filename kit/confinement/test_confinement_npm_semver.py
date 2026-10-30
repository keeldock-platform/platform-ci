import unittest

import npm_semver as subject


class VersionTests(unittest.TestCase):
    def test_parse_version_reads_core_prerelease_and_ignores_build(self):
        self.assertEqual(subject.parse_version("1.2.3"), (1, 2, 3, ()))
        self.assertEqual(subject.parse_version("v1.2.3"), (1, 2, 3, ()))
        self.assertEqual(subject.parse_version("1.2.3-beta.4"), (1, 2, 3, ("beta", 4)))
        self.assertEqual(subject.parse_version("1.2.3+build.7"), (1, 2, 3, ()))

    def test_parse_version_refuses_everything_that_is_not_an_exact_version(self):
        for value in (
            "", "1", "1.2", "1.2.x", "01.2.3", "1.02.3", "1.2.03", "1.2.3-", "1.2.3-01",
            "1.2.3-be ta", "^1.2.3", ">=1.2.3", "1.2.3 ", None, 1, ("1.2.3",), "9" * 20 + ".0.0",
        ):
            with self.subTest(value=value):
                with self.assertRaises(subject.SemverError):
                    subject.parse_version(value)

    def test_ordering_follows_the_semver_precedence_rules(self):
        ordered = [
            "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
            "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0",
        ]
        parsed = [subject.parse_version(item) for item in ordered]
        for index in range(len(parsed) - 1):
            with self.subTest(low=ordered[index], high=ordered[index + 1]):
                self.assertEqual(subject.compare_versions(parsed[index], parsed[index + 1]), -1)
                self.assertEqual(subject.compare_versions(parsed[index + 1], parsed[index]), 1)
                self.assertEqual(subject.compare_versions(parsed[index], parsed[index]), 0)


class RangeTests(unittest.TestCase):
    def assert_satisfies(self, version, text, expected=True):
        with self.subTest(version=version, range=text):
            self.assertIs(subject.satisfies(version, text), expected)

    def test_exact_and_comparator_ranges(self):
        self.assert_satisfies("1.2.3", "1.2.3")
        self.assert_satisfies("1.2.3", "=1.2.3")
        self.assert_satisfies("1.2.4", "1.2.3", False)
        self.assert_satisfies("1.2.3", ">=1.2.3")
        self.assert_satisfies("1.2.2", ">=1.2.3", False)
        self.assert_satisfies("1.2.3", ">1.2.3", False)
        self.assert_satisfies("1.2.4", ">1.2.3")
        self.assert_satisfies("1.2.3", "<=1.2.3")
        self.assert_satisfies("1.2.3", "<1.2.3", False)
        self.assert_satisfies("1.2.2", "<1.2.3")
        self.assert_satisfies("1.5.0", ">= 1.2.3 < 2.0.0")
        self.assert_satisfies("2.0.0", ">= 1.2.3 < 2.0.0", False)

    def test_caret_ranges(self):
        self.assert_satisfies("1.2.3", "^1.2.3")
        self.assert_satisfies("1.9.9", "^1.2.3")
        self.assert_satisfies("2.0.0", "^1.2.3", False)
        self.assert_satisfies("1.2.2", "^1.2.3", False)
        self.assert_satisfies("0.2.9", "^0.2.3")
        self.assert_satisfies("0.3.0", "^0.2.3", False)
        self.assert_satisfies("0.0.3", "^0.0.3")
        self.assert_satisfies("0.0.4", "^0.0.3", False)
        self.assert_satisfies("1.9.0", "^1.2")
        self.assert_satisfies("2.0.0", "^1", False)
        self.assert_satisfies("0.9.0", "^0")
        self.assert_satisfies("0.0.9", "^0.0")
        self.assert_satisfies("0.1.0", "^0.0", False)

    def test_tilde_ranges(self):
        self.assert_satisfies("1.2.9", "~1.2.3")
        self.assert_satisfies("1.3.0", "~1.2.3", False)
        self.assert_satisfies("1.2.0", "~1.2")
        self.assert_satisfies("1.9.0", "~1")
        self.assert_satisfies("2.0.0", "~1", False)
        self.assert_satisfies("1.2.5", "~>1.2.3")

    def test_x_ranges_partial_versions_and_wildcards(self):
        self.assert_satisfies("1.2.3", "*")
        self.assert_satisfies("0.0.0", "")
        self.assert_satisfies("1.2.3", "x")
        self.assert_satisfies("1.5.0", "1.x")
        self.assert_satisfies("2.0.0", "1.x", False)
        self.assert_satisfies("1.2.9", "1.2.*")
        self.assert_satisfies("1.3.0", "1.2.*", False)
        self.assert_satisfies("1.2.0", "1.2")
        self.assert_satisfies("1.3.0", ">1.2")
        self.assert_satisfies("1.2.9", ">1.2", False)
        self.assert_satisfies("2.0.0", ">1")
        self.assert_satisfies("1.9.9", ">1", False)
        self.assert_satisfies("1.9.9", "<=1")
        self.assert_satisfies("2.0.0", "<=1", False)
        self.assert_satisfies("1.3.0", "<=1.2", False)
        self.assert_satisfies("1.2.9", "<=1.2")
        self.assert_satisfies("1.2.0", "<1.2", False)
        self.assert_satisfies("1.1.9", "<1.2")

    def test_hyphen_ranges(self):
        self.assert_satisfies("1.2.3", "1.2.3 - 2.3.4")
        self.assert_satisfies("2.3.4", "1.2.3 - 2.3.4")
        self.assert_satisfies("2.3.5", "1.2.3 - 2.3.4", False)
        self.assert_satisfies("2.9.9", "1.2.3 - 2")
        self.assert_satisfies("3.0.0", "1.2.3 - 2", False)
        self.assert_satisfies("1.2.0", "1.2 - 2.0.0")

    def test_unions(self):
        self.assert_satisfies("19.0.0", "^18 || ^19")
        self.assert_satisfies("17.0.0", "^18 || ^19", False)
        self.assert_satisfies("1.2.3", "<1.0.0 || >=1.2.0 <1.3.0")
        self.assert_satisfies("1.3.0", "<1.0.0 || >=1.2.0 <1.3.0", False)
        self.assert_satisfies("0.5.0", "<1.0.0 || >=1.2.0 <1.3.0")

    def test_prerelease_versions_are_included_the_way_npm_includes_them(self):
        self.assert_satisfies("1.2.4-beta.1", "^1.2.3")
        self.assert_satisfies("2.0.0-beta.1", "^1.2.3", False)
        self.assert_satisfies("1.2.3-beta.1", ">=1.2.3", False)
        self.assert_satisfies("1.2.3-beta.1", "<1.2.3")
        self.assert_satisfies("1.0.0-alpha", ">=1.0.0-alpha <1.0.0")
        self.assert_satisfies("1.5.0-rc.1", "1.x")

    def test_unparsable_ranges_raise_instead_of_passing(self):
        for text in (
            "latest", "npm:foo@1", "file:../x", "1.2.3 ||| 2", "^", ">=", "1.2.3.4", ">*", "<*",
            "1.2.3 -", "~~1.2.3", "^^1", ">=>1", "1.2.3-", "a.b.c", "1.2.3 - >=2.0.0",
            "x" * 2000, 5, None,
        ):
            with self.subTest(range=text):
                with self.assertRaises(subject.SemverError):
                    subject.satisfies("1.2.3", text)

    def test_bounds_on_range_size(self):
        many_sets = " || ".join("1.0." + str(index) for index in range(subject.MAX_SETS + 1))
        with self.assertRaises(subject.SemverError):
            subject.parse_range(many_sets)
        many_comparators = " ".join(">=1.0." + str(index) for index in range(subject.MAX_COMPARATORS + 1))
        with self.assertRaises(subject.SemverError):
            subject.parse_range(many_comparators)
        with self.assertRaises(subject.SemverError):
            subject.parse_range("1.2.3 " + chr(0xE9))


if __name__ == "__main__":
    unittest.main()
