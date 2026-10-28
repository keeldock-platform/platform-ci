import hashlib
from pathlib import Path
import unittest

from native_loopback_profile import (
    CHANNEL_ORDER,
    NEGATIVE_EGRESS_PROOFS,
    NATIVE_LOOPBACK_PROOF_PLAN,
    POSITIVE_LOOPBACK_PROOFS,
    PROOF_SUBJECTS,
    ChannelName,
    LoopbackEndpoint,
    NativeLoopbackProfile,
    ProfileError,
    validate_profile,
)


ROOT = Path(__file__).resolve().parent
SOURCE_PROFILE_DIGESTS = {
    "linux_harness.py": "1283f3c1481728e675c823ad3df3cf84dd7b37154938af25d5043c093b9156c0",
    "macos_deny_default.py": "ab15114cddef7f94732bfd8497a08fde41f75b49e6c42721a447b4f895ce628f",
}


def valid_profile():
    channels = tuple(
        LoopbackEndpoint(name=channel, host="127.0.0.1", port=18000 + index)
        for index, channel in enumerate(CHANNEL_ORDER)
    )
    return NativeLoopbackProfile(channels=channels)


class ChannelDeclarationTests(unittest.TestCase):
    def test_catalogue_names_the_server_and_each_driver_session_endpoint(self):
        self.assertEqual(
            tuple(channel.value for channel in CHANNEL_ORDER),
            (
                "appium_server",
                "xcuitest_webdriver_agent",
                "mac2_webdriver_agent",
                "uiautomator2_driver",
                "android_chromedriver",
                "novawindows_driver",
                "linux_tauri_driver",
                "linux_webkit_webdriver",
                "windows_tauri_driver",
                "edge_webdriver",
            ),
        )
        self.assertEqual(len(set(CHANNEL_ORDER)), len(CHANNEL_ORDER))


class ProfileValidationTests(unittest.TestCase):
    def test_accepts_complete_random_port_ipv4_loopback_profile(self):
        profile = valid_profile()
        self.assertIs(validate_profile(profile), profile)

    def test_rejects_external_ipv4_and_ipv6_addresses(self):
        for host in ("192.0.2.1", "2001:db8::1", "::1", "localhost"):
            profile = valid_profile()
            endpoint = profile.channels[0]
            changed = (LoopbackEndpoint(endpoint.name, host, endpoint.port),) + profile.channels[1:]
            with self.subTest(host=host), self.assertRaisesRegex(ProfileError, "address_not_ipv4_loopback"):
                validate_profile(NativeLoopbackProfile(changed))

    def test_rejects_ipv4_and_ipv6_wildcard_binds(self):
        for host in ("0.0.0.0", "::"):
            profile = valid_profile()
            endpoint = profile.channels[0]
            changed = (LoopbackEndpoint(endpoint.name, host, endpoint.port),) + profile.channels[1:]
            with self.subTest(host=host), self.assertRaisesRegex(ProfileError, "address_not_ipv4_loopback"):
                validate_profile(NativeLoopbackProfile(changed))

    def test_rejects_runner_ipc_paths(self):
        profile = valid_profile()
        endpoint = profile.channels[0]
        changed = (LoopbackEndpoint(endpoint.name, endpoint.host, endpoint.port, ipc_path="runner_ipc"),)
        changed += profile.channels[1:]
        with self.assertRaisesRegex(ProfileError, "ipc_path_forbidden"):
            validate_profile(NativeLoopbackProfile(changed))

    def test_rejects_extra_or_missing_channels(self):
        profile = valid_profile()
        first = profile.channels[0]
        extra = LoopbackEndpoint("runner_ipc", "127.0.0.1", 19000)
        with self.assertRaisesRegex(ProfileError, "channel_unlisted"):
            validate_profile(NativeLoopbackProfile(profile.channels + (extra,)))
        with self.assertRaisesRegex(ProfileError, "channel_missing"):
            validate_profile(NativeLoopbackProfile(profile.channels[1:]))
        with self.assertRaisesRegex(ProfileError, "channel_duplicate"):
            validate_profile(NativeLoopbackProfile(profile.channels + (first,)))

    def test_rejects_invalid_or_shared_session_ports(self):
        profile = valid_profile()
        first = profile.channels[0]
        second = profile.channels[1]
        cases = (
            (LoopbackEndpoint(first.name, first.host, 0),) + profile.channels[1:],
            (LoopbackEndpoint(first.name, first.host, True),) + profile.channels[1:],
            (first, LoopbackEndpoint(second.name, second.host, first.port)) + profile.channels[2:],
        )
        expected = ("port_invalid", "port_invalid", "port_duplicate")
        for channels, reason in zip(cases, expected):
            with self.subTest(reason=reason), self.assertRaisesRegex(ProfileError, reason):
                validate_profile(NativeLoopbackProfile(channels))

    def test_rejects_non_tcp_or_non_random_per_run_declarations(self):
        profile = valid_profile()
        endpoint = profile.channels[0]
        changed = (LoopbackEndpoint(endpoint.name, endpoint.host, endpoint.port, transport="udp"),)
        changed += profile.channels[1:]
        with self.assertRaisesRegex(ProfileError, "transport_invalid"):
            validate_profile(NativeLoopbackProfile(changed))
        with self.assertRaisesRegex(ProfileError, "port_allocation_invalid"):
            validate_profile(NativeLoopbackProfile(profile.channels, port_allocation="fixed"))


class ProofPlanTests(unittest.TestCase):
    def test_positive_plan_proves_every_declared_loopback_channel_reachable(self):
        self.assertEqual(NATIVE_LOOPBACK_PROOF_PLAN.positive_loopback, POSITIVE_LOOPBACK_PROOFS)
        self.assertEqual(
            {check.channel for check in POSITIVE_LOOPBACK_PROOFS},
            set(ChannelName),
        )
        self.assertEqual(
            {check.channel: (check.name, check.target) for check in POSITIVE_LOOPBACK_PROOFS},
            {
                channel: ("loopback_" + channel.value, "declared_channel")
                for channel in ChannelName
            },
        )
        self.assertTrue(all(check.expected == "reachable" for check in POSITIVE_LOOPBACK_PROOFS))
        self.assertTrue(all(check.transport == "tcp" for check in POSITIVE_LOOPBACK_PROOFS))
        self.assertTrue(all(check.subjects == PROOF_SUBJECTS for check in POSITIVE_LOOPBACK_PROOFS))

    def test_negative_plan_refuses_egress_and_runner_ipc_for_every_subject(self):
        expected_probes = {
            "ipv4_external_tcp": ("non_loopback_ipv4", "tcp"),
            "ipv4_external_udp": ("non_loopback_ipv4", "udp"),
            "ipv6_external_tcp": ("non_loopback_ipv6", "tcp"),
            "ipv6_external_udp": ("non_loopback_ipv6", "udp"),
            "dns_lookup": ("external_name_resolution", "dns"),
            "https_egress": ("external_https", "https"),
            "proxy_use": ("configured_proxy", "proxy"),
            "redirect_egress": ("external_redirect", "redirect"),
            "registry_access": ("package_registry", "https"),
            "browser_driver_download": ("driver_download_origin", "https"),
            "runner_api_access": ("runner_api", "https"),
            "emulator_guest_egress": ("emulator_guest_external", "tcp_udp"),
            "external_adb_forward": ("adb_forward_outside_loopback", "tcp"),
            "unlisted_local_channel": ("unlisted_local_endpoint", "tcp"),
            "unlisted_ipc_channel": ("unlisted_ipc_endpoint", "ipc"),
            "runner_ipc_path": ("runner_ipc", "ipc"),
            "direct_connect_capability": ("direct_connect_endpoint", "webdriver"),
        }
        self.assertEqual(NATIVE_LOOPBACK_PROOF_PLAN.negative_egress, NEGATIVE_EGRESS_PROOFS)
        self.assertEqual(
            {check.name: (check.target, check.transport) for check in NEGATIVE_EGRESS_PROOFS},
            expected_probes,
        )
        self.assertTrue(all(check.expected == "refused" for check in NEGATIVE_EGRESS_PROOFS))
        self.assertTrue(all(check.subjects == PROOF_SUBJECTS for check in NEGATIVE_EGRESS_PROOFS))


class SourceJobProfileTests(unittest.TestCase):
    def test_existing_linux_and_macos_source_job_profiles_remain_byte_identical(self):
        for filename, expected_digest in SOURCE_PROFILE_DIGESTS.items():
            with self.subTest(profile=filename):
                actual = hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()
                self.assertEqual(actual, expected_digest)
