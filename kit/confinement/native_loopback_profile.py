from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


class ChannelName(str, Enum):
    APPIUM_SERVER = "appium_server"
    XCUITEST_WEBDRIVER_AGENT = "xcuitest_webdriver_agent"
    MAC2_WEBDRIVER_AGENT = "mac2_webdriver_agent"
    UIAUTOMATOR2_DRIVER = "uiautomator2_driver"
    ANDROID_CHROMEDRIVER = "android_chromedriver"
    NOVAWINDOWS_DRIVER = "novawindows_driver"
    LINUX_TAURI_DRIVER = "linux_tauri_driver"
    LINUX_WEBKIT_WEBDRIVER = "linux_webkit_webdriver"
    WINDOWS_TAURI_DRIVER = "windows_tauri_driver"
    EDGE_WEBDRIVER = "edge_webdriver"


CHANNEL_ORDER = tuple(ChannelName)
REQUIRED_CHANNELS = frozenset(CHANNEL_ORDER)


@dataclass(frozen=True)
class LoopbackEndpoint:
    name: ChannelName
    host: str
    port: int
    transport: str = "tcp"
    ipc_path: Optional[str] = None


@dataclass(frozen=True)
class NativeLoopbackProfile:
    channels: Tuple[LoopbackEndpoint, ...]
    port_allocation: str = "random_per_run"


class ProfileError(ValueError):
    pass


def validate_profile(profile):
    if type(profile) is not NativeLoopbackProfile:
        raise ProfileError("profile_type_invalid")
    if type(profile.channels) is not tuple:
        raise ProfileError("channel_collection_invalid")
    if type(profile.port_allocation) is not str or profile.port_allocation != "random_per_run":
        raise ProfileError("port_allocation_invalid")

    seen_names = set()
    seen_ports = set()
    for endpoint in profile.channels:
        if type(endpoint) is not LoopbackEndpoint:
            raise ProfileError("endpoint_type_invalid")
        if type(endpoint.name) is not ChannelName:
            raise ProfileError("channel_unlisted")
        if endpoint.name in seen_names:
            raise ProfileError("channel_duplicate")
        seen_names.add(endpoint.name)
        if type(endpoint.host) is not str or endpoint.host != "127.0.0.1":
            raise ProfileError("address_not_ipv4_loopback")
        if type(endpoint.port) is not int or not 1 <= endpoint.port <= 65535:
            raise ProfileError("port_invalid")
        if endpoint.port in seen_ports:
            raise ProfileError("port_duplicate")
        seen_ports.add(endpoint.port)
        if type(endpoint.transport) is not str or endpoint.transport != "tcp":
            raise ProfileError("transport_invalid")
        if endpoint.ipc_path is not None:
            raise ProfileError("ipc_path_forbidden")

    if seen_names != REQUIRED_CHANNELS:
        if seen_names - REQUIRED_CHANNELS:
            raise ProfileError("channel_unlisted")
        raise ProfileError("channel_missing")
    return profile


@dataclass(frozen=True)
class ProofCheck:
    name: str
    target: str
    transport: str
    expected: str
    subjects: Tuple[str, ...]
    channel: Optional[ChannelName] = None


@dataclass(frozen=True)
class ProofPlan:
    positive_loopback: Tuple[ProofCheck, ...]
    negative_egress: Tuple[ProofCheck, ...]


PROOF_SUBJECTS = ("test_worker", "automation_processes")
POSITIVE_LOOPBACK_PROOFS = tuple(
    ProofCheck(
        name="loopback_" + channel.value,
        target="declared_channel",
        transport="tcp",
        expected="reachable",
        subjects=PROOF_SUBJECTS,
        channel=channel,
    )
    for channel in CHANNEL_ORDER
)
NEGATIVE_EGRESS_PROOFS = (
    ProofCheck("ipv4_external_tcp", "non_loopback_ipv4", "tcp", "refused", PROOF_SUBJECTS),
    ProofCheck("ipv4_external_udp", "non_loopback_ipv4", "udp", "refused", PROOF_SUBJECTS),
    ProofCheck("ipv6_external_tcp", "non_loopback_ipv6", "tcp", "refused", PROOF_SUBJECTS),
    ProofCheck("ipv6_external_udp", "non_loopback_ipv6", "udp", "refused", PROOF_SUBJECTS),
    ProofCheck("dns_lookup", "external_name_resolution", "dns", "refused", PROOF_SUBJECTS),
    ProofCheck("https_egress", "external_https", "https", "refused", PROOF_SUBJECTS),
    ProofCheck("proxy_use", "configured_proxy", "proxy", "refused", PROOF_SUBJECTS),
    ProofCheck("redirect_egress", "external_redirect", "redirect", "refused", PROOF_SUBJECTS),
    ProofCheck("registry_access", "package_registry", "https", "refused", PROOF_SUBJECTS),
    ProofCheck("browser_driver_download", "driver_download_origin", "https", "refused", PROOF_SUBJECTS),
    ProofCheck("runner_api_access", "runner_api", "https", "refused", PROOF_SUBJECTS),
    ProofCheck("emulator_guest_egress", "emulator_guest_external", "tcp_udp", "refused", PROOF_SUBJECTS),
    ProofCheck("external_adb_forward", "adb_forward_outside_loopback", "tcp", "refused", PROOF_SUBJECTS),
    ProofCheck("unlisted_local_channel", "unlisted_local_endpoint", "tcp", "refused", PROOF_SUBJECTS),
    ProofCheck("unlisted_ipc_channel", "unlisted_ipc_endpoint", "ipc", "refused", PROOF_SUBJECTS),
    ProofCheck("runner_ipc_path", "runner_ipc", "ipc", "refused", PROOF_SUBJECTS),
    ProofCheck("direct_connect_capability", "direct_connect_endpoint", "webdriver", "refused", PROOF_SUBJECTS),
)
NATIVE_LOOPBACK_PROOF_PLAN = ProofPlan(
    positive_loopback=POSITIVE_LOOPBACK_PROOFS,
    negative_egress=NEGATIVE_EGRESS_PROOFS,
)
