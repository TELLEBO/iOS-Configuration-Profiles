#!/usr/bin/env python3
"""Build the TAD enforcement profile.

Unlike daita/, this profile really does enforce the defense — because the VPN app it
targets is one you build, and it reads the dictionary iOS hands it. The mechanism that is
inert against Mullvad (VendorConfig -> providerConfiguration) is load-bearing here.

Replace the placeholder bundle identifiers with your own before deploying:

    python3 build_profile.py --bundle-id com.example.tadvpn \
                             --provider-bundle-id com.example.tadvpn.PacketTunnel \
                             --endpoint vpn.example.com:51820
"""

import argparse
import plistlib
import uuid
from pathlib import Path

NS = uuid.UUID("2f3b71c4-8d10-5a92-b6e7-41c0d9a2f7b3")
BASE_ID = "com.github.tellebo.ios-configuration-profiles.tad"
OUT = Path(__file__).with_name("TAD-Enforced-VPN.mobileconfig")

PLACEHOLDER_APP = "com.example.tadvpn"
PLACEHOLDER_EXT = "com.example.tadvpn.PacketTunnel"

LEVELS = ["off", "light", "moderate", "heavy"]

TRAPS = [
    "allowUSBRestrictedMode",
    "allowSafariPrivateBrowsing",
    "allowCloudPrivateRelay",
    "allowOTAPKIUpdates",
    "allowCloudBackup",
    "allowCloudPhotoLibrary",
    "allowCloudKeychainSync",
    "allowSafariHistoryClearing",
]

CONSENT = """\
TRAFFIC-ANALYSIS DEFENSE — ENFORCED

This profile configures the {app} VPN and sets a minimum traffic-analysis defense level
of "{level}". You can raise the level in the app. You cannot lower it while this profile
is installed.

WHAT THE DEFENSE DOES

It injects cover traffic and pads packets to a constant size so that an observer watching
the encrypted tunnel cannot infer which sites you visit from packet sizes and timing.

WHAT IT COSTS

Real bandwidth and battery. Cover traffic is indistinguishable from your traffic to an
observer, which means it is also indistinguishable to your data plan. Expect materially
higher data use, more so at "moderate" and "heavy".

FAIL-CLOSED BEHAVIOUR

{peer}

LIMITS

- This enforces a floor, not the device. Removing this profile removes the floor.
- The defense protects traffic inside this VPN tunnel. Traffic that does not go through
  the tunnel is not protected.

Removable at: Settings > General > VPN & Device Management (unless your organisation has
supervised this device and disallowed removal).
"""

PEER_STRICT = """\
If the server cannot run the matching server-side defense, the app refuses to connect
rather than leave you believing you are protected when you are not."""

PEER_LENIENT = """\
This profile permits connecting to servers that cannot run the matching server-side
defense. The defense will be substantially weaker on those servers: most of the
identifying signal is in the traffic coming back to you, which only the server can shape."""


def build(args) -> dict:
    vendor_config = {
        # Read by the packet-tunnel extension as providerConfiguration. Booleans are sent
        # as real plist booleans; the Swift loader coerces strings too, because MDM
        # vendors are inconsistent about this.
        "TADDefenseLevel": args.level,
        "TADEnforced": True,
        "TADRequirePeerSupport": not args.allow_undefended_servers,
        "TADMaxPaddingFraction": str(args.max_padding_fraction),
        "TADMaxBlockingFraction": str(args.max_blocking_fraction),
        "TADConstantPacketSize": True,
        "TADServerEndpoint": args.endpoint,
    }

    vpn_payload = {
        "PayloadType": "com.apple.vpn.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{BASE_ID}.vpn",
        "PayloadUUID": str(uuid.uuid5(NS, f"{BASE_ID}.vpn")).upper(),
        "PayloadDisplayName": f"TAD VPN — defense floor: {args.level}",
        "PayloadDescription": (
            "Configures the VPN and pins a minimum traffic-analysis defense level."
        ),
        "UserDefinedName": args.display_name,
        # VPNType "VPN" is what selects a third-party provider; the schema then requires
        # VPNSubType. AlwaysOn is not an option: its TunnelConfigurations accept IKEv2
        # only, so no packet-tunnel provider can be an iOS Always-On VPN.
        "VPNType": "VPN",
        "VPNSubType": args.bundle_id,
        "ProviderBundleIdentifier": args.provider_bundle_id,
        "ProviderType": "packet-tunnel",
        "VendorConfig": vendor_config,
        # On-demand is the closest available substitute for Always-On with a
        # packet-tunnel provider.
        "OnDemandEnabled": 1,
        "OnDemandRules": [{"Action": "Connect"}],
    }

    peer_text = PEER_LENIENT if args.allow_undefended_servers else PEER_STRICT
    return {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": BASE_ID,
        "PayloadUUID": str(uuid.uuid5(NS, BASE_ID)).upper(),
        "PayloadDisplayName": f"Traffic-Analysis Defense — enforced ({args.level})",
        "PayloadDescription": (
            "Pins a minimum traffic-analysis defense level for the TAD VPN app."
        ),
        "PayloadOrganization": args.organization,
        "PayloadScope": "System",
        "PayloadRemovalDisallowed": False,
        "ConsentText": {
            "default": CONSENT.format(
                app=args.display_name, level=args.level, peer=peer_text
            )
        },
        "PayloadContent": [vpn_payload],
    }


def validate(path: Path, args) -> None:
    parsed = plistlib.loads(path.read_bytes())

    for p in [parsed] + parsed["PayloadContent"]:
        assert p["PayloadVersion"] == 1, "PayloadVersion is the plist format version, always 1"
        for trap in TRAPS:
            assert trap not in p, f"trap key present: {trap}"

    vpn = parsed["PayloadContent"][0]
    assert vpn["PayloadType"] == "com.apple.vpn.managed"
    # Apple's schema: VPNSubType is required when VPNType is "VPN".
    assert vpn["VPNType"] == "VPN" and vpn["VPNSubType"], "VPNType=VPN requires VPNSubType"
    assert vpn["ProviderType"] == "packet-tunnel"
    assert vpn["ProviderBundleIdentifier"].startswith(vpn["VPNSubType"]), (
        "the extension's bundle id must be under the app's, or iOS will not pair them"
    )

    vc = vpn["VendorConfig"]
    assert vc["TADDefenseLevel"] in LEVELS
    assert vc["TADEnforced"] is True, "an unenforced profile has no reason to exist"
    assert vc["TADDefenseLevel"] != "off", "cannot enforce a floor of 'off'"
    assert "TADAppInstanceNonce" not in vc, (
        "the app stamps its own configurations with this; a profile writing it would "
        "let a profile-delivered policy masquerade as app-created"
    )
    for frac_key in ("TADMaxPaddingFraction", "TADMaxBlockingFraction"):
        assert 0.0 <= float(vc[frac_key]) <= 1.0, f"{frac_key} must be in [0.0, 1.0]"

    assert parsed["PayloadRemovalDisallowed"] is False

    print(f"validated {path.name}")
    print(f"  app            {vpn['VPNSubType']}")
    print(f"  extension      {vpn['ProviderBundleIdentifier']}")
    print(f"  defense floor  {vc['TADDefenseLevel']} (enforced)")
    print(f"  fail closed    {vc['TADRequirePeerSupport']}")

    if args.bundle_id == PLACEHOLDER_APP:
        print(
            "\n  NOTE: placeholder bundle identifiers. This profile will install and do "
            "nothing\n  until --bundle-id and --provider-bundle-id name an app that "
            "actually reads\n  providerConfiguration. See ../README.md."
        )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bundle-id", default=PLACEHOLDER_APP)
    ap.add_argument("--provider-bundle-id", default=PLACEHOLDER_EXT)
    ap.add_argument("--level", choices=LEVELS[1:], default="moderate")
    ap.add_argument("--endpoint", default="vpn.example.com:51820")
    ap.add_argument("--display-name", default="TAD VPN")
    ap.add_argument("--organization", default="tellebo/iOS-Configuration-Profiles")
    ap.add_argument("--max-padding-fraction", type=float, default=0.5)
    ap.add_argument("--max-blocking-fraction", type=float, default=0.2)
    ap.add_argument(
        "--allow-undefended-servers",
        action="store_true",
        help="permit connecting to servers with no server-side machines (weakens the "
        "defense substantially; off by default)",
    )
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()

    args.out.write_bytes(plistlib.dumps(build(args)))
    validate(args.out, args)
    print(
        "\nplutil is macOS-only; this is a plistlib round-trip, not on-device proof.\n"
        "Install on a test device before deploying."
    )


if __name__ == "__main__":
    main()
