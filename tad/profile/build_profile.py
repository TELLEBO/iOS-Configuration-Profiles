#!/usr/bin/env python3
"""Build the combined TAD + encrypted-DNS profile.

One profile, three effects:

  1. Installs the VPN configuration and turns it on automatically (On Demand), with the
     Connect On Demand toggle disabled so it stays on.
  2. Pins a minimum traffic-analysis defense level the user cannot lower.
  3. Pins the DNS resolver, in both of the places it has to be pinned — see below.

Why DNS is configured twice
---------------------------
An active VPN overrides a system-wide `com.apple.dnsSettings.managed` payload. So the
DNS payload alone would be silently inert exactly when the VPN is doing its job. The
resolver therefore goes in two places:

  * `VendorConfig` -> the tunnel builds `NEDNSOverHTTPSSettings` from it, so while the VPN
    is up, DoH runs *inside* the tunnel: encrypted end-to-end to the resolver, and shaped
    by the traffic-analysis defense on the way out.
  * `com.apple.dnsSettings.managed` -> covers the window before the tunnel is up, so DNS
    is never in the clear.

The build asserts the two agree. A profile whose fallback resolver differs from its
in-tunnel resolver is a bug, not a configuration.

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

# Values taken from signed vendor profiles, not from memory.
#
# dnsforge-hard: verified 2026-09-12 against hard-dnsforge-doh.mobileconfig, whose CMS
#   signature verifies against a Let's Encrypt certificate for CN=hard.dnsforge.de.
# quad9: verified against Quad9_Secured_DNS_over_HTTPS_20260119.mobileconfig in
#   github.com/Quad9DNS/documentation.
RESOLVERS = {
    "dnsforge-hard": {
        "name": "DNSforge hard",
        "url": "https://hard.dnsforge.de/dns-query",
        "addresses": [
            "49.12.222.213",
            "2a01:4f8:c17:2c61::213",
            "88.198.122.154",
            "2a01:4f8:c013:5ec0::154",
        ],
        "note": (
            "Aggressive filtering: ads, trackers and malware across roughly 2.8 million "
            "domains, with no allowances made for breakage. Expect some sites and app "
            "features to stop working."
        ),
    },
    "quad9": {
        "name": "Quad9 Secured",
        "url": "https://dns.quad9.net/dns-query",
        "addresses": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
        "note": "DNSSEC validation and malicious-domain blocking. No ad filtering.",
    },
}

# Carrier services — chiefly visual voicemail — that resolve through carrier-operated DNS
# and break under a system-wide encrypted resolver. List adopted from Quad9's published
# profile.
CARRIER_BYPASS_DOMAINS = [
    "dav.orange.fr",
    "msg.t-mobile.com",
    "ip.videotron.ca",
    "vvm.ee.co.uk",
]

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
{app} — VPN, TRAFFIC-ANALYSIS DEFENSE AND ENCRYPTED DNS

WHAT HAPPENS AFTER YOU INSTALL THIS

The VPN turns itself on and stays on. All DNS goes to {dns} over DNS-over-HTTPS. Traffic
inside the tunnel is shaped by a traffic-analysis defense at the "{level}" level or higher.

THE THREE PARTS

VPN, always on. Connect On Demand is enabled and its toggle is disabled, so the tunnel
comes back by itself.

Traffic-analysis defense. Cover traffic and constant packet sizes, so an observer watching
the encrypted tunnel cannot infer which sites you visit from packet sizes and timing. You
can raise the level in the app. You cannot lower it while this profile is installed.

Encrypted DNS. {dns_note}

WHAT IT COSTS

Cover traffic is real traffic: expect materially higher data use and battery drain, more so
at "moderate" and "heavy". Filtering DNS breaks things by design — if a site or an app
stops working, the resolver is the first thing to suspect.

FAIL-CLOSED BEHAVIOUR

{peer}

LIMITS

- This enforces a floor, not the device. Removing this profile removes all three parts.
- The defense protects traffic inside the tunnel. Traffic that does not go through the
  tunnel is not protected.
- Encrypted DNS is not a kill switch. On iOS 25 and earlier, do not assume DNS fails
  closed when the resolver is unreachable.

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


def vpn_payload(args, resolver) -> dict:
    vendor_config = {
        # ── Traffic-analysis defense ──────────────────────────────────────────────────
        "TADDefenseLevel": args.level,
        "TADEnforced": True,
        "TADRequirePeerSupport": not args.allow_undefended_servers,
        "TADMaxPaddingFraction": str(args.max_padding_fraction),
        "TADMaxBlockingFraction": str(args.max_blocking_fraction),
        "TADConstantPacketSize": True,
        "TADServerEndpoint": args.endpoint,
        # ── DNS, applied to the tunnel's own network settings ─────────────────────────
        # The extension turns these into NEDNSOverHTTPSSettings. Without them the tunnel
        # would fall back to whatever DNS the VPN server hands out, and the DNS payload
        # below would not save it — an active VPN overrides that payload.
        "TADDNSProtocol": "HTTPS",
        "TADDNSServerURL": resolver["url"],
        "TADDNSServerAddresses": resolver["addresses"],
    }

    return {
        "PayloadType": "com.apple.vpn.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{BASE_ID}.vpn",
        "PayloadUUID": str(uuid.uuid5(NS, f"{BASE_ID}.vpn")).upper(),
        "PayloadDisplayName": f"{args.display_name} — always on, defense floor: {args.level}",
        "PayloadDescription": (
            "Configures the VPN, turns it on automatically, and pins both the minimum "
            "traffic-analysis defense level and the DNS resolver used inside the tunnel."
        ),
        "UserDefinedName": args.display_name,
        # VPNType "VPN" selects a third-party provider; the schema then requires
        # VPNSubType. AlwaysOn is not an option: its TunnelConfigurations accept IKEv2
        # only, so no packet-tunnel provider can be an iOS Always-On VPN. On Demand with
        # the user override disabled is the closest thing available.
        "VPNType": "VPN",
        "VPNSubType": args.bundle_id,
        "ProviderBundleIdentifier": args.provider_bundle_id,
        "ProviderType": "packet-tunnel",
        "VendorConfig": vendor_config,
        "OnDemandEnabled": 1,
        "OnDemandRules": [{"Action": "Connect"}],
        # iOS 14+, and not a supervised-only key: greys out the Connect On Demand toggle
        # in Settings so the tunnel cannot be casually switched off.
        "OnDemandUserOverrideDisabled": 1,
    }


def dns_payload(args, resolver) -> dict:
    dns_settings = {
        "DNSProtocol": "HTTPS",
        "ServerURL": resolver["url"],
        "ServerAddresses": resolver["addresses"],
        # iOS 26.0+. false is Apple's default; set explicitly so the intent survives a
        # future default change. Ignored on earlier iOS.
        "AllowFailover": False,
    }

    payload = {
        "PayloadType": "com.apple.dnsSettings.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{BASE_ID}.dns",
        "PayloadUUID": str(uuid.uuid5(NS, f"{BASE_ID}.dns")).upper(),
        "PayloadDisplayName": f"Encrypted DNS — {resolver['name']} (used while the VPN is down)",
        "PayloadDescription": (
            "System-wide DNS-over-HTTPS. An active VPN overrides this, so it covers the "
            "window before the tunnel is up."
        ),
        "DNSSettings": dns_settings,
    }

    if not args.no_carrier_bypass:
        payload["OnDemandRules"] = [
            {
                "Action": "EvaluateConnection",
                "ActionParameters": [
                    {"DomainAction": "NeverConnect", "Domains": CARRIER_BYPASS_DOMAINS}
                ],
            },
            {"Action": "Connect"},
        ]
    return payload


def build(args, resolver) -> dict:
    peer_text = PEER_LENIENT if args.allow_undefended_servers else PEER_STRICT
    return {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": BASE_ID,
        "PayloadUUID": str(uuid.uuid5(NS, BASE_ID)).upper(),
        "PayloadDisplayName": (
            f"{args.display_name} — always-on VPN, {args.level} defense, {resolver['name']} DNS"
        ),
        "PayloadDescription": (
            "Always-on VPN with an enforced traffic-analysis defense floor and pinned "
            "encrypted DNS."
        ),
        "PayloadOrganization": args.organization,
        "PayloadScope": "System",
        "PayloadRemovalDisallowed": False,
        "ConsentText": {
            "default": CONSENT.format(
                app=args.display_name,
                level=args.level,
                dns=resolver["name"],
                dns_note=resolver["note"],
                peer=peer_text,
            )
        },
        "PayloadContent": [vpn_payload(args, resolver), dns_payload(args, resolver)],
    }


def validate(path: Path, args, resolver) -> None:
    parsed = plistlib.loads(path.read_bytes())

    for p in [parsed] + parsed["PayloadContent"]:
        assert p["PayloadVersion"] == 1, "PayloadVersion is the plist format version, always 1"
        for trap in TRAPS:
            assert trap not in p, f"trap key present: {trap}"

    ids = [p["PayloadIdentifier"] for p in parsed["PayloadContent"]]
    assert len(ids) == len(set(ids)), "duplicate payload identifiers"

    by_type = {p["PayloadType"]: p for p in parsed["PayloadContent"]}
    vpn = by_type["com.apple.vpn.managed"]
    dns = by_type["com.apple.dnsSettings.managed"]

    # Apple's schema: VPNSubType is required when VPNType is "VPN".
    assert vpn["VPNType"] == "VPN" and vpn["VPNSubType"], "VPNType=VPN requires VPNSubType"
    assert vpn["ProviderType"] == "packet-tunnel"
    assert vpn["ProviderBundleIdentifier"].startswith(vpn["VPNSubType"]), (
        "the extension's bundle id must be under the app's, or iOS will not pair them"
    )

    # Automatic connection is the point; a profile that installs a VPN and leaves it off
    # has not done what its consent text promises.
    assert vpn["OnDemandEnabled"] == 1, "the VPN must come up on its own"
    assert vpn["OnDemandRules"], "OnDemandEnabled without rules connects nothing"
    assert vpn["OnDemandUserOverrideDisabled"] == 1, "the On Demand toggle must be pinned"

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

    # The in-tunnel resolver and the VPN-down fallback must be the same resolver.
    d = dns["DNSSettings"]
    assert d["DNSProtocol"] == vc["TADDNSProtocol"] == "HTTPS"
    assert d["ServerURL"] == vc["TADDNSServerURL"] == resolver["url"], (
        "in-tunnel and fallback resolvers disagree"
    )
    assert d["ServerAddresses"] == vc["TADDNSServerAddresses"] == resolver["addresses"]
    assert d["ServerURL"].startswith("https://")

    assert parsed["PayloadRemovalDisallowed"] is False

    print(f"validated {path.name}")
    print(f"  payloads       {', '.join(sorted(by_type))}")
    print(f"  app            {vpn['VPNSubType']}")
    print(f"  extension      {vpn['ProviderBundleIdentifier']}")
    print(f"  auto-connect   on demand, user override disabled")
    print(f"  defense floor  {vc['TADDefenseLevel']} (enforced)")
    print(f"  fail closed    {vc['TADRequirePeerSupport']}")
    print(f"  resolver       {resolver['name']} — {d['ServerURL']}")
    print(f"                 in-tunnel (DoH) and system fallback, asserted identical")

    if args.bundle_id == PLACEHOLDER_APP:
        print(
            "\n  NOTE: placeholder bundle identifiers. The DNS payload will work as soon "
            "as this\n  profile is installed, but the VPN and the defense will not exist "
            "until\n  --bundle-id and --provider-bundle-id name an app that actually "
            "reads\n  providerConfiguration. See ../README.md."
        )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bundle-id", default=PLACEHOLDER_APP)
    ap.add_argument("--provider-bundle-id", default=PLACEHOLDER_EXT)
    ap.add_argument("--level", choices=LEVELS[1:], default="moderate")
    ap.add_argument("--resolver", choices=sorted(RESOLVERS), default="dnsforge-hard")
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
    ap.add_argument(
        "--no-carrier-bypass",
        action="store_true",
        help="do not exclude carrier visual-voicemail domains from encrypted DNS",
    )
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()

    resolver = RESOLVERS[args.resolver]
    args.out.write_bytes(plistlib.dumps(build(args, resolver)))
    validate(args.out, args, resolver)
    print(
        "\nplutil is macOS-only; this is a plistlib round-trip, not on-device proof.\n"
        "Install on a test device before deploying."
    )


if __name__ == "__main__":
    main()
