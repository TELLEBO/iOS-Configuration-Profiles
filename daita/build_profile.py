#!/usr/bin/env python3
"""Build the DAITA-support encrypted DNS configuration profile.

This profile does NOT enable Mullvad DAITA. Nothing delivered as a .mobileconfig
can — see README.md for the evidence. It configures the one part of the
surrounding threat model that IS profile-enforceable on an unsupervised iPhone:
encrypted DNS, so name resolution does not leak in the clear while the Mullvad
tunnel is down.

Build:  python3 build_profile.py
"""

import argparse
import plistlib
import uuid
from pathlib import Path

# Stable namespace so rebuilds are byte-identical and reinstalling replaces
# rather than duplicates. iOS keys replacement off PayloadIdentifier, but a
# churning UUID makes the committed artifact impossible to diff.
NS = uuid.UUID("6f1d6d9a-0b27-5c31-9f3e-2b0f1c6a4d88")

BASE_ID = "com.github.tellebo.ios-configuration-profiles.daita-support"
OUT = Path(__file__).with_name("DAITA-Support-Encrypted-DNS.mobileconfig")

# Verified 2026-09-12 against Quad9's own signed profile,
# Quad9_Secured_DNS_over_HTTPS_20260119.mobileconfig, in github.com/Quad9DNS/documentation.
RESOLVERS = {
    "quad9": {
        "name": "Quad9 Secured (DNSSEC + malicious-domain blocking)",
        "url": "https://dns.quad9.net/dns-query",
        "addresses": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
    },
    # Mullvad's public resolvers shut down 2026-11-02; kept only for users who
    # need the profile before that date. Mullvad now sponsors Quad9 instead.
    # Verified 2026-09-12 against their signed vanilla profile in
    # github.com/mullvad/encrypted-dns-profiles.
    "mullvad": {
        "name": "Mullvad vanilla (SHUTS DOWN 2026-11-02)",
        "url": "https://dns.mullvad.net/dns-query",
        "addresses": ["2a07:e340::2", "194.242.2.2"],
    },
}

# Carrier services that break under a system-wide encrypted resolver — chiefly
# visual voicemail, which resolves through carrier-operated DNS. List adopted
# from Quad9's published profile.
CARRIER_BYPASS_DOMAINS = [
    "dav.orange.fr",
    "msg.t-mobile.com",
    "ip.videotron.ca",
    "vvm.ee.co.uk",
]

# Keys that sound protective and are not. Asserted absent from every payload.
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
WHAT THIS PROFILE DOES NOT DO

It does not enable, force, or verify Mullvad's DAITA (Defense against AI-guided
Traffic Analysis). DAITA lives inside the Mullvad app and no configuration
profile can reach it. Turn it on manually: Mullvad app > Settings > VPN settings
> DAITA.

WHAT IT DOES

Routes all DNS queries to {name} over DNS-over-HTTPS, so
name resolution is not sent in the clear to the local network or your ISP while
the Mullvad tunnel is down. While the tunnel is up, Mullvad's in-tunnel DNS
takes precedence and this payload does nothing.

SIDE EFFECTS

- Visual voicemail on Orange, T-Mobile, Videotron and EE is excluded from
  encrypted DNS so it keeps working. Other carriers may still break voicemail
  or captive-portal sign-in; remove the profile if so.
- Network-level content filtering on your home or office network stops applying.
- This is not a kill switch. If the resolver is unreachable, do not assume DNS
  fails closed on iOS 25 and earlier.

Removable at any time: Settings > General > VPN & Device Management.
"""


def build(resolver_key: str) -> dict:
    r = RESOLVERS[resolver_key]

    dns_settings = {
        "DNSProtocol": "HTTPS",
        "ServerURL": r["url"],
        "ServerAddresses": r["addresses"],
        # iOS 26.0+ (Apple: com.apple.dnsSettings.managed). false is Apple's
        # default; set explicitly so the intent survives a future default change.
        # Ignored on earlier iOS.
        "AllowFailover": False,
    }

    dns_payload = {
        "PayloadType": "com.apple.dnsSettings.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{BASE_ID}.dns",
        "PayloadUUID": str(uuid.uuid5(NS, f"{BASE_ID}.dns")).upper(),
        "PayloadDisplayName": f"Encrypted DNS — {r['name']}",
        "PayloadDescription": (
            "Sends all DNS queries over DNS-over-HTTPS. Does not enable DAITA."
        ),
        "DNSSettings": dns_settings,
        "OnDemandRules": [
            {
                "Action": "EvaluateConnection",
                "ActionParameters": [
                    {
                        "DomainAction": "NeverConnect",
                        "Domains": CARRIER_BYPASS_DOMAINS,
                    }
                ],
            },
            {"Action": "Connect"},
        ],
    }

    return {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": BASE_ID,
        "PayloadUUID": str(uuid.uuid5(NS, BASE_ID)).upper(),
        "PayloadDisplayName": "DAITA Support — Encrypted DNS (does NOT enable DAITA)",
        "PayloadDescription": (
            "Encrypted DNS for a Mullvad DAITA setup. DAITA itself must be enabled "
            "in the Mullvad app; no configuration profile can set it."
        ),
        "PayloadOrganization": "tellebo/iOS-Configuration-Profiles",
        "PayloadScope": "System",
        "PayloadRemovalDisallowed": False,
        "ConsentText": {"default": CONSENT.format(name=r["name"])},
        "PayloadContent": [dns_payload],
    }


def validate(path: Path, resolver_key: str) -> None:
    parsed = plistlib.loads(path.read_bytes())

    # PayloadVersion is the plist format version, always 1. Anything else makes
    # iOS refuse the profile with "The profile version is not supported."
    for p in [parsed] + parsed["PayloadContent"]:
        assert p["PayloadVersion"] == 1, f"PayloadVersion must be 1, got {p['PayloadVersion']}"

    for p in [parsed] + parsed["PayloadContent"]:
        for trap in TRAPS:
            assert trap not in p, f"trap key present: {trap}"

    # No payload may claim to configure the VPN: a profile-delivered VPN payload
    # cannot drive Mullvad's tunnel, and shipping one would be an inert key that
    # looks effective.
    types = {p["PayloadType"] for p in parsed["PayloadContent"]}
    assert "com.apple.vpn.managed" not in types, "VPN payload cannot enforce DAITA"

    ids = [p["PayloadIdentifier"] for p in parsed["PayloadContent"]]
    assert len(ids) == len(set(ids)), "duplicate payload identifiers"
    assert parsed["PayloadIdentifier"] == BASE_ID

    dns = parsed["PayloadContent"][0]["DNSSettings"]
    assert dns["DNSProtocol"] == "HTTPS"
    assert dns["ServerURL"] == RESOLVERS[resolver_key]["url"]
    assert dns["ServerURL"].startswith("https://")
    assert dns["ServerAddresses"] == RESOLVERS[resolver_key]["addresses"]

    assert parsed["PayloadRemovalDisallowed"] is False
    assert "DAITA" in parsed["ConsentText"]["default"]

    print(f"validated {path.name}")
    print(f"  payloads:  {', '.join(sorted(types))}")
    print(f"  resolver:  {dns['ServerURL']}")
    print(f"  profile ID {parsed['PayloadIdentifier']}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--resolver", choices=sorted(RESOLVERS), default="quad9")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()

    args.out.write_bytes(plistlib.dumps(build(args.resolver)))
    validate(args.out, args.resolver)
    print(
        "\nplutil is macOS-only; this is a plistlib round-trip, not on-device proof.\n"
        "Install on a test device before deploying."
    )


if __name__ == "__main__":
    main()
