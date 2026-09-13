#!/usr/bin/env python3
"""Build the iOS DNS firewall profile.

One profile, no app, no server, no subscription. It splits DNS across resolvers so that
ad and tracker domains go to an aggressive blocker while everything else goes to the most
reliable one available.

    python3 build_profile.py                       # Quad9 catch-all, AdGuard for ad domains
    python3 build_profile.py --aggressive dnsforge-hard
    python3 build_profile.py --web-filter          # add the Safari/WebKit URL deny list
    python3 build_profile.py --list-resolvers

What it cannot do is in README.md, up front. The short version: a configuration profile
has no code execution, so there is no defense against AI-guided traffic analysis here and
there cannot be one.
"""

import argparse
import ipaddress
import plistlib
import uuid
from pathlib import Path

from resolvers import AD_AND_TRACKER_DOMAINS, HIGH, LOW, MEDIUM, RESOLVERS

NS = uuid.UUID("9a4e2b71-63c8-5d04-8f19-7e2c05b3a6d1")
BASE_ID = "com.github.tellebo.ios-configuration-profiles.firewall"
OUT = Path(__file__).with_name("iOS-DNS-Firewall.mobileconfig")

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

# Carrier services, chiefly visual voicemail, that resolve through carrier-operated DNS and
# break under a system-wide encrypted resolver. From Quad9's published profile.
CARRIER_BYPASS = ["dav.orange.fr", "msg.t-mobile.com", "ip.videotron.ca", "vvm.ee.co.uk"]

CONSENT = """\
DNS FIREWALL

WHAT IT DOES

Every DNS query from this device is sent encrypted, over HTTPS, to a filtering resolver.
Domains that serve ads, trackers and mobile analytics go to {aggressive} and are blocked.
Everything else goes to {catchall}, which blocks malware and phishing and is chosen for
reliability rather than for how much it blocks.

This works at the domain level and applies to every app, not just the browser.

WHAT IT DOES NOT DO

It is not a defense against traffic analysis. A configuration profile cannot pad packets,
generate cover traffic, or delay anything — it has no code that runs. An observer can still
see the size and timing of your traffic. Nothing installable as a profile changes that.

It is also not a full firewall. It cannot block an app that connects to a raw IP address,
and it cannot block traffic by port or protocol.

SIDE EFFECTS

- Some apps and sites will lose functionality. That is what blocking means.
- If a resolver is unreachable, DNS fails rather than falling back to the network's own
  resolver. That is deliberate: the alternative is silently handing your queries to
  whatever DNS an unknown Wi-Fi network offers.
- Network-level filtering you run at home stops applying.
- Visual voicemail on Orange, T-Mobile, Videotron and EE is excluded so it keeps working.

Removable at any time: Settings > General > VPN & Device Management.
"""


def dns_payload(key: str, resolver: dict, suffix: str, domains=None, carrier_bypass=False,
                allow_failover=False) -> dict:
    """One encrypted-DNS payload.

    `domains` is None for the catch-all. Apple: "If not set, all domains use the DNS
    server" — so exactly one payload may omit it, which the build asserts.
    """
    settings = {
        "DNSProtocol": "HTTPS",
        "ServerURL": resolver["url"],
        "ServerAddresses": resolver["v4"] + resolver["v6"],
        # iOS 26+. False is Apple's default; set explicitly so a future default change
        # cannot quietly turn this into a leak. Ignored on earlier iOS.
        "AllowFailover": allow_failover,
    }
    if domains is not None:
        settings["SupplementalMatchDomains"] = domains

    payload = {
        "PayloadType": "com.apple.dnsSettings.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{BASE_ID}.dns.{suffix}",
        "PayloadUUID": str(uuid.uuid5(NS, f"{BASE_ID}.dns.{suffix}")).upper(),
        "PayloadDisplayName": (
            f"DNS — {resolver['name']}"
            + (f" ({len(domains)} ad/tracker domains)" if domains is not None else " (everything else)")
        ),
        "PayloadDescription": resolver["blocks"],
        "DNSSettings": settings,
    }
    if carrier_bypass:
        payload["OnDemandRules"] = [
            {
                "Action": "EvaluateConnection",
                "ActionParameters": [{"DomainAction": "NeverConnect", "Domains": CARRIER_BYPASS}],
            },
            {"Action": "Connect"},
        ]
    return payload


def web_filter_payload(deny_urls: list[str], auto_filter: bool) -> dict:
    """Safari/WebKit URL filtering.

    Verified unsupervised-legal against Apple's own documentation, which lists
    "Requires supervision: N/A" and "Allow manual install: iOS" for this payload — worth
    checking, because several hardening guides list it as supervised-only.

    Its reach is narrower than DNS: it filters web content, not every app's traffic.
    """
    payload = {
        "PayloadType": "com.apple.webcontent-filter",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{BASE_ID}.webfilter",
        "PayloadUUID": str(uuid.uuid5(NS, f"{BASE_ID}.webfilter")).upper(),
        "PayloadDisplayName": "Web content filter (Safari and WebKit only)",
        "PayloadDescription": "URL-level deny list. Does not cover non-web app traffic.",
        "FilterType": "BuiltIn",
        "AutoFilterEnabled": auto_filter,
    }
    if deny_urls:
        payload["DenyListURLs"] = deny_urls
    return payload


def ikev2_payload(server: str, remote_id: str, local_id: str) -> dict:
    """An IKEv2 VPN.

    IKEv2 is the only VPN an iPhone can run with no app installed, because the IPsec stack
    is part of iOS. WireGuard and every packet-tunnel provider need an app, which is why
    this is the shape a no-app VPN has to take.

    It still needs a server. There is no such thing as a VPN without one, and a profile
    that pretended otherwise would be an inert file with a reassuring name.
    """
    return {
        "PayloadType": "com.apple.vpn.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{BASE_ID}.vpn",
        "PayloadUUID": str(uuid.uuid5(NS, f"{BASE_ID}.vpn")).upper(),
        "PayloadDisplayName": f"VPN — {server}",
        "UserDefinedName": "DNS Firewall VPN",
        "VPNType": "IKEv2",
        "IKEv2": {
            "RemoteAddress": server,
            "RemoteIdentifier": remote_id,
            "LocalIdentifier": local_id,
            # Certificate authentication. A shared secret would be simpler and is a
            # materially worse idea for a profile that may be shared or synced.
            "AuthenticationMethod": "Certificate",
            "ExtendedAuthEnabled": False,
            "EnablePFS": True,
            "IKESecurityAssociationParameters": {
                "EncryptionAlgorithm": "AES-256-GCM",
                "IntegrityAlgorithm": "SHA2-384",
                "DiffieHellmanGroup": 20,
                "LifeTimeInMinutes": 1440,
            },
            "ChildSecurityAssociationParameters": {
                "EncryptionAlgorithm": "AES-256-GCM",
                "IntegrityAlgorithm": "SHA2-384",
                "DiffieHellmanGroup": 20,
                "LifeTimeInMinutes": 1440,
            },
        },
        "OnDemandEnabled": 1,
        "OnDemandRules": [{"Action": "Connect"}],
        # iOS 14+, not supervised-only: greys out the Connect On Demand toggle.
        "OnDemandUserOverrideDisabled": 1,
    }


def build(args) -> dict:
    catchall = RESOLVERS[args.catchall]
    aggressive = RESOLVERS[args.aggressive]

    payloads = [
        # Order matters only for readability on the device; iOS matches by domain.
        dns_payload(args.aggressive, aggressive, "aggressive", domains=AD_AND_TRACKER_DOMAINS,
                    allow_failover=args.allow_failover),
        dns_payload(args.catchall, catchall, "catchall", domains=None, carrier_bypass=True,
                    allow_failover=args.allow_failover),
    ]

    if args.web_filter:
        payloads.append(web_filter_payload(args.deny_url, args.auto_filter))

    if args.ikev2_server:
        payloads.append(
            ikev2_payload(args.ikev2_server, args.ikev2_remote_id or args.ikev2_server,
                          args.ikev2_local_id or "iphone")
        )

    return {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": BASE_ID,
        "PayloadUUID": str(uuid.uuid5(NS, BASE_ID)).upper(),
        "PayloadDisplayName": f"DNS Firewall — {catchall['name']} + {aggressive['name']}",
        "PayloadDescription": "Encrypted, filtering DNS split across two resolvers.",
        "PayloadOrganization": args.organization,
        "PayloadScope": "System",
        "PayloadRemovalDisallowed": False,
        "ConsentText": {
            "default": CONSENT.format(catchall=catchall["name"], aggressive=aggressive["name"])
        },
        "PayloadContent": payloads,
    }


def validate(path: Path, args) -> None:
    parsed = plistlib.loads(path.read_bytes())

    for p in [parsed] + parsed["PayloadContent"]:
        assert p["PayloadVersion"] == 1, "PayloadVersion is the plist format version, always 1"
        for trap in TRAPS:
            assert trap not in p, f"trap key present: {trap}"

    ids = [p["PayloadIdentifier"] for p in parsed["PayloadContent"]]
    assert len(ids) == len(set(ids)), "duplicate payload identifiers"

    dns = [p for p in parsed["PayloadContent"] if p["PayloadType"] == "com.apple.dnsSettings.managed"]
    assert len(dns) >= 2, "a split needs at least two resolvers"

    # THE invariant. A payload with no SupplementalMatchDomains claims every domain; two of
    # them would leave which resolver wins undefined, and none would leave most traffic on
    # the network's own DNS.
    catchalls = [p for p in dns if "SupplementalMatchDomains" not in p["DNSSettings"]]
    assert len(catchalls) == 1, (
        f"exactly one catch-all DNS payload required, found {len(catchalls)}"
    )

    for p in dns:
        s = p["DNSSettings"]
        assert s["DNSProtocol"] == "HTTPS"
        assert s["ServerURL"].startswith("https://")
        assert s["ServerAddresses"], "bootstrap addresses are required, or resolving the resolver needs DNS"
        for addr in s["ServerAddresses"]:
            ipaddress.ip_address(addr)  # raises on anything that is not an IP
        if "SupplementalMatchDomains" in s:
            assert s["SupplementalMatchDomains"], "an empty match list routes nothing"
            assert not any(d.startswith(".") for d in s["SupplementalMatchDomains"])

    # The whole point of the catch-all is that it is the one that must not go down.
    catchall_key = args.catchall
    if RESOLVERS[catchall_key]["redundancy"] == LOW and not args.force:
        raise AssertionError(
            f"{RESOLVERS[catchall_key]['name']} is a low-redundancy operator "
            f"({RESOLVERS[catchall_key]['footprint']}). Putting it in the catch-all slot "
            f"means an outage takes DNS down for everything. Use a high-redundancy "
            f"resolver, or pass --force if you accept that."
        )

    assert parsed["PayloadRemovalDisallowed"] is False

    vpn = [p for p in parsed["PayloadContent"] if p["PayloadType"] == "com.apple.vpn.managed"]
    for p in vpn:
        # A packet-tunnel VPN needs an app. Only IKEv2 runs on the OS's own stack, so
        # anything else here would be a profile that installs and does nothing.
        assert p["VPNType"] == "IKEv2", "a no-app VPN on iOS can only be IKEv2"

    print(f"validated {path.name}")
    print(f"  payloads        {len(parsed['PayloadContent'])}")
    for p in dns:
        s = p["DNSSettings"]
        scope = (
            f"{len(s['SupplementalMatchDomains'])} domains"
            if "SupplementalMatchDomains" in s
            else "everything else"
        )
        print(f"    DNS  {s['ServerURL']:<48} {scope}")
    if vpn:
        print(f"    VPN  IKEv2 -> {vpn[0]['IKEv2']['RemoteAddress']}")
    if any(p["PayloadType"] == "com.apple.webcontent-filter" for p in parsed["PayloadContent"]):
        print("    Web  built-in content filter (Safari/WebKit only)")
    print(f"  catch-all       {RESOLVERS[catchall_key]['name']} "
          f"[{RESOLVERS[catchall_key]['redundancy']} redundancy]")
    print(f"  fail behaviour  {'falls back to network DNS' if args.allow_failover else 'fails closed'}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--catchall", choices=sorted(RESOLVERS), default="quad9",
                    help="resolver for everything not matched (default: quad9)")
    ap.add_argument("--aggressive", choices=sorted(RESOLVERS), default="adguard",
                    help="resolver for ad and tracker domains (default: adguard)")
    ap.add_argument("--allow-failover", action="store_true",
                    help="fall back to the network's DNS if the resolver is unreachable "
                         "(default: fail closed)")
    ap.add_argument("--web-filter", action="store_true",
                    help="add the Safari/WebKit URL deny list")
    ap.add_argument("--auto-filter", action="store_true",
                    help="with --web-filter, enable Apple's automatic adult-content filter "
                         "(restricts third-party browsers)")
    ap.add_argument("--deny-url", action="append", default=[],
                    help="URL substring to block; repeatable. Requires --web-filter")
    ap.add_argument("--ikev2-server", help="IKEv2 server hostname. You must run this server")
    ap.add_argument("--ikev2-remote-id")
    ap.add_argument("--ikev2-local-id")
    ap.add_argument("--organization", default="tellebo/iOS-Configuration-Profiles")
    ap.add_argument("--force", action="store_true",
                    help="allow a low-redundancy resolver as the catch-all")
    ap.add_argument("--list-resolvers", action="store_true")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()

    if args.list_resolvers:
        print(f"\n  {'KEY':<22} {'REDUNDANCY':<11} BLOCKS")
        print(f"  {'-' * 74}")
        for k, r in sorted(RESOLVERS.items(), key=lambda kv: (kv[1]["redundancy"] != HIGH, kv[0])):
            print(f"  {k:<22} {r['redundancy']:<11} {r['blocks']}")
            print(f"  {'':<22} {'':<11} {r['footprint']}")
        print()
        return

    if args.deny_url and not args.web_filter:
        raise SystemExit("--deny-url requires --web-filter")

    args.out.write_bytes(plistlib.dumps(build(args)))
    validate(args.out, args)
    print("\nplutil is macOS-only; this is a plistlib round-trip, not on-device proof.\n"
          "Install on a test device before relying on it.")


if __name__ == "__main__":
    main()
