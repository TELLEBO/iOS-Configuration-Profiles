"""Resolver catalogue.

Every address here was resolved live on 2026-09-13, not copied from a published list.
That matters more than it sounds: several widely-circulated lists still give
176.9.93.198 / 176.9.1.117 for DNSforge base, which is not where `dnsforge.de` points
any more, and dns0.eu appears on most "best DNS" lists despite having shut down.

The method was validated against two independent fixed points: `dns.quad9.net` and
`hard.dnsforge.de` both resolve to exactly the addresses in their operators' own
CMS-signed configuration profiles.

`redundancy` is what actually determines uptime, and it is the reason this file records
anycast footprint rather than marketing copy. It is used as a build assertion: a
low-redundancy operator is refused in the catch-all slot unless explicitly forced.
"""

HIGH = "high"       # global anycast, many independent sites
MEDIUM = "medium"   # anycast, smaller footprint
LOW = "low"         # single operator, few sites

RESOLVERS = {
    "quad9": {
        "name": "Quad9 Secured",
        "url": "https://dns.quad9.net/dns-query",
        "v4": ["9.9.9.9", "149.112.112.112"],
        "v6": ["2620:fe::fe", "2620:fe::9"],
        "redundancy": HIGH,
        "footprint": "150+ anycast locations, Swiss non-profit",
        "blocks": "Malware and phishing. DNSSEC validating. No ad blocking.",
        "breakage": "very low",
    },
    "cloudflare-security": {
        "name": "Cloudflare Security",
        "url": "https://security.cloudflare-dns.com/dns-query",
        "v4": ["1.1.1.2", "1.0.0.2"],
        "v6": ["2606:4700:4700::1112", "2606:4700:4700::1002"],
        "redundancy": HIGH,
        "footprint": "300+ cities, 100+ countries — the largest anycast network here",
        "blocks": "Malware. No ad blocking.",
        "breakage": "very low",
    },
    "cloudflare-family": {
        "name": "Cloudflare Family",
        "url": "https://family.cloudflare-dns.com/dns-query",
        "v4": ["1.1.1.3", "1.0.0.3"],
        "v6": ["2606:4700:4700::1113", "2606:4700:4700::1003"],
        "redundancy": HIGH,
        "footprint": "300+ cities, 100+ countries",
        "blocks": "Malware and adult content.",
        "breakage": "low",
    },
    "adguard": {
        "name": "AdGuard DNS",
        "url": "https://dns.adguard-dns.com/dns-query",
        "v4": ["94.140.14.14", "94.140.15.15"],
        "v6": ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
        "redundancy": MEDIUM,
        "footprint": "60+ anycast locations",
        "blocks": "Ads, trackers and malware. The aggressive option that still runs anycast.",
        "breakage": "moderate — some apps and sites lose functionality",
    },
    "adguard-family": {
        "name": "AdGuard Family",
        "url": "https://family.adguard-dns.com/dns-query",
        "v4": ["94.140.14.15", "94.140.15.16"],
        "v6": ["2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff"],
        "redundancy": MEDIUM,
        "footprint": "60+ anycast locations",
        "blocks": "Ads, trackers, malware, adult content. SafeSearch forced.",
        "breakage": "moderate to high",
    },
    "dnsforge-base": {
        "name": "DNSforge base",
        "url": "https://dnsforge.de/dns-query",
        "v4": ["49.12.67.122", "91.99.154.175"],
        "v6": ["2a01:4f8:c013:29d::122", "2a01:4f8:c010:8c35::175"],
        "redundancy": LOW,
        "footprint": "single German operator, Hetzner-hosted, two addresses per tier",
        "blocks": "Ads, trackers, malware.",
        "breakage": "moderate",
    },
    "dnsforge-hard": {
        "name": "DNSforge hard",
        "url": "https://hard.dnsforge.de/dns-query",
        "v4": ["49.12.222.213", "88.198.122.154"],
        "v6": ["2a01:4f8:c17:2c61::213", "2a01:4f8:c013:5ec0::154"],
        "redundancy": LOW,
        "footprint": "single German operator, Hetzner-hosted, two addresses per tier",
        "blocks": "~2.8M domains, no allowance for breakage.",
        "breakage": "high — by design",
    },
}

# Ad, tracker and mobile-attribution domains routed to the aggressive resolver.
#
# Chosen so that blocking them is the *intended* outcome rather than collateral. Domains
# that break sign-in, push notifications or payments are deliberately absent: graph.facebook.com
# (Facebook login), onesignal.com (push delivery) and the like belong on nobody's default
# list, however tempting.
#
# A bare domain matches its subdomains — Apple: "both *.example.com and example.com match
# against mydomain.example.com" — so there is no need to enumerate hosts.
AD_AND_TRACKER_DOMAINS = [
    # Ad exchanges and serving
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "adnxs.com",
    "adsrvr.org",
    "criteo.com",
    "criteo.net",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "casalemedia.com",
    "bidswitch.net",
    "smartadserver.com",
    "teads.tv",
    "moatads.com",
    "33across.com",
    # Content recommendation / chumbox
    "taboola.com",
    "outbrain.com",
    # Web analytics
    "google-analytics.com",
    "googletagmanager.com",
    "scorecardresearch.com",
    "quantserve.com",
    "hotjar.com",
    "mouseflow.com",
    "fullstory.com",
    "smartlook.com",
    "crazyegg.com",
    # Mobile attribution and product analytics
    "appsflyer.com",
    "adjust.com",
    "branch.io",
    "kochava.com",
    "singular.net",
    "app-measurement.com",
    "amplitude.com",
    "mixpanel.com",
    "segment.io",
    "segment.com",
    "braze.com",
    "clevertap.com",
    # In-app advertising SDKs
    "applovin.com",
    "adcolony.com",
    "vungle.com",
    "chartboost.com",
    "inmobi.com",
    "supersonicads.com",
    # Social tracking pixels (login endpoints deliberately excluded)
    "connect.facebook.net",
    "an.facebook.com",
]
