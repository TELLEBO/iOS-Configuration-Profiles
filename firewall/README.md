# iOS DNS firewall — one profile, nothing else

No app. No server. No subscription. One `.mobileconfig` that filters every DNS query the
device makes, in every app, and splits those queries across resolvers so aggressive
blocking lands where it is safe and reliability covers everything else.

```bash
python3 build_profile.py                      # Quad9 catch-all, AdGuard for ad domains
python3 build_profile.py --list-resolvers
```

## First, the part that is not possible

**There is no defense against AI-guided traffic analysis in this profile, and there cannot
be one.**

Not "a weaker version". Not "partially". Zero. A configuration profile is declarative data
that iOS reads at install time — it has no code that runs. A traffic-analysis defense works
by padding every packet to a constant size, injecting cover traffic on a timer, and holding
real traffic back for bounded intervals. All three are things that happen *per packet, at
runtime*. There is no payload, key, or combination of payloads that can do any of them.

This is the same finding as [`../daita/`](../daita/), and it does not soften with effort.
If you want the actual defense, it needs code on both ends of the tunnel — that is
[`../dvpn/`](../dvpn/), which is built and measured, and it needs an app on iOS.

What encrypted DNS *does* remove is the plaintext DNS side channel: without it, every site
you visit is announced in the clear to the local network before you visit it. That is a
genuine and large win, and it is a different thing from flow-shape defense. Be clear with
yourself about which one you have.

## What the profile actually is

Three layers, only the first of which covers every app:

| Layer | Covers | Supervision |
|---|---|---|
| **Encrypted DNS** (2 payloads) | **Every app on the device**, by domain | None needed |
| Web content filter (optional) | Safari and WebKit only, by URL substring | None needed |
| IKEv2 VPN (optional) | IP-level, hides destinations from the local network | None needed, **but you must run the server** |

The DNS layer is the firewall. The other two are additions with real limits.

### Why the web content filter is here at all

Because it turns out not to be supervised-only. Apple's own documentation for
`com.apple.webcontent-filter` lists **"Requires supervision: N/A"** and **"Allow manual
install: iOS"** — which contradicts a good deal of published hardening guidance, including
the guidance this repository started from. It is off by default here because it only
filters web content, matches URLs by substring, and its `AutoFilterEnabled` option
restricts third-party browsers.

### Why the VPN is IKEv2 and needs a server

IKEv2 is the only VPN an iPhone can run with **no app installed**, because the IPsec stack
ships with iOS. WireGuard and every other packet-tunnel provider require an app — a VPN
payload naming one that is not installed produces a profile that installs cleanly and does
nothing, which is the exact failure [`../daita/`](../daita/) documents.

And it still needs a server. There is no VPN without one. The profile can carry the client
half; you provide the other.

## How the split works, and what it does not buy you

```
  ad / tracker / analytics domains  ──▶  AdGuard DNS        (aggressive, blocks them)
  everything else                   ──▶  Quad9 Secured      (reliable, blocks malware)
```

Apple's `SupplementalMatchDomains` decides which resolver sees which query: *"If not set,
all domains use the DNS server."* So exactly one payload omits it and becomes the
catch-all, and the build **asserts** that — two catch-alls would leave the winner undefined,
and none would leave most traffic on the network's own DNS.

**Splitting does not stack blocklists.** A query goes to exactly one resolver. Routing a
domain to a second blocker does not add its rules to the first. What the split actually
buys:

- **Aggressive blocking where breakage is the point.** Ad and attribution domains are sent
  to a resolver tuned to break them, while the rest of your traffic never touches it.
- **A smaller blast radius per operator.** If the aggressive resolver has an outage, ads
  resolve again but the internet still works. The reverse would be far worse — which is
  precisely why the catch-all slot has a redundancy requirement.

The domain list is 47 entries in `resolvers.py`, chosen so that blocking them is the
intended outcome rather than collateral. Login, push-notification and payment endpoints are
deliberately absent: `graph.facebook.com` and `onesignal.com` are tempting and belong on
nobody's default list.

## Choosing for uptime

You asked for the best uptime, so two things need saying plainly.

**I could not measure it.** Every DoH endpoint is blocked from the environment this was
built in, so there are no latency or availability numbers here that I collected. What I
could verify is which addresses are live right now and what each operator's anycast
footprint is — and footprint is what actually determines uptime.

| Resolver | Redundancy | Footprint |
|---|---|---|
| Cloudflare Security / Family | **high** | 300+ cities, 100+ countries |
| Quad9 Secured | **high** | 150+ anycast locations, Swiss non-profit, DNSSEC validating |
| AdGuard DNS | medium | 60+ anycast locations |
| DNSforge base / hard | **low** | single German operator, Hetzner-hosted, two addresses per tier |

**DNSforge is the weakest choice on this axis.** Its blocklists are good and its `hard`
tier is the most aggressive option here, but it is one operator on one hosting provider.
That is fine for the ad-domain slice, where failure means ads come back. It is a poor
choice for the catch-all, where failure means no DNS at all — so the build refuses it in
that slot unless you pass `--force`, and says why.

Two things also worth knowing, both found while checking rather than assumed:

- **dns0.eu is dead.** It appears on most current "best DNS" lists. It shut down for
  sustainability reasons, and `zero.dns0.eu` no longer resolves.
- **Published address lists go stale.** Several still give `176.9.93.198` and `176.9.1.117`
  for DNSforge base; `dnsforge.de` has not pointed there for some time. Every address in
  `resolvers.py` was resolved live on 2026-09-13, and the method was validated against two
  fixed points — `dns.quad9.net` and `hard.dnsforge.de` both match their operators' own
  CMS-signed profiles exactly.

To measure for yourself, from the device's own network: `dnscheck` or `dnsperftest`, run at
the times and places you actually use the phone. Anycast means your nearest instance is the
only one that matters, and no published median predicts it.

### Fail closed, and the tension with uptime

`AllowFailover` is set to `false` (iOS 26+; it is also Apple's default). If your resolver is
unreachable, **DNS fails** rather than falling back to whatever the network offers. That is
the right default for a firewall — the fallback is silently handing every query to an
unknown Wi-Fi network's DNS — but it means resolver availability *is* your availability.
That is the second reason the catch-all slot is guarded.

`--allow-failover` reverses it if you would rather have working DNS than private DNS.

## What it cannot block

- **An app connecting to a raw IP address.** No DNS query, no filtering. This is how a
  determined tracker with hardcoded addresses gets through, and it is the ceiling on every
  DNS-based firewall.
- **By port or protocol.** iOS exposes no profile payload for that.
- **Traffic inside an app that ships its own resolver.** Some apps do DoH themselves; the
  system resolver never sees it.
- **Anything about packet sizes or timing.** See the top of this file.

## Options

| Flag | Effect |
|---|---|
| `--catchall KEY` | resolver for unmatched domains (default `quad9`) |
| `--aggressive KEY` | resolver for ad/tracker domains (default `adguard`) |
| `--allow-failover` | fall back to network DNS instead of failing closed |
| `--web-filter` | add the Safari/WebKit URL deny list |
| `--auto-filter` | with `--web-filter`, enable Apple's adult-content filter (restricts other browsers) |
| `--deny-url URL` | URL substring to block; repeatable |
| `--ikev2-server HOST` | add an IKEv2 VPN payload pointing at your server |
| `--force` | permit a low-redundancy resolver as the catch-all |

The build asserts `PayloadVersion == 1` throughout, absence of trap keys, exactly one
catch-all, non-empty match lists, that every bootstrap address parses as an IP, that DoH
URLs are HTTPS, that any VPN payload is IKEv2 (nothing else works without an app), and the
catch-all redundancy requirement.

## Install

1. AirDrop or email the `.mobileconfig` to the device.
2. **Settings → General → VPN & Device Management → Downloaded Profile → Install.**
3. It is unsigned, so iOS shows **"Not Verified"**. Expected for a self-built profile; it is
   plain XML, so read it first.
4. Verify: **Settings → General → VPN & Device Management** lists it, and
   **Settings → Wi-Fi → (i)** shows DNS configured by a profile.
5. Test blocking by visiting a domain from the list — it should fail to resolve rather than
   load slowly.

If you also use **Lockdown Mode**, install and verify profiles *first*: Lockdown Mode
blocks profile installation.

## Sources

- [apple/device-management](https://github.com/apple/device-management) — `com.apple.dnsSettings.managed.yaml` (`multiple: true`, `supervised: false`), `com.apple.webcontent-filter.yaml`
- [Apple: WebContentFilter](https://developer.apple.com/documentation/devicemanagement/webcontentfilter) — the supervision row
- [Apple: DNSSettings](https://developer.apple.com/documentation/devicemanagement/dnssettings)
- [dns0.eu shutdown](https://www.bleepingcomputer.com/news/security/dns0eu-private-dns-service-shuts-down-over-sustainability-issues/)
- [Quad9DNS/documentation](https://github.com/Quad9DNS/documentation) — signed profile used as a fixed point
