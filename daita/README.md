# DAITA on iPhone — what a configuration profile can and cannot do

**Verdict: no `.mobileconfig` can enable or enforce Mullvad DAITA on an iPhone, supervised
or not.** DAITA is a setting inside the Mullvad app, stored in Mullvad's own keychain
access group, and Apple exposes no profile payload that reaches into a third-party app's
tunnel settings. Any profile claiming to "enforce DAITA" is shipping inert keys.

The background research is in [RESEARCH.md](RESEARCH.md). What actually turns DAITA on is
the [manual runbook](#the-runbook-that-actually-enforces-daita) below — it takes about a
minute. The profile in this directory covers the one adjacent thing that *is*
profile-enforceable: encrypted DNS.

## Why it cannot be done — the three mechanisms, each checked

### 1. VPN payload with a vendor configuration — inert

`com.apple.vpn.managed` can target a third-party VPN app: `VPNType=VPN`, `VPNSubType` set
to the app's bundle identifier, `ProviderBundleIdentifier` set to its packet-tunnel
extension, and a `VendorConfig` dictionary of app-specific settings. Per Apple's schema,
`VendorConfig` is "the vendor-specific configuration dictionary, which the system reads
only when `VPNSubType` has a value" — the system *delivers* it; the app decides whether to
read it.

Mullvad's iOS app never reads it. A grep for `providerConfiguration` across `ios/` in
`mullvad/mullvadvpn-app` returns zero hits; the app constructs its own
`NETunnelProviderProtocol` at runtime and loads tunnel settings — DAITA included — from its
keychain store. A profile-delivered VPN payload would also create a *second, separate* VPN
configuration that has none of the app's account or device state.

**This is the trap to avoid.** It installs cleanly, shows up in Settings, and does nothing.

### 2. Always On VPN — wrong protocol, and not for third-party tunnels

`VPNType=AlwaysOn` restricts `TunnelConfigurations` → `ProtocolType` to a `rangelist` of
exactly one value: `IKEv2`. Mullvad on iOS is WireGuard-only. Always On cannot carry a
packet-tunnel provider at all, so it cannot keep a DAITA tunnel up, let alone enable DAITA.

(Mullvad already implements this itself: its `TunnelConfiguration` sets
`includeAllNetworks` — Apple's kill-switch flag — plus an on-demand `Connect` rule matching
any interface. Use the app's own toggles, not a profile.)

### 3. Managed app configuration — blocked three times over

The modern path is the `com.apple.configuration.app.managed` declaration and its
`AppConfig` dictionary. It fails on every gate:

- it is a **declarative-management declaration**, delivered by an enrolled MDM server, not
  something a downloaded `.mobileconfig` can carry;
- the app must be **MDM-managed** (installed or taken over by the MDM);
- the app must **read** the configuration — Mullvad's iOS source contains no reference to
  `com.apple.configuration.managed` or any managed-app-config API.

Even a full MDM enrolment could not set DAITA, because the third condition is the app
vendor's to implement and Mullvad has not.

I also checked Apple's full declarative configuration catalogue (`apple/device-management`,
`release` branch): there is no VPN configuration and no third-party-app settings
declaration.

## The runbook that actually enforces DAITA

On the device, in the Mullvad app (2026.4 or later):

1. **Settings → VPN settings → DAITA → On.**
2. **Settings → VPN settings → Multihop → When needed** (the default). This is what makes
   DAITA apply at exit locations whose servers do not support it. Setting Multihop to
   *Never* can silently leave DAITA inactive at such exits.
3. **Settings → VPN settings → Kill switch / Include all networks → On.** DAITA only
   protects traffic inside the tunnel; this stops traffic leaving outside it.
4. Keep auto-connect / on-demand enabled so the tunnel comes back by itself.
5. Stay current. DAITA v2 pulls its padding machines from the relay, and Mullvad published
   an advisory about a DAITA bug specific to iOS 2025.1–2025.2.

To verify it is live rather than trusting the toggle: connect, then watch the app's
connection panel — a DAITA connection reports the feature as active and, when the exit
lacks support, shows the multihop entry relay it routed through. Data usage rising while
the device is idle is the expected signature of DAITA's cover traffic.

Nothing in that list is reachable from a configuration profile. If you need it enforced
across a fleet, the enforcement point is a Mullvad feature request for managed app
configuration, not an Apple payload.

## The profile that ships here

`DAITA-Support-Encrypted-DNS.mobileconfig` — built by `build_profile.py`.

It is named for what it is. Its on-device display name is
**"DAITA Support — Encrypted DNS (does NOT enable DAITA)"** so it can never be mistaken
for the thing it is not.

**Rationale.** DAITA hides the *shape* of traffic inside the tunnel. Two things defeat that
in practice: DAITA being off (unreachable by profile), and traffic that never enters the
tunnel. While the Mullvad tunnel is down — booting, reconnecting, or switched off — DNS
queries go out in the clear and name every site you are about to visit, which is exactly
the information DAITA exists to obscure. That leak *is* profile-enforceable.

| Key | Payload | Effect | Status |
|---|---|---|---|
| `DNSProtocol` = `HTTPS` | `com.apple.dnsSettings.managed` | All DNS over DoH | **Binds now** (iOS 14+, unsupervised) |
| `ServerURL` = `https://dns.quad9.net/dns-query` | same | Quad9 Secured resolver — DNSSEC validation, malicious-domain blocking | **Binds now** |
| `ServerAddresses` | same | Bootstrap IPs so resolution does not depend on resolving the resolver | **Binds now** |
| `AllowFailover` = `false` | same | No silent fallback to system DNS | **Binds on iOS 26+**; ignored below |
| `OnDemandRules` → `NeverConnect` | same | Carrier visual-voicemail domains bypass DoH so voicemail keeps working | **Binds now** |
| `PayloadRemovalDisallowed` = `false` | profile | Removable from Settings | **Binds now** |

Scope is deliberately narrow: when the Mullvad tunnel is **up**, Mullvad's in-tunnel DNS
takes precedence and this payload does nothing. It matters only when the tunnel is down.

**Why Quad9 and not Mullvad's resolver:** Mullvad is shutting down its public encrypted DNS
servers on **2026-11-02** and sponsoring Quad9 instead; their own `.mobileconfig` files stop
working on that date. The Quad9 endpoint and bootstrap addresses here were taken from
Quad9's own signed profile, not from memory. `build_profile.py --resolver mullvad` still
emits the Mullvad variant if you need it before the cutoff. (This affects only Mullvad's
*public* resolvers — DNS inside the VPN tunnel is unaffected.)

**Known side effects**, also stated in the profile's consent text: network-level filtering
on your own LAN stops applying; captive portals and carriers other than the four excluded
may misbehave. Encrypted DNS is **not** a kill switch — on iOS 25 and earlier, do not
assume DNS fails closed when the resolver is unreachable.

## Keys deliberately excluded

| Key / approach | Why not |
|---|---|
| `com.apple.vpn.managed` with `VendorConfig` | Inert — Mullvad never reads `providerConfiguration`. Would look like it works. |
| `VPNType=AlwaysOn` | IKEv2-only; cannot carry a WireGuard packet-tunnel provider. |
| `allowVPNCreation` = `false` | Supervised-only, and actively harmful here — it blocks creating VPN configurations, which is what the Mullvad app needs to do. |
| On-demand VPN to an unroutable address as a kill switch | Only one VPN configuration is active at a time; a blackhole on-demand rule fights Mullvad's own on-demand rule. Use the app's "Include all networks" instead. |
| `allowAppRemoval` = `false` | Supervised-only, and global — it blocks removing *every* app, which is a large usability cost that still does not protect the DAITA toggle. Documented below rather than shipped. |
| `allowCloudPrivateRelay` = `false` | A trap key: setting it *disables* iCloud Private Relay. Left at its default. |

## If the device is supervised

Supervision does not unlock DAITA — no profile setting exists at any privilege level. What
it can do is protect the *deployment* so a user cannot quietly undo it. These are
**supervised-armed**: on a normal iPhone they bind nothing, which is why they are not in
the shipped profile. Add them yourself only with the cost understood:

- `allowAppRemoval = false` — stops the Mullvad app being deleted. Blocks deleting all
  other apps too.
- `allowUIConfigurationProfileInstallation = false` — stops a competing profile being added.
- Profile-removal password (supervised-only on iOS) — stops this profile being removed.

Do not set `PayloadRemovalDisallowed = true` without a removal-password payload: the
profile can become unremovable short of erasing the device.

## Install

1. Get `DAITA-Support-Encrypted-DNS.mobileconfig` onto the iPhone — AirDrop, or email it to
   yourself and tap the attachment.
2. **Settings → General → VPN & Device Management → Downloaded Profile → Install.**
3. It is unsigned, so iOS shows **"Not Verified"**. That is expected for a self-built
   profile; verify the contents yourself before installing (it is plain XML — read it).
4. Confirm: **Settings → General → VPN & Device Management** lists the profile, and
   **Settings → Wi-Fi → (i)** shows DNS as configured by a profile.
5. Then do the [manual DAITA runbook](#the-runbook-that-actually-enforces-daita) — the
   profile does not do it for you.

Remove at any time from the same Settings pane.

If you also use **Lockdown Mode**, install and verify profiles *first*: Lockdown Mode
blocks configuration-profile installation.

## Rebuilding

```
python3 build_profile.py                      # Quad9 (default)
python3 build_profile.py --resolver mullvad   # pre-2026-11-02 only
```

UUIDs are derived deterministically from the payload identifiers, so rebuilds are
byte-identical and the artifact stays diffable. The build asserts `PayloadVersion == 1`
everywhere, that no trap key is present, and that no VPN payload has crept in. `plutil` is
macOS-only; this is a `plistlib` round-trip, which is structural validation, **not**
on-device proof. Test on a device you can afford to reset.

## Sources

- [Apple: VPN payload (`com.apple.vpn.managed`)](https://developer.apple.com/documentation/devicemanagement/vpn) and [`VPN.AlwaysOn`](https://developer.apple.com/documentation/devicemanagement/vpn/alwayson-data.dictionary)
- [apple/device-management](https://github.com/apple/device-management) — `mdm/profiles/com.apple.dnsSettings.managed.yaml`, `com.apple.vpn.managed.yaml`, `com.apple.applicationaccess.yaml`, `declarative/declarations/configurations/app.managed.yaml` (`release` branch)
- [mullvad/mullvadvpn-app](https://github.com/mullvad/mullvadvpn-app) — `ios/MullvadSettings/DAITASettings.swift`, `SettingsManager.swift`, `ios/MullvadVPN/TunnelManager/TunnelConfiguration.swift`, `ios/CHANGELOG.md`
- [mullvad/encrypted-dns-profiles](https://github.com/mullvad/encrypted-dns-profiles) — shutdown notice
- [Shutting down our public encrypted DNS servers and sponsoring Quad9 instead](https://mullvad.net/en/blog/shutting-down-our-public-encrypted-dns-servers-and-sponsoring-quad9-instead) — Mullvad, 2026-09-03
- [Quad9DNS/documentation](https://github.com/Quad9DNS/documentation) — `docs/assets/mobileconfig/Quad9_Secured_DNS_over_HTTPS_20260119.mobileconfig`, source of the verified endpoint and bootstrap addresses
