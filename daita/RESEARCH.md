# DAITA — research notes

Research date: 2026-09-12. Primary sources are linked at the bottom; claims about the
Mullvad iOS client are cited to the app source at `mullvad/mullvadvpn-app` (`main`,
marketing version 2026.6).

## What DAITA is

DAITA — Defense against AI-guided Traffic Analysis — is a feature of the Mullvad VPN
client. A VPN encrypts packet contents but not their *shape*: sizes, timings, directions
and bursts survive encryption, and a machine-learning classifier trained on those features
can identify which website you loaded from the outside of the tunnel. This is website
fingerprinting. DAITA attacks the feature set the classifier depends on.

It was developed with the Computer Science department at Karlstad University and is built
on **Maybenot**, an open-source, peer-reviewed traffic-analysis defense framework that
Mullvad funds.

Three techniques:

1. **Constant packet sizes** — every packet leaving over the tunnel is padded to the same
   size, so small packets (which are unusually revealing) stop being distinguishable.
2. **Random background traffic** — dummy packets are interspersed unpredictably, masking
   the routine chatter a device emits when idle.
3. **Data-pattern distortion** — during bursts of real activity, cover traffic is injected
   in both directions to blur the load pattern of a page visit.

Maybenot expresses these as *padding machines*: small state machines that react to
tunnel events by emitting padding or blocking. Both the client and the relay run them, so
a DAITA connection requires a DAITA-capable relay on the other end.

## Cost

Padding and cover traffic are real bytes. Mullvad's own guidance: DAITA increases network
traffic and battery usage, which matters on metered cellular plans. This is the tradeoff —
DAITA buys shape-obfuscation with bandwidth.

## iOS timeline

From the Mullvad iOS changelog (`ios/CHANGELOG.md`):

| Version | Date | Change |
|---|---|---|
| 2024.7 | 2024-09-16 | DAITA setting added to the iOS app |
| 2024.9 | 2024-11-07 | "DAITA everywhere, using multihop" — route via a DAITA relay when the chosen exit lacks support |
| 2025.1 | 2025-01-14 | **DAITA v2**: padding machines provided dynamically by the relay instead of bundled in the app |
| 2025.2–2025.3 | 2025 | DAITA settings view fixed on iOS 15; DAITA-for-multihop fix. (Mullvad separately published an advisory about a DAITA bug in iOS 2025.1/2025.2 — update past those.) |
| 2026.4 | 2026-08 | Multihop modes (When needed / Always / Never) ship on iOS first |
| current | 2026 | "Remove *Direct only* from Daita" — the old DAITA-direct-only toggle is replaced by Multihop modes |

Two practical consequences of DAITA v2 and Multihop modes:

- Because machines come from the relay, DAITA behaviour can change without an app update,
  and the relay must support it.
- Not every server is DAITA-capable. With Multihop set to **When needed** (the default),
  the app automatically routes through a nearby DAITA-capable server when your chosen exit
  location does not support the feature. Setting Multihop to **Never** can therefore leave
  DAITA inactive at exits that lack support.

DAITA requires WireGuard. It is not available for OpenVPN, and on iOS the Mullvad app is
WireGuard-only anyway.

## Where the setting actually lives

This is the crux of whether a configuration profile can touch it.

`ios/MullvadSettings/DAITASettings.swift` defines:

```swift
public enum DAITAState: Codable, Sendable { case on, off }

public struct DAITASettings: Codable, Equatable, Sendable {
    public var daitaState: DAITAState
    ...
}
```

`DAITASettings` is a field of `TunnelSettings` (currently `TunnelSettingsV8`), and
`TunnelSettings` is persisted by `SettingsManager` (`ios/MullvadSettings/SettingsManager.swift`):

```swift
private let keychainServiceName = "Mullvad VPN"

public init(store: SettingsStore? = nil) {
    self.store = store ?? KeychainSettingsStore(
        serviceName: keychainServiceName,
        accessGroup: ApplicationConfiguration.securityGroupIdentifier
    )
}
```

So DAITA's on/off state is a JSON-encoded field inside a **keychain item in Mullvad's own
keychain access group**, shared between the app and its packet-tunnel extension. It is not
a preference domain, not a plist in the app container, and not anything MDM writes to.

The tunnel configuration the app hands iOS (`ios/MullvadVPN/TunnelManager/TunnelConfiguration.swift`)
confirms the direction of control:

```swift
let protocolConfig = NETunnelProviderProtocol()
protocolConfig.providerBundleIdentifier = ApplicationTarget.packetTunnel.bundleIdentifier
protocolConfig.serverAddress = ""
protocolConfig.includeAllNetworks = includeAllNetworks
protocolConfig.excludeLocalNetworks = excludeLocalNetworks
```

The app builds its own `NETunnelProviderProtocol` at runtime. It sets no
`providerConfiguration` — and a repo-wide grep for `providerConfiguration` across `ios/`
returns **zero** hits. Whatever a configuration profile puts in a VPN payload's
`VendorConfig` would never be read.

Note also `includeAllNetworks` and on-demand (`NEOnDemandRuleConnect` with
`interfaceTypeMatch = .any`): Mullvad already implements its own kill switch and always-on
behaviour internally, from its own settings.

## Sources

- [DAITA: Defense Against AI-guided Traffic Analysis](https://mullvad.net/en/vpn/daita) — Mullvad
- [Introducing Defense against AI-guided Traffic Analysis (DAITA)](https://mullvad.net/en/blog/introducing-defense-against-ai-guided-traffic-analysis-daita) — Mullvad, 2024-05-07
- [DAITA now available on iOS](https://mullvad.net/en/blog/defense-against-ai-guided-traffic-analysis-daita-now-available-on-ios) — Mullvad, 2024-09-24
- [DAITA bug in iOS app versions 2025.1 and 2025.2](https://mullvad.net/en/blog/daita-bug-in-ios-app-versions-20251-and-20252) — Mullvad
- [Introducing Multihop modes](https://mullvad.net/en/blog/introducing-multihop-modes) — Mullvad, 2026-08-24
- [Maybenot: A Framework for Traffic Analysis Defenses](https://arxiv.org/pdf/2304.09510) — Pulls & Witwer
- [mullvad/mullvadvpn-app](https://github.com/mullvad/mullvadvpn-app) — `ios/MullvadSettings/`, `ios/MullvadVPN/TunnelManager/`, `ios/CHANGELOG.md`
