# TAD — a profile-enforceable traffic-analysis defense for a VPN you operate

DAITA's architecture, rebuilt as an independent feature, with the one addition that makes
it enforceable from a configuration profile: **the client reads the policy the profile
delivers.**

That is the whole trick. From [`../daita/`](../daita/): a profile cannot enable Mullvad's
DAITA because Mullvad's app never reads `providerConfiguration`. iOS delivers the
dictionary either way — the app decides whether to look. Build the app, and the mechanism
that was inert becomes the enforcement channel.

Read [ARCHITECTURE.md](ARCHITECTURE.md) before building anything. Two constraints there
decide whether this project is viable for you, and both are cheaper to learn now:

- **You must operate both ends.** Maybenot machines are client/server pairs.
  `interspace_client` with no peer running `interspace_server` emits *nothing* — it waits
  on `PaddingRecv` forever. This is asserted in the test suite, not assumed. You cannot
  bolt this onto someone else's VPN.
- **Cover traffic is real traffic.** It costs bandwidth and battery in proportion to how
  much it protects you.

## Status

Be clear-eyed about what is here. This is a working core and a design, not a shippable VPN.

| Component | State |
|---|---|
| `engine/` — policy + Maybenot integration + C ABI | **Built and tested.** 20 tests, `cargo test`, clippy clean |
| `engine/tests/defense_loop.rs` — two-endpoint simulator | **Built and tested.** Proves the two-sided and closed-loop requirements against the real machines |
| `ios/*.swift` — extension integration | **Not compiled.** No Swift toolchain or Apple SDK was available; reference integration code |
| `profile/` — the enforcing `.mobileconfig` | **Built and validated** structurally (plistlib round-trip). Ships with placeholder bundle IDs |
| Transport (WireGuard/QUIC), constant packet size | **Not implemented.** `TadTransport` is the seam where it goes |
| Server side | **Not implemented.** The engine runs there (`Role::Server`); the daemon around it does not exist |

## The engine

```
cd engine
cargo test          # 20 tests
cargo clippy --all-targets
cargo build --release
```

Three defense levels, each a machine set from [`maybenot-machines`](https://github.com/maybenot-io/maybenot):

| Level | Client machines | Server machines | Needs a peer? | Defends WF? |
|---|---|---|---|---|
| `light` | `netflow` | — | No | No — coarsens NetFlow records only |
| `moderate` | `interspace_client` | `interspace_server` | **Yes** | Yes, general purpose |
| `heavy` | `scrambler_client` | `scrambler_server` | **Yes** | Yes, aimed at strong-shape traffic (video, large loads) |

`light` is the honest cheap option: it needs no peer and correspondingly does not defend
against website fingerprinting. Do not deploy it and tell users they are protected from it.

### Enforcement semantics

- A profile sets a **floor**. Raising above it is always allowed; lowering is **refused**,
  never silently clamped, so the UI can explain which control is locked.
- Only `source: "profile"` may set `enforced`. An app's own settings screen claiming
  enforcement over its user is rejected (`EnforcedWithoutProfile`).
- `require_peer_support` (default on) **fails closed**: rather than run a peer-dependent
  level against a server that cannot hold up its half, the connection is refused. A tunnel
  the user believes is defended and is not is worse than no tunnel.

## The profile

One profile, three effects. After installing it: the VPN turns itself on and stays on, DNS
goes to DNSforge hard over DoH, and traffic inside the tunnel is shaped by the defense at
`moderate` or above.

```
cd profile
python3 build_profile.py \
    --bundle-id com.yourco.vpn \
    --provider-bundle-id com.yourco.vpn.PacketTunnel \
    --endpoint vpn.yourco.com:51820 \
    --level moderate \
    --resolver dnsforge-hard
```

| Payload | What it does | Binds |
|---|---|---|
| `com.apple.vpn.managed` | VPN config, `ProviderType=packet-tunnel`, TAD policy + resolver in `VendorConfig` | iOS 4+ |
| ⤷ `OnDemandEnabled` + `OnDemandRules` | brings the tunnel up by itself | iOS 4+ |
| ⤷ `OnDemandUserOverrideDisabled` | greys out the Connect On Demand toggle in Settings | **iOS 14+, not supervised-only** |
| `com.apple.dnsSettings.managed` | DoH to the same resolver, for the window before the tunnel is up | iOS 14+ |

### Why the resolver is pinned twice

**An active VPN overrides `com.apple.dnsSettings.managed`.** Pinning DNS only there would
leave it inert exactly when the VPN is doing its job. So the resolver goes in two places:

- **`VendorConfig`** — the extension turns `TADDNSServerURL` / `TADDNSServerAddresses`
  into `NEDNSOverHTTPSSettings` on the tunnel's own network settings. While the VPN is up,
  DoH runs *inside* the tunnel: encrypted end-to-end to DNSforge, and shaped by the
  traffic-analysis defense on the way out. Your VPN server sees a DoH connection to
  DNSforge, not the names being resolved.
- **The DNS payload** — covers boot and reconnection, so DNS is never in the clear.

`build_profile.py` **asserts the two agree**. A profile whose fallback resolver differs
from its in-tunnel resolver is a bug, not a configuration.

The build also asserts `PayloadVersion == 1` throughout, that no trap key is present, that
`VPNSubType` is set (Apple's schema requires it when `VPNType` is `VPN`), that the
extension identifier sits under the app's, that the floor is not `off`, that on-demand is
enabled *and* pinned, and that the profile does not write the app's own origin nonce.

### About DNSforge hard

The endpoint and bootstrap addresses came from the signed `hard.dnsforge.de` profile —
CMS signature verified against a Let's Encrypt certificate for `CN=hard.dnsforge.de` —
not from memory.

**Hard mode filters aggressively**: ads, trackers and malware across roughly 2.8 million
domains, with no allowances made for breakage. Things will break, by design. When a site
or an app feature stops working, suspect the resolver first. `--resolver quad9` is the
conservative alternative (DNSSEC and malicious-domain blocking, no ad filtering).

Two further notes on that source profile:

- Its signing certificate expires **2026-11-02**. That does not affect an already-installed
  profile, but a fresh install after that date shows as unverified.
- If you were already using it standalone, **remove it** before installing this one. Two
  `com.apple.dnsSettings.managed` payloads configuring different resolvers is an ambiguous
  state, not a redundant one.

This profile is unsigned, so iOS shows "Not Verified" on install. That is expected for a
self-built profile; it is plain XML, so read it first.

**The shipped file carries placeholder bundle identifiers** and will install and do
nothing until you point it at your app. That is deliberate — a profile naming an app that
does not read `providerConfiguration` is exactly the inert artifact `../daita/` was written
to warn about.

### What "automatically on" does and does not mean

- **Always-On VPN is unavailable to any packet-tunnel provider.** `VPNType=AlwaysOn`
  restricts `TunnelConfigurations` → `ProtocolType` to a rangelist of exactly one value,
  `IKEv2`. On Demand with `OnDemandUserOverrideDisabled` is the strongest substitute, and
  unlike Always-On it needs no supervision.
- **The tunnel comes up on traffic, not at boot.** On Demand connects when something tries
  to use the network. There is a brief window at boot or after a network change before the
  tunnel is up — which is the window the DNS payload exists to cover.
- **It cannot survive its own removal.** On an unsupervised iPhone the owner can delete the
  profile, and the VPN, the defense floor and the pinned DNS all go with it. Supervision
  can make the profile non-removable; see `../daita/README.md` for the supervised-armed
  keys and their costs.

## What to build next, in order

1. **The server.** Not optional — see the two-sided requirement. Run `tad-engine` with
   `Role::Server` alongside your VPN termination, and expose defense capability in your
   handshake so `peerSupportsDefense` is a real answer rather than a hardcoded `true`.
2. **The transport,** implementing `TadTransport`. Constant packet size belongs here,
   applied to the encrypted datagram — not to the inner IP packets `packetFlow` hands you.
3. **Capability negotiation.** The client must learn, before carrying traffic, whether this
   server runs the counterpart machines for the negotiated level.
4. **Measure before you ship.** Use [`maybenot-simulator`](https://github.com/maybenot-io/maybenot)
   to evaluate machines against your own traffic, and measure real data and battery cost at
   each level. The defaults here (`max_padding_frac` 0.5, `max_blocking_frac` 0.2) are
   substantial.

## Licensing

- Maybenot and `maybenot-machines`: **MIT OR Apache-2.0**, © Tobias Pulls. Use freely.
- The Mullvad app: **GPL-3.0-only**. This implementation was written against Maybenot's
  public API and Apple's published schemas. Do not copy Mullvad's client code into a
  differently-licensed product.
- Do not call your feature **DAITA** — that is Mullvad's name for their implementation.

## Sources

- [maybenot-io/maybenot](https://github.com/maybenot-io/maybenot) — framework, machine library, FFI, simulator
- [Maybenot v2](https://arxiv.org/abs/2304.09510) — the paper
- [apple/device-management](https://github.com/apple/device-management) — `com.apple.vpn.managed.yaml`
- [Apple: VPN payload](https://developer.apple.com/documentation/devicemanagement/vpn) · [NETunnelProviderProtocol](https://developer.apple.com/documentation/networkextension/netunnelproviderprotocol)
- [`../daita/`](../daita/) — the research this builds on
