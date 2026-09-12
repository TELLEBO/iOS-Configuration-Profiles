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

```
cd profile
python3 build_profile.py \
    --bundle-id com.yourco.vpn \
    --provider-bundle-id com.yourco.vpn.PacketTunnel \
    --endpoint vpn.yourco.com:51820 \
    --level moderate
```

It emits a `com.apple.vpn.managed` payload with `VPNType=VPN`, `VPNSubType` set to your
app, `ProviderType=packet-tunnel`, and the policy in `VendorConfig`. The build asserts
`PayloadVersion == 1` throughout, that no trap key is present, that `VPNSubType` is set
(Apple's schema requires it when `VPNType` is `VPN`), that the extension identifier sits
under the app's, that the floor is not `off`, and that the profile does not write the
app's own origin nonce.

**The shipped file carries placeholder bundle identifiers** and will install and do
nothing until you point it at your app. That is deliberate — a profile naming an app that
does not read `providerConfiguration` is exactly the inert artifact `../daita/` was written
to warn about.

Two things the profile cannot do, both verified against Apple's schema:

- **Always-On VPN is unavailable.** `VPNType=AlwaysOn` restricts `TunnelConfigurations` →
  `ProtocolType` to a rangelist of exactly one value, `IKEv2`. No packet-tunnel provider
  can be an iOS Always-On VPN. On-demand (`OnDemandEnabled`, which this profile sets) is
  the closest substitute.
- **It cannot survive its own removal.** On an unsupervised iPhone the owner can delete the
  profile and the floor goes with it. Supervision can make the profile non-removable; see
  `../daita/README.md` for the supervised-armed keys and their costs.

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
