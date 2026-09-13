# TAD vs DAITA — capability assessment and roadmap

Assessed 2026-09-13 against the code in this directory and Mullvad's shipped DAITA.

## Verdict

**TAD is not more powerful than DAITA. It is not currently a competing defense at all.**

TAD is a *control plane with no data plane*. It decides what the defense should be, proves
the decision is enforceable, and refuses to run when conditions are wrong. It does not yet
shape a single real packet: there is no transport, no constant packet size, and no server.

DAITA is the inverse — a complete, field-hardened data plane with no control plane. It has
shaped real traffic on a production relay fleet since September 2024 and cannot be
configured from outside its own app by any means.

The two are not competitors on one axis. TAD's advantage is narrow, real, and worth
approximately nothing until the data plane exists.

## Where the ML actually is

A note on framing, because it changes what "accuracy" means here: neither system contains
a machine-learning model. The AI is the *adversary* — a website-fingerprinting classifier
trained on packet sizes, timings and directions. The meaningful accuracy metric is
therefore **the attacker's classification accuracy against defended traffic**, lower being
better, measured against an undefended baseline on the same trace corpus.

DAITA has published, peer-reviewed grounding for its machines. **TAD has no number at all**,
because the measurement harness does not exist. That is P1 below, and no capability claim
should be made about TAD until it produces one.

## Comparison

| Axis | DAITA | TAD | Winner |
|---|---|---|---|
| Padding machines | Maybenot, relay-provisioned since v2 (2025.1) | Maybenot, three static sets chosen at build time | DAITA |
| Constant packet size | Implemented in their WireGuard fork | **Absent** — no transport exists | DAITA |
| Server side | Production relay fleet, automatic multihop to a capable relay when the chosen exit lacks support | **Absent** — `Role::Server` exists, the daemon does not | DAITA |
| Peer capability handling | Reroutes via multihop; can be inactive at unsupported exits if Multihop is set to Never | Fails closed — refuses to connect rather than appear protected | TAD |
| Profile/MDM enforcement | **None.** Zero `providerConfiguration` reads; settings live in its own keychain | Profile sets a floor; raise allowed, lower refused explicitly; only profile-sourced policy may claim `enforced` | TAD |
| DNS pinning | In-app resolver choice | In-tunnel DoH + system fallback payload, asserted identical at build time | TAD |
| Auto-on | In-app auto-connect + `includeAllNetworks` kill switch | `OnDemandUserOverrideDisabled` (unsupervised-legal) | Draw |
| Client maturity | Shipped 2 years; accounts, UI, obfuscation, PQ key exchange | No app; Swift never compiled | DAITA |
| Measurement | Peer-reviewed machines, field-tuned | **None** | DAITA |
| Licensing headroom | GPL-3.0-only client | MIT/Apache path via Maybenot | TAD |
| Test coverage of integration pitfalls | Unknown (not public in this form) | 20 tests, incl. executable proof of the two-sided and closed-loop requirements | TAD |

Net: DAITA wins everything that protects a user today. TAD wins manageability, honest
failure, and licensing headroom — a real niche for a fleet operator, and unrealised.

## Enhancements required, in dependency order

### P0 — without these there is no defense, only a policy engine

1. **Transport with constant packet size.** Implement `TadTransport`: an encrypted
   datagram channel (WireGuard or QUIC) that can emit a data-free padding datagram, hold
   outgoing traffic for a bounded interval, classify inbound datagrams as padding or
   normal, and pad every datagram to a fixed length. Constant size must be applied
   **after encryption**; padding the inner IP packets `packetFlow` hands you accomplishes
   nothing.
2. **Server-side daemon.** Run `tad-engine` with `Role::Server` at the tunnel terminator,
   with the same closed event loop. Until this exists, `moderate` and `heavy` are inert:
   `interspace_client` waits on `PaddingRecv` forever. This is asserted in
   `engine/tests/defense_loop.rs`.
3. **Capability negotiation.** `peerSupportsDefense` is currently passed a hardcoded
   `true` at the `PacketTunnelProvider` call site. Carry a defense-capability field and
   the negotiated level in the handshake, so `Policy::preflight` gates on a real answer.
   Until then the fail-closed guarantee is decorative.

### P1 — without these no capability claim is defensible

4. **Measurement harness.** `maybenot-simulator` consumes `time,direction` traces and a
   `Network` delay model and emits the defended trace. Build: trace corpus in → simulator
   with each level's client+server machine sets → attacker classifier (Deep
   Fingerprinting / Tik-Tok / RF class) → report attacker accuracy, bandwidth overhead and
   added latency per level. Gate releases on it.
5. **Dynamic machine provisioning.** Replace the three static machine-spec arrays with
   server-supplied machines, as DAITA v2 did. No new wire format is needed:
   `Machine::serialize()` already produces a versioned base64(zlib(bincode)) string and
   `FromStr` parses it. Requires: signed machine bundles, a version/rollback story, and a
   policy floor that still binds when the server proposes something weaker.
6. **Compile the iOS side and put it in CI.** `ios/*.swift` has never been through a
   compiler. Add an Xcode project, cross-compile the engine for `aarch64-apple-ios`, and
   run the test suite plus a device smoke test per commit.

### P2 — parity and hardening

7. **Fail-closed panic path.** `panic = "abort"` in the release profile kills the
   extension on a defense bug. Aborting is the right direction (no unshaped traffic) but
   the app must treat restart as normal and not loop; add a circuit breaker and a
   user-visible state.
8. **Kill-switch integration.** Set `includeAllNetworks` from policy so traffic cannot
   leave outside the tunnel, with `excludeLocalNetworks` as a deliberate opt-in.
9. **Obfuscation and PQ key exchange**, to reach parity with Mullvad's transport options.
10. **Compliance attestation.** The natural extension of TAD's one real advantage: a fleet
    operator wants *proof* the floor held, not just a pin. Signed, privacy-preserving
    attestation of negotiated level and uptime — aggregate counts, never destinations.

## Phase plan

| Phase | Scope | Exit criterion |
|---|---|---|
| 1 | P0.1 + P0.2 on a testbed (two hosts, no iOS) | A defended trace that differs measurably from undefended, client and server machines both firing |
| 2 | P0.3 + P1.6 | iOS build green in CI; device connects; negotiated level visible in logs; fail-closed verified by pointing at a non-capable server |
| 3 | P1.4 | Published table: attacker accuracy, bandwidth overhead, latency, battery, per level |
| 4 | P1.5 + P2.7/8 | Machines updatable without an app release; floor still enforced; kill switch on |
| 5 | P2.9/10 | Parity features; attestation pilot with one fleet |

Phases 1–2 are the difference between a design and a product. Phase 3 is the difference
between a product and a claim anyone should believe.

## Honest summary for stakeholders

TAD should not be positioned against DAITA today. It is a defensible bet on an axis DAITA
has structurally conceded — centrally enforceable, verifiably-on traffic-analysis defense
for managed fleets — and it needs Phases 1 through 3 before that bet is testable. The
engineering risk is concentrated in P0.2: the defense is two-sided, so this is a network
operator's project, not an app project.
