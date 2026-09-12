# Traffic-Analysis Defense (TAD) — architecture

## What "copying DAITA" actually means

DAITA is not one thing. It decomposes into four parts, and only one of them is Mullvad's:

| Part | What it is | Can you reuse it? |
|---|---|---|
| **Padding machines** | State machines that emit cover traffic and blocking in response to tunnel events | **Yes** — this is [Maybenot](https://github.com/maybenot-io/maybenot), MIT OR Apache-2.0, funded by Mullvad but not owned by their app |
| **Constant packet size** | Every tunnel datagram padded to the same length | **Yes** — it is a property of your transport, not licensed code. Mullvad implement it in their WireGuard fork |
| **Relay-side machines** | The server half of every defense | **Yes**, but you have to operate the servers |
| **The Mullvad client** | Swift/Rust glue, UI, account system | **No** — GPL-3.0-only. Do not copy it |

So the honest answer to "copy the architecture": you reimplement the *integration*, and you
depend on Maybenot for the hard part — the machines themselves, which are drawn from the
peer-reviewed website-fingerprinting literature (FRONT, Interspace, RegulaTor, Tamaraw,
Break-Pad, Scrambler). Reimplementing those from scratch would be strictly worse than using
the library Mullvad uses.

One naming point: **do not call your feature DAITA.** That is Mullvad's name for their
implementation. This one is called TAD here for that reason.

## The layers

```
   configuration profile  (com.apple.vpn.managed, VendorConfig)
            │  iOS delivers the dictionary
            ▼
   NETunnelProviderProtocol.providerConfiguration
            │  ios/TadPolicy.swift reads and coerces it
            ▼
   Policy  (JSON)  ── enforcement floor, fail-closed rule, padding budgets
            │
            ▼
   tad-engine  (Rust)  ── Maybenot framework + machine selection
            │  events in, actions out
            ▼
   PacketTunnelProvider  ── executes actions, reports what it did
            │
            ▼
   transport (WireGuard / QUIC)  ── constant packet size, padding datagrams
            │
            ▼
   VPN server  ── runs tad-engine with Role::Server
```

Layer 1 is the part that does not exist in DAITA, and it is the whole reason this is a
separate feature rather than a fork.

## Why enforcement works here and not for Mullvad

From the previous piece of work in [`../daita/`](../daita/): no configuration profile can
enable DAITA, because Mullvad's app reads its tunnel settings from its own keychain and
never reads `providerConfiguration` — a grep for that symbol across their `ios/` tree
returns zero hits.

That is not an iOS limitation. It is a property of *that app*. Apple delivers the
dictionary; the app decides whether to look at it. An app you build can look at it, and
then a profile genuinely pins the defense.

What enforcement means, precisely:

- The profile sets a **floor**, not a fixed value. The user may raise the level; attempts
  to lower it are **refused, not silently clamped**, so the UI can say which control is
  locked and by what.
- Only a profile-sourced policy may set `enforced`. The app's own settings screen cannot
  claim authority over the person using it — `PolicyError::EnforcedWithoutProfile`.
- The floor lasts as long as the profile does. On a supervised device that can be made
  non-removable. On a personal device the owner can remove it. This is a commitment device
  against casual downgrade, not a defence against the device's owner — say so in your UI.

## The event loop, and the way it gets broken

Maybenot machines advance on **their own effects**, not only on real traffic. The tunnel
must report back everything it was told to do:

| Event | When |
|---|---|
| `TunnelRecv` | every incoming datagram, before decryption or queueing |
| `NormalRecv` / `PaddingRecv` | once classified, after `TunnelRecv` |
| `NormalSent` | a real outgoing packet is queued |
| `TunnelSent` | a datagram actually leaves |
| `PaddingSent { machine }` | a `SendPadding` action was honoured — **including when the padding was replaced** by an already-queued packet |
| `BlockingBegin { machine }` / `BlockingEnd` | around honoured `BlockOutgoing` actions |
| `TimerBegin` / `TimerEnd` | around a machine's internal timer, armed by `UpdateTimer` |

A tunnel that sends padding but never reports `PaddingSent` looks like it is defending and
is not. `engine/tests/defense_loop.rs` contains the negative control: the same machines,
the same traffic, feedback withheld, measurably less defense.

## The two-sided requirement

**This is the constraint that decides whether the project is feasible for you.**

Maybenot machines ship in `_client` / `_server` pairs. The client shapes what it sends; the
server shapes what it sends back. Downstream traffic carries most of the
website-fingerprinting signal, so a client-only deployment defends the direction that
matters least.

It is worse than "half a defense" for some machines. `interspace_client`'s start state
transitions on `PaddingRecv` — padding arriving *from the peer*. With no server-side
machines it never leaves state 0 and emits nothing at all. `engine/tests/defense_loop.rs`
asserts exactly this: `interspace_is_inert_without_a_peer_and_alive_with_one` measures zero
client padding over 60 simulated seconds without a peer, and non-zero with one.

**Therefore: you cannot bolt this onto someone else's VPN.** You need to operate both ends.
The engine runs on the server too (`Role::Server`) — that is why the crate takes a role
rather than assuming the client.

The one exception is `light`, the NetFlow-coarsening machine: it pads during idle periods
to keep flow records coarse, needs no counterpart, and correspondingly does not defend
against website fingerprinting at all. It is honest about being the cheap option.

## Constant packet size is not a machine

Maybenot shapes *when* packets are sent. It does not make them the same size. Constant
packet size is a property of the transport, applied to the **encrypted datagram**, after
encryption.

Getting this wrong is a classic integration bug: `NEPacketTunnelProvider.packetFlow` hands
you the inner IP packets, and padding those accomplishes nothing, because the observer sees
the outer datagrams. In this design `TadTransport.constantPacketSize` owns it, and the
engine only reports whether the policy asked for it.

## Costs, stated plainly

Cover traffic is real traffic. It is indistinguishable from your traffic to an observer,
which means it is also indistinguishable to a data plan and a battery. `max_padding_frac`
and `max_blocking_frac` are passed straight to Maybenot as hard caps, and the defaults
(0.5 / 0.2) are already substantial. Anyone deploying `heavy` to a fleet on cellular should
measure first.

Blocking has a second cost: it delays real packets. `max_blocking_frac` bounds the fraction
of time outgoing traffic may be held, and latency-sensitive traffic will feel it.

## What this does not defend against

- **Traffic outside the tunnel.** The defense shapes what goes through the VPN. Anything
  that does not is untouched.
- **A malicious or compromised server.** It sees your traffic before it is shaped for the
  outside world. Traffic analysis defense is not a trust-reduction measure.
- **Endpoint compromise, or anything above the network layer.** The shape of your traffic
  is one signal among many.
- **An adversary who can correlate across your other links.** This is a defense against
  passive flow-shape analysis of *this* tunnel.

## Sources

- [maybenot-io/maybenot](https://github.com/maybenot-io/maybenot) — the framework, MIT OR Apache-2.0, © Tobias Pulls. `crates/maybenot-ffi` is an alternative C ABI if you want the framework without this crate's policy layer
- [Maybenot: A Framework for Traffic Analysis Defenses](https://arxiv.org/abs/2304.09510) — v2 of the framework
- [Apple: VPN payload](https://developer.apple.com/documentation/devicemanagement/vpn) and [`apple/device-management`](https://github.com/apple/device-management) `mdm/profiles/com.apple.vpn.managed.yaml` — `VPNType`, `VPNSubType`, `VendorConfig`, and the IKEv2-only `AlwaysOn` rangelist
- [Apple: NETunnelProviderProtocol](https://developer.apple.com/documentation/networkextension/netunnelproviderprotocol) — `providerConfiguration`
- [`../daita/`](../daita/) — why the same mechanism is inert against Mullvad's app
