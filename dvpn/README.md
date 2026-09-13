# DAITA VPN

A traffic-analysis defense with both halves built: the policy layer that pins it on, and
the data plane that actually shapes packets. This closes the P0 gap that
[`../tad/ROADMAP.md`](../tad/ROADMAP.md) identified — the version assessed there was a
control plane with no data plane.

## One thing this is not, and cannot be

**A configuration profile alone cannot defend against traffic analysis.** A
`.mobileconfig` is declarative configuration with no code execution: it cannot pad a
packet, inject cover traffic, or hold a queue. That was the finding in
[`../daita/`](../daita/), and it does not change with effort.

What a profile *can* do is pin the defense on and refuse to let it be turned off. That is
the control plane. This directory is the data plane underneath it. Both are needed; neither
is sufficient.

## Measured, not asserted

A 30-second session between two processes, defended, against a baseline run of the same
workload with no defense at all:

```
                                 UNDEFENDED       DEFENDED
  ────────────────────────────────────────────────────────
  packets                               737           1659
    sent / received                39 / 698     376 / 1283
  bytes                              749353        2030616
  ────────────────────────────────────────────────────────
  distinct packet sizes                  73              1
  size entropy (bits)                 1.136          0.000
  link occupancy                      31.7%          68.3%
  distinguishable bursts                  9              9
  ────────────────────────────────────────────────────────
  Bandwidth cost      2.59x  (+159%)
  Cover traffic       56% of defended packets
```

Three things to read out of that, including the one that does not flatter it:

- **Size entropy is zero.** 73 distinct packet sizes became one. Every datagram on the wire
  is 1224 bytes, whether it carries a TCP ACK, a full segment, or nothing at all.
- **Occupancy more than doubled**, 31.7% → 68.3%. The link stops going quiet when the user
  does — idle gaps are a strong fingerprinting signal.
- **Burst count did not improve at all**, 9 → 9. Interspace at `moderate` does not fill
  every idle gap, so the coarse shape of "nine page loads happened" survives. That is a
  real limitation of this level, visible because the harness measures it rather than
  asserting success. `heavy` and constant-rate machines exist to attack it.

The cost is not rounding error: **2.59× the bandwidth**. Cover traffic is real traffic, and
it is indistinguishable from your traffic to your data plan as well as to an observer.

**Not measured:** attacker classification accuracy. That needs a multi-site trace corpus
and a trained classifier. Size uniformity and occupancy are *necessary* conditions for a
defense, not sufficient ones — a trace can be perfectly uniform in size and still leak
through timing. No effectiveness claim should be made from the table above.

## Using it with WireGuard

[WIREGUARD.md](WIREGUARD.md) covers the generator and the relay. Short version: a stock
WireGuard `.conf` has no field for padding machines and no hook to add one, so WireGuard is
left unmodified and its datagrams are carried inside the shaped transport. `dvpn-wgconf`
emits ready-to-use configs with real keys, DNSforge DNS and a computed MTU of 1152.

```bash
./target/release/dvpn-wgconf --server-endpoint vpn.example.com:5601 --clients 2 --dns base --out wg/
```

Works today on Linux and macOS, where the relay runs beside stock WireGuard. **Not** on iOS
with the stock WireGuard app — iOS has no background relay process, so the shaping has to
live inside the VPN app's own Network Extension.

## Reproducing it

```bash
cd dvpn
cargo build --release

# Two processes, a real socket between them.
./target/release/dvpn-node serve  --listen 127.0.0.1:5601 --level moderate --seconds 32 &
./target/release/dvpn-node client --connect 127.0.0.1:5601 --floor moderate --seconds 30

# The control: same workload, real packet sizes, no defense.
./target/release/dvpn-node baseline --connect 127.0.0.1:5999 --seconds 30

./target/release/dvpn-measure traces/baseline.csv traces/client-wire.csv
```

Traces are written as `nanoseconds,direction,bytes`. The first two columns are the format
[`maybenot-simulator`](https://github.com/maybenot-io/maybenot) consumes, so the same
traces feed a simulator study without conversion.

### Watching it refuse

The defense is two-sided. A server that cannot shape return traffic cannot be made safe by
the client trying harder, so the client refuses rather than pretending:

```bash
./target/release/dvpn-node serve --listen 127.0.0.1:5556 --level moderate --no-server-machines &
./target/release/dvpn-node client --connect 127.0.0.1:5556 --floor moderate
```

```
refusing to connect: server has no counterpart machines for level 2; refusing
  this server cannot shape return traffic. Most of the identifying
  signal is downstream, so connecting would leave you believing you
  were defended when you were not.
```

And a server that can only offer less than the profile's floor:

```bash
./target/release/dvpn-node serve --listen 127.0.0.1:5558 --level light &
./target/release/dvpn-node client --connect 127.0.0.1:5558 --floor heavy
```

```
refusing to connect: server offers level 1, policy floor is 3; refusing
```

## How it is put together

| Crate | What it owns |
|---|---|
| `wire` | Constant-size frames; capability negotiation. The encoder's output type is `&mut [u8; FRAME_LEN]`, so a short frame is a type error rather than a branch someone forgets |
| `transport` | Sealing, the egress queue, blocking, replay window. Emits one datagram size, always |
| `node` | The session loop — the same one for client and server — plus the handshake and a synthetic workload |
| `measure` | Trace analysis against a baseline |
| `../tad/engine` | Policy, enforcement floor, and the Maybenot integration |

Frame sizing: 1200-byte frame + 8-byte counter + 16-byte Poly1305 tag = 1224 bytes of UDP
payload. With a 48-byte IPv6/UDP header that is 1272, under the 1280 minimum MTU, so
nothing fragments. Fragmentation would reintroduce a size signal no amount of inner padding
could remove.

## Against Mullvad's DAITA

Now that the data plane exists, the comparison is narrower and more honest than the one in
[`../tad/ROADMAP.md`](../tad/ROADMAP.md):

| | DAITA | DAITA VPN |
|---|---|---|
| Padding machines | Maybenot, relay-provisioned | Maybenot, same library, static per level |
| Constant packet size | Yes, in their WireGuard fork | **Yes, measured: 1 distinct size, 0.000 bits entropy** |
| Both ends shaping | Production relay fleet | **Yes, on a testbed** |
| Peer cannot comply | Reroutes via multihop; can sit inactive at unsupported exits | **Refuses to connect, and says why** |
| Level disagreement | — | **Machine-set hashes compared in the handshake** |
| Profile-enforced floor | None | Yes |
| DNS pinned in-tunnel | In-app choice | Yes, by the same profile |
| Key exchange | WireGuard + post-quantum | **Absent — testbed PSK only** |
| Mobile client | Shipped 2 years | Swift written, never compiled |
| Scale | Global relay fleet | Two processes on loopback |
| Evidence | Peer-reviewed machines, field-tuned | One synthetic workload |

**Where it is genuinely stronger: architecture and failure posture.** Enforcement from a
configuration profile, refusal instead of silent degradation, and cryptographic agreement
on what a defense level *means* are three things DAITA does not do, and the second is a
security property, not a convenience.

**Where it is not stronger: everything about deployment.** Same machines from the same
library, no key exchange, no mobile client, no fleet, one workload. It is not a better
defense than DAITA today. It is a better-behaved one, on a bench.

## Security notes

- **There is no authenticated key exchange.** Keys come from a pre-shared string. Use
  Noise_IK or WireGuard's handshake from a reviewed implementation; do not write one here.
  The node prints this at startup and it is not a formality.
- Sealing is ChaCha20-Poly1305 with counter nonces, domain-separated per direction, and a
  64-packet sliding replay window. The send counter refuses to wrap rather than reusing a
  nonce.
- Datagrams that fail authentication, replay, or framing are dropped and counted, never
  surfaced: a peer who can make the node report a forged frame as real traffic can steer
  the defense.
- This is a testbed. It has not been audited, it has no side-channel hardening, and the
  workload is synthetic.

## What is still missing

In dependency order, carried over from the roadmap:

1. **Authenticated key exchange.** The one blocker that is not optional.
2. **A real trace corpus and classifier**, for the attacker-accuracy number the table above
   deliberately does not contain.
3. **The iOS client compiled.** `../tad/ios/*.swift` implements this contract against
   `TadTransport`; this crate is what goes behind it.
4. **Dynamic machine provisioning.** `Machine::serialize()` is already a versioned
   base64-zlib wire format, so this needs signing and a rollback story, not a new encoding.
5. **Burst structure.** The 9 → 9 result is the open problem at `moderate`.

## Naming

"DAITA" is Mullvad's name for their implementation. This directory uses it because it was
asked for; anything published should not, both to avoid implying endorsement and because
the two systems are not the same thing.

Maybenot is MIT or Apache-2.0. Mullvad's client is GPL-3.0-only and none of it is used here.
