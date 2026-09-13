# WireGuard with the DAITA VPN defense

`dvpn-wgconf` generates a ready-to-use WireGuard setup — real keys, correct MTU, DNSforge
DNS — in either of two modes. The difference between them is one line, and it is the
difference between a defended tunnel and a plain one.

## A stock `.conf` cannot carry the defense

WireGuard's configuration format has no field for padding machines, cover traffic, or
blocking, and no hook to add one. The keys it accepts are the ones it accepts. Mullvad
implement DAITA by **forking wireguard-go**, not by configuring it.

So there are two honest ways to give WireGuard traffic a traffic-analysis defense: fork the
implementation, or leave WireGuard alone and carry its datagrams inside a transport that
shapes. This does the second.

```
  wg client ──udp──▶ wg-client relay ══shaped══▶ wg-server relay ──udp──▶ wg server
  Endpoint =            constant-size frames,          forwards to
  127.0.0.1:51820       cover traffic, blocking        the real endpoint
```

WireGuard is unmodified and unaware. From the outside, its handshake and data messages —
whose sizes are distinctive and well documented — are gone, replaced by identical frames
mixed with cover traffic.

## Generate

```bash
cd dvpn && cargo build --release

./target/release/dvpn-wgconf \
    --server-endpoint vpn.example.com:5601 \
    --clients 2 --dns base --out wg/
```

```
  mode        SHAPED — traffic-analysis defense active
  DNS         dnsforge base (dnsforge.de)
              49.12.67.122, 91.99.154.175, 2a01:4f8:c013:29d::122, 2a01:4f8:c010:8c35::175
  MTU         1152 (derived, not guessed)
  addresses   10.13.13.0/24, fd0d:daita:vpn::/64
```

Produces `wg/server.conf` and `wg/client-N.conf`, each `0600`, with freshly generated
X25519 keypairs and a per-peer `PresharedKey`.

`--direct` instead produces a plain WireGuard tunnel with filtered DNS and **no defense**,
labelled as such in the file itself.

## Run

Start the relays first. In shaped mode the tunnel **will not come up** without them, which
is deliberate: it fails closed rather than quietly falling back to an undefended
connection.

```bash
# on the server
dvpn-node wg-server --listen 0.0.0.0:5601 --wg-forward 127.0.0.1:51820
wg-quick up ./server.conf          # WireGuard listens on loopback only

# on the client
dvpn-node wg-client --connect vpn.example.com:5601 --wg-listen 127.0.0.1:51820 --floor moderate
wg-quick up ./client-1.conf
```

Verified end to end on loopback: five datagrams sent into the client relay came back
through the shaped tunnel intact, carried alongside 28 padding frames.

```
  round trip 0: ECHO:wg-datagram-0
  ...
  RESULT 5/5 round trips through the shaped tunnel
  bridge: 5 forwarded into the tunnel, 5 delivered out, 0 dropped as oversize
```

## Where this works, and where it does not

| Platform | Shaped mode | Direct mode |
|---|---|---|
| Linux, macOS | **Yes** — relay runs as a process beside stock WireGuard | Yes |
| Android | Yes, with a wrapper app hosting the relay | Yes |
| **iOS** | **No, not with the stock WireGuard app** | Yes |

iOS does not let you run a background relay process, and the WireGuard iOS app cannot be
pointed at one that does not exist. On iOS the shaping has to live *inside* the VPN app's
own Network Extension — which is what [`../tad/ios/`](../tad/ios/) implements against this
crate's transport. The generated `.conf` is then consumed by that app rather than by the
WireGuard app.

Put plainly: on a desktop this is usable today; on an iPhone the direct mode works with the
stock app and the shaped mode needs the custom client built.

## MTU 1152, and why it is computed

```
  1197   dvpn frame payload (1200-byte frame − 3-byte header)
 −  32   WireGuard data message overhead (4 type/reserved, 4 receiver, 8 counter, 16 tag)
 = 1165  budget for the inner packet
 → 1152  rounded down to a multiple of 16 — WireGuard pads before sealing
```

A wrong MTU here does not fail loudly. It presents as "small requests work, large downloads
stall" — the path-MTU black hole that costs an afternoon. The generator computes it, a test
asserts it is both small enough to fit and not wastefully small, and the relay counts and
names any oversize datagram it has to drop.

## DNS

`DNS =` takes resolver **addresses**. WireGuard has no DNS-over-HTTPS field, so a URL there
produces a broken tunnel rather than encrypted DNS. What you get from this line is:

- queries go to DNSforge instead of whatever the local network offers,
- they travel inside the tunnel, so the local network and your ISP do not see them,
- and from the VPN server onward they are **plain DNS on port 53** to DNSforge.

For DNS-over-HTTPS end to end, pair this with the profile in
[`../tad/profile/`](../tad/profile/), which pins DoH inside the tunnel *and* covers the
window before the tunnel is up. On iOS an active VPN overrides a system DNS payload, which
is why that profile pins the resolver in both places.

### Tiers

| `--dns` | Hostname | IPv4 | What it blocks |
|---|---|---|---|
| `base` | `dnsforge.de` | 49.12.67.122, 91.99.154.175 | Ads, trackers, malware. The default |
| `hard` | `hard.dnsforge.de` | 49.12.222.213, 88.198.122.154 | ~2.8M domains, no allowance for breakage |
| `clean` | `clean.dnsforge.de` | 49.12.223.2, 49.12.43.208 | Base plus adult content and gambling, SafeSearch forced |

**These addresses were resolved live on 2026-09-13, not copied from a published list.**
That distinction turned out to matter: several third-party listings still give
`176.9.93.198` and `176.9.1.117` for the base tier, and `dnsforge.de` does not point there
any more. The method was validated against `hard.dnsforge.de`, whose live addresses match
the four in DNSforge's own CMS-signed configuration profile exactly. Re-check them before a
real deployment — resolver addresses move, and this file will age.

## `PersistentKeepalive` is not cover traffic

`PersistentKeepalive = 25` keeps NAT state alive. It is not a defense and must not be
mistaken for one: a fixed 25-second beacon is itself a recognisable pattern, and it does
nothing about the sizes or timing of real traffic. The cover traffic comes from the shaping
relay.

## Still missing

- **Authenticated key exchange for the shaping layer.** The relay's own keys come from a
  pre-shared string. WireGuard inside it has a real handshake; the outer layer does not.
  This is the blocker that is not optional.
- **Roaming.** The relay learns one peer address and keeps it. A phone moving between
  networks needs the endpoint re-established.
- **Recovery.** If the relay dies, the tunnel stops. That is the fail-closed behaviour
  working as intended, but a deployed client needs supervision and a clear user-visible
  state rather than silence.
