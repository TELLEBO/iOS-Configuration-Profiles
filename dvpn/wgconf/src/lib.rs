//! WireGuard configuration generation, sized for the shaped transport.
//!
//! ## Why the MTU is not a guess
//!
//! A WireGuard data message is 32 bytes of overhead — 4 type/reserved, 4 receiver index,
//! 8 counter, 16 Poly1305 tag — around an inner packet that is first padded up to a
//! multiple of 16. When that message travels inside a [`dvpn_wire`] frame it has to fit in
//! [`dvpn_wire::MAX_PAYLOAD`].
//!
//! Getting this wrong does not fail loudly. It fails as "large downloads stall" — the
//! path MTU black hole that eats an afternoon — so the number is computed here rather than
//! copied from a forum post.

#![forbid(unsafe_code)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use x25519_dalek::{PublicKey, StaticSecret};

/// WireGuard data-message overhead: type+reserved, receiver index, counter, AEAD tag.
pub const WG_OVERHEAD: usize = 4 + 4 + 8 + 16;

/// Largest inner IP packet that still fits, once WireGuard's own framing and its 16-byte
/// padding are accounted for.
pub const fn shaped_mtu() -> usize {
    let budget = dvpn_wire::MAX_PAYLOAD - WG_OVERHEAD;
    // WireGuard pads the inner packet up to a multiple of 16 before sealing, so the usable
    // MTU is the largest multiple of 16 that fits — not the raw remainder.
    budget - (budget % 16)
}

/// A WireGuard keypair, base64 as the tooling expects.
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub private: String,
    pub public: String,
}

/// 32 bytes from the OS CSPRNG.
///
/// Panics rather than degrading: a key generator that quietly falls back to a weaker
/// source is worse than one that stops, because nothing downstream can tell the
/// difference.
fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS entropy unavailable");
    bytes
}

pub fn generate_keypair() -> KeyPair {
    let secret = StaticSecret::from(random_32());
    let public = PublicKey::from(&secret);
    KeyPair {
        private: B64.encode(secret.to_bytes()),
        public: B64.encode(public.to_bytes()),
    }
}

/// A 32-byte pre-shared key.
///
/// WireGuard mixes this into the handshake as an extra symmetric secret. It is optional,
/// costs nothing, and is the cheapest hedge available against a future adversary who
/// records traffic now and breaks X25519 later.
pub fn generate_psk() -> String {
    B64.encode(random_32())
}

/// A DNSforge resolver tier.
///
/// Addresses resolved live on 2026-09-13 rather than copied from a published list. That
/// mattered: several third-party listings still give 176.9.93.198 and 176.9.1.117 for the
/// base tier, which is not where `dnsforge.de` points any more. The method was validated
/// against `hard.dnsforge.de`, whose live addresses match the four in DNSforge's own
/// CMS-signed configuration profile exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolver {
    pub name: &'static str,
    pub hostname: &'static str,
    pub v4: [&'static str; 2],
    pub v6: [&'static str; 2],
    pub note: &'static str,
}

pub const BASE: Resolver = Resolver {
    name: "dnsforge base",
    hostname: "dnsforge.de",
    v4: ["49.12.67.122", "91.99.154.175"],
    v6: ["2a01:4f8:c013:29d::122", "2a01:4f8:c010:8c35::175"],
    note: "Ads, trackers and malware blocked. The default tier.",
};

pub const HARD: Resolver = Resolver {
    name: "dnsforge hard",
    hostname: "hard.dnsforge.de",
    v4: ["49.12.222.213", "88.198.122.154"],
    v6: ["2a01:4f8:c17:2c61::213", "2a01:4f8:c013:5ec0::154"],
    note: "Aggressive: ~2.8M domains, no allowance for breakage.",
};

pub const CLEAN: Resolver = Resolver {
    name: "dnsforge clean",
    hostname: "clean.dnsforge.de",
    v4: ["49.12.223.2", "49.12.43.208"],
    v6: ["2a01:4f8:c17:4fbc::2", "2a01:4f8:c012:ed89::208"],
    note: "Base plus adult content and gambling, with SafeSearch forced.",
};

pub fn resolver(name: &str) -> Option<Resolver> {
    match name.trim().to_ascii_lowercase().as_str() {
        "base" | "default" => Some(BASE),
        "hard" => Some(HARD),
        "clean" => Some(CLEAN),
        _ => None,
    }
}

impl Resolver {
    /// The `DNS =` line. WireGuard takes plain resolver addresses — there is no field for
    /// a DNS-over-HTTPS URL, so encryption of DNS comes from the tunnel carrying it, not
    /// from this line.
    pub fn dns_line(&self, include_v6: bool) -> String {
        let mut parts: Vec<&str> = self.v4.to_vec();
        if include_v6 {
            parts.extend_from_slice(&self.v6);
        }
        parts.join(", ")
    }
}

#[derive(Clone, Debug)]
pub struct Peer {
    pub name: String,
    pub keys: KeyPair,
    pub psk: String,
    pub v4: String,
    pub v6: String,
}

#[derive(Clone, Debug)]
pub struct Network {
    pub v4_prefix: String,
    pub v6_prefix: String,
    pub listen_port: u16,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            // RFC 1918 space unlikely to collide with a home or office LAN.
            v4_prefix: "10.13.13".into(),
            // RFC 4193 unique-local.
            v6_prefix: "fd0d:daita:vpn".into(),
            listen_port: 51820,
        }
    }
}

impl Network {
    pub fn address(&self, index: u8) -> (String, String) {
        (
            format!("{}.{}", self.v4_prefix, index),
            format!("{}::{:x}", self.v6_prefix, index),
        )
    }
}

/// Build the client configuration.
///
/// `endpoint` is where the WireGuard client sends: the shaping relay on loopback when the
/// defense is in use, or the server directly when it is not. That single line is the whole
/// difference between a defended tunnel and a plain one — which is exactly why it is
/// labelled in the output rather than left for the reader to infer.
pub fn client_config(
    client: &Peer,
    server_public: &str,
    endpoint: &str,
    resolver: Resolver,
    net: &Network,
    shaped: bool,
) -> String {
    let mtu = shaped_mtu();
    let mut s = String::new();

    s.push_str("# DAITA VPN — WireGuard client\n#\n");
    if shaped {
        s.push_str(
            "# Endpoint points at the local shaping relay, NOT at the server. Start the\n\
             # relay first:  dvpn-node wg-client --connect <server>:5601 --wg-listen 127.0.0.1:51820\n\
             # Without the relay running, this tunnel will not come up at all.\n",
        );
    } else {
        s.push_str(
            "# DIRECT MODE: no traffic-analysis defense. This is a plain WireGuard tunnel\n\
             # with filtered DNS. Packet sizes and timing are exposed exactly as usual.\n",
        );
    }
    s.push_str(&format!("#\n# DNS: {} ({})\n", resolver.name, resolver.note));
    s.push_str(&format!(
        "# MTU {mtu} = {} (frame payload) - {WG_OVERHEAD} (WireGuard) rounded down to a multiple of 16.\n\n",
        dvpn_wire::MAX_PAYLOAD
    ));

    s.push_str("[Interface]\n");
    s.push_str(&format!("PrivateKey = {}\n", client.keys.private));
    s.push_str(&format!("Address = {}/32, {}/128\n", client.v4, client.v6));
    s.push_str(&format!("DNS = {}\n", resolver.dns_line(true)));
    s.push_str(&format!("MTU = {mtu}\n\n"));

    s.push_str("[Peer]\n");
    s.push_str(&format!("PublicKey = {server_public}\n"));
    s.push_str(&format!("PresharedKey = {}\n", client.psk));
    s.push_str(&format!("Endpoint = {endpoint}\n"));
    s.push_str("AllowedIPs = 0.0.0.0/0, ::/0\n");
    // Keeps NAT state alive. It is not cover traffic and must not be mistaken for it:
    // a fixed 25-second beacon is itself a recognisable pattern.
    s.push_str("PersistentKeepalive = 25\n");
    let _ = net;
    s
}

pub fn server_config(server: &Peer, clients: &[Peer], net: &Network) -> String {
    let mtu = shaped_mtu();
    let mut s = String::new();

    s.push_str("# DAITA VPN — WireGuard server\n#\n");
    s.push_str(
        "# When the defense is in use, this listens on loopback and the shaping relay\n\
         # forwards to it:  dvpn-node wg-server --listen 0.0.0.0:5601 --wg-forward 127.0.0.1:51820\n\
         # Do not expose this port directly in that configuration.\n\n",
    );

    s.push_str("[Interface]\n");
    s.push_str(&format!("PrivateKey = {}\n", server.keys.private));
    s.push_str(&format!("Address = {}/24, {}/64\n", server.v4, server.v6));
    s.push_str(&format!("ListenPort = {}\n", net.listen_port));
    s.push_str(&format!("MTU = {mtu}\n"));
    s.push_str(
        "\n# Routing and NAT are yours to set up; these run as root via wg-quick.\n\
         # PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n\
         # PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n",
    );

    for c in clients {
        s.push_str(&format!("\n[Peer]\n# {}\n", c.name));
        s.push_str(&format!("PublicKey = {}\n", c.keys.public));
        s.push_str(&format!("PresharedKey = {}\n", c.psk));
        s.push_str(&format!("AllowedIPs = {}/32, {}/128\n", c.v4, c.v6));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mtu_leaves_room_for_wireguard_inside_a_frame() {
        let mtu = shaped_mtu();
        assert_eq!(mtu % 16, 0, "WireGuard pads to a multiple of 16");
        assert!(
            mtu + WG_OVERHEAD <= dvpn_wire::MAX_PAYLOAD,
            "a full-MTU packet would not fit in a frame"
        );
        assert!(
            mtu + 16 + WG_OVERHEAD > dvpn_wire::MAX_PAYLOAD,
            "the MTU is smaller than it needs to be; a whole 16-byte block is being wasted"
        );
    }

    #[test]
    fn keys_are_the_shape_wireguard_expects() {
        let k = generate_keypair();
        let priv_bytes = B64.decode(&k.private).unwrap();
        let pub_bytes = B64.decode(&k.public).unwrap();
        assert_eq!(priv_bytes.len(), 32);
        assert_eq!(pub_bytes.len(), 32);
        assert_eq!(B64.decode(generate_psk()).unwrap().len(), 32);
    }

    #[test]
    fn two_keypairs_are_not_the_same() {
        // Cheap, but a generator seeded from a constant is a real and quiet disaster.
        let a = generate_keypair();
        let b = generate_keypair();
        assert_ne!(a.private, b.private);
        assert_ne!(a.public, b.public);
    }

    #[test]
    fn the_public_key_derives_from_the_private_one() {
        let k = generate_keypair();
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&B64.decode(&k.private).unwrap());
        let derived = PublicKey::from(&StaticSecret::from(sk));
        assert_eq!(B64.encode(derived.to_bytes()), k.public);
    }

    #[test]
    fn resolver_tiers_are_distinct_and_populated() {
        for r in [BASE, HARD, CLEAN] {
            assert!(r.v4.iter().all(|a| a.parse::<std::net::Ipv4Addr>().is_ok()), "{}", r.name);
            assert!(r.v6.iter().all(|a| a.parse::<std::net::Ipv6Addr>().is_ok()), "{}", r.name);
        }
        assert_ne!(BASE.v4, HARD.v4);
        assert_ne!(BASE.v4, CLEAN.v4);
        assert_eq!(resolver("base"), Some(BASE));
        assert_eq!(resolver("nonsense"), None);
    }

    #[test]
    fn the_dns_line_is_addresses_not_a_url() {
        // WireGuard has no DoH field; a URL here silently produces a broken tunnel.
        let line = BASE.dns_line(true);
        assert!(!line.contains("http"));
        assert_eq!(line.split(", ").count(), 4);
    }

    #[test]
    fn a_shaped_client_config_points_at_the_relay_and_says_so() {
        let net = Network::default();
        let (v4, v6) = net.address(2);
        let peer = Peer {
            name: "phone".into(),
            keys: generate_keypair(),
            psk: generate_psk(),
            v4,
            v6,
        };
        let cfg = client_config(&peer, "SERVERPUB", "127.0.0.1:51820", HARD, &net, true);
        assert!(cfg.contains("Endpoint = 127.0.0.1:51820"));
        assert!(cfg.contains("shaping relay"));
        assert!(cfg.contains(&format!("MTU = {}", shaped_mtu())));
        assert!(cfg.contains("AllowedIPs = 0.0.0.0/0, ::/0"));

        let direct = client_config(&peer, "SERVERPUB", "vpn.example.com:51820", HARD, &net, false);
        assert!(direct.contains("no traffic-analysis defense"));
    }
}
