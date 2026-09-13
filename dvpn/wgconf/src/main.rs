//! `dvpn-wgconf` — generate a ready-to-use WireGuard setup.
//!
//! ```text
//! dvpn-wgconf --server-endpoint vpn.example.com:5601 --clients 2 --dns base --out wg/
//! dvpn-wgconf --direct --server-endpoint vpn.example.com:51820 --dns hard --out wg/
//! ```
//!
//! Two modes, and the difference is not cosmetic:
//!
//! - **shaped** (default) — the client's `Endpoint` is the local shaping relay, so
//!   WireGuard traffic travels inside constant-size frames with cover traffic. This is the
//!   configuration that has a traffic-analysis defense.
//! - **`--direct`** — a plain WireGuard tunnel with filtered DNS and no defense at all.
//!   Useful, honest, and clearly labelled in the generated file.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use dvpn_wgconf::*;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let get = |k: &str| -> Option<String> {
        args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned()
    };
    let has = |k: &str| args.iter().any(|a| a == k);

    if has("--help") || has("-h") {
        eprintln!("{}", include_str!("usage.txt"));
        return ExitCode::SUCCESS;
    }

    let shaped = !has("--direct");
    let dns_name = get("--dns").unwrap_or_else(|| "base".into());
    let Some(res) = resolver(&dns_name) else {
        eprintln!("error: unknown DNS tier '{dns_name}' (base, hard, clean)");
        return ExitCode::from(2);
    };
    let clients: u8 = get("--clients").and_then(|s| s.parse().ok()).unwrap_or(1);
    if clients == 0 || clients > 250 {
        eprintln!("error: --clients must be between 1 and 250");
        return ExitCode::from(2);
    }
    let out = PathBuf::from(get("--out").unwrap_or_else(|| "wg".into()));
    let relay_listen = get("--relay-listen").unwrap_or_else(|| "127.0.0.1:51820".into());
    let server_endpoint = match get("--server-endpoint") {
        Some(e) => e,
        None => {
            eprintln!("error: --server-endpoint is required (host:port of the server)");
            return ExitCode::from(2);
        }
    };

    let net = Network::default();
    let (sv4, sv6) = net.address(1);
    let server = Peer {
        name: "server".into(),
        keys: generate_keypair(),
        psk: String::new(),
        v4: sv4,
        v6: sv6,
    };

    let peers: Vec<Peer> = (0..clients)
        .map(|i| {
            let (v4, v6) = net.address(i + 2);
            Peer {
                name: format!("client-{}", i + 1),
                keys: generate_keypair(),
                psk: generate_psk(),
                v4,
                v6,
            }
        })
        .collect();

    // The client's Endpoint is the whole difference between a defended tunnel and a plain
    // one, so it is derived from the mode rather than left to the operator to remember.
    let endpoint = if shaped { relay_listen.clone() } else { server_endpoint.clone() };

    if let Err(e) = write_all(&out, &server, &peers, &net, res, &endpoint, shaped) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }

    println!("\n  Wrote {} client config(s) and one server config to {}", peers.len(), out.display());
    println!("  {}", "─".repeat(62));
    println!("  mode        {}", if shaped { "SHAPED — traffic-analysis defense active" } else { "DIRECT — no defense" });
    println!("  DNS         {} ({})", res.name, res.hostname);
    println!("              {}", res.dns_line(true));
    println!("  MTU         {} (derived, not guessed)", shaped_mtu());
    println!("  addresses   {}.0/24, {}::/64", net.v4_prefix, net.v6_prefix);
    println!("  {}", "─".repeat(62));

    if shaped {
        println!("\n  Start the relay before bringing the tunnel up:");
        println!("    server:  dvpn-node wg-server --listen 0.0.0.0:5601 \\");
        println!("                       --wg-forward 127.0.0.1:{}", net.listen_port);
        println!("    client:  dvpn-node wg-client --connect {server_endpoint} \\");
        println!("                       --wg-listen {relay_listen} --floor moderate");
        println!("\n  Without the relay running, the tunnel will not come up. That is");
        println!("  deliberate: it fails closed rather than falling back to an");
        println!("  undefended direct connection.");
    } else {
        println!("\n  DIRECT mode: this is a plain WireGuard tunnel. DNS is filtered;");
        println!("  packet sizes and timing are exposed exactly as usual.");
    }

    println!("\n  These files contain private keys. They are written 0600; keep them that way.\n");
    ExitCode::SUCCESS
}

fn write_all(
    out: &PathBuf,
    server: &Peer,
    peers: &[Peer],
    net: &Network,
    res: Resolver,
    endpoint: &str,
    shaped: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(out)?;

    write_private(&out.join("server.conf"), &server_config(server, peers, net))?;
    for p in peers {
        let cfg = client_config(p, &server.keys.public, endpoint, res, net, shaped);
        write_private(&out.join(format!("{}.conf", p.name)), &cfg)?;
    }
    Ok(())
}

/// Write owner-read/write only. A WireGuard config is a private key in a text file; the
/// default umask is not a good enough answer.
fn write_private(path: &PathBuf, contents: &str) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(contents.as_bytes())
}
