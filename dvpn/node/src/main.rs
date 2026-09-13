//! DAITA VPN node — client or server, same defense engine, same session loop.
//!
//! ```text
//! dvpn-node serve    --listen 127.0.0.1:5555 [--level moderate] [--no-server-machines]
//! dvpn-node client   --connect 127.0.0.1:5555 --floor moderate [--level heavy] [--seconds 20]
//! dvpn-node baseline --connect 127.0.0.1:5555 [--seconds 20]
//! ```
//!
//! `baseline` is the control: the same workload, sent with its real packet sizes and no
//! defense at all. Without it there is nothing to compare a defended trace against, and
//! any claim about overhead or effectiveness is unfalsifiable.
//!
//! Keys here are derived from a pre-shared string. That is a testbed convenience and is
//! called out loudly at startup: a real deployment needs an authenticated key exchange
//! (Noise_IK or WireGuard's handshake) from a reviewed implementation.

mod levels;
mod session;
mod timers;
mod workload;

use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use dvpn_transport::{ChaChaSeal, Direction, Endpoint, Seal};
use dvpn_wire::{FrameKind, Hello, HelloAck, MAX_PAYLOAD, NegotiationError, VERSION, negotiate};
use tad_engine::{DefenseLevel, Engine, Policy, PolicySource, Role};

use session::{Session, Source};

const DEFAULT_PSK: &str = "dvpn-testbed-preshared-key";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("");
    let get = |k: &str| -> Option<String> {
        args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned()
    };
    let has = |k: &str| args.iter().any(|a| a == k);

    let seconds: u64 = get("--seconds").and_then(|s| s.parse().ok()).unwrap_or(20);
    let out_dir = PathBuf::from(get("--out").unwrap_or_else(|| "traces".into()));
    let psk = get("--psk").unwrap_or_else(|| DEFAULT_PSK.to_string());

    let result = match mode {
        "serve" => {
            let listen = get("--listen").unwrap_or_else(|| "127.0.0.1:5555".into());
            let level = get("--level").and_then(|s| levels::parse(&s)).unwrap_or(DefenseLevel::Moderate);
            serve(&listen, level, has("--no-server-machines"), seconds, &psk, &out_dir)
        }
        "client" => {
            let connect = get("--connect").unwrap_or_else(|| "127.0.0.1:5555".into());
            let floor = get("--floor").and_then(|s| levels::parse(&s)).unwrap_or(DefenseLevel::Moderate);
            let want = get("--level").and_then(|s| levels::parse(&s)).unwrap_or(floor);
            client(&connect, floor, want, seconds, &psk, &out_dir)
        }
        "baseline" => {
            let connect = get("--connect").unwrap_or_else(|| "127.0.0.1:5555".into());
            baseline(&connect, seconds, &out_dir)
        }
        _ => {
            eprintln!("{}", include_str!("usage.txt"));
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

type Err = Box<dyn std::error::Error>;

/// Testbed key derivation. Domain-separated per direction so the two sides never share a
/// key stream, but this is not key *agreement* — see the module docs.
fn keys(psk: &str) -> ([u8; 32], [u8; 32]) {
    let d = |tag: &str| {
        let mut h = blake3::Hasher::new();
        h.update(b"dvpn-testbed-kdf-v1\0");
        h.update(tag.as_bytes());
        h.update(psk.as_bytes());
        *h.finalize().as_bytes()
    };
    (d("c2s"), d("s2c"))
}

fn policy(level: DefenseLevel) -> Policy {
    // Modelled as profile-delivered, because that is how a deployed client gets it: the
    // floor comes from the configuration profile, not from the app's own settings.
    Policy {
        level,
        enforced: true,
        source: PolicySource::Profile,
        ..Default::default()
    }
}

fn banner(psk_is_default: bool) {
    eprintln!("── dvpn-node ─────────────────────────────────────────────");
    eprintln!("  TESTBED BUILD. Keys are derived from a pre-shared string;");
    eprintln!("  there is no authenticated key exchange. Do not deploy.");
    if psk_is_default {
        eprintln!("  Using the built-in default PSK. Pass --psk for anything real.");
    }
    eprintln!("──────────────────────────────────────────────────────────");
}

fn serve(
    listen: &str,
    level: DefenseLevel,
    no_server_machines: bool,
    seconds: u64,
    psk: &str,
    out_dir: &PathBuf,
) -> Result<(), Err> {
    banner(psk == DEFAULT_PSK);
    let socket = UdpSocket::bind(listen)?;
    eprintln!("listening on {} (level {})", socket.local_addr()?, level.as_str());

    // Wait for a Hello. Poll rather than block forever, so the process is interruptible,
    // and only tighten the timeout once a client has actually turned up.
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    let (c2s, s2c) = keys(psk);
    let mut probe = [0u8; 4096];
    let accept_deadline = Instant::now() + Duration::from_secs(30);
    let (n, peer) = loop {
        match socket.recv_from(&mut probe) {
            Ok(v) => break v,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if Instant::now() > accept_deadline {
                    return Err("no client arrived within 30s".into());
                }
            }
            Err(e) => return Err(format!("accept failed: {e}").into()),
        }
    };
    socket.set_read_timeout(Some(Duration::from_millis(20)))?;

    let mut seal = ChaChaSeal::new(&s2c, &c2s, Direction::ServerToClient);
    let mut frame = [0u8; dvpn_wire::FRAME_LEN];
    seal.open(&probe[..n], &mut frame).map_err(|e| format!("first datagram rejected: {e}"))?;
    let decoded = dvpn_wire::decode(&frame)?;
    if decoded.kind != FrameKind::Hello {
        return Err("first frame was not a Hello".into());
    }
    let hello = Hello::decode(decoded.payload)?;
    eprintln!(
        "hello from {peer}: version {} wants level {}",
        hello.version, hello.desired_level
    );

    // Answer honestly: the highest level both ends support, and whether we actually loaded
    // counterpart machines. `--no-server-machines` simulates an under-provisioned relay,
    // which is the case the client must refuse.
    let ours = levels::supported(Role::Server);
    let ceiling = levels::to_u8(level);
    let accepted = ours
        .best_common(hello.supported)
        // Capped by what the client asked for AND by what this server is configured to
        // run. Leaving the configured ceiling out of this was a bug: the server answered
        // with a level it had not been told to provide, and the client's floor check
        // passed against a promise nobody intended to keep.
        .map(|common| common.min(hello.desired_level).min(ceiling))
        .unwrap_or(0);
    let have_machines = !no_server_machines
        && levels::from_u8(accepted).is_some_and(|l| !l.machines(Role::Server).is_empty());

    let ack = HelloAck {
        version: VERSION,
        accepted_level: accepted,
        server_machines: have_machines,
        machines_hash: if no_server_machines {
            [0u8; 32]
        } else {
            levels::hash_for(Role::Server, accepted)
        },
    };

    let mut endpoint = Endpoint::new(socket, peer, seal);
    let now = Instant::now();
    let mut body = [0u8; MAX_PAYLOAD];
    let len = ack.encode(&mut body)?;
    endpoint.send_control(FrameKind::HelloAck, &body[..len], now)?;
    eprintln!(
        "accepted level {} (server machines: {})",
        accepted, have_machines
    );

    let level = levels::from_u8(accepted).unwrap_or(DefenseLevel::Off);
    if level == DefenseLevel::Off || level.machines(Role::Server).is_empty() {
        eprintln!("nothing to run server-side at level {}; idling", level.as_str());
        return Ok(());
    }

    let engine = Engine::start_with_role(&policy(level), level, true, Role::Server)?;
    eprintln!("engine up: {} machines", engine.num_machines());

    let mut sess = Session::new(engine, endpoint);
    let mut src = workload::Responder::new(Instant::now());
    sess.run(&mut src, Instant::now() + Duration::from_secs(seconds))?;

    report("server", &sess);
    write_traces(out_dir, "server", &sess, &src.real)?;
    Ok(())
}

fn client(
    connect: &str,
    floor: DefenseLevel,
    want: DefenseLevel,
    seconds: u64,
    psk: &str,
    out_dir: &PathBuf,
) -> Result<(), Err> {
    banner(psk == DEFAULT_PSK);
    let peer: SocketAddr = connect.parse()?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(20)))?;

    let (c2s, s2c) = keys(psk);
    let seal = ChaChaSeal::new(&c2s, &s2c, Direction::ClientToServer);
    let mut endpoint = Endpoint::new(socket, peer, seal);

    let desired = want.max(floor);
    let hello = Hello {
        version: VERSION,
        desired_level: levels::to_u8(desired),
        supported: levels::supported(Role::Client),
        machines_hash: levels::hash_for(Role::Client, levels::to_u8(desired)),
    };
    let now = Instant::now();
    let mut body = [0u8; MAX_PAYLOAD];
    let len = hello.encode(&mut body)?;
    endpoint.send_control(FrameKind::Hello, &body[..len], now)?;
    eprintln!("hello sent: want {} floor {}", desired.as_str(), floor.as_str());

    // Wait for the answer.
    let ack = {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if Instant::now() > deadline {
                return Err("server did not answer the handshake".into());
            }
            if let Some(dvpn_transport::Received::Control(payload)) = endpoint.recv(Instant::now())?
            {
                break HelloAck::decode(&payload)?;
            }
        }
    };

    // The decision the old code could not make, because it was handed a hardcoded `true`.
    let accepted = match negotiate(
        &ack,
        levels::to_u8(floor),
        |l| levels::hash_for(Role::Server, l),
        levels::requires_peer,
    ) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("refusing to connect: {e}");
            match e {
                NegotiationError::PeerHasNoMachines { .. } => eprintln!(
                    "  this server cannot shape return traffic. Most of the identifying\n  \
                     signal is downstream, so connecting would leave you believing you\n  \
                     were defended when you were not."
                ),
                NegotiationError::BelowFloor { .. } => eprintln!(
                    "  your configuration profile pins a minimum defense level that this\n  \
                     server cannot meet."
                ),
                _ => {}
            }
            return Err("negotiation failed".into());
        }
    };

    let level = levels::from_u8(accepted).ok_or("server named an unknown level")?;
    let engine = Engine::start(&policy(floor), level, ack.server_machines)?;
    eprintln!(
        "negotiated {} · {} machines · constant packet size {}",
        level.as_str(),
        engine.num_machines(),
        engine.constant_packet_size()
    );

    let mut sess = Session::new(engine, endpoint);
    let mut src = workload::Browsing::new(Instant::now(), Duration::from_millis(3500));
    sess.run(&mut src, Instant::now() + Duration::from_secs(seconds))?;

    report("client", &sess);
    write_traces(out_dir, "client", &sess, &src.real)?;
    Ok(())
}

/// The undefended control: same workload, real packet sizes, no padding, no blocking.
fn baseline(connect: &str, seconds: u64, out_dir: &PathBuf) -> Result<(), Err> {
    let peer: SocketAddr = connect.parse()?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(5)))?;
    eprintln!("baseline: no defense, real packet sizes");

    let start = Instant::now();
    let deadline = start + Duration::from_secs(seconds);
    let mut src = workload::Browsing::new(start, Duration::from_millis(3500));
    let mut responder = workload::Responder::new(start);
    let mut buf = [0u8; 2048];

    while Instant::now() < deadline {
        let now = Instant::now();
        for p in src.packets(now) {
            let _ = socket.send_to(&p, peer);
            // Model the server's reply locally: the control must exercise the same
            // request/response shape as the defended run, or the comparison is unfair.
            responder.on_received(&p, now);
        }
        for p in responder.packets(now) {
            src.on_received(&p, now);
        }
        if let Ok((n, _)) = socket.recv_from(&mut buf) {
            src.on_received(&buf[..n], now);
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    std::fs::create_dir_all(out_dir)?;
    let path = out_dir.join("baseline.csv");
    std::fs::File::create(&path)?.write_all(workload::trace_csv(&src.real).as_bytes())?;
    eprintln!("wrote {} ({} packets)", path.display(), src.real.len());
    Ok(())
}

fn report(who: &str, sess: &Session) {
    let s = sess.endpoint.stats();
    eprintln!(
        "\n{who}: level {} role {:?}\n  sent    {} data, {} padding\n  received {} data, {} padding\n  dropped {}",
        sess.level().as_str(),
        sess.role(),
        s.data_out,
        s.padding_out,
        s.data_in,
        s.padding_in,
        s.dropped
    );
}

fn write_traces(
    dir: &PathBuf,
    who: &str,
    sess: &Session,
    real: &[workload::RealPacket],
) -> Result<(), Err> {
    std::fs::create_dir_all(dir)?;

    let wire = dir.join(format!("{who}-wire.csv"));
    let mut f = std::fs::File::create(&wire)?;
    for e in sess.endpoint.trace() {
        writeln!(
            f,
            "{},{},{}",
            e.at.as_nanos(),
            if e.sent { "s" } else { "r" },
            e.bytes
        )?;
    }

    let inner = dir.join(format!("{who}-real.csv"));
    std::fs::File::create(&inner)?.write_all(workload::trace_csv(real).as_bytes())?;

    eprintln!("  traces: {} · {}", wire.display(), inner.display());
    Ok(())
}
