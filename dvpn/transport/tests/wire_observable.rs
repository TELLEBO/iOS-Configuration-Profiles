//! Tests written from the adversary's seat: everything asserted here is something an
//! observer of the link can measure. If a test in this file fails, the defense has a
//! leak — not a bug in an abstraction.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use dvpn_transport::*;
use dvpn_wire::{FrameKind, MAX_PAYLOAD};

const K1: [u8; 32] = [0x11; 32];
const K2: [u8; 32] = [0x22; 32];

/// A connected pair of endpoints on loopback.
fn pair() -> (Endpoint<ChaChaSeal>, Endpoint<ChaChaSeal>) {
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (aa, ba) = (a.local_addr().unwrap(), b.local_addr().unwrap());
    let t = Some(Duration::from_millis(200));
    a.set_read_timeout(t).unwrap();
    b.set_read_timeout(t).unwrap();
    (
        Endpoint::new(a, ba, ChaChaSeal::new(&K1, &K2, Direction::ClientToServer)),
        Endpoint::new(b, aa, ChaChaSeal::new(&K2, &K1, Direction::ServerToClient)),
    )
}

/// Watch the wire without being either endpoint.
fn observer() -> (UdpSocket, SocketAddr) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let a = s.local_addr().unwrap();
    (s, a)
}

#[test]
fn an_observer_sees_one_datagram_size_no_matter_what_is_inside() {
    let (obs, obs_addr) = observer();
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut client = Endpoint::new(sock, obs_addr, ChaChaSeal::new(&K1, &K2, Direction::ClientToServer));
    let now = Instant::now();

    // A TCP ACK, a DNS query, a full-MTU segment, and cover traffic.
    for payload in [vec![], vec![0u8; 40], vec![0u8; 74], vec![0u8; MAX_PAYLOAD]] {
        client.queue(&payload).unwrap();
    }
    client.flush(now).unwrap();
    client.send_padding(now, false).unwrap();

    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok((n, _)) = obs.recv_from(&mut buf) {
        seen.push(n);
        if seen.len() == 5 {
            break;
        }
    }

    assert_eq!(seen.len(), 5, "expected five datagrams, saw {seen:?}");
    assert!(
        seen.iter().all(|&n| n == DATAGRAM_LEN),
        "datagram sizes leaked payload size: {seen:?}"
    );
}

#[test]
fn payload_size_is_not_recoverable_from_the_ciphertext_length() {
    // Same assertion one level down: sealing adds a constant, so the sealed length carries
    // no information about the frame's contents.
    let mut seal = ChaChaSeal::new(&K1, &K2, Direction::ClientToServer);
    let mut lens = Vec::new();
    for n in [0usize, 1, 500, MAX_PAYLOAD] {
        let mut frame = [0u8; dvpn_wire::FRAME_LEN];
        dvpn_wire::encode(FrameKind::Data, &vec![0xcd; n], &mut frame).unwrap();
        let mut out = Vec::new();
        seal.seal(&frame, &mut out).unwrap();
        lens.push(out.len());
    }
    assert!(lens.iter().all(|&l| l == DATAGRAM_LEN), "{lens:?}");
}

#[test]
fn real_traffic_survives_the_round_trip() {
    let (mut client, mut server) = pair();
    let now = Instant::now();

    client.queue(b"GET / HTTP/1.1").unwrap();
    client.queue(&[0xab; MAX_PAYLOAD]).unwrap();
    let emitted = client.flush(now).unwrap();
    assert_eq!(emitted, vec![Emitted::Data, Emitted::Data]);

    assert_eq!(
        server.recv(now).unwrap(),
        Some(Received::Data(b"GET / HTTP/1.1".to_vec()))
    );
    assert_eq!(server.recv(now).unwrap(), Some(Received::Data(vec![0xab; MAX_PAYLOAD])));
}

#[test]
fn padding_arrives_classified_as_padding() {
    // The receiving end must be able to tell cover traffic from real traffic, or it cannot
    // feed PaddingRecv and the peer's machines stall.
    let (mut client, mut server) = pair();
    let now = Instant::now();
    assert!(client.send_padding(now, false).unwrap());
    assert_eq!(server.recv(now).unwrap(), Some(Received::Padding));
    assert_eq!(server.stats().padding_in, 1);
    assert_eq!(server.stats().data_in, 0);
}

#[test]
fn blocking_holds_real_traffic_and_releases_it_after() {
    let (mut client, mut server) = pair();
    let t0 = Instant::now();

    client.block_outgoing(t0, Duration::from_millis(50), false);
    client.queue(b"held").unwrap();

    assert!(client.flush(t0).unwrap().is_empty(), "blocked traffic must not leave");
    assert!(client.has_queued());
    assert_eq!(server.recv(t0).unwrap(), None, "nothing should have arrived");

    let t1 = t0 + Duration::from_millis(60);
    assert_eq!(client.flush(t1).unwrap(), vec![Emitted::Data]);
    assert_eq!(server.recv(t1).unwrap(), Some(Received::Data(b"held".to_vec())));
}

#[test]
fn a_longer_block_is_not_cancelled_by_a_shorter_one() {
    let (mut client, _server) = pair();
    let t0 = Instant::now();
    client.block_outgoing(t0, Duration::from_millis(100), false);
    client.block_outgoing(t0, Duration::from_millis(10), false);
    assert!(
        client.is_blocked(t0 + Duration::from_millis(50)),
        "the shorter request truncated the longer machine's block"
    );
}

#[test]
fn bypass_padding_respects_whether_the_block_allowed_it() {
    let (mut client, _s) = pair();
    let t0 = Instant::now();

    client.block_outgoing(t0, Duration::from_millis(50), false);
    assert!(!client.send_padding(t0, true).unwrap(), "non-bypassable block was bypassed");

    let (mut client2, _s2) = pair();
    client2.block_outgoing(t0, Duration::from_millis(50), true);
    assert!(client2.send_padding(t0, true).unwrap(), "bypassable block should let it through");
    assert!(!client2.send_padding(t0, false).unwrap(), "non-bypass padding must still wait");
}

#[test]
fn a_tampered_datagram_is_dropped_silently() {
    let (client, mut server) = pair();
    let now = Instant::now();

    // Forge a datagram of exactly the right size: correct length, wrong key.
    let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
    attacker.connect(server.local_addr().unwrap()).unwrap();
    attacker.send(&vec![0x5a; DATAGRAM_LEN]).unwrap();

    // It came from the wrong address and would fail authentication anyway.
    assert_eq!(server.recv(now).unwrap(), None);
    assert!(server.stats().dropped >= 1);
    drop(client);
}

#[test]
fn a_replayed_datagram_is_not_delivered_twice() {
    let mut seal_send = ChaChaSeal::new(&K1, &K2, Direction::ClientToServer);
    let mut seal_recv = ChaChaSeal::new(&K2, &K1, Direction::ServerToClient);

    let mut frame = [0u8; dvpn_wire::FRAME_LEN];
    dvpn_wire::encode(FrameKind::Data, b"once", &mut frame).unwrap();
    let mut datagram = Vec::new();
    seal_send.seal(&frame, &mut datagram).unwrap();

    let mut out = [0u8; dvpn_wire::FRAME_LEN];
    assert!(seal_recv.open(&datagram, &mut out).is_ok());
    assert!(
        matches!(seal_recv.open(&datagram, &mut out), Err(TransportError::Replay { .. })),
        "a replayed datagram would let an attacker inject spurious defense events"
    );
}

#[test]
fn a_datagram_of_the_wrong_size_is_rejected_before_decryption() {
    let mut seal = ChaChaSeal::new(&K2, &K1, Direction::ServerToClient);
    let mut out = [0u8; dvpn_wire::FRAME_LEN];
    assert!(matches!(
        seal.open(&[0u8; 64], &mut out),
        Err(TransportError::WrongDatagramLength { got: 64 })
    ));
}

#[test]
fn the_trace_records_the_constant_size_rather_than_asserting_it() {
    let (mut client, _s) = pair();
    let now = Instant::now();
    client.queue(b"x").unwrap();
    client.flush(now).unwrap();
    client.send_padding(now, false).unwrap();

    let trace = client.trace();
    assert_eq!(trace.len(), 2);
    assert!(trace.iter().all(|e| e.bytes == DATAGRAM_LEN));
    assert!(trace[0].sent && !trace[0].padding);
    assert!(trace[1].sent && trace[1].padding);

    // And it serialises to the format the simulator reads.
    let csv = client.trace_csv();
    assert_eq!(csv.lines().count(), 2);
    assert!(csv.lines().all(|l| l.ends_with(",s")));
}

#[test]
fn an_oversize_packet_is_refused_rather_than_truncated() {
    let (mut client, _s) = pair();
    assert!(matches!(
        client.queue(&vec![0u8; MAX_PAYLOAD + 1]),
        Err(TransportError::PacketTooLarge { .. })
    ));
}
