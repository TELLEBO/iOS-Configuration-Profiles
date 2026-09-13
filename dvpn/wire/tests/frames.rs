//! The constant-length property is the whole reason this crate exists, so it is the first
//! thing asserted — across every frame kind and every payload size.

use dvpn_wire::*;

#[test]
fn every_frame_is_the_same_length_whatever_it_carries() {
    let mut buf = [0u8; FRAME_LEN];

    let cases: Vec<(FrameKind, Vec<u8>)> = vec![
        (FrameKind::Padding, vec![]),
        (FrameKind::Close, vec![]),
        (FrameKind::Data, vec![]),
        (FrameKind::Data, vec![0xab; 1]),
        (FrameKind::Data, vec![0xab; 40]),
        (FrameKind::Data, vec![0xab; 576]),
        (FrameKind::Data, vec![0xab; MAX_PAYLOAD]),
        (FrameKind::Hello, vec![0x11; 36]),
    ];

    for (kind, payload) in cases {
        encode(kind, &payload, &mut buf).expect("encodes");
        // The signature makes this tautological, which is the point: there is no code path
        // that emits a short frame.
        assert_eq!(buf.len(), FRAME_LEN, "{kind:?} with {} bytes", payload.len());
        let back = decode(&buf).expect("decodes");
        assert_eq!(back.kind, kind);
        assert_eq!(back.payload, &payload[..]);
    }
}

#[test]
fn a_one_byte_packet_and_a_full_one_are_indistinguishable_by_length() {
    let mut small = [0u8; FRAME_LEN];
    let mut large = [0u8; FRAME_LEN];
    encode(FrameKind::Data, &[0x01], &mut small).unwrap();
    encode(FrameKind::Data, &vec![0x02; MAX_PAYLOAD], &mut large).unwrap();
    assert_eq!(small.len(), large.len());
    // A padding frame is the same size as both — it has to be, or cover traffic would be
    // trivially filterable.
    let mut pad = [0u8; FRAME_LEN];
    encode(FrameKind::Padding, &[], &mut pad).unwrap();
    assert_eq!(pad.len(), small.len());
}

#[test]
fn the_tail_of_a_short_frame_is_zeroed_not_left_over() {
    let mut buf = [0u8; FRAME_LEN];
    encode(FrameKind::Data, &vec![0xff; 600], &mut buf).unwrap();
    encode(FrameKind::Data, &[0x01, 0x02], &mut buf).unwrap();
    assert!(
        buf[HEADER_LEN + 2..].iter().all(|&b| b == 0),
        "stale bytes from the previous frame leaked into the tail"
    );
}

#[test]
fn oversize_payload_is_refused() {
    let mut buf = [0u8; FRAME_LEN];
    let err = encode(FrameKind::Data, &vec![0; MAX_PAYLOAD + 1], &mut buf).unwrap_err();
    assert!(matches!(err, WireError::PayloadTooLarge { .. }));
}

#[test]
fn padding_frames_may_not_carry_data() {
    let mut buf = [0u8; FRAME_LEN];
    assert!(matches!(
        encode(FrameKind::Padding, &[1, 2, 3], &mut buf).unwrap_err(),
        WireError::UnexpectedPayload(FrameKind::Padding)
    ));
}

#[test]
fn a_hostile_frame_is_dropped_not_trusted() {
    let mut buf = [0u8; FRAME_LEN];

    buf[0] = 99;
    assert!(matches!(decode(&buf), Err(WireError::UnknownKind(99))));

    // Declared length past the end of the frame: the classic read-overrun setup.
    buf[0] = FrameKind::Data as u8;
    buf[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(matches!(decode(&buf), Err(WireError::BadLength { .. })));

    buf[0] = FrameKind::Padding as u8;
    buf[1..3].copy_from_slice(&10u16.to_be_bytes());
    assert!(matches!(decode(&buf), Err(WireError::UnexpectedPayload(_))));
}

#[test]
fn frame_kinds_classify_for_the_defense_engine() {
    assert!(FrameKind::Data.is_normal());
    for k in [FrameKind::Padding, FrameKind::Hello, FrameKind::HelloAck, FrameKind::Close] {
        assert!(!k.is_normal(), "{k:?} must not count as normal traffic");
    }
}
