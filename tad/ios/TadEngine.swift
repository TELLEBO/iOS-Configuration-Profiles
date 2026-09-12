// TadEngine.swift — Swift wrapper over the tad-engine C ABI.
//
// NOT COMPILED IN THIS REPOSITORY (see TadPolicy.swift for why).
//
// Build the static library for the device and link it into the Network Extension target:
//
//   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
//   cargo build --release --target aarch64-apple-ios
//   cbindgen --lang c --output tad_engine.h ../engine        # generate the header
//
// Then in the extension target: add libtad_engine.a to "Link Binary With Libraries", put
// tad_engine.h in a bridging header, and add the native static libs cargo reports for the
// target (`RUSTFLAGS="--print native-static-libs" cargo build --target aarch64-apple-ios`).
//
// Threading: a MaybenotFramework is not safe to use concurrently, so every call here must
// happen on the tunnel's own serial queue. This class does not add locking of its own —
// it would hide the requirement rather than satisfy it.

import Foundation

final class TadEngine {
    private var policy: OpaquePointer?
    private var engine: OpaquePointer?
    private var actionBuffer: [TadAction] = []

    /// The number of machines running, which is also the action-buffer capacity the ABI
    /// requires.
    private(set) var machineCount: Int = 0

    /// Whether a profile pinned this configuration; the settings UI must render the
    /// control as locked and say so.
    private(set) var isLocked = false

    /// Whether the transport must pad every outgoing datagram to a constant size.
    private(set) var constantPacketSize = false

    init(policyJSON: String) throws {
        var p: OpaquePointer?
        let result = policyJSON.withCString { tad_policy_parse($0, &p) }
        guard result == TadResultOk, let parsed = p else {
            throw TadError.policyRejected(result)
        }
        policy = parsed
        isLocked = tad_policy_is_locked(parsed)
    }

    /// The minimum level the profile permits. Only meaningful when `isLocked`.
    var enforcedFloor: TadLevel {
        guard let policy else { return .off }
        return TadLevel(raw: tad_policy_floor(policy))
    }

    /// Start the defense.
    ///
    /// Throws rather than degrading: a refused downgrade and an incapable peer are both
    /// conditions the user needs told about, not papered over.
    func start(requested: TadLevel, peerSupportsDefense: Bool) throws {
        guard let policy else { throw TadError.engineStartFailed(TadResultNullPointer) }
        var e: OpaquePointer?
        let result = tad_engine_start(policy, requested.raw, peerSupportsDefense, &e)
        guard result == TadResultOk, let started = e else {
            throw TadError.engineStartFailed(result)
        }
        engine = started
        machineCount = tad_engine_num_machines(started)
        constantPacketSize = tad_engine_constant_packet_size(started)
        actionBuffer = Array(repeating: TadAction(), count: max(machineCount, 1))
    }

    /// Feed a batch of events, get back the actions the tunnel must perform.
    ///
    /// Batching matters: the framework processes a whole batch against one timestamp, and
    /// a later event in the batch may supersede an action an earlier one produced. Feeding
    /// events one at a time produces more churn for no benefit.
    func onEvents(_ events: [TadEvent]) -> [TadAction] {
        guard let engine, !actionBuffer.isEmpty else { return [] }
        var written = 0
        let result = events.withUnsafeBufferPointer { eventPtr in
            actionBuffer.withUnsafeMutableBufferPointer { actionPtr in
                tad_engine_on_events(
                    engine,
                    eventPtr.baseAddress,
                    events.count,
                    actionPtr.baseAddress,
                    actionPtr.count,
                    &written
                )
            }
        }
        guard result == TadResultOk else { return [] }
        return Array(actionBuffer.prefix(written))
    }

    deinit {
        if let engine { tad_engine_stop(engine) }
        if let policy { tad_policy_free(policy) }
    }
}

enum TadLevel: UInt32 {
    case off = 0, light = 1, moderate = 2, heavy = 3

    init(raw: UInt32) { self = TadLevel(rawValue: raw) ?? .off }
    var raw: UInt32 { rawValue }

    var displayName: String {
        switch self {
        case .off: return "Off"
        case .light: return "Light"
        case .moderate: return "Moderate"
        case .heavy: return "Heavy"
        }
    }
}

// MARK: - Event construction
//
// The framework's event vocabulary is precise and the tunnel must be too; these helpers
// exist so call sites read as the contract does. See ../ARCHITECTURE.md, "The event loop".

extension TadEvent {
    static func tunnelRecv() -> TadEvent { TadEvent(event_type: 2, machine: 0) }
    static func normalRecv() -> TadEvent { TadEvent(event_type: 0, machine: 0) }
    static func paddingRecv() -> TadEvent { TadEvent(event_type: 1, machine: 0) }
    static func normalSent() -> TadEvent { TadEvent(event_type: 3, machine: 0) }
    static func tunnelSent() -> TadEvent { TadEvent(event_type: 5, machine: 0) }
    static func paddingSent(machine: Int) -> TadEvent {
        TadEvent(event_type: 4, machine: machine)
    }
    static func blockingBegin(machine: Int) -> TadEvent {
        TadEvent(event_type: 6, machine: machine)
    }
    static func blockingEnd() -> TadEvent { TadEvent(event_type: 7, machine: 0) }
    static func timerBegin(machine: Int) -> TadEvent { TadEvent(event_type: 8, machine: machine) }
    static func timerEnd(machine: Int) -> TadEvent { TadEvent(event_type: 9, machine: machine) }
}

extension TadAction {
    enum Kind: UInt32 { case cancel = 0, sendPadding = 1, blockOutgoing = 2, updateTimer = 3 }
    var kind: Kind { Kind(rawValue: tag) ?? .cancel }
    var timeout: TimeInterval { TimeInterval(timeout_nanos) / 1_000_000_000 }
    var blockDuration: TimeInterval { TimeInterval(duration_nanos) / 1_000_000_000 }
}
