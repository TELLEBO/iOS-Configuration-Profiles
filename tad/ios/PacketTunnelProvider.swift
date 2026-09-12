// PacketTunnelProvider.swift — where the defense meets real packets.
//
// NOT COMPILED IN THIS REPOSITORY (see TadPolicy.swift). This is the integration shape,
// with the transport left abstract behind `TadTransport`: the defense is independent of
// whether you carry packets over WireGuard, QUIC or something else, and pinning it to one
// would hide that.
//
// ── The two things that go wrong ──────────────────────────────────────────────────────
//
// 1. An open loop. Machines advance on their own effects. If the tunnel injects padding
//    but never reports `paddingSent`, or blocks but never reports `blockingBegin`, most
//    machines sit in their start state and the "defense" is decoration. This is not
//    hypothetical — ../engine/tests/defense_loop.rs asserts the difference.
//
// 2. Padding the wrong layer. `packetFlow` hands you inner IP packets. Padding those does
//    nothing: the observer sees the *encrypted datagrams* you put on the wire. Constant
//    packet size has to be applied by the transport, after encryption, which is why
//    `TadTransport` owns it rather than this class.

import Foundation
import NetworkExtension
import os

/// The encrypted transport to the VPN server. Whatever implements this must be able to
/// send a datagram that carries no user data (padding) and to report what it observed on
/// the wire.
protocol TadTransport: AnyObject {
    /// Pad every outgoing datagram to a constant size. Set before the first send.
    var constantPacketSize: Bool { get set }

    func connect(endpoint: String) async throws -> TadPeerCapabilities
    func send(_ packets: [Data]) async throws
    /// Send a datagram carrying no user data.
    func sendPadding() async throws
    /// Stop releasing outgoing datagrams for `duration`; queued packets go out after.
    func blockOutgoing(for duration: TimeInterval, bypassable: Bool) async
    func receive() async throws -> [TadDatagram]
}

struct TadPeerCapabilities {
    /// Whether the server is running the counterpart machines for the negotiated level.
    /// The engine fails closed on this when the policy says to.
    let supportsDefense: Bool
}

struct TadDatagram {
    let payload: Data
    /// Whether the peer marked this datagram as padding. Classified by the transport,
    /// after decryption, before the packet reaches the tunnel.
    let isPadding: Bool
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: "tad", category: "tunnel")

    /// Every engine call happens here. A Maybenot framework is not safe to use
    /// concurrently and this queue is what makes that true rather than hoped for.
    private let engineQueue = DispatchQueue(label: "tad.engine")

    private var engine: TadEngine?
    private var transport: TadTransport?
    private var paddingTimers: [Int: DispatchSourceTimer] = [:]

    override func startTunnel(options: [String: NSObject]?) async throws {
        let providerConfig = (protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration

        let loader = TadPolicyLoader(appNonce: TadKeychain.appInstanceNonce())
        let policyJSON = try loader.policyJSON(from: providerConfig)

        let engine = try TadEngine(policyJSON: policyJSON)
        self.engine = engine

        // What the user asked for in the app, clamped upward by the profile — never
        // downward, and never silently. `start` throws on a refused downgrade so the app
        // can explain which control is locked and why.
        let requested = max(TadSettings.userSelectedLevel, engine.enforcedFloor)

        let endpoint = (providerConfig?[TadConfigKey.serverEndpoint] as? String) ?? ""
        let transport = try makeTransport()
        self.transport = transport

        let capabilities = try await transport.connect(endpoint: endpoint)
        try engine.start(
            requested: requested,
            peerSupportsDefense: capabilities.supportsDefense
        )
        transport.constantPacketSize = engine.constantPacketSize

        log.info("""
            TAD started: level=\(requested.displayName, privacy: .public) \
            locked=\(engine.isLocked, privacy: .public) \
            machines=\(engine.machineCount, privacy: .public) \
            constantPacketSize=\(engine.constantPacketSize, privacy: .public)
            """)

        try await setTunnelNetworkSettings(makeNetworkSettings())
        startPacketLoop()
        startReceiveLoop()
    }

    // MARK: - Outgoing

    private func startPacketLoop() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, let transport = self.transport else { return }

            Task {
                do {
                    try await transport.send(packets)
                    // One NormalSent per packet queued, one TunnelSent per datagram that
                    // left. Reporting a single event for a batch would understate the
                    // traffic and mis-shape the defense.
                    let events = packets.flatMap { _ in
                        [TadEvent.normalSent(), TadEvent.tunnelSent()]
                    }
                    self.feed(events)
                } catch {
                    self.log.error("send failed: \(error.localizedDescription, privacy: .public)")
                }
            }
            self.startPacketLoop()
        }
    }

    // MARK: - Incoming

    private func startReceiveLoop() {
        Task { [weak self] in
            guard let self else { return }
            while let transport = self.transport {
                do {
                    let datagrams = try await transport.receive()
                    var events: [TadEvent] = []
                    var inner: [Data] = []
                    for datagram in datagrams {
                        // TunnelRecv first, before the packet is classified or queued —
                        // the framework's ordering requirement, not a stylistic choice.
                        events.append(.tunnelRecv())
                        events.append(datagram.isPadding ? .paddingRecv() : .normalRecv())
                        if !datagram.isPadding {
                            inner.append(datagram.payload)
                        }
                    }
                    if !inner.isEmpty {
                        self.packetFlow.writePackets(inner, withProtocols: inner.map { _ in
                            NSNumber(value: AF_INET)
                        })
                    }
                    self.feed(events)
                } catch {
                    self.log.error("receive failed: \(error.localizedDescription, privacy: .public)")
                    return
                }
            }
        }
    }

    // MARK: - The engine loop

    private func feed(_ events: [TadEvent]) {
        guard !events.isEmpty else { return }
        engineQueue.async { [weak self] in
            guard let self, let engine = self.engine else { return }
            for action in engine.onEvents(events) {
                self.perform(action)
            }
        }
    }

    /// Carry out one action, and report back what was done.
    ///
    /// Must be called on `engineQueue`.
    private func perform(_ action: TadAction) {
        switch action.kind {
        case .sendPadding:
            schedulePadding(machine: action.machine, after: action.timeout)

        case .blockOutgoing:
            let machine = action.machine
            let duration = action.blockDuration
            let bypass = action.bypass
            engineQueue.asyncAfter(deadline: .now() + action.timeout) { [weak self] in
                guard let self, let transport = self.transport else { return }
                Task {
                    await transport.blockOutgoing(for: duration, bypassable: bypass)
                    // BlockingEnd is emitted by the transport when the block lifts, not
                    // guessed at from the duration here.
                    self.feed([.blockingEnd()])
                }
                self.feed([.blockingBegin(machine: machine)])
            }

        case .cancel:
            paddingTimers.removeValue(forKey: action.machine)?.cancel()

        case .updateTimer:
            // The machine's internal timer. Arm it and report TimerBegin now, TimerEnd on
            // expiry; machines that use it will not advance otherwise.
            scheduleInternalTimer(machine: action.machine, after: action.blockDuration)
        }
    }

    private func schedulePadding(machine: Int, after timeout: TimeInterval) {
        // A new SendPadding supersedes this machine's pending action timer.
        paddingTimers.removeValue(forKey: machine)?.cancel()

        let timer = DispatchSource.makeTimerSource(queue: engineQueue)
        timer.schedule(deadline: .now() + timeout)
        timer.setEventHandler { [weak self] in
            guard let self, let transport = self.transport else { return }
            self.paddingTimers.removeValue(forKey: machine)
            Task {
                try? await transport.sendPadding()
                // PaddingSent is owed even when the padding was replaced by a packet
                // already in the queue — the framework counts the intent, and omitting it
                // stalls the machine.
                self.feed([.paddingSent(machine: machine), .tunnelSent()])
            }
        }
        paddingTimers[machine] = timer
        timer.resume()
    }

    private func scheduleInternalTimer(machine: Int, after duration: TimeInterval) {
        feed([.timerBegin(machine: machine)])
        engineQueue.asyncAfter(deadline: .now() + duration) { [weak self] in
            self?.feed([.timerEnd(machine: machine)])
        }
    }

    // MARK: - Teardown

    override func stopTunnel(with reason: NEProviderStopReason) async {
        for timer in paddingTimers.values { timer.cancel() }
        paddingTimers.removeAll()
        engine = nil
        transport = nil
    }

    // MARK: - Stubs the host app supplies

    private func makeTransport() throws -> TadTransport {
        fatalError("supply your WireGuard/QUIC transport here")
    }

    private func makeNetworkSettings() -> NEPacketTunnelNetworkSettings {
        fatalError("supply your tunnel network settings here")
    }
}

enum TadKeychain {
    /// Read the nonce from the keychain access group shared by the app and the extension.
    static func appInstanceNonce() -> String? { nil }
}

enum TadSettings {
    /// The level chosen in the app's own UI.
    static var userSelectedLevel: TadLevel { .off }
}

extension TadLevel: Comparable {
    static func < (a: TadLevel, b: TadLevel) -> Bool { a.rawValue < b.rawValue }
}
