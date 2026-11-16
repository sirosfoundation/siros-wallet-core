// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
//
// WmpUniFFITransport — the SDK's Transport protocol implemented over the
// in-process Rust engine core. This is the Phase 1 integration: the SDK's
// existing WmpSession/WmpPeer/Profile stack talks through this class instead
// of through a WebSocket to the remote engine.
//
// The class is a drop-in replacement for WmpWebSocketTransport:
//
//   let transport = WmpUniFFITransport()
//   let session = WmpSession(config: config, transport: transport)
//   let peer = WmpPeer(session: session)
//   peer.use(OpenID4xProfile(config: config))
//   try await peer.connect(authToken: token)
//
// Everything downstream (the profile dispatch, the flow events, the
// FlowClient) works unchanged.

import Foundation
import SirosTransport
import engine_adapter_sdk

/// The SDK's Transport protocol implemented over the in-process Rust
/// engine. Sends a WMP message through the engine's UniFFI-exposed
/// `send`, and delivers the engine's notifications through the
/// `incoming()` AsyncStream.
///
/// No WebSocket, no network to the engine — the only HTTP is the
/// engine's own outgoing fetches through the SDK's HttpClient port.
public final class WmpUniFFITransport: Transport, @unchecked Sendable {

    private let engine: WmpEngine
    private let stateContinuation: AsyncStream<TransportState>.Continuation
    private let _state: AsyncStream<TransportState>
    private let incomingContinuation: AsyncStream<Data>.Continuation
    private let _incoming: AsyncStream<Data>
    private let lock = NSLock()
    private var currentState: TransportState = .disconnected

    public init(config: EngineConfig = EngineConfig(
        maxMessageSize: 1048576,
        defaultSessionTtlSecs: 3600,
    )) {
        self.engine = createEngine(config: config)

        var stateCont: AsyncStream<TransportState>.Continuation!
        self._state = AsyncStream { stateCont = $0 }
        self.stateContinuation = stateCont

        var incomingCont: AsyncStream<Data>.Continuation!
        self._incoming = AsyncStream { incomingCont = $0 }
        self.incomingContinuation = incomingCont
    }

    public func state() -> AsyncStream<TransportState> { _state }
    public func incoming() -> AsyncStream<Data> { _incoming }

    public func connect() async {
        lock.lock()
        defer { lock.unlock() }
        guard currentState == .disconnected else { return }
        currentState = .connecting
        stateContinuation.yield(.connecting)
        // The in-process engine is always "connected" — no socket to open.
        currentState = .connected
        stateContinuation.yield(.connected)
    }

    public func send(_ message: Data) async {
        // One WMP message in, the reply out. A notification answers nil.
        let response = try? engine.send(message: Array(message))
        if let response {
            incomingContinuation.yield(Data(response))
        }
        // Deliver any queued notifications (flow progress, sub-flows).
        let notifications = engine.takeNotifications()
        for n in notifications {
            incomingContinuation.yield(Data(n))
        }
    }

    public func disconnect() async {
        lock.lock()
        defer { lock.unlock() }
        currentState = .disconnected
        stateContinuation.yield(.disconnected)
    }
}
