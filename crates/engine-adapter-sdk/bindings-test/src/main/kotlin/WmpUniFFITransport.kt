// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
//
// WmpUniFFITransport — the SDK's Transport interface implemented over the
// in-process Rust engine core. This is the Phase 1 integration: the SDK's
// existing WmpSession/WmpPeer/Profile stack talks through this class instead
// of through a WebSocket to the remote engine.
//
// The class is a drop-in replacement for WmpWebSocketTransport:
//
//   val transport = WmpUniFFITransport()
//   val session = WmpSession(config, transport)
//   val peer = WmpPeer(session)
//   peer.use(OpenID4xProfile(config))
//   peer.connect(authToken)  // creates the session on the in-process engine
//
// Everything downstream (the profile dispatch, the flow events, the
// FlowClient) works unchanged.

package org.siros.sdk.transport

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import uniffi.engine_adapter_sdk.EngineConfig
import uniffi.engine_adapter_sdk.WmpEngine
import uniffi.engine_adapter_sdk.createEngine

/**
 * The SDK's Transport interface implemented over the in-process Rust
 * engine. Sends a WMP message through the engine's UniFFI-exposed
 * `send`, and delivers the engine's notifications through the
 * `incoming()` flow.
 *
 * No WebSocket, no network to the engine — the only HTTP is the
 * engine's own outgoing fetches through the SDK's HttpClient port.
 */
class WmpUniFFITransport(
    private val config: EngineConfig = EngineConfig(
        maxMessageSize = 1048576uL,
        defaultSessionTtlSecs = 3600uL,
    ),
) : Transport {

    private val engine: WmpEngine = createEngine(config)

    private val _state = MutableStateFlow(TransportState.DISCONNECTED)
    override val state: StateFlow<TransportState> = _state

    private val incomingChannel = Channel<ByteArray>(Channel.BUFFERED)

    override suspend fun connect() {
        if (_state.value == TransportState.CONNECTED) return
        _state.value = TransportState.CONNECTING
        // The in-process engine is always "connected" — no socket to open.
        _state.value = TransportState.CONNECTED
    }

    override suspend fun send(message: ByteArray) {
        // One WMP message in, the reply out. A notification answers null.
        val response = engine.send(message)
        if (response != null) {
            incomingChannel.trySend(response)
        }
        // Deliver any queued notifications (flow progress, sub-flows).
        val notifications = engine.takeNotifications()
        for (n in notifications) {
            incomingChannel.trySend(n)
        }
    }

    override fun incoming(): Flow<ByteArray> = incomingChannel.receiveAsFlow()

    override suspend fun disconnect() {
        _state.value = TransportState.DISCONNECTED
        incomingChannel.close()
    }
}
