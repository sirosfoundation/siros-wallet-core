import uniffi.engine_adapter_sdk.EngineConfig
import uniffi.engine_adapter_sdk.createEngine
import uniffi.engine_adapter_sdk.WmpEngine

/**
 * The in-process engine smoke: creates the engine over the app's
 * callbacks, sends a wmp.session.create through the UniFFI handle, and
 * validates the reply. This is what the SDK's WmpUniFFITransport does —
 * one message in, the reply out, no WebSocket.
 */
fun engineSmoke() {
    val engine = createEngine(
        EngineConfig(
            maxMessageSize = 1048576uL,
            defaultSessionTtlSecs = 3600uL,
            maxConcurrentFlows = 16uL,
            consentCheck = "warn",
        ),
        TestHttpClient(),
        TestHost(),
        // No PDP: the smoke creates no flow that would need one.
        null,
    )

    // Send a session create through the in-process engine.
    val createMessage = """{"jsonrpc":"2.0","id":"engine-1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"},"security":{"mode":"tls"}}}"""
        .toByteArray()

    val response = engine.send(createMessage)
        ?: throw IllegalStateException("session create answered no reply")

    val reply = String(response)
    check(reply.contains("\"id\":\"engine-1\"")) { "reply id: $reply" }
    check(reply.contains("\"session_id\"")) { "session id present: $reply" }
    check(reply.contains("ses-")) { "the engine assigned a ses- id: $reply" }
    check(reply.contains("\"capabilities\"")) { "capabilities present: $reply" }
    check(reply.contains("\"mode\":\"tls\"")) { "security mode: $reply" }

    // A flow start whose session negotiated nothing answers -31005
    // (core §10.3): the families are registered now, but the flows
    // capability was not negotiated by this session-less start.
    val flowMessage = """{"jsonrpc":"2.0","id":"engine-2","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_type":"oid4vci","flow_id":"flow-test"}}"""
        .toByteArray()
    val flowReply = String(engine.send(flowMessage) ?: throw IllegalStateException("no reply"))
    check(flowReply.contains("\"code\":-31005")) { "flow refused with -31005: $flowReply" }
    check(flowReply.contains("\"unsupported\":\"oid4vci\"")) { "the refused type is named: $flowReply" }

    // The engine is ready.
    check(engine.isReady()) { "engine ready" }

    // The notification channel answers (nothing queued yet).
    check(engine.takeNotifications().isEmpty()) { "no notifications queued" }

    println("in-process-engine-smoke: ok — session created, capability-less flow refused with -31005")
}