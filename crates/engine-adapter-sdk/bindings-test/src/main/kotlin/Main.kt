import uniffi.engine_adapter_sdk.FetchPurpose
import uniffi.engine_adapter_sdk.Host
import uniffi.engine_adapter_sdk.HttpClient
import uniffi.engine_adapter_sdk.HttpRequest
import uniffi.engine_adapter_sdk.HttpResponse
import uniffi.engine_adapter_sdk.SdkException
import uniffi.engine_adapter_sdk.ping
import uniffi.engine_adapter_sdk.runPreAuthorizedFlow

/**
 * The JVM smoke of the engine's async port shapes (P0.4): the JVM
 * implements the engine's async HttpClient and Host callback interfaces
 * with suspend functions, and drives an exported async flow function end
 * to end against the engine cdylib.
 *
 * Build and run from the repository root:
 *
 *   make check-bindings            # generates bindings/kotlin
 *   make kotlin-smoke              # compiles and runs this file
 */
class TestHttpClient : HttpClient {
    override suspend fun send(request: HttpRequest): HttpResponse {
        // Assert the engine declared the purpose and the limits the port
        // contract promises, and answer the world's two endpoints.
        return when (request.purpose) {
            FetchPurpose.ISSUER_METADATA -> {
                check(request.maxResponseBytes == 1048576UL) {
                    "metadata fetch must declare the 1 MiB limit, got ${request.maxResponseBytes}"
                }
                HttpResponse(200u, "issuer-metadata".toByteArray())
            }
            FetchPurpose.TOKEN -> {
                check(request.method == "POST") { "token fetch must be a POST" }
                check(request.body.decodeToString().contains("tx_code=1234")) {
                    "token fetch must carry the answered tx_code, got ${request.body.decodeToString()}"
                }
                HttpResponse(200u, "credential-issued".toByteArray())
            }
            else -> throw IllegalStateException("unexpected purpose: ${request.purpose}")
        }
    }
}

class TestHost : Host {
    override suspend fun requestTxCode(flowId: String): String {
        check(flowId == "flow-1") { "unexpected flow id: $flowId" }
        return "1234"
    }
}

fun main() = kotlinx.coroutines.runBlocking {
    val pong = ping()
    check(pong == "pong") { "ping returned $pong" }

    val result = runPreAuthorizedFlow(TestHttpClient(), TestHost(), "https://issuer.example")
    check(result == "credential-issued") { "flow returned $result" }

    // A declined sub-flow surfaces as the SDK's Declined error.
    val declined = try {
        runPreAuthorizedFlow(
            TestHttpClient(),
            object : Host {
                override suspend fun requestTxCode(flowId: String): String = ""
            },
            "https://issuer.example",
        )
        error("the declined flow should not have succeeded")
    } catch (e: SdkException.Declined) {
        "declined"
    }
    check(declined == "declined")

    println("uniffi-async-smoke: ok — async ports across UniFFI work on the JVM")
}
