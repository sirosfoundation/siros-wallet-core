import uniffi.engine_adapter_sdk.AttestationParams
import uniffi.engine_adapter_sdk.AttestationResult
import uniffi.engine_adapter_sdk.ConsentParams
import uniffi.engine_adapter_sdk.ConsentResult
import uniffi.engine_adapter_sdk.CredentialSelectionParams
import uniffi.engine_adapter_sdk.CredentialSelectionResult
import uniffi.engine_adapter_sdk.FetchPurpose
import uniffi.engine_adapter_sdk.HeaderPair
import uniffi.engine_adapter_sdk.Host
import uniffi.engine_adapter_sdk.HttpClient
import uniffi.engine_adapter_sdk.HttpRequest
import uniffi.engine_adapter_sdk.HttpResponse
import uniffi.engine_adapter_sdk.MatchResult
import uniffi.engine_adapter_sdk.MatchParams
import uniffi.engine_adapter_sdk.SigningKeyParams
import uniffi.engine_adapter_sdk.SigningKeyResult
import uniffi.engine_adapter_sdk.VpParams
import uniffi.engine_adapter_sdk.VpResult
import uniffi.engine_adapter_sdk.DpopProofParams
import uniffi.engine_adapter_sdk.DpopProofResult
import uniffi.engine_adapter_sdk.RedirectPolicy
import uniffi.engine_adapter_sdk.SdkException
import uniffi.engine_adapter_sdk.SignParams
import uniffi.engine_adapter_sdk.SignResult
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
 *   make kotlin-smoke
 */
class TestHttpClient : HttpClient {
    override suspend fun send(request: HttpRequest): HttpResponse {
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
    override suspend fun requestSign(params: SignParams): SignResult {
        throw SdkException.Declined()
    }

    override suspend fun requestMatch(params: MatchParams): MatchResult {
        throw SdkException.Declined()
    }

    override suspend fun requestVp(params: VpParams): VpResult {
        throw SdkException.Declined()
    }

    override suspend fun requestDpopProof(params: DpopProofParams): DpopProofResult {
        throw SdkException.Declined()
    }

    override suspend fun requestConsent(params: ConsentParams): ConsentResult {
        return ConsentResult(true)
    }

    override suspend fun requestTxCode(flowId: String): String {
        check(flowId == "flow-1") { "unexpected flow id: $flowId" }
        return "1234"
    }

    override suspend fun openAuthorization(flowId: String, url: String): Unit {
        // No browser in the smoke.
    }

    override suspend fun requestSigningKey(params: SigningKeyParams): SigningKeyResult {
        // No named key in the smoke: the engine proceeds without key
        // identification.
        throw SdkException.Cannot("no named key")
    }

    override suspend fun requestAttestation(params: AttestationParams): AttestationResult {
        // No client attestation in the smoke: the flow continues
        // without it.
        throw SdkException.Cannot("no attestation")
    }

    override suspend fun requestCredentialSelection(
        params: CredentialSelectionParams,
    ): CredentialSelectionResult {
        // No selection UI in the smoke (a single-configuration offer
        // never asks).
        throw SdkException.Cannot("no selection UI")
    }

    override fun progress(flowId: String, step: String, detail: String?) {
        // No progress in the smoke.
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
                override suspend fun requestSign(params: SignParams): SignResult =
                    throw SdkException.Declined()
                override suspend fun requestMatch(params: MatchParams): MatchResult =
                    throw SdkException.Declined()
                override suspend fun requestVp(params: VpParams): VpResult =
                    throw SdkException.Declined()
                override suspend fun requestDpopProof(params: DpopProofParams): DpopProofResult =
                    throw SdkException.Declined()
                override suspend fun requestConsent(params: ConsentParams): ConsentResult =
                    ConsentResult(false)
                override suspend fun requestTxCode(flowId: String): String = ""
                override suspend fun openAuthorization(flowId: String, url: String): Unit {}
                override suspend fun requestSigningKey(params: SigningKeyParams): SigningKeyResult =
                    throw SdkException.Cannot("no named key")
                override suspend fun requestAttestation(params: AttestationParams): AttestationResult =
                    throw SdkException.Cannot("no attestation")
                override suspend fun requestCredentialSelection(
                    params: CredentialSelectionParams,
                ): CredentialSelectionResult =
                    throw SdkException.Cannot("no selection UI")
                override fun progress(flowId: String, step: String, detail: String?) {}
            },
            "https://issuer.example",
        )
        error("the declined flow should not have succeeded")
    } catch (e: SdkException.Declined) {
        "declined"
    }
    check(declined == "declined")

    println("uniffi-async-smoke: ok — the engine's port traits work over UniFFI on the JVM")

    // The in-process engine smoke: session lifecycle through the
    // WmpEngine handle, no WebSocket.
    engineSmoke()
}