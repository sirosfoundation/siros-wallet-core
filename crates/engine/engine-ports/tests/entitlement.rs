//! The entitlement wire types (ARF 6.6.2.3), as the Go stack defines
//! them: the mode, the finding codes, and the bounded decision the
//! relay carries — `go-wallet-backend`'s `pkg/issuertrust` (branch
//! `feat/issuer-entitlement-in-evaluate`) and go-wmp's
//! `IssuerEntitlement.Bounded()` (#526) are the reference.

use engine_ports::{
    EntitlementCode, EntitlementDecision, EntitlementFinding, EntitlementMode, EntitlementRequest,
    EvaluationRequest, EvaluationResponse, Pdp, PdpError, ResolveRequest, ResolveResponse,
};

/// The mode names, as the Go evaluator parses them
/// (`issuertrust.ParseMode`): `warn`, `fail`, `off` — and the default:
/// an unrecognised value is warn, never off, so a typo cannot silently
/// disable the check (the ARF obligation applies 24 months after the
/// amending Regulation, so warn is the mode an unevaluated deployment
/// runs).
#[test]
fn the_mode_names_parse_with_warn_as_the_default() {
    // The Go reference: ParseMode returns ModeWarn for anything but
    // the two other names.
    assert_eq!(EntitlementMode::parse("warn"), EntitlementMode::Warn);
    assert_eq!(EntitlementMode::parse("fail"), EntitlementMode::Fail);
    assert_eq!(EntitlementMode::parse("off"), EntitlementMode::Off);
    for unrecognized in ["", "WARN", "strict", "failure"] {
        assert_eq!(
            EntitlementMode::parse(unrecognized),
            EntitlementMode::Warn,
            "unrecognised mode `{unrecognized}` must read as warn, never off"
        );
    }
}

/// The finding codes' wire names, as go-wmp's `IssuerEntitlement` relay
/// and the Go evaluator's `Code` strings carry them: a caller acts on
/// the code, never on a sentence, so the names are the contract.
#[test]
fn the_finding_codes_carry_their_wire_names() {
    // One entry per code, from the Go evaluator's Code constants.
    let expected = [
        (
            EntitlementCode::NoAccessCertificate,
            "no_access_certificate",
        ),
        (EntitlementCode::NotWrpac, "access_certificate_not_wrpac"),
        (
            EntitlementCode::NoRegistrationCertificate,
            "no_registration_certificate",
        ),
        (
            EntitlementCode::RegistrationMalformed,
            "registration_certificate_malformed",
        ),
        (
            EntitlementCode::RegistrationExpired,
            "registration_certificate_expired",
        ),
        (
            EntitlementCode::RegistrationOverlong,
            "registration_certificate_validity_too_long",
        ),
        (
            EntitlementCode::BindingMismatch,
            "registration_certificate_not_bound",
        ),
        (EntitlementCode::NotProvider, "not_an_attestation_provider"),
        (
            EntitlementCode::TypeNotRegistered,
            "attestation_type_not_registered",
        ),
        (
            EntitlementCode::RegistrationUnverified,
            "registration_certificate_unverified",
        ),
        (
            EntitlementCode::RegistrarNotTrusted,
            "registrar_not_trusted",
        ),
        (
            EntitlementCode::AccessCertificateNotTrusted,
            "access_certificate_not_trusted",
        ),
    ];
    for (code, name) in &expected {
        assert_eq!(code.as_str(), *name);
    }
    assert_eq!(expected.len(), 12, "the twelve codes of the Go evaluator");
}

/// The bounds of the relayed decision: at most 16 findings, a message
/// cut at 256 bytes, a credential type at 128 — the Go evaluator's
/// `MaxFindings` and `MaxCredentialTypeLen`, and go-wmp's message cap
/// in `Bounded()` (#526). Whatever the evaluator answered, the relay
/// carries no more.
#[test]
fn the_bounded_decision_caps_the_findings() {
    // Seventeen findings arise; the relay carries sixteen and the
    // truncation flag (the Go evaluator counts the rest, never lists
    // them).
    let findings: Vec<EntitlementFinding> = (0..17)
        .map(|i| EntitlementFinding {
            code: EntitlementCode::NoRegistrationCertificate,
            message: format!("finding {i}"),
            credential_type: None,
        })
        .collect();
    let decision = EntitlementDecision {
        allowed: false,
        mode: EntitlementMode::Fail,
        evaluated: true,
        findings,
        findings_truncated: false,
    };

    let bounded = decision.bounded();
    assert_eq!(bounded.findings.len(), 16, "the Go MaxFindings");
    assert!(bounded.findings_truncated);
    assert!(!bounded.allowed);
    assert_eq!(bounded.mode, EntitlementMode::Fail);
    assert!(bounded.evaluated);
}

/// The message cut lands on a character boundary: a cut byte would
/// produce invalid UTF-8 in the relay.
#[test]
fn the_bounded_decision_cuts_messages_on_character_boundaries() {
    // 300 one-byte characters: the cut is at the 256-byte cap.
    let decision = EntitlementDecision {
        allowed: true,
        mode: EntitlementMode::Warn,
        evaluated: true,
        findings: vec![EntitlementFinding {
            code: EntitlementCode::NotProvider,
            message: "x".repeat(300),
            credential_type: None,
        }],
        findings_truncated: false,
    };
    assert_eq!(decision.bounded().findings[0].message.len(), 256);

    // A three-byte character straddling the cap: the cut drops the
    // whole character, leaving 255 bytes, not 256.
    let decision = EntitlementDecision {
        allowed: true,
        mode: EntitlementMode::Warn,
        evaluated: true,
        findings: vec![EntitlementFinding {
            code: EntitlementCode::NotProvider,
            message: "€".repeat(86),
            credential_type: None,
        }],
        findings_truncated: false,
    };
    let cut = &decision.bounded().findings[0].message;
    assert_eq!(cut.len(), 255, "the whole 3-byte character is dropped");
}

/// The credential type cut: 128 bytes, the Go evaluator's
/// `MaxCredentialTypeLen`.
#[test]
fn the_bounded_decision_cuts_credential_types_at_one_twenty_eight() {
    let decision = EntitlementDecision {
        allowed: true,
        mode: EntitlementMode::Warn,
        evaluated: true,
        findings: vec![EntitlementFinding {
            code: EntitlementCode::TypeNotRegistered,
            message: "the type is not registered".to_owned(),
            credential_type: Some("x".repeat(200)),
        }],
        findings_truncated: false,
    };
    let bounded = decision.bounded();
    assert_eq!(
        bounded.findings[0].credential_type.as_deref().map(str::len),
        Some(128),
        "the Go MaxCredentialTypeLen"
    );
}

/// The no-evaluation decision (ARF 6.6.2.3's grace): nothing was
/// checked, and "not checked" must never read as "checked and fine" —
/// so `evaluated` is false while `allowed` stays true.
#[test]
fn the_not_evaluated_decision_allows_without_evaluating() {
    let decision = engine_ports::entitlement_not_evaluated();
    assert!(decision.allowed);
    assert!(!decision.evaluated);
    assert!(decision.findings.is_empty());
    assert!(!decision.findings_truncated);
}

/// A PDP that does not implement the operation answers
/// `NotImplemented` — the default every minimal PDP inherits, which
/// the flow call-site reads as "not evaluated" (the ARF's grace, so a
/// minimal host keeps every flow working).
#[tokio::test]
async fn a_pdp_without_the_operation_answers_not_implemented() {
    /// The minimal PDP: the trust operations alone, nothing else.
    struct MinimalPdp;

    #[async_trait::async_trait]
    impl Pdp for MinimalPdp {
        async fn evaluate(
            &self,
            _request: EvaluationRequest,
        ) -> Result<EvaluationResponse, PdpError> {
            Ok(EvaluationResponse {
                trusted: true,
                decision: None,
                context: None,
            })
        }

        async fn resolve(&self, _request: ResolveRequest) -> Result<ResolveResponse, PdpError> {
            Ok(ResolveResponse {
                metadata: Vec::new(),
                trust_info: None,
            })
        }
    }

    let request = EntitlementRequest {
        issuer: "https://issuer.example".to_owned(),
        metadata: Vec::new(),
        key_material: Vec::new(),
        offers: Vec::new(),
    };
    let answer = MinimalPdp.evaluate_entitlement(request).await;
    assert!(matches!(answer, Err(PdpError::NotImplemented)));
}
