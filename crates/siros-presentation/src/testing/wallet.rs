//! The wallet: its credentials, its host, and the phases driven to the response.

use crate::{
    plan, AdditionIndex, Fulfilment, OfferIndex, PlanInput, Planned, PresentationError, Response,
    Selection, SignId, Subset,
};
use ciborium::Value as Ciborium;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::DateTime;
use siros_codec::signature::Es256Signature;
use siros_credential::Credential;
use siros_dcql::QueryId;
use siros_display::{CardText, CardWording, DisplayCache, Locale};
use siros_oid4vp::VerifiedRequest;
use siros_transaction_data::{Amr, Configuration, Factor, HeldMetadata, Inherence, Possession};
use siros_trust::TrustStore;
use siros_wallet_state::{CredentialId, WalletState};
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::testing::{self, Issuer, Spec, TestProver, SEED};
use siros_zkp_req_nym_auth::verifier_id::VerifierIdForm;

use super::host::{holding_absent, issuer_display, label_text};
use super::verifier::{b64, Rng, NOW};

/// The holder's key, nym_auth's test device key, which every credential is bound to.
pub fn holder() -> SigningKey {
    testing::key(Spec::default().device)
}

/// The public JWK of the holder's key.
pub fn holder_jwk() -> Value {
    let point = holder().verifying_key().to_encoded_point(false);
    json!({"kty": "EC", "crv": "P-256", "x": b64(point.x().unwrap()), "y": b64(point.y().unwrap())})
}

pub const VCT: &str = "https://issuer.example/pid";
pub const MDL: &str = "org.iso.18013.5.1.mDL";
pub const MDL_NS: &str = "org.iso.18013.5.1";

/// The `[salt, name, value]` disclosure of a claim, base64url.
fn disclosure(name: &str, value: &Value) -> String {
    b64(json!([b64(name.as_bytes()), name, value])
        .to_string()
        .as_bytes())
}

/// An SD-JWT VC of `vct` bound to the holder's key, with the selectively disclosable claims
/// `claims`.
pub fn sd_jwt(vct: &str, claims: &[(&str, Value)]) -> String {
    sd_jwt_with(vct, claims, json!({}))
}

/// An SD-JWT VC as [`sd_jwt`] gives it, with the payload members of `extra`.
pub fn sd_jwt_with(vct: &str, claims: &[(&str, Value)], extra: Value) -> String {
    sd_jwt_issued(
        vct,
        claims,
        extra,
        json!({"alg": "ES256", "typ": "dc+sd-jwt"}),
    )
}

/// An SD-JWT VC as [`sd_jwt`] gives it, whose issuer JWT header carries the certificates `x5c`,
/// DER, in base64.
pub fn sd_jwt_x5c(vct: &str, claims: &[(&str, Value)], x5c: &[&[u8]]) -> String {
    let x5c: Vec<String> = x5c.iter().map(|der| base64(der)).collect();
    let header = json!({"alg": "ES256", "typ": "dc+sd-jwt", "x5c": x5c});
    sd_jwt_issued(vct, claims, json!({}), header)
}

/// base64 with padding (RFC 4648, Section 4), as `x5c` writes a certificate.
pub fn base64(bytes: &[u8]) -> String {
    let mut text = b64(bytes).replace('-', "+").replace('_', "/");
    while text.len() % 4 != 0 {
        text.push('=');
    }
    text
}

fn sd_jwt_issued(vct: &str, claims: &[(&str, Value)], extra: Value, header: Value) -> String {
    let disclosures: Vec<String> = claims.iter().map(|(n, v)| disclosure(n, v)).collect();
    let digests: Vec<String> = disclosures
        .iter()
        .map(|d| b64(&Sha256::digest(d.as_bytes())))
        .collect();
    let mut payload = json!({
        "iss": "https://issuer.example",
        "vct": vct,
        "cnf": {"jwk": holder_jwk()},
        "_sd": digests,
        "_sd_alg": "sha-256",
    });
    for (name, value) in extra.as_object().unwrap() {
        payload[name] = value.clone();
    }
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(payload.to_string().as_bytes())
    );
    let signature: Signature = testing::key(0x44).sign(input.as_bytes());
    let mut compact = format!("{input}.{}~", b64(&signature.to_bytes()));
    for d in disclosures {
        compact.push_str(&d);
        compact.push('~');
    }
    compact
}

/// The disclosure of a claim of [`sd_jwt`], as the presentation carries it.
pub fn disclosed(name: &str, value: &Value) -> String {
    disclosure(name, value)
}

/// An mdoc of `doc_type` bound to the holder's key, with the elements `items` in one namespace.
pub fn mdoc(doc_type: &str, name_space: &str, items: &[(&str, Cbor)]) -> String {
    mdoc_by(
        &Issuer::root(0x12, "Test mDL issuer"),
        doc_type,
        name_space,
        items,
    )
}

/// An mdoc as [`mdoc`] gives it, which `issuer` signs, its certificate the `x5chain`.
pub fn mdoc_by(
    issuer: &Issuer,
    doc_type: &str,
    name_space: &str,
    items: &[(&str, Cbor)],
) -> String {
    let text = Cbor::text;
    let tagged = |value: &Cbor| Cbor::Tag(24, Box::new(Cbor::Bytes(value.encode())));
    let encoded: Vec<Vec<u8>> = items
        .iter()
        .enumerate()
        .map(|(id, (identifier, value))| {
            tagged(&Cbor::Map(vec![
                (text("digestID"), Cbor::Unsigned(id as u64)),
                (text("random"), Cbor::Bytes(vec![id as u8; 16])),
                (text("elementIdentifier"), text(identifier)),
                (text("elementValue"), value.clone()),
            ]))
            .encode()
        })
        .collect();
    let digests = encoded
        .iter()
        .enumerate()
        .map(|(id, item)| {
            (
                Cbor::Unsigned(id as u64),
                Cbor::Bytes(Sha256::digest(item).to_vec()),
            )
        })
        .collect();
    let point = holder().verifying_key().to_encoded_point(false);
    let tdate = |t: &str| Cbor::Tag(0, Box::new(text(t)));
    let mso = Cbor::Map(vec![
        (text("version"), text("1.0")),
        (text("digestAlgorithm"), text("SHA-256")),
        (
            text("valueDigests"),
            Cbor::Map(vec![(text(name_space), Cbor::Map(digests))]),
        ),
        (
            text("deviceKeyInfo"),
            Cbor::Map(vec![(
                text("deviceKey"),
                Cbor::Map(vec![
                    (Cbor::Unsigned(1), Cbor::Unsigned(2)),
                    (Cbor::Negative(0), Cbor::Unsigned(1)),
                    (Cbor::Negative(1), Cbor::Bytes(point.x().unwrap().to_vec())),
                    (Cbor::Negative(2), Cbor::Bytes(point.y().unwrap().to_vec())),
                ]),
            )]),
        ),
        (text("docType"), text(doc_type)),
        (
            text("validityInfo"),
            Cbor::Map(vec![
                (text("signed"), tdate("2026-01-01T00:00:00Z")),
                (text("validFrom"), tdate("2026-01-01T00:00:00Z")),
                (text("validUntil"), tdate("2027-01-01T00:00:00Z")),
            ]),
        ),
    ]);
    let payload = tagged(&mso).encode();
    let protected = Cbor::Map(vec![(Cbor::Unsigned(1), Cbor::Negative(6))]).encode();
    let sig_structure = Cbor::Array(vec![
        text("Signature1"),
        Cbor::Bytes(protected.clone()),
        Cbor::Bytes(Vec::new()),
        Cbor::Bytes(payload.clone()),
    ])
    .encode();
    let signature: Signature = issuer.key.sign(&sig_structure);
    let issuer_signed = Cbor::Map(vec![
        (
            text("nameSpaces"),
            Cbor::Map(vec![(
                text(name_space),
                Cbor::Array(encoded.into_iter().map(Cbor::Encoded).collect()),
            )]),
        ),
        (
            text("issuerAuth"),
            Cbor::Array(vec![
                Cbor::Bytes(protected),
                Cbor::Map(vec![(Cbor::Unsigned(33), Cbor::Bytes(issuer.der.clone()))]),
                Cbor::Bytes(payload),
                Cbor::Bytes(signature.to_bytes().to_vec()),
            ]),
        ),
    ]);
    base64url::encode(&issuer_signed.encode()).into_string()
}

/// A nym_auth attestation of nym_auth's test issuer, with its seed delivered.
pub fn nym_auth(spec: &Spec) -> (String, Value) {
    let issuer = Issuer::root(0x11, "Test Document Signer");
    let data = testing::issue(&issuer, spec);
    let auxiliary = json!([{"type": "auxiliary_data", "value": [{
        "type": "hash_commitment", "alg": "sha-256",
        "path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"],
        "opening": b64(&SEED)
    }]}]);
    (data, auxiliary)
}

/// The issuer certificate of [`nym_auth`]'s attestations.
pub fn nym_auth_issuer() -> Vec<u8> {
    Issuer::root(0x11, "Test Document Signer").der
}

/// A credential entry of the wallet state: `(format, data, metadata)` with `credentialId` `id`
/// in batch `batch`.
pub struct Held {
    pub id: u64,
    pub batch: u64,
    pub format: &'static str,
    pub data: String,
    pub metadata: Option<Value>,
}

impl Held {
    pub fn new(id: u64, format: &'static str, data: String) -> Self {
        Self {
            id,
            batch: id,
            format,
            data,
            metadata: None,
        }
    }
}

/// The host's card wording of the fixtures, in English: an issuer line of the name alone.
pub fn card_wording() -> CardWording {
    CardWording {
        title: CardText::new("Credential").unwrap(),
        issuer: CardText::new("Unknown issuer").unwrap(),
        issuer_template: None,
    }
}

/// The wallet: its state, its credentials, and what its host gives the plan.
pub struct Wallet {
    pub credentials: Vec<Credential>,
    pub display: DisplayCache,
    pub language: Locale,
    /// The host's card wording.
    pub card_wording: CardWording,
    pub configuration: Configuration,
    pub systems: Vec<NymAuthSystem>,
    pub verifier_id: VerifierIdForm,
    pub background: Vec<CredentialId>,
    pub key_factors: Vec<(siros_wallet_state::KeyId, Amr)>,
    /// The transaction metadata the host holds.
    pub metadata: HeldMetadata,
    pub trust: TrustStore,
    state: WalletState,
}

impl Wallet {
    /// A wallet holding `held`, each bound to the holder's key under the `kid` `key-<id>`.
    pub fn new(held: Vec<Held>) -> Self {
        Self::with_records(held, Vec::new())
    }

    /// A wallet holding `held`, whose presentation records name the credentials of each of
    /// `records`.
    pub fn with_records(held: Vec<Held>, records: Vec<Vec<u64>>) -> Self {
        let presentations: Vec<Value> = records
            .iter()
            .enumerate()
            .map(|(id, used)| {
                json!({
                    "presentationId": id, "transactionId": id, "data": "",
                    "usedCredentialIds": used, "presentationTimestampSeconds": 1_750_000_000,
                    "audience": "https://verifier.example"
                })
            })
            .collect();
        let entries: Vec<Value> = held
            .iter()
            .map(|h| {
                let mut entry = json!({
                    "credentialId": h.id,
                    "format": h.format,
                    "data": h.data,
                    "kid": format!("key-{}", h.id),
                    "instanceId": h.id,
                    "batchId": h.batch,
                    "credentialIssuerIdentifier": "https://issuer.example",
                    "credentialConfigurationId": "example"
                });
                if let Some(metadata) = &h.metadata {
                    entry["metadata"] = metadata.clone();
                }
                entry
            })
            .collect();
        let state = WalletState::parse(
            &json!({
                "schemaVersion": 4,
                "credentials": entries,
                "keypairs": [],
                "presentations": presentations,
                "settings": {"openidRefreshTokenMaxAgeInSeconds": "0"},
                "credentialIssuanceSessions": []
            })
            .to_string(),
        )
        .unwrap();
        let credentials: Vec<Credential> = state
            .credentials()
            .iter()
            .map(|e| Credential::parse(e).unwrap())
            .collect();
        let amr = Amr::new(vec![
            Factor::Possession(Possession::KeyInLocalNativeWscd),
            Factor::Inherence(Inherence::FingerprintDevice),
        ])
        .unwrap();
        let key_factors = credentials
            .iter()
            .filter_map(|c| c.key_id().cloned())
            .map(|kid| (kid, amr.clone()))
            .collect();
        Self {
            credentials,
            display: issuer_display(),
            language: Locale::parse("en").unwrap(),
            card_wording: card_wording(),
            configuration: Configuration::default(),
            systems: NymAuthSystem::ALL.to_vec(),
            verifier_id: VerifierIdForm::X509SanDns,
            background: Vec::new(),
            key_factors,
            metadata: holding_absent(&[VCT]),
            trust: TrustStore::parse("[]").unwrap(),
            state,
        }
    }

    /// The wallet's presentation records.
    pub fn records(&self) -> &[siros_wallet_state::PresentationRecord] {
        self.state.presentations()
    }

    /// Every credential is presentable without the wallet's UI.
    pub fn all_in_background(mut self) -> Self {
        self.background = self
            .credentials
            .iter()
            .map(|c| c.entry().credential_id())
            .collect();
        self
    }

    pub fn input<'a>(&'a self, request: &'a VerifiedRequest) -> PlanInput<'a> {
        PlanInput {
            request,
            credentials: &self.credentials,
            trust: &self.trust,
            records: self.state.presentations(),
            display: &self.display,
            language: &self.language,
            card_wording: &self.card_wording,
            configuration: &self.configuration,
            held: &self.metadata,
            systems: &self.systems,
            verifier_id: self.verifier_id,
            background: &self.background,
            key_factors: &self.key_factors,
            now: DateTime::from_unix(NOW).unwrap(),
        }
    }
}

/// The plan of `input`. Its view shows neither the seed nym_auth's test issuer delivers nor the
/// picker's marker of an unverified request.
pub fn ready<'a>(input: &PlanInput<'a>) -> Result<Planned<'a>, PresentationError> {
    let planned = plan(input)?;
    let texts = view_texts(planned.view());
    let opening = b64(&SEED);
    assert!(texts.iter().all(|t| !t.contains(&opening)), "{texts:?}");
    assert!(
        texts.iter().all(|t| !t.contains("(unverified request)")),
        "{texts:?}"
    );
    Ok(planned)
}

/// The host's signatures for every `Sign` effect of `prepared`, with the holder's key.
pub fn sign_all(signs: &[crate::Sign]) -> Vec<(SignId, Es256Signature)> {
    signs
        .iter()
        .map(|sign| {
            assert!(sign.key().as_str().starts_with("key-"));
            let signature: Signature = holder().sign(sign.input());
            (sign.id(), Es256Signature::new(signature.to_bytes().into()))
        })
        .collect()
}

/// Both phases for the offer at `offer` of the plan of `input`, with the additions at
/// `additions` and the subsets `subsets` of `credentialId`s: the plan, then
/// [`respond_with`] the selection on the plan's digest.
pub fn respond_to(
    input: &PlanInput<'_>,
    offer: usize,
    additions: Vec<usize>,
    subsets: Vec<(String, Vec<u64>)>,
) -> Result<Response, PresentationError> {
    let digest = *ready(input)?.view().digest();
    let subsets = subsets
        .into_iter()
        .map(|(query, ids)| {
            let ids = ids.into_iter().map(CredentialId::new).collect();
            Subset::new(QueryId::parse(&query).unwrap(), ids)
        })
        .collect();
    let additions = additions.into_iter().map(AdditionIndex::new).collect();
    let selection = Selection::new(digest, OfferIndex::new(offer), additions, subsets);
    respond_with(input, |_| Ok(selection))
}

/// Phase 2 for the selection `select` makes on the plan of `input`: the plan again, the
/// selection, the holder's signatures and the response.
pub fn respond_with(
    input: &PlanInput<'_>,
    select: impl FnOnce(&Planned<'_>) -> Result<Selection, PresentationError>,
) -> Result<Response, PresentationError> {
    let planned = ready(input)?;
    let selection = select(&planned)?;
    let chosen = planned.choose(&selection, Fulfilment::WalletUi)?;
    let mut rng = Rng(77);
    let prepared = chosen.prepare(&mut rng)?;
    let signatures = sign_all(prepared.signs());
    prepared.finish(signatures, &TestProver { fail: None }, &mut rng)
}

/// Both phases for the first offer of the plan of `input`: the plan, the plan again, the
/// selection on the plan's digest, the signatures and the response.
pub fn respond(input: &PlanInput<'_>) -> Response {
    let digest = *ready(input).unwrap().view().digest();
    let planned = ready(input).unwrap();
    let selection = Selection::new(digest, OfferIndex::new(0), Vec::new(), Vec::new());
    let chosen = planned.choose(&selection, Fulfilment::WalletUi).unwrap();
    let mut rng = Rng(77);
    let prepared = chosen.prepare(&mut rng).unwrap();
    let signatures = sign_all(prepared.signs());
    prepared
        .finish(signatures, &TestProver { fail: None }, &mut rng)
        .unwrap()
}

/// An ES256 signature `r ‖ s` verifies `message` under the holder's key.
pub fn holder_signed(message: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    let signature = Signature::from_slice(signature).unwrap();
    holder().verifying_key().verify(message, &signature).is_ok()
}

/// The CBOR item of `bytes`, read with ciborium.
pub fn ciborium(bytes: &[u8]) -> Ciborium {
    ciborium::from_reader(bytes).unwrap()
}

/// Every text a consent view shows, the digest included.
pub fn view_texts(view: &crate::ConsentView<'_>) -> Vec<String> {
    use crate::{MemberView, Shown};
    use siros_display::{ClaimRow, DisplayValue};
    use siros_transaction_data::RowValue;

    fn value(shown: &DisplayValue, out: &mut Vec<String>) {
        match shown {
            DisplayValue::Text(text) => out.push(text.clone()),
            DisplayValue::List(values) => values.iter().for_each(|v| value(v, out)),
            DisplayValue::Group(rows) => rows.iter().for_each(|r| row(r, out)),
            _ => {}
        }
    }
    fn row(claim: &ClaimRow, out: &mut Vec<String>) {
        out.push(claim.label().as_str().to_owned());
        value(claim.value(), out);
    }
    fn member(member: &MemberView, out: &mut Vec<String>) {
        out.push(member.query_id().as_str().to_owned());
        for credential in member.credentials() {
            let card = credential.card();
            out.push(card.title().as_str().to_owned());
            out.push(card.issuer().as_str().to_owned());
            match credential.shown() {
                Shown::Claims(rows) => rows.iter().for_each(|r| row(r, out)),
                Shown::Proof(rows) => {
                    for proof in rows {
                        out.push(proof.label().as_str().to_owned());
                        out.extend(proof.value().map(|v| v.as_str().to_owned()));
                    }
                }
            }
            if let Some(transaction) = credential.transaction() {
                let view = transaction.view();
                out.extend(view.affirmative_action_label().map(label_text));
                for row in view.rows() {
                    out.push(label_text(row.label()));
                    if let RowValue::Value(value) = row.value() {
                        out.push(value.text());
                    }
                }
            }
        }
    }
    let mut out = vec![
        view.verifier().display().to_owned(),
        view.digest().to_string(),
    ];
    for offer in view.offers() {
        out.extend(offer.purpose().map(str::to_owned));
        offer.members().iter().for_each(|m| member(m, &mut out));
        for addition in offer.additions() {
            out.extend(addition.purpose().map(str::to_owned));
            addition.members().iter().for_each(|m| member(m, &mut out));
        }
    }
    out
}
