// The panic-lint discipline (AGENTS.md: nothing panics outside the tests).
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

//! The OpenMLS-backed [`MlsProvider`] (the wmp-mls spec, RFC 9420): the
//! engine's real MLS group cryptography.
//!
//! **The 0.10 line** (issue #114): `openmls_rust_crypto` 0.7 carries
//! hpke-rs 0.8 → hpke-rs-libcrux 0.8.1 → libcrux ≥0.0.10, lifting the
//! eight RUSTSEC advisories the 0.8 line's libcrux =0.0.7 carried.
//! The 0.10 crates declare MSRV 1.94 — above the workspace floor
//! (1.94, raised with this upgrade, issue #114).
//!
//! The wire shapes (wmp-mls spec §2–§4): every MLS artefact — KeyPackage,
//! Welcome, Commit, the application ciphertext — crosses WMP
//! **base64url-encoded** inside its JSON member; the group id is the
//! provider's own opaque string. The suites: 0x0001
//! (X25519/AES128GCM/Ed25519, MUST) and 0x0002 (P-256/AES128GCM, SHOULD) —
//! both openmls supports.
//!
//! The credential (spec §2.2): `basic` — the member's WMP identifier
//! string in the credential identity, authenticated outside MLS (the
//! session's own channel). The `x509` type arrives with the trust-anchor
//! work (Madrid's test-CA decision).
//!
//! **One provider = one WMP member** (one identity, one key store): the
//! provider's own `crypto` holds the member's private keys — the key
//! packages it issues and the Welcomes it joins — and every group it
//! holds is a group *this member* belongs to. The cross-member flows
//! (A's Welcome reaching B) ride the engine's message passing, the
//! KeyPackages riding the well-known publication (spec §2.3).

/// The engine's MLS handler bridge.
pub mod engine;

pub use engine::EngineMlsHandler;
use std::collections::BTreeMap;
use std::sync::Mutex;

use openmls::framing::{MlsMessageBodyIn, MlsMessageIn, ProcessedMessage, ProcessedMessageContent};
use openmls::group::{GroupEpoch, MlsGroup, MlsGroupJoinConfig, StagedWelcome};
use openmls::key_packages::{KeyPackage, KeyPackageIn};
// The prelude glob: openmls's own types (BasicCredential, Ciphersuite,
// CredentialWithKey, LeafNodeParameters) AND its tls_codec re-export (the
// Serialize/Deserialize traits — tls_serialize_detached,
// tls_deserialize_exact). One glob, one version.
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider as _;

// The certificate key import (issue #114): the PKCS#8 decoder trait
// (the same pkcs8 0.11 both signature crates re-export) and the SEC1
// point encoder for the P-256 public key.
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::pkcs8::DecodePrivateKey as _;

use wmp_core::error::RpcError;
use wmp_core::handler::HandlerError;
use wmp_core::mls::{
    KeyPackage as WmpKeyPackage, MlsProvider, CIPHER_SUITE_P256_AES128_GCM,
    CIPHER_SUITE_X25519_AES128_GCM,
};

/// The OpenMLS-backed provider: **one WMP member's** MLS cryptography. The
/// member's identity is its WMP identifier string; its key store holds
/// its private keys; its groups are the groups it belongs to.
pub struct OpenMlsProvider {
    /// The member's own key store: its key packages' private keys and the
    /// Welcomes it joins. One store for the member's whole life.
    crypto: OpenMlsRustCrypto,
    /// The member's own signature keypair (the group operations sign with
    /// it; the key packages mint it).
    signer: SignatureKeyPair,
    /// The member's WMP identifier string (the basic credential identity).
    identity: String,
    /// The member's X.509 certificate chain (DER, leaf first) when the
    /// identity authenticates by certificate (the `mtls`/`x5c` schemes):
    /// the MLS credential is X.509 (wmp-mls §2.3: "each participant uses
    /// the MLS credential type appropriate for their scheme"). Absent = the
    /// basic credential (the `did`/`opaque` schemes).
    certificate_chain: Vec<Vec<u8>>,
    groups: Mutex<BTreeMap<String, MlsGroup>>,
    next: Mutex<u64>,
}

impl OpenMlsProvider {
    /// The member's identity (its WMP identifier string).
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// A provider for the member `identity` (the WMP identifier string -
    /// the sender the session names).
    /// A provider for the member `identity` (the WMP identifier string -
    /// the sender the session names). Fallsible: the member's own
    /// signature keypair mints here (never a panic in library code).
    #[allow(clippy::needless_return)]
    pub fn for_identity(identity: &str) -> Result<Self, HandlerError> {
        Self::for_identity_with_certificate(identity, None)
    }

    /// A provider whose MLS credential is the X.509 certificate chain
    /// (wmp-mls §2.3: "each participant uses the MLS credential type
    /// appropriate for their scheme" — the `mtls`/`x5c` schemes carry the
    /// subscriber certificate, not a bare identity string). The chain is
    /// DER, leaf first; the MLS credential carries it so the group's peers
    /// find the member by certificate (found live at the Cleverbase
    /// interop: Echo's MLS refused to decrypt our messages because our
    /// member carried a BasicCredential while the scheme called for X.509).
    ///
    /// The member signs with a fresh Ed25519 key here — blind to the
    /// chain's key algorithm; [`Self::for_identity_with_certificate_and_key`]
    /// is the form that carries the leaf's own private key.
    pub fn for_identity_with_certificate(
        identity: &str,
        certificate_chain_der: Option<Vec<Vec<u8>>>,
    ) -> Result<Self, HandlerError> {
        Self::for_identity_with_certificate_and_key(identity, certificate_chain_der, None)
    }

    /// The signer-accepting form of [`Self::for_identity_with_certificate`]:
    /// the certificate's own private key signs the member's group
    /// operations. RFC 9420 §5.3.1: the leaf node's signature key is the
    /// credential's key — a chain whose leaf is P-256 must sign with that
    /// P-256 key, not with a fresh Ed25519 pair (the mismatch refuses:
    /// "the leaf node signature is not valid").
    ///
    /// `private_key_der` is the leaf's private key, PKCS#8 (RFC 5958) —
    /// the one DER form that names its own algorithm (the OID), so the
    /// signer type derives from the key itself: Ed25519 (RFC 8410 §7)
    /// or P-256 (RFC 5915). Without a key the member signs with a fresh
    /// Ed25519 pair (the current behaviour).
    pub fn for_identity_with_certificate_and_key(
        identity: &str,
        certificate_chain_der: Option<Vec<Vec<u8>>>,
        private_key_der: Option<Vec<u8>>,
    ) -> Result<Self, HandlerError> {
        let crypto = OpenMlsRustCrypto::default();
        let signer = match private_key_der {
            Some(der) => signer_from_pkcs8_der(&der)?,
            None => fresh_ed25519_signer()?,
        };
        Ok(Self {
            crypto,
            signer,
            identity: identity.to_owned(),
            certificate_chain: certificate_chain_der.unwrap_or_default(),
            groups: Mutex::new(BTreeMap::new()),
            next: Mutex::new(1),
        })
    }

    /// The suite a number names, or `-32602` (an unknown suite).
    fn suite(cipher_suite: i64) -> Result<Ciphersuite, HandlerError> {
        match cipher_suite {
            CIPHER_SUITE_X25519_AES128_GCM => {
                Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
            }
            CIPHER_SUITE_P256_AES128_GCM => {
                Ok(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
            }
            other => Err(RpcError::new(
                wmp_core::error::ERR_INVALID_PARAMS,
                Some(serde_json::json!({
                    "reason": "unknown cipher suite", "cipher_suite": other,
                })),
            )
            .into()),
        }
    }

    /// The member's own credential bundle: the X.509 certificate chain
    /// when the identity authenticates by certificate (wmp-mls §2.3:
    /// "each participant uses the MLS credential type appropriate for
    /// their scheme" — the mtls/x5c schemes carry the chain, and the
    /// group's peers find the member by it), the basic credential
    /// otherwise (the did/opaque schemes' bare identity string).
    fn credential(&self) -> CredentialWithKey {
        let credential = if !self.certificate_chain.is_empty() {
            // The X.509 credential content: the TLS-encoded certificate
            // chain (each cert: uint16 length + DER bytes), which
            // VLBytes wraps with the outer length during serialization.
            let mut content = Vec::new();
            for cert in &self.certificate_chain {
                // The certificate length rides the MLS varint encoding
                // (RFC 9420 §5.3: 0xxxxxxx for 0-127, 01xxxxxx xxxxxxxx
                // for 128-16383), NOT a uint16 — the uint16 form writes
                // `03 36` for 822 bytes where the protocol expects `43 36`.
                // Found live at the interop: Echo's ts-mls stopped with
                // "Data length exceeds buffer" on the uint16 form.
                let len = cert.len().min(16383);
                if len < 128 {
                    content.push(len as u8);
                } else {
                    content.push(0x40 | ((len >> 8) & 0x3F) as u8);
                    content.push((len & 0xFF) as u8);
                }
                content.extend_from_slice(cert);
            }
            openmls::credentials::Credential::new(
                openmls::credentials::CredentialType::X509,
                content,
            )
        } else {
            BasicCredential::new(self.identity.as_bytes().to_vec()).into()
        };
        CredentialWithKey {
            credential,
            signature_key: self.signer.public().to_vec().into(),
        }
    }

    /// A group's WMP id (`grp-<serial>`), minted. Retained for the engine
    /// handler's own group naming (the FFI surface keys by the MLS
    /// GroupId — see `create_group`); unused here since the id moved.
    #[allow(dead_code)]
    fn mint_id(&self) -> String {
        let mut next = self.next.lock().unwrap_or_else(|p| p.into_inner());
        let id = format!("grp-{:04}", *next);
        *next += 1;
        id
    }

    /// The epoch as the WMP results name it.
    fn epoch(group: &MlsGroup) -> i64 {
        let epoch: GroupEpoch = group.epoch();
        epoch.as_u64() as i64
    }
}

impl MlsProvider for OpenMlsProvider {
    /// A fresh KeyPackage (spec §2.3): serialized base64url, its `id`
    /// minted (`kp-<serial>`), the identity THIS member's own. The private
    /// keys land in the member's own key store — the Welcome join reads
    /// them back from there.
    fn generate_key_package(&self, cipher_suite: i64) -> Result<WmpKeyPackage, HandlerError> {
        let suite = Self::suite(cipher_suite)?;
        // Per-suite signature keys: the suite's algorithm names the scheme
        // (P-256 for 0x0002; the group's own signer may be another suite's).
        // The credential carries THIS signer's public key — the leaf's
        // signature and the credential's key must agree (the "leaf node
        // signature is not valid" refusal's cause).
        let signer = SignatureKeyPair::new(suite.signature_algorithm())
            .map_err(|e| mls_error(&e.to_string()))?;
        signer
            .store(self.crypto.storage())
            .map_err(|e| mls_error(&e.to_string()))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(self.identity.as_bytes().to_vec()).into(),
            signature_key: signer.public().to_vec().into(),
        };
        let bundle = KeyPackage::builder()
            // The published package must be addable to any group the
            // wire spec's accepted_credential_types ([x509, basic],
            // wmp-mls §2.3) admits: RFC 9420 valn0104 runs BOTH ways —
            // the group's members must accept the package's credential
            // type, and the package's leaf must accept the credential
            // types the group's members carry. openmls 0.10 holds an
            // explicitly-set capability list to exactly what it names
            // (the Reject policy), so both wire suites and both
            // credential types go in explicitly (a package minted
            // basic-only refuses a group with an X.509 member: found
            // by the certificate-key suite — the add failed with
            // "Credentials are not acceptable" the other way round).
            .leaf_node_capabilities(Capabilities::new(
                None,
                Some(&[
                    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                ]),
                None,
                None,
                Some(&[CredentialType::Basic, CredentialType::X509]),
            ))
            .build(suite, &self.crypto, &signer, credential)
            .map_err(|e| mls_error(&e.to_string()))?;
        let bytes = bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| mls_error(&e.to_string()))?;
        let id = {
            let mut next = self.next.lock().unwrap_or_else(|p| p.into_inner());
            let id = format!("kp-{:04}", *next);
            *next += 1;
            id
        };
        Ok(WmpKeyPackage {
            id,
            cipher_suite,
            key_package: base64url(&bytes),
            expires: String::new(),
        })
    }

    /// Creates a group (spec §3.1): THIS member's group. The Welcomes for
    /// the initial participants ride their KeyPackages — fetched from
    /// their well-known publication (spec §2.3) by the engine wiring — so
    /// this engine-side create names the participants for the registry
    /// and mints the group; the add flow ([`add_member`]) is how members
    /// with real packages join.
    ///
    /// **The id**: the group's own MLS `GroupId` (base64url) — NOT a
    /// provider-local mint. The GroupId rides the GroupContext (every
    /// member's tree shares it), so the id the create answers HERE is
    /// the same id [`process_welcome`] answers for a member joining the
    /// same group by its Welcome — the FFI contract keys the group
    /// operations by it across members (found by the FFI round-trip
    /// test: a member could not decrypt under the CREATOR's id because
    /// the join had minted a fresh, unrelated one).
    fn create_group(
        &self,
        cipher_suite: i64,
        participants: &[String],
    ) -> Result<(String, BTreeMap<String, String>), HandlerError> {
        let suite = Self::suite(cipher_suite)?;
        let group = MlsGroup::builder()
            // The suite the caller names governs the group (spec §3.1's
            // cipher_suite param). The builder's own default is 0x0001,
            // and a create that silently minted the default refused
            // every 0x0002 member's package later ("the add proposal's
            // ciphersuite ... do not match the ones in the group
            // context", RFC 9420 valn0201 — found by the
            // certificate-key suite after the 0.10 upgrade: the group
            // was 0x0001 while the added member's package was 0x0002).
            .ciphersuite(suite)
            // The Welcome's GroupInfo carries the ratchet tree (the
            // extension), so the joiner needs nothing out of band - the
            // book's own async handshaking rule.
            .use_ratchet_tree_extension(true)
            // The group creator's capabilities MUST advertise the wire
            // suites and the accepted credential types (wmp-mls spec
            // 2.3; RFC 9420 valn0104: every member's leaf must support
            // the group's ciphersuite and every other member's
            // credential type). openmls 0.10 holds an explicitly-set
            // capability list to exactly what it names (the Reject
            // policy) — an unset ciphersuite list is EMPTY, and the
            // create refused its own group (found by the round-trip
            // suite after the 0.10 upgrade). Both wire suites go in:
            // 0x0001 (the MUST) and 0x0002 (the SHOULD), both the
            // provider answers. Found live at the Cleverbase interop
            // in the 0.8 line: a creator's leaf that advertised
            // basic-only refused a peer whose KeyPackage carried an
            // X.509 credential ("Credentials are not acceptable") - the
            // provider's own group create refused the very members the
            // spec's accepted_credential_types ([x509, basic]) promise
            // to accept.
            .with_capabilities(Capabilities::new(
                None,
                Some(&[
                    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                ]),
                None,
                None,
                Some(&[CredentialType::Basic, CredentialType::X509]),
            ))
            .build(&self.crypto, &self.signer, self.credential())
            .map_err(|e| mls_error(&e.to_string()))?;
        // The participants the create names join by the add flow once
        // their KeyPackages arrive; the create still answers a Welcome per
        // name here for the engine's registry shape (empty ones until then
        // would be wrong - so the create with participants refuses the
        // not-yet-wired form rather than minting placeholder Welcomes).
        if !participants.is_empty() {
            return Err(not_implemented(
                "participant packages in create (use add_member)",
            ));
        }
        let group_id = base64url(group.group_id().as_slice());
        self.groups
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(group_id.clone(), group);
        Ok((group_id, BTreeMap::new()))
    }

    /// Joins by processing a Welcome (spec §3.2): the member's own key
    /// store holds the package the Welcome encrypted to — the group
    /// answers under a fresh minted id.
    fn process_welcome(&self, welcome: &str) -> Result<(String, i64), HandlerError> {
        let bytes = decode_base64url(welcome)?;
        let message =
            MlsMessageIn::tls_deserialize_exact(&bytes).map_err(|e| mls_error(&e.to_string()))?;
        // The official extraction (the book's own join path): the body
        // names its Welcome or the join refuses.
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(mls_error("the message is not a Welcome")),
        };
        let staged = StagedWelcome::new_from_welcome(
            &self.crypto,
            &MlsGroupJoinConfig::default(),
            welcome,
            // The ratchet tree rides the Welcome's GroupInfo (the create's
            // use_ratchet_tree_extension) — nothing out of band.
            None,
        )
        .map_err(|e| mls_error(&e.to_string()))?;
        let group = staged
            .into_group(&self.crypto)
            .map_err(|e| mls_error(&e.to_string()))?;
        let epoch = Self::epoch(&group);
        // The SAME id the creator's create answered (the MLS GroupId from
        // the shared GroupContext — see create_group): the join keys the
        // member's group by it, so the creator's id addresses the joiner's
        // group too.
        let group_id = base64url(group.group_id().as_slice());
        self.groups
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(group_id.clone(), group);
        Ok((group_id, epoch))
    }

    /// Adds a member (spec §3.3): the commit for the group, the Welcome
    /// for the member. The commit is merged immediately (the member set
    /// has grown the moment the commit is answered).
    fn add_member(
        &self,
        group_id: &str,
        key_package: &str,
    ) -> Result<(String, String), HandlerError> {
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        let Some(group) = groups.get_mut(group_id) else {
            return Err(no_group(group_id));
        };
        let bytes = decode_base64url(key_package)?;
        let package_in =
            KeyPackageIn::tls_deserialize_exact(&bytes).map_err(|e| mls_error(&e.to_string()))?;
        let package = package_in
            .validate(
                self.crypto.crypto(),
                openmls::versions::ProtocolVersion::default(),
            )
            .map_err(|e| mls_error(&e.to_string()))?;
        let (commit, welcome, _info) = group
            .add_members(&self.crypto, &self.signer, &[package])
            .map_err(|e| mls_error(&e.to_string()))?;
        // The staged commit merges now (the member set grew).
        group
            .merge_pending_commit(&self.crypto)
            .map_err(|e| mls_error(&e.to_string()))?;
        let commit_bytes = commit.to_bytes().map_err(|e| mls_error(&e.to_string()))?;
        let welcome_bytes = welcome.to_bytes().map_err(|e| mls_error(&e.to_string()))?;
        Ok((base64url(&commit_bytes), base64url(&welcome_bytes)))
    }

    /// Removes a member (spec §3.4): the commit.
    fn remove_member(&self, group_id: &str, participant: &str) -> Result<String, HandlerError> {
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        let Some(group) = groups.get_mut(group_id) else {
            return Err(no_group(group_id));
        };
        let wanted = BasicCredential::new(participant.as_bytes().to_vec());
        let index = group
            .members()
            .find(|m| m.credential.serialized_content() == wanted.identity())
            .map(|m| m.index)
            .ok_or_else(|| mls_error("the participant is not a member"))?;
        let (commit, _welcome, _info) = group
            .remove_members(&self.crypto, &self.signer, &[index])
            .map_err(|e| mls_error(&e.to_string()))?;
        group
            .merge_pending_commit(&self.crypto)
            .map_err(|e| mls_error(&e.to_string()))?;
        let bytes = commit.to_bytes().map_err(|e| mls_error(&e.to_string()))?;
        Ok(base64url(&bytes))
    }

    /// Processes a commit: the epoch it advanced to. The commit is
    /// **merged** — `process_message` only stages it (OpenMLS: the
    /// `StagedCommit` waits for [`MlsGroup::merge_staged_commit`], so the
    /// epoch does not advance until the merge — found by the FFI
    /// round-trip test: a member processed a removal commit and its
    /// epoch stayed put).
    fn process_commit(&self, group_id: &str, commit: &str) -> Result<i64, HandlerError> {
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        let Some(group) = groups.get_mut(group_id) else {
            return Err(no_group(group_id));
        };
        let bytes = decode_base64url(commit)?;
        let message =
            MlsMessageIn::tls_deserialize_exact(&bytes).map_err(|e| mls_error(&e.to_string()))?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|e| mls_error(&e.to_string()))?;
        let processed = group
            .process_message(&self.crypto, protocol_message)
            .map_err(|e| mls_error(&e.to_string()))?;
        if let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() {
            group
                .merge_staged_commit(&self.crypto, *staged)
                .map_err(|e| mls_error(&e.to_string()))?;
        }
        Ok(Self::epoch(group))
    }

    /// A self-update commit (spec §3.5): the new leaf's commit, merged.
    fn self_update(&self, group_id: &str) -> Result<String, HandlerError> {
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        let Some(group) = groups.get_mut(group_id) else {
            return Err(no_group(group_id));
        };
        let bundle = group
            .self_update(&self.crypto, &self.signer, LeafNodeParameters::default())
            .map_err(|e| mls_error(&e.to_string()))?;
        group
            .merge_pending_commit(&self.crypto)
            .map_err(|e| mls_error(&e.to_string()))?;
        let bytes = bundle
            .commit()
            .to_bytes()
            .map_err(|e| mls_error(&e.to_string()))?;
        Ok(base64url(&bytes))
    }

    /// Encrypts plaintext for the group (spec §4): the ciphertext, the
    /// epoch it was encrypted under.
    fn encrypt(&self, group_id: &str, plaintext: &[u8]) -> Result<(String, i64), HandlerError> {
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        let Some(group) = groups.get_mut(group_id) else {
            return Err(no_group(group_id));
        };
        let message = group
            .create_message(&self.crypto, &self.signer, plaintext)
            .map_err(|e| mls_error(&e.to_string()))?;
        let epoch = Self::epoch(group);
        let bytes = message.to_bytes().map_err(|e| mls_error(&e.to_string()))?;
        Ok((base64url(&bytes), epoch))
    }

    /// Decrypts the group's ciphertext (spec §4): the plaintext, the
    /// Exports the group's GroupInfo (spec 3.1's create param): the
    /// serialized MlsMessageOut, base64url, with the ratchet tree —
    /// the joiner's out-of-band bootstrap when the Welcome's own
    /// GroupInfo cannot serve.
    fn export_group_info(&self, group_id: &str) -> Result<String, HandlerError> {
        use openmls_traits::OpenMlsProvider as _;
        let groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        let Some(group) = groups.get(group_id) else {
            return Err(no_group(group_id));
        };
        let info = group
            .export_group_info(self.crypto.crypto(), &self.signer, true)
            .map_err(|e| mls_error(&e.to_string()))?;
        let bytes = info
            .tls_serialize_detached()
            .map_err(|e| mls_error(&e.to_string()))?;
        Ok(base64url(&bytes))
    }

    /// Decrypts base64url ciphertext from the group, returning the plaintext and the
    /// epoch. A message this member sent itself refuses (MLS ratchets —
    /// own ciphertexts do not decrypt; the recipient's provider answers).
    fn decrypt(&self, group_id: &str, ciphertext: &str) -> Result<(Vec<u8>, i64), HandlerError> {
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        let Some(group) = groups.get_mut(group_id) else {
            return Err(no_group(group_id));
        };
        let bytes = decode_base64url(ciphertext)?;
        let message =
            MlsMessageIn::tls_deserialize_exact(&bytes).map_err(|e| mls_error(&e.to_string()))?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|e| mls_error(&e.to_string()))?;
        let processed: ProcessedMessage = group
            .process_message(&self.crypto, protocol_message)
            .map_err(|e| mls_error(&e.to_string()))?;
        let epoch = Self::epoch(group);
        let plaintext = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
            _ => return Err(mls_error("the message is not an application message")),
        };
        Ok((plaintext, epoch))
    }
}

// ─── The signer (the certificate's key import) ─────────────────────────────

/// A fresh Ed25519 signer — the member's own signature keypair when no
/// certificate key arrives (the 0x0001 suite's algorithm, RFC 9420
/// §5.1). Fallible: never a panic in library code.
fn fresh_ed25519_signer() -> Result<SignatureKeyPair, HandlerError> {
    SignatureKeyPair::new(
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm(),
    )
    .map_err(|e| mls_error(&e.to_string()))
}

/// The certificate's private key as the member's signer. The PKCS#8
/// algorithm OID names the scheme — RFC 9420 §5.3.1: the credential's
/// signature key is the certificate's, so the signer type derives from
/// the key, and the public key derives from the private (the
/// certificate's own key pair, never a fresh one beside it).
///
/// Ed25519 (RFC 8410 §7) and P-256 (RFC 5915) — the two algorithms the
/// wire suites' leaf certificates carry. Each decoder checks its own
/// OID, so the two parses cannot borrow each other's keys; anything
/// else refuses (never a silent fallback that signs with a key the
/// certificate never certified).
fn signer_from_pkcs8_der(der: &[u8]) -> Result<SignatureKeyPair, HandlerError> {
    if let Ok(ed) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
        return Ok(SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            ed.as_bytes().to_vec(),
            ed.verifying_key().to_bytes().to_vec(),
        ));
    }
    if let Ok(ec) = p256::SecretKey::from_pkcs8_der(der) {
        // The public key in the encoding the MLS credential carries:
        // the uncompressed SEC1 point (RFC 9420 §5.3.1's signature
        // key; the same form SignatureKeyPair::new mints for 0x0002).
        let public = ec.public_key().to_sec1_point(false).as_bytes().to_vec();
        return Ok(SignatureKeyPair::from_raw(
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            ec.to_bytes().to_vec(),
            public,
        ));
    }
    Err(mls_error(
        "the private key is neither Ed25519 (RFC 8410) nor P-256 (RFC 5915) PKCS#8",
    ))
}

// ─── The codec + the errors ────────────────────────────────────────────────

/// base64url, unpadded (the wmp-mls spec's wire form).
fn base64url(bytes: &[u8]) -> String {
    wmp_core::token::base64url_unpadded(bytes)
}

/// base64url decode; `-31004` on a malformed member.
fn decode_base64url(encoded: &str) -> Result<Vec<u8>, HandlerError> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(encoded.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for (i, byte) in encoded.bytes().enumerate() {
        if byte == b'=' {
            break;
        }
        let value = ALPHABET.iter().position(|&a| a == byte).ok_or_else(|| {
            mls_error(&format!(
                "the base64url member carries an invalid byte at {i}"
            ))
        })? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

/// An MLS failure answers the spec's MLS error code (-31004).
fn mls_error(reason: &str) -> HandlerError {
    RpcError::new(
        wmp_core::error::ERR_MLS_ERROR,
        Some(serde_json::json!({ "reason": reason })),
    )
    .into()
}

/// A group the provider does not hold answers the MLS error.
fn no_group(group_id: &str) -> HandlerError {
    mls_error(&format!("unknown group {group_id}"))
}

/// Not yet wired (the arms above that answer it).
fn not_implemented(what: &str) -> HandlerError {
    RpcError::new(
        wmp_core::error::ERR_INTERNAL_ERROR,
        Some(serde_json::json!({ "reason": "not implemented", "what": what })),
    )
    .into()
}
