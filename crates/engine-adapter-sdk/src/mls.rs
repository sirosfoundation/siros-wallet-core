//! The MLS crypto surface (the wmp-mls spec, RFC 9420) — the wallet's
//! in-process MLS provider, exposed through UniFFI.
//!
//! **The deployment shape** (wmp-mls.md §5): the WMP relay is the Delivery
//! Service — it routes and queues but reads no plaintext. The MLS crypto
//! (the Welcomes a wallet processes, the epoch keys it encrypts to) runs
//! IN THE WALLET. This surface is that crypto: the `engine-adapter-sdk`
//! embeds the `wmp-mls` provider (OpenMLS 0.8) and the Kotlin/Swift SDKs
//! drive it through these bindings — the same Rust crate the engine
//! itself uses, one crypto everywhere.
//!
//! The flow (the invitation's join, spec §3.2/§4.3): the invite's Welcome
//! rides the session create result (`process_welcome`), the wallet then
//! encrypts every message body to the epoch key (`encrypt`), the
//! recipients' wallets decrypt (`decrypt`) — the relay carries only
//! ciphertext.
//!
//! The feature gate: `mls` (the crate's Cargo feature; the Kotlin/Swift
//! bindings regenerate with it on). The 0.8 line rides wmp-mls (0.9
//! raised its MSRV above the workspace floor).

use wmp_core::mls::MlsProvider as _;
use wmp_mls::OpenMlsProvider;

/// A member's KeyPackage (spec §2.3): the base64url package, its minted
/// id, the suite. Published on the member's well-known for the add flows.
#[derive(uniffi::Record, Clone, Debug)]
pub struct MlsKeyPackage {
    /// The minted package id (`kp-<serial>`).
    pub id: String,
    /// The cipher suite (0x0001 X25519 / 0x0002 P-256).
    pub cipher_suite: i64,
    /// The base64url-encoded MLS KeyPackage.
    pub key_package: String,
}

/// A group creation (spec §3.1): the group's id, the epoch (0 — the
/// create mints the group alone; members join by the add).
#[derive(uniffi::Record, Clone, Debug)]
pub struct MlsGroupCreated {
    /// The minted group id (`grp-<serial>`).
    pub group_id: String,
    /// The epoch the create minted (0).
    pub epoch: i64,
}

/// A Welcome processed (spec §3.2): the group the member joined, the
/// epoch it joined at.
#[derive(uniffi::Record, Clone, Debug)]
pub struct MlsJoined {
    /// The group the Welcome opened (minted fresh on the join).
    pub group_id: String,
    /// The epoch the member joined at.
    pub epoch: i64,
}

/// An add staged (spec §3.3): the commit for the group, the Welcome for
/// the added member.
#[derive(uniffi::Record, Clone, Debug)]
pub struct MlsAddStaged {
    /// The base64url MLS Commit (merged into this member's group).
    pub commit: String,
    /// The base64url MLS Welcome (hand to the added member).
    pub welcome: String,
}

/// A message encrypted (spec §4): the base64url MLSMessage, the epoch
/// it was encrypted under.
#[derive(uniffi::Record, Clone, Debug)]
pub struct MlsEncrypted {
    /// The base64url MLSMessage (the ciphertext the relay carries).
    pub ciphertext: String,
    /// The epoch the encryption used.
    pub epoch: i64,
}

/// A message decrypted: the plaintext bytes, the epoch.
#[derive(uniffi::Record, Clone, Debug)]
pub struct MlsDecrypted {
    /// The plaintext bytes.
    pub plaintext: Vec<u8>,
    /// The epoch the ciphertext was encrypted under.
    pub epoch: i64,
}

/// An MLS operation refused: the message names the cause (never a panic
/// in library code).
#[derive(uniffi::Error, Clone, Debug)]
pub enum MlsException {
    /// The operation refused; the detail names the cause.
    Refused(String),
}

impl std::fmt::Display for MlsException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self::Refused(detail) = self;
        write!(f, "mls: {detail}")
    }
}

impl std::error::Error for MlsException {}

impl MlsException {
    fn new(detail: impl Into<String>) -> Self {
        Self::Refused(detail.into())
    }
}

/// The member's MLS crypto: ONE provider per wallet identity (one
/// identity, one key store), the groups it belongs to.
#[derive(uniffi::Object)]
pub struct WmpMls {
    provider: OpenMlsProvider,
}

#[uniffi::export]
impl WmpMls {
    /// A provider for the member `identity` (the WMP identifier string —
    /// the sender the session names).
    #[uniffi::constructor]
    pub fn new(identity: String) -> Result<Self, MlsException> {
        let provider = OpenMlsProvider::for_identity(&identity)
            .map_err(|e| MlsException::new(format!("{e}")))?;
        Ok(Self { provider })
    }

    /// The member's identity (the string `new` took).
    pub fn identity(&self) -> String {
        self.provider.identity().to_owned()
    }

    /// A fresh KeyPackage (spec §2.3) for the suite: publish it on the
    /// member's well-known for the add flows.
    pub fn generate_key_package(&self, cipher_suite: i64) -> Result<MlsKeyPackage, MlsException> {
        let package = self
            .provider
            .generate_key_package(cipher_suite)
            .map_err(mls)?;
        Ok(MlsKeyPackage {
            id: package.id,
            cipher_suite: package.cipher_suite,
            key_package: package.key_package,
        })
    }

    /// Create a group (spec §3.1): THIS member's group, epoch 0. The
    /// members join by the add flow ([`Self::add_member`]) once their
    /// KeyPackages are at hand.
    pub fn create_group(&self, cipher_suite: i64) -> Result<MlsGroupCreated, MlsException> {
        let (group_id, _welcomes) = self.provider.create_group(cipher_suite, &[]).map_err(mls)?;
        Ok(MlsGroupCreated { group_id, epoch: 0 })
    }

    /// Export the group's GroupInfo (spec §3.1's `group_info` create
    /// param): the serialized MlsMessageOut, base64url, with the
    /// ratchet tree. The peer's `wmp.mls.group.create` validator
    /// demands the param — a wallet-driven create mints it here and
    /// hands it to the peer; a member joining by Welcome never needs
    /// it. Found live at the Cleverbase interop (2026-11-24): the
    /// wallet path hit the create's refusal on its first group create
    /// because this surface had no export (issue #108).
    pub fn export_group_info(&self, group_id: String) -> Result<String, MlsException> {
        self.provider.export_group_info(&group_id).map_err(mls)
    }

    /// Process a Welcome (spec §3.2): the member joins the group, the
    /// epoch it joined at. The Welcome rides the invitation or the
    /// group's message passing (out of band).
    pub fn process_welcome(&self, welcome: String) -> Result<MlsJoined, MlsException> {
        let (group_id, epoch) = self.provider.process_welcome(&welcome).map_err(mls)?;
        Ok(MlsJoined { group_id, epoch })
    }

    /// Stage an add (spec §3.3): the commit for the group, the Welcome
    /// for the added member. The commit is merged here (the member set
    /// grew); carry the Welcome to the member.
    pub fn add_member(
        &self,
        group_id: String,
        key_package: String,
    ) -> Result<MlsAddStaged, MlsException> {
        let (commit, welcome) = self
            .provider
            .add_member(&group_id, &key_package)
            .map_err(mls)?;
        Ok(MlsAddStaged { commit, welcome })
    }

    /// Stage a removal (spec §3.4): the commit (merged here) that
    /// cryptographically excludes the participant.
    pub fn remove_member(
        &self,
        group_id: String,
        participant: String,
    ) -> Result<String, MlsException> {
        self.provider
            .remove_member(&group_id, &participant)
            .map_err(mls)
    }

    /// Process a commit (a staged add/remove/update the member
    /// receives): the epoch it advanced to.
    pub fn process_commit(&self, group_id: String, commit: String) -> Result<i64, MlsException> {
        self.provider
            .process_commit(&group_id, &commit)
            .map_err(mls)
    }

    /// A self-update commit (spec §3.5): the post-compromise rotation,
    /// merged here.
    pub fn self_update(&self, group_id: String) -> Result<String, MlsException> {
        self.provider.self_update(&group_id).map_err(mls)
    }

    /// Encrypt a message body to the group's current epoch key
    /// (spec §4.1): the base64url MLSMessage, the epoch. The relay
    /// carries this ciphertext opaque (it never sees plaintext).
    pub fn encrypt(
        &self,
        group_id: String,
        plaintext: Vec<u8>,
    ) -> Result<MlsEncrypted, MlsException> {
        let (ciphertext, epoch) = self.provider.encrypt(&group_id, &plaintext).map_err(mls)?;
        Ok(MlsEncrypted { ciphertext, epoch })
    }

    /// Decrypt the group's ciphertext (spec §4.1): the plaintext, the
    /// epoch. A message this member sent itself refuses (MLS ratchets —
    /// the recipient's provider answers).
    pub fn decrypt(
        &self,
        group_id: String,
        ciphertext: String,
    ) -> Result<MlsDecrypted, MlsException> {
        let (plaintext, epoch) = self.provider.decrypt(&group_id, &ciphertext).map_err(mls)?;
        Ok(MlsDecrypted { plaintext, epoch })
    }
}

/// The provider's `identity` accessor (pub through the FFI).
/// The error mapping: the handler's refusal, the reason surfaced (the
/// RpcError's own message is generic — "MLS error" — its data carries
/// the cause; the wallets' logs need it).
fn mls(e: wmp_core::handler::HandlerError) -> MlsException {
    let mut detail = format!("{e}");
    if let wmp_core::handler::HandlerError::Rpc(rpc) = &e {
        let reason = rpc
            .data
            .as_ref()
            .and_then(|d| serde_json::from_str::<serde_json::Value>(d.get()).ok());
        if let Some(reason) = reason {
            if let Some(why) = reason.get("reason").and_then(|v| v.as_str()) {
                detail = format!("{detail}: {why}");
            }
        }
    }
    MlsException::new(detail)
}
