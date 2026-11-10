//! CSC §7.2 and §7.2.1: which credentials approve an entry, the response member each format
//! carries, and `qesApproval`, the digest of the entry by its `hashAlgorithmOID`.

use siros_openid4vp::detail;
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Fault, Member};
use siros_openid4vp::wallet::Credential;
use siros_openid4vp::wallet_metadata::Placement;
#[cfg(feature = "resolve")]
use siros_openid4vp::{
    plugins::{MemberTwice, MemberValue, Members},
    request::Entry,
};

use crate::approval::SignatureQualifier;
use crate::{CLAIM, DOCUMENT, NAMESPACE};

/// The hash algorithms the wallet computes, by object identifier (NIST CSOR
/// 2.16.840.1.101.3.4.2): the SHA-2 and SHA-3 families ETSI TS 119 312 recommends for signatures
/// (CSC §7.2 and its [i.13]); the SHA-3 family under the feature `sha3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalHash {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA-224.
    Sha224,
    /// SHA-512/224.
    Sha512_224,
    /// SHA-512/256.
    Sha512_256,
    /// SHA3-224.
    #[cfg(feature = "sha3")]
    Sha3_224,
    /// SHA3-256.
    #[cfg(feature = "sha3")]
    Sha3_256,
    /// SHA3-384.
    #[cfg(feature = "sha3")]
    Sha3_384,
    /// SHA3-512.
    #[cfg(feature = "sha3")]
    Sha3_512,
}

const OIDS: &[(&str, ApprovalHash)] = &[
    ("2.16.840.1.101.3.4.2.1", ApprovalHash::Sha256),
    ("2.16.840.1.101.3.4.2.2", ApprovalHash::Sha384),
    ("2.16.840.1.101.3.4.2.3", ApprovalHash::Sha512),
    ("2.16.840.1.101.3.4.2.4", ApprovalHash::Sha224),
    ("2.16.840.1.101.3.4.2.5", ApprovalHash::Sha512_224),
    ("2.16.840.1.101.3.4.2.6", ApprovalHash::Sha512_256),
    #[cfg(feature = "sha3")]
    ("2.16.840.1.101.3.4.2.7", ApprovalHash::Sha3_224),
    #[cfg(feature = "sha3")]
    ("2.16.840.1.101.3.4.2.8", ApprovalHash::Sha3_256),
    #[cfg(feature = "sha3")]
    ("2.16.840.1.101.3.4.2.9", ApprovalHash::Sha3_384),
    #[cfg(feature = "sha3")]
    ("2.16.840.1.101.3.4.2.10", ApprovalHash::Sha3_512),
];

impl ApprovalHash {
    /// The algorithm an object identifier names.
    pub(crate) fn of(oid: &str) -> Option<Self> {
        OIDS.iter()
            .find(|(known, _)| *known == oid)
            .map(|(_, algorithm)| *algorithm)
    }

    #[cfg(feature = "resolve")]
    /// The digest of data.
    fn digest(self, data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
        #[cfg(feature = "sha3")]
        use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
            Self::Sha224 => Sha224::digest(data).to_vec(),
            Self::Sha512_224 => Sha512_224::digest(data).to_vec(),
            Self::Sha512_256 => Sha512_256::digest(data).to_vec(),
            #[cfg(feature = "sha3")]
            Self::Sha3_224 => Sha3_224::digest(data).to_vec(),
            #[cfg(feature = "sha3")]
            Self::Sha3_256 => Sha3_256::digest(data).to_vec(),
            #[cfg(feature = "sha3")]
            Self::Sha3_384 => Sha3_384::digest(data).to_vec(),
            #[cfg(feature = "sha3")]
            Self::Sha3_512 => Sha3_512::digest(data).to_vec(),
        }
    }
}

static DEVICE_SIGNED: [Member; 1] = [Member::element(NAMESPACE, "qesApproval")];
static KEY_BINDING: [Member; 1] = [Member::claim(CLAIM)];

/// How a proof carries `qesApproval` (CSC §7.2.1), by its format's placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    /// §7.2.1.1, an element of a name space: the `DeviceSigned` element `qesApproval` of
    /// [`NAMESPACE`], a bstr of the digest of the entry's decoded UTF-8 bytes.
    DeviceSigned,
    /// §7.2.1.2, a claim: the Key Binding JWT claim [`CLAIM`], the base64 digest of the entry as
    /// received.
    KeyBinding,
}

impl Encoding {
    /// The encoding of a placement.
    pub(crate) const fn of(placement: Placement) -> Self {
        match placement {
            Placement::NameSpaces => Self::DeviceSigned,
            Placement::Claims => Self::KeyBinding,
        }
    }

    /// The response member the format carries.
    pub(crate) fn members(self) -> &'static [Member] {
        match self {
            Self::DeviceSigned => &DEVICE_SIGNED,
            Self::KeyBinding => &KEY_BINDING,
        }
    }

    #[cfg(feature = "resolve")]
    /// `qesApproval` for the entry, by the algorithm its `hashAlgorithmOID` names.
    pub(crate) fn approval(
        self,
        hash: ApprovalHash,
        entry: &Entry<'_>,
    ) -> Result<Members, MemberTwice> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        let (member, value) = match self {
            Self::DeviceSigned => (
                DEVICE_SIGNED.clone(),
                MemberValue::Bytes(hash.digest(entry.decoded().as_bytes())),
            ),
            Self::KeyBinding => (
                KEY_BINDING.clone(),
                MemberValue::Text(STANDARD.encode(hash.digest(entry.raw().as_bytes()))),
            ),
        };
        let [member] = member;
        Members::new(vec![(member, value)])
    }
}

/// Whether the credential's rulebook lets it approve the qualifier (CSC §6.3; §7.2.1 Note 22):
/// its [`DOCUMENT`] lists it. A fault when the document is no `{"signature_qualifiers"?:
/// [string, ...]}`.
pub(crate) fn approves(
    credential: &Credential<'_>,
    qualifier: SignatureQualifier,
) -> Result<bool, Fault> {
    let Some(bytes) = credential.document(DOCUMENT) else {
        return Ok(false);
    };
    let id = || credential.id.to_string();
    let malformed =
        |why: &'static str| crate::fault(detail!("{id}: the {DOCUMENT} document {why}", id = id()));
    let text = std::str::from_utf8(bytes).map_err(|_| malformed("is no UTF-8"))?;
    let document = Node::parse(text)
        .map_err(|e| crate::caused(detail!("{id}: the {DOCUMENT} document", id = id()), e))?;
    let object = document
        .as_object()
        .ok_or_else(|| malformed("is no JSON object"))?;
    if let Some(name) = object.names().find(|name| *name != "signature_qualifiers") {
        return Err(crate::fault(detail!(
            "{id}: the {DOCUMENT} document holds the unknown member {name}",
            id = id(),
            name = name.to_owned()
        )));
    }
    let Some(listed) = object.get("signature_qualifiers") else {
        return Ok(false);
    };
    let qualifiers = listed
        .as_array()
        .and_then(|items| items.iter().map(Node::as_str).collect::<Option<Vec<_>>>())
        .ok_or_else(|| malformed("lists signature_qualifiers that are no array of strings"))?;
    Ok(qualifiers.contains(&qualifier.as_str()))
}
