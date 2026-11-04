//! COSE as the wallet reads it: coset, which refuses a label twice in one header bucket, and
//! RFC 9052 §3's rule that no label sits in both buckets. Plug-ins' phase-2 code builds and reads
//! COSE through the re-exported coset.

pub use coset;

use coset::{AsCborValue, CoseEncrypt, CoseSign1};
use siros_explain::Explain;

use super::{CborError, Value, decode, key_form};

/// Why a value is no COSE structure the wallet reads.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.cose")]
pub enum CoseShape {
    /// The protected header's bytes are no CBOR data item with distinct keys.
    #[error("the protected header")]
    Protected(
        #[source]
        #[explain(name = "cause")]
        CborError,
    ),
    /// A header label has no key form.
    #[error("a header label")]
    Label(
        #[source]
        #[explain(name = "cause")]
        CborError,
    ),
    /// The value is no `[bstr, map, ...]`, or the protected header no map.
    #[error("no COSE structure: {0}")]
    Layout(#[explain(name = "rule")] &'static str),
    /// A label in both buckets (RFC 9052 §3: "MUST NOT occur in both").
    #[error("the label {0:?} is in both the protected and the unprotected header")]
    BothBuckets(#[explain(skip)] Value),
    /// coset's refusal, a label twice in one bucket among them.
    #[error("coset refuses the structure")]
    Cose(
        #[source]
        #[explain(skip)]
        coset::CoseError,
    ),
}

/// RFC 9052 §3: no label in both the protected and the unprotected bucket, labels compared by key
/// form (RFC 8949 §5.6.1). The protected bucket's bytes are read with distinct keys.
fn disjoint_buckets(structure: &Value) -> Result<(), CoseShape> {
    let Value::Array(items) = structure else {
        return Err(CoseShape::Layout("no array"));
    };
    let [Value::Bytes(protected), Value::Map(unprotected), ..] = items.as_slice() else {
        return Err(CoseShape::Layout("no protected bstr and unprotected map"));
    };
    let protected = match protected.as_slice() {
        [] => Vec::new(),
        bytes => match decode(bytes).map_err(CoseShape::Protected)? {
            Value::Map(pairs) => pairs,
            _ => return Err(CoseShape::Layout("a protected header that is no map")),
        },
    };
    let mut forms = protected
        .iter()
        .map(|(label, _)| key_form(label))
        .collect::<Result<Vec<_>, _>>()
        .map_err(CoseShape::Label)?;
    forms.sort();
    for (label, _) in unprotected {
        if forms
            .binary_search(&key_form(label).map_err(CoseShape::Label)?)
            .is_ok()
        {
            return Err(CoseShape::BothBuckets(label.clone()));
        }
    }
    Ok(())
}

/// An untagged COSE_Sign1 (RFC 9052 §4.2), the form ISO/IEC 18013-5's `IssuerAuth` takes, read
/// from a value [`decode`] returned.
///
/// # Errors
///
/// A label sits in both buckets, the protected header is unreadable, or coset refuses it.
pub fn read_sign1(value: Value) -> Result<CoseSign1, CoseShape> {
    disjoint_buckets(&value)?;
    CoseSign1::from_cbor_value(value).map_err(CoseShape::Cose)
}

/// An untagged COSE_Encrypt (RFC 9052 §5.1), read from a value [`decode`] returned.
///
/// # Errors
///
/// A label sits in both buckets, the protected header is unreadable, or coset refuses it.
pub fn read_encrypt(value: Value) -> Result<CoseEncrypt, CoseShape> {
    disjoint_buckets(&value)?;
    CoseEncrypt::from_cbor_value(value).map_err(CoseShape::Cose)
}
