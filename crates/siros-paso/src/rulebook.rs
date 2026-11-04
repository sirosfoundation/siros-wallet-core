//! The rulebooks of PaSO's types: Payment, Generic and Mandate, and PaSO View's generic renderer
//! for every other `urn:paso:sca:` type. Each decides the metadata a type renders with, its
//! payload rules, its claim order and sections, and the wallet's own strings it falls back on.

use siros_openid4vp::claims::Concrete;
use siros_openid4vp::json::{Node, Object};
use siros_openid4vp::rows::TableLocale;

use crate::entry::Payload;
use crate::outcome::{NotCompatible, Outcome, Unsupported};
use crate::path::{at, concrete_text};

/// The exact type identifier of the Payment rulebook.
pub const PAYMENT: &str = "urn:paso:sca:global:payment:1";
const GENERIC: &str = "urn:paso:sca:global:generic";
const MANDATE: &str = "urn:paso:sca:global:mandate";
/// The prefix of every PaSO type identifier.
pub const PASO: &str = "urn:paso:sca:";

/// The fields the Payment rulebook requires (Payment §1).
pub(crate) const PAYMENT_REQUIRED: [&[&str]; 3] =
    [&["amount"], &["payee", "name"], &["payee", "id"]];

/// Which rulebook renders a type: the exact identifier first, then the longest prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// PaSO View §2-4: the generic renderer.
    View,
    /// The Payment rulebook: View's rendering; the type presents as a payment.
    Payment,
    /// The Generic rulebook: payload member order, `payment_payload` as a delimited section.
    Generic,
    /// The Mandate rulebook: its own claims, labels and order.
    Mandate,
}

impl Family {
    /// The rulebook of a type identifier; `None` outside `urn:paso:sca:`.
    #[must_use]
    pub fn of(kind: &str) -> Option<Self> {
        if kind == PAYMENT {
            return Some(Self::Payment);
        }
        let generic = kind
            .strip_prefix(GENERIC)
            .is_some_and(|rest| rest.starts_with(':'));
        let mandate = kind
            .strip_prefix(MANDATE)
            .is_some_and(|rest| rest.starts_with(':'));
        match (generic, mandate, kind.starts_with(PASO)) {
            (true, _, _) => Some(Self::Generic),
            (_, true, _) => Some(Self::Mandate),
            (_, _, true) => Some(Self::View),
            _ => None,
        }
    }
}

/// A Generic or Mandate type identifier's subtype: `[a-z0-9-]+`, or none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subtype<'t> {
    /// `urn:paso:sca:global:<rulebook>:1`.
    None,
    /// `urn:paso:sca:global:<rulebook>:<subtype>:1`.
    Named(&'t str),
}

impl<'t> Subtype<'t> {
    /// The subtype of `<base>:1` or `<base>:<subtype>:1`.
    fn parse(kind: &'t str, base: &str) -> Option<Self> {
        let middle = kind.strip_prefix(base)?.strip_suffix(":1")?;
        if middle.is_empty() {
            return Some(Self::None);
        }
        middle
            .strip_prefix(':')
            .filter(|sub| {
                !sub.is_empty()
                    && sub
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            .map(Self::Named)
    }

    /// A Generic type identifier's subtype (Generic §1).
    pub(crate) fn generic(kind: &'t str) -> Result<Self, Unsupported> {
        Self::parse(kind, GENERIC).ok_or_else(|| Unsupported::NotGeneric(kind.to_owned()))
    }

    /// A Mandate type identifier's subtype (Mandate §1).
    pub(crate) fn mandate(kind: &'t str) -> Result<Self, Unsupported> {
        Self::parse(kind, MANDATE).ok_or_else(|| Unsupported::NotMandate(kind.to_owned()))
    }

    /// Whether it is the named subtype.
    fn is(self, name: &str) -> bool {
        matches!(self, Self::Named(own) if own == name)
    }
}

/// The rulebook of a type with its subtype: what renders it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rulebook<'t> {
    /// PaSO View's generic renderer.
    View,
    /// The Payment rulebook.
    Payment,
    /// The Generic rulebook and the type's subtype.
    Generic(Subtype<'t>),
    /// The Mandate rulebook and the type's subtype.
    Mandate(Subtype<'t>),
}

impl Rulebook<'_> {
    /// The wallet's transaction title when the metadata gives none (Proof Metadata §3.2).
    #[must_use]
    pub fn title(&self, locale: TableLocale) -> &'static str {
        use TableLocale::{De, En};
        match (self, locale) {
            (Self::View, En) => "Confirm Transaction",
            (Self::View, De) => "Transaktion bestätigen",
            (Self::Payment, En) => "Payment Confirmation",
            (Self::Payment, De) => "Zahlungsbestätigung",
            (Self::Generic(sub), En) if sub.is("aisp") => "Authorize Data Sharing",
            (Self::Generic(sub), De) if sub.is("aisp") => "Datenfreigabe erlauben",
            (Self::Generic(_), En) => "Confirm Payment",
            (Self::Generic(_), De) => "Zahlung bestätigen",
            (Self::Mandate(Subtype::None), En) => "Authorize Account Delegate",
            (Self::Mandate(Subtype::None), De) => "Kontovollmacht erteilen",
            (Self::Mandate(sub), En) if sub.is("emandate") => "Authorize Recurring Payment",
            (Self::Mandate(sub), De) if sub.is("emandate") => "Wiederkehrende Zahlung erlauben",
            (Self::Mandate(sub), En) if sub.is("agentic") => "Authorize Agent Purchase",
            (Self::Mandate(sub), De) if sub.is("agentic") => "Agentenkauf erlauben",
            (Self::Mandate(_), En) => "Authorize Mandate",
            (Self::Mandate(_), De) => "Mandat erteilen",
        }
    }

    /// The wallet's confirm action when the metadata gives none.
    #[must_use]
    pub fn confirm(&self, locale: TableLocale) -> &'static str {
        use TableLocale::{De, En};
        match (self, locale) {
            (Self::View, En) => "Confirm",
            (Self::View, De) => "Bestätigen",
            (Self::Generic(sub), En) if sub.is("aisp") => "Authorize",
            (Self::Generic(sub), De) if sub.is("aisp") => "Erlauben",
            (Self::Payment | Self::Generic(_), En) => "Pay",
            (Self::Payment | Self::Generic(_), De) => "Bezahlen",
            (Self::Mandate(Subtype::None), En) => "Authorize Delegate",
            (Self::Mandate(Subtype::None), De) => "Vollmacht erteilen",
            (Self::Mandate(sub), En) if sub.is("emandate") => "Authorize Mandate",
            (Self::Mandate(sub), De) if sub.is("emandate") => "Mandat erteilen",
            (Self::Mandate(sub), En) if sub.is("agentic") => "Authorize Agent",
            (Self::Mandate(sub), De) if sub.is("agentic") => "Agent erlauben",
            (Self::Mandate(_), En) => "Authorize",
            (Self::Mandate(_), De) => "Erteilen",
        }
    }

    /// The title of the section the embedded `payment_payload` renders in (Generic §3.2,
    /// Mandate §2.2); `None` for a rulebook without sections.
    #[must_use]
    pub fn section(&self, locale: TableLocale) -> Option<&'static str> {
        use TableLocale::{De, En};
        match (self, locale) {
            (Self::View | Self::Payment, _) => None,
            (Self::Generic(_), En) => Some("Payment Details"),
            (Self::Generic(_), De) => Some("Zahlungsdetails"),
            (Self::Mandate(sub), En) if sub.is("emandate") => Some("First Collection"),
            (Self::Mandate(sub), De) if sub.is("emandate") => Some("Erste Abbuchung"),
            (Self::Mandate(_), En) => Some("Payment"),
            (Self::Mandate(_), De) => Some("Zahlung"),
        }
    }

    /// Whether a claim instance shows its label alone though not `label_only`: a `null` custom
    /// claim of the Generic rulebook (Generic §3.1 rule 4).
    #[must_use]
    pub fn label_alone(&self, path: &[Concrete<'_>], value: &Node<'_>) -> bool {
        matches!(self, Self::Generic(_))
            && *value == Node::Null
            && matches!(path, [Concrete::Key(key)] if key != "transaction_id" && key != "payment_payload")
    }

    /// The rulebook's payload rules beyond conformance.
    pub(crate) fn check_payload(&self, payload: Payload<'_>) -> Result<(), Outcome> {
        let object = payload.object();
        match self {
            Self::View => Ok(()),
            Self::Payment => required(payload.node(), NotCompatible::PaymentRequired),
            Self::Generic(_) => {
                if object.members().len() > 11 {
                    return Err(NotCompatible::GenericProperties.into());
                }
                if !object
                    .get("transaction_id")
                    .and_then(Node::as_str)
                    .is_some_and(|id| !id.is_empty())
                {
                    return Err(NotCompatible::GenericTransactionId.into());
                }
                // At most 11 properties with `transaction_id` among them leave at most 10
                // custom claims (Generic §3).
                if let Some(custom) = object.members().iter().find(|member| {
                    !matches!(member.name.as_ref(), "transaction_id" | "payment_payload")
                        && !matches!(member.value, Node::Null | Node::String(_))
                }) {
                    return Err(NotCompatible::GenericCustom(custom.name.to_string()).into());
                }
                embedded(object, NotCompatible::GenericPayment)
            }
            Self::Mandate(_) => embedded(object, NotCompatible::MandatePayment),
        }
    }
}

/// Each field the Payment rulebook requires present in a payment payload: a field of a
/// non-object is absent.
fn required(payment: &Node<'_>, absent: fn(String) -> NotCompatible) -> Result<(), Outcome> {
    for path in PAYMENT_REQUIRED {
        let concrete: Vec<Concrete<'_>> = path
            .iter()
            .map(|key| Concrete::Key((*key).into()))
            .collect();
        let found = match payment {
            Node::Object(_) => at(payment, &concrete).map_err(NotCompatible::from)?,
            _ => None,
        };
        if found.is_none() {
            return Err(absent(concrete_text(&concrete)).into());
        }
    }
    Ok(())
}

/// An embedded `payment_payload`, when present, holds the fields the Payment rulebook requires
/// (Generic §3.2, Mandate §2.2).
fn embedded(payload: &Object<'_>, absent: fn(String) -> NotCompatible) -> Result<(), Outcome> {
    payload
        .get("payment_payload")
        .map_or(Ok(()), |embedded| required(embedded, absent))
}
