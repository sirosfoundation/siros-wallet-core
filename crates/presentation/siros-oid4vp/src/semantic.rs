//! The semantics identifier of a Wallet-Relying Party (ETSI TS 119 475, Clauses 5.1.3 and
//! 5.1.5).
//!
//! The access certificate's policy says whom it is issued to (ETSI TS 119 411-8, Clause 5.3):
//! a natural person under NCP-n-eudiwrp or QCP-n-eudiwrp, a legal person under NCP-l-eudiwrp or
//! QCP-l-eudiwrp. A natural person's identifier is its `serialNumber` (GEN-5.1.5-01), a legal
//! person's its `organizationIdentifier` (GEN-5.1.3-01). Both follow ETSI EN 319 412-1, Clauses
//! 5.1.3 and 5.1.4: "3 character [...] identity type reference; 2 character ISO 3166-1 country
//! code; hyphen-minus "-" [...]; and identifier", the type references of TS 119 475 Tables 2
//! and 4 (GEN-5.1.3-02, GEN-5.1.5-02).

/// The identity type references of a legal person (ETSI TS 119 475, Table 2).
const LEGAL_TYPES: [&str; 5] = ["VAT", "NTR", "LEI", "EOR", "EXC"];
/// The identity type references of a natural person: TIN (ETSI TS 119 475, Table 4), and items
/// 1 to 4 of ETSI EN 319 412-1, Clause 5.1.3: passport, identity card, personal number and
/// personal tax reference.
const NATURAL_TYPES: [&str; 5] = ["TIN", "PAS", "IDC", "PNO", "TAX"];

/// Whom a Wallet-Relying Party access certificate is issued to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Person {
    /// A legal person: `organizationIdentifier`.
    Legal,
    /// A natural person: `serialNumber`.
    Natural,
}

impl Person {
    /// The identity type references of the person.
    fn types(self) -> &'static [&'static str] {
        match self {
            Self::Legal => &LEGAL_TYPES,
            Self::Natural => &NATURAL_TYPES,
        }
    }
}

/// A semantics identifier, such as `VATBE-0876866142`: an identity type reference of the
/// person, two uppercase letters of an ISO 3166-1 country code, `-`, and an identifier of
/// printable ASCII without leading or trailing space. The national-scheme form of ETSI EN 319
/// 412-1, two characters and `:` in place of the type reference, is refused, as go-trust
/// refuses it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticIdentifier(String);

/// Why a certificate gives no semantics identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum SemanticIdError {
    /// The certificate policies extension does not decode.
    #[cfg(feature = "crypto")]
    Policies(#[source] der::Error),
    /// No certificate policy says whether the subject is a natural or a legal person.
    Unclassified,
    /// The certificate policies say both.
    Contradictory,
    /// The subject holds no attribute of its identifier.
    Absent,
    /// The subject holds the attribute more than once.
    Repeated,
    /// A `serialNumber` that is not a `PrintableString`, or an `organizationIdentifier` that is
    /// no `DirectoryString` of UTF-8 or printable text.
    #[cfg(feature = "crypto")]
    Encoding(#[source] der::Error),
    /// The value starts with no identity type reference of the person.
    TypeReference,
    /// The country code is not two uppercase letters.
    Country,
    /// No `-` follows the country code.
    Separator,
    /// The identifier after `-` is empty.
    Identifier,
    /// The identifier holds a character other than printable ASCII, or starts or ends with a
    /// space.
    Character,
}

impl SemanticIdError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            #[cfg(feature = "crypto")]
            Self::Policies(_) => "semantic_id_policies",
            Self::Unclassified => "semantic_id_unclassified",
            Self::Contradictory => "semantic_id_contradictory",
            Self::Absent => "semantic_id_absent",
            Self::Repeated => "semantic_id_repeated",
            #[cfg(feature = "crypto")]
            Self::Encoding(_) => "semantic_id_encoding",
            Self::TypeReference => "semantic_id_type_reference",
            Self::Country => "semantic_id_country",
            Self::Separator => "semantic_id_separator",
            Self::Identifier => "semantic_id_identifier",
            Self::Character => "semantic_id_character",
        }
    }
}

impl SemanticIdentifier {
    /// The semantics identifier `text` of a `person`.
    ///
    /// # Errors
    ///
    /// [`SemanticIdError`]: the first part of the structure `text` breaks.
    pub fn parse(text: &str, person: Person) -> Result<Self, SemanticIdError> {
        let rest = text
            .get(..3)
            .filter(|reference| person.types().contains(reference))
            .and_then(|_| text.get(3..))
            .ok_or(SemanticIdError::TypeReference)?;
        rest.get(..2)
            .filter(|country| country.bytes().all(|b| b.is_ascii_uppercase()))
            .ok_or(SemanticIdError::Country)?;
        let identifier = rest
            .get(2..)
            .and_then(|tail| tail.strip_prefix('-'))
            .ok_or(SemanticIdError::Separator)?;
        if identifier.is_empty() {
            return Err(SemanticIdError::Identifier);
        }
        let printable = identifier.bytes().all(|b| (0x20..=0x7E).contains(&b));
        if !printable || identifier.starts_with(' ') || identifier.ends_with(' ') {
            return Err(SemanticIdError::Character);
        }
        Ok(Self(text.to_owned()))
    }

    /// The semantics identifier `text` a host states without its certificate: a natural
    /// person's when its type reference is one, else a legal person's.
    ///
    /// # Errors
    ///
    /// [`SemanticIdError`]: the first part of the structure `text` breaks.
    pub fn parse_stated(text: &str) -> Result<Self, SemanticIdError> {
        let natural = text
            .get(..3)
            .is_some_and(|reference| NATURAL_TYPES.contains(&reference));
        let person = if natural {
            Person::Natural
        } else {
            Person::Legal
        };
        Self::parse(text, person)
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
