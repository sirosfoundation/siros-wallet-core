//! Value types and label formats (PaSO View, Section 3; PaSO Proof Metadata, Sections 3.1 to
//! 3.3).

/// A value type of PaSO View, Section 3, without the `template:` prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BaseType {
    /// `boolean`: a JSON boolean.
    Boolean,
    /// `frequency`: an ISO 20022 frequency code.
    Frequency,
    /// `image`: a Data URL, or an `https` URL with an `#integrity` sibling.
    Image,
    /// `iso_date`: an ISO 8601 date.
    IsoDate,
    /// `iso_time`: an ISO 8601 time.
    IsoTime,
    /// `iso_date_time`: an ISO 8601 date and time.
    IsoDateTime,
    /// `iso_currency`: an ISO 4217 alphabetic code.
    IsoCurrency,
    /// `iso_currency_amount`: a decimal amount, a space and an ISO 4217 alphabetic code.
    IsoCurrencyAmount,
    /// `label_only`: the label alone; the value may be of any JSON type.
    LabelOnly,
    /// `mini_markdown`: text with emphasis, strong emphasis and underline.
    MiniMarkdown,
    /// `url`: an `https` URL.
    Url,
}

impl BaseType {
    const ALL: [Self; 11] = [
        Self::Boolean,
        Self::Frequency,
        Self::Image,
        Self::IsoDate,
        Self::IsoTime,
        Self::IsoDateTime,
        Self::IsoCurrency,
        Self::IsoCurrencyAmount,
        Self::LabelOnly,
        Self::MiniMarkdown,
        Self::Url,
    ];

    /// The name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Frequency => "frequency",
            Self::Image => "image",
            Self::IsoDate => "iso_date",
            Self::IsoTime => "iso_time",
            Self::IsoDateTime => "iso_date_time",
            Self::IsoCurrency => "iso_currency",
            Self::IsoCurrencyAmount => "iso_currency_amount",
            Self::LabelOnly => "label_only",
            Self::MiniMarkdown => "mini_markdown",
            Self::Url => "url",
        }
    }

    fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|base| base.as_str() == name)
    }
}

/// The prefix of a value type that interpolates placeholders (PaSO View, Section 3).
const TEMPLATE: &str = "template:";

/// A claim's `value_type`: a [`BaseType`], or `template:` and one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueType {
    /// The value formatted by its type.
    Plain(BaseType),
    /// A string whose placeholders are interpolated, then formatted by the inner type.
    Template(BaseType),
}

impl ValueType {
    /// The value type `name`; `None` for a name PaSO View, Section 3 does not define.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.strip_prefix(TEMPLATE) {
            Some(inner) => BaseType::named(inner).map(Self::Template),
            None => BaseType::named(name).map(Self::Plain),
        }
    }

    /// The type that formats the value: the base type, or the inner type of a template.
    #[must_use]
    pub fn base(self) -> BaseType {
        match self {
            Self::Plain(base) | Self::Template(base) => base,
        }
    }

    /// The name, as metadata writes it.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::Plain(base) => base.as_str().to_owned(),
            Self::Template(base) => format!("{TEMPLATE}{}", base.as_str()),
        }
    }
}

/// How a label's text is formatted: a `display` entry's `display_type`, or a `ui_labels`
/// entry's `value_type` (Section 3.3). Labels are text: plain, `mini_markdown`, or
/// `template:mini_markdown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelFormat {
    /// No `display_type` or `value_type`: plain text.
    Plain,
    /// `mini_markdown`.
    MiniMarkdown,
    /// `template:mini_markdown`: placeholders interpolated, then `mini_markdown`.
    TemplateMiniMarkdown,
}

impl LabelFormat {
    /// The format of the `display_type` or `value_type` `name`; `None` for a type a label may
    /// not have.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match ValueType::parse(name)? {
            ValueType::Plain(BaseType::MiniMarkdown) => Some(Self::MiniMarkdown),
            ValueType::Template(BaseType::MiniMarkdown) => Some(Self::TemplateMiniMarkdown),
            ValueType::Plain(_) | ValueType::Template(_) => None,
        }
    }

    /// The name, as metadata writes it; `None` for plain text.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        match self {
            Self::Plain => None,
            Self::MiniMarkdown => Some("mini_markdown"),
            Self::TemplateMiniMarkdown => Some("template:mini_markdown"),
        }
    }
}
