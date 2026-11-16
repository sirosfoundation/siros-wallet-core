//! Display entries: how a credential type shows in one locale.

use serde_json::{Map, Value};

use crate::colour::Colour;
use crate::error::DisplayError;
use crate::json;
use crate::locale::{Locale, Localized};
use crate::logo::{self, Logo};
use crate::text::LabelText;

/// A `display` entry of OpenID4VCI `credential_metadata` (OpenID4VCI 1.0, Section 12.2.4) or of
/// Type Metadata with its `simple` rendering (SD-JWT VC, Sections 5.5 and 5.5.1.1).
#[derive(Debug, Clone)]
pub(crate) struct DisplayEntry {
    pub(crate) locale: Option<Locale>,
    pub(crate) name: LabelText,
    pub(crate) logo: Option<Logo>,
    pub(crate) background: Option<Colour>,
    pub(crate) text: Option<Colour>,
}

impl DisplayEntry {
    /// The entry named `name` in `locale`, with the `logo`, `background_color` and `text_color`
    /// of `rendering`.
    pub(crate) fn read(
        locale: Option<Locale>,
        name: LabelText,
        rendering: &Map<String, Value>,
    ) -> Result<Self, DisplayError> {
        Ok(Self {
            locale,
            name,
            logo: logo::optional(rendering)?,
            background: json::colour(rendering, "background_color")?,
            text: json::colour(rendering, "text_color")?,
        })
    }
}

impl Localized for DisplayEntry {
    fn locale(&self) -> Option<&Locale> {
        self.locale.as_ref()
    }
}
