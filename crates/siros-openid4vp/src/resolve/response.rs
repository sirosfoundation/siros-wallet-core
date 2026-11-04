//! The response: `vp_token` and the DigitalCredential's `data` (OpenID4VP Annex A).

use crate::host::{Presentation, SealedJwe};
use crate::ids::QueryId;
use crate::json::quote;

/// `vp_token`: per Credential Query presented, its presentations in selection order; the queries
/// in the order of their first record.
#[derive(Debug, Clone, Default)]
pub struct VpToken(Vec<(String, Vec<Presentation>)>);

impl VpToken {
    pub(crate) fn push(&mut self, query: &QueryId<'_>, presentation: Presentation) {
        match self.0.iter_mut().find(|(id, _)| id == query.as_str()) {
            Some((_, presentations)) => presentations.push(presentation),
            None => self.0.push((query.to_string(), vec![presentation])),
        }
    }

    /// The JSON text, without whitespace.
    #[must_use]
    pub fn json(&self) -> String {
        let members: Vec<String> = self
            .0
            .iter()
            .map(|(query, presentations)| {
                let items: Vec<&str> = presentations
                    .iter()
                    .map(|presentation| presentation.0.get())
                    .collect();
                format!("{}:[{}]", quote(query), items.join(","))
            })
            .collect();
        format!("{{{}}}", members.join(","))
    }

    /// `{"vp_token": ...}`, the response's plaintext.
    pub(crate) fn data(&self) -> String {
        format!("{{\"vp_token\":{}}}", self.json())
    }
}

/// The DigitalCredential's `data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseData {
    /// `dc_api`: `{"vp_token": ...}`.
    Plain(String),
    /// `dc_api.jwt`: the JWE whose plaintext is `{"vp_token": ...}`.
    Encrypted(SealedJwe),
}

impl ResponseData {
    /// The JSON text, without whitespace.
    #[must_use]
    pub fn json(&self) -> String {
        match self {
            Self::Plain(text) => text.clone(),
            Self::Encrypted(jwe) => format!("{{\"response\":{}}}", quote(jwe.as_str())),
        }
    }
}

/// The response to a selection.
#[derive(Debug, Clone)]
pub struct Response {
    /// `vp_token`.
    pub vp_token: VpToken,
    /// The DigitalCredential's `data`.
    pub data: ResponseData,
}
