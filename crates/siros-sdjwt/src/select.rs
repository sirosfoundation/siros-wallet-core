//! The disclosures of a presentation (S3): each node on a selected path, with its parents and
//! descendants (RFC 9901 §7.2 step 2; OpenID4VP 1.0 §7.3 selects a claim "with its sub-claims as
//! the value").

use rustc_hash::FxHashSet;
use siros_openid4vp::claims::{Concrete, ConcretePath};

use crate::error::SelectError;
use crate::key_binding::Presentation;
use crate::sd_jwt::SdJwt;
use crate::tree::{ClaimValue, Element, IssuedClaim};

impl SdJwt {
    /// The presentation that discloses the claims at `paths`: the disclosures in the order the
    /// paths first reach them, each once. No paths give the Issuer-signed JWT alone.
    ///
    /// # Errors
    ///
    /// [`SelectError`]: a path reaches no value the credential holds.
    pub fn select(&self, paths: &[ConcretePath<'_>]) -> Result<Presentation, SelectError> {
        let mut chosen = Chosen::default();
        for path in paths {
            let mut within: Option<&ClaimValue> = None;
            for (position, step) in path.iter().enumerate() {
                let claim = self
                    .step(within, step)
                    .ok_or(SelectError::Absent(position))?;
                chosen.add(claim);
                within = Some(claim.value());
            }
            if let Some(value) = within {
                chosen.add_within(value);
            }
        }
        let mut text = format!("{}~", self.issuer_jwt());
        for disclosure in chosen.order {
            text.push_str(disclosure);
            text.push('~');
        }
        Ok(Presentation::new(text, self.hash_alg()))
    }

    /// The claim `step` names in `within`, the payload's root when `None`.
    fn step<'s>(
        &'s self,
        within: Option<&'s ClaimValue>,
        step: &Concrete<'_>,
    ) -> Option<&'s IssuedClaim> {
        match (within, step) {
            (None, Concrete::Key(name)) => self.claims().get(name),
            (Some(ClaimValue::Object(object)), Concrete::Key(name)) => object.get(name),
            (Some(ClaimValue::Array(elements)), Concrete::Index(at)) => {
                match elements.get(at.position())? {
                    Element::Present(claim) => Some(claim),
                    Element::Withheld(_) => None,
                }
            }
            _ => None,
        }
    }
}

/// The chosen disclosures in the order they are first chosen.
#[derive(Default)]
struct Chosen<'a> {
    order: Vec<&'a str>,
    seen: FxHashSet<&'a str>,
}

impl<'a> Chosen<'a> {
    fn add(&mut self, claim: &'a IssuedClaim) {
        if let Some(disclosure) = claim.disclosure().map(|d| d.encoded())
            && self.seen.insert(disclosure)
        {
            self.order.push(disclosure);
        }
    }

    /// Every disclosure inside `value`, parents before children, in tree order.
    fn add_within(&mut self, value: &'a ClaimValue) {
        let claims: Vec<&'a IssuedClaim> = match value {
            ClaimValue::Object(object) => object.members().map(|(_, claim)| claim).collect(),
            ClaimValue::Array(elements) => elements
                .iter()
                .filter_map(|element| match element {
                    Element::Present(claim) => Some(claim),
                    Element::Withheld(_) => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        for claim in claims {
            self.add(claim);
            self.add_within(claim.value());
        }
    }
}
