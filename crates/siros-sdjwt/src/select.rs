//! Selecting the disclosures that claims path pointers reach (OpenID4VP 1.0, Section 7;
//! RFC 9901, Section 7.2).

use rustc_hash::FxHashSet;
use siros_dcql::{resolve, ClaimPath, PathError};

use crate::key_binding::Presentation;
use crate::node::{present, Shape};
use crate::sd_jwt::SdJwt;
use crate::tree::Claim;

impl SdJwt {
    /// The presentation that discloses the claims `pointers` select.
    ///
    /// Each selected claim adds the disclosures on its path from the root, parents first (RFC
    /// 9901, Section 7.2, step 2), then the disclosures inside its value (OpenID4VP 1.0,
    /// Section 7.3 selects a claim "with its sub-claims as the value"). The disclosures follow
    /// the pointers' order, each once. An empty `pointers` gives the issuer JWT alone.
    ///
    /// [`siros_dcql::resolve`] walks each pointer over [`Node`](crate::Node)s from
    /// [`SdJwt::root`].
    ///
    /// # Errors
    ///
    /// [`PathError`]: a pointer applies a component to the wrong kind of value, or selects no
    /// present claim.
    pub fn select(&self, pointers: &[ClaimPath]) -> Result<Presentation, PathError> {
        let mut chosen = Chosen::default();
        for pointer in pointers {
            for target in resolve(self.root(), pointer)? {
                for disclosure in target.path() {
                    chosen.add(disclosure);
                }
                chosen.add_within(target.shape());
            }
        }
        let mut text = self.issuer_jwt().as_str().to_owned();
        text.push('~');
        for disclosure in chosen.order {
            text.push_str(disclosure);
            text.push('~');
        }
        Ok(Presentation::new(text, self.alg()))
    }
}

/// The chosen disclosures in the order they are first chosen.
#[derive(Default)]
struct Chosen<'a> {
    order: Vec<&'a str>,
    seen: FxHashSet<&'a str>,
}

impl<'a> Chosen<'a> {
    fn add(&mut self, disclosure: &'a str) {
        if self.seen.insert(disclosure) {
            self.order.push(disclosure);
        }
    }

    /// Every disclosure inside `shape`, parents before children, in tree order.
    fn add_within(&mut self, shape: Shape<'a>) {
        let claims: Vec<&'a Claim> = match shape {
            Shape::Object(object) => object.members().map(|(_, claim)| claim).collect(),
            Shape::Array(elements) => present(elements.iter()).collect(),
            Shape::Leaf => Vec::new(),
        };
        for claim in claims {
            if let Some(disclosure) = claim.disclosure_text() {
                self.add(disclosure);
            }
            self.add_within(Shape::of(claim.value()));
        }
    }
}
