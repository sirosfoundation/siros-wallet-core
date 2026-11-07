//! Phase 2: the https logo a displayed `payee.logo` names, the authentication need and TS12's Key
//! Binding JWT claims (TS12 §3.6).

use std::borrow::Cow;

use siros_openid4vp::detail;
use siros_openid4vp::effects::Fetch;
use siros_openid4vp::hash;
use siros_openid4vp::host::{Authentication, AuthenticationNeed, Has, Platform, ProfileHost};
use siros_openid4vp::json::{Node, Object};
use siros_openid4vp::plugins::{
    Answered, Fault, FetchedRecord, JsonText, Member, MemberValue, Members,
};
use siros_openid4vp::request::Entry;
use siros_openid4vp::rows::HttpsUrl;
use siros_paso::FailedImage;
use siros_paso::RandomIds;
use siros_paso::image::{self, Resolution};
use siros_paso::outcome::NotCompatible;

use crate::payload::Logo;
use crate::{FAULT, Translated, Ts12Finding, Ts12Profile, amr, read_document, translate};

/// The record's one entry.
fn the_entry<'r>(record: &Answered<'r>) -> Result<&'r Entry<'r>, Fault> {
    let [index] = record.entries().entries() else {
        return Err(Fault::new(FAULT, detail!("bound entries other than one")));
    };
    record
        .request()
        .entry(*index)
        .ok_or_else(|| Fault::new(FAULT, detail!("a bound entry the request lacks")))
}

/// The record's entry translated for its credential, which phase 1 bound.
fn translated_of(record: &Answered<'_>) -> Result<Translated, Fault> {
    let document = read_document(record.credential())?
        .ok_or_else(|| Fault::new(FAULT, detail!("a bound credential without its document")))?;
    translate(&document, the_entry(record)?)?
        .map_err(|_| Fault::new(FAULT, detail!("a bound entry that no longer translates")))
}

/// The https logo the metadata displays: its URL as written and its integrity value.
fn displayed_https(translated: &Translated) -> Option<(&HttpsUrl, &str)> {
    let Some(Logo::Https { url, integrity }) = translated.typed.logo() else {
        return None;
    };
    let claims = translated.metadata.get("claims")?.as_array()?;
    let displayed = claims.iter().any(|claim| {
        claim.get("display").is_some()
            && claim
                .get("path")
                .and_then(Node::as_array)
                .is_some_and(|path| path.iter().filter_map(Node::as_str).eq(["payee", "logo"]))
    });
    displayed.then_some((url, integrity.as_str()))
}

/// Needs the platform, and `RandomIds` for `jti`.
impl<H> ProfileHost<H> for Ts12Profile
where
    H: Has<dyn Platform> + Has<dyn RandomIds>,
{
    /// View §3: a displayed https logo the matcher had not fetched.
    fn wanted(&self, record: Answered<'_>, _host: &H) -> Result<Vec<HttpsUrl>, Fault> {
        let translated = translated_of(&record)?;
        Ok(displayed_https(&translated)
            .filter(|(url, _)| matches!(self.resolution(url.written()), Resolution::Unknown))
            .into_iter()
            .map(|(url, _)| url.clone())
            .collect())
    }

    /// The profile knowing the failed logo as a failed fetch: phase 1 then excludes the
    /// credential.
    fn informed(&self, findings: &[&Ts12Finding]) -> Self {
        let mut informed = self.clone();
        informed.resources.extend(findings.iter().map(|finding| {
            (
                finding.failed.url.clone(),
                siros_paso::Fetch::Failed(finding.failed.failure.to_string()),
            )
        }));
        informed
    }

    /// `amr` always holds two categories.
    fn authentication(&self, _record: Answered<'_>) -> Result<AuthenticationNeed, Fault> {
        Ok(AuthenticationNeed::Strong)
    }

    /// View §3: the logo the caller fetched meets its integrity value and is an image.
    fn revalidate(
        &self,
        record: FetchedRecord<'_>,
        _host: &H,
    ) -> Result<Option<Ts12Finding>, Fault> {
        let answered = record.record();
        let translated = translated_of(&answered)?;
        let Some((url, integrity)) = displayed_https(&translated) else {
            return Ok(None);
        };
        if !matches!(self.resolution(url.written()), Resolution::Unknown) {
            return Ok(None);
        }
        let fetch = record
            .resources()
            .fetched(url)
            .ok_or_else(|| Fault::new(FAULT, detail!("a logo the profile wanted is unanswered")))?;
        let resolution = |_: &str| match fetch {
            Fetch::Fetched { content, media } => Resolution::Fetched { content, media },
            Fetch::Unfetched => Resolution::Failed("the fetch failed"),
        };
        let written = Node::String(Cow::Borrowed(integrity));
        match image::resolve(url.written(), Some(&written), resolution) {
            Ok(_) => Ok(None),
            Err(NotCompatible::Image { failure, .. }) => Ok(Some(Ts12Finding {
                failed: FailedImage {
                    url: url.written().to_owned(),
                    failure,
                },
            })),
            Err(other) => Err(Fault::caused(FAULT, detail!("a logo"), other)),
        }
    }

    /// The Key Binding JWT's TS12 claims (TS12 §3.6, CS-12 §7.3 item 8, §8.2).
    fn respond(
        &self,
        record: Answered<'_>,
        host: &H,
        authentication: &Authentication,
    ) -> Result<Members, Fault> {
        let amr = amr_claim(authentication);
        let mut members = vec![
            (
                Member::claim("jti"),
                MemberValue::Text(Has::<dyn RandomIds>::module(host).random_id().to_string()),
            ),
            (
                Member::claim("response_mode"),
                MemberValue::Text(record.mode().as_str().to_owned()),
            ),
            (
                Member::claim("amr"),
                MemberValue::Json(JsonText::from(&amr)),
            ),
        ];
        let hashes = hash::members(&[the_entry(&record)?], record.request().envelope().hashes())
            .map_err(|e| Fault::caused(FAULT, detail!("B.3.3.1 hashes"), e))?;
        members.extend(hashes.iter().cloned());
        Members::new(members).map_err(|e| Fault::caused(FAULT, detail!("TS12's claims"), e))
    }
}

/// One object per factor applied, in the order applied.
fn amr_claim(authentication: &Authentication) -> Node<'static> {
    Node::Array(
        authentication
            .factors()
            .items()
            .iter()
            .map(|factor| {
                let method = amr(factor);
                Node::Object(Object::single(
                    Cow::Borrowed(method.category().name()),
                    Node::String(Cow::Borrowed(method.name())),
                ))
            })
            .collect(),
    )
}
