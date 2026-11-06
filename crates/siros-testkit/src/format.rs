//! A format whose credentials say which queries and options they answer.
//!
//! A query object holds `{"options"?: [[item, ...], ...]}`; without `options` the query has one
//! option of no item. A credential's view: `{"answers": [query ids], "answerable"?: {query id:
//! [option, ...]}, "logo"?: uri, "carries"?: bool, "alg": its algorithm}`. The Verifier's
//! `vp_formats_supported` value for "test": `{"algs"?: [...]}`.

use siros_explain::{
    AllOf, Amount, Currency, Date, DateTime, Decimal, Fraction, Offset, Second, Text, Time, Value,
};
use siros_openid4vp::consent::Card;
use siros_openid4vp::detail;
use siros_openid4vp::host::{
    AnsweredContext, AnsweredOption, AnsweredQuery, FormatHost, PresentError, Presentation, Usable,
};
use siros_openid4vp::ids::{FormatId, InvalidId, QueryId};
use siros_openid4vp::json::{Node, quote};
use siros_openid4vp::plugins::{
    Carriage, Exclude, Fault, FindingData, Format, FormatQuery, Member, MemberValue, Members,
    NoCandidate, OptionIndex, OptionItems, Options, Shown, ViewAdditions, ViewTypes,
};
use siros_openid4vp::refusal::{Quoted, Refusal};
use siros_openid4vp::request::{AgreeableKey, Item, Query};
use siros_openid4vp::rows::{BooleanText, Env, Row, Value as RowValue};
use siros_openid4vp::session::Session;
use siros_openid4vp::wallet::Credential;
use siros_openid4vp::wallet_metadata::Placement;

use crate::FAULT;
use crate::rules::{Excluded, FormatRule};

/// A text of the test format's rows that a transaction profile words: a message of the test app's
/// own module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "testkit.format")]
pub enum DoubleText {
    /// ISO 20022's `MNTH`.
    #[error("monthly")]
    Monthly,
}

/// A value of every kind PaSO View §3 types but an image, one row each in every card, under the
/// kind's name: a boolean, a frequency, a date, a time, a date-time, a currency, an amount, a
/// `mini_markdown` text and a URL.
fn typed() -> Option<Vec<(&'static str, Text)>> {
    let eur = Currency::from_code("EUR")?;
    let at =
        |hour, minute, second| Time::new(hour, minute, Some(Second::new(second, Fraction::NONE)?));
    let value = |value: Value| Text::Value(value);
    Some(vec![
        ("boolean", Text::of(&BooleanText::Yes)),
        ("frequency", Text::of(&DoubleText::Monthly)),
        ("date", value(Value::Date(Date::new(2026, 9, 2)?))),
        (
            "time",
            value(Value::Time {
                at: at(10, 15, 30)?,
                offset: Some(Offset::new(0)?),
            }),
        ),
        (
            "date_time",
            value(Value::DateTime(DateTime::new(
                Date::new(2026, 6, 2)?,
                at(10, 15, 30)?,
                Some(Offset::new(120)?),
            ))),
        ),
        ("currency", value(Value::Currency(eur))),
        (
            "currency_amount",
            value(Value::Amount(Amount::new(
                Decimal::new(123_456_750, 2)?,
                eur,
            ))),
        ),
        ("mini_markdown", Text::Raw("a b".to_owned())),
        (
            "url",
            Text::Raw("https://xn--bcher-kva.example/x".to_owned()),
        ),
    ])
}

/// The test format, `test`. Its proof writes `aud` and `nonce`.
#[derive(Debug, Clone)]
pub struct TestFormat {
    id: FormatId<'static>,
    reserved: [Member; 2],
    placement: Placement,
    formats: Node<'static>,
}

impl TestFormat {
    /// The format, its proof holding a profile's members as claims.
    pub fn new() -> Result<Self, InvalidId> {
        Self::placing(Placement::Claims)
    }

    /// The format, its proof holding a profile's members by `placement`.
    pub fn placing(placement: Placement) -> Result<Self, InvalidId> {
        Ok(Self {
            id: FormatId::parse("test")?,
            reserved: [Member::claim("aud"), Member::claim("nonce")],
            placement,
            formats: Node::Object(siros_openid4vp::json::Object::default()),
        })
    }

    /// The format, its `vp_formats_supported` member `formats`, which may be no object.
    #[must_use]
    pub fn stating(self, formats: Node<'static>) -> Self {
        Self { formats, ..self }
    }
}

impl Format for TestFormat {
    fn id(&self) -> FormatId<'_> {
        self.id.borrowed()
    }

    fn reserved(&self) -> &[Member] {
        &self.reserved
    }

    /// No member unless [`TestFormat::stating`] gave one: the test format states no algorithm.
    fn wallet_formats(&self) -> Result<Node<'static>, Fault> {
        Ok(self.formats.clone())
    }

    fn placement(&self) -> Option<Placement> {
        Some(self.placement)
    }

    /// None: a test credential states no type.
    fn additions<'c>(
        &self,
        _credential: &'c Credential<'c>,
    ) -> Result<Box<dyn ViewAdditions + 'c>, Fault> {
        Ok(Box::new(ViewTypes::new(Vec::new())))
    }

    fn query<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: siros_openid4vp::routing::QueryContext<'q>,
    ) -> Result<Box<dyn FormatQuery + 'q>, AllOf<Refusal>> {
        Ok(Box::new(TestQuery::parse(
            query,
            context.supported().cloned(),
        )?))
    }
}

/// Needs no module.
impl<H> FormatHost<H> for TestFormat {
    fn answer<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: AnsweredContext<'q>,
    ) -> Result<Box<dyn AnsweredQuery<H> + 'q>, AllOf<Refusal>> {
        Ok(Box::new(TestQuery::parse(
            query,
            context.context().supported().cloned(),
        )?))
    }
}

impl<'q> TestQuery<'q> {
    fn parse(query: &'q Query<'q>, supported: Option<Node<'q>>) -> Result<Self, AllOf<Refusal>> {
        let refuse = |rule: FormatRule| AllOf::one(Refusal::new(rule));
        let id = || query.id().to_string();
        let algs_ok = supported.as_ref().is_none_or(|value| {
            value.as_object().is_some_and(|object| {
                object
                    .get("algs")
                    .is_none_or(|algs| algs.as_array().is_some())
            })
        });
        if !algs_ok {
            return Err(refuse(FormatRule::Algs { query: id() }));
        }
        let object = Node::from_raw(query.object())
            .map_err(|cause| refuse(FormatRule::Json { query: id(), cause }))?;
        let options = match object.get("options") {
            None => vec![OptionItems::new(Vec::new())],
            Some(options) => options
                .as_array()
                .and_then(|options| options.iter().map(option).collect::<Option<Vec<_>>>())
                .ok_or_else(|| refuse(FormatRule::Options { query: id() }))?,
        };
        Ok(Self {
            id: query.id().clone(),
            options: Options::new(options),
            supported,
        })
    }
}

fn option(node: &Node<'_>) -> Option<OptionItems> {
    node.as_array()?
        .iter()
        .map(|item| match item {
            Node::Number(number) => number
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .and_then(Item::new),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .map(OptionItems::new)
}

struct TestQuery<'q> {
    id: QueryId<'q>,
    options: Options,
    supported: Option<Node<'q>>,
}

/// The credential's view.
fn view<'c>(credential: &'c Credential<'_>) -> Result<Node<'c>, Fault> {
    let what = || detail!("{id}: view", id = credential.id.to_string());
    let text = std::str::from_utf8(credential.view).map_err(|e| Fault::caused(FAULT, what(), e))?;
    Node::parse(text).map_err(|e| Fault::caused(FAULT, what(), e))
}

impl FormatQuery for TestQuery<'_> {
    fn options(&self) -> &Options {
        &self.options
    }

    fn admits(
        &self,
        credential: &Credential<'_>,
        _keys: &[AgreeableKey<'_>],
    ) -> Result<(), NoCandidate> {
        let Some(algs) = self
            .supported
            .as_ref()
            .and_then(|supported| supported.get("algs"))
            .and_then(Node::as_array)
        else {
            return Ok(());
        };
        let view = view(credential)?;
        let alg = view.get("alg").ok_or_else(|| {
            Fault::new(
                FAULT,
                detail!("{id}: view without alg", id = credential.id.to_string()),
            )
        })?;
        if algs.contains(alg) {
            return Ok(());
        }
        let listed: Vec<String> = algs
            .iter()
            .map(|alg| {
                alg.as_str()
                    .map_or_else(|| alg.python_text().to_string(), |a| Quoted(a).to_string())
            })
            .collect();
        Err(Exclude::new(Excluded::Algs {
            listed: listed.join(", "),
        })
        .into())
    }

    fn answerable(
        &self,
        credential: &Credential<'_>,
        _env: &Env,
        _provided: &[Member],
    ) -> Result<Vec<OptionIndex>, Fault> {
        let view = view(credential)?;
        let answers = view
            .get("answers")
            .and_then(Node::as_array)
            .ok_or_else(|| {
                Fault::new(
                    FAULT,
                    detail!("{id}: view without answers", id = credential.id.to_string()),
                )
            })?;
        if !answers
            .iter()
            .any(|answer| answer.as_str() == Some(self.id.as_str()))
        {
            return Ok(Vec::new());
        }
        let able = view
            .get("answerable")
            .and_then(|able| able.get(self.id.as_str()))
            .and_then(Node::as_array);
        let listed = |k: usize| {
            able.is_none_or(|able| {
                able.iter()
                    .any(|o| matches!(o, Node::Number(n) if n.as_u64() == Some(k as u64)))
            })
        };
        Ok(self
            .options
            .indexed()
            .map(|(option, _)| option)
            .filter(|option| listed(option.position()))
            .collect())
    }

    fn carries(&self, credential: &Credential<'_>, _members: &[Member]) -> Result<Carriage, Fault> {
        match view(credential)?.get("carries") {
            None | Some(Node::Bool(true)) => Ok(Carriage::Carried),
            Some(Node::Bool(false)) => Ok(Carriage::Uncarried),
            Some(_) => Err(Fault::new(
                FAULT,
                detail!(
                    "{id}: carries is not a boolean",
                    id = credential.id.to_string()
                ),
            )),
        }
    }

    fn draw(
        &self,
        credential: &Credential<'_>,
        _shown: Shown<'_>,
        env: &Env,
    ) -> Result<Card, Fault> {
        let view = view(credential)?;
        let mut rows = vec![
            Row::new(
                Text::Raw(self.id.as_str().to_owned()),
                RowValue::Text(Text::Raw(credential.id.as_str().to_owned())),
            ),
            Row::full_text(Text::Name("statement")),
        ];
        let typed = typed().ok_or_else(|| Fault::new(FAULT, detail!("a test value")))?;
        for (kind, text) in typed {
            rows.push(Row::new(Text::Name(kind), RowValue::Text(text)));
        }
        Ok(Card {
            icon: env.icon(view.get("logo").and_then(Node::as_str)).clone(),
            title: Text::Raw(credential.id.to_string()),
            subtitle: None,
            rows,
        })
    }
}

impl<H> AnsweredQuery<H> for TestQuery<'_> {
    fn choose<'a>(
        &'a self,
        credential: Usable<'a>,
        env: &Env,
        provided: &[Member],
    ) -> Result<Vec<Box<dyn AnsweredOption<H> + 'a>>, Fault> {
        Ok(self
            .answerable(credential.credential(), env, provided)?
            .into_iter()
            .map(|option| {
                Box::new(TestOption { credential, option }) as Box<dyn AnsweredOption<H> + 'a>
            })
            .collect())
    }
}

/// An answerable option of a test query.
struct TestOption<'a> {
    credential: Usable<'a>,
    option: OptionIndex,
}

impl<H> AnsweredOption<H> for TestOption<'_> {
    fn option(&self) -> OptionIndex {
        self.option
    }

    /// Nothing: the test format assumes nothing phase 2 checks.
    fn revalidate(
        &self,
        _session: &Session<'_>,
        _host: &H,
    ) -> Result<Option<Box<dyn FindingData>>, Fault> {
        Ok(None)
    }

    fn present(
        &self,
        members: &Members,
        session: &Session<'_>,
        _host: &H,
    ) -> Result<Presentation, PresentError> {
        Ok(self.presentation(members, session)?)
    }
}

impl TestOption<'_> {
    /// `{"credential", "option", "proof": {"aud", "nonce", the members}}`.
    fn presentation(
        &self,
        members: &Members,
        session: &Session<'_>,
    ) -> Result<Presentation, Fault> {
        let mut proof = vec![
            format!("\"aud\":{}", quote(session.audience().as_str())),
            format!("\"nonce\":{}", quote(session.nonce().as_str())),
        ];
        for (member, value) in members.iter() {
            let Member::Claim(name) = member else {
                return Err(Fault::new(
                    FAULT,
                    detail!("a test proof holds no {member}", member = member.clone()),
                ));
            };
            if name == "aud" || name == "nonce" {
                return Err(Fault::new(
                    FAULT,
                    detail!("the member {name} is the format's own", name = name.clone()),
                ));
            }
            let value = match value {
                MemberValue::Text(text) => quote(text),
                MemberValue::Json(json) => json.as_str().to_owned(),
                MemberValue::Bytes(_) => {
                    return Err(Fault::new(
                        FAULT,
                        detail!(
                            "a test proof holds no byte string ({name})",
                            name = name.clone()
                        ),
                    ));
                }
                MemberValue::Cbor(_) => {
                    return Err(Fault::new(
                        FAULT,
                        detail!(
                            "a test proof holds no CBOR data item ({name})",
                            name = name.clone()
                        ),
                    ));
                }
            };
            proof.push(format!("{}:{value}", quote(name)));
        }
        let text = format!(
            "{{\"credential\":{},\"option\":{},\"proof\":{{{}}}}}",
            quote(self.credential.credential().id.as_str()),
            self.option.position(),
            proof.join(",")
        );
        Presentation::object(&text)
            .map_err(|e| Fault::caused(FAULT, detail!("a test presentation"), e))
    }
}
