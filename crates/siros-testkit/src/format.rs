//! A format whose credentials say which queries and options they answer.
//!
//! A query object holds `{"options"?: [[item, ...], ...]}`; without `options` the query has one
//! option of no item. A credential's view: `{"answers": [query ids], "answerable"?: {query id:
//! [option, ...]}, "logo"?: uri, "carries"?: bool, "alg": its algorithm}`. The Verifier's
//! `vp_formats_supported` value for "test": `{"algs"?: [...]}`.

use siros_i18n::{Context, Message, Text};
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
use siros_syntax::{AllOf, Currency, Date, DateTime, Decimal, OffsetTime};

use crate::rules::{Excluded, FormatRule};
use crate::{caused, fault};

/// A text of the test doubles, which the test app words in its own module.
#[derive(Debug, Clone, PartialEq, Eq, Message)]
pub enum DoubleText {
    /// ISO 20022's `MNTH`.
    #[message(id = "format.monthly")]
    Monthly,
    /// A text as the test wrote it: an id, a kind's name, a Verifier's name.
    #[message(id = "format.written")]
    Written {
        /// The text.
        text: String,
    },
    /// A date.
    #[message(id = "format.date")]
    Date {
        /// The date.
        value: Date,
    },
    /// A time of day with its offset.
    #[message(id = "format.time")]
    Time {
        /// The time.
        value: OffsetTime,
    },
    /// A date and time.
    #[message(id = "format.date_time")]
    DateTime {
        /// The date and time.
        value: DateTime,
    },
    /// A currency.
    #[message(id = "format.currency")]
    Currency {
        /// The currency.
        code: Currency,
    },
    /// An amount in a currency.
    #[message(id = "format.amount")]
    Amount {
        /// The amount.
        value: Decimal,
        /// Its currency.
        currency: Currency,
    },
    /// The test profile's label of the entries it binds.
    #[message(id = "profile.reference")]
    Reference,
    /// The test profile's section.
    #[message(id = "profile.section")]
    Section,
    /// The test profile's label of its logo.
    #[message(id = "profile.logo")]
    Logo,
    /// The test profile's counterparty.
    #[message(id = "profile.merchant")]
    Merchant,
    /// The test profile's confirm action.
    #[message(id = "profile.confirm")]
    Confirm,
    /// The test profile's title of the entries it binds.
    #[message(id = "profile.entries")]
    Entries {
        /// The entries' indexes, separated by `,`.
        reference: String,
    },
    /// The test profile's hint of the entries it binds.
    #[message(id = "profile.hint")]
    Hint {
        /// The entries' indexes, separated by `,`.
        reference: String,
    },
}

impl DoubleText {
    /// The text as the test wrote it.
    pub fn written(text: impl Into<String>) -> Self {
        Self::Written { text: text.into() }
    }
}

/// The text `context` words for `message`.
///
/// # Errors
///
/// The test doubles' fault, caused by the `siros_i18n::ResolveError` of a message `context`
/// words no text for.
pub fn resolve(context: &Context, message: &dyn Message) -> Result<Text, Fault> {
    context
        .resolve(message)
        .map_err(|e| caused(detail!("{id}: no text", id = message.id().to_owned()), e))
}

/// A typed value of a card's row: its kind's name, the row's label, and its statement.
struct Typed {
    kind: &'static str,
    value: Box<dyn Message>,
}

impl Typed {
    fn of(kind: &'static str, value: impl Message + 'static) -> Self {
        Self {
            kind,
            value: Box::new(value),
        }
    }
}

/// A value of every kind PaSO View §3 types but an image, one row each in every card, under the
/// kind's name: a boolean, a frequency, a date, a time, a date-time, a currency, an amount, a
/// `mini_markdown` text and a URL.
fn typed() -> Result<Vec<Typed>, siros_syntax::Malformed> {
    let eur = Currency::parse("EUR")?;
    Ok(vec![
        Typed::of("boolean", BooleanText::Yes),
        Typed::of("frequency", DoubleText::Monthly),
        Typed::of(
            "date",
            DoubleText::Date {
                value: Date::parse("2026-09-02")?,
            },
        ),
        Typed::of(
            "time",
            DoubleText::Time {
                value: OffsetTime::parse("10:15:30Z")?,
            },
        ),
        Typed::of(
            "date_time",
            DoubleText::DateTime {
                value: DateTime::parse("2026-06-02T10:15:30+02:00")?,
            },
        ),
        Typed::of("currency", DoubleText::Currency { code: eur }),
        Typed::of(
            "currency_amount",
            DoubleText::Amount {
                value: Decimal::parse("1234567.50")?,
                currency: eur,
            },
        ),
        Typed::of("mini_markdown", DoubleText::written("a b")),
        Typed::of(
            "url",
            DoubleText::written("https://xn--bcher-kva.example/x"),
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
    let text = std::str::from_utf8(credential.view).map_err(|e| caused(what(), e))?;
    Node::parse(text).map_err(|e| caused(what(), e))
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
            fault(detail!(
                "{id}: view without alg",
                id = credential.id.to_string()
            ))
        })?;
        if algs.contains(alg) {
            return Ok(());
        }
        let listed: Vec<String> = algs
            .iter()
            .map(|alg| {
                alg.as_str()
                    .map_or_else(|| alg.json_spaced().to_string(), |a| Quoted(a).to_string())
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
                fault(detail!(
                    "{id}: view without answers",
                    id = credential.id.to_string()
                ))
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
            Some(_) => Err(fault(detail!(
                "{id}: carries is not a boolean",
                id = credential.id.to_string()
            ))),
        }
    }

    fn displayable(
        &self,
        _credential: &Credential<'_>,
        _options: &[OptionIndex],
        _env: &Env,
    ) -> Result<(), NoCandidate> {
        Ok(())
    }

    /// The query's id beside the credential's, a full-text row, and a row of each typed value;
    /// the credential's id as the title.
    fn draw(
        &self,
        credential: &Credential<'_>,
        _shown: Shown<'_>,
        env: &Env,
        context: &Context,
    ) -> Result<Card, Fault> {
        let view = view(credential)?;
        let written = |text: &str| resolve(context, &DoubleText::written(text));
        let mut rows = vec![
            Row::new(
                written(self.id.as_str())?,
                RowValue::Text(written(credential.id.as_str())?),
            ),
            Row::full_text(written("statement")?),
        ];
        let typed = typed().map_err(|e| caused(detail!("a test value"), e))?;
        for row in typed {
            rows.push(Row::new(
                written(row.kind)?,
                RowValue::Text(resolve(context, &*row.value)?),
            ));
        }
        Ok(Card {
            icon: env.icon(view.get("logo").and_then(Node::as_str)).clone(),
            title: written(credential.id.as_str())?,
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
                return Err(fault(detail!(
                    "a test proof holds no {member}",
                    member = member.clone()
                )));
            };
            if name == "aud" || name == "nonce" {
                return Err(fault(detail!(
                    "the member {name} is the format's own",
                    name = name.clone()
                )));
            }
            let value = match value {
                MemberValue::Text(text) => quote(text),
                MemberValue::Json(json) => json.as_str().to_owned(),
                MemberValue::Bytes(_) => {
                    return Err(fault(detail!(
                        "a test proof holds no byte string ({name})",
                        name = name.clone()
                    )));
                }
                MemberValue::Cbor(_) => {
                    return Err(fault(detail!(
                        "a test proof holds no CBOR data item ({name})",
                        name = name.clone()
                    )));
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
        Presentation::object(&text).map_err(|e| caused(detail!("a test presentation"), e))
    }
}
