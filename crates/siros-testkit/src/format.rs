//! A format whose credentials say which queries and options they answer.
//!
//! A query object holds `{"options"?: [[item, ...], ...]}`; without `options` the query has one
//! option of no item. A credential's view: `{"answers": [query ids], "answerable"?: {query id:
//! [option, ...]}, "logo"?: uri, "carries"?: bool, "alg": its algorithm}`. The Verifier's
//! `vp_formats_supported` value for "test": `{"algs"?: [...]}`.

use siros_explain::AllOf;
use siros_openid4vp::consent::Card;
use siros_openid4vp::detail;
use siros_openid4vp::host::{
    AnsweredContext, AnsweredOption, AnsweredQuery, FormatHost, PresentError, Presentation, Usable,
};
use siros_openid4vp::ids::{FormatId, InvalidId, QueryId};
use siros_openid4vp::json::{Node, quote};
use siros_openid4vp::plugins::{
    Exclude, Fault, FindingData, Format, FormatQuery, Member, MemberValue, Members, NoCandidate,
    OptionIndex, OptionItems, Shown, ViewAdditions, ViewTypes,
};
use siros_openid4vp::refusal::{Quoted, Refusal};
use siros_openid4vp::request::{AgreeableKey, Item, Query};
use siros_openid4vp::rows::{Env, FormattedKind, Label, Row, Value, Written};
use siros_openid4vp::session::Session;
use siros_openid4vp::wallet::Credential;
use siros_openid4vp::wallet_metadata::Placement;

use crate::FAULT;
use crate::rules::{Excluded, FormatRule};

/// The values of every kind but an image, one row each in every card.
const TYPED: [(FormattedKind, Written<'static>); 9] = [
    (FormattedKind::Boolean, Written::Boolean(true)),
    (FormattedKind::Frequency, Written::Text("MNTH")),
    (FormattedKind::Date, Written::Text("2026-09-02")),
    (FormattedKind::Time, Written::Text("10:15:30Z")),
    (
        FormattedKind::DateTime,
        Written::Text("2026-06-02T10:15:30+02:00"),
    ),
    (FormattedKind::Currency, Written::Text("EUR")),
    (
        FormattedKind::CurrencyAmount,
        Written::Text("1234567.50 EUR"),
    ),
    (FormattedKind::MiniMarkdown, Written::Text("a **b**")),
    (
        FormattedKind::Url,
        Written::Text("https://bücher.example/x"),
    ),
];

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
        let id = || query.id.to_string();
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
        let object = Node::from_raw(query.object)
            .map_err(|cause| refuse(FormatRule::Json { query: id(), cause }))?;
        let options = match object.get("options") {
            None => vec![OptionItems::new(Vec::new())],
            Some(options) => options
                .as_array()
                .and_then(|options| options.iter().map(option).collect::<Option<Vec<_>>>())
                .ok_or_else(|| refuse(FormatRule::Options { query: id() }))?,
        };
        Ok(Self {
            id: query.id.clone(),
            options,
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
    options: Vec<OptionItems>,
    supported: Option<Node<'q>>,
}

/// The credential's view.
fn view<'c>(credential: &'c Credential<'_>) -> Result<Node<'c>, Fault> {
    let what = || detail!("{id}: view", id = credential.id.to_string());
    let text = std::str::from_utf8(credential.view).map_err(|e| Fault::caused(FAULT, what(), e))?;
    Node::parse(text).map_err(|e| Fault::caused(FAULT, what(), e))
}

impl FormatQuery for TestQuery<'_> {
    fn options(&self) -> &[OptionItems] {
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
        Ok((0..self.options.len())
            .filter(|k| listed(*k))
            .map(OptionIndex)
            .collect())
    }

    fn carries(&self, credential: &Credential<'_>, _members: &[Member]) -> Result<bool, Fault> {
        match view(credential)?.get("carries") {
            None => Ok(true),
            Some(Node::Bool(carries)) => Ok(*carries),
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
        let locale = env.first().table;
        let format = |kind, written| {
            Value::format(kind, written, locale, env.amounts())
                .map_err(|e| Fault::caused(FAULT, detail!("a test value"), e))
        };
        let mut rows = vec![
            Row::new(
                Label::text(self.id.as_str()),
                format(FormattedKind::Text, Written::Text(credential.id.as_str()))?,
            ),
            Row::full_text(Label::text("statement")),
        ];
        for (kind, written) in TYPED {
            rows.push(Row::new(
                Label::mini_markdown(format!("*{}*", kind.as_str())),
                format(kind, written)?,
            ));
        }
        Ok(Card {
            icon: env.icon(view.get("logo").and_then(Node::as_str)).clone(),
            title: credential.id.to_string(),
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
            format!("\"aud\":{}", quote(&session.audience())),
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
            self.option.0,
            proof.join(",")
        );
        Presentation::object(&text)
            .map_err(|e| Fault::caused(FAULT, detail!("a test presentation"), e))
    }
}
