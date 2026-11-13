//! One `transaction_data` entry rendered with one type's metadata, in PaSO Core §7.4.2's order:
//! the metadata (Proof Metadata §3), payload conformance (step 2), images (step 3), templates,
//! the locale (View §4 over the End-User's priority list), then the rows and UI labels (View
//! §2-3) within the wallet's item bound. Every text then resolves through the wallet's context:
//! a statement of its wording, or a display array's message of the type's converted source
//! ([`crate::view`]), which a clone of the context loads when the context does not word it.

use std::borrow::Cow;
use std::fmt;
use std::num::NonZeroUsize;

use siros_explain::Explain;
use siros_i18n::{Arg, Context, Message, Text};
use siros_openid4vp::claims::{Concrete, ConcretePath};
use siros_openid4vp::detail;
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::refusal::ReprItem;
use siros_openid4vp::rows::{ClaimText, Env, Image, Row, Value, WalletText};
use siros_syntax::{Currency, Date, DateTime, Decimal, OffsetTime};

use crate::conform::{ClaimIndex, Instance, NullIndices, Placement, conform, instances, written};
use crate::entry::Payload;
use crate::image::{self, Resolution};
use crate::labels::{self, LabelLimits, LabelSlot, LabelViolation};
use crate::locale::{ArrayKey, Discarded, matched, select};
use crate::mandate;
use crate::metadata::{DisplayArray, Displayed, LabelForm, Metadata, UiKey, ValueType, kind_name};
use crate::outcome::{Excluded, NotCompatible, Outcome, RenderedAt, Unsupported};
use crate::path::{at, concrete_text};
use crate::rulebook::{Family, PasoType, Rulebook, Section, Subtype};
use crate::template::{Template, Valued};
use crate::value::{self as values, FormattedKind, Parsed, ValueKind};
use crate::view::{self, ViewId};
use crate::{caused, fault};

/// The wallet's bound on a rendering's items: its rows and UI elements (View §2), at least 200.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ItemBound(usize);

/// An item bound under View §2's 200.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[error("View §2 bound {bound} under 200")]
#[explain(id = "bound_too_low")]
pub struct BoundTooLow {
    /// The bound given.
    bound: usize,
}

impl ItemBound {
    /// View §2's least bound.
    pub const LEAST: Self = Self(200);

    /// The bound, when at least 200.
    pub const fn new(bound: usize) -> Result<Self, BoundTooLow> {
        if bound < 200 {
            Err(BoundTooLow { bound })
        } else {
            Ok(Self(bound))
        }
    }

    /// The bound.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl fmt::Display for ItemBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A row with what it shows: the claim, the payload element, and its value's kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewRow {
    /// The row, a transaction overlay's.
    pub row: Row,
    /// The kind of value it shows, by its claim's value type; `None` for a label alone.
    pub kind: Option<ValueKind>,
    /// The claim.
    pub claim: ClaimIndex,
    /// The payload element's path.
    pub path: ConcretePath<'static>,
}

/// The consent's actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actions {
    /// The confirm action.
    pub confirm: Text,
    /// The denial action: the metadata's, else the wallet's own (Proof Metadata §3.2).
    pub deny: Text,
    /// The `security_hint`: plain text, shown exactly.
    pub hint: Option<Text>,
}

/// The rows a payment presentation's header shows: the Payment rulebook's `payee.name` and
/// `amount`, both with a text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentRows {
    merchant: RowPosition,
    amount: RowPosition,
}

/// A row's position among a rendering's rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowPosition(usize);

impl RowPosition {
    /// The position.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl PaymentRows {
    /// The merchant's row's position among the rows.
    #[must_use]
    pub const fn merchant(self) -> RowPosition {
        self.merchant
    }

    /// The amount's row's position among the rows.
    #[must_use]
    pub const fn amount(self) -> RowPosition {
        self.amount
    }
}

/// An entry rendered for a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionView {
    /// The locale View §4 selected, which the response reports (Core §7.2).
    pub locale: LocaleTag,
    /// The transaction title.
    pub title: Text,
    /// The rows, in the rulebook's order.
    pub rows: Vec<ViewRow>,
    /// The actions.
    pub actions: Actions,
    /// For a type that presents as a payment, the rows its header shows.
    pub payment: Option<PaymentRows>,
}

impl TransactionView {
    /// The text of the row at a position.
    fn text(&self, position: RowPosition) -> Option<&Text> {
        self.rows
            .get(position.get())
            .and_then(|row| row.row.value.as_ref())
            .and_then(Value::text)
    }

    /// The payment's merchant and amount texts.
    #[must_use]
    pub fn payment_texts(&self) -> Option<(&Text, &Text)> {
        let rows = self.payment?;
        Some((self.text(rows.merchant)?, self.text(rows.amount)?))
    }
}

/// A transaction type a profile registered: its identifier, the rulebook that renders it, and its
/// metadata in PaSO's form (Proof Metadata §3), read together by each profile's registry lookup.
#[derive(Debug, Clone, PartialEq)]
pub struct Registered<'r> {
    kind: PasoType<'r>,
    given: &'r Node<'r>,
}

impl<'r> Registered<'r> {
    /// The type and its metadata.
    #[must_use]
    pub const fn of(kind: PasoType<'r>, given: &'r Node<'r>) -> Self {
        Self { kind, given }
    }

    /// The type's metadata.
    #[must_use]
    pub const fn given(&self) -> &'r Node<'r> {
        self.given
    }
}

/// What a rendering reads.
#[derive(Clone)]
pub struct Request<'r> {
    /// The type, its rulebook and its metadata.
    pub registered: Registered<'r>,
    /// The payload, in PaSO's value forms.
    pub payload: Payload<'r>,
    /// The wallet's configuration: its priority list selects the locale (View §4).
    pub env: &'r Env,
    /// The wallet's context, which words the texts.
    pub context: &'r Context,
    /// View §2's item bound.
    pub bound: ItemBound,
    /// The labels' maximum lengths.
    pub limits: LabelLimits,
    /// What the wallet knows of an https image.
    pub resolve: &'r dyn Fn(&str) -> Resolution<'r>,
}

/// What an instance's row shows beside its label.
enum Content {
    /// Nothing: `label_only`, or a label alone by its rulebook.
    Alone,
    /// The resolved image.
    Image(Image),
    /// The value formatted by a kind.
    Formatted(FormattedKind),
    /// The value interpolated, then formatted by the inner kind.
    Template(FormattedKind),
}

/// A claim instance shown, with what its row shows.
struct Shown<'p> {
    instance: Instance<'p>,
    content: Content,
}

/// A rendering whose every rule held, its texts not yet resolved.
pub(crate) struct Plan {
    view: ViewId,
    locale: LocaleTag,
    title: Planned,
    rows: Vec<PlannedRow>,
    confirm: Planned,
    deny: Planned,
    hint: Option<Planned>,
    payment: Option<PaymentRows>,
}

/// A text a plan resolves.
enum Planned {
    /// A statement of the wallet's wording.
    Statement(Box<dyn Message>),
    /// A display array's message of the type's converted source.
    Label(Label),
}

/// A display array's message in the selected locale: its id, whether each of the array's
/// template entries is live, and each value its templates reference, one per claim.
struct Label {
    id: String,
    liveness: Vec<(usize, bool)>,
    values: Vec<(ClaimIndex, Parsed)>,
}

/// A row of a plan.
struct PlannedRow {
    label: Planned,
    value: Option<PlannedValue>,
    section: Option<Section>,
    kind: Option<ValueKind>,
    claim: ClaimIndex,
    path: ConcretePath<'static>,
}

/// A row's value in a plan.
enum PlannedValue {
    /// The resolved image.
    Image(Image),
    /// A value shown as a text.
    Text(Valued),
}

impl<'r> Request<'r> {
    /// The rendering of the entry.
    ///
    /// # Errors
    ///
    /// The outer [`Fault`]: the context does not word a text, or the type's converted source
    /// does not load into it. The inner [`Outcome`]: what keeps the entry from rendering.
    pub fn render(&self) -> Result<Result<TransactionView, Outcome>, Fault> {
        match self.plan() {
            Ok(plan) => plan.resolve(self).map(Ok),
            Err(outcome) => Ok(Err(outcome)),
        }
    }

    /// Every rule of the rendering, its texts not yet resolved.
    pub(crate) fn plan(&self) -> Result<Plan, Outcome> {
        let (metadata, rulebook) = rulebook_metadata(&self.registered, self.limits)?;
        rulebook.check_payload(self.payload)?;
        conform(self.payload, &metadata, &rulebook)?;
        let shown = self.images(&metadata, &rulebook)?;
        let discarded = self.discarded(&metadata, &shown)?;
        let arrays = arrays(&metadata);
        let locale = self.locale(&arrays, &discarded)?;
        let view = ViewId::of(self.registered.given());
        let names = Names {
            view: &view,
            locale: &locale,
            discarded: &discarded,
        };
        let taken = |key: ArrayKey, array: &DisplayArray<'_>| -> Option<usize> {
            matched(key, array, &locale, &discarded).map(|(position, _)| position)
        };
        let rows = shown
            .into_iter()
            .map(|shown| {
                let key = ArrayKey::Claim(shown.instance.claim);
                let position = taken(key, &shown.instance.display.names)
                    .ok_or(NotCompatible::TemplatesExhausted)?;
                self.row(&names, &metadata, &rulebook, position, shown)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ui = |key: UiKey| -> Result<Option<Planned>, NotCompatible> {
            let Some(label) = metadata.ui.iter().find(|label| label.key == key) else {
                return Ok(None);
            };
            let array = ArrayKey::Ui(key);
            let position = taken(array, &label.entries).ok_or(NotCompatible::TemplatesExhausted)?;
            let placed = Placed {
                array,
                entries: &label.entries,
                position,
                limit: self.limits.of(key.slot()),
                at: RenderedAt::Ui { key },
            };
            self.label(&names, &metadata, &NullIndices::default(), placed)
                .map(Some)
        };
        let title = ui(UiKey::TransactionTitle)?
            .unwrap_or_else(|| Planned::Statement(Box::new(rulebook.title())));
        let confirm = ui(UiKey::AffirmativeActionLabel)?
            .unwrap_or_else(|| Planned::Statement(Box::new(rulebook.confirm())));
        let deny = ui(UiKey::DenialActionLabel)?
            .unwrap_or_else(|| Planned::Statement(Box::new(WalletText::Deny)));
        let hint = ui(UiKey::SecurityHint)?;
        let items = rows.len() + 3 + usize::from(hint.is_some());
        if items > self.bound.get() {
            return Err(NotCompatible::TooManyItems {
                items,
                bound: self.bound,
            }
            .into());
        }
        let payment = match rulebook {
            Rulebook::Payment => payment_rows(&rows),
            _ => None,
        };
        Ok(Plan {
            view,
            locale,
            title,
            rows,
            confirm,
            deny,
            hint,
            payment,
        })
    }

    /// View §4's locale over the End-User's priority list as given: the credential excluded
    /// when no tag matches every array; not compatible when only the entries absent claims
    /// discard (View §3 template) stop every tag.
    fn locale(
        &self,
        arrays: &[(ArrayKey, &DisplayArray<'_>)],
        discarded: &Discarded,
    ) -> Result<LocaleTag, Outcome> {
        let priority = self.env.priority();
        if select(arrays, priority, &Discarded::default()).is_none() {
            return Err(Excluded {
                locales: priority.to_vec(),
            }
            .into());
        }
        select(arrays, priority, discarded).ok_or_else(|| NotCompatible::TemplatesExhausted.into())
    }

    /// Core §7.4.2 step 3: the instances in order, each image resolved; one that fails makes
    /// the entry not compatible.
    fn images<'p>(
        &self,
        metadata: &'p Metadata<'p>,
        rulebook: &Rulebook<'_>,
    ) -> Result<Vec<Shown<'p>>, NotCompatible>
    where
        'r: 'p,
    {
        let mut out = Vec::new();
        for instance in instances(rulebook, metadata, self.payload)? {
            let content =
                match instance.display.value {
                    _ if rulebook.label_alone(&instance.path, instance.value) => Content::Alone,
                    ValueType::LabelOnly => Content::Alone,
                    ValueType::Plain => Content::Formatted(FormattedKind::Text),
                    ValueType::Kind(ValueKind::Formatted(kind)) => Content::Formatted(kind),
                    ValueType::Template(kind) => Content::Template(kind),
                    ValueType::Kind(ValueKind::Image) => {
                        let url = instance.value.as_str().ok_or_else(|| {
                            NotCompatible::ImageNotString {
                                path: ReprItem::repr(instance.value),
                            }
                        })?;
                        let sibling = match integrity_sibling(&instance.path) {
                            Some(path) => at(self.payload.node(), &path)?,
                            None => None,
                        };
                        Content::Image(image::resolve(url, sibling, self.resolve)?)
                    }
                };
            out.push(Shown { instance, content });
        }
        Ok(out)
    }

    /// The display entries templates whose claim is absent discard: a claim's template label
    /// incomplete for one of its instances, every label of a claim whose template value is
    /// incomplete for one, a template UI label incomplete.
    fn discarded(
        &self,
        metadata: &Metadata<'_>,
        shown: &[Shown<'_>],
    ) -> Result<Discarded, NotCompatible> {
        let payload = self.payload.node();
        let mut uses: Vec<(ClaimIndex, &Displayed<'_>, Vec<&Instance<'_>>)> = Vec::new();
        for shown in shown {
            let instance = &shown.instance;
            match uses.iter_mut().find(|(claim, ..)| *claim == instance.claim) {
                Some((.., instances)) => instances.push(instance),
                None => uses.push((instance.claim, instance.display, vec![instance])),
            }
        }
        let mut discarded = Discarded::default();
        for (claim, display, instances) in &uses {
            let key = ArrayKey::Claim(*claim);
            for (position, entry) in display.names.entries().iter().enumerate() {
                let LabelForm::Template(text) = entry.label else {
                    continue;
                };
                for instance in instances {
                    if !Template(text).complete(&metadata.claims, payload, &instance.nulls)? {
                        discarded.discard(key, position);
                        break;
                    }
                }
            }
            if let ValueType::Template(_) = display.value {
                for instance in instances {
                    // A label alone's `null` has no template to complete.
                    let Some(text) = instance.value.as_str() else {
                        continue;
                    };
                    if !Template(text).complete(&metadata.claims, payload, &instance.nulls)? {
                        for position in 0..display.names.entries().len() {
                            discarded.discard(key, position);
                        }
                    }
                }
            }
        }
        for label in &metadata.ui {
            for (position, entry) in label.entries.entries().iter().enumerate() {
                if let LabelForm::Template(text) = entry.label
                    && !Template(text).complete(
                        &metadata.claims,
                        payload,
                        &NullIndices::default(),
                    )?
                {
                    discarded.discard(ArrayKey::Ui(label.key), position);
                }
            }
        }
        Ok(discarded)
    }

    /// A label's text: the wallet's own, or the converted source's message for its array, with
    /// each template entry's liveness and its referenced values; the template the language takes
    /// held to §3.3 for its slot (View §2), interpolated as written, and to the visible character
    /// over what it shows.
    fn label(
        &self,
        names: &Names<'_>,
        metadata: &Metadata<'_>,
        nulls: &NullIndices,
        placed: Placed<'_, '_>,
    ) -> Result<Planned, NotCompatible> {
        let claims = &metadata.claims;
        let payload = self.payload.node();
        let entries = placed.entries.entries();
        let entry = entries
            .get(placed.position)
            .ok_or(NotCompatible::TemplatesExhausted)?;
        match entry.label {
            LabelForm::Own(label) => return Ok(Planned::Statement(Box::new(label))),
            LabelForm::Template(template) => {
                let template = Template(template);
                let text = template.interpolate(claims, payload, nulls)?;
                let violation = match labels::as_written(&text, placed.limit) {
                    Err(violation) => Some(violation),
                    Ok(()) => (!template.shows_visible(claims, payload, nulls)?)
                        .then_some(LabelViolation::Invisible),
                };
                if let Some(violation) = violation {
                    return Err(NotCompatible::RenderedLabel {
                        at: placed.at,
                        violation,
                    });
                }
            }
            LabelForm::Plain(_) | LabelForm::Markdown(_) => {}
        }
        let mut liveness = Vec::new();
        let mut values: Vec<(ClaimIndex, Parsed)> = Vec::new();
        for (position, entry) in entries.iter().enumerate() {
            if let LabelForm::Template(template) = entry.label {
                liveness.push((position, !names.discarded.holds(placed.array, position)));
                for (claim, value) in Template(template).arguments(claims, payload, nulls)? {
                    if values.iter().all(|(known, _)| *known != claim) {
                        values.push((claim, value));
                    }
                }
            }
        }
        Ok(Planned::Label(Label {
            id: names.view.message(names.locale, placed.array),
            liveness,
            values,
        }))
    }

    /// One instance's row: its label in the presentation's language, its value, its section.
    fn row(
        &self,
        names: &Names<'_>,
        metadata: &Metadata<'_>,
        rulebook: &Rulebook<'_>,
        position: usize,
        shown: Shown<'_>,
    ) -> Result<PlannedRow, NotCompatible> {
        let Shown { instance, content } = shown;
        let placed = Placed {
            array: ArrayKey::Claim(instance.claim),
            entries: &instance.display.names,
            position,
            limit: self.limits.of(LabelSlot::ClaimName),
            at: RenderedAt::Claim {
                claim: concrete_text(&instance.path),
            },
        };
        let label = self.label(names, metadata, &instance.nulls, placed)?;
        let kind = match content {
            Content::Alone => None,
            Content::Image(_) => Some(ValueKind::Image),
            Content::Formatted(kind) | Content::Template(kind) => Some(ValueKind::Formatted(kind)),
        };
        let value =
            match content {
                Content::Alone => None,
                Content::Image(image) => Some(PlannedValue::Image(image)),
                Content::Formatted(kind) => Some(PlannedValue::Text(Valued::Alone(formatted(
                    kind,
                    instance.value,
                )?))),
                Content::Template(kind) => {
                    let template = instance.value.as_str().ok_or_else(|| {
                        NotCompatible::TemplateNotString {
                            claim: concrete_text(&instance.path),
                        }
                    })?;
                    Some(PlannedValue::Text(Template(template).value(
                        kind,
                        &metadata.claims,
                        self.payload.node(),
                        &instance.nulls,
                    )?))
                }
            };
        let section = match instance.placement {
            Placement::Main => None,
            Placement::Embedded => rulebook.section(),
        };
        Ok(PlannedRow {
            label,
            value,
            section,
            kind,
            claim: instance.claim,
            path: owned(&instance.path),
        })
    }
}

/// What names a plan's converted labels: the type's id prefix, the selected locale, and the
/// entries absent claims discard.
struct Names<'a> {
    view: &'a ViewId,
    locale: &'a LocaleTag,
    discarded: &'a Discarded,
}

impl Plan {
    /// The rendering, each text resolved through the request's context, or through a clone of it
    /// that loads the type's converted source when the context does not word the plan's labels.
    pub(crate) fn resolve(self, request: &Request<'_>) -> Result<TransactionView, Fault> {
        let context = self.context(request)?;
        let rows = self
            .rows
            .into_iter()
            .map(|row| row.resolve(&context))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TransactionView {
            locale: self.locale,
            title: self.title.resolve(&context)?,
            rows,
            actions: Actions {
                confirm: self.confirm.resolve(&context)?,
                deny: self.deny.resolve(&context)?,
                hint: self.hint.map(|hint| hint.resolve(&context)).transpose()?,
            },
            payment: self.payment,
        })
    }

    /// The context that words the plan: the request's when it words the plan's first converted
    /// label or the plan has none; else a clone of it with the type's converted source loaded.
    fn context<'c>(&self, request: &Request<'c>) -> Result<Cow<'c, Context>, Fault> {
        let first = self
            .rows
            .iter()
            .map(|row| &row.label)
            .chain([&self.title, &self.confirm, &self.deny])
            .chain(&self.hint)
            .find_map(|planned| match planned {
                Planned::Label(label) => Some(label.id.as_str()),
                Planned::Statement(_) => None,
            });
        match first {
            Some(id) if !view::words(request.context, id) => view::load(
                &request.registered,
                request.limits,
                request.context,
                request.env.priority(),
            )
            .map(Cow::Owned)
            .map_err(|e| {
                caused(
                    detail!(
                        "the converted view {view}",
                        view = self.view.as_str().to_owned()
                    ),
                    e,
                )
            }),
            Some(_) | None => Ok(Cow::Borrowed(request.context)),
        }
    }
}

impl Planned {
    /// The text.
    fn resolve(self, context: &Context) -> Result<Text, Fault> {
        match self {
            Self::Statement(statement) => resolved(context, statement.as_ref()),
            Self::Label(label) => {
                let worded = label.worded(context)?;
                resolved(context, &worded)
            }
        }
    }
}

impl Label {
    /// The message with its arguments: each liveness as `live` or `dead`; each referenced value
    /// as its value, an amount as its number and its currency, a boolean and a frequency as the
    /// context words them, a text as shown.
    fn worded(self, context: &Context) -> Result<Worded, Fault> {
        let mut args: Vec<(String, Given)> = self
            .liveness
            .into_iter()
            .map(|(position, live)| (view::liveness(position), Given::Liveness(Liveness(live))))
            .collect();
        for (claim, value) in self.values {
            let name = view::argument(claim);
            match value {
                Parsed::Text(text) => args.push((name, Given::Text(text))),
                Parsed::Date(date) => args.push((name, Given::Date(date))),
                Parsed::Time(time) => args.push((name, Given::Time(time))),
                Parsed::DateTime(at) => args.push((name, Given::DateTime(at))),
                Parsed::Currency(code) => args.push((name, Given::Currency(code))),
                Parsed::Amount(amount) => {
                    args.push((name, Given::Number(amount.value())));
                    args.push((view::currency(claim), Given::Currency(amount.currency())));
                }
                stated @ (Parsed::Boolean(_) | Parsed::Frequency(_)) => {
                    let text = resolved(context, stated.shown().as_ref())?;
                    args.push((name, Given::Text(text.to_string())));
                }
            }
        }
        Ok(Worded { id: self.id, args })
    }
}

/// A converted label's message with its arguments.
struct Worded {
    id: String,
    args: Vec<(String, Given)>,
}

/// A converted label's argument, of the type whose formatters show it.
enum Given {
    Liveness(Liveness),
    Text(String),
    Date(Date),
    Time(OffsetTime),
    DateTime(DateTime),
    Currency(Currency),
    /// An amount's number.
    Number(Decimal),
}

/// Whether no absent claim discards an entry, `live` or `dead`: a type no wallet names, so the
/// converted selection over it takes `:string`.
struct Liveness(bool);

impl fmt::Display for Liveness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0 { view::LIVE } else { view::DEAD })
    }
}

impl Message for Worded {
    fn id(&self) -> &str {
        &self.id
    }

    fn arg(&self, key: &str) -> Option<&dyn Arg> {
        self.args
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, given)| match given {
                Given::Liveness(live) => live as &dyn Arg,
                Given::Text(text) => text,
                Given::Date(date) => date,
                Given::Time(time) => time,
                Given::DateTime(at) => at,
                Given::Currency(code) => code,
                Given::Number(number) => number,
            })
    }
}

impl PlannedRow {
    /// The row with its texts.
    fn resolve(self, context: &Context) -> Result<ViewRow, Fault> {
        let label = self.label.resolve(context)?;
        let value = match self.value {
            None => None,
            Some(PlannedValue::Image(image)) => Some(Value::Image(image)),
            Some(PlannedValue::Text(valued)) => Some(Value::Text(shown(context, valued)?)),
        };
        let section = self
            .section
            .map(|section| resolved(context, &section))
            .transpose()?;
        Ok(ViewRow {
            row: Row {
                label,
                value,
                section,
            },
            kind: self.kind,
            claim: self.claim,
            path: self.path,
        })
    }
}

/// A value's text: a value alone as its statement shows it; a template value's text joined with
/// each typed value as its statement shows it, shown as a text.
fn shown(context: &Context, valued: Valued) -> Result<Text, Fault> {
    match valued {
        Valued::Alone(value) => resolved(context, value.shown().as_ref()),
        Valued::Joined(joined) => {
            let value = joined
                .text(|typed| {
                    resolved(context, typed.shown().as_ref()).map(|text| text.to_string())
                })?
                .ok_or_else(|| fault(detail!("a template value's mini_markdown lost a value")))?;
            resolved(context, &ClaimText::Text { value })
        }
    }
}

/// The text the context words for a message.
fn resolved(context: &Context, message: &dyn Message) -> Result<Text, Fault> {
    context
        .resolve(message)
        .map_err(|e| caused(detail!("the text of {id}", id = message.id().to_owned()), e))
}

/// Where a label shows: its array, the position of the entry the language takes, its limit, and
/// how a refusal names it.
#[derive(Debug, Clone)]
struct Placed<'a, 'm> {
    array: ArrayKey,
    entries: &'a DisplayArray<'m>,
    position: usize,
    limit: NonZeroUsize,
    at: RenderedAt,
}

/// A value of a kind other than an image, parsed.
fn formatted(kind: FormattedKind, value: &Node<'_>) -> Result<Parsed, NotCompatible> {
    values::formatted(kind, written(value)).map_err(|bad| NotCompatible::Value {
        value_type: kind_name(ValueKind::Formatted(kind)),
        bad,
    })
}

/// The metadata a type renders with and its rulebook: the Mandate rulebook's own metadata with
/// the given metadata's `security_hint`, else the given metadata; the Generic subtype read once
/// the metadata parsed (Generic §1).
pub(crate) fn rulebook_metadata<'m>(
    registered: &'m Registered<'m>,
    limits: LabelLimits,
) -> Result<(Metadata<'m>, Rulebook<'m>), Outcome> {
    let kind = &registered.kind;
    let given = registered.given;
    if *given == Node::Null {
        return Err(Unsupported::NoEntry {
            kind: kind.to_owned_type(),
        }
        .into());
    }
    Ok(match kind.family() {
        Family::Mandate => {
            let subtype = Subtype::mandate(kind)?;
            (
                mandate::metadata(given, limits)?,
                Rulebook::Mandate(subtype),
            )
        }
        Family::View => (Metadata::parse(given, limits)?, Rulebook::View),
        Family::Payment => (Metadata::parse(given, limits)?, Rulebook::Payment),
        Family::Generic => {
            let metadata = Metadata::parse(given, limits)?;
            (metadata, Rulebook::Generic(Subtype::generic(kind)?))
        }
    })
}

/// The path of an element's `#integrity` sibling: its member name suffixed.
pub(crate) fn integrity_sibling(path: &[Concrete<'_>]) -> Option<ConcretePath<'static>> {
    let (Concrete::Key(key), parent) = path.split_last()? else {
        return None;
    };
    let mut sibling = owned(parent);
    sibling.push(Concrete::Key(Cow::Owned(format!("{key}#integrity"))));
    Some(sibling)
}

/// A concrete path owning its member names.
fn owned(path: &[Concrete<'_>]) -> ConcretePath<'static> {
    path.iter()
        .map(|part| match part {
            Concrete::Key(key) => Concrete::Key(Cow::Owned(key.to_string())),
            Concrete::Index(index) => Concrete::Index(*index),
        })
        .collect()
}

/// Every display array: the displayed claims' in claims order, then the UI labels'.
pub(crate) fn arrays<'a, 'm>(metadata: &'a Metadata<'m>) -> Vec<(ArrayKey, &'a DisplayArray<'m>)> {
    metadata
        .claims
        .iter()
        .enumerate()
        .filter_map(|(k, claim)| {
            claim
                .display
                .as_ref()
                .map(|display| (ArrayKey::Claim(ClaimIndex(k)), &display.names))
        })
        .chain(
            metadata
                .ui
                .iter()
                .map(|label| (ArrayKey::Ui(label.key), &label.entries)),
        )
        .collect()
}

/// The Payment rulebook's header rows: the last rows at `payee.name` and `amount`, when both
/// show a text.
fn payment_rows(rows: &[PlannedRow]) -> Option<PaymentRows> {
    let at_path = |keys: &[&str]| {
        rows.iter().rposition(|row| {
            row.path.len() == keys.len()
                && row
                    .path
                    .iter()
                    .zip(keys)
                    .all(|(part, key)| matches!(part, Concrete::Key(name) if name == key))
        })
    };
    let texted = |position: usize| {
        rows.get(position)
            .is_some_and(|row| matches!(row.value, Some(PlannedValue::Text(_))))
    };
    let merchant = at_path(&["payee", "name"])?;
    let amount = at_path(&["amount"])?;
    (texted(merchant) && texted(amount)).then_some(PaymentRows {
        merchant: RowPosition(merchant),
        amount: RowPosition(amount),
    })
}
