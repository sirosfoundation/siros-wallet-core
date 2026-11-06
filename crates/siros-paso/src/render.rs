//! One `transaction_data` entry rendered with one type's metadata, in PaSO Core §7.4.2's order:
//! the metadata (Proof Metadata §3), payload conformance (step 2), images (step 3), templates,
//! the locale (View §4 over the End-User's priority list), then the rows and UI labels (View
//! §2-3) within the wallet's item bound.

use std::borrow::Cow;

use siros_explain::{DefinedModule, Entry, Explain, Keyed, RequestText, Text};
use siros_openid4vp::claims::{Concrete, ConcretePath};
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::json::Node;
use siros_openid4vp::rows::{Env, Image, Row, Value, WalletText};

use crate::PasoRequested;

use crate::conform::{ClaimIndex, Instance, Placement, conform, instances, written};
use crate::entry::Payload;
use crate::image::{self, Resolution};
use crate::labels::{LabelSlot, LabelText};
use crate::locale::{ArrayKey, Discarded, matched, select};
use crate::mandate;
use crate::metadata::{DisplayArray, Displayed, LabelForm, Metadata, UiKey, ValueType, kind_name};
use crate::outcome::{Excluded, NotCompatible, Outcome, RenderedAt, Unsupported};
use crate::path::{at, concrete_text};
use crate::rulebook::{Family, Rulebook, Subtype};
use crate::template::Template;
use crate::value::{self as values, FormattedKind, ValueKind};
use crate::view;

/// The wallet's bound on a rendering's items: its rows and UI elements (View §2), at least 200.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ItemBound(usize);

/// An item bound under View §2's 200.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso")]
#[error("View §2 bound {0} under 200")]
pub struct BoundTooLow(#[explain(name = "bound")] pub usize);

impl ItemBound {
    /// View §2's least bound.
    pub const LEAST: Self = Self(200);

    /// The bound, when at least 200.
    pub const fn new(bound: usize) -> Result<Self, BoundTooLow> {
        if bound < 200 {
            Err(BoundTooLow(bound))
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

/// A row with what it shows: the claim, the payload element, and its value's kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewRow {
    /// The row, a transaction overlay's.
    pub row: Row<RequestText>,
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
    pub hint: Option<RequestText>,
}

/// The rows a payment presentation's header shows: the Payment rulebook's `payee.name` and
/// `amount`, both with a text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentRows {
    merchant: usize,
    amount: usize,
}

impl PaymentRows {
    /// The merchant's row's position among the rows.
    #[must_use]
    pub const fn merchant(self) -> usize {
        self.merchant
    }

    /// The amount's row's position among the rows.
    #[must_use]
    pub const fn amount(self) -> usize {
        self.amount
    }
}

/// An entry rendered for a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionView {
    /// The locale View §4 selected, which the response reports (Core §7.2).
    pub locale: LocaleTag,
    /// The defined module the metadata converts to, which its display arrays' texts name.
    pub module: DefinedModule,
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
    fn text(&self, position: usize) -> Option<&RequestText> {
        self.rows
            .get(position)
            .and_then(|row| row.row.value.as_ref())
            .and_then(Value::text)
    }

    /// The payment's merchant and amount texts.
    #[must_use]
    pub fn payment_texts(&self) -> Option<(&RequestText, &RequestText)> {
        let rows = self.payment?;
        Some((self.text(rows.merchant)?, self.text(rows.amount)?))
    }
}

/// What a rendering reads: the type, the payload, the metadata given for the type, the wallet's
/// configuration and item bound, and what it knows of https images.
pub(crate) struct Request<'r, R> {
    pub(crate) kind: &'r str,
    pub(crate) family: Family,
    pub(crate) payload: Payload<'r>,
    pub(crate) given: &'r Node<'r>,
    pub(crate) env: &'r Env,
    pub(crate) bound: ItemBound,
    pub(crate) resolve: R,
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

impl<'r, R: Fn(&str) -> Resolution<'r>> Request<'r, R> {
    /// The rendering of the entry.
    pub(crate) fn render(&self) -> Result<TransactionView, Outcome> {
        let (metadata, rulebook) = rulebook_metadata(self.kind, self.family, self.given)?;
        rulebook.check_payload(self.payload)?;
        conform(self.payload, &metadata, &rulebook)?;
        let shown = self.images(&metadata, &rulebook)?;
        let discarded = self.discarded(&metadata, &shown)?;
        let arrays = arrays(&metadata);
        let module = view::module_of(self.given);
        let locale = self.locale(&arrays, &discarded)?;
        let taken = |key: ArrayKey, array: &DisplayArray<'_>| -> Option<usize> {
            matched(key, array, &locale, &discarded).map(|(position, _)| position)
        };
        let rows = shown
            .into_iter()
            .map(|shown| {
                let key = ArrayKey::Claim(shown.instance.claim);
                let position = taken(key, &shown.instance.display.names)
                    .ok_or(NotCompatible::TemplatesExhausted)?;
                self.row(module, &metadata, &rulebook, &discarded, position, shown)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ui = |key: UiKey| -> Result<Option<RequestText>, NotCompatible> {
            let Some(label) = metadata.ui.iter().find(|label| label.key == key) else {
                return Ok(None);
            };
            let array = ArrayKey::Ui(key);
            let position = taken(array, &label.entries).ok_or(NotCompatible::TemplatesExhausted)?;
            let placed = Placed {
                array,
                entries: &label.entries,
                position,
                slot: key.slot(),
                at: RenderedAt::Ui(key),
            };
            self.label(module, &metadata, &discarded, &[], placed)
                .map(Some)
        };
        let header = |key: UiKey, own: Text| -> Result<Text, NotCompatible> {
            Ok(ui(key)?.map_or(own, RequestText::into_text))
        };
        let title = header(UiKey::TransactionTitle, Text::of(&rulebook.title()))?;
        let confirm = header(UiKey::AffirmativeActionLabel, Text::of(&rulebook.confirm()))?;
        let deny = header(UiKey::DenialActionLabel, Text::of(&WalletText::Deny))?;
        let hint = ui(UiKey::SecurityHint)?;
        let items = rows.len() + 3 + usize::from(hint.is_some());
        if items > self.bound.get() {
            return Err(NotCompatible::TooManyItems {
                items,
                bound: self.bound.get(),
            }
            .into());
        }
        let payment = match rulebook {
            Rulebook::Payment => payment_rows(&rows),
            _ => None,
        };
        Ok(TransactionView {
            locale,
            module,
            title,
            rows,
            actions: Actions {
                confirm,
                deny,
                hint,
            },
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
                locales: priority.iter().map(ToString::to_string).collect(),
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
            let content = match instance.display.value {
                _ if rulebook.label_alone(&instance.path, instance.value) => Content::Alone,
                ValueType::LabelOnly => Content::Alone,
                ValueType::Plain => Content::Formatted(FormattedKind::Text),
                ValueType::Kind(ValueKind::Formatted(kind)) => Content::Formatted(kind),
                ValueType::Template(kind) => Content::Template(kind),
                ValueType::Kind(ValueKind::Image) => {
                    let url = instance.value.as_str().ok_or_else(|| {
                        NotCompatible::ImageNotString(instance.value.python_repr().to_string())
                    })?;
                    let sibling = match integrity_sibling(&instance.path) {
                        Some(path) => at(self.payload.node(), &path)?,
                        None => None,
                    };
                    Content::Image(image::resolve(url, sibling, &self.resolve)?)
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
                    && !Template(text).complete(&metadata.claims, payload, &[])?
                {
                    discarded.discard(ArrayKey::Ui(label.key), position);
                }
            }
        }
        Ok(discarded)
    }

    /// A label's text: the wallet's own, or the converted module's message for its array, with
    /// each template entry's liveness and its referenced values; the template the language takes
    /// held to §3.3 for its slot (View §2), interpolated as written.
    fn label(
        &self,
        module: DefinedModule,
        metadata: &Metadata<'_>,
        discarded: &Discarded,
        nulls: &[usize],
        placed: Placed<'_, '_>,
    ) -> Result<RequestText, NotCompatible> {
        let claims = &metadata.claims;
        let payload = self.payload.node();
        let entries = placed.entries.entries();
        let entry = entries
            .get(placed.position)
            .ok_or(NotCompatible::TemplatesExhausted)?;
        match entry.label {
            LabelForm::Own(label) => {
                return Ok(RequestText::of(&PasoRequested::Mandate(label)));
            }
            LabelForm::Template(template) => {
                let text = Template(template).interpolate(claims, payload, nulls)?;
                LabelText::parse(&text, placed.slot)
                    .map(drop)
                    .map_err(|violation| NotCompatible::RenderedLabel {
                        at: placed.at,
                        violation,
                    })?;
            }
            LabelForm::Plain(_) | LabelForm::Markdown(_) => {}
        }
        let mut args: Vec<Entry<Cow<'static, str>, RequestText>> = Vec::new();
        for (position, entry) in entries.iter().enumerate() {
            if let LabelForm::Template(template) = entry.label {
                let live = if discarded.holds(placed.array, position) {
                    view::DEAD
                } else {
                    view::LIVE
                };
                args.push(Entry::new(
                    view::liveness(position),
                    RequestText::name(live),
                ));
                args.extend(Template(template).arguments(claims, payload, nulls)?);
            }
        }
        let key = view::key(placed.array);
        Ok(RequestText::defined(module, key, Keyed::first_of(args)))
    }

    /// One instance's row: its label in the presentation's language, its value, its section.
    fn row(
        &self,
        module: DefinedModule,
        metadata: &Metadata<'_>,
        rulebook: &Rulebook<'_>,
        discarded: &Discarded,
        position: usize,
        shown: Shown<'_>,
    ) -> Result<ViewRow, NotCompatible> {
        let Shown { instance, content } = shown;
        let placed = Placed {
            array: ArrayKey::Claim(instance.claim),
            entries: &instance.display.names,
            position,
            slot: LabelSlot::ClaimName,
            at: RenderedAt::Claim(concrete_text(&instance.path)),
        };
        let label = self.label(module, metadata, discarded, &instance.nulls, placed)?;
        let kind = match content {
            Content::Alone => None,
            Content::Image(_) => Some(ValueKind::Image),
            Content::Formatted(kind) | Content::Template(kind) => Some(ValueKind::Formatted(kind)),
        };
        let value = match content {
            Content::Alone => None,
            Content::Image(image) => Some(Value::Image(image)),
            Content::Formatted(kind) => Some(formatted(kind, instance.value)?),
            Content::Template(kind) => {
                let template = instance.value.as_str().ok_or_else(|| {
                    NotCompatible::TemplateNotString(concrete_text(&instance.path))
                })?;
                Some(Value::Text(Template(template).value(
                    kind,
                    &metadata.claims,
                    self.payload.node(),
                    &instance.nulls,
                )?))
            }
        };
        let section = match instance.placement {
            Placement::Main => None,
            Placement::Embedded => rulebook
                .section()
                .map(|section| RequestText::of(&PasoRequested::Section(section))),
        };
        Ok(ViewRow {
            row: Row {
                label,
                value,
                section,
            },
            kind,
            claim: instance.claim,
            path: owned(&instance.path),
        })
    }
}

/// Where a label shows: its array, the position of the entry the language takes, its slot, and
/// how a refusal names it.
#[derive(Debug, Clone)]
struct Placed<'a, 'm> {
    array: ArrayKey,
    entries: &'a DisplayArray<'m>,
    position: usize,
    slot: LabelSlot,
    at: RenderedAt,
}

/// A value of a kind other than an image, with its text.
fn formatted(kind: FormattedKind, value: &Node<'_>) -> Result<Value<RequestText>, NotCompatible> {
    values::formatted(kind, written(value))
        .map(|(_, text)| Value::Text(text))
        .map_err(|bad| NotCompatible::Value {
            value_type: kind_name(ValueKind::Formatted(kind)),
            bad,
        })
}

/// The metadata a type renders with and its rulebook: the Mandate rulebook's own metadata with
/// the given metadata's `security_hint`, else the given metadata; the Generic subtype read once
/// the metadata parsed (Generic §1).
pub(crate) fn rulebook_metadata<'m>(
    kind: &'m str,
    family: Family,
    given: &'m Node<'m>,
) -> Result<(Metadata<'m>, Rulebook<'m>), Outcome> {
    if *given == Node::Null {
        return Err(Unsupported::NoEntry(kind.to_owned()).into());
    }
    Ok(match family {
        Family::Mandate => {
            let subtype = Subtype::mandate(kind)?;
            (mandate::metadata(given)?, Rulebook::Mandate(subtype))
        }
        Family::View => (Metadata::parse(given)?, Rulebook::View),
        Family::Payment => (Metadata::parse(given)?, Rulebook::Payment),
        Family::Generic => {
            let metadata = Metadata::parse(given)?;
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
fn payment_rows(rows: &[ViewRow]) -> Option<PaymentRows> {
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
            .and_then(|row| row.row.value.as_ref())
            .and_then(Value::text)
            .is_some()
    };
    let merchant = at_path(&["payee", "name"])?;
    let amount = at_path(&["amount"])?;
    (texted(merchant) && texted(amount)).then_some(PaymentRows { merchant, amount })
}
