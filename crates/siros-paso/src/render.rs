//! One `transaction_data` entry rendered with one type's metadata, in PaSO Core §7.4.2's order:
//! the metadata (Proof Metadata §3), payload conformance (step 2), images (step 3), templates,
//! locale selection (View §4), then the rows and UI labels (View §2-3) within the wallet's item
//! bound.

use std::borrow::Cow;

use siros_explain::Explain;
use siros_openid4vp::claims::{Concrete, ConcretePath};
use siros_openid4vp::json::Node;
use siros_openid4vp::rows::{
    DisplayLocale, Env, FormattedKind, Image, Label, Row, Value, ValueKind, WalletText,
};

use crate::conform::{ClaimIndex, Instance, Placement, conform, instances, written};
use crate::entry::Payload;
use crate::image::{self, Resolution};
use crate::labels::{LabelSlot, LabelText};
use crate::locale::{ArrayKey, Discarded, Selection, select};
use crate::mandate;
use crate::metadata::{
    DisplayArray, Displayed, LabelForm, Localized, Metadata, UiKey, ValueType, kind_name,
};
use crate::outcome::{Excluded, NotCompatible, Outcome, RenderedAt, Unsupported};
use crate::path::{at, concrete_text};
use crate::rulebook::{Family, Rulebook, Subtype};
use crate::template::Template;

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

/// A row with what it shows: the claim and the payload element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewRow {
    /// The row.
    pub row: Row,
    /// The claim.
    pub claim: ClaimIndex,
    /// The payload element's path.
    pub path: ConcretePath<'static>,
}

/// The consent's actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actions {
    /// The confirm action.
    pub confirm: Label,
    /// The denial action: the metadata's, else the wallet's own (Proof Metadata §3.2).
    pub deny: Label,
    /// The `security_hint`: plain text, shown exactly.
    pub hint: Option<String>,
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
    pub locale: DisplayLocale,
    /// The transaction title.
    pub title: Label,
    /// The rows, in the rulebook's order.
    pub rows: Vec<ViewRow>,
    /// The actions.
    pub actions: Actions,
    /// For a type that presents as a payment, the rows its header shows.
    pub payment: Option<PaymentRows>,
}

impl TransactionView {
    /// The text of the row at a position.
    fn text(&self, position: usize) -> Option<&str> {
        self.rows
            .get(position)
            .and_then(|row| row.row.value.as_ref())
            .and_then(Value::text)
    }

    /// The payment's merchant and amount texts.
    #[must_use]
    pub fn payment_texts(&self) -> Option<(&str, &str)> {
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
        if select(&arrays, self.env.locales(), &Discarded::default()).is_none() {
            return Err(Excluded {
                locales: self.env.locales().map(ToString::to_string).collect(),
            }
            .into());
        }
        let selection = select(&arrays, self.env.locales(), &discarded)
            .ok_or(NotCompatible::TemplatesExhausted)?;
        let rows = shown
            .into_iter()
            .map(|shown| self.row(&metadata, &rulebook, &selection, shown))
            .collect::<Result<Vec<_>, _>>()?;
        let ui = |key: UiKey| -> Result<Option<Label>, NotCompatible> {
            selection
                .entry(ArrayKey::Ui(key))
                .map(|entry| {
                    let at = RenderedAt::Ui(key);
                    self.label(&metadata, entry, &[], key.slot(), at, &selection)
                })
                .transpose()
        };
        let table = selection.locale.table;
        let title =
            ui(UiKey::TransactionTitle)?.unwrap_or_else(|| Label::text(rulebook.title(table)));
        let confirm = ui(UiKey::AffirmativeActionLabel)?
            .unwrap_or_else(|| Label::text(rulebook.confirm(table)));
        let deny = ui(UiKey::DenialActionLabel)?
            .unwrap_or_else(|| Label::text(selection.locale.text(WalletText::Deny)));
        let hint = ui(UiKey::SecurityHint)?.map(|label| label.text);
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
            locale: selection.locale,
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

    /// A label rendered: a template interpolated, then held to §3.3 for its slot (View §2).
    fn label(
        &self,
        metadata: &Metadata<'_>,
        entry: &Localized<'_>,
        nulls: &[usize],
        slot: LabelSlot,
        at: RenderedAt,
        selection: &Selection<'_, '_>,
    ) -> Result<Label, NotCompatible> {
        let text = match entry.label {
            LabelForm::Plain(text) | LabelForm::Markdown(text) => text.as_str().to_owned(),
            LabelForm::Template(template) => Template(template).interpolate(
                &metadata.claims,
                self.payload.node(),
                nulls,
                selection.locale.table,
                self.env.amounts(),
            )?,
        };
        LabelText::parse(&text, slot)
            .map(drop)
            .map_err(|violation| NotCompatible::RenderedLabel { at, violation })?;
        Ok(Label {
            kind: entry.label.kind(),
            text,
        })
    }

    /// One instance's row: its label in the selected locale, its value formatted there, its
    /// section.
    fn row(
        &self,
        metadata: &Metadata<'_>,
        rulebook: &Rulebook<'_>,
        selection: &Selection<'_, '_>,
        shown: Shown<'_>,
    ) -> Result<ViewRow, NotCompatible> {
        let Shown { instance, content } = shown;
        // Every display array matched: a missing entry is one no locale kept.
        let entry = selection
            .entry(ArrayKey::Claim(instance.claim))
            .ok_or(NotCompatible::TemplatesExhausted)?;
        let at = RenderedAt::Claim(concrete_text(&instance.path));
        let label = self.label(
            metadata,
            entry,
            &instance.nulls,
            LabelSlot::ClaimName,
            at,
            selection,
        )?;
        let value = match content {
            Content::Alone => None,
            Content::Image(image) => Some(Value::Image(image)),
            Content::Formatted(kind) => Some(self.formatted(kind, instance.value, selection)?),
            Content::Template(kind) => {
                let template = instance.value.as_str().ok_or_else(|| {
                    NotCompatible::TemplateNotString(concrete_text(&instance.path))
                })?;
                let text = Template(template).interpolate(
                    &metadata.claims,
                    self.payload.node(),
                    &instance.nulls,
                    selection.locale.table,
                    self.env.amounts(),
                )?;
                Some(self.formatted(kind, &Node::String(Cow::Owned(text)), selection)?)
            }
        };
        // View §2's rule on formatted values holds by construction: each formatted text is a
        // payload string conformance held to Proof Metadata §3.3's directional rule, an
        // interpolation of such strings, or text of the wallet's own table.
        let section = match instance.placement {
            Placement::Main => None,
            Placement::Embedded => rulebook.section(selection.locale.table),
        };
        Ok(ViewRow {
            row: Row {
                label,
                value,
                section: section.map(str::to_owned),
            },
            claim: instance.claim,
            path: owned(&instance.path),
        })
    }

    /// A value of a kind other than an image, formatted in the selected locale.
    fn formatted(
        &self,
        kind: FormattedKind,
        value: &Node<'_>,
        selection: &Selection<'_, '_>,
    ) -> Result<Value, NotCompatible> {
        Value::format(
            kind,
            written(value),
            selection.locale.table,
            self.env.amounts(),
        )
        .map_err(|bad| NotCompatible::Value {
            value_type: kind_name(ValueKind::Formatted(kind)),
            bad,
        })
    }
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
            (
                mandate::metadata(subtype, given)?,
                Rulebook::Mandate(subtype),
            )
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
fn arrays<'a, 'm>(metadata: &'a Metadata<'m>) -> Vec<(ArrayKey, &'a DisplayArray<'m>)> {
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
