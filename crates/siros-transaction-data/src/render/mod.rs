//! Generic rendering (PaSO View, Section 2): every displayed claim instance as a labelled row in
//! the order of the claims, `null` paths expanded by the recursive rule, labels interpolated and
//! checked, and a cap on the items shown.

mod template;

use siros_codec::json::Json;
use siros_dcql::PathComponent;
use siros_oid4vp::RequestSignature;

use crate::definition::{
    BaseType, ClaimDisplay, ClaimIndex, ClaimName, LabelFormat, LabelLength, LabelRole, LabelRules,
    LabelText, Prominence, TextFault, UiLabel,
};
use crate::image::{Image, ImageFault};
use crate::payload::{
    scalar, select, Location, PayloadText, Reach, Scalar, Typed, ValueFault, Values,
};
use crate::projection::{Projected, ProjectedClaim};
use crate::sources::Rulebook;
use crate::type_id::TypeId;
use crate::view::{Interpolated, Row, RowValue, Segment, ShownLabel, TransactionView};

use template::Sources;
pub use template::TemplateFault;

/// The most items a view shows: claim instances and UI elements (PaSO View, Section 2).
pub const MAX_ITEMS: usize = 200;

/// Why an entry cannot render in full. The entry is then not compatible (PaSO View, Section
/// 2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum RenderFault {
    /// A template does not interpolate.
    Template(#[source] TemplateFault),
    /// The interpolated label of the claim at this position, or of a UI element, breaks a rule
    /// of PaSO Proof Metadata, Section 3.3.
    Label(Option<ClaimIndex>, #[source] TextFault),
    /// The view would show this many items, more than [`MAX_ITEMS`].
    TooManyItems(usize),
    /// A TS12 leaf parameter at this location has no localised name, and its level is not 4
    /// (EC TS12 v1.0.1, Section 3.3.1).
    LabelMissing(Location),
    /// A TS12 type has no `affirmative_action_label` (EC TS12 v1.0.1, Section 3.3.3).
    AffirmativeAbsent,
    /// The interpolated value of the claim at this location is no value of the template's
    /// inner type.
    Value(Location, #[source] ValueFault),
}

impl RenderFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Template(fault) => fault.code(),
            Self::Label(_, fault) => fault.code(),
            Self::TooManyItems(_) => "render_too_many_items",
            Self::LabelMissing(_) => "render_label_missing",
            Self::AffirmativeAbsent => "render_affirmative_absent",
            Self::Value(_, fault) => fault.code(),
        }
    }
}

/// A displayed claim instance: the claim, its display entry, its location, the array positions
/// its `null`s took, and its value.
pub(crate) struct Placed<'p, V> {
    index: ClaimIndex,
    claim: &'p ProjectedClaim,
    display: &'p ClaimDisplay,
    location: Location,
    wildcards: Vec<u64>,
    value: V,
}

/// A row's value, ready to show: an image verified.
pub(crate) enum Ready {
    /// A value that formats as text.
    Scalar(Scalar),
    /// `label_only`.
    LabelOnly,
    /// A template and its inner type.
    Template(PayloadText, BaseType),
    /// An image, verified.
    Image(Image),
}

impl<'p, V> Placed<'p, V> {
    /// The instance's location in the payload.
    pub(crate) fn location(&self) -> &Location {
        &self.location
    }

    /// The instance's value.
    pub(crate) fn value(&self) -> &V {
        &self.value
    }

    /// The instance with the value `value`.
    pub(crate) fn with<W>(self, value: W) -> Placed<'p, W> {
        Placed {
            index: self.index,
            claim: self.claim,
            display: self.display,
            location: self.location,
            wildcards: self.wildcards,
            value,
        }
    }
}

/// The displayed claim instances of `projected` over `payload` that hold a value of `values`,
/// in display order: at each level the claims without a `null` left first, in declared order,
/// then each group of the claims that share a prefix up to their first `null`, element by
/// element (PaSO View, Section 2).
pub(crate) fn layout<'p>(
    projected: &'p Projected,
    payload: &Json,
    values: &'p Values,
) -> Vec<Placed<'p, &'p Typed>> {
    let level: Vec<Pending<'p>> = projected
        .claims()
        .iter()
        .enumerate()
        .filter_map(|(at, claim)| {
            Some(Pending {
                index: ClaimIndex::new(at),
                claim,
                display: claim.display()?,
                components: claim.definition().path().components().to_vec(),
                wildcards: Vec::new(),
            })
        })
        .collect();
    let mut placed = Vec::new();
    expand(level, payload, values, &mut placed);
    placed
}

/// A claim at a level of the recursive rule: its path with the `null`s bound so far replaced by
/// their positions.
#[derive(Clone)]
struct Pending<'p> {
    index: ClaimIndex,
    claim: &'p ProjectedClaim,
    display: &'p ClaimDisplay,
    components: Vec<PathComponent>,
    wildcards: Vec<u64>,
}

fn expand<'p>(
    level: Vec<Pending<'p>>,
    payload: &Json,
    values: &'p Values,
    placed: &mut Vec<Placed<'p, &'p Typed>>,
) {
    let first_null = |p: &Pending<'_>| p.components.iter().position(|c| *c == PathComponent::Null);
    for pending in level.iter().filter(|p| first_null(p).is_none()) {
        let Some(location) = Location::bound(&pending.components, &[]) else {
            continue;
        };
        if let Some(value) = values.get(&location) {
            placed.push(Placed {
                index: pending.index,
                claim: pending.claim,
                display: pending.display,
                location,
                wildcards: pending.wildcards.clone(),
                value,
            });
        }
    }
    let mut groups: Vec<(Vec<PathComponent>, Vec<Pending<'p>>)> = Vec::new();
    for pending in &level {
        let Some(null) = first_null(pending) else {
            continue;
        };
        let prefix = pending.components.get(..null).unwrap_or_default().to_vec();
        match groups.iter_mut().find(|(key, _)| *key == prefix) {
            Some((_, members)) => members.push(pending.clone()),
            None => groups.push((prefix, vec![pending.clone()])),
        }
    }
    for (prefix, members) in groups {
        let elements = match select(payload, &prefix).as_deref() {
            Ok([found]) => match found.value {
                Json::Array(items) => items.len(),
                _ => 0,
            },
            _ => 0,
        };
        for position in (0u64..).take(elements) {
            let next = members
                .iter()
                .map(|member| bind_first_null(member, position))
                .collect();
            expand(next, payload, values, placed);
        }
    }
}

/// `pending` with its first `null` taking `position`.
fn bind_first_null<'p>(pending: &Pending<'p>, position: u64) -> Pending<'p> {
    let mut components = pending.components.clone();
    if let Some(null) = components.iter_mut().find(|c| **c == PathComponent::Null) {
        *null = PathComponent::Index(position);
    }
    let mut wildcards = pending.wildcards.clone();
    wildcards.push(position);
    Pending {
        components,
        wildcards,
        ..pending.clone()
    }
}

/// What a view is rendered from.
pub(crate) struct Rendering<'r> {
    pub(crate) type_id: &'r TypeId,
    pub(crate) projected: &'r Projected,
    pub(crate) payload: &'r Json,
    pub(crate) values: &'r Values,
    pub(crate) floors: &'r [(Location, Prominence)],
    pub(crate) signature: RequestSignature,
}

impl Rendering<'_> {
    /// The view of the instances `placed`, their values ready, without the TS12 images
    /// `absent` that did not verify.
    ///
    /// # Errors
    ///
    /// [`RenderFault`]: the first rule the view breaks.
    pub(crate) fn render(
        &self,
        placed: Vec<Placed<'_, Ready>>,
        absent: Vec<(Location, ImageFault)>,
    ) -> Result<TransactionView, RenderFault> {
        let projected = self.projected;
        let sources = Sources {
            claims: projected.claims(),
            payload: self.payload,
            values: self.values,
        };
        let rules = projected.source().label_rules();
        let rows = placed
            .into_iter()
            .map(|place| self.row(place, &sources, rules))
            .collect::<Result<Vec<_>, _>>()?;
        let view = TransactionView {
            type_id: self.type_id.clone(),
            source: projected.source(),
            rulebook: projected.rulebook(),
            title: projected
                .title()
                .map(|l| ui_label(l, &sources, rules))
                .transpose()?,
            affirmative: projected
                .affirmative()
                .map(|l| ui_label(l, &sources, rules))
                .transpose()?,
            denial: projected
                .denial()
                .map(|l| ui_label(l, &sources, rules))
                .transpose()?,
            security_hint: projected.security_hint().map(|hint| hint.value().clone()),
            rows,
            absent,
            signature: self.signature,
        };
        if let Rulebook::Ts12(_) = projected.rulebook() {
            self.ts12_complete(&view)?;
        }
        Ok(view)
    }

    /// The row of `place`, its label under `rules`.
    fn row(
        &self,
        place: Placed<'_, Ready>,
        sources: &Sources<'_>,
        rules: LabelRules,
    ) -> Result<Row, RenderFault> {
        let display = place.display;
        let label = shown::<ClaimName>(
            display.name().as_str(),
            display.format(),
            &place.wildcards,
            sources,
            rules,
        )
        .map_err(|fault| match fault {
            Shown::Template(fault) => RenderFault::Template(fault),
            Shown::Text(fault) => RenderFault::Label(Some(place.index), fault),
        })?;
        let value = match place.value {
            Ready::Scalar(value) => RowValue::Value(value),
            Ready::LabelOnly => RowValue::LabelOnly,
            Ready::Image(image) => RowValue::Image(image),
            Ready::Template(text, inner) => {
                let segments = template::interpolate(text.as_str(), &place.wildcards, sources)
                    .map_err(RenderFault::Template)?;
                inner_value(segments, inner)
                    .map_err(|fault| RenderFault::Value(place.location.clone(), fault))?
            }
        };
        let set = place.claim.definition().prominence();
        let prominence = match self.projected.rulebook() {
            Rulebook::Ts12(_) => Some(self.prominence(set, &place.location)),
            Rulebook::Generic => set,
        };
        Ok(Row {
            location: place.location,
            label,
            value,
            prominence,
        })
    }

    /// The level of a TS12 leaf at `location`: the metadata's, 3 when unset, raised to the
    /// leaf's floor (EC TS12 v1.0.1, Section 3.3.1).
    fn prominence(&self, set: Option<Prominence>, location: &Location) -> Prominence {
        let level = set.unwrap_or(Prominence::Supplementary);
        match self.floors.iter().find(|(at, _)| at == location) {
            Some((_, floor)) => level.min(*floor),
            None => level,
        }
    }

    /// Checks that every TS12 leaf parameter shows as a row, is an image left out, or that the
    /// metadata marks it 4 and its type lets it be left out; and that the type has an
    /// `affirmative_action_label` (EC TS12 v1.0.1, Sections 3.3.1 and 3.3.3).
    fn ts12_complete(&self, view: &TransactionView) -> Result<(), RenderFault> {
        if view.affirmative.is_none() {
            return Err(RenderFault::AffirmativeAbsent);
        }
        for (location, _) in self.values.iter() {
            let shown = view.rows.iter().any(|row| row.location == *location);
            if shown || view.absent.iter().any(|(at, _)| at == location) {
                continue;
            }
            let claim = self.projected.claims().iter().find(|claim| {
                location.reach(claim.definition().path().components()) == Reach::Addresses
            });
            let level = self.prominence(claim.and_then(|c| c.definition().prominence()), location);
            if claim.is_none() || level != Prominence::Omittable {
                return Err(RenderFault::LabelMissing(location.clone()));
            }
        }
        Ok(())
    }
}

/// Why a label does not show.
enum Shown {
    Template(TemplateFault),
    Text(TextFault),
}

/// The label `text` of role `R` formatted by `format`: interpolated when a template, then
/// checked against the rules of its role under `rules`, each value counted as the payload
/// writes it (PaSO View, Section 2).
fn shown<R: LabelRole>(
    text: &str,
    format: LabelFormat,
    wildcards: &[u64],
    sources: &Sources<'_>,
    rules: LabelRules,
) -> Result<ShownLabel, Shown> {
    match format {
        LabelFormat::Plain | LabelFormat::MiniMarkdown => Ok(ShownLabel {
            segments: vec![Segment::Text(text.to_owned())],
            format,
        }),
        LabelFormat::TemplateMiniMarkdown => {
            let segments =
                template::interpolate(text, wildcards, sources).map_err(Shown::Template)?;
            LabelText::<R>::parse(&written(&segments), LabelLength::Final, rules)
                .map(drop)
                .map_err(Shown::Text)?;
            Ok(ShownLabel {
                segments,
                format: LabelFormat::MiniMarkdown,
            })
        }
    }
}

/// A UI element's label under `rules`, interpolated when a template.
fn ui_label<R: LabelRole>(
    label: &UiLabel<R>,
    sources: &Sources<'_>,
    rules: LabelRules,
) -> Result<ShownLabel, RenderFault> {
    shown::<R>(label.value().as_str(), label.format(), &[], sources, rules).map_err(|fault| {
        match fault {
            Shown::Template(fault) => RenderFault::Template(fault),
            Shown::Text(fault) => RenderFault::Label(None, fault),
        }
    })
}

/// The text of `segments`, each value as the payload writes it.
fn written(segments: &[Segment]) -> String {
    segments
        .iter()
        .map(|segment| match segment {
            Segment::Text(text) => text.clone(),
            Segment::Value(value) => value.text(),
        })
        .collect()
}

/// The interpolated `segments` of a template whose inner type is `inner`: their text, each value
/// as the payload writes it, is a value of `inner`.
fn inner_value(segments: Vec<Segment>, inner: BaseType) -> Result<RowValue, ValueFault> {
    match inner {
        BaseType::LabelOnly => Ok(RowValue::LabelOnly),
        BaseType::Boolean | BaseType::Image => Err(ValueFault::Type(inner)),
        _ => {
            scalar(PayloadText::parse(written(&segments))?, inner).map(drop)?;
            Ok(RowValue::Template(Interpolated { segments, inner }))
        }
    }
}
