//! The leaf parameters of a TS12 payload (EC TS12 v1.0.1, Section 3.3.1), each typed for the
//! generic rendering, with the least prominent level the type lets it take.

use siros_codec::date::Date;
use siros_codec::json::{Json, JsonNumber};

use crate::currency::CurrencyCode;
use crate::definition::Prominence;
use crate::image::ImageRef;
use crate::json::write;
use crate::payload::{
    integrity_of, Frequency, IsoDateTime, Location, NumberText, PayloadText, Scalar, Step, Typed,
    ValueFault, Values, INTEGRITY_SUFFIX,
};
use crate::ts12::rules::{DateOrDateTime, DateTimeText, LogoUrl};

/// The leaf parameters of a payload, each with its location in the payload.
pub(crate) struct Leaves {
    location: Location,
    leaves: Vec<Leaf>,
}

/// A leaf parameter.
struct Leaf {
    location: Location,
    value: LeafValue,
    /// The least prominent level the type allows, whatever the metadata sets: for a member its
    /// schema requires and the user must see.
    floor: Option<Prominence>,
}

enum LeafValue {
    Text(String),
    Number(NumberText),
    Boolean(bool),
    Date(Date),
    DateTime(String),
    DateOrDateTime(String),
    Logo(String),
    Frequency(Frequency),
    Currency(CurrencyCode),
}

/// The typed leaves of a TS12 payload: the value at each location, and the floor of each leaf
/// that has one.
pub(crate) struct TypedLeaves {
    pub(crate) values: Values,
    pub(crate) floors: Vec<(Location, Prominence)>,
}

impl Leaves {
    /// The leaves of a payload.
    pub(crate) fn payload() -> Self {
        Self {
            location: Location::default(),
            leaves: Vec::new(),
        }
    }

    fn push(&mut self, name: &str, value: LeafValue, floor: Option<Prominence>) {
        self.leaves.push(Leaf {
            location: self.location.then(Step::Key(name.to_owned())),
            value,
            floor,
        });
    }

    /// The string member `name`.
    pub(crate) fn text(&mut self, name: &str, value: &impl AsRef<str>, floor: Option<Prominence>) {
        self.push(name, LeafValue::Text(value.as_ref().to_owned()), floor);
    }

    /// The string member `name`, when present.
    pub(crate) fn optional_text(&mut self, name: &str, value: Option<&impl AsRef<str>>) {
        if let Some(value) = value {
            self.text(name, value, None);
        }
    }

    /// The date member `name`, when present.
    pub(crate) fn optional_date(&mut self, name: &str, value: Option<Date>) {
        if let Some(value) = value {
            self.push(name, LeafValue::Date(value), None);
        }
    }

    /// The date and time member `name`, when present.
    pub(crate) fn optional_date_time(&mut self, name: &str, value: Option<&DateTimeText>) {
        if let Some(value) = value {
            self.push(name, LeafValue::DateTime(value.as_ref().to_owned()), None);
        }
    }

    /// The date, or date and time, member `name`, when present.
    pub(crate) fn optional_date_or_time(&mut self, name: &str, value: Option<&DateOrDateTime>) {
        if let Some(value) = value {
            self.push(
                name,
                LeafValue::DateOrDateTime(value.as_ref().to_owned()),
                None,
            );
        }
    }

    /// The image URL member `name`, when present.
    pub(crate) fn optional_logo(&mut self, name: &str, value: Option<&LogoUrl>) {
        if let Some(value) = value {
            self.push(name, LeafValue::Logo(value.as_ref().to_owned()), None);
        }
    }

    /// The currency member `name`.
    pub(crate) fn currency(&mut self, name: &str, value: CurrencyCode, floor: Option<Prominence>) {
        self.push(name, LeafValue::Currency(value), floor);
    }

    /// The number member `name`.
    pub(crate) fn number(&mut self, name: &str, value: &JsonNumber, floor: Option<Prominence>) {
        self.push(name, LeafValue::Number(NumberText::of(value)), floor);
    }

    /// The number member `name`, when present.
    pub(crate) fn optional_number(&mut self, name: &str, value: Option<&JsonNumber>) {
        if let Some(value) = value {
            self.number(name, value, None);
        }
    }

    /// The boolean member `name`, when present.
    pub(crate) fn optional_boolean(&mut self, name: &str, value: Option<bool>) {
        if let Some(value) = value {
            self.push(name, LeafValue::Boolean(value), None);
        }
    }

    /// The frequency member `name`.
    pub(crate) fn frequency(&mut self, name: &str, value: Frequency) {
        self.push(name, LeafValue::Frequency(value), None);
    }

    /// The leaves of the object member `name`, which `leaves` adds.
    pub(crate) fn object(&mut self, name: &str, leaves: impl FnOnce(&mut Self)) {
        let child = self.location.then(Step::Key(name.to_owned()));
        let parent = std::mem::replace(&mut self.location, child);
        leaves(self);
        self.location = parent;
    }

    /// The members the schema of an object leaves open: an object's leaves, or the value of any
    /// other member as one leaf. The `#integrity` companion of an image member of the object
    /// belongs to the image.
    pub(crate) fn rest(&mut self, members: &[(String, Json)]) {
        for (name, value) in members {
            let companion = name.strip_suffix(INTEGRITY_SUFFIX).is_some_and(|of| {
                let image = self.location.then(Step::Key(of.to_owned()));
                self.leaves
                    .iter()
                    .any(|leaf| leaf.location == image && matches!(leaf.value, LeafValue::Logo(_)))
            });
            match value {
                _ if companion => {}
                Json::Object(object) => self.object(name, |leaves| leaves.rest(object)),
                Json::String(text) => self.text(name, text, None),
                Json::Number(number) => self.number(name, number, None),
                Json::Bool(b) => self.push(name, LeafValue::Boolean(*b), None),
                Json::Null | Json::Array(_) => self.text(name, &write(value), None),
            }
        }
    }

    /// The leaves typed for the generic rendering of `payload`: text under the directional
    /// rules, images under PaSO View, Section 3.
    ///
    /// # Errors
    ///
    /// The location and fault of the first leaf that is no value of its type.
    pub(crate) fn typed(self, payload: &Json) -> Result<TypedLeaves, (Location, ValueFault)> {
        let mut values = Vec::with_capacity(self.leaves.len());
        let mut floors = Vec::new();
        for leaf in self.leaves {
            let fault = |fault| (leaf.location.clone(), fault);
            let value = match leaf.value {
                LeafValue::Text(text) => {
                    Typed::Scalar(Scalar::Text(PayloadText::parse(text).map_err(fault)?))
                }
                LeafValue::Number(number) => Typed::Scalar(Scalar::Number(number)),
                LeafValue::Boolean(b) => Typed::Scalar(Scalar::Boolean(b)),
                LeafValue::Date(date) => Typed::Scalar(Scalar::Date(date)),
                LeafValue::DateTime(text) => Typed::Scalar(date_time(&text).map_err(fault)?),
                LeafValue::DateOrDateTime(text) => Typed::Scalar(match Date::parse(&text) {
                    Some(date) => Scalar::Date(date),
                    None => date_time(&text).map_err(fault)?,
                }),
                LeafValue::Logo(url) => {
                    Typed::Image(ImageRef::logo(&url, integrity_of(payload, &leaf.location)))
                }
                LeafValue::Frequency(frequency) => Typed::Scalar(Scalar::Frequency(frequency)),
                LeafValue::Currency(code) => Typed::Scalar(Scalar::Currency(code)),
            };
            if let Some(floor) = leaf.floor {
                floors.push((leaf.location.clone(), floor));
            }
            values.push((leaf.location, value));
        }
        Ok(TypedLeaves {
            values: Values::new(values),
            floors,
        })
    }
}

/// The RFC 3339 `date-time` `text` as an ISO 8601 date and time.
fn date_time(text: &str) -> Result<Scalar, ValueFault> {
    IsoDateTime::parse(text)
        .map(Scalar::DateTime)
        .ok_or(ValueFault::Type(crate::definition::BaseType::IsoDateTime))
}
