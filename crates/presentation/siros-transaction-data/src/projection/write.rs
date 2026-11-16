//! The JSON text of a projected definition: `{language, source, rulebook, definition}`, the
//! definition in the form of PaSO Proof Metadata, Section 3, each array with its one entry.

use siros_dcql::PathComponent;
use siros_display::{Locale, Localized};

use super::{Projected, ProjectedClaim};
use crate::definition::{
    LabelRole, Mandatory, Prominence, UiElementKey, UiLabel, ValueType, AFFIRMATIVE, DENIAL,
    SECURITY_HINT, TITLE,
};
use crate::json::{quoted, write};

impl Projected {
    /// The JSON text of the projection. The text is a function of the projection: members in a
    /// fixed order, claims and elements in the metadata's, the additional parameters in the
    /// member order of RFC 8785, Section 3.2.3.
    #[must_use]
    pub fn to_json(&self) -> String {
        let claims: Vec<String> = self.claims.iter().map(ProjectedClaim::to_json).collect();
        let mut labels: Vec<String> = Vec::new();
        push_label(&mut labels, &AFFIRMATIVE, self.affirmative.as_ref());
        push_label(&mut labels, &DENIAL, self.denial.as_ref());
        push_label(&mut labels, &TITLE, self.title.as_ref());
        if let Some(hint) = &self.security_hint {
            labels.push(element(
                &SECURITY_HINT,
                &entry_json(hint.locale(), &[("value", quoted(hint.value().as_str()))]),
            ));
        }
        for (key, label) in &self.others {
            labels.push(element(key, &ui_label_json(label)));
        }
        let mut members = vec![
            format!("\"claims\":[{}]", claims.join(",")),
            format!("\"ui_labels\":{{{}}}", labels.join(",")),
        ];
        members.extend(
            self.extra
                .iter()
                .map(|(name, value)| format!("{}:{}", quoted(name), write(value))),
        );
        format!(
            "{{\"language\":{},\"source\":{},\"rulebook\":{},\"definition\":{{{}}}}}",
            quoted(self.language.as_str()),
            quoted(self.source.as_str()),
            quoted(self.rulebook.as_str()),
            members.join(",")
        )
    }
}

impl ProjectedClaim {
    fn to_json(&self) -> String {
        let definition = &self.definition;
        let path: Vec<String> = definition
            .path()
            .components()
            .iter()
            .map(|component| match component {
                PathComponent::Key(key) => quoted(key),
                PathComponent::Index(index) => index.to_string(),
                PathComponent::Null => "null".to_owned(),
            })
            .collect();
        let mut members = vec![
            format!("\"path\":[{}]", path.join(",")),
            format!(
                "\"mandatory\":{}",
                definition.mandatory() == Mandatory::Required
            ),
        ];
        if let Some(value_type) = definition.value_type() {
            members.push(format!(
                "\"value_type\":{}",
                quoted(&ValueType::name(value_type))
            ));
        }
        if let Some(display) = &self.display {
            let mut parts = vec![("name", quoted(display.name().as_str()))];
            if let Some(format) = display.format().name() {
                parts.push(("display_type", quoted(format)));
            }
            if let Some(description) = display.description() {
                parts.push(("description", quoted(description.as_str())));
            }
            members.push(format!(
                "\"display\":[{}]",
                entry_json(display.locale(), &parts)
            ));
        }
        if let Some(prominence) = definition.prominence() {
            members.push(format!(
                "\"visualisation\":{}",
                Prominence::level(prominence)
            ));
        }
        format!("{{{}}}", members.join(","))
    }
}

/// Adds the element `key` of the one entry `label`, when present.
fn push_label<R: LabelRole>(
    labels: &mut Vec<String>,
    key: &UiElementKey,
    label: Option<&UiLabel<R>>,
) {
    if let Some(label) = label {
        labels.push(element(key, &ui_label_json(label)));
    }
}

/// The member `key` of `ui_labels`: an array of the one entry `entry`.
fn element(key: &UiElementKey, entry: &str) -> String {
    format!("{}:[{entry}]", quoted(key.as_str()))
}

fn ui_label_json<R: LabelRole>(label: &UiLabel<R>) -> String {
    let mut parts = vec![("value", quoted(label.value().as_str()))];
    if let Some(format) = label.format().name() {
        parts.push(("value_type", quoted(format)));
    }
    entry_json(label.locale(), &parts)
}

/// The JSON object of an entry in `locale`, with the members `parts` after `locale`.
fn entry_json(locale: Option<&Locale>, parts: &[(&str, String)]) -> String {
    let members: Vec<String> = locale
        .map(|locale| format!("\"locale\":{}", quoted(locale.as_str())))
        .into_iter()
        .chain(
            parts
                .iter()
                .map(|(name, value)| format!("\"{name}\":{value}")),
        )
        .collect();
    format!("{{{}}}", members.join(","))
}
