//! A JSON value as Python's `repr` writes the value `json` reads, for refusal texts that compare
//! with the reference model's.

use std::fmt;

use siros_openid4vp::json::Node;
use siros_openid4vp::refusal::Quoted;

/// A member's value as Python's `repr` writes `dict.get` of it: `None` for an absent member or
/// `null`, `True` and `False`, numbers as `json` reads them, strings quoted, lists and dicts of
/// those.
pub(crate) struct Repr<'n, 'a>(pub(crate) Option<&'n Node<'a>>);

impl fmt::Display for Repr<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(value) = self.0 else {
            return f.write_str("None");
        };
        match value {
            Node::Null => f.write_str("None"),
            Node::Bool(true) => f.write_str("True"),
            Node::Bool(false) => f.write_str("False"),
            Node::Number(_) => write!(f, "{}", value.python_text()),
            Node::String(text) => write!(f, "{}", Quoted(text)),
            Node::Array(items) => {
                f.write_str("[")?;
                for (k, item) in items.iter().enumerate() {
                    if k > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{}", Repr(Some(item)))?;
                }
                f.write_str("]")
            }
            Node::Object(object) => {
                f.write_str("{")?;
                for (k, member) in object.members().iter().enumerate() {
                    if k > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{}: {}", Quoted(&member.name), Repr(Some(&member.value)))?;
                }
                f.write_str("}")
            }
        }
    }
}
