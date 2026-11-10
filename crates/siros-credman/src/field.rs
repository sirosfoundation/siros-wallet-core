//! A row as Credential Manager's field: its label and value as one short line of plain text, and
//! whether a text was cut to fit, which A9 reads.

use siros_explain::Explain;
use siros_openid4vp::rows::{Row, Value};
use siros_openid4vp::text::DisplayText;

use crate::cluster::Clusters;

/// The most characters of a field's label or value the matcher writes: a picker row holds one short
/// line. The bound is siros-credman's own; Credential Manager's ABI states no length for a field
/// (android-credman-sys ABI.md §5).
pub const FIELD_MAX: usize = 80;

/// The end of a cut text.
const ELLIPSIS: &str = "\u{2026}";

/// Whether a field's text holds what it shows whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Extent {
    /// The text is whole.
    Whole,
    /// The text is cut to fit, or stands for a value a line of text cannot show.
    Clipped,
}

/// The text of a field: at most [`FIELD_MAX`] characters, and its extent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldText {
    text: String,
    extent: Extent,
}

/// The label of a field: a [`FieldText`] with a visible character ([`DisplayText::visible`]),
/// which Credential Manager requires of a field's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldName(FieldText);

/// A row whose label holds no visible character: no field can name it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(id = "field.no_name")]
#[error("a row's label holds no visible character")]
pub struct NoName;

/// A field of an entry: its label, and its value when the row has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    name: FieldName,
    value: Option<FieldText>,
}

impl FieldText {
    /// `text`, whole when it holds at most [`FIELD_MAX`] characters.
    ///
    /// A longer text keeps its longest prefix that ends at an extended grapheme cluster boundary
    /// (UAX #29) and fits [`FIELD_MAX`] characters with a closer for each directional initiator it
    /// leaves open and an ellipsis after them. Next to a mark, after a Prepend character and after
    /// a ZWJ, the prefix may end at an earlier boundary. The closers match UAX #9 (X6a, X7, X8) and
    /// close the innermost initiator first: PDI an isolate, PDF an embedding or an override. The
    /// ellipsis starts a cluster of its own.
    #[must_use]
    pub fn fit(text: &str) -> Self {
        if text.chars().count() <= FIELD_MAX {
            return Self {
                text: text.to_owned(),
                extent: Extent::Whole,
            };
        }
        let cut = Cut::of(text);
        let mut clipped: String = text.chars().take(cut.chars).collect();
        clipped.extend(cut.open.closers());
        clipped.push_str(ELLIPSIS);
        Self {
            text: clipped,
            extent: Extent::Clipped,
        }
    }

    /// `text` standing for a value a line of text cannot show whole.
    #[must_use]
    pub fn partial(text: &str) -> Self {
        Self {
            extent: Extent::Clipped,
            ..Self::fit(text)
        }
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The extent.
    #[must_use]
    pub const fn extent(&self) -> Extent {
        self.extent
    }
}

impl FieldName {
    /// `text` from its first character other than white space, fitted as [`FieldText::fit`] fits
    /// it.
    ///
    /// # Errors
    ///
    /// [`NoName`] when `text` holds no visible character ([`DisplayText::visible`]).
    pub fn fit(text: &str) -> Result<Self, NoName> {
        let text = text.trim_start();
        if text.chars().any(DisplayText::visible) {
            Ok(Self(FieldText::fit(text)))
        } else {
            Err(NoName)
        }
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The extent.
    #[must_use]
    pub const fn extent(&self) -> Extent {
        self.0.extent()
    }
}

impl Field {
    /// The field of a row, its label's and its value's texts plain, their styles dropped:
    /// Credential Manager draws plain text. A full-text row shows its label alone; an image shows
    /// clipped, as a field holds text alone.
    ///
    /// # Errors
    ///
    /// [`NoName`]: the label holds no visible character.
    pub fn of(row: &Row) -> Result<Self, NoName> {
        let name = FieldName::fit(&row.label.to_string())?;
        let value = match &row.value {
            None => None,
            Some(Value::Image(_)) => Some(FieldText::partial("")),
            Some(Value::Text(text)) => Some(FieldText::fit(&text.to_string())),
        };
        Ok(Self { name, value })
    }

    /// The label.
    #[must_use]
    pub const fn name(&self) -> &FieldName {
        &self.name
    }

    /// The value; `None` shows the label alone.
    #[must_use]
    pub const fn value(&self) -> Option<&FieldText> {
        self.value.as_ref()
    }

    /// Whether the label and the value are whole.
    #[must_use]
    pub fn extent(&self) -> Extent {
        let clipped = std::iter::once(&self.name.0)
            .chain(&self.value)
            .any(|text| text.extent == Extent::Clipped);
        if clipped {
            Extent::Clipped
        } else {
            Extent::Whole
        }
    }
}

/// A prefix of a text that ends where [`Clusters`] allows a cut.
#[derive(Debug, Clone, Default)]
struct Cut {
    /// The characters it holds.
    chars: usize,
    /// The directional initiators it leaves open.
    open: Open,
}

impl Cut {
    /// The longest cut of `text` that fits [`FIELD_MAX`] characters with its closers and the
    /// ellipsis. A closer is a control, which starts a cluster (UAX #29 GB5).
    fn of(text: &str) -> Self {
        let mut read = Self::default();
        let mut cut = Self::default();
        let mut clusters = Clusters::default();
        for c in text.chars() {
            if read.chars >= FIELD_MAX {
                break;
            }
            let boundary = clusters.cut_before(c);
            if boundary && read.chars + read.open.len() < FIELD_MAX {
                cut = read.clone();
            }
            read.chars += 1;
            read.open.read(c);
        }
        cut
    }
}

/// A directional initiator (UAX #9 X2–X5c).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Initiator {
    /// LRI, RLI or FSI.
    Isolate,
    /// LRE, RLE, LRO or RLO.
    Embedding,
}

impl Initiator {
    const fn closer(self) -> char {
        match self {
            Self::Isolate => '\u{2069}',
            Self::Embedding => '\u{202C}',
        }
    }
}

/// The directional initiators a text leaves open, innermost last.
///
/// The stack grows without bound. Outside an overflow isolate it matches as UAX #9's stack of
/// depth 125 does. Every cut that fits lies outside one: inside, at least 63 initiators stay open,
/// and they and their closers exceed [`FIELD_MAX`].
#[derive(Debug, Clone, Default)]
struct Open(Vec<Initiator>);

impl Open {
    /// Reads the text's next character.
    fn read(&mut self, c: char) {
        match c {
            '\u{2066}'..='\u{2068}' => self.0.push(Initiator::Isolate),
            '\u{202A}' | '\u{202B}' | '\u{202D}' | '\u{202E}' => self.0.push(Initiator::Embedding),
            // X6a: a PDI closes the innermost open isolate and the embeddings opened inside it.
            '\u{2069}' => {
                if let Some(isolate) = self.0.iter().rposition(|open| *open == Initiator::Isolate) {
                    self.0.truncate(isolate);
                }
            }
            // X7: a PDF closes the innermost initiator when that is an embedding.
            '\u{202C}' => {
                if let Some((Initiator::Embedding, outer)) = self.0.split_last() {
                    let outer = outer.len();
                    self.0.truncate(outer);
                }
            }
            // X8: a paragraph separator (Bidi_Class B) closes every initiator.
            '\n' | '\r' | '\u{1C}'..='\u{1E}' | '\u{85}' | '\u{2029}' => self.0.clear(),
            _ => {}
        }
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    /// The closers, innermost first.
    fn closers(&self) -> impl Iterator<Item = char> + '_ {
        self.0.iter().rev().map(|open| open.closer())
    }
}
