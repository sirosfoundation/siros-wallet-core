//! ICU4X 2.4's selection of date and time patterns from CLDR's `availableFormats`, as its data
//! generator runs it (icu_provider_source 2.4.0, `datetime/semantic_skeletons.rs`, and
//! icu_datetime 2.4.0, `provider/skeleton/helpers.rs`): a field set becomes the requested
//! fields, the closest skeleton of `availableFormats` gives its pattern, and the pattern's fields
//! take the requested widths. Each `Err` is a form ICU4X's generator panics on.

use std::cmp::Ordering;

/// A field symbol ICU4X reads in a pattern (icu_datetime, `provider/fields/symbols.rs`), in
/// the canonical order of a skeleton's fields (`get_canonical_order`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Symbol {
    Era,
    Year,
    ExtendedYear,
    CyclicYear,
    RelatedYear,
    Month,
    StandAloneMonth,
    Day,
    DayOfYear,
    WeekdayInMonth,
    ModifiedJulianDay,
    Weekday,
    LocalWeekday,
    StandAloneWeekday,
    AmPm,
    NoonMidnight,
    FlexiblePeriod,
    Hour11,
    Hour12,
    Hour23,
    Minute,
    Second,
    MillisInDay,
    /// Seconds with this many fraction digits, 1 to 9.
    DecimalSecond(u8),
    SpecificZone,
    OffsetZone,
    GenericZone,
    LocationZone,
    IsoZone,
    IsoZoneWithZ,
}

/// The pattern letter of each symbol but the decimal second.
const LETTERS: [(char, Symbol); 29] = [
    ('G', Symbol::Era),
    ('y', Symbol::Year),
    ('u', Symbol::ExtendedYear),
    ('U', Symbol::CyclicYear),
    ('r', Symbol::RelatedYear),
    ('M', Symbol::Month),
    ('L', Symbol::StandAloneMonth),
    ('d', Symbol::Day),
    ('D', Symbol::DayOfYear),
    ('F', Symbol::WeekdayInMonth),
    ('g', Symbol::ModifiedJulianDay),
    ('E', Symbol::Weekday),
    ('e', Symbol::LocalWeekday),
    ('c', Symbol::StandAloneWeekday),
    ('a', Symbol::AmPm),
    ('b', Symbol::NoonMidnight),
    ('B', Symbol::FlexiblePeriod),
    ('K', Symbol::Hour11),
    ('h', Symbol::Hour12),
    ('H', Symbol::Hour23),
    ('m', Symbol::Minute),
    ('s', Symbol::Second),
    ('A', Symbol::MillisInDay),
    ('z', Symbol::SpecificZone),
    ('O', Symbol::OffsetZone),
    ('v', Symbol::GenericZone),
    ('V', Symbol::LocationZone),
    ('x', Symbol::IsoZone),
    ('X', Symbol::IsoZoneWithZ),
];

impl Symbol {
    /// The symbol of a pattern letter; `None` for a letter ICU4X writes as text.
    pub(crate) fn of(letter: char) -> Option<Self> {
        LETTERS
            .iter()
            .find(|(known, _)| *known == letter)
            .map(|(_, symbol)| *symbol)
    }

    /// The symbol's pattern letter.
    pub(crate) fn letter(self) -> char {
        match self {
            Self::DecimalSecond(_) => 'S',
            symbol => LETTERS
                .iter()
                .find(|(_, known)| *known == symbol)
                .map_or('S', |(letter, _)| *letter),
        }
    }

    /// The kind skeleton matching compares (`idx_for_skeleton`).
    fn kind(self) -> u8 {
        match self {
            Self::Era => 0,
            Self::Year | Self::ExtendedYear | Self::CyclicYear | Self::RelatedYear => 1,
            Self::Month | Self::StandAloneMonth => 2,
            Self::Day | Self::DayOfYear | Self::WeekdayInMonth | Self::ModifiedJulianDay => 4,
            Self::Weekday | Self::LocalWeekday | Self::StandAloneWeekday => 5,
            Self::AmPm | Self::NoonMidnight | Self::FlexiblePeriod => 6,
            Self::Hour11 | Self::Hour12 | Self::Hour23 => 7,
            Self::Minute => 8,
            Self::Second | Self::MillisInDay | Self::DecimalSecond(_) => 9,
            Self::SpecificZone
            | Self::OffsetZone
            | Self::GenericZone
            | Self::LocationZone
            | Self::IsoZone
            | Self::IsoZoneWithZ => 10,
        }
    }

    /// The order of a skeleton's fields: the order of `LETTERS`, a decimal second after
    /// milliseconds of the day by its digits.
    fn order(self) -> (usize, u8) {
        let (symbol, digits) = match self {
            Self::DecimalSecond(digits) => (Self::MillisInDay, digits),
            symbol => (symbol, 0),
        };
        let rank = LETTERS
            .iter()
            .position(|(_, known)| *known == symbol)
            .unwrap_or(LETTERS.len());
        (rank, digits)
    }

    /// Whether a requested width of 1 or 2 stands for the abbreviated text
    /// (`is_at_least_abbreviated`).
    fn abbreviated(self) -> bool {
        matches!(
            self,
            Self::Era
                | Self::CyclicYear
                | Self::Weekday
                | Self::AmPm
                | Self::NoonMidnight
                | Self::FlexiblePeriod
                | Self::SpecificZone
        )
    }
}

/// A pattern field: its symbol and its width, 1 to 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Field {
    pub(crate) symbol: Symbol,
    pub(crate) width: u8,
}

impl Ord for Field {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.symbol.order(), self.width).cmp(&(other.symbol.order(), other.width))
    }
}

impl PartialOrd for Field {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Field {
    /// Whether the field writes text (`get_length_type`).
    fn text(self) -> bool {
        match self.symbol {
            Symbol::Era
            | Symbol::CyclicYear
            | Symbol::Weekday
            | Symbol::AmPm
            | Symbol::NoonMidnight
            | Symbol::FlexiblePeriod
            | Symbol::SpecificZone
            | Symbol::OffsetZone
            | Symbol::GenericZone
            | Symbol::LocationZone => true,
            Symbol::Month
            | Symbol::StandAloneMonth
            | Symbol::LocalWeekday
            | Symbol::StandAloneWeekday => self.width > 2,
            Symbol::Year
            | Symbol::ExtendedYear
            | Symbol::RelatedYear
            | Symbol::Day
            | Symbol::DayOfYear
            | Symbol::WeekdayInMonth
            | Symbol::ModifiedJulianDay
            | Symbol::Hour11
            | Symbol::Hour12
            | Symbol::Hour23
            | Symbol::Minute
            | Symbol::Second
            | Symbol::MillisInDay
            | Symbol::DecimalSecond(_)
            | Symbol::IsoZone
            | Symbol::IsoZoneWithZ => false,
        }
    }
}

/// A pattern's item: text, a field, or a run of a letter outside ICU4X's field symbols, which
/// ICU4X writes as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Item {
    Text(String),
    Field(Field),
    Unread(char, usize),
}

/// Why a pattern or a skeleton does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unreadable {
    /// A quote opens a text that no quote closes.
    Unclosed,
    /// A field is longer than six letters.
    Width,
    /// A skeleton names a field twice.
    Duplicate,
    /// A skeleton holds a character outside the field letters.
    Symbol,
}

/// The width of a run of `count` letters.
fn width(count: usize) -> Result<u8, Unreadable> {
    u8::try_from(count)
        .ok()
        .filter(|width| (1..=6).contains(width))
        .ok_or(Unreadable::Width)
}

/// A TR35 pattern's runs: quoted and unquoted text, and runs of one ASCII letter
/// (icu_datetime, `provider/pattern/reference/tokenizer.rs`).
enum Token {
    Text(String),
    Letters(char, usize),
}

fn tokens(text: &str) -> Result<Vec<Token>, Unreadable> {
    let mut tokens = Vec::new();
    let mut chars = text.chars().peekable();
    let mut run = String::new();
    let mut quoted = false;
    while let Some(c) = chars.next() {
        if c == '\'' {
            if chars.next_if_eq(&'\'').is_some() {
                run.push('\'');
            } else {
                quoted = !quoted;
            }
        } else if quoted || !c.is_ascii_alphabetic() {
            run.push(c);
        } else {
            if !run.is_empty() {
                tokens.push(Token::Text(std::mem::take(&mut run)));
            }
            let mut count = 1;
            while chars.next_if_eq(&c).is_some() {
                count += 1;
            }
            tokens.push(Token::Letters(c, count));
        }
    }
    if quoted {
        return Err(Unreadable::Unclosed);
    }
    if !run.is_empty() {
        tokens.push(Token::Text(run));
    }
    Ok(tokens)
}

/// A pattern's items as ICU4X reads them (`provider/pattern/reference/parser.rs`): `s` with
/// `S` after it, or after `.`, is a second with fraction digits; `Z` is an offset.
pub(crate) fn pattern(text: &str) -> Result<Vec<Item>, Unreadable> {
    let tokens = tokens(text)?;
    let mut items: Vec<Item> = Vec::new();
    let mut rest = tokens.as_slice();
    while let Some((token, tail)) = rest.split_first() {
        rest = tail;
        let (letter, count) = match token {
            Token::Text(text) => {
                push_text(&mut items, text);
                continue;
            }
            Token::Letters(letter, count) => (*letter, *count),
        };
        let field = match letter {
            's' => {
                let fraction = match rest {
                    [Token::Letters('S', digits), tail @ ..] => Some((*digits, tail)),
                    [Token::Text(dot), Token::Letters('S', digits), tail @ ..] if dot == "." => {
                        Some((*digits, tail))
                    }
                    _ => None,
                };
                let symbol = match fraction {
                    Some((digits, tail)) => {
                        rest = tail;
                        Symbol::DecimalSecond(
                            u8::try_from(digits)
                                .ok()
                                .filter(|digits| (1..=9).contains(digits))
                                .ok_or(Unreadable::Width)?,
                        )
                    }
                    None => Symbol::Second,
                };
                Field {
                    symbol,
                    width: width(count)?,
                }
            }
            'Z' => match count {
                1..=3 => Field {
                    symbol: Symbol::IsoZone,
                    width: 4,
                },
                4 => Field {
                    symbol: Symbol::OffsetZone,
                    width: 4,
                },
                5 => Field {
                    symbol: Symbol::IsoZoneWithZ,
                    width: 5,
                },
                _ => return Err(Unreadable::Width),
            },
            _ => match Symbol::of(letter) {
                Some(symbol) => Field {
                    symbol,
                    width: width(count)?,
                },
                None => {
                    items.push(Item::Unread(letter, count));
                    continue;
                }
            },
        };
        items.push(Item::Field(field));
    }
    Ok(items)
}

/// `text` appended to the items, joining the text before it.
fn push_text(items: &mut Vec<Item>, text: &str) {
    match items.last_mut() {
        Some(Item::Text(last)) => last.push_str(text),
        _ => items.push(Item::Text(text.to_owned())),
    }
}

/// A skeleton: its fields, ordered.
pub(crate) type Skeleton = Vec<Field>;

/// A skeleton of `availableFormats`, its fields ordered (`Skeleton::try_from`); `None` for one
/// ICU4X skips: one with a variant subtag, or with a quarter or week field.
pub(crate) fn skeleton(text: &str) -> Result<Option<Skeleton>, Unreadable> {
    let mut fields: Skeleton = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let mut count = 1;
        while chars.next_if_eq(&c).is_some() {
            count += 1;
        }
        let (symbol, count) = match c {
            'Z' => match count {
                1..=3 => (Symbol::IsoZone, 4),
                4 => (Symbol::OffsetZone, count),
                5 => (Symbol::IsoZoneWithZ, 4),
                _ => return Err(Unreadable::Width),
            },
            '-' => return Ok(None),
            'Q' | 'q' | 'Y' | 'w' | 'W' => return Ok(None),
            // CLDR's stand-alone weekday matches as the format weekday.
            'c' => (Symbol::Weekday, count),
            _ => (Symbol::of(c).ok_or(Unreadable::Symbol)?, count),
        };
        let field = Field {
            symbol,
            width: width(count)?,
        };
        if fields.contains(&field) {
            return Err(Unreadable::Duplicate);
        }
        fields.push(field);
    }
    fields.sort();
    Ok(Some(fields))
}

/// The distances of skeleton matching (`helpers.rs`).
const WIDTH_MISMATCH: u32 = 1;
const TEXT_VS_NUMERIC: u32 = 100;
const SUBSTANTIAL: u32 = 1000;
const SKELETON_EXTRA: u32 = 10_000;
const REQUESTED_MISSING: u32 = 100_000;

/// A pattern of `availableFormats`, and whether its skeleton has plural variants.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub(crate) items: Vec<Item>,
    pub(crate) plural: bool,
}

/// The pattern skeleton matching chose, and its distance from the request; `u32::MAX` for the
/// fields written one after another, ICU4X's last resort.
#[derive(Debug, Clone)]
pub(crate) struct Chosen {
    pub(crate) items: Vec<Item>,
    pub(crate) distance: u32,
    pub(crate) plural: bool,
}

/// The closest skeleton to `fields`, its distance and its count of missing fields
/// (`find_best_skeleton`): the first of the skeletons, in their order, at the least distance.
fn closest<'a>(
    skeletons: &'a [(Skeleton, Entry)],
    fields: &[Field],
) -> Option<(&'a Entry, u32, usize)> {
    let mut best: Option<(&Entry, u32, usize)> = None;
    for (skeleton, entry) in skeletons {
        let (mut distance, mut missing) = (0u32, 0usize);
        let (mut requested, mut offered) = (fields, skeleton.as_slice());
        loop {
            match (requested.split_first(), offered.split_first()) {
                (Some((want, wants)), Some((have, haves))) => {
                    match have.symbol.kind().cmp(&want.symbol.kind()) {
                        Ordering::Less => {
                            offered = haves;
                            distance += SKELETON_EXTRA;
                        }
                        Ordering::Greater => {
                            requested = wants;
                            distance += REQUESTED_MISSING;
                            missing += 1;
                        }
                        Ordering::Equal => {
                            distance += if want == have {
                                0
                            } else if want.symbol != have.symbol {
                                SUBSTANTIAL
                            } else if want.text() != have.text() {
                                TEXT_VS_NUMERIC
                            } else {
                                WIDTH_MISMATCH
                            };
                            (requested, offered) = (wants, haves);
                        }
                    }
                }
                (None, Some((_, haves))) => {
                    offered = haves;
                    distance += SKELETON_EXTRA;
                }
                (Some((_, wants)), None) => {
                    requested = wants;
                    distance += REQUESTED_MISSING;
                    missing += 1;
                }
                (None, None) => break,
            }
        }
        if best.is_none_or(|(_, least, _)| distance < least) {
            best = Some((entry, distance, missing));
        }
    }
    best
}

/// The pattern for `fields` (`create_best_pattern_for_fields` over fields of the date alone or
/// of the time alone, through `get_best_available_format_pattern`): the closest skeleton's
/// pattern, each field of a requested kind at the requested width where both write text or
/// both write digits; a single field the closest skeleton writes poorly, alone.
pub(crate) fn choose(skeletons: &[(Skeleton, Entry)], fields: &[Field]) -> Chosen {
    let found = closest(skeletons, fields);
    let least = found.map_or(u32::MAX, |(_, distance, _)| distance);
    if let [field] = fields
        && least >= TEXT_VS_NUMERIC
    {
        return Chosen {
            items: vec![Item::Field(*field)],
            distance: least,
            plural: false,
        };
    }
    let Some((entry, distance, _)) = found.filter(|(_, _, missing)| *missing < fields.len()) else {
        // No skeleton holds a requested field: the fields, a space between each.
        let mut items = Vec::new();
        for field in fields {
            if !items.is_empty() {
                items.push(Item::Text(" ".to_owned()));
            }
            items.push(Item::Field(*field));
        }
        return Chosen {
            items,
            distance: u32::MAX,
            plural: false,
        };
    };
    let mut items = entry.items.clone();
    if distance != 0 {
        for item in &mut items {
            let Item::Field(field) = item else { continue };
            let Some(want) = fields
                .iter()
                .find(|want| want.symbol.kind() == field.symbol.kind())
            else {
                continue;
            };
            if want.width != field.width && want.text() == field.text() {
                field.width = if want.symbol.abbreviated() && want.width < 3 {
                    3
                } else {
                    want.width
                };
            }
        }
    }
    Chosen {
        items,
        distance,
        plural: entry.plural,
    }
}

/// The class of names a text field loads: its kind, and the field's variant and width class
/// (icu_datetime, `pattern/names.rs`, `load_for_pattern`).
fn names(field: Field) -> Option<(u8, Symbol, u8)> {
    let class = |width: u8| match width {
        1..=3 => 3,
        other => other,
    };
    match field.symbol {
        Symbol::Era | Symbol::CyclicYear => Some((0, field.symbol, class(field.width))),
        Symbol::Month | Symbol::StandAloneMonth if field.text() => {
            Some((2, field.symbol, field.width))
        }
        Symbol::Weekday | Symbol::LocalWeekday | Symbol::StandAloneWeekday if field.text() => {
            Some((5, field.symbol, class(field.width)))
        }
        Symbol::AmPm | Symbol::NoonMidnight | Symbol::FlexiblePeriod => {
            Some((6, field.symbol, class(field.width)))
        }
        _ => None,
    }
}

/// The patterns of one field set, best match first, with the names each kind loads kept to the
/// first pattern's (`enforce_consistent_field_length`): a later field of a kind whose names
/// differ takes the field that loaded them.
pub(crate) fn consistent(patterns: &mut [&mut Chosen]) {
    patterns.sort_by_key(|chosen| chosen.distance);
    let mut loaded: Vec<Field> = Vec::new();
    for chosen in patterns.iter_mut() {
        let mut replaced: Vec<(Field, Field)> = Vec::new();
        for item in &chosen.items {
            let Item::Field(field) = item else { continue };
            let Some((kind, ..)) = names(*field) else {
                continue;
            };
            match loaded
                .iter()
                .find(|first| names(**first).is_some_and(|(k, ..)| k == kind))
            {
                Some(first) if names(*first) != names(*field) => replaced.push((*field, *first)),
                Some(_) => {}
                None => loaded.push(*field),
            }
        }
        for item in &mut chosen.items {
            if let Item::Field(field) = item
                && let Some((_, first)) = replaced.iter().find(|(from, _)| from == field)
            {
                *field = *first;
            }
        }
    }
}
