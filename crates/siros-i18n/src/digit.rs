//! Decimal digits, and the ten characters a numbering system writes them with.

/// A decimal digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Digit {
    Zero,
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
    Nine,
}

impl Digit {
    /// The digit `c` writes; `None` for a character other than `0` to `9`.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "conformance"
    ))]
    pub(crate) const fn of(c: char) -> Option<Self> {
        Some(match c {
            '0' => Self::Zero,
            '1' => Self::One,
            '2' => Self::Two,
            '3' => Self::Three,
            '4' => Self::Four,
            '5' => Self::Five,
            '6' => Self::Six,
            '7' => Self::Seven,
            '8' => Self::Eight,
            '9' => Self::Nine,
            _ => return None,
        })
    }

    /// The last decimal digit of `n`.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date"
    ))]
    pub(crate) const fn last(n: u128) -> Self {
        match n % 10 {
            0 => Self::Zero,
            1 => Self::One,
            2 => Self::Two,
            3 => Self::Three,
            4 => Self::Four,
            5 => Self::Five,
            6 => Self::Six,
            7 => Self::Seven,
            8 => Self::Eight,
            9.. => Self::Nine,
        }
    }

    /// The digits of `n`, most significant first, without leading zeros: `0` for zero.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date"
    ))]
    pub(crate) fn of_integer(n: u128) -> Vec<Self> {
        let mut digits = vec![Self::last(n)];
        let mut rest = n / 10;
        while rest > 0 {
            digits.push(Self::last(rest));
            rest /= 10;
        }
        digits.reverse();
        digits
    }

    /// The number it writes, 0 to 9.
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    pub(crate) const fn value(self) -> u8 {
        self as u8
    }
}

/// The characters of the ten digits, from zero.
#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date"
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Numerals([char; 10]);

#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date"
))]
impl Numerals {
    /// `0` to `9`.
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    pub(crate) const ASCII: Self = Self(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']);

    /// The numerals whose zero is `text`, one character; the nine characters after it in Unicode
    /// write one to nine. `None` for another text.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut chars = text.chars();
        let zero = chars.next()?;
        if chars.next().is_some() {
            return None;
        }
        let after = |n: u32| char::from_u32(u32::from(zero) + n);
        Some(Self([
            zero,
            after(1)?,
            after(2)?,
            after(3)?,
            after(4)?,
            after(5)?,
            after(6)?,
            after(7)?,
            after(8)?,
            after(9)?,
        ]))
    }

    /// The character of `digit`.
    pub(crate) const fn digit(self, digit: Digit) -> char {
        let [zero, one, two, three, four, five, six, seven, eight, nine] = self.0;
        match digit {
            Digit::Zero => zero,
            Digit::One => one,
            Digit::Two => two,
            Digit::Three => three,
            Digit::Four => four,
            Digit::Five => five,
            Digit::Six => six,
            Digit::Seven => seven,
            Digit::Eight => eight,
            Digit::Nine => nine,
        }
    }

    /// Writes `value` in `width` digits or more, zeros before its own.
    #[cfg(feature = "date")]
    pub(crate) fn write(self, value: u32, width: u8, out: &mut String) {
        let digits = Digit::of_integer(u128::from(value));
        for _ in digits.len()..usize::from(width) {
            out.push(self.digit(Digit::Zero));
        }
        out.extend(digits.into_iter().map(|digit| self.digit(digit)));
    }
}
