//! Decimal digits, and the ten characters the `digits` table writes them with.

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
    pub(crate) const fn value(self) -> u8 {
        self as u8
    }
}

/// The characters of the ten digits, from zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Numerals([char; 10]);

impl Numerals {
    /// `0` to `9`.
    pub(crate) const ASCII: Self = Self(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']);

    /// The numerals `text` lists, zero to nine; `None` for a text of another count of
    /// characters.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut chars = text.chars();
        let mut numerals = ['0'; 10];
        for numeral in &mut numerals {
            *numeral = chars.next()?;
        }
        chars.next().is_none().then_some(Self(numerals))
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
    pub(crate) fn write(self, value: u128, width: u8, out: &mut String) {
        let digits = Digit::of_integer(value);
        for _ in digits.len()..usize::from(width) {
            out.push(self.digit(Digit::Zero));
        }
        out.extend(digits.into_iter().map(|digit| self.digit(digit)));
    }
}
