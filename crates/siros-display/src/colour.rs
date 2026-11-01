//! Card colours: the numerical colour values of CSS Color Module Level 3, Section 4.2.

use crate::error::{ColourFault, DisplayError};

/// An sRGB colour with its opacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Colour {
    red: u8,
    green: u8,
    blue: u8,
    alpha: u8,
}

impl Colour {
    /// The colour of a numerical colour value: `#rgb`, `#rrggbb`, `rgb()`, `rgba()`, `hsl()` or
    /// `hsla()` (CSS Color Module Level 3, Sections 4.2.1 to 4.2.5). Components outside their
    /// range are clipped to it, as Section 4.2 requires.
    ///
    /// # Errors
    ///
    /// [`DisplayError::Colour`] with the [`ColourFault`] of text of none of these forms.
    pub fn parse(text: &str) -> Result<Self, DisplayError> {
        let text = text.trim();
        match text.strip_prefix('#') {
            Some(hex) => hexadecimal(hex),
            None => functional(text),
        }
        .map_err(DisplayError::Colour)
    }

    /// The red component.
    pub fn red(&self) -> u8 {
        self.red
    }

    /// The green component.
    pub fn green(&self) -> u8 {
        self.green
    }

    /// The blue component.
    pub fn blue(&self) -> u8 {
        self.blue
    }

    /// The opacity, from 0 (transparent) to 255 (opaque).
    pub fn alpha(&self) -> u8 {
        self.alpha
    }
}

fn opaque(red: u8, green: u8, blue: u8) -> Colour {
    Colour {
        red,
        green,
        blue,
        alpha: u8::MAX,
    }
}

/// `#rgb`, each digit repeated, or `#rrggbb`.
fn hexadecimal(hex: &str) -> Result<Colour, ColourFault> {
    let digits = hex
        .chars()
        .map(|digit| digit.to_digit(16).map(|value| value as u8))
        .collect::<Option<Vec<u8>>>()
        .ok_or(ColourFault::Hexadecimal)?;
    match digits.as_slice() {
        [r, g, b] => Ok(opaque(r * 17, g * 17, b * 17)),
        [r1, r2, g1, g2, b1, b2] => Ok(opaque(r1 * 16 + r2, g1 * 16 + g2, b1 * 16 + b2)),
        _ => Err(ColourFault::Hexadecimal),
    }
}

/// `rgb(…)`, `rgba(…)`, `hsl(…)` or `hsla(…)`, the name in any ASCII case.
fn functional(text: &str) -> Result<Colour, ColourFault> {
    let (name, rest) = text.split_once('(').ok_or(ColourFault::Notation)?;
    let inner = rest.strip_suffix(')').ok_or(ColourFault::Notation)?;
    let args: Vec<&str> = inner.split(',').map(str::trim).collect();
    let (colour, alpha) = match (name.to_ascii_lowercase().as_str(), args.as_slice()) {
        ("rgb", [r, g, b]) => (rgb([r, g, b])?, None),
        ("rgba", [r, g, b, a]) => (rgb([r, g, b])?, Some(*a)),
        ("hsl", [h, s, l]) => (hsl(h, s, l)?, None),
        ("hsla", [h, s, l, a]) => (hsl(h, s, l)?, Some(*a)),
        _ => return Err(ColourFault::Function(args.len())),
    };
    let alpha = match alpha {
        None => u8::MAX,
        Some(a) => channel(number(a, 3)?.clamp(0.0, 1.0)),
    };
    Ok(Colour { alpha, ..colour })
}

/// Three integers, or three percentages (Section 4.2.1).
fn rgb(parts: [&str; 3]) -> Result<Colour, ColourFault> {
    let percentages = parts.iter().all(|part| part.ends_with('%'));
    let mut values = [0u8; 3];
    for (position, (part, value)) in parts.iter().zip(&mut values).enumerate() {
        let component = if percentages {
            percentage(part, position)?.clamp(0.0, 1.0) * 255.0
        } else {
            integer(part, position)?.clamp(0.0, 255.0)
        };
        *value = rounded(component);
    }
    let [r, g, b] = values;
    Ok(opaque(r, g, b))
}

/// A hue in degrees, then saturation and lightness as percentages (Section 4.2.4).
fn hsl(h: &str, s: &str, l: &str) -> Result<Colour, ColourFault> {
    let hue = number(h, 0)?;
    let saturation = percentage(s, 1)?.clamp(0.0, 1.0);
    let lightness = percentage(l, 2)?.clamp(0.0, 1.0);
    // The HSL-to-RGB conversion of Section 4.2.4, with the hue in degrees.
    let m2 = if lightness <= 0.5 {
        lightness * (saturation + 1.0)
    } else {
        lightness + saturation - lightness * saturation
    };
    let m1 = lightness * 2.0 - m2;
    let component = |h: f64| channel(hue_to_rgb(m1, m2, h));
    Ok(opaque(
        component(hue + 120.0),
        component(hue),
        component(hue - 120.0),
    ))
}

fn hue_to_rgb(m1: f64, m2: f64, degrees: f64) -> f64 {
    let h = degrees.rem_euclid(360.0);
    if h < 60.0 {
        m1 + (m2 - m1) * h / 60.0
    } else if h < 180.0 {
        m2
    } else if h < 240.0 {
        m1 + (m2 - m1) * (240.0 - h) / 60.0
    } else {
        m1
    }
}

/// `value` of 0 to 1 as 0 to 255.
fn channel(value: f64) -> u8 {
    rounded(value * 255.0)
}

/// `value` of 0 to 255, to the nearest integer.
fn rounded(value: f64) -> u8 {
    // The value is clamped to 0 to 255 first, so the conversion is exact.
    value.round().clamp(0.0, 255.0) as u8
}

/// The value of `text`, the argument at `position`, when `valid` holds of its digits.
fn value(text: &str, position: usize, valid: bool) -> Result<f64, ColourFault> {
    if !valid {
        return Err(ColourFault::Argument(position));
    }
    text.parse().map_err(|_| ColourFault::Argument(position))
}

/// A CSS `<integer>`, the argument at `position`: an optional sign and decimal digits.
fn integer(text: &str, position: usize) -> Result<f64, ColourFault> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    let valid = !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    value(text, position, valid)
}

/// A CSS `<number>`, the argument at `position`: an optional sign, digits, and an optional
/// fraction with at least one digit after the point.
fn number(text: &str, position: usize) -> Result<f64, ColourFault> {
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, "1"));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    let valid = !unsigned.is_empty() && digits(whole) && !fraction.is_empty() && digits(fraction);
    value(text, position, valid)
}

/// A CSS `<percentage>`, the argument at `position`, as a fraction of one.
fn percentage(text: &str, position: usize) -> Result<f64, ColourFault> {
    let number_text = text
        .strip_suffix('%')
        .ok_or(ColourFault::Argument(position))?;
    number(number_text, position).map(|p| p / 100.0)
}
