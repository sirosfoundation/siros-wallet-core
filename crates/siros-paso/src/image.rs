//! View §3 `image`: a PNG, JPEG or SVG Data URL, or an https URL with an `#integrity` sibling
//! whose content verifies; at most 512 KiB encoded and 2048 pixels each way (Core §7.4.2 step 3).
//! An https image the matcher has not fetched renders pending, and phase 2 fetches it.

use std::borrow::Cow;

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use siros_explain::Explain;
use siros_openid4vp::json::Node;
use siros_openid4vp::media::MediaType;
use siros_openid4vp::rows::{
    HttpsUrl, Image, ImageHeight, ImageMedia, ImageRef, ImageSource, ImageWidth, RemoteImage,
    SriMetadata,
};
use siros_openid4vp::sri;
use siros_openid4vp::text::python_space;

use crate::outcome::NotCompatible;

/// The largest image, encoded or fetched: 512 KiB.
const MAX_BYTES: usize = 512 * 1024;
/// The largest dimension in pixels.
const MAX_PIXELS: u64 = 2048;

/// base64 as Python's `b64decode(validate=True)` reads it: the standard alphabet, the padding
/// a length needs, bits past the last byte ignored.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
        .with_decode_allow_trailing_bits(true),
);

/// An image the rules refuse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum ImageFailure {
    /// A Data URL over 512 KiB encoded.
    #[error("over 512 KiB encoded")]
    #[explain(id = "image.encoded_too_large")]
    EncodedTooLarge,
    /// A Data URL whose base64 does not decode.
    #[error("bad base64")]
    #[explain(id = "image.bad_base64")]
    BadBase64,
    /// An https image without a string `#integrity` sibling.
    #[error("no #integrity sibling")]
    #[explain(id = "image.no_integrity")]
    NoIntegrity,
    /// The image could not be fetched, with the reason the wallet recorded.
    #[error("{0}")]
    #[explain(id = "image.fetch")]
    Fetch(#[explain(skip)] String),
    /// Fetched content over 512 KiB.
    #[error("over 512 KiB")]
    #[explain(id = "image.too_large")]
    TooLarge,
    /// Fetched content its `#integrity` does not verify.
    #[error("the content does not match its #integrity")]
    #[explain(id = "image.integrity_mismatch")]
    IntegrityMismatch,
    /// Fetched content of a media type other than PNG, JPEG or SVG.
    #[error("media type {media_type}")]
    #[explain(id = "image.media_type")]
    MediaType {
        /// The fetched media type.
        media_type: MediaType,
    },
    /// Neither a Data URL of a supported image nor an https URL.
    #[error("neither a Data URL nor https")]
    #[explain(id = "image.neither_data_nor_https")]
    NeitherDataNorHttps,
    /// Content that is no image of its media type, or without a size.
    #[error("unreadable image")]
    #[explain(id = "image.unreadable")]
    Unreadable,
    /// More than 2048 pixels one way.
    #[error("{width}x{height} exceeds 2048 pixels")]
    #[explain(id = "image.oversized")]
    Oversized {
        /// The width.
        width: u64,
        /// The height.
        height: u64,
    },
}

/// What the wallet knows of an https image.
#[derive(Debug, Clone, Copy)]
pub enum Resolution<'r> {
    /// Nothing: the matcher has not fetched it.
    Unknown,
    /// Its fetched content and media type.
    Fetched {
        /// The content.
        content: &'r [u8],
        /// The media type.
        media: &'r MediaType,
    },
    /// Its fetch failed, for this reason.
    Failed(&'r str),
}

/// An image's media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Media {
    Png,
    Jpeg,
    Svg,
}

impl Media {
    const ALL: [Self; 3] = [Self::Png, Self::Jpeg, Self::Svg];

    const fn name(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Svg => "image/svg+xml",
        }
    }

    fn of(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|media| media.name() == name)
    }

    const fn image(self) -> ImageMedia {
        match self {
            Self::Png => ImageMedia::PNG,
            Self::Jpeg => ImageMedia::JPEG,
            Self::Svg => ImageMedia::SVG,
        }
    }
}

/// A Data URL `data:<image media type>;base64,<base64>`: its media type and base64 text.
fn data_url(url: &str) -> Option<(Media, &str)> {
    let rest = url.strip_prefix("data:")?;
    let (media, encoded) = rest.split_once(";base64,")?;
    let media = Media::of(media)?;
    let body = encoded.trim_end_matches('=');
    let padding = encoded.len() - body.len();
    let alphabet = body
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
    (alphabet && padding <= 2).then_some((media, encoded))
}

/// The image a payload value names, resolved with what the wallet knows of an https URL's
/// [`ascii`](HttpsUrl::ascii) form; a pending remote image when it knows nothing.
pub fn resolve<'r>(
    url: &str,
    integrity: Option<&Node<'_>>,
    resolution: &dyn Fn(&str) -> Resolution<'r>,
) -> Result<Image, NotCompatible> {
    let refuse = |shown: &str, failure: ImageFailure| NotCompatible::Image {
        url: shown.chars().take(60).collect(),
        failure,
    };
    let (content, media, https) = match data_url(url) {
        Some((media, encoded)) => {
            if encoded.len() > MAX_BYTES {
                return Err(refuse(url, ImageFailure::EncodedTooLarge));
            }
            let content = BASE64
                .decode(encoded)
                .map_err(|_| refuse(url, ImageFailure::BadBase64))?;
            (Cow::Owned(content), media, None)
        }
        None => {
            let https =
                HttpsUrl::parse(url).map_err(|_| refuse(url, ImageFailure::NeitherDataNorHttps))?;
            let shown = https.ascii();
            let integrity = integrity
                .and_then(Node::as_str)
                .map(|integrity| SriMetadata::written(integrity.to_owned()))
                .ok_or_else(|| refuse(shown, ImageFailure::NoIntegrity))?;
            let (content, media) = match resolution(shown) {
                Resolution::Unknown => {
                    return Ok(Image::Remote(RemoteImage::new(https, integrity)));
                }
                Resolution::Failed(reason) => {
                    return Err(refuse(shown, ImageFailure::Fetch(reason.to_owned())));
                }
                Resolution::Fetched { content, media } => (content, media),
            };
            if content.len() > MAX_BYTES {
                return Err(refuse(shown, ImageFailure::TooLarge));
            }
            if !sri::matches(content, &integrity) {
                return Err(refuse(shown, ImageFailure::IntegrityMismatch));
            }
            let media = Media::of(media.essence()).ok_or_else(|| {
                refuse(
                    shown,
                    ImageFailure::MediaType {
                        media_type: media.clone(),
                    },
                )
            })?;
            (Cow::Borrowed(content), media, Some(https))
        }
    };
    let shown = https.as_ref().map_or(url, HttpsUrl::ascii);
    let size = Size::of(&content, media).ok_or_else(|| refuse(shown, ImageFailure::Unreadable))?;
    if size.width > MAX_PIXELS || size.height > MAX_PIXELS {
        return Err(refuse(
            shown,
            ImageFailure::Oversized {
                width: size.width,
                height: size.height,
            },
        ));
    }
    let unreadable = || refuse(shown, ImageFailure::Unreadable);
    let width = u32::try_from(size.width).map_err(|_| unreadable())?;
    let height = u32::try_from(size.height).map_err(|_| unreadable())?;
    let source = https.map_or(ImageSource::Data, |https| ImageSource::Url(Box::new(https)));
    Ok(Image::Embedded(ImageRef::new(
        source,
        media.image(),
        ImageWidth::new(width),
        ImageHeight::new(height),
    )))
}

/// An image's dimensions in pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Size {
    width: u64,
    height: u64,
}

impl Size {
    /// The dimensions the content's header gives; `None` when it is no image of its type.
    fn of(content: &[u8], media: Media) -> Option<Self> {
        match media {
            Media::Png => Self::png(content),
            Media::Jpeg => Self::jpeg(content),
            Media::Svg => Self::svg(content),
        }
    }

    /// The signature, then `IHDR` at byte 12 and the width and height after it.
    fn png(content: &[u8]) -> Option<Self> {
        let signature = content.get(..8)? == b"\x89PNG\r\n\x1a\n";
        let header = content.get(12..16)? == b"IHDR";
        let word = |at: usize| -> Option<u64> {
            let bytes: [u8; 4] = content.get(at..at + 4)?.try_into().ok()?;
            Some(u64::from(u32::from_be_bytes(bytes)))
        };
        (signature && header).then_some(())?;
        Some(Self {
            width: word(16)?,
            height: word(20)?,
        })
    }

    /// The start of image, then the segments up to the first start of frame (SOF0 to SOF15
    /// but DHT, JPG and DAC), whose height and width it gives.
    fn jpeg(content: &[u8]) -> Option<Self> {
        (content.get(..2)? == b"\xff\xd8").then_some(())?;
        let half = |at: usize| -> Option<u64> {
            let bytes: [u8; 2] = content.get(at..at + 2)?.try_into().ok()?;
            Some(u64::from(u16::from_be_bytes(bytes)))
        };
        let mut at = 2usize;
        while at + 9 < content.len() {
            if *content.get(at)? != 0xFF {
                return None;
            }
            let marker = *content.get(at + 1)?;
            if (0xC0..=0xCF).contains(&marker) && !matches!(marker, 0xC4 | 0xC8 | 0xCC) {
                return Some(Self {
                    height: half(at + 5)?,
                    width: half(at + 7)?,
                });
            }
            at += 2 + usize::try_from(half(at + 2)?).ok()?;
        }
        None
    }

    /// The first `<svg ...>` tag's `width` and `height`, a `px` suffix dropped, else its
    /// `viewBox`'s last two of four numbers, each truncated to an integer.
    fn svg(content: &[u8]) -> Option<Self> {
        let attributes = Attributes::of_root(content)?;
        if let (Some(width), Some(height)) = (attributes.get("width"), attributes.get("height")) {
            let dimension = |value: &str| {
                let value = value
                    .strip_suffix("px")
                    .or_else(|| value.strip_suffix("px\n"))
                    .unwrap_or(value);
                pixels(python_float(value)?)
            };
            return Some(Self {
                width: dimension(width)?,
                height: dimension(height)?,
            });
        }
        let view_box = attributes.get("viewBox")?.replace(',', " ");
        let numbers = view_box
            .split(python_space)
            .filter(|number| !number.is_empty())
            .map(python_float)
            .collect::<Option<Vec<f64>>>()?;
        let [_, _, width, height] = numbers.as_slice() else {
            return None;
        };
        Some(Self {
            width: pixels(*width)?,
            height: pixels(*height)?,
        })
    }
}

/// A finite non-negative number of pixels, truncated toward zero.
fn pixels(value: f64) -> Option<u64> {
    (value.is_finite() && value > -1.0).then(|| value.trunc().max(0.0) as u64)
}

/// Python's `float` of a string: surrounding whitespace, a sign, then `inf`, `infinity` or
/// `nan` in any case, or ASCII digits with single underscores between them, a fraction and an
/// exponent.
fn python_float(text: &str) -> Option<f64> {
    let text = text.trim_matches(python_space);
    let (negative, body) = match text.strip_prefix('-') {
        Some(body) => (true, body),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let lower = body.to_ascii_lowercase();
    let magnitude = match lower.as_str() {
        "inf" | "infinity" => f64::INFINITY,
        "nan" => f64::NAN,
        _ => {
            let (mantissa, exponent) = match body.split_once(['e', 'E']) {
                Some((mantissa, exponent)) => (mantissa, Some(exponent)),
                None => (body, None),
            };
            let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
            let digits = |part: &str| {
                !part.is_empty()
                    && !part.starts_with('_')
                    && !part.ends_with('_')
                    && !part.contains("__")
                    && part.bytes().all(|b| b.is_ascii_digit() || b == b'_')
            };
            let mantissa_ok = match (whole.is_empty(), fraction.is_empty()) {
                (true, true) => false,
                (true, false) => digits(fraction),
                (false, true) => digits(whole),
                (false, false) => digits(whole) && digits(fraction),
            };
            let exponent_ok = exponent.is_none_or(|exponent| {
                digits(exponent.strip_prefix(['+', '-']).unwrap_or(exponent))
            });
            if !(mantissa_ok && exponent_ok) {
                return None;
            }
            body.replace('_', "").parse().ok()?
        }
    };
    Some(if negative { -magnitude } else { magnitude })
}

/// The `name="value"` attributes of the first `<svg ...>` tag, the last of a name winning.
struct Attributes(Vec<(String, String)>);

impl Attributes {
    /// The root tag: `<svg` at a word boundary, then everything up to the first `>`.
    fn of_root(content: &[u8]) -> Option<Self> {
        let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let tag = (0..content.len()).find_map(|start| {
            let rest = content.get(start..)?;
            let after = rest.strip_prefix(b"<svg")?;
            if after.first().copied().is_some_and(word) {
                return None;
            }
            let end = after.iter().position(|b| *b == b'>')?;
            after.get(..end)
        })?;
        Self::parse(tag)
    }

    /// Each `[\w:-]+\s*=\s*"[^"]*"` in order, as UTF-8.
    fn parse(tag: &[u8]) -> Option<Self> {
        let name_byte = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-');
        let space = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c');
        let mut out = Vec::new();
        let mut at = 0;
        while at < tag.len() {
            let name_len = tag.get(at..)?.iter().take_while(|b| name_byte(**b)).count();
            if name_len == 0 {
                at += 1;
                continue;
            }
            let mut k = at + name_len;
            k += tag.get(k..)?.iter().take_while(|b| space(**b)).count();
            let quoted = tag.get(k) == Some(&b'=') && {
                k += 1;
                k += tag.get(k..)?.iter().take_while(|b| space(**b)).count();
                tag.get(k) == Some(&b'"')
            };
            let close = if quoted {
                tag.get(k + 1..)?.iter().position(|b| *b == b'"')
            } else {
                None
            };
            match close {
                Some(close) => {
                    let name = std::str::from_utf8(tag.get(at..at + name_len)?).ok()?;
                    let value = std::str::from_utf8(tag.get(k + 1..k + 1 + close)?).ok()?;
                    out.push((name.to_owned(), value.to_owned()));
                    at = k + 2 + close;
                }
                None => at += name_len,
            }
        }
        Some(Self(out))
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .rev()
            .find(|(known, _)| known == name)
            .map(|(_, value)| value.as_str())
    }
}
