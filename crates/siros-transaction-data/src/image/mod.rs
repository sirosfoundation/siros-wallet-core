//! Images of a payload (PaSO View, Section 3, `image`; EC TS12 v1.0.1, Section 4.3.1, for a
//! TS12 logo): a Data URL, or an `https` URL with the integrity values of its `#integrity`
//! sibling. The core checks an image's form, and carries it to the consent view for the UI. It
//! never resolves or verifies image content.

use siros_codec::json::Json;
use siros_codec::{base64, Base64Error};
use siros_oid4vp::HttpsUrl;

use crate::integrity::{Integrity, IntegrityFault};

/// The most bytes of a Data URL's encoded payload, and of an image the UI shows.
pub const MAX_IMAGE_BYTES: usize = 512 * 1024;

/// The most pixels of an image the UI shows, in either direction.
pub const MAX_IMAGE_PIXELS: u32 = 2048;

/// How a request reached the wallet, which sets the images it admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// The Digital Credentials API. The verifier chose it, and its images are Data URLs of a
    /// format Credential Manager shows: [`ImageFormat::DC_API`] (the owner's ruling).
    DcApi,
    /// A redirect flow: every image of PaSO View, Section 3.
    Redirect,
}

/// An image format a Data URL may name (PaSO View, Section 3, `image`: PNG, JPEG and SVG).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageFormat {
    /// `image/png`.
    Png,
    /// `image/jpeg`.
    Jpeg,
    /// `image/svg+xml`.
    Svg,
}

impl ImageFormat {
    const ALL: [Self; 3] = [Self::Png, Self::Jpeg, Self::Svg];

    /// The formats of an image over the Digital Credentials API: those Credential Manager
    /// decodes that PaSO View requires. Credential Manager takes an entry's image as an Android
    /// `Bitmap` (androidx `VerificationEntryDisplayProperties.icon`, `2b7ce630`), which androidx
    /// registers as a PNG (`OpenId4VpRegistry.getIconBytes`); Android decodes PNG and JPEG into
    /// a `Bitmap`, and no SVG.
    pub const DC_API: [Self; 2] = [Self::Png, Self::Jpeg];

    /// The media type.
    #[must_use]
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Svg => "image/svg+xml",
        }
    }

    fn of_media_type(media_type: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|format| format.media_type().eq_ignore_ascii_case(media_type))
    }
}

/// An image of the consent view, as information for the UI. The core checked its form alone.
///
/// The UI, before it shows the image: takes the bytes of a Data URL, or resolves the URL and
/// verifies its content against each integrity value ([`Integrity::check`]); holds the content
/// to [`MAX_IMAGE_BYTES`] and [`MAX_IMAGE_PIXELS`]; renders an SVG document statically, with no
/// script, animation or resource outside those the document pins (PaSO Proof SD-JWT-VC and SVG,
/// Section 3); and leaves out an image it cannot verify, since an image carries no consent
/// information (PaSO View, Section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Image {
    /// The image of a Data URL (RFC 2397) in base64.
    Data {
        /// The format its media type names.
        format: ImageFormat,
        /// The decoded bytes.
        bytes: Vec<u8>,
    },
    /// An `https` URL.
    Remote {
        /// The URL.
        url: HttpsUrl,
        /// The integrity values (W3C SRI) of its `#integrity` sibling; `None` for a TS12 logo
        /// without one.
        integrity: Option<Integrity>,
    },
}

/// An image value of a payload, as its form reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageRef {
    /// An image of a well-formed value.
    Image(Image),
    /// A TS12 logo whose value is not well-formed, and why: the view leaves it out (PaSO Proof
    /// SD-JWT-VC and SVG, Section 2: "considered absent").
    Malformed {
        /// The value, as the payload writes it.
        reference: String,
        /// Why it is not well-formed.
        cause: ImageFault,
    },
}

/// Why an image is refused: a PaSO entry is then not compatible (PaSO View, Section 3), and a
/// TS12 logo is left out.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum ImageFault {
    /// The value is neither a Data URL nor an `https` URL.
    NotHttps,
    /// The `https` URL has no `#integrity` sibling.
    IntegrityAbsent,
    /// The `#integrity` sibling is no string.
    IntegrityNotString,
    /// The `#integrity` sibling is no integrity metadata.
    Integrity(#[source] IntegrityFault),
    /// The Data URL has no comma, no `;base64`, or a media type other than PNG, JPEG and SVG.
    DataUrl,
    /// The Data URL's payload is no base64.
    Base64(#[source] Base64Error),
    /// The Data URL's payload has this many bytes, more than 512 KiB.
    TooLarge(usize),
    /// An `https` URL in a request over the Digital Credentials API, whose images are Data URLs.
    RemoteOverDcApi,
    /// A Data URL of this format in a request over the Digital Credentials API, which shows
    /// [`ImageFormat::DC_API`] alone.
    FormatOverDcApi(ImageFormat),
}

impl ImageFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotHttps => "image_not_https",
            Self::IntegrityAbsent => "image_integrity_absent",
            Self::IntegrityNotString => "image_integrity_not_string",
            Self::Integrity(fault) => fault.code(),
            Self::DataUrl => "image_data_url",
            Self::Base64(_) => "image_base64",
            Self::TooLarge(_) => "image_too_large",
            Self::RemoteOverDcApi => "image_remote_over_dc_api",
            Self::FormatOverDcApi(_) => "image_format_over_dc_api",
        }
    }
}

impl ImageRef {
    /// The image of a TS12 logo `text`, `integrity` the value of its `#integrity` sibling, which
    /// a logo may lack: a value that is not well-formed is left out.
    pub(crate) fn logo(text: &str, integrity: Option<&Json>) -> Self {
        let image = match integrity {
            None => Image::parse(text, Sibling::Absent),
            Some(json) => Image::parse(text, Sibling::Given(json)),
        };
        image.map_or_else(
            |cause| Self::Malformed {
                reference: text.to_owned(),
                cause,
            },
            Self::Image,
        )
    }

    /// The image of the payload string `text`, `integrity` the value of its `#integrity`
    /// sibling, which an `https` URL needs.
    pub(crate) fn parse(text: &str, integrity: Option<&Json>) -> Result<Self, ImageFault> {
        let integrity = integrity.ok_or(ImageFault::IntegrityAbsent);
        Image::parse(text, Sibling::Required(integrity)).map(Self::Image)
    }

    /// The image the view shows for a request that came over `channel`.
    ///
    /// # Errors
    ///
    /// [`ImageFault`]: why the value is not well-formed, or not admitted over the channel.
    pub(crate) fn admit(&self, channel: Channel) -> Result<Image, ImageFault> {
        let image = match self {
            Self::Image(image) => image,
            Self::Malformed { cause, .. } => return Err(cause.clone()),
        };
        match (channel, image) {
            (Channel::DcApi, Image::Remote { .. }) => Err(ImageFault::RemoteOverDcApi),
            (Channel::DcApi, Image::Data { format, .. })
                if !ImageFormat::DC_API.contains(format) =>
            {
                Err(ImageFault::FormatOverDcApi(*format))
            }
            (Channel::DcApi | Channel::Redirect, image) => Ok(image.clone()),
        }
    }
}

/// What an `https` image takes of its `#integrity` sibling.
enum Sibling<'j> {
    /// A PaSO image: the sibling's value, or why there is none.
    Required(Result<&'j Json, ImageFault>),
    /// A TS12 logo with a sibling.
    Given(&'j Json),
    /// A TS12 logo without one.
    Absent,
}

impl Image {
    /// The image of `text`: a Data URL, or an `https` URL with the integrity values `sibling`
    /// gives.
    fn parse(text: &str, sibling: Sibling<'_>) -> Result<Self, ImageFault> {
        if let Some(rest) = strip_prefix_ignore_case(text, "data:") {
            return data_url(rest);
        }
        let url = HttpsUrl::parse(text).ok_or(ImageFault::NotHttps)?;
        let sibling = match sibling {
            Sibling::Required(sibling) => Some(sibling?),
            Sibling::Given(sibling) => Some(sibling),
            Sibling::Absent => None,
        };
        let integrity = sibling
            .map(|sibling| match sibling {
                Json::String(value) => Integrity::parse(value).map_err(ImageFault::Integrity),
                _ => Err(ImageFault::IntegrityNotString),
            })
            .transpose()?;
        Ok(Self::Remote { url, integrity })
    }
}

/// The image of a Data URL's text after `data:`: `<media type>[;<parameter>]*;base64,<data>`,
/// the payload at most 512 KiB.
fn data_url(rest: &str) -> Result<Image, ImageFault> {
    let (header, payload) = rest.split_once(',').ok_or(ImageFault::DataUrl)?;
    let mut parts = header.split(';');
    let format = parts
        .next()
        .and_then(ImageFormat::of_media_type)
        .ok_or(ImageFault::DataUrl)?;
    if !parts
        .next_back()
        .is_some_and(|last| last.eq_ignore_ascii_case("base64"))
    {
        return Err(ImageFault::DataUrl);
    }
    if payload.len() > MAX_IMAGE_BYTES {
        return Err(ImageFault::TooLarge(payload.len()));
    }
    let bytes = base64::decode(payload).map_err(ImageFault::Base64)?;
    Ok(Image::Data { format, bytes })
}

/// `text` after `prefix`, compared without regard to ASCII case.
pub(crate) fn strip_prefix_ignore_case<'t>(text: &'t str, prefix: &str) -> Option<&'t str> {
    text.get(..prefix.len())
        .filter(|start| start.eq_ignore_ascii_case(prefix))
        .and_then(|_| text.get(prefix.len()..))
}
