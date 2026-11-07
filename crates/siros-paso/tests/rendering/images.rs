//! Each image format's dimensions and View §3's bounds.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use siros_openid4vp::media::MediaType;
use siros_openid4vp::rows::{Image, Value};
use siros_paso::image::ImageFailure;
use siros_paso::outcome::{NotCompatible, Outcome};
use siros_paso::{Fetch, PasoProfile};

use crate::common::{CUSTOM, Card, en, entry, png, sri};

use super::claims;

/// A Data URL of content of a media type.
pub(super) fn data_url(media: &str, content: &[u8]) -> String {
    format!("data:{media};base64,{}", STANDARD.encode(content))
}

/// A JPEG (ITU-T T.81 B.1.1): the start of image, each segment as its marker and data behind
/// the two length bytes that count themselves, the end of image.
pub(super) fn jpeg(segments: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![0xFF, 0xD8];
    for (marker, data) in segments {
        out.extend([0xFF, *marker]);
        out.extend(
            u16::try_from(data.len() + 2)
                .expect("a segment")
                .to_be_bytes(),
        );
        out.extend(data);
    }
    out.extend([0xFF, 0xD9]);
    out
}

/// A frame header's data (T.81 B.2.2): precision 8, the lines (height) and the samples per
/// line (width), one component.
pub(super) fn frame(width: u16, height: u16) -> Vec<u8> {
    let mut out = vec![8];
    out.extend(height.to_be_bytes());
    out.extend(width.to_be_bytes());
    out.extend([1, 1, 0x11, 0]);
    out
}

/// What an image claim's value renders as: the dimensions View §3 reads, or the failure.
pub(super) type ImageShown = Result<(u32, u32), ImageFailure>;

/// How an image claim's value renders.
pub(super) fn image(value: &str, profile: &PasoProfile) -> ImageShown {
    let meta = claims(
        r#"{"path": ["logo"], "value_type": "image", "display": [{"locale": "en", "name": "Logo"}]}"#,
    );
    let card = Card::sd_jwt(&format!(r#"{{"{CUSTOM}": {meta}}}"#));
    let entry_json = format!(
        r#"{{"type": "{CUSTOM}", "credential_ids": ["q"], "payload": {{"transaction_id": "t", "logo": "{value}"}}}}"#
    );
    match profile
        .render(
            &entry(&entry_json),
            siros_openid4vp::routing::ChannelKind::DcApi,
            &card.credential(),
            crate::common::placement(&card.credential().format),
            &en(),
        )
        .expect("no fault")
    {
        Ok(rendered) => match &rendered.view.rows[0].row.value {
            Some(Value::Image(Image::Embedded(shown))) => {
                Ok((shown.width().get(), shown.height().get()))
            }
            other => panic!("an image row: {other:?}"),
        },
        Err(Outcome::NotCompatible(NotCompatible::Image { failure, .. })) => Err(failure),
        Err(other) => panic!("an image failure: {other}"),
    }
}

#[test]
pub(super) fn image_headers_give_the_dimensions_view_section_3_bounds() {
    use ImageFailure::{NeitherDataNorHttps, Oversized, Unreadable};
    let svg = |root: &str| data_url("image/svg+xml", root.as_bytes());
    let mut no_header = png(1, 1);
    no_header[12..16].copy_from_slice(b"IDAT");
    // 512 KiB of base64 exactly; RFC 4648's '+' and '/' among its characters.
    let pattern = [0xFB, 0xEF, 0xBE, 0xFF, 0xFF, 0xFF];
    let filled: Vec<u8> = png(1, 1)
        .into_iter()
        .chain(pattern.iter().copied().cycle())
        .take(393_216)
        .collect();
    let full = data_url("image/png", &filled);
    assert!(
        full.len() == "data:image/png;base64,".len() + 524_288
            && full.contains('+')
            && full.contains('/')
    );
    let url_safe = format!(
        "data:image/png;base64,{}",
        URL_SAFE.encode([png(1, 1), pattern[..3].to_vec()].concat())
    );
    let cases: Vec<(&str, String, ImageShown)> = vec![
        // PNG: IHDR's width and height (PNG §11.2.2), at most 2048 each way.
        ("png", data_url("image/png", &png(40, 30)), Ok((40, 30))),
        (
            "png at the bound",
            data_url("image/png", &png(2048, 2048)),
            Ok((2048, 2048)),
        ),
        (
            "png too high",
            data_url("image/png", &png(1, 2049)),
            Err(Oversized {
                width: 1,
                height: 2049,
            }),
        ),
        (
            "png without IHDR",
            data_url("image/png", &no_header),
            Err(Unreadable),
        ),
        // JPEG: the first frame header's lines and samples per line (T.81 B.2.2), past the
        // segments before it; a Huffman table (DHT) is no frame header.
        (
            "progressive jpeg",
            data_url(
                "image/jpeg",
                &jpeg(&[
                    (0xE0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0".to_vec()),
                    (0xC4, vec![0; 17]),
                    (0xC2, frame(300, 200)),
                ]),
            ),
            Ok((300, 200)),
        ),
        (
            "jpeg too wide",
            data_url("image/jpeg", &jpeg(&[(0xC0, frame(2049, 1))])),
            Err(Oversized {
                width: 2049,
                height: 1,
            }),
        ),
        (
            "jpeg cut after its dimensions",
            data_url(
                "image/jpeg",
                &[
                    0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x01, 0x00, 0x01,
                ],
            ),
            Err(Unreadable),
        ),
        // SVG: the root's width and height in user units, else its viewBox's last two numbers
        // (SVG 1.1 §7.2, §7.7), each read as Python's float and truncated.
        (
            "svg",
            svg(r#"<svg xmlns="http://www.w3.org/2000/svg" width="120" height="80"></svg>"#),
            Ok((120, 80)),
        ),
        (
            "svg in px",
            svg(r#"<svg width="120px" height="80.9px">"#),
            Ok((120, 80)),
        ),
        (
            "svg viewBox",
            svg(r#"<svg viewBox="0 0 64,48">"#),
            Ok((64, 48)),
        ),
        (
            "svg viewBox without a height",
            svg(r#"<svg viewBox="0 0 64 48" width="10">"#),
            Ok((64, 48)),
        ),
        (
            "svg root after another tag, the last width winning",
            svg(
                "<?xml version=\"1.0\"?><svgfoo/><svg xmlns:xlink=\"x\" version=1.1 width=\"5\" data-x=\"1\" width =\t\"7\"\nheight\n= \"6\">",
            ),
            Ok((7, 6)),
        ),
        (
            "svg with a base64 value ending in = before the size",
            svg(r#"<svg data-icon="QUJD=" width="5" height="6">"#),
            Ok((5, 6)),
        ),
        (
            "svg single quotes unread",
            svg(r#"<svg width='5' height='6' viewBox="0 0 9 8">"#),
            Ok((9, 8)),
        ),
        (
            "svg float forms",
            svg(r#"<svg width="1e3" height=" 2_0 ">"#),
            Ok((1000, 20)),
        ),
        (
            "svg fractions",
            svg(r#"<svg width="-0.5" height=".5e1">"#),
            Ok((0, 5)),
        ),
        (
            "svg signs",
            svg(r#"<svg width="+3." height="1_000">"#),
            Ok((3, 1000)),
        ),
        (
            "svg nan",
            svg(r#"<svg width="nan" height="4">"#),
            Err(Unreadable),
        ),
        (
            "svg infinite",
            svg(r#"<svg width="inf" height="4">"#),
            Err(Unreadable),
        ),
        (
            "svg negative",
            svg(r#"<svg width="-1" height="4">"#),
            Err(Unreadable),
        ),
        (
            "svg double underscore",
            svg(r#"<svg width="1__0" height="4">"#),
            Err(Unreadable),
        ),
        (
            "svg leading underscore",
            svg(r#"<svg width="_1" height="4">"#),
            Err(Unreadable),
        ),
        (
            "svg trailing underscore",
            svg(r#"<svg width="1_" height="4">"#),
            Err(Unreadable),
        ),
        (
            "svg underscore before the point",
            svg(r#"<svg width="1_.5" height="4">"#),
            Err(Unreadable),
        ),
        (
            "svg underscore in the exponent",
            svg(r#"<svg width="1e_3" height="4">"#),
            Err(Unreadable),
        ),
        (
            "svg empty exponent",
            svg(r#"<svg width="1e" height="4">"#),
            Err(Unreadable),
        ),
        (
            "svg point alone",
            svg(r#"<svg width="." height="4">"#),
            Err(Unreadable),
        ),
        (
            "svg without dimensions",
            svg(r#"<svg height="4">"#),
            Err(Unreadable),
        ),
        (
            "svg short viewBox",
            svg(r#"<svg viewBox="0 0 64">"#),
            Err(Unreadable),
        ),
        (
            "svg root unclosed",
            svg(r#"<svg width="5" height="6""#),
            Err(Unreadable),
        ),
        (
            "svg too wide",
            svg(r#"<svg width="2049" height="1">"#),
            Err(Oversized {
                width: 2049,
                height: 1,
            }),
        ),
        // A Data URL: an image media type, then base64 in RFC 4648's alphabet with at most
        // two padding characters, at most 512 KiB of it.
        ("512 KiB of base64", full, Ok((1, 1))),
        (
            "three padding characters",
            format!("{}===", data_url("image/png", &png(1, 1))),
            Err(NeitherDataNorHttps),
        ),
        ("base64url", url_safe, Err(NeitherDataNorHttps)),
        (
            "gif",
            "data:image/gif;base64,R0lGODlh".to_owned(),
            Err(NeitherDataNorHttps),
        ),
    ];
    for (why, value, want) in cases {
        assert_eq!(image(&value, &PasoProfile::default()), want, "{why}");
    }
    // View §3: a refused https image names the form the wallet shows.
    assert!(matches!(
        siros_paso::image::resolve("https://b\u{fc}cher.example/l.png", None, &|_| {
            siros_paso::image::Resolution::Unknown
        }),
        Err(NotCompatible::Image { url, failure: ImageFailure::NoIntegrity })
            if url == "https://xn--bcher-kva.example/l.png"
    ));
    // A fetched image of 512 KiB exactly.
    let url = "https://cdn.example/l.png";
    let content = [png(1, 1), vec![0; 524_288 - 57]].concat();
    let fetched = PasoProfile::default().with_resource(
        siros_openid4vp::rows::HttpsUrl::parse(url).expect("url"),
        Fetch::Fetched {
            content: content.clone(),
            media: MediaType::parse("image/png").expect("a media type"),
        },
    );
    let meta = claims(
        r#"{"path": ["logo"], "value_type": "image", "display": [{"locale": "en", "name": "Logo"}]}"#,
    );
    let card = Card::sd_jwt(&format!(r#"{{"{CUSTOM}": {meta}}}"#));
    let entry_json = format!(
        r#"{{"type": "{CUSTOM}", "credential_ids": ["q"], "payload": {{"transaction_id": "t", "logo": "{url}", "logo#integrity": "{}"}}}}"#,
        sri(&content)
    );
    let rendered = fetched
        .render(
            &entry(&entry_json),
            siros_openid4vp::routing::ChannelKind::DcApi,
            &card.credential(),
            crate::common::placement(&card.credential().format),
            &en(),
        )
        .expect("no fault")
        .expect("renders");
    assert!(matches!(
        &rendered.view.rows[0].row.value,
        Some(Value::Image(Image::Embedded(shown))) if (shown.width().get(), shown.height().get()) == (1, 1)
    ));
}
