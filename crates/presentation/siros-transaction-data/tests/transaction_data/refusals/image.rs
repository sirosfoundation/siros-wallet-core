//! The form of an image value (PaSO View, Section 3, `image`): a base64 Data URL of PNG, JPEG or
//! SVG of at most 512 KiB, or an `https` URL with the integrity values of its `#integrity`
//! sibling; over the Digital Credentials API, a Data URL of PNG or JPEG. A PaSO entry with an
//! image of another form is not compatible. The view carries the image to the UI.

use serde_json::json;
use siros_transaction_data::{
    Channel, ClaimIndex, ImageFault, ImageFormat, Incompatibility, IntegrityFault, Location,
    LocationStep, PayloadFault, ValueFault, MAX_IMAGE_BYTES,
};

use crate::common::{
    b64, configured, credential, entries, png, query, rows, sri, Host, Shown, CARD,
};

const TYPE: &str = "urn:paso:sca:com.example:logo:1";
const URL: &str = "https://cdn.example/logo.png";

fn data(media_type: &str, bytes: &[u8]) -> String {
    format!("data:{media_type};base64,{}", b64(bytes))
}

/// The rows the card shows for a logo of `logo`, its `#integrity` sibling `integrity`, for a
/// request over `channel`.
fn outcome(channel: Channel, logo: &str, integrity: Option<&str>) -> Shown {
    let definition = json!({"claims": [
        {"path": ["logo"], "value_type": "image", "display": [{"locale": "en", "name": "Logo"}]}
    ]});
    let mut host = Host::new(json!([configured(TYPE, CARD, &definition)]));
    host.channel = channel;
    let mut payload = json!({"logo": logo});
    if let Some(integrity) = integrity {
        payload["logo#integrity"] = json!(integrity);
    }
    let entry = json!({"type": TYPE, "credential_ids": ["card"], "payload": payload});
    let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
    rows(&host, &entries[0], &credential(CARD, &[]))
}

fn shown(value: &str) -> Shown {
    Ok(vec![("Logo".to_owned(), value.to_owned())])
}

fn logo() -> Location {
    Location::new(vec![LocationStep::Key("logo".to_owned())])
}

/// A fault of the value's form, found as the payload conforms.
fn malformed(fault: ImageFault) -> Shown {
    Err(Incompatibility::Payload(PayloadFault::Value(
        ClaimIndex::new(0),
        logo(),
        ValueFault::Image(fault),
    )))
}

/// A fault of the image over the request's channel.
fn refused(fault: ImageFault) -> Shown {
    Err(Incompatibility::Image(logo(), fault))
}

#[test]
fn each_image_rule_holds_alone() {
    let pin = sri(&png(5, 5));
    let large = format!("data:image/png;base64,{}", "A".repeat(MAX_IMAGE_BYTES + 4));
    let rows: Vec<(&str, Channel, String, Option<&str>, Shown)> = vec![
        (
            "a PNG Data URL",
            Channel::Redirect,
            data("image/png", &png(10, 10)),
            None,
            shown("<image Png>"),
        ),
        (
            "an SVG Data URL over a redirect",
            Channel::Redirect,
            data("image/svg+xml", b"<svg/>"),
            None,
            shown("<image Svg>"),
        ),
        (
            "an https URL with #integrity over a redirect",
            Channel::Redirect,
            URL.to_owned(),
            Some(&pin),
            shown(&format!("<image {URL} pinned>")),
        ),
        (
            "an https URL without #integrity",
            Channel::Redirect,
            URL.to_owned(),
            None,
            malformed(ImageFault::IntegrityAbsent),
        ),
        (
            "an #integrity sibling of no SRI syntax",
            Channel::Redirect,
            URL.to_owned(),
            Some("sha1-abc"),
            malformed(ImageFault::Integrity(IntegrityFault::Malformed)),
        ),
        (
            "an http URL",
            Channel::Redirect,
            "http://cdn.example/logo.png".to_owned(),
            Some(&pin),
            malformed(ImageFault::NotHttps),
        ),
        (
            "a GIF Data URL",
            Channel::Redirect,
            data("image/gif", b"GIF89a"),
            None,
            malformed(ImageFault::DataUrl),
        ),
        (
            "a Data URL without base64",
            Channel::Redirect,
            "data:image/png,abc".to_owned(),
            None,
            malformed(ImageFault::DataUrl),
        ),
        (
            "a Data URL that is no base64",
            Channel::Redirect,
            "data:image/png;base64,***".to_owned(),
            None,
            malformed(ImageFault::Base64(
                siros_codec::base64::decode("***").unwrap_err(),
            )),
        ),
        (
            "a Data URL over 512 KiB",
            Channel::Redirect,
            large.clone(),
            None,
            malformed(ImageFault::TooLarge(MAX_IMAGE_BYTES + 4)),
        ),
        (
            "a PNG Data URL over the DC API",
            Channel::DcApi,
            data("image/png", &png(10, 10)),
            None,
            shown("<image Png>"),
        ),
        (
            "a JPEG Data URL over the DC API",
            Channel::DcApi,
            data("image/jpeg", &[0xff, 0xd8, 0xff]),
            None,
            shown("<image Jpeg>"),
        ),
        (
            "an https URL with #integrity over the DC API",
            Channel::DcApi,
            URL.to_owned(),
            Some(&pin),
            refused(ImageFault::RemoteOverDcApi),
        ),
        (
            "an SVG Data URL over the DC API",
            Channel::DcApi,
            data("image/svg+xml", b"<svg/>"),
            None,
            refused(ImageFault::FormatOverDcApi(ImageFormat::Svg)),
        ),
        (
            "a Data URL over 512 KiB over the DC API",
            Channel::DcApi,
            large,
            None,
            malformed(ImageFault::TooLarge(MAX_IMAGE_BYTES + 4)),
        ),
    ];
    for (case, channel, logo, integrity, expected) in rows {
        assert_eq!(outcome(channel, &logo, integrity), expected, "{case}");
    }
}

/// The view carries an image as information for the UI: a Data URL's format and decoded bytes,
/// an `https` URL with its integrity values.
#[test]
fn the_view_carries_the_image() {
    use siros_transaction_data::{Image, Integrity, RowValue, Selection};

    let image = |logo: &str, integrity: Option<&str>| {
        let definition = json!({"claims": [
            {"path": ["logo"], "value_type": "image", "display": [{"locale": "en", "name": "Logo"}]}
        ]});
        let host = Host::new(json!([configured(TYPE, CARD, &definition)]));
        let mut payload = json!({"logo": logo});
        if let Some(integrity) = integrity {
            payload["logo#integrity"] = json!(integrity);
        }
        let entry = json!({"type": TYPE, "credential_ids": ["card"], "payload": payload});
        let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
        let Ok(Selection::Takes(taken)) = host.select(&[&entries[0]], &credential(CARD, &[]))
        else {
            panic!("{logo}")
        };
        let [row] = taken.view().rows() else {
            panic!("{logo}")
        };
        let RowValue::Image(image) = row.value() else {
            panic!("{logo}")
        };
        image.clone()
    };
    let bytes = png(10, 10);
    assert_eq!(
        image(&data("image/png", &bytes), None),
        Image::Data {
            format: ImageFormat::Png,
            bytes
        }
    );
    let pin = sri(&png(5, 5));
    assert_eq!(
        image(URL, Some(&pin)),
        Image::Remote {
            url: siros_oid4vp::HttpsUrl::parse(URL).unwrap(),
            integrity: Some(Integrity::parse(&pin).unwrap()),
        }
    );
}
