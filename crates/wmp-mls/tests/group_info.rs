//! The GroupInfo export (spec §3.1's `wmp.mls.group.create` param) and the
//! creator's advertised credential capabilities (spec §2.3's
//! `accepted_credential_types` — RFC 9420 valn0104): found live at the
//! Cleverbase interop (2026-11-24), where a peer's X.509-credential
//! KeyPackage was refused ("Credentials are not acceptable") and their
//! group create demanded the `group_info` member the provider never
//! minted.

use wmp_core::mls::MlsProvider;
use wmp_mls::OpenMlsProvider;

#[test]
fn the_group_info_exports_and_parses() {
    let provider = OpenMlsProvider::for_identity("wallet-a").expect("the provider");
    let (group_id, _welcomes) = provider.create_group(0x0001, &[]).expect("the group");
    let info = provider.export_group_info(&group_id).expect("the export");

    // The wire: base64url of an MlsMessageOut wrapping the GroupInfo —
    // parse it back at the same entry point the peer's resolve served.
    let bytes = decode(&info);
    assert!(!bytes.is_empty(), "the export carries bytes");
    assert!(
        info.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "base64url, unpadded"
    );
    // The MlsMessage envelope's wire_type discriminant: 4 = GroupInfo
    // (the same wire table the KeyPackage's 5 came from).
    assert_eq!(&bytes[..2], &[0x00, 0x01], "the version");
    assert_eq!(bytes[2], 0x00, "the discriminant's high byte");
    assert_eq!(bytes[3], 0x04, "wire_type 4: GroupInfo");

    // An unknown group refuses like every other group-keyed call.
    let refused = provider
        .export_group_info("no-such-group")
        .expect_err("an unknown group refuses");
    assert_eq!(refused.to_rpc().code, wmp_core::error::ERR_MLS_ERROR);
}

/// base64url decode — the test-side twin of the provider's own codec.
fn decode(encoded: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(encoded.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in encoded.bytes() {
        if byte == b'=' {
            break;
        }
        let value = ALPHABET.iter().position(|&a| a == byte).unwrap() as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}
