//! Resumption tokens and unpadded base64url against RFC 4648.

use wmp_core::token::{
    base64url_unpadded, new_resumption_token, tokens_equal, RESUMPTION_TOKEN_BYTES,
};

#[test]
fn token_is_32_unpadded_base64url_chars() {
    let token = new_resumption_token([0u8; RESUMPTION_TOKEN_BYTES]);
    assert_eq!(token.len(), 32);
    assert!(!token.contains('='));
    // 192 zero bits encode to the repeated zero symbol.
    assert_eq!(token, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
}

#[test]
fn token_matches_known_base64url_vectors() {
    // RFC 4648 test vectors, carried over the URL-safe alphabet.
    assert_eq!(base64url_unpadded(&[0xfb, 0xff]), "-_8");
    assert_eq!(
        base64url_unpadded(&[0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e]),
        "FPucA9l-"
    );
    // One and two byte tails produce 2 and 3 characters.
    assert_eq!(base64url_unpadded(&[0x00]), "AA");
    assert_eq!(base64url_unpadded(&[0x00, 0x00]), "AAA");
}

#[test]
fn tokens_compare_without_early_exit() {
    assert!(tokens_equal("ses-abc", "ses-abc"));
    assert!(!tokens_equal("ses-abc", "ses-abd"));
    assert!(!tokens_equal("ses-abc", "ses-ab"));
}
