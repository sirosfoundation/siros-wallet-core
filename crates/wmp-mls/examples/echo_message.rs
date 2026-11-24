//! The Echo-chain MLS artifacts (the Madrid interop, 2026-11-24): one
//! group, one Welcome for the Echo participant, one encrypted message.
//!
//! ```sh
//! cargo run -p wmp-mls --example echo_message -- <key_package_b64> <plaintext>
//! ```
//! Prints, on separate lines: the group id, the commit, the welcome, the
//! ciphertext, the epoch — the WMP calls' fields.

use std::error::Error;

use wmp_core::mls::MlsProvider as _;
use wmp_mls::OpenMlsProvider;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: echo_message <echo_key_package_b64> <plaintext>");
        std::process::exit(2);
    }
    let echo_kp = &args[1];
    let plaintext = args[2].as_bytes();

    let identity = "ebcore:iso6523:0007:5595421925";
    let provider = OpenMlsProvider::for_identity(identity)?;

    let (kp_bytes, echo_suite) = {
        use openmls::prelude::tls_codec::Deserialize as _;
        use openmls::prelude::MlsMessageIn;
        let wrapped = MlsMessageIn::tls_deserialize_exact(&decode_b64(echo_kp)?)
            .map_err(|e| format!("the envelope: {e}"))?;
        let kp_in = match wrapped.extract() {
            openmls::prelude::MlsMessageBodyIn::KeyPackage(kp_in) => kp_in,
            _ => return Err("the envelope holds no KeyPackage".into()),
        };
        let crypto = openmls_rust_crypto::OpenMlsRustCrypto::default();
        use openmls_traits::OpenMlsProvider as _;
        let package = kp_in
            .validate(
                crypto.crypto(),
                openmls::versions::ProtocolVersion::default(),
            )
            .map_err(|e| format!("the package validation: {e}"))?;
        use openmls::prelude::tls_codec::Serialize as _;
        let bytes = package
            .tls_serialize_detached()
            .map_err(|e| format!("the bare package: {e}"))?;
        (bytes, package.ciphersuite())
    };
    // Our provider's suite ids: 1 = X25519/AES128/Ed25519,
    // 2 = P256/AES128/P256 (lib.rs's suite table).
    let suite_id = match echo_suite {
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => 1,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => 2,
        other => {
            return Err(format!("Echo's package uses a suite our provider lacks: {other:?}").into())
        }
    };
    eprintln!("Echo's package suite: {suite_id}");

    // The group (spec 3.1): ours, on the ADDED member's suite, no
    // initial participants — members join by the add flow.
    let (group_id, _welcomes) = provider.create_group(suite_id, &[])?;

    // The add (spec 3.3): stage Echo's KeyPackage — the commit for the
    // group, the Welcome for Echo. Their published "key_package" rides
    // an MLSMessage envelope (found by the parse probe: KeyPackageIn
    // EndOfStream, MlsMessageIn OK) — unwrapped above, then handed to
    // the add as the bare package.
    let echo_kp_b64 = b64url_str(&kp_bytes);
    let (commit, welcome) = provider.add_member(&group_id, &echo_kp_b64)?;

    // The message (spec 4.1): encrypt to the group's current epoch.
    let (ciphertext, epoch) = provider.encrypt(&group_id, plaintext)?;

    // The GroupInfo (spec 3.1's create param): the ratchet-tree-bearing
    // bootstrap their wmp.mls.group.create demands.
    let group_info = provider.export_group_info(&group_id)?;

    println!("{group_id}");
    println!("{commit}");
    println!("{welcome}");
    println!("{ciphertext}");
    println!("{epoch}");
    println!("{group_info}");
    Ok(())
}

/// base64url, unpadded — the crate's own wire codec shape.
fn b64url_str(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(ALPHABET[(buffer >> bits) as usize & 0x3F] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[(buffer << (6 - bits)) as usize & 0x3F] as char);
    }
    out
}

fn decode_b64(s: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        let v = ALPHABET.iter().position(|&a| a == c).unwrap_or(255) as u32;
        if v == 255 {
            continue;
        }
        buffer = (buffer << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}
