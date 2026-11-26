// The zkp presenter seam's node-testable surface: the Handover CBOR
// (pinned against siros-zkp-catalogues' own known-answer vectors, the
// byte-for-byte ground the Rust presenter verifies) and the seed
// extraction from the stored credential metadata.

import test from "node:test";
import assert from "node:assert/strict";

import { openId4VpHandover, secretSeedOf } from "../dist/presenter.js";

const hexToBytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((h) => parseInt(h, 16)));
const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");

// siros-zkp-catalogues/tests/vectors/session.json — the redirect vectors,
// the same ground truth Handover::redirect asserts against.
const VECTORS = [
  {
    name: "B.2.6.1 non-normative example",
    client_id: "x509_san_dns:example.com",
    nonce: "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
    response_uri: "https://example.com/response",
    jwk_thumbprint_hex: "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047",
    session_transcript_hex: "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac",
  },
  {
    name: "nym_auth verifier 1 (encrypted response)",
    client_id: "x509_san_dns:verifier.example",
    nonce: "pOA0oqEAhLnqug2r7Ve4tQ",
    response_uri: "https://verifier.example/verification/direct_post",
    jwk_thumbprint_hex: "1111111111111111111111111111111111111111111111111111111111111111",
    session_transcript_hex: "83f6f682714f70656e494434565048616e646f76657258204dcf19c000b7cbfe74ab5698820f4022e200e5165fbb6cddd4bea272e1cdf39d",
  },
];

test("the Handover CBOR matches the catalogues' known answers, byte for byte", async () => {
  for (const v of VECTORS) {
    // The transcript is [null, null, Handover] (0x83 0xf6 0xf6 + the
    // handover); the vector pins the transcript, so the handover is it
    // minus the three-byte head.
    const transcript = hexToBytes(v.session_transcript_hex);
    const expected = transcript.slice(3);
    const handover = await openId4VpHandover(
      v.client_id,
      v.nonce,
      b64u(hexToBytes(v.jwk_thumbprint_hex)),
      v.response_uri,
    );
    assert.equal(bytesToHex(handover), bytesToHex(expected), v.name);
  }
});

test("an empty thumbprint is the null handover member (a request without response encryption)", async () => {
  const handover = await openId4VpHandover("x509_san_dns:example.com", "n", "", "https://example.com/response");
  // ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, null, response_uri]))]
  // — the null is 0xf6 inside the digest input, not an absent member.
  assert.equal(handover[0], 0x82); // array(2)
  assert.equal(handover[1], 0x71); // text(17): "OpenID4VPHandover"
  assert.equal(handover[19], 0x58); // bytes(32): the digest's header
  assert.equal(handover[20], 0x20); // 32
  // array(2) + text(17) + 17 bytes + the digest's bytes(32) + 32.
  assert.equal(handover.length, 1 + 1 + 17 + 1 + 1 + 32);
});

// The stored metadata's seed: the ssc slot's opening, 16 bytes — the
// shape the realeyes issuer delivers (probe-pinned on the wire).
test("the seed extraction reads the ssc opening from the stored metadata", () => {
  const opening = "GLRK-vDrMBBi_DN9o9UC7Q"; // 16 bytes, base64url
  const metadata = {
    auxiliary_data: [
      {
        type: "hash_commitment",
        alg: "sha-256",
        path: ["eu.europa.ec.eudi.nym_auth.1", "ssc"],
        opening,
      },
    ],
  };
  const seed = secretSeedOf(metadata);
  assert.ok(seed instanceof Uint8Array);
  assert.equal(seed.length, 16);
  assert.equal(b64u(seed), opening);
});

test("the seed extraction fails closed on every other shape", () => {
  assert.equal(secretSeedOf(null), null);
  assert.equal(secretSeedOf({}), null);
  assert.equal(secretSeedOf({ auxiliary_data: [] }), null);
  // Two ssc slots: ambiguous, no seed.
  assert.equal(secretSeedOf({
    auxiliary_data: [
      { path: ["d", "ssc"], opening: "GLRK-vDrMBBi_DN9o9UC7Q" },
      { path: ["d", "ssc"], opening: "GLRK-vDrMBBi_DN9o9UC7Q" },
    ],
  }), null);
  // A non-ssc slot alone: nothing to open.
  assert.equal(secretSeedOf({ auxiliary_data: [{ path: ["d", "psc"], opening: "GLRK-vDrMBBi_DN9o9UC7Q" }] }), null);
  // Not 16 bytes: refused, never truncated into a proof.
  assert.equal(secretSeedOf({ auxiliary_data: [{ path: ["d", "ssc"], opening: "AAAA" }] }), null);
  // A foreign record (the issuer's display metadata, say): no seed.
  assert.equal(secretSeedOf({ display: [{ locale: "en-US", name: "Nym Attestation" }] }), null);
});
