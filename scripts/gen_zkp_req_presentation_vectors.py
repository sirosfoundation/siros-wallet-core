#!/usr/bin/env python3
"""Regenerates crates/siros-zkp-req-nym-auth/tests/vectors/presentation/.

The vectors of a ZkpPresentation in a JSON vp_token, at the nym_auth rulebook draft (commit
e65861c): zkp_req, Sections 4, 4.1 and 6.1, the backends' `Proof`, and the Section 3 `inputs`
and Section 9 codes of the Longfellow system. They port v0.11.0's v0.4 response vectors;
`v0_4` says what changed for a case.

Deterministic: running it twice yields byte-identical files. The CBOR is encoded here by hand
(shortest form, definite lengths) so the vectors do not depend on a CBOR library.

    python3 scripts/gen_zkp_req_presentation_vectors.py
"""
import base64
import json
import os

OUT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "crates", "siros-zkp-req-nym-auth", "tests", "vectors", "presentation",
)

# ---- CBOR (RFC 8949), minimal encoder ------------------------------------
def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 1 << 8: return bytes([major << 5 | 24, n])
    if n < 1 << 16: return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n < 1 << 32: return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    return bytes([major << 5 | 27]) + n.to_bytes(8, "big")
def uint(n): return head(0, n)
def bstr(b): return head(2, len(b)) + b
def tstr(s): return head(3, len(s.encode())) + s.encode()
def arr(items): return head(4, len(items)) + b"".join(items)
def mp(pairs): return head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
def tag(n, item): return head(6, n) + item
TRUE, FALSE, NULL = b"\xf5", b"\xf4", b"\xf6"
def tdate(s): return tag(0, tstr(s))

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

# ---- shared request ------------------------------------------------------
SYS = "urn:circuits:longfellow:nym_auth:v1"
BACKEND = "longfellow-libzk-v1"
PT = "2026-10-20T12:00:00Z"
ZK = bytes(range(64))
NYM = bytes(range(32))
# The Document Signer certificate of the nym_auth reference credential (zk-cred-vega 6bc2622,
# test-vectors/nymauth/nym-auth-mdoc.txt, x5chain): O=Test only, CN=nym_auth test issuer, P-256.
KEY = bytes.fromhex(
    "308201663082010da003020102020101300a06082a8648ce3d040302303331123010060355040a0c095465737420"
    "6f6e6c79311d301b06035504030c146e796d5f61757468207465737420697373756572301e170d32363031303130"
    "30303030305a170d3238303130313030303030305a303331123010060355040a0c0954657374206f6e6c79311d30"
    "1b06035504030c146e796d5f617574682074657374206973737565723059301306072a8648ce3d020106082a8648"
    "ce3d03010703420004b626aa933b215bc28f3b4924bf675454d2121f28bbb146415c181092f7fd9080bf77935765"
    "2d68be5ab61c667bde4ebff67b9efa2535c1138508fad656a2ab63a3123010300e0603551d0f0101ff0404030207"
    "80300a06082a8648ce3d040302034700304402204743cdab5ef1af88052b4d5ed17e59f537f6a99abf971027c93c"
    "a885d9126d8202206a9d9ad557fc91be72ab15cd31179808ec05723fbe09f743d6bf8055b23e1ff5")

PSEUDONYM = {"fn_id": "pseudonym", "return": "nym",
             "params": {"config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256"}}
AGE = {"fn_id": "age_check", "return": "age-range-123", "params": {"range": "13-17"}}

def query(items=None, **extra):
    q = {"id": "nym_attestation", "format": "zkp_req",
         "meta": {"source_format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.nym_auth.1"},
         "_req": items or [PSEUDONYM, AGE]}
    q.update(extra)
    return q

def cm(systems=(SYS,), backends=(BACKEND,)):
    return {"vp_formats_supported": {"zkp_req": {
        "proof_backend_values": list(backends), "system_id_values": list(systems)}}}

def results(nym=NYM, age=TRUE, order=("nym", "age-range-123"), extra=(), drop=(), nym_raw=None):
    vals = {"nym": bstr(nym) if nym_raw is None else nym_raw, "age-range-123": age}
    pairs = [(tstr(k), vals[k]) for k in order if k in vals and k not in drop]
    return mp(pairs + list(extra))

def proof(keys=None, proof_time="default", zk=None, omit=(), extra=(), raw=None):
    """`Proof = {"inputs": {issuer_key_set, proof_time}, "zk_proof": bstr}`."""
    inputs = {"issuer_key_set": arr([bstr(KEY)]) if keys is None else keys}
    if proof_time == "default": inputs["proof_time"] = tdate(PT)
    elif proof_time is not None: inputs["proof_time"] = proof_time
    pairs = [(tstr(k), v) for k, v in inputs.items() if k not in omit] + [(tstr(k), v) for k, v in extra]
    members = {"inputs": mp(pairs), "zk_proof": bstr(ZK) if zk is None else zk}
    for k, v in (raw or {}).items(): members[k] = v
    return mp([(tstr(k), v) for k, v in members.items() if k not in omit])

def pres(system_id=None, backend=None, req_set=None, pr=None, res=None, omit=(), extra=(), order=None):
    """Encode a ZkpPresentation; `pr` is the bytes of `proof` (a `Proof` by default)."""
    m = {
        "system_id": tstr(SYS) if system_id is None else system_id,
        "proof_backend": tstr(BACKEND) if backend is None else backend,
        "proof": bstr(proof()) if pr is None else pr,
        "results": results() if res is None else res,
    }
    if req_set is not None: m["req_set"] = req_set
    names = order or ["system_id", "proof_backend", "req_set", "proof", "results"]
    pairs = [(tstr(n), m[n]) for n in names if n in m and n not in omit]
    return mp(pairs + [(tstr(k), v) for k, v in extra])

def vp(*presentations, key="nym_attestation", **others):
    t = {key: [b64u(p) if isinstance(p, bytes) else p for p in presentations]}
    t.update(others)
    return t

VECTORS = {}
def add(name, desc, vp_token, q, client, text, change):
    v = {"description": desc, "query": q or query(), "client_metadata": cm() if client is None else client}
    if text is not None: v["vp_token_text"] = text
    else: v["vp_token"] = vp_token
    v["expect"] = {"valid": True}
    if change: v["v0_4"] = change
    VECTORS[name] = v
def ok(name, desc, vp_token=None, q=None, client=None, text=None, change=None):
    add("ok_" + name, desc, vp_token, q, client, text, change)
def err(name, code, desc, vp_token=None, q=None, client=None, text=None, change=None):
    add("err_" + name, desc, vp_token, q, client, text, change)
    VECTORS["err_" + name]["expect"] = {"error": code}

P = pres
CODE = "Same case; the code follows the draft."
INSIDE = "issuer_key_set and proof_time are inputs of `Proof`, inside `proof` (the backends' `Proof`)."
# ---- valid ---------------------------------------------------------------
ok("normative_both", "A pseudonym (32 bytes) and an age assertion with a handle; proof_time in the exact 20-byte form.", vp(P()),
   change="The draft shape: proof_backend, and `proof` holds `Proof` with the inputs.")
ok("pseudonym_only", "Only a pseudonym requested.", vp(P(res=results(drop=("age-range-123",)))), q=query(items=[PSEUDONYM]))
ok("results_order_irrelevant", "Result keys in any order.", vp(P(res=results(order=("age-range-123", "nym")))))
ok("member_order_irrelevant", "Presentation members in any order (CBOR map order carries no meaning).",
   vp(P(order=["results", "proof", "proof_backend", "system_id"])))
ok("two_presentations", "multiple: true allows more than one presentation; each is checked.", vp(P(), P()), q=query(multiple=True))
ok("other_query_ids_ignored", "Entries for other credential queries are not looked at.", vp(P(), other=["garbage"]))
ok("issuer_key_set_single", "One certificate: the set of a system whose circuit takes one issuer key.", vp(P()))
ok("assertion_without_handle", "An age_check without return is an assertion: results holds only the pseudonym (Section 3).",
   vp(P(res=results(drop=("age-range-123",)))), q=query(items=[PSEUDONYM, {"fn_id": "age_check", "params": {"range": "13-17"}}]))
ok("req_set_first_option", "With _req_sets, req_set names the answered option (Section 2.1).",
   vp(P(req_set=uint(0))), q=query(_req_sets=[[0, 1], [0]]))
ok("req_set_second_option", "The second option: only its handles (Section 3).",
   vp(P(req_set=uint(1), res=results(drop=("age-range-123",)))), q=query(_req_sets=[[0, 1], [0]]))
for name, text in [("epoch", "1970-01-01T00:00:00Z"), ("leap_day", "2024-02-29T23:59:59Z"),
                   ("year_end", "2026-12-31T23:59:59Z"), ("max", "9999-12-31T23:59:59Z"),
                   ("century_non_leap", "2100-02-28T00:00:00Z")]:
    ok("proof_time_" + name, f"proof_time {text} has the exact form; the tolerance is the Verifier's clock's.",
       vp(P(pr=bstr(proof(proof_time=tdate(text))))), change=INSIDE)

# ---- envelope --------------------------------------------------------------
err("not_json", "response_not_object", "vp_token is not JSON.", text="{not json", change=CODE)
err("not_object", "response_not_object", "vp_token is a JSON array.", text="[]", change=CODE)
err("null_vp_token", "response_not_object", "vp_token is JSON null.", text="null", change=CODE)
err("duplicate_member", "duplicate_member", "The vp_token object repeats a member name (raw text: a parsed object cannot hold it).",
    text='{"nym_attestation":["AA"],"nym_attestation":["AA"]}')
err("query_id_missing", "query_id_missing", "No entry for the query id.", vp(P(), key="other"))
err("presentations_not_array", "presentations_not_array", "The entry is an object.", {"nym_attestation": {}})
err("null_query_entry", "presentations_not_array", "The entry is null: a type error, not absence.", {"nym_attestation": None})
err("presentations_empty", "presentations_empty", "An empty array.", {"nym_attestation": []})
err("multiple_not_allowed", "presentations_multiple_not_allowed", "Two presentations without multiple: true.", vp(P(), P()))
err("multiple_false", "presentations_multiple_not_allowed", "Two presentations with multiple: false.", vp(P(), P()), q=query(multiple=False))
err("second_presentation_bad", "result_keys", "Every presentation is checked, not only the first.",
    vp(P(), P(res=results(drop=("age-range-123",)))), q=query(multiple=True),
    change="Section 4.1, step 4: one rule for the keys of results (v0.4: result_handle_missing).")
err("presentation_not_string", "presentation_not_string", "An element is a number.", {"nym_attestation": [1]})
err("presentation_object", "presentation_not_string", "An element is a JSON object (the pre-v0.4 JSON presentation).",
    {"nym_attestation": [{"circuit_id": SYS}]})
err("null_presentation", "presentation_not_string", "An element is JSON null.", {"nym_attestation": [None]})
good = b64u(P())
err("presentation_padded", "presentation_not_base64url", "Padding is not allowed.", {"nym_attestation": [good + "=" * (-len(good) % 4) if len(good) % 4 else good + "="]})
err("presentation_standard_alphabet", "presentation_not_base64url", "Standard alphabet: '+' or '/' instead of '-' or '_'.",
    {"nym_attestation": [good[:10] + "+" + good[11:]]})
err("presentation_whitespace", "presentation_not_base64url", "Embedded whitespace.", {"nym_attestation": [good[:8] + " " + good[8:]]})
def noncanonical():
    for extra in range(0, 4):
        s = b64u(P(pr=bstr(proof(zk=bstr(ZK + bytes(extra))))))
        if len(s) % 4 in (2, 3):
            alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            i = alpha.index(s[-1])
            return s[:-1] + alpha[i | 1]
err("presentation_noncanonical_final_char", "presentation_not_base64url", "Non-zero trailing bits in the last character.", {"nym_attestation": [noncanonical()]})

# ---- CBOR -----------------------------------------------------------------
def raw_err(name, code, desc, data, change=None):
    err(name, code, desc, {"nym_attestation": [b64u(data)]}, change=change)
whole = P()
STRICT = "The reader's own codes: indefinite lengths, reserved values and stray breaks are `cbor_unsupported`; v0.4 grouped them differently."
raw_err("cbor_empty", "cbor_truncated", "Zero bytes.", b"", change=STRICT)
raw_err("cbor_truncated", "cbor_truncated", "The map is cut off.", whole[:-3], change=STRICT)
raw_err("cbor_reserved_info", "cbor_unsupported", "Additional information 28 is reserved.", b"\x1c", change=STRICT)
raw_err("cbor_invalid_utf8", "cbor_invalid_utf8", "A text-string key that is not UTF-8.", head(5, 1) + head(3, 2) + b"\xff\xfe" + TRUE, change=STRICT)
raw_err("cbor_impossible_length", "cbor_truncated", "An array claims 2^32 elements; refused without allocating.", b"\x9a\xff\xff\xff\xff", change=STRICT)
raw_err("cbor_too_deep", "cbor_too_deep", "Thirty-three levels of nesting, one past the reader's limit of 32.", b"\x81" * 33 + b"\x00",
        change="The reader's limit is 32 levels (v0.4: 16).")
raw_err("cbor_break_outside", "cbor_unsupported", "A stray break byte.", b"\xff", change=STRICT)
raw_err("cbor_indefinite_map", "cbor_unsupported", "An indefinite-length map (0xbf ... 0xff).",
        b"\xbf" + tstr("system_id") + tstr(SYS) + b"\xff", change=STRICT)
raw_err("cbor_indefinite_array", "cbor_unsupported", "results as an indefinite-length map.",
        P(res=b"\xbf" + tstr("nym") + bstr(NYM) + b"\xff"), change=STRICT)
raw_err("cbor_indefinite_bstr", "cbor_unsupported", "proof as an indefinite-length byte string.",
        P(pr=b"\x5f" + bstr(ZK[:16]) + bstr(ZK[16:]) + b"\xff"), change=STRICT)
raw_err("cbor_indefinite_tstr", "cbor_unsupported", "A result handle as an indefinite-length text string.",
        P(res=mp([(b"\x7f" + tstr("nym") + tstr("") + b"\xff", bstr(NYM)), (tstr("age-range-123"), TRUE)])), change=STRICT)
raw_err("cbor_trailing_bytes", "cbor_trailing_bytes", "One extra byte after the map.", whole + b"\x00")
raw_err("cbor_two_items", "cbor_trailing_bytes", "Two concatenated presentations.", whole + whole)
raw_err("cbor_duplicate_member", "cbor_duplicate_key", "The presentation map repeats `proof`.",
        mp([(tstr("system_id"), tstr(SYS)), (tstr("proof_backend"), tstr(BACKEND)), (tstr("proof"), bstr(proof())),
            (tstr("proof"), bstr(proof())), (tstr("results"), results())]))
raw_err("cbor_duplicate_handle", "cbor_duplicate_key", "results repeats a handle.",
        P(res=mp([(tstr("nym"), bstr(NYM)), (tstr("nym"), bstr(NYM)), (tstr("age-range-123"), TRUE)])))
raw_err("cbor_duplicate_key_same_value_different_form", "cbor_duplicate_key", "A repeated key is refused even when both values are identical.",
        P(res=mp([(tstr("age-range-123"), TRUE), (tstr("age-range-123"), TRUE), (tstr("nym"), bstr(NYM))])))

# ---- presentation shape -----------------------------------------------------
raw_err("presentation_array", "presentation_not_map", "The presentation is a CBOR array.", arr([tstr(SYS)]))
raw_err("presentation_text", "presentation_not_map", "The presentation is a text string.", tstr("x"))
raw_err("presentation_null", "presentation_not_map", "The presentation is CBOR null.", NULL)
KEY_NOT_TEXT = "A key that is not text names no member of Section 4 (v0.4: presentation_key_not_text)."
raw_err("presentation_key_uint", "presentation_unknown_member", "A presentation key is an integer.", mp([(uint(1), tstr(SYS))]), change=KEY_NOT_TEXT)
raw_err("presentation_key_bytes", "presentation_unknown_member", "A presentation key is a byte string.", mp([(bstr(b"system_id"), tstr(SYS))]), change=KEY_NOT_TEXT)
for legacy in ("proof_system", "x5chain", "circuit_id", "error", "error_description", "extra"):
    err("unknown_member_" + legacy, "presentation_unknown_member",
        f"A member `{legacy}` outside the members of Section 4.", vp(P(extra=[(legacy, tstr("x"))])))
for legacy, value in (("issuer_key_set", arr([bstr(KEY)])), ("proof_time", tdate(PT))):
    err("unknown_member_" + legacy, "presentation_unknown_member",
        f"The v0.4 member `{legacy}` at the top level.", vp(P(extra=[(legacy, value)])), change=INSIDE)
for m in ("system_id", "proof_backend", "proof", "results"):
    err("member_missing_" + m, "presentation_member_missing", f"`{m}` absent.", vp(P(omit=(m,))),
        change="proof_backend is a member (Section 4)." if m == "proof_backend" else None)
err("wrong_type_system_id", "presentation_member_wrong_type", "system_id is a byte string.", vp(P(system_id=bstr(SYS.encode()))))
err("wrong_type_proof_backend", "presentation_member_wrong_type", "proof_backend is an integer.", vp(P(backend=uint(1))))
err("wrong_type_proof_text", "presentation_member_wrong_type", "proof is a text string.", vp(P(pr=tstr("proof"))))
err("wrong_type_results_array", "presentation_member_wrong_type", "results is an array.", vp(P(res=arr([]))))
err("wrong_type_req_set_text", "presentation_member_wrong_type", "req_set is a text string.", vp(P(req_set=tstr("0"))), q=query(_req_sets=[[0, 1]]))
err("null_system_id", "presentation_member_wrong_type", "system_id is CBOR null: wrong type, not absent.", vp(P(system_id=NULL)))
err("null_proof", "presentation_member_wrong_type", "proof is CBOR null.", vp(P(pr=NULL)))
err("null_results", "presentation_member_wrong_type", "results is CBOR null.", vp(P(res=NULL)))
err("result_key_not_text", "presentation_member_wrong_type", "A results key is an integer.",
    vp(P(res=mp([(uint(1), bstr(NYM)), (tstr("age-range-123"), TRUE)]))),
    change="results is `{ * tstr => any }`: a key of another type is a wrong type (v0.4: result_key_not_text).")

# ---- Section 4.1, steps 1 to 5 -------------------------------------------------
err("system_id_not_offered", "system_not_listed", "system_id is not in system_id_values (step 1).", vp(P(system_id=tstr("urn:circuits:other:v1"))), change=CODE)
err("proof_backend_not_offered", "backend_not_listed", "proof_backend is not in proof_backend_values (step 1).", vp(P(backend=tstr("vega-v1"))))
err("system_not_on_backend", "system_not_on_backend", "Longfellow does not run on vega-v1 (step 2).",
    vp(P(backend=tstr("vega-v1"))), client=cm(backends=(BACKEND, "vega-v1")))
err("system_id_no_offer_list", "request", "The request stated no system_id_values: the Verifier's own request is invalid (Section 1.2).",
    vp(P()), client={}, change="Section 1.2 requires both lists (v0.4: system_id_not_offered).")
err("system_id_empty_offer_list", "request", "An empty system_id_values: the Verifier's own request is invalid (Section 1.2).",
    vp(P()), client=cm(()), change="Section 1.2 requires non-empty lists (v0.4: system_id_not_offered).")
err("req_set_missing", "req_set_missing", "The query has _req_sets and the presentation no req_set (step 3).",
    vp(P()), q=query(_req_sets=[[0, 1], [0]]))
err("req_set_extra", "req_set_extra", "The query has no _req_sets and the presentation a req_set (step 3).", vp(P(req_set=uint(0))))
err("req_set_unknown", "req_set_unknown", "req_set names no option (step 3).", vp(P(req_set=uint(2))), q=query(_req_sets=[[0, 1], [0]]))
KEYS = "Section 4.1, step 4: one rule for the keys of results."
err("result_handle_unexpected", "result_keys", "A handle the request did not return.", vp(P(res=results(extra=[(tstr("extra"), TRUE)]))),
    change=KEYS + " (v0.4: result_handle_unexpected)")
err("result_handle_missing", "result_keys", "A returned handle has no result.", vp(P(res=results(drop=("age-range-123",)))),
    change=KEYS + " (v0.4: result_handle_missing)")
err("result_empty", "result_keys", "results is an empty map for an option with handles.", vp(P(res=mp([]))),
    change=KEYS + " (v0.4: result_handle_missing)")
err("result_of_other_function", "result_keys", "Results keyed by the function id instead of the handle.",
    vp(P(res=mp([(tstr("pseudonym"), bstr(NYM)), (tstr("age_check"), TRUE)]))), change=KEYS + " (v0.4: result_handle_unexpected)")
err("result_of_other_option", "result_keys", "req_set 1 answers the pseudonym alone: the age handle is extra.",
    vp(P(req_set=uint(1))), q=query(_req_sets=[[0, 1], [0]]))
NOT_TRUE = "Section 4.1, step 5: a function without a result gives true."
for name, value, why in [("uint", uint(1), "1"), ("text", tstr("true"), "the text \"true\""), ("null", NULL, "CBOR null"),
                         ("object", mp([(tstr("satisfied"), TRUE)]), "the pre-v0.4 shape {\"satisfied\": true}"),
                         ("false", FALSE, "false")]:
    err("predicate_" + name, "result_not_true", f"An age_check result of {why}.", vp(P(res=results(age=value))),
        change=NOT_TRUE + " (v0.4: " + ("result_not_satisfied" if name == "false" else "result_wrong_type") + ")")

# ---- the backends' Proof and the system's inputs (Section 3) ---------------------
ENC = "`proof` is `bstr .cbor Proof`; a broken `Proof` or `inputs` is proof_encoding (Section 9)."
err("proof_empty", "proof_encoding", "proof is a zero-length byte string: no `Proof`.", vp(P(pr=bstr(b""))), change=ENC + " (v0.4: proof_empty)")
err("proof_not_cbor", "proof_encoding", "proof holds bytes that are not CBOR.", vp(P(pr=bstr(b"\xff\xff"))))
err("proof_inputs_missing", "proof_encoding", "`Proof` without inputs.", vp(P(pr=bstr(proof(omit=("inputs",))))))
err("proof_zk_proof_missing", "proof_encoding", "`Proof` without zk_proof.", vp(P(pr=bstr(proof(omit=("zk_proof",))))))
err("proof_unknown_member", "proof_encoding", "`Proof` with a third member.", vp(P(pr=bstr(proof(raw={"extra": TRUE})))))
err("proof_trailing_bytes", "proof_encoding", "Bytes after `Proof`.", vp(P(pr=bstr(proof() + b"\x00"))))
err("inputs_unknown", "proof_encoding", "inputs with a value the rulebook does not name.", vp(P(pr=bstr(proof(extra=[("x5chain", TRUE)])))))
err("zk_proof_over_1_mib", "proof_encoding", "zk_proof over 1 MiB (the backend's limit).", vp(P(pr=bstr(proof(zk=bstr(bytes(1 << 20 | 1)))))))
err("issuer_key_set_missing", "proof_encoding", "inputs without issuer_key_set.", vp(P(pr=bstr(proof(omit=("issuer_key_set",))))), change=INSIDE)
err("issuer_key_set_empty", "issuer_key_set", "issuer_key_set is an empty array: zero certificates.", vp(P(pr=bstr(proof(keys=arr([]))))),
    change=INSIDE + " Exactly one certificate (Section 3; v0.4: issuer_key_set_empty).")
err("issuer_key_set_two", "issuer_key_set", "Two certificates: the system takes exactly one.", vp(P(pr=bstr(proof(keys=arr([bstr(KEY), bstr(KEY)]))))),
    change=INSIDE + " Exactly one certificate (Section 3; v0.4 allowed eight).")
err("issuer_key_set_too_many", "issuer_key_set", "Nine certificates.", vp(P(pr=bstr(proof(keys=arr([bstr(KEY)] * 9))))),
    change=INSIDE + " Exactly one certificate (v0.4: issuer_key_set_too_many).")
err("issuer_key_not_bytes", "proof_encoding", "An element is a text string (a base64 certificate, as in the pre-v0.4 x5chain).",
    vp(P(pr=bstr(proof(keys=arr([tstr("MIIB")]))))), change=INSIDE + " `[ bstr ]` (v0.4: issuer_key_not_bytes).")
err("issuer_key_null", "proof_encoding", "An element is CBOR null.", vp(P(pr=bstr(proof(keys=arr([NULL]))))), change=INSIDE)
err("issuer_key_set_bstr", "proof_encoding", "issuer_key_set is a single byte string, not an array.", vp(P(pr=bstr(proof(keys=bstr(KEY))))), change=INSIDE)
err("issuer_key_set_map", "proof_encoding", "issuer_key_set is a map.", vp(P(pr=bstr(proof(keys=mp([]))))), change=INSIDE)
err("issuer_key_empty", "issuer_key_set", "A zero-length certificate is no DER certificate.", vp(P(pr=bstr(proof(keys=arr([bstr(b"")]))))),
    change=INSIDE + " The certificate is parsed (Section 6; v0.4: issuer_key_empty).")
err("issuer_key_not_certificate", "issuer_key_set", "A byte string that is no DER certificate.", vp(P(pr=bstr(proof(keys=arr([bstr(b"\x30" * 4097)]))))),
    change=INSIDE + " The certificate is parsed (Section 6; v0.4: issuer_key_too_large).")
err("proof_time_missing", "proof_encoding", "inputs without proof_time: the Longfellow system names it.", vp(P(pr=bstr(proof(proof_time=None)))),
    change=INSIDE + " (v0.4: proof_time_missing)")
for name, value, why in [("plain_text", tstr(PT), "a text string without tag 0"),
                         ("epoch_tag", tag(1, uint(1760961600)), "tag 1 (epoch time)"),
                         ("tag0_bytes", tag(0, bstr(PT.encode())), "tag 0 around a byte string"),
                         ("plain_uint", uint(1760961600), "an integer"),
                         ("null", NULL, "CBOR null")]:
    err("proof_time_" + name, "proof_encoding", f"proof_time is {why}: no tdate.", vp(P(pr=bstr(proof(proof_time=value)))),
        change=INSIDE + " A wrong CBOR type breaks Section 3 (v0.4: proof_time_not_tdate).")
for name, text, why in [
    ("fraction", "2026-10-20T12:00:00.000Z", "fractional seconds"),
    ("offset", "2026-10-20T12:00:00+00:00", "a numeric offset instead of Z"),
    ("lowercase_z", "2026-10-20T12:00:00z", "a lowercase z"),
    ("lowercase_t", "2026-10-20t12:00:00Z", "a lowercase t"),
    ("space", "2026-10-20 12:00:00Z", "a space instead of T"),
    ("no_seconds", "2026-10-20T12:00Z", "no seconds"),
    ("date_only", "2026-10-20", "a date without a time"),
    ("short_year", "26-10-20T12:00:00Z", "a two-digit year"),
    ("month_13", "2026-13-20T12:00:00Z", "month 13"),
    ("not_leap_day", "2026-02-29T12:00:00Z", "29 February in a common year"),
    ("century_not_leap", "2100-02-29T00:00:00Z", "29 February 2100"),
    ("hour_24", "2026-10-20T24:00:00Z", "hour 24"),
    ("second_60", "2026-10-20T23:59:60Z", "a leap second"),
    ("trailing_space", "2026-10-20T12:00:00Z ", "a trailing space"),
    ("empty", "", "an empty string"),
    ("non_ascii_digit", "2026-10-20T12:00:0٠Z", "a non-ASCII digit"),
]:
    err("proof_time_" + name, "proof_time", f"proof_time is a tdate but not exactly YYYY-MM-DDThh:mm:ssZ: {why}.",
        vp(P(pr=bstr(proof(proof_time=tdate(text))))), change=INSIDE + " Malformed is the `proof_time` code (v0.4: proof_time_form).")

# ---- results types (Section 9: results) and the Verifier's own request -----------
for n in (0, 16, 31, 33, 48, 64):
    err(f"pseudonym_length_{n}", "results", f"A {n}-byte pseudonym where prf sha-256 sets 32.", vp(P(res=results(nym=bytes(n)))),
        change="The `results` code of Section 9 (v0.4: pseudonym_wrong_length).")
for name, value in (("text", tstr(NYM.hex())), ("null", NULL), ("true", TRUE)):
    err("pseudonym_" + name, "results", f"A pseudonym of {name}.", vp(P(res=results(nym_raw=value))),
        change="The `results` code of Section 9 (v0.4: result_wrong_type).")
err("result_function_unknown", "request", "The Verifier's own query has a function the catalogue does not define: its request is invalid.",
    vp(P(res=mp([(tstr("x"), TRUE)]))), q=query(items=[{"fn_id": "no-such-fn", "return": "x"}]),
    change="An unknown fn_id makes the query invalid (v0.4: result_function_unknown).")
err("pseudonym_prf_missing", "request", "The Verifier's own pseudonym item has no ver and prf: its request is invalid.",
    vp(P(res=results(drop=("age-range-123",)))), q=query(items=[{"fn_id": "pseudonym", "return": "nym", "params": {"config": "known-offender-matching-ssc"}}]),
    change="ver and prf are REQUIRED (v0.4: pseudonym_prf_unknown).")
err("age_check_only_unsupported", "request", "The Verifier's own option has no pseudonym: the Longfellow system answers unsupported (Section 2).",
    vp(P(res=results(drop=("nym",)))), q=query(items=[AGE]),
    change="The system rulebook's Section 2 requires a pseudonym item (v0.4: accepted).")

# ---- order: Section 4.1 numbers its steps ---------------------------------------------
ORDER = "The draft orders Section 4.1's steps; other orders of v0.4 are not the draft's and are gone."
err("order_listed_before_req_set", "system_not_listed", "An unlisted system and a missing req_set: step 1 first.",
    vp(P(system_id=tstr("urn:other"))), q=query(_req_sets=[[0, 1]]), change=ORDER)
err("order_req_set_before_results", "req_set_unknown", "An unknown req_set and wrong results keys: step 3 first.",
    vp(P(req_set=uint(5), res=mp([]))), q=query(_req_sets=[[0, 1]]), change=ORDER)
err("order_keys_before_values", "result_keys", "A missing handle and a value other than true: step 4 first.",
    vp(P(res=mp([(tstr("age-range-123"), FALSE)]))), change=ORDER)
err("order_envelope_before_presentation", "presentations_multiple_not_allowed",
    "Two presentations, both malformed: the count is refused before either is read.", {"nym_attestation": [b64u(b""), b64u(b"")]})

# ---- write ------------------------------------------------------------------------------
os.makedirs(OUT, exist_ok=True)
for f in os.listdir(OUT):
    if f.endswith(".json"): os.remove(os.path.join(OUT, f))
for name in sorted(VECTORS):
    v = VECTORS[name]
    with open(os.path.join(OUT, name + ".json"), "w") as fh:
        json.dump(v, fh, indent=2, ensure_ascii=False); fh.write("\n")
print(len(VECTORS), "vectors")
