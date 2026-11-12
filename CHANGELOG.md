# Changelog

All notable changes to this workspace. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `siros-ts12` serves TS12's `urn:eudi:sca:payment:1` and
  `urn:eudi:sca:login_risk_transaction:1`: `Ts12Document::compose` at registration, the typed
  payloads, T1 to T6, `Profile::reserves`, the rendering through siros-paso's engine under TS12's
  label limits, and the Key Binding JWT's `jti`, `response_mode`, `amr` and hashes.
- `siros-ts12` types each member and argument: `FieldPath`, `Expected`, `DateForm` and `MaxChars`
  in `PayloadRefusal`; `TransactionType` and `QueryId` in `Ts12Rule` and `Ts12Unsupported`;
  `Ts12Unsupported::{NoSchema, SchemaForm, ClaimsForm, NoClaimPath, ClaimPath, Level, ClaimLabels,
  CatalogueForm, UiLabels}` per rule; `ComposeError::{UriForm, Unfetched}` per rule; `DocumentKey` in
  `DOCUMENT`; `FetchedDocument`, `ComposedDocument`, `Category` and `TwinnedMember` in the document;
  `Keyed<HttpsUrl, Fetch>` in `with_resources`; `AmrMethod`; `Ts12Finding { url, failure }`.
  `TypeEntry::built_in` parses a type's metadata once, and `paso_metadata` returns an `Object`.
  `mit_options.apr` is an exact decimal within 38 digits, `Expected::Decimal` refusing the rest.
  `register` returns the `ProfileHandle`.
- `checked!` takes a type with a destructor; `DocumentKey::new` and `TypePrefix::new` are `const`.
- `siros-integration` holds the WE BUILD build beside HAIP's: `x509_hash` alone,
  `DcApiProtocols::SIGNED`, siros-paso and siros-ts12, CS-02's rules, a host without `CoseEncrypt`
  or `DeviceMac`, over F11 and F12.
- `siros-paso` opens `render::Request`, `Registered`, `LabelLimits` and `bound` to a second profile.
  `render::Request` and `image::resolve` take the image resolver as `&dyn Fn(&str) -> Resolution`,
  so every profile shares one render engine.
- `Profile::reserves`: a credential a profile reserves answers only a query its own entries name.
- `cargo xtask layout` reads the sources' syntax trees and refuses test code under `src/`, a
  message source outside a crate's `tests/` and siros-testkit, and, in the shipped crates, an error
  without `Explain`, a statement that implements `Display` and a statement field given a string
  literal, a `format!` included.
- `cargo xtask layout` refuses, under `feature = "test-util"`, an inherent `impl`
  of a type outside the gate, any item that makes a value of a type with private
  fields, and a free `pub fn`, a `pub const` or a `pub static`, and refuses the
  gate on anything but a whole item. The types the gate declares are the
  doubles'.
- `siros-testkit`'s `x509` holds the test certificates and chains; `siros-x509`
  has no `test-util` feature.
- A refusal's message and a claim's display name a received number as written.
- The JSON writer writes RFC 8259 text: a number goes out as received, so `1e400`
  stays `1e400` in a response, a wallet metadata text and a metadata digest's input.
- A PaSO rule's `path`, `claim`, `field` and `member` arguments name a claim path as
  its JSON array: `null` for a wildcard, an index beyond `usize` by its digits.
- `siros-openid4vp`'s `text::DisplayText` refuses the characters of Unicode's
  General Categories Cc, Cf, Zl, Zp, Co and Cn and text over `LABEL_MAX`,
  `VALUE_MAX`, `TEMPLATE_MAX` or `CARD_TEXT_MAX`. The claims kit reads every
  metadata text through it, in every language; a text it refuses excludes the
  credential for the query (`FormatQuery::displayable`, `ExcludedBy::Display`).
  A label or a card text with no visible character, one that is neither
  White_Space nor Default_Ignorable_Code_Point (`DisplayText::visible`), is
  `TextError::Empty`, and the kit takes its fallback.
- `siros-openid4vp`'s `claims::kit::merge_metadata` writes a credential's view
  `metadata` from the format's display document and `IssuedMetadata`: the
  format's entries first, OpenID4VCI's `credential_metadata` per language after
  them, `auxiliary_data` left out at every depth of every input. Both claims
  formats' registration calls it over their `Resolved`'s `issued`, and
  `RegistrationError::Metadata` holds the `MergeError`.
- A card's subtitle is the name of the Credential Issuer's display entry
  (`IssuedMetadata::issuer_display`, the view's `issuer_display`), else the
  view's `issuer`. A text there is read through `DisplayText`.
- A byte string shows by its length: `ClaimText::Bytes`, over the mdoc view's
  `byte_strings`.
- General categories come from `icu_properties`, in place of
  `unicode-general-category`: Unicode 18 in place of 16, so a text may show the 17,810 code points
  assigned since.
- An mdoc's `full-date` (tag 1004) and `tdate` (tag 0) elements show as
  `ClaimText::Date` and `ClaimText::DateTime`, over the view's `dates`.
  `RegistrationError::FullDate` and `Tdate` refuse a value that siros-syntax's
  `Date::parse` or `DateTime::parse` refuses. An MSO's `validityInfo` refuses a
  `+` in a number of its times.
- `siros-wallet-state` chooses a batch's instance (`WalletState::least_used`,
  C5). `Built::used` and `Built::audience` give the app what it fills a
  `PresentationRecord` with, beside the `vp_token`.
- `siros-trust` writes the core's `Facts` from an issuer chain and the trust
  store (`IssuerFacts`): `aki` with the chain's keyIdentifiers in base64url, and
  each admitting store type with its values. The admission rule is the core's
  `Facts::admits`, which the matcher, phase 2 and `AdmittedIssuer::resolve` run.
- The presentation core: `siros-openid4vp`, `siros-x509`, `siros-mdoc`,
  `siros-sdjwt`, `siros-paso`, `siros-qes`, `siros-testkit`, `siros-explain`,
  `siros-explain-derive`, `siros-i18n`, `siros-cldr` and `siros-integration`,
  from the design's reference implementation, and `siros-syntax`,
  `siros-i18n-derive` and `siros-derive-internals`. Each is edition 2024 and
  unpublished. `siros-mdoc` and `siros-sdjwt` replace the earlier crates of
  those names.
- `siros-explain` is the error contract: `Explain` gives an error's stable id,
  `err.<scope>.<id>`, and each named argument by its key: the field, which a
  reader takes by its type or by its `Display`.
  `#[derive(Explain)]` sits beside thiserror's derive: each struct or variant
  carries `#[explain(id = "…")]` or `#[error(transparent)]`, a named field is an
  argument, a cause is `#[source]` or `#[explain(skip)]`, a tuple argument and a
  field spelled `r#source` are refused, and an id given twice in a crate fails
  the build. `scope!` names a crate's scope once, at its root. A plug-in's error
  crosses the core as `Box<dyn Explain>`, and a contract breach is a
  `Fault(Box<dyn Explain>)` over the crate's own fault error.
- `siros-syntax` holds the checked texts and values: `checked!`, `Keyed` with
  `Entry` and `Repeated`, the non-empty `AllOf`, and `Count`, `Decimal`,
  `Amount`, `Currency` with ISO 4217 List One (SIX's `list-one.xml`, published
  2026-09-17, vendored and read by the build script), `Date`, `Time`,
  `OffsetTime`, `Offset` and `DateTime`. Each value type writes its literal form
  as `Display` and parses exactly that form, refusing any other text with
  `Malformed`. `Digits`, one or more ASCII digits as written, give their count
  through `Count::from`.
- `siros-i18n` resolves the wallet's texts. A `Context` holds the
  MessageFormat 2 sources of one locale, each loaded whole and checked
  (`LoadError`); `Context::resolve` makes a `Text`, styled spans, from an error
  or a statement (`ResolveError`), and no other code makes one. A statement
  derives `Message` (`siros-i18n-derive`). Every argument is text: `:string`
  writes it as given; `:number` and `:integer` parse an MF2 number literal and
  show its fraction digits as written; `:offset`, `:currency` (its `currency`
  option literal or variable), `:percent`, `:siros:date`, `:siros:time` and
  `:siros:datetime` parse their operand. An option's value is a literal or a
  variable's value: an argument's text, a literal, or the value of a declared
  call. `u:dir` takes `ltr`, `rtl`, `auto` or `inherit`; another value from a
  variable refuses the resolution (`ResolveError::Option`). A load takes
  memory in proportion to its source, and time in proportion to its source and,
  for each use of a call, to the calls its operand's value applies. Each
  function sits behind its
  feature: `number`, `currency`, `offset` and `date`, the defaults with `derive`
  and `nfc`. `nfc` holds names, variant keys and selector literals in NFC, as
  MF2 compares them, and adds `Context::module_in_nfc`, which refuses a source NFC
  would change (`LoadError::Unnormalized`); without it they stay as written.
  `check` holds `Context::check`, and `conformance` MF2's test functions for
  siros-i18n's conformance tests. `escape` writes a resource value that resolves
  to a given text, and `Context::bidi` takes the app's bidi strategy.
- siros-i18n's `check` feature is the wallet's one completeness test: each
  derive registers its id and argument names, and `Context::check` refuses an
  id two crates share, an id no source words and a message that names an
  argument its row lacks.
- `siros-i18n-derive`: `#[derive(Message)]` on a statement, its id under the crate's scope and
  its named fields as arguments. A repeated id fails the build; under `check` each id registers a
  row for `Context::check`.
- `siros-derive-internals`: the field rules `#[derive(Explain)]` and `#[derive(Message)]` share,
  which siros-explain-derive and siros-i18n-derive call through its `Derive` trait.
- `siros-mdoc::stored` reads a stored mdoc: its items against the MSO's
  digests, the MSO, `issuerAuth`, and the data the device key signs.
  ISO/IEC 18013-5 Annex D's DeviceResponse is its known answer, and each
  construction rule refuses its fixture.
- `siros-sdjwt`'s `Registered` reads an issued SD-JWT (RFC 9901 §7.1) into
  the `dc+sd-jwt` document and its view: the processed payload at its issued
  array positions, the issuer's and holder key's algorithms and curves, and
  `validity`, each number as the issuer wrote it. It holds SD-JWT VC's rules:
  `typ` is `dc+sd-jwt`, no disclosure reveals a registered claim, `cnf` is a
  `jwk` of its curve. `Registered::holder` gives `Facts::holder`. Phase 2
  presents from the document: the option's disclosures with their parents and
  descendants, and a compact Key Binding JWT whose `sd_hash` covers the SD-JWT
  as sent; `PresentFault` is a presentation fault's source. RFC 9901 A.1 to A.4
  and §5 are its known answers.
- A credential's display metadata, SD-JWT VC Type Metadata's `display` and
  `claims[].display` and OpenID4VCI's claims display, shows as written: the
  claims kit picks the entry by `Env.priority` (`format_entry`) and shows its
  text through `ClaimText::Label`.
- `ClaimsFormat::withheld` names an array element that holds no value, which a
  claims path walks past at its issued position.
- `siros-mdoc::registration` builds the view from a stored mdoc, with
  `validityInfo`. ISO/IEC 18013-5 Annex D is its known answer.
- `siros-credman` lays out the core's consent entries as Android Credential
  Manager's Standard and Payment entries, and decides each set's delegation:
  `Full` when the set needs no wallet display (A9, K4). `siros-openid4vp`
  composes the consent entry as platform-neutral data (`consent`), its
  transaction header filled by the profile.
- `siros-credman` holds the registration, versioned, seekable and read lazily: a header, a directory
  of entries each checked against the blob's size, then the entries: the locale it was written in,
  the End-User's ranked locale tags, the wallet's bidi choice, the wallet's sources for the matcher,
  formats first, and each registered transaction type's converted View source. `Base::load` loads
  the base sources into one context in that locale. Under `register`, which turns on siros-i18n's
  `nfc`, `register::write` takes a `Base`, loads its sources again, then each transaction source
  into a clone of its context and all of them into one clone, each through `Context::module_in_nfc`,
  before it writes. It refuses a base source (`RegisterError::Source`) or a transaction source
  (`RegisterError::Transaction`) whose names, variant keys or selector literals NFC would change, so
  a matcher built without `nfc` resolves the registration to the wallet's texts.
  `Registration::open` reads the header, the directory and the base; `Registration::context` loads
  the sources of the types a request names into a clone of the base's context and reads no other
  entry. The writer and `Registration::context` load a source byte-equal to an earlier type's once:
  types whose metadata is one object share one converted source. The wallet registers again when
  its language changes.
- `siros-credman::emit` is the matcher's entry emission: every choice of a display as Credential
  Manager draws it, each text resolved through the registration's context. It fails as a whole on
  the first choice that does not emit (`NotEmitted`, naming the entry and holding the cause). A
  field name needs a visible character (`NoName`). A field's text is cut at the longest
  extended-grapheme-cluster boundary that keeps the text, a closer for each bidi isolate or
  embedding the cut leaves open, and the ellipsis within 80 characters (`FIELD_MAX`).
- `siros-webuild` holds WE BUILD's CS-02 rules: `Cs02Claims` requires a
  Request Object's `exp` and `aud` (CS-02 §8.2), `Cs02ErrorAnswer` reads the
  Verifier's error answer from the Response URI (CS-02 §8.3).
- `siros-openid4vp`'s extension points, each implemented by the core's own
  cases as peers: response types and response modes (`ResponseType`, `Mode`,
  `ModeHost`; `vp_token` and the modes `dc_api`, `dc_api.jwt`,
  `direct_post.jwt`, `direct_post`), transaction data hash algorithms
  (`HashAlgorithm`; `Sha2`, `Sha3`, `Blake2`, `K12`), scope
  queries (`ScopeQuery`, §5.5), rules on a Request Object's claims
  (`ObjectRule`, A14), the `request_uri` POST and encrypted Request Objects
  (`RequestPost`, `EncryptedRequests`). The registry refuses each conflict:
  a name twice, an error mode over the DC API, a DC API mode declaring
  `wallet_metadata` members, a transaction data profile without `sha-256`, a
  scope query the DCQL reader refuses or whose ids another shares.
- `siros-openid4vp`'s features put each mechanism behind the feature its users
  turn on: `match`, `resolve`, `dc-api`, `uri`, `signed`,
  `request-decryption`, `cbor`, `transaction-data`, `sha3`, `blake2`, `k12`,
  `sri` and `claims`. A build compiles what it registers: an
  SD-JWT DC API build links no CBOR, COSE, form encoding, curve arithmetic or
  hash beyond SHA-2. `siros-paso`'s `sealed-signals` holds its `COSE_Encrypt`
  sealing, `siros-qes`'s `sha3` its SHA-3 approval hashes. A feature changes
  no signature: a crate compiles the same when another turns it on. The
  registry's host fixes what it takes of each plug-in (`Build`): `NoHost` takes
  phase 1's `Format`, `Profile` and `Mode` in every build, and under `resolve`
  a host holding a `Platform` takes plug-ins with their phase 2 over it.
- A crate's `test-util` feature holds doubles of the extension points the crate
  defines, written with its public API alone. `siros-testkit`'s `probe` hands a
  test what the core's flow gives a plug-in: a `QueryContext`, an
  `AnsweredContext`, a `Session` and a `FetchedRecord`.
- `cargo xtask builds` checks that each build of the design's section 4.11
  compiles none of the crates its row excludes and siros-i18n with the features
  its row names alone, its matcher (the core and the plug-ins without
  `resolve`, siros-credman) included, and that the SD-JWT and the mdoc DC API
  builds each compile fewer than 96 crates, two different sets; `cargo xtask
  alone` checks each crate alone, with and without its default features, and
  the workspace crates it names. CI runs both.
- `siros-testkit`'s doubles of the extension points: `TestMode`,
  `TestResponseType`, `TestHash`, `TestScope`, `TestObjectRule`,
  `TestPostContribution` and `TestAnswerReader`.
- Statements derive `Message`: the core's `WalletText`, `ClaimText` and
  `BooleanText`; siros-paso's Mandate labels, rulebook titles, actions and
  sections, ISO 20022 frequencies, the places a refusal names (`ArrayAt`,
  `RenderedAt`) and its values shown alone (`ValueText`); siros-qes's QES
  approval (`QesTitle`, `QesText`). Each statement's documentation names the
  situation it reports and its arguments. The crates ship no message source:
  the wallet's sources word every id. `siros-testkit`'s test app words every
  statement the workspace's tests link, in English and German (`locales/`), over
  siros-cldr's en and de format options.
- `siros-paso` classifies the inherence facts the platform reports as Risk
  Signal Registry §2.8's `bio_strong` and `bio_weak` (`BiometricClass`).
- `HttpsUrl` holds one form in ASCII, which every build shows and a caller fetches: a host beyond
  ASCII has each label in UTS #46's case and each label beyond ASCII written `xn--` and its Punycode,
  with no Unicode tables. `NotHttpsUrl` refuses a label whose Punycode overflows (`LabelOverflow`)
  and an ASCII form that is no registered name (`NotRegName`). `RemoteImage` holds an
  `HttpsUrl`. Two texts with one ASCII form are one URL: one `Resource`, one answer, one key of
  `with_resource` and `with_resources`; `FailedImage::url` and a parsed URL's
  `NotCompatible::Image` hold that form, and its `Display`, which an argument
  carries, writes it.
- A host UTS #46 refuses parses. A PaSO `url` value, a TS12 `payee.website` and a QES document link
  without a checksum at such a host show its Punycode and take no fetch. A PaSO image, a TS12 logo
  and a checksummed QES document reach the caller's GET and fail there: phase 2's outcome stands.
- `claims::kit::format_entry` is RFC 4647 Lookup over the priority list, then
  filtering, then the entry without a locale; an array answering none gives no
  entry, and the row or the card takes its next choice.
- `siros-mdoc`: a device key's label 3 stating a signature algorithm its curve does not make is refused (`DeviceKeyFault::Algorithm`; RFC 9052 §7.1): X25519 and X448 make none, Ed25519 and Ed448 EdDSA and their own fully-specified identifier, the EC2 curves ES256, ES384, ES512 and their own fully-specified identifier (RFC 9053 §2.1, §2.2, §7.1; RFC 9864 §2). The view read holds the same rule.
- `siros-mdoc`: a device key signs with a `SignatureAlgorithm` alone. X25519 and X448 are for ECDH only (RFC 9053 §7.1), and a label 3 of no signature algorithm restricts any key to something other than signing (RFC 9052 §7.1): `DeviceKey::algorithm` is `None`, the view omits `device_alg`, and the key authenticates by device MAC alone, or is refused (`DeviceAuthRefused::KeyAgreementOnly`). `deviceauth_alg_values` matches a device MAC by header `alg` 5 and over the whole of OpenID4VP B.2.2's table, the four brainpool rows included; a refusal's clause names the identifiers of the credential's keys (`Constraint::also` holds the 5).
- `siros-mdoc`'s and `siros-sdjwt`'s registration take typed input (`Resolved`) and refuse only what can happen: `RegistrationError::Metadata` holds the merge's rules. `merge_metadata`'s format document and `IssuedMetadata::{configuration, response}` are `json::Object`.
- `siros-mdoc` and `siros-sdjwt` type what their public signatures name: `Registered::{view, document}` return `ViewBytes` and `DocumentBytes`; `CertificateChain` and `SdJwt::x5c` give `DerCertificate`; `IssuerAuth::signature` an `IssuerSignature`; `Resolved::issuer` is an `IssuerName`; `Handover::Redirect::response_uri` a `HandoverUri`; `SdJwt::{issuer_jwt, typ}` return `IssuerJwt` and `JwtType`; `KeyBinding` takes a `KbSignature` from a `KbSigningInput` and assembles an `SdJwtKb`; `RegistrationError::IssuerCurve` names a `ResolvedCurve`.
- `siros-paso`'s label limits are a parameter: `LabelText::parse` takes the limit, and
  `view::convert` takes a `Registered` and `LabelLimits`.
- `siros-paso` refuses a label with no visible character (`LabelViolation::Invisible`), which
  Credential Manager's field name needs. A fixed label without one, a `mini_markdown` label judged by
  its spans' text (`LabelText::markdown`), leaves the metadata unsupported; a template label whose
  rendered spans and values show none leaves the entry not compatible
  (`NotCompatible::RenderedLabel`). `siros-ts12` renders through the same rules.
- `siros-mdoc::stored`'s `Mso::device_key` returns a `DeviceKey` on any curve
  of ISO/IEC 18013-5 Table 22, and `KeyAuthorizations` keeps the issuer's
  order.
- `siros-testkit`'s issuers write what registration reads: `sd_jwt_issuer`
  issues the SD-JWT, `issuer` the view's validity, `keyAuthorizations` and
  device key algorithm. `sd_jwt_reading` reads a presentation back.
- `siros-openid4vp`'s `Presentation` is made by `Presentation::text` or
  `Presentation::object` alone (§8.1). A format states a credential's types
  (`ViewAdditions`), which a profile reads in its `Binding`; `siros-sdjwt`'s
  `vct_values` matches a type the credential's `extends` chain names (B.3.5).
- `siros-openid4vp` composes `wallet_metadata` from what each registered part
  contributes: the formats, the prefixes (`client_id_prefixes_supported`), the
  prefix's verifying module, the URI modes, encrypted Request Objects and each
  `PostContribution`, whose parameters the POST carries beside it. The
  Response URI's answer reads through registered `AnswerReader`s. The registry
  refuses a name two parts declare and one the core writes. A deployment that
  requires a Request Object's claims registers an `ObjectRule`.
- `ErrorCode` is open: a code in RFC 6749 Appendix A.7's syntax, checked by
  `ErrorCode::new` or `checked!`; a plug-in's rule returns its
  specification's code.
- The host's modules state the algorithms they implement (`Haip::verifies`,
  `Haip::agreements`, `RequestDecryption::decrypts`), and the core accepts
  exactly those: A7 refuses an `alg` the module does not state before the
  caller is asked. `VerificationKey` and `EphemeralKey` are public JWKs, the
  secret behind a `KeyHandle`; the core links no curve arithmetic.
- `CoreHost` is `Platform` alone; each registration that makes the core call
  another module bounds it (`client_prefix` and `jwe_mode`: `Haip`;
  `request_encryption`: `RequestDecryption`). `RandomIds` and `CoseEncrypt`
  are `siros-paso`'s modules.
- The session holds the facts a presentation binds; `siros-mdoc` builds
  B.2.6's handover, the RFC 7638 thumbprint and ISO/IEC 18013-5's
  `SessionTranscript` from them, and decodes a transcript a Verifier holds.
- A format states how its proof carries a profile's members
  (`Format::placement`), and a profile places its members by it
  (`Profile::members(placement)`), naming no format.
- `Profile`'s phase-2 methods (`wanted`, `informed`, `authentication`) are
  `ProfileHost`'s; each plug-in gates its phase 2 on its own `resolve`.
- The core refuses a mode's JWE choice whose key the request does not name
  (`RouteBreach::Foreign`), whose key or `enc` the sealing module does not
  state, or whose `enc` the Verifier does not list (§5.1). `siros-testkit`'s
  `TestChoice::Foreign` chooses a key of other metadata.
- Phase 2 answers with `Built`: the Authorization Response
  (`AuthorizationResponse`, §8.1's object, its parameters beside `vp_token`
  and `state` each a `ResponseMember`) and its `Delivery`, the
  DigitalCredential's `data` (`DcApiData`, a JSON object the core reads back)
  or a `PostBody` POSTed to the `response_uri`. `FormBody::of` writes any flat
  members, each name once (`NotForm`); `PostBody::of` refuses the form media
  type (`FormMedia`), which `MediaType::form` names and `MediaType::is_form`
  finds. An error response (`ErrorResponse`) carries its code,
  its description and `state` as received; `ErrorDescription::sanitized`
  writes a refusal's text with `?` for each character outside RFC 6749
  Appendix A.8.
- A response mode writes the body around an answer (`ModeHost::answer`): the
  core seals the Authorization Response to the route's key through
  `Haip::encrypt_jwe` and hands the mode the `SealedJwe` alone
  (`AnswerContent`, `ModeRoute`), and refuses a body of another channel than
  the request's (`RouteBreach::BodyChannel`). `dc_api` writes the response,
  `dc_api.jwt` `{"response": JWE}`, `direct_post.jwt` `response=<JWE>`
  (`ResponseForm::of`). `siros-testkit`'s `TestMode` writes a body of either
  channel (`TestBody`), and `JweHaip` seals with ECDH-ES.
- A URI response mode writes the form around an error (`ErrorModeHost::error`,
  `ErrorContent`), which `error_mode` registers through `HostedErrorMode`; a
  mode answering under the name is of the same type (`ModeTwice` otherwise).
  `direct_post` and `direct_post.jwt` write §8.2's plain form (`ErrorForm::of`),
  `direct_post.jwt` `response=<JWE>` for an error the core sealed. A
  rejection's error goes in the clear on its route (`Rejected::reply`): A.4's
  `{"error": code}` over the DC API, or a cancelled flow (`DcApiErrors`,
  `Reply`), and §8.2's plain form by URI.
- Phase 2 answers an authenticated request through its route.
  `Prepared::prepare` takes the `Authenticated` and the ids the End-User
  chose, none when every credential set is optional (§6.4.2), and reads the
  request from the authenticated envelope. `Route::new` binds the authenticated endpoint, the
  registered modes the request names and the key the answering mode chose,
  checked; `Route::answering` gives the `AnswerRoute`, whose `answer` seals,
  has the mode wrap the content and delivers to the bound endpoint, and whose
  `session` holds the binding facts and the `RouteKey`. By URI a request whose
  mode names no registered error mode is `Unroutable`
  (`Outcome::Unroutable`). `Route::refusal`, `Route::unmet` and
  `Route::unavailable` send a refusal, an unmet request under its `UnmetCode`
  and `wallet_unavailable` on the route: A.4's error over the DC API, the
  error mode's body by URI, sealed by the core when the route bound a key.
  `Match::unmet` derives the code from the exclusions' plug-in
  (`ExcludedBy`). A candidate holds its query's transaction and the
  profile's binding as one value (`Candidate::bound`,
  `TransactionBinding`), from which phase 2 reads a record's transaction.
  The envelope holds `client_metadata` as read
  (`Envelope::client_metadata`), and `Authenticated` the Verifier's keys.
- An extension adds Authorization Response parameters (`ResponseParameters`,
  `ResponseParametersHost`, `HostedResponseParameters`,
  `RegistryBuilder::response_parameters`) under names the registry checks
  (`NamePlace::ResponseParameter`, `CORE_RESPONSE`); phase 2 writes them
  after `vp_token` and `state`, and a member of another name or a name written
  twice is a `Fault` caused by `ParameterBreach`. `siros-testkit`'s
  `TestResponseParameters` is the double; its `fixtures::authenticate` and
  `fixtures::trust_config` give a test an authenticated request.
- The consent entry's icon is of any image media type; `siros-credman` draws
  PNG and JPEG and the card's icon otherwise.
- `siros-openid4vp` encodes CBOR deterministically (RFC 8949 §4.2.1), reads
  CBOR with definite lengths alone under a nesting bound, and reads a
  `dcql_query`'s Credential Queries alone (`Query::read_all`).
- `siros-openid4vp::text::lookup` is RFC 4647 §3.3.1 basic filtering: a range
  matches the tag equal to it, else the first tag extending it (`en` matches
  `en-GB`, `en-US` matches no `en`) over received tags, through
  `LocaleTag::filters`; a text outside RFC 4647's grammar matches no range. A
  credential's display entry matches by it. `Env::new` takes the End-User's
  priority list as given; its documentation states the app's practice of
  putting each tag's generic form after it. The wallet's wording shows an amount
  through `:currency` or as written. `ids::LocaleTag` is `siros-i18n`'s.
- The texts of a consent entry, a header, a row and Credential Manager's
  entries are siros-i18n's `Text`, resolved through the wallet's `Context`:
  `Card`'s title and subtitle, `Overlay`'s hint, `TransactionHeader`'s
  counterparty and amount, `Header`'s actions, a row's label, value and
  section, `StaticEntry`, and `siros-credman`'s Standard and Payment entries.
  Every extension point that writes a text takes the `Context`
  (`FormatQuery::draw`, `Profile::bind`, the claims kit, `PrefixClaim::bind`),
  and so do `Match::run`, `Views::of` and `Prepared::prepare`; the wallet picks
  the locale by the context it passes. The wallet's, PaSO's and QES's own
  texts are statements; a value shown alone is a `ClaimText` in its literal
  form (a date, a time, an amount, a claim's JSON number as written, QES's
  `numSignatures`); a boolean, a claim's `null` and a frequency are
  statements; an issuer's, a Verifier's or a credential's text shows as
  written, the Verifier's name for the consent included (`ClientBinding::name`,
  `Verifier::name`). A row's value is an image or a `Text`. Credential
  Manager's fields show a `Text`'s plain text.
- `siros-paso` selects a transaction's locale as PaSO View §4 writes it, over
  `Env`'s priority list as given: for each tag in order, every display array
  takes the entry RFC 4647 §3.4's Lookup finds over its tagged entries, else its
  first entry without a locale, the entries a template with an absent claim
  discards left out; the first tag whose every array matches is
  `display_locale`, and none excludes the credential. It converts a type's
  display rules to MF2 source for the wallet's context (`view::convert`): the
  source declares the context's locale, its ids carry the metadata's SHA-256,
  and each display array is one message (`claim_<k>`, a UI label's name) of the
  entries View §4 tries for the selected tag, a template entry an absent claim
  discards selected by its argument `e<j>`. A `mini_markdown` label is its MF2
  markup, and a template label's `{n}` the argument `c<n>`, `""` when the claim
  is absent. A claim's value enters as its literal text: a date or a time
  through `:siros:date`, `:siros:time` or `:siros:datetime`, an amount as its
  value and its currency through `:currency`, a frequency and a boolean as their
  statements' resolved texts. Every issuer text goes through `escape`, and the
  source's ids, names and variant keys are ASCII, so a matcher built without
  siros-i18n's `nfc` loads it into the wallet's messages. A template value of an
  inner text or `mini_markdown` kind sets each referenced value of a typed kind
  as its typed text (View §3 step 3). A `mini_markdown` value shows its text
  without its styles. A time of day holds seconds 00 to 59; a date-time's second
  60 is RFC 3339's leap second. A value's refusal names the rule it breaks
  (`value::Breach`).
- PaSO View's vocabulary is `siros-paso`'s: its value types (`value`:
  `ValueKind`, `FormattedKind`, `Parsed`, `Written`, `BadValue`,
  `formatted`), the ISO 20022 frequencies (`frequency`) and the
  `mini_markdown` parser (`markdown`). The core keeps RFC 4647 matching and
  Python's whitespace in `text`. A PaSO rendering's row states its value's
  kind (`ViewRow::kind`).
- A library's diagnostic stays out of its error's message arguments
  (`#[explain(skip)]`), kept in the log line: JSON's syntax, a URI's and a
  form's cause, a certificate's DER reason, an mdoc's CBOR shape, an image
  fetch's and an ad-hoc JWT's encoding failure.
- The matcher offers an entry with ad-hoc PaSO metadata (Proof Metadata §5):
  `siros-paso::adhoc::Carried::read` reads each `metadata` JWT of a DC API
  request as a signed request is read, unverified; `view::carried` converts its
  display rules to MF2 source, which the matcher loads into a clone of its
  context. The wallet verifies the JWT as §5.3 states before it
  relies on it: the `typ`, the key (the `x5c` chain anchored in the trust
  store through the required `IssuerTrust` module, or the `kid` in the
  issuer's key set), the ES256 signature through `Haip::verify`, `iss`, `exp`,
  the credential binding of §7 step 6 and the type. In the URI flow
  `adhoc::Verified::of` verifies each JWT for each credential, `view::verified`
  converts what it verified, and first match relies on a JWT for a credential
  once `PasoProfile::with_verified` holds it verified for it
  (`AdhocFailure::Unverified` otherwise); `PasoProfile::render` takes the
  request's channel. In phase 2 `ProfileHost::wanted` and `Prepared::prepare`
  take the host, and PaSO verifies the JWT before it lists the images to fetch;
  the revalidation finds a refused JWT alone (`PasoFinding::refused`). A JWT
  that fails is incompatible for the credential, the stored metadata never
  standing in, and the informed profile (`PasoProfile::with_refusals`) moves
  past its entry. The PaSO document records the issuer's key set as public
  JWKs, or the credential's chain root and leaf subject as DER.
- A record commits to the texts its entry showed: its id's last item is
  `shown`, the hexadecimal SHA-256 of every `Text` of the entry's card, header
  and overlay under an injective encoding. Phase 2 derives its records with its
  own context, answers only byte-equal records, and refuses a pick whose
  `shown` differs (`Finding::Rendered`).

### Changed

- `siros-wallet-state` refuses a repeated member name in every object it reads, a `presentations` entry included. `CredentialEntry::format` is optional: the empty string reads as unknown. `PresentationRecord::new` takes `PresentationData` and `Audience`.
- `siros-trust`: `Certificate::p256_key` and `p384_key` return `P256Point` and `P384Point`.
- `siros-zkp-catalogues` refuses a device key off P-256 for the nym_auth form
  (`FormError::DeviceKey`).
- A malformed `aki` value of a Trusted Authorities Query equals no held value
  (OpenID4VP section 6.1.1): `siros-trust` no longer refuses its form.
- `siros-zkp-req`, `siros-zkp-catalogues`, `siros-trust` and `proving/` read
  DCQL, CBOR, JSON, identifiers, sessions and authenticated requests through
  `siros-openid4vp`. `siros-zkp-req` holds its member faults and value macros,
  and refuses an indefinite length through the core's definite reading.
- `siros-zkp-catalogues` reads the semantics identifier from the trust
  service's facts and its stored mdocs through `siros-mdoc::stored`, and holds
  its calendar dates and ES256 signatures. Its session binds the key that
  `siros-openid4vp`'s key rule chooses for the response.
- `siros-trust` takes the core's `Timestamp` and identifiers. Its chain
  reader is part of the crate, without a feature, on the workspace's
  `x509-cert`, `der`, `p256` and `p384`.
- `siros-wallet-state` holds its own errors and timestamp.
- `clippy.toml` disallows `BTreeMap` and `BTreeSet`, and `split_off` and
  `split_at` on vectors, strings, slices and `str`. `wmp-core` and
  `engine-conformance` keep their ordered maps under `#[expect]`.
- `scripts/check_panic_sites.py` reads a `const` item's initialiser and an
  inline `const` block as build-time code.
- `engine-adapter-wasm`'s mini host builds its presentations itself. The
  PID's holds the disclosures the match named and the KB-JWT over `iat`,
  `aud`, `nonce` and `sd_hash` (RFC 9901 §4.3), with `base64` for the
  segments. The mDL's is the DeviceResponse of the selected items with the
  device signature over the OpenID4VPHandover's session transcript
  (OpenID4VP B.2.6.1); `ciborium` writes its CBOR in the core deterministic
  encoding (RFC 8949 §4.2.1).
- Rust 1.89 is the floor of every crate. The msrv job checks the workspace on
  1.89, then each crate with and without its default features. The workspace
  resolves with resolver 3. Both container images build on Rust 1.99.1, the
  pinned toolchain.
- CI builds the documentation with warnings denied, runs clippy over the
  libraries without default features, and denies warnings when it checks each
  crate alone.

### Removed

- `siros-trust`'s `QueryAuthorities`, `Admission`, `Issuer`, `Ground`, `Refusal`,
  `FactRefusal`, `Authority`, `AkiError`, `AuthorityError`, `EntryError::Id` and
  the generic parameter of `Unadmitted`: the core's `Facts::admits` and `Query`
  replace them.
- `siros-codec`, `siros-dcql` and `siros-oid4vp`: `siros-openid4vp` reads
  DCQL, CBOR, JSON and requests, and the crates that read them name it.
  `direct_post.cwt` waits for the `zkp_req` plug-in (the design's Appendix A).
  crates.io's `siros-dcql` stays as siros-dc-matcher published it.
- `siros-credential`, `siros-display`, `siros-transaction-data` and
  `siros-presentation`. `docs/wallet-core-design.md`, section 10.3, names the
  crate and milestone that takes each of their capabilities; `zkp_req`
  matching and its phase 2 wait for the `zkp_req` plug-in (Appendix A). The
  generated Unicode tables and `scripts/gen_unicode_tables.py` leave with them.
- `docs/wallet-core-architecture.md`: `docs/wallet-core-design.md` is the
  contract of the presentation core.

## [0.1.2] — 2026-11-06

The first release whose run completed: the 0.1.0 and 0.1.1 tags' runs
failed at their packaging jobs (the AAR action's v4 line, then the
image job's action pins - both fixed on main by then) and produced no
GitHub releases. This cut carries the fixes and the complete artifact
set: the
AAR, the XCFramework, the bindings, and the engine server's container
image (ghcr.io/sirosfoundation/engine-server, this release's new
publish).

### Added (since the 0.1.0 cut)

- The engine server's container image: built by the release workflow
  on tags (ghcr, the version tag + latest) and verified on every push
  by CI - a static musl binary on distroless, built with the pinned
  toolchain (rust-toolchain.toml, the single source of truth).
- The engine server's environment configuration
  (`Config::from_env`): the `ENGINE_*` variables over the defaults -
  the container platform's deployment shape (the compose file, the
  chart), beside the `ENGINE_CONFIG`-named JSON file. Includes the AS
  trust knobs the dev stacks need: `ENGINE_AS_JWKS_URL` (the Go
  backend's own AS publishes under `/auth/.well-known/`),
  `ENGINE_AS_ISSUER` (its configured issuer) and
  `ENGINE_AS_AUDIENCES` (set-but-empty accepts every audience).
- CI: the AAR/XCFramework recipes verified on every push (was:
  release-time only), the engine image build with its health probe
  asserted.

## [0.1.0] — 2026-11-05

The first release: the wallet core (presentation side, imported
unchanged) and the WMP engine — `siros-wallet-core` as the primary WMP
engine across the deployment models (wasm, cloud, native), the
drop-in replacement of `go-wallet-backend --mode=engine` and the
legacy WebSocket protocol (the plan and its record:
`docs/engine-parity.md`).

### Added

- Initial import of the wallet core, presentation side, ported unchanged from
  the siros-dc-matcher workspace (pull requests
  [#54](https://github.com/sirosfoundation/siros-dc-matcher/pull/54) and
  [#55](https://github.com/sirosfoundation/siros-dc-matcher/pull/55), closed
  2026-11-01 for placement, not content): `siros-codec`, `siros-credential`,
  `siros-dcql`, `siros-display`, `siros-mdoc`, `siros-oid4vp`,
  `siros-presentation`, `siros-sdjwt`, `siros-transaction-data`, `siros-trust`,
  `siros-wallet-state`, `siros-zkp-req`, `siros-zkp-catalogues`, with the
  architecture contract and the `zkp_req` specifications under `docs/`.
- The WMP engine core, on the go-wmp v0.13.0 mechanics:
  - `wmp-core`: the peer (dispatch, sessions, sub-flow routing), the session
    service (single-use rotating tokens, owner binding, capability
    negotiation), the typed JSON-RPC error codes, `wmp.resolve` (the vctm
    lookup), typed protocol version negotiation.
  - `engine-ports`: the port traits — the engine core's only interface with
    the world (`Host`, `HttpClient`, `Clock`, `Rng`, `Pdp`, `KeyValue`,
    `Telemetry`) — including the verifier attestation, client-held DPoP and
    credential-selection asks, the DID resolution and the eval context of
    the trust port, and the issuer entitlement (ARF 6.6.2.3) with its
    bounded wire shapes.
  - `engine-core`: the flow runtime (the capability gate) and the OpenID4
    flow family — OpenID4VCI (both grants, PKCE, PAR + the RFC 7523
    assertion, tx_code, deferred, §10/§11 notifications, DPoP, response
    encryption, the credential selection, the issuer entitlement check)
    and OpenID4VP (request parsing with the per-scheme rules — the signed
    + x5c form of `x509_san_dns`, the constant-time `x509_hash` binding,
    the `verifier_attestation` extraction and `cnf.jwk` verification —
    the four response modes, JARM, the DCQL assembly, the consent vetting
    with its modes, the sign-stage refusals) — plus the
    `credential_notification` flow over its single-use, TTL-bounded
    notification context store (WMP OpenID4x 3.4).
  - The adapters: `engine-adapter-server` (the drop-in engine server: the
    HTTP+SSE WMP binding with the outbox and `Last-Event-ID` replay, the
    host bridge — the engine's asks as child flows — the TAC principal and
    the lifecycle gate, the backend proxy PDP), `engine-adapter-wasm` (the
    in-page dispatcher for the browser wallet), `engine-adapter-sdk` (the
    UniFFI bindings for Kotlin and Swift: `createEngine` over the full
    ports, the `WmpEngine` transport handle), and `engine-conformance`
    (the OIDF-suite runner).
  - The mobile packaging: the AAR (the native `.so` per ABI, the empty
    classes.jar — the Kotlin bindings are vendored source) and the
    XCFramework (the iOS device + simulator static slices), published per
    tag as the Maven coordinate `org.siros:siros-wallet-core` (GitHub
    Packages) and as release assets; the packaging recipes verified on
    every push by CI.

### Changed

- `siros-zkp-req-nym-auth` is renamed to `siros-zkp-catalogues` on import. The
  ZK stack is two crates permanently: `siros-zkp-req` (protocol) and
  `siros-zkp-catalogues` (every rulebook as modules and features). nym_auth is
  the first rulebook in the catalogue crate; further rulebooks, credential
  forms and systems land in it rather than in new crates.

### Not ported

The Android credential picker and its registration (`siros-picker`,
  `siros-registration`, `siros-picker-testhost`, `android-credman`,
  `siros-dc-matcher-ffi`) remain in siros-dc-matcher, which consumes this core.
