//! check_props.py `check_dressed` on one dressed case: PaSO View §2-4 on each rendering, the
//! request rules with the real registry, each profile's binding rule against what the core bound
//! or excluded, the box the core composes for each entry, then the display and the responses.

use std::rc::Rc;

use crate::common::HaipHost;
use serde_json::Value;
use siros_credman::{CredmanEntry, EntryIcon, StandardEntry};
use siros_explain::Text;
use siros_openid4vp::consent::Card;
use siros_openid4vp::ids::FormatId;
use siros_openid4vp::matching::{Accepted, Candidate, Match, StaticEntry, Views, option_items};
use siros_openid4vp::plugins::{
    Carriage, Fault, FormatQuery, Member, NoCandidate, OptionIndex, Profile, Registry, Shown,
};
use siros_openid4vp::request::{
    ClientMetadata, EntryIndex, HolderBinding, Item, Query, QueryIndex, Request,
};
use siros_openid4vp::rows::{Env, Row};
use siros_openid4vp::wallet::{Credential, Holder, Wallet};
use siros_paso::outcome::Outcome;
use siros_paso::{PasoProfile, Rendered};
use siros_qes::QesProfile;
use siros_testkit::fixtures::{self, Held};
use siros_testkit::probe::read_query;

use crate::common::registry;
use crate::generate::Dressed;
use crate::spec::Spec;
use crate::tally::Tally;
use crate::{display, outcome};

/// A dressed case as the checks read it: the request, the real registry, the wallet, its
/// configuration and static entries, each query as its format parsed it.
pub struct Case<'c> {
    /// The request.
    pub request: &'c Request<'c>,
    /// The real registry.
    pub registry: &'c Registry<HaipHost>,
    /// The wallet.
    pub wallet: &'c Wallet<'c>,
    /// The wallet's configuration.
    pub env: &'c Env,
    /// What the core renders the wallet's texts with.
    pub rendering: &'c siros_openid4vp::rendering::Rendering<'c>,
    /// The wallet's static entries.
    pub statics: &'c [StaticEntry],
    /// The credentials as the wallet registers them.
    pub held: &'c [Held],
    /// The credentials the host says can no longer be presented.
    pub unusable: &'c [String],
    /// Each query as its format parsed it; `None` for a format without a plug-in.
    pub parsed: Vec<Option<Parsed<'c>>>,
    /// The specifications' tables.
    pub spec: &'c Spec,
    /// Each PaSO entry rendered for each credential.
    pub renders: &'c [Rendering],
}

/// A query as its format parses it in the context the core gives the format. Each reading runs
/// the core's flow to that context, and a registered credential by its id.
pub struct Parsed<'c> {
    request: &'c Request<'c>,
    query: &'c Query<'c>,
    registry: Rc<Registry<HaipHost>>,
    held: &'c [Held],
    env: Env,
}

impl Parsed<'_> {
    /// The closure's result over the parse and a credential of the wallet.
    fn read<R: 'static>(
        &self,
        credential: &Credential<'_>,
        read: impl FnOnce(&dyn FormatQuery, &Credential<'_>, &Env, ClientMetadata<'_>) -> R + 'static,
    ) -> R {
        let held = self
            .held
            .iter()
            .find(|held| held.id == credential.id.as_str())
            .expect("a credential of the wallet")
            .clone();
        let registry = Rc::clone(&self.registry);
        let env = self.env.clone();
        read_query(self.request, self.query, move |query, context| {
            let client = ClientMetadata::parse(context.request().client_metadata())
                .expect("accepted metadata");
            let format = registry.format(query.format()).expect("a format");
            let parsed = format
                .query(query, context)
                .map_err(|refusals| format!("{refusals:?}"))
                .expect("an accepted query parses");
            let credential = held.credential().expect("a credential");
            read(&*parsed, &credential, &env, client)
        })
        .expect("the core reads the query")
    }

    /// [`FormatQuery::admits`] under the request's keys.
    fn admits(&self, credential: &Credential<'_>) -> Result<(), NoCandidate> {
        self.read(credential, |parsed, credential, _, client| {
            parsed.admits(credential, &client.agreeable_keys())
        })
    }

    /// [`FormatQuery::carries`].
    fn carries(&self, credential: &Credential<'_>, members: &[Member]) -> Result<Carriage, Fault> {
        let members = members.to_vec();
        self.read(credential, move |parsed, credential, _, _| {
            parsed.carries(credential, &members)
        })
    }

    /// [`FormatQuery::answerable`] in the case's configuration.
    fn answerable(
        &self,
        credential: &Credential<'_>,
        provided: &[Member],
    ) -> Result<Vec<OptionIndex>, Fault> {
        let provided = provided.to_vec();
        self.read(credential, move |parsed, credential, env, _| {
            parsed.answerable(credential, env, &provided)
        })
    }

    /// [`FormatQuery::draw`] in the case's configuration.
    fn draw(
        &self,
        credential: &Credential<'_>,
        everyone: &[Item],
        chosen: &[Item],
    ) -> Result<Card, Fault> {
        let (everyone, chosen) = (everyone.to_vec(), chosen.to_vec());
        self.read(credential, move |parsed, credential, env, _| {
            let shown = Shown {
                everyone: &everyone,
                chosen: &chosen,
            };
            parsed.draw(credential, shown, env)
        })
    }
}

impl<'c> Case<'c> {
    /// A query's parse by its format.
    pub fn parsed(&self, query: QueryIndex) -> Option<&Parsed<'c>> {
        self.parsed.get(query.get()).and_then(Option::as_ref)
    }

    /// The query at a position.
    pub fn query(&self, query: QueryIndex) -> &Query<'_> {
        self.request.query(query).expect("a query of the request")
    }

    /// The entry's decoded JSON.
    pub fn entry_json(&self, entry: EntryIndex) -> Value {
        let entry = self.request.entry(entry).expect("an entry of the request");
        serde_json::from_str(entry.decoded()).expect("an entry's JSON")
    }

    /// The format's identifier for a query.
    pub fn format_id(&self, query: QueryIndex) -> FormatId<'_> {
        self.query(query).format().borrowed()
    }

    /// A PaSO entry rendered for a credential.
    pub fn rendered(&self, entry: EntryIndex, credential: &str) -> &Result<Rendered, Outcome> {
        self.renders
            .iter()
            .find(|r| r.entry == entry && r.credential == credential)
            .map(|r| &r.outcome)
            .expect("each PaSO entry rendered for each credential")
    }
}

/// A PaSO entry rendered for a credential (PaSO's `render`, Core §7.4.2's per-entry step).
pub struct Rendering {
    /// The entry.
    pub entry: EntryIndex,
    /// The credential's id.
    pub credential: String,
    /// The rendering, or the outcome that kept the entry from rendering.
    pub outcome: Result<Rendered, Outcome>,
}

/// Each PaSO entry with an object payload rendered for each credential.
fn renders(request: &Request<'_>, wallet: &Wallet<'_>, env: &Env) -> Vec<Rendering> {
    let paso = PasoProfile::default();
    let mut out = Vec::new();
    for credential in wallet.credentials() {
        for (index, entry) in request.indexed_entries() {
            let json: Value = serde_json::from_str(entry.decoded()).expect("an entry's JSON");
            if entry.kind().as_str().starts_with("urn:paso:sca:") && json["payload"].is_object() {
                out.push(Rendering {
                    entry: index,
                    credential: credential.id.to_string(),
                    outcome: paso
                        .render(
                            entry,
                            request.envelope().channel().kind(),
                            credential,
                            crate::common::placement(&credential.format),
                            env,
                        )
                        .expect("no fault"),
                });
            }
        }
    }
    out
}

/// A credential's document as JSON.
pub fn document(credential: &Credential<'_>, key: &str) -> Option<Value> {
    credential
        .document(key)
        .map(|bytes| serde_json::from_slice(bytes).expect("a JSON document"))
}

/// OpenID4VP §6.1.1: no Trusted Authorities Query, or a value the credential holds under one of
/// the query's types.
fn trusted(query: &Query<'_>, credential: &Credential<'_>) -> bool {
    query.trusted_authorities().is_empty()
        || query.trusted_authorities().iter().any(|wanted| {
            credential
                .facts
                .authority(wanted.kind())
                .is_some_and(|held| wanted.values().iter().any(|v| held.values.contains(v)))
        })
}

/// What the binding rule says a credential gets for a query a PaSO entry names.
enum Want {
    /// The entry first match binds.
    Entry(EntryIndex),
    /// An entry's locale failure excludes the credential, with its clause.
    Excluded(&'static str),
    /// No entry renders, or the presentation cannot carry PaSO's members.
    Nothing,
}

/// Checks one dressed case.
pub fn check(dressed: &Dressed, spec: &Spec, tally: &mut Tally) {
    let received = dressed.received();
    let request = fixtures::request_of(&received).expect("a dressed request parses");
    let registry = Rc::new(registry().expect("the real registry"));
    let credentials = dressed
        .credentials
        .iter()
        .map(|held| held.credential().expect("a credential"))
        .collect();
    let wallet = Wallet::new(credentials).expect("a wallet");
    let env = &dressed.env;
    let renders = renders(&request, &wallet, env);
    // The PaSO renderer on every entry for every credential whose metadata lists its type, or
    // that brings its own metadata.
    for rendering in &renders {
        let credential = wallet
            .credentials()
            .iter()
            .find(|c| c.id.as_str() == rendering.credential)
            .expect("a credential");
        let document = document(credential, "paso").expect("a PaSO document");
        let entry = request.entry(rendering.entry).expect("an entry");
        let json: Value = serde_json::from_str(entry.decoded()).expect("an entry's JSON");
        let listed = document["transaction_data_types"]
            .get(entry.kind().as_str())
            .is_some();
        if json.get("metadata").is_some() || listed {
            let text = credential
                .document("paso")
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .expect("a PaSO document's text");
            outcome::check(
                &json,
                (&document, text),
                &rendering.outcome,
                env,
                spec,
                tally,
            );
        }
    }
    let accepted = match Accepted::new(&request, &*registry) {
        Ok(accepted) => accepted,
        Err(refused) => {
            for text in refused.texts() {
                tally.add(format!(
                    "refused {}",
                    text.split(' ').next().unwrap_or_default()
                ));
            }
            return;
        }
    };
    let parsed = request
        .indexed_queries()
        .map(|(_, query)| {
            registry.format(query.format()).map(|_| Parsed {
                request: &request,
                query,
                registry: Rc::clone(&registry),
                held: &dressed.credentials,
                env: env.clone(),
            })
        })
        .collect();
    let app = crate::common::wallet_app(&wallet, &request, env, &HaipHost::default());
    let rendering = app.rendering().expect("the rendering");
    let case = Case {
        request: &request,
        registry: &registry,
        wallet: &wallet,
        env,
        rendering: &rendering,
        statics: &dressed.statics,
        held: &dressed.credentials,
        unusable: &dressed.unusable,
        parsed,
        spec,
        renders: &renders,
    };
    let matched = Match::run(&accepted, &wallet, env, &rendering).expect("no fault");
    bindings(&case, &matched, tally);
    let views = Views::of(&matched, env).expect("no fault");
    boxes(&case, &accepted, &matched, &views, tally);
    display::check(&case, &matched, &views, tally);
}

/// Each profile's binding rule, stated here, against what the core bound or excluded: holder
/// binding needs a key (OpenID4VP §6.1); the Verifier's algorithms admit the credential; PaSO's
/// first match (Core §7.4.2); QES's one entry, its qualifier, its members carried (CSC §6.3,
/// §7.2.1).
fn bindings(case: &Case<'_>, matched: &Match<'_>, tally: &mut Tally) {
    let paso = PasoProfile::default();
    for (index, query) in case.request.indexed_queries() {
        let candidates = matched.candidates(index);
        let Some(parsed) = case.parsed(index) else {
            assert!(
                candidates.is_empty(),
                "P-no format, no candidate {}",
                query.id()
            );
            continue;
        };
        let own = case.request.entries_naming(index);
        for credential in case.wallet.credentials() {
            let (got, excluded) = given(matched, index, credential);
            let trusted = trusted(query, credential);
            let keyed = query.holder_binding() == HolderBinding::Waived
                || credential.facts.holder == Holder::Bound;
            if credential.format != *query.format() || !trusted || !keyed {
                assert!(
                    got.is_none() && !excluded,
                    "P-not a candidate {} {}",
                    query.id(),
                    credential.id
                );
                if credential.format == *query.format() && trusted {
                    tally.add("not candidates: holder binding without a key");
                }
                continue;
            }
            match parsed.admits(credential) {
                Ok(()) => {}
                Err(NoCandidate::Excluded(_)) => {
                    assert!(
                        got.is_none() && excluded,
                        "P-algorithms {} {}",
                        query.id(),
                        credential.id
                    );
                    tally.add("excluded by the Verifier's algorithms");
                    continue;
                }
                Err(NoCandidate::Fault(fault)) => panic!("{fault}"),
            }
            let qes_entry = own
                .first()
                .copied()
                .filter(|e| case.entry_json(*e)["type"] == siros_qes::TYPE);
            if let Some(entry) = qes_entry {
                qes_binding(case, matched, index, entry, credential, parsed, tally);
                continue;
            }
            let members = crate::common::placement(&case.format_id(index))
                .and_then(|placement| paso.members(placement));
            let carried = !own.is_empty()
                && members.is_some_and(|m| {
                    parsed.carries(credential, m).expect("no fault") == Carriage::Carried
                });
            let mut want = Want::Nothing;
            if carried {
                for e in &own {
                    match case.rendered(*e, credential.id.as_str()) {
                        Ok(_) => {
                            want = Want::Entry(*e);
                            break;
                        }
                        Err(Outcome::Excluded(excluded)) => {
                            want = Want::Excluded(excluded.clause().as_str());
                            break;
                        }
                        Err(Outcome::Unsupported(_) | Outcome::NotCompatible(_)) => {}
                    }
                }
            }
            let answers = |provided| {
                !parsed
                    .answerable(credential, provided)
                    .expect("no fault")
                    .is_empty()
            };
            match want {
                _ if own.is_empty() => {
                    // A query no entry names: a candidate exactly when the credential answers an
                    // option of its format's (OpenID4VP §6.3, §6.4.1), without a transaction.
                    tally.add("credentials for queries no entry names");
                    assert!(
                        got.is_some() == answers(&[]) && got.is_none_or(|got| got.bound.is_none()),
                        "P-unnamed {} {}",
                        query.id(),
                        credential.id
                    );
                }
                Want::Entry(e) => {
                    // Core §7.4.2: the first entry in array order that renders binds.
                    let provided = members.expect("PaSO's members for the format");
                    assert_eq!(
                        got.is_some(),
                        answers(provided),
                        "P-matched {} {}",
                        query.id(),
                        credential.id
                    );
                    assert!(
                        got.is_none_or(|got| bound_entries(got) == [e]),
                        "P-first match {} {}",
                        query.id(),
                        credential.id
                    );
                    if got.is_some() {
                        tally.add("bound by first match");
                    }
                }
                Want::Excluded(clause) => {
                    // View §4: a locale failure excludes the credential.
                    assert!(
                        got.is_none() && excluded,
                        "P-excluded {} {}",
                        query.id(),
                        credential.id
                    );
                    tally.add(format!("excluded {clause}"));
                }
                Want::Nothing => {
                    // Core §7.4.2 step 2: no compatible entry excludes the credential.
                    assert!(
                        got.is_none() && excluded,
                        "P-excluded {} {}",
                        query.id(),
                        credential.id
                    );
                    tally.add("excluded no compatible entry");
                }
            }
        }
    }
}

/// What the core gave a credential for a query: the candidate, and whether a plug-in excluded
/// it.
fn given<'m>(
    matched: &'m Match<'m>,
    query: QueryIndex,
    credential: &Credential<'_>,
) -> (Option<&'m Candidate<'m>>, bool) {
    let candidate = matched
        .candidates(query)
        .iter()
        .find(|c| c.credential.id == credential.id);
    let excluded = matched
        .excluded()
        .iter()
        .any(|x| x.query == query && x.credential.id == credential.id);
    (candidate, excluded)
}

fn bound_entries(candidate: &Candidate<'_>) -> Vec<EntryIndex> {
    candidate
        .bound
        .as_ref()
        .map(|binding| binding.bound.entries.entries().to_vec())
        .unwrap_or_default()
}

/// CSC §6.3, §7.2.1 Note 22: a credential binds the query's QES entry exactly when its rulebook
/// approves the entry's signatureQualifier and its presentation carries qesApproval.
fn qes_binding(
    case: &Case<'_>,
    matched: &Match<'_>,
    query: QueryIndex,
    entry: EntryIndex,
    credential: &Credential<'_>,
    parsed: &Parsed<'_>,
    tally: &mut Tally,
) {
    let (got, excluded) = given(matched, query, credential);
    let qualifier = case.entry_json(entry)["signatureQualifier"].clone();
    let approves = document(credential, "qes").is_some_and(|document| {
        document["signature_qualifiers"]
            .as_array()
            .is_some_and(|qualifiers| qualifiers.contains(&qualifier))
    });
    let qes = QesProfile::default();
    let members = crate::common::placement(&case.format_id(query))
        .and_then(|placement| qes.members(placement));
    let carried = members
        .is_some_and(|m| parsed.carries(credential, m).expect("no fault") == Carriage::Carried);
    if approves && carried {
        let provided = members.expect("QES's members for the format");
        let answers = !parsed
            .answerable(credential, provided)
            .expect("no fault")
            .is_empty();
        assert_eq!(got.is_some(), answers, "P-QES matched {}", credential.id);
        assert!(
            got.is_none_or(|got| bound_entries(got) == [entry]),
            "P-QES bound {}",
            credential.id
        );
        if got.is_some() {
            tally.add("QES bound");
        }
    } else {
        assert!(
            got.is_none() && excluded,
            "P-QES excluded {}",
            credential.id
        );
        tally.add("QES excluded");
    }
}

/// The box the core composes for each entry: the format's card for the option's items; a
/// transaction's profile over it.
fn boxes(
    case: &Case<'_>,
    accepted: &Accepted<'_>,
    matched: &Match<'_>,
    views: &Views<'_>,
    tally: &mut Tally,
) {
    for view in views.iter() {
        tally.add("entries");
        let candidate = matched
            .candidate(view.pick.query, view.pick.candidate)
            .expect("the view's candidate");
        let parsed = case.parsed(view.pick.query).expect("a format");
        let (everyone, chosen) = option_items(
            accepted.options(view.pick.query),
            &candidate.options,
            view.pick.option,
        );
        // The format's card shows the items in every answerable option, then the option's own.
        let card: Card = parsed
            .draw(candidate.credential, &everyone, &chosen)
            .expect("no fault");
        let Some(bound) = candidate.bound.as_ref().map(|binding| &binding.bound) else {
            assert!(view.record.entries().is_empty(), "P-record without entries");
            assert_eq!(
                CredmanEntry::of(&view.entry),
                CredmanEntry::Standard(StandardEntry {
                    icon: EntryIcon::of(&card.icon),
                    title: card.title,
                    subtitle: card.subtitle,
                    warning: None,
                    rows: card.rows,
                }),
                "P-no transaction is the format's box"
            );
            assert!(view.header.is_none(), "P-no transaction, no header");
            tally.add("format boxes");
            continue;
        };
        tally.add("proxied");
        let first = bound.entries.entries()[0];
        let entry = case.request.entry(first).expect("the bound entry");
        if entry.kind().as_str() == siros_qes::TYPE {
            // CSC §6.4: the approval's rows, its statement first as a full-text row, then the
            // card's; no warning; the approval's header.
            let mut rows: Vec<Row> = bound.overlay.rows.iter().cloned().map(Row::from).collect();
            rows.extend(card.rows.iter().cloned());
            assert_eq!(
                CredmanEntry::of(&view.entry),
                CredmanEntry::Standard(StandardEntry {
                    icon: EntryIcon::of(&card.icon),
                    title: card.title,
                    subtitle: card.subtitle,
                    warning: None,
                    rows,
                }),
                "P-QES box"
            );
            assert!(
                view.header == Some(&bound.header)
                    && bound
                        .overlay
                        .rows
                        .first()
                        .is_some_and(|row| row.value.is_none()),
                "P-QES header and statement"
            );
            tally.add("QES boxes");
            continue;
        }
        // PaSO: the bound entry as PaSO renders it for the credential.
        let rendered = case
            .rendered(first, candidate.credential.id.as_str())
            .as_ref()
            .expect("the bound entry renders");
        let t = &rendered.view;
        let header = view.header.expect("a transaction's header");
        assert_eq!(
            (&header.title, &header.confirm, &header.cancel),
            (&t.title, &t.actions.confirm, &t.actions.deny),
            "P-header"
        );
        let shown: Vec<Row> = t.rows.iter().map(|row| row.row.clone().into()).collect();
        match CredmanEntry::of(&view.entry) {
            CredmanEntry::Payment(payment) => {
                // View §2: merchant and amount show once, in the payment entry; every other
                // transaction row stays a row, then the card's; the hint is the additional
                // information.
                let heads = t.payment.expect("P-payment rows");
                let (merchant, amount) = t.payment_texts().expect("P-payment rows");
                let rest: Vec<_> = shown
                    .iter()
                    .enumerate()
                    .filter(|(k, _)| *k != heads.merchant().get() && *k != heads.amount().get())
                    .map(|(_, row)| row.clone())
                    .collect();
                assert_eq!(rest.len() + 2, shown.len(), "P-proxy rows");
                let mut want = rest;
                want.extend(card.rows.iter().cloned());
                assert_eq!(payment.rows, want, "P-proxy rows");
                assert_eq!(
                    (&payment.merchant, &payment.amount),
                    (merchant.text(), amount.text()),
                    "P-payment box"
                );
                assert_eq!(
                    (
                        &payment.method_name,
                        &payment.method_subtitle,
                        payment.method_icon.icon()
                    ),
                    (&card.title, &card.subtitle, &card.icon),
                    "P-payment method"
                );
                assert_eq!(
                    payment.additional_info,
                    t.actions.hint.clone().map(Text::from),
                    "P-hint on the entry"
                );
                tally.add("payment boxes");
            }
            CredmanEntry::Standard(standard) => {
                // The card stays the box's identity; the transaction's rows come first.
                assert!(t.payment_texts().is_none(), "P-standard box");
                let mut want = shown;
                want.extend(card.rows.iter().cloned());
                assert_eq!(standard.rows, want, "P-proxy rows");
                assert_eq!(
                    (standard.icon.icon(), &standard.title, &standard.subtitle),
                    (&card.icon, &card.title, &card.subtitle),
                    "P-card is the identity"
                );
                assert_eq!(
                    standard.warning,
                    t.actions.hint.clone().map(Text::from),
                    "P-hint on the entry"
                );
                tally.add("PaSO standard boxes");
            }
        }
        if t.actions.hint.is_some() {
            tally.add("hints on entries");
        }
    }
}
