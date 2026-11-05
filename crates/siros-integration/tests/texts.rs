//! The crate modules: each loads whole in English and in the test app's German, and renders the
//! texts the tables of `f7f6c55` (siros-wallet-core `f7f6c55`, imported from wallet-rs `f718dc3`)
//! held, in both languages (I31's clause on the tables).

use siros_explain::{Explain, Messages, ModuleId, Text};
use siros_i18n::{Module, ModuleError};
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::rows::{Choice, Env, Frequency, WalletText};
use siros_paso::mandate::MandateLabel;
use siros_paso::rulebook::{Confirm, Section, Title};
use siros_qes::QesText;
use siros_testkit::fixtures::OPTIONS;
use siros_testkit::render::{App, CrateSource, GERMAN_PASO, GERMAN_QES, main_module};

fn paso() -> CrateSource {
    CrateSource {
        id: siros_paso::CrateModule::ID,
        messages: siros_paso::CrateModule::messages(),
        english: siros_paso::CrateModule::ENGLISH,
        german: GERMAN_PASO,
    }
}

fn qes() -> CrateSource {
    CrateSource {
        id: siros_qes::CrateModule::ID,
        messages: siros_qes::CrateModule::messages(),
        english: siros_qes::CrateModule::ENGLISH,
        german: GERMAN_QES,
    }
}

/// Catches a crate module that misses a message, or a text its declaration refuses, in either
/// language; the German source short of its first key shows the check is whole.
#[test]
fn each_crate_module_loads_whole_in_english_and_german() {
    for source in [CrateSource::openid4vp(), paso(), qes()] {
        let module = source.load().expect("the module loads");
        let tags: Vec<&str> = module.locales().map(LocaleTag::as_str).collect();
        assert_eq!(tags, ["en", "de"], "{:?}", source.id);
        let lines: Vec<&str> = source.german.lines().collect();
        let at = lines
            .iter()
            .position(|line| line.contains(" = "))
            .expect("a message");
        let key = lines[at].split(" =").next().expect("a key").to_owned();
        let kept: Vec<&str> = [&lines[..at], &lines[at + 1..]].concat();
        let short = CrateSource {
            german: Box::leak(kept.join("\n").into_boxed_str()),
            ..source
        };
        match short.load() {
            Err(ModuleError::Missing {
                key: missing,
                locale,
            }) => {
                assert!(
                    missing.ends_with(&key) && locale == "de",
                    "{missing} in {locale}"
                );
            }
            other => panic!("a German source without {key}: {other:?}"),
        }
    }
}

/// The texts of the tables at `f7f6c55`, each with its English and German: the oracle the
/// modules' rendering answers to.
fn tables() -> Vec<(Text, &'static str, &'static str)> {
    fn row(
        message: &dyn Explain,
        en: &'static str,
        de: &'static str,
    ) -> (Text, &'static str, &'static str) {
        (Text::of(message), en, de)
    }
    vec![
        row(&WalletText::Deny, "Cancel", "Abbrechen"),
        row(&WalletText::Share, "Share", "Teilen"),
        row(&WalletText::None, "None", "Keine"),
        row(&WalletText::Credential, "Credential", "Nachweis"),
        row(&WalletText::RequestTitle, "Share your data", "Daten teilen"),
        row(&WalletText::Yes, "Yes", "Ja"),
        row(&WalletText::No, "No", "Nein"),
        row(&Frequency::Intraday, "intraday", "untertägig"),
        row(&Frequency::Daily, "daily", "täglich"),
        row(&Frequency::Weekly, "weekly", "wöchentlich"),
        row(
            &Frequency::EveryTwoWeeks,
            "every two weeks",
            "alle zwei Wochen",
        ),
        row(&Frequency::TwiceAMonth, "twice a month", "zweimal im Monat"),
        row(&Frequency::Monthly, "monthly", "monatlich"),
        row(
            &Frequency::EveryTwoMonths,
            "every two months",
            "alle zwei Monate",
        ),
        row(&Frequency::Quarterly, "quarterly", "vierteljährlich"),
        row(
            &Frequency::EveryFourMonths,
            "every four months",
            "alle vier Monate",
        ),
        row(&Frequency::TwiceAYear, "twice a year", "halbjährlich"),
        row(&Frequency::Yearly, "yearly", "jährlich"),
        row(
            &Frequency::EveryTwoYears,
            "every two years",
            "alle zwei Jahre",
        ),
        row(
            &MandateLabel::MandateId,
            "Mandate reference",
            "Mandatsreferenz",
        ),
        row(
            &MandateLabel::Mandatee,
            "Authorized party",
            "Bevollmächtigte Partei",
        ),
        row(
            &MandateLabel::Action,
            "Authorized action",
            "Erlaubte Handlung",
        ),
        row(&MandateLabel::Conditions, "Conditions", "Bedingungen"),
        row(
            &MandateLabel::MaxAmount,
            "Maximum amount per use",
            "Höchstbetrag pro Nutzung",
        ),
        row(
            &MandateLabel::MaxCount,
            "Maximum uses",
            "Höchstzahl der Nutzungen",
        ),
        row(&MandateLabel::Period, "Per period", "Zeitraum"),
        row(&MandateLabel::ValidFrom, "Valid from", "Gültig ab"),
        row(&MandateLabel::ValidUntil, "Valid until", "Gültig bis"),
        row(&MandateLabel::Amount, "Amount", "Betrag"),
        row(&MandateLabel::Payee, "Payee", "Empfänger"),
        row(
            &MandateLabel::PayeeLogo,
            "Payee logo",
            "Logo des Empfängers",
        ),
        row(
            &Title::Transaction,
            "Confirm Transaction",
            "Transaktion bestätigen",
        ),
        row(
            &Title::Payment,
            "Payment Confirmation",
            "Zahlungsbestätigung",
        ),
        row(
            &Title::DataSharing,
            "Authorize Data Sharing",
            "Datenfreigabe erlauben",
        ),
        row(
            &Title::GenericPayment,
            "Confirm Payment",
            "Zahlung bestätigen",
        ),
        row(
            &Title::AccountDelegate,
            "Authorize Account Delegate",
            "Kontovollmacht erteilen",
        ),
        row(
            &Title::RecurringPayment,
            "Authorize Recurring Payment",
            "Wiederkehrende Zahlung erlauben",
        ),
        row(
            &Title::AgentPurchase,
            "Authorize Agent Purchase",
            "Agentenkauf erlauben",
        ),
        row(&Title::Mandate, "Authorize Mandate", "Mandat erteilen"),
        row(&Confirm::Confirm, "Confirm", "Bestätigen"),
        row(&Confirm::AllowSharing, "Authorize", "Erlauben"),
        row(&Confirm::Pay, "Pay", "Bezahlen"),
        row(
            &Confirm::Delegate,
            "Authorize Delegate",
            "Vollmacht erteilen",
        ),
        row(&Confirm::Mandate, "Authorize Mandate", "Mandat erteilen"),
        row(&Confirm::Agent, "Authorize Agent", "Agent erlauben"),
        row(&Confirm::Authorize, "Authorize", "Erteilen"),
        row(
            &Section::PaymentDetails,
            "Payment Details",
            "Zahlungsdetails",
        ),
        row(
            &Section::FirstCollection,
            "First Collection",
            "Erste Abbuchung",
        ),
        row(&Section::Payment, "Payment", "Zahlung"),
        row(
            &QesText::TitleSignatures,
            "Approve qualified signatures",
            "Qualifizierte Signaturen freigeben",
        ),
        row(
            &QesText::TitleSeals,
            "Approve qualified seals",
            "Qualifizierte Siegel freigeben",
        ),
        row(&QesText::Confirm, "Approve", "Freigeben"),
        // f7f6c55 wrote what an approval creates and its framework as two texts, joined by a
        // space: one message holds both.
        row(
            &QesText::CreatesEidasSignatures,
            "Creates qualified electronic signatures under the EU eIDAS regulation",
            "Erstellt qualifizierte elektronische Signaturen nach der EU-eIDAS-Verordnung",
        ),
        row(
            &QesText::CreatesEidasSeals,
            "Creates qualified electronic seals under the EU eIDAS regulation",
            "Erstellt qualifizierte elektronische Siegel nach der EU-eIDAS-Verordnung",
        ),
        row(&QesText::Count, "Signatures", "Signaturen"),
        row(&QesText::Name, "Name", "Name"),
        row(
            &QesText::NoName,
            "This document has no name",
            "Dieses Dokument hat keinen Namen",
        ),
        row(
            &QesText::OneTimePassword,
            "One-time password",
            "Einmalpasswort",
        ),
        row(&QesText::Link, "Document link", "Dokument-Link"),
        row(
            &QesText::Embedded,
            "Included in the request",
            "In der Anfrage enthalten",
        ),
        row(&QesText::Integrity, "Integrity", "Integrität"),
        row(
            &QesText::Verified,
            "Checked automatically",
            "Automatisch geprüft",
        ),
        row(&QesText::Unverified, "Not checked", "Nicht geprüft"),
        row(
            &QesText::Section { document: 1 },
            "Document 1",
            "Dokument 1",
        ),
        row(
            &QesText::Section { document: 1234 },
            "Document 1234",
            "Dokument 1234",
        ),
    ]
}

/// Catches a module message that renders another text than the table held, in either language.
#[test]
fn the_modules_render_the_tables_texts() {
    let modules: Vec<Module> = [CrateSource::openid4vp(), paso(), qes()]
        .iter()
        .map(|source| source.load().expect("the module loads"))
        .chain([main_module().expect("the main module")])
        .collect();
    let app = App::new(&modules.iter().collect::<Vec<_>>()).expect("the package");
    let screen: Vec<ModuleId> = modules.iter().map(Module::id).collect();
    let env = |tag: &str| {
        Env::new(
            vec![LocaleTag::parse(tag).expect("a tag")],
            Vec::new(),
            OPTIONS,
            Vec::new(),
            Choice::First,
        )
        .expect("the configuration")
    };
    let (en, de) = (env("en"), env("de"));
    let english = app
        .renderer(screen.clone(), &en)
        .expect("an English renderer");
    let german = app.renderer(screen, &de).expect("a German renderer");
    let differences: Vec<String> = tables()
        .into_iter()
        .flat_map(|(text, en, de)| {
            [(&english, en), (&german, de)]
                .into_iter()
                .filter_map(move |(renderer, want)| {
                    let got = renderer.plain(&text).expect("the text renders");
                    (got != want).then(|| format!("{text:?}: {got:?}, the table {want:?}"))
                })
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(differences.is_empty(), "{differences:#?}");
}
