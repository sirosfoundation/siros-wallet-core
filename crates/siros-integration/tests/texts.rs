//! The crate modules: each loads whole in English and in the test app's German, and renders the
//! texts the tables of `f7f6c55` (siros-wallet-core `f7f6c55`, imported from wallet-rs `f718dc3`)
//! held, in both languages (I31's clause on the tables).

use siros_explain::{
    Amount, Currency, Date, DateTime, Decimal, Explain, Fraction, Messages, ModuleId, Offset,
    Second, Text, Time, Value,
};
use siros_i18n::{Module, ModuleError};
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::rows::{Choice, Env, WalletText};
use siros_paso::frequency::Frequency;
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

/// The values f7f6c55's tables formatted, each with its English and German text there, and the
/// reason the rendering through siros-i18n differs where it does: CLDR 49's formats, whose
/// oracle is ICU4X 2.4 (I35, I36), in place of the tables' hand-made ones.
fn formatted_values() -> Vec<(Value, &'static str, &'static str, Option<&'static str>)> {
    let eur = Currency::from_code("EUR").expect("EUR");
    let jpy = Currency::from_code("JPY").expect("JPY");
    let date = |year, month, day| Date::new(year, month, day).expect("a date");
    let at = |hour, minute, second| {
        Time::new(
            hour,
            minute,
            Some(Second::new(second, Fraction::NONE).expect("a second")),
        )
        .expect("a time")
    };
    let amount = |units, scale, currency| {
        Value::Amount(Amount::new(
            Decimal::new(units, scale).expect("a decimal"),
            currency,
        ))
    };
    vec![
        (
            Value::Date(date(2026, 9, 2)),
            "2 Sep 2026",
            "02.09.2026",
            Some("CLDR en's medium date writes the month first and a comma before the year"),
        ),
        (
            Value::Time {
                at: at(10, 15, 30),
                offset: Some(Offset::new(0).expect("UTC")),
            },
            "10:15:30 UTC",
            "10:15:30 UTC",
            Some(
                "CLDR's medium time, the test app's length: en's 12-hour clock, and no zone, which the \
                 lengths long and full write",
            ),
        ),
        (
            Value::DateTime(DateTime::new(
                date(2026, 6, 2),
                at(10, 15, 30),
                Some(Offset::new(120).expect("an offset")),
            )),
            "2 Jun 2026, 10:15:30 UTC+02:00",
            "02.06.2026, 10:15:30 UTC+02:00",
            Some(
                "CLDR's medium date and time, the test app's length: en's month first and 12-hour \
                 clock, and no zone, which the lengths long and full write",
            ),
        ),
        (
            Value::Currency(eur),
            "EUR",
            "EUR",
            Some("CLDR's currency symbol in place of the code"),
        ),
        (
            amount(123_456_750, 2, eur),
            "€1,234,567.50",
            "1234567.50 EUR",
            Some(
                "CLDR de's currency format: grouped digits, a decimal comma, the symbol after them",
            ),
        ),
        (
            amount(10_000, 0, jpy),
            "10000 JPY",
            "10000 JPY",
            Some("CLDR's currency format: grouped digits and the currency's symbol"),
        ),
    ]
}

/// Catches a typed value that renders other than f7f6c55's table without a classed reason, and a
/// reason the rendering no longer needs.
#[test]
fn the_tables_formatted_values_differ_only_where_classed() {
    let modules: Vec<Module> = vec![main_module().expect("the main module")];
    let app = App::new(&modules.iter().collect::<Vec<_>>()).expect("the package");
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
    let mut unclassed = Vec::new();
    for (value, table_en, table_de, reason) in formatted_values() {
        let text = Text::Value(value);
        let got = [
            app.plain(&en, &text).expect("renders"),
            app.plain(&de, &text).expect("renders"),
        ];
        let differs = got != [table_en, table_de];
        if differs != reason.is_some() {
            unclassed.push(format!(
                "{text:?}: {got:?}, the table [{table_en:?}, {table_de:?}], classed {reason:?}"
            ));
        }
    }
    assert!(unclassed.is_empty(), "{unclassed:#?}");
}
