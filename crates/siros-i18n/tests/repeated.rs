//! Two crates that choose one scope register one id twice: `Context::check` refuses it first.

use siros_i18n::{CheckError, Context};

siros_i18n::scope!("i18n");

/// An error under siros-i18n's scope and one of its ids.
#[derive(Debug, thiserror::Error, siros_explain::Explain)]
#[error("a second error of siros-i18n's scope")]
#[explain(id = "load.syntax")]
#[expect(
    dead_code,
    reason = "its row is the fixture; the binary builds no value of it"
)]
struct Twice;

#[test]
fn check_refuses_an_id_two_crates_register() {
    assert_eq!(
        Context::new().check(),
        Err(CheckError::Repeated {
            id: "err.i18n.load.syntax".to_owned()
        })
    );
}
