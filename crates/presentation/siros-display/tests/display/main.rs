//! The tests of siros-display, in one binary.

#[cfg(feature = "credential")]
mod known_answer;
mod locale;
mod proof;
mod purpose;
#[cfg(feature = "credential")]
mod strip;
mod text;
