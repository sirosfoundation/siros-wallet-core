//! The workspace's build gates, run as `cargo xtask <command>`:
//!
//! - `builds`: each build of `xtask/builds.json` (the crates an app depends on, each with the
//!   features it turns on) compiles none of the crates and crate features its row excludes. A
//!   build is a probe package, written under `target/xtask/`, that depends on its crates; `cargo
//!   tree -e normal` lists what it compiles, over the workspace's lock file.
//! - `alone`: each crate the table lists builds alone, with and without its default features, and
//!   `cargo tree -e normal` of it names exactly the workspace crates its row gives.
//!
//! Each command prints one line per row and exits with failure when a row fails. The table names
//! the crates; the code names none.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Deserialize;

/// The table: the builds and the crates that stand alone.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    builds: Vec<Build>,
    alone: Vec<Alone>,
}

/// A build: the crates an app depends on, and the crates, or `crate/feature` pairs, it must not
/// compile.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Build {
    name: String,
    crates: Vec<Dependency>,
    forbid: Vec<String>,
}

/// A crate a build depends on, without its default features, with the features it turns on.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Dependency {
    name: String,
    features: Vec<String>,
}

/// A crate that stands alone, and the workspace crates its normal dependencies name.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Alone {
    name: String,
    names: Vec<String>,
}

/// Why a command could not judge.
#[derive(Debug)]
enum Failure {
    /// A file could not be read or written.
    Io(PathBuf, std::io::Error),
    /// Cargo could not run, or refused.
    Cargo(String),
    /// The table or Cargo's output does not read.
    Read(String),
    /// The command line names no command.
    Usage,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, cause) => write!(f, "{}: {cause}", path.display()),
            Self::Cargo(text) => write!(f, "cargo: {text}"),
            Self::Read(text) => write!(f, "{text}"),
            Self::Usage => write!(f, "usage: cargo xtask builds|alone"),
        }
    }
}

/// The workspace: its root and its members, each with its directory.
struct Workspace {
    root: PathBuf,
    members: Vec<(String, PathBuf)>,
}

fn main() -> ExitCode {
    let command = std::env::args().nth(1);
    let outcome = Workspace::read().and_then(|workspace| match command.as_deref() {
        Some("builds") => builds(&workspace),
        Some("alone") => alone(&workspace),
        _ => Err(Failure::Usage),
    });
    match outcome {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(failure) => {
            eprintln!("xtask: {failure}");
            ExitCode::FAILURE
        }
    }
}

/// Cargo's output for the arguments, refused when it exits with failure.
fn cargo(args: &[&str]) -> Result<String, Failure> {
    let program = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(&program)
        .args(args)
        .output()
        .map_err(|e| Failure::Cargo(format!("{program}: {e}")))?;
    if output.status.success() {
        String::from_utf8(output.stdout).map_err(|e| Failure::Cargo(e.to_string()))
    } else {
        Err(Failure::Cargo(format!(
            "{} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

impl Workspace {
    /// The workspace `cargo metadata` describes.
    fn read() -> Result<Self, Failure> {
        let text = cargo(&["metadata", "--locked", "--no-deps", "--format-version", "1"])?;
        let metadata: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| Failure::Read(e.to_string()))?;
        let root = metadata
            .get("workspace_root")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Failure::Read("metadata without workspace_root".to_owned()))?;
        let packages = metadata
            .get("packages")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| Failure::Read("metadata without packages".to_owned()))?;
        let members = packages
            .iter()
            .map(|package| {
                let name = package.get("name").and_then(serde_json::Value::as_str);
                let manifest = package
                    .get("manifest_path")
                    .and_then(serde_json::Value::as_str)
                    .map(Path::new)
                    .and_then(Path::parent);
                match (name, manifest) {
                    (Some(name), Some(directory)) => Ok((name.to_owned(), directory.to_path_buf())),
                    _ => Err(Failure::Read(
                        "a package without its name or manifest".to_owned(),
                    )),
                }
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            root: PathBuf::from(root),
            members,
        })
    }

    /// The table beside this crate's manifest.
    fn table(&self) -> Result<Table, Failure> {
        let path = self.root.join("xtask").join("builds.json");
        let text = fs::read_to_string(&path).map_err(|e| Failure::Io(path.clone(), e))?;
        serde_json::from_str(&text).map_err(|e| Failure::Read(format!("{}: {e}", path.display())))
    }

    /// A member's directory.
    fn directory(&self, name: &str) -> Result<&Path, Failure> {
        self.members
            .iter()
            .find(|(member, _)| member == name)
            .map(|(_, directory)| directory.as_path())
            .ok_or_else(|| Failure::Read(format!("{name} is no workspace member")))
    }
}

/// The probe package's name, which the trees leave out.
const PROBE: &str = "xtask-build-probe";

/// Each build's tree against its excluded crates; true when every build compiles none of them.
fn builds(workspace: &Workspace) -> Result<bool, Failure> {
    let table = workspace.table()?;
    let mut holds = true;
    for (place, build) in table.builds.iter().enumerate() {
        let manifest = probe(workspace, place, build)?;
        let manifest = manifest.to_string_lossy();
        let tree = |edges: &str| {
            cargo(&[
                "tree",
                "--offline",
                "-e",
                edges,
                "--prefix",
                "none",
                "--manifest-path",
                &manifest,
            ])
        };
        let crates = compiled(&tree("normal")?);
        let features = enabled(&tree("normal,features")?);
        let found: Vec<&str> = build
            .forbid
            .iter()
            .filter(|forbidden| match forbidden.split_once('/') {
                Some(pair) => features
                    .iter()
                    .any(|(name, feature)| (name.as_str(), feature.as_str()) == pair),
                None => crates.iter().any(|(name, _)| name == *forbidden),
            })
            .map(String::as_str)
            .collect();
        println!(
            "build {}: {} crates; forbidden {} of {}{}",
            build.name,
            crates.len(),
            found.len(),
            build.forbid.len(),
            if found.is_empty() {
                String::new()
            } else {
                format!(": {}", found.join(", "))
            }
        );
        holds &= found.is_empty();
    }
    Ok(holds)
}

/// Writes the probe package of a build under `target/xtask/`, over the workspace's lock file;
/// its manifest's path.
fn probe(workspace: &Workspace, place: usize, build: &Build) -> Result<PathBuf, Failure> {
    let directory = workspace
        .root
        .join("target")
        .join("xtask")
        .join(format!("build-{place}"));
    let source = directory.join("src");
    fs::create_dir_all(&source).map_err(|e| Failure::Io(source.clone(), e))?;
    let mut manifest = format!(
        "[package]\nname = \"{PROBE}\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[dependencies]\n"
    );
    for dependency in &build.crates {
        let path = workspace.directory(&dependency.name)?;
        let features: Vec<String> = dependency
            .features
            .iter()
            .map(|feature| format!("\"{feature}\""))
            .collect();
        manifest.push_str(&format!(
            "{} = {{ path = {:?}, default-features = false, features = [{}] }}\n",
            dependency.name,
            path.to_string_lossy(),
            features.join(", ")
        ));
    }
    manifest.push_str("\n[workspace]\n");
    let write = |path: PathBuf, text: &str| {
        fs::write(&path, text).map_err(|e| Failure::Io(path.clone(), e))
    };
    write(source.join("lib.rs"), "")?;
    write(directory.join("Cargo.toml"), &manifest)?;
    let lock = workspace.root.join("Cargo.lock");
    let _bytes: u64 =
        fs::copy(&lock, directory.join("Cargo.lock")).map_err(|e| Failure::Io(lock, e))?;
    Ok(directory.join("Cargo.toml"))
}

/// The crates a `cargo tree --prefix none` lists, by name and version, each once, the probe left
/// out.
fn compiled(tree: &str) -> Vec<(String, String)> {
    let mut crates: Vec<(String, String)> = tree
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            Some((words.next()?.to_owned(), words.next()?.to_owned()))
        })
        .filter(|(name, _)| name != PROBE)
        .collect();
    crates.sort();
    crates.dedup();
    crates
}

/// The features a `cargo tree -e features --prefix none` lists as `name feature "feature"`, each
/// once.
fn enabled(tree: &str) -> Vec<(String, String)> {
    let mut features: Vec<(String, String)> = tree
        .lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once(" feature \"")?;
            let feature = rest.split_once('"')?.0;
            Some((name.to_owned(), feature.to_owned()))
        })
        .collect();
    features.sort();
    features.dedup();
    features
}

/// Each listed crate alone; true when each builds with and without its default features and its
/// tree names exactly its row's workspace crates.
fn alone(workspace: &Workspace) -> Result<bool, Failure> {
    let table = workspace.table()?;
    let mut holds = true;
    for row in &table.alone {
        let builds = |extra: &[&str]| {
            let mut args = vec!["check", "--locked", "--quiet", "-p", row.name.as_str()];
            args.extend_from_slice(extra);
            cargo(&args).is_ok()
        };
        let default = builds(&[]);
        let bare = builds(&["--no-default-features"]);
        let tree = cargo(&[
            "tree", "--locked", "-e", "normal", "--prefix", "none", "-p", &row.name,
        ])?;
        let mut named: Vec<String> = compiled(&tree)
            .into_iter()
            .map(|(name, _)| name)
            .filter(|name| {
                *name != row.name && workspace.members.iter().any(|(member, _)| member == name)
            })
            .collect();
        named.dedup();
        let mut want = row.names.clone();
        want.sort();
        let names_hold = named == want;
        println!(
            "alone {}: default {}, no default features {}, names {}{}",
            row.name,
            verdict(default),
            verdict(bare),
            verdict(names_hold),
            if names_hold {
                String::new()
            } else {
                format!(" (tree {named:?}, table {want:?})")
            }
        );
        holds &= default && bare && names_hold;
    }
    Ok(holds)
}

/// A check's word.
const fn verdict(holds: bool) -> &'static str {
    if holds { "holds" } else { "FAILS" }
}
