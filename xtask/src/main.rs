//! The workspace's build gates, run as `cargo xtask <command>`:
//!
//! - `builds`: each build of `xtask/builds.json` (the crates an app depends on, each with the
//!   features it turns on) compiles none of the crates and crate features its row excludes, each
//!   crate its row lists as exact with those features alone, fewer crates than its row's bound,
//!   and another set of crates than the build its row names. A row's `matcher` is the build of
//!   its own crates, held to its build's exclusions and its own, and to its own exact crates. A
//!   build is a probe package, written under `target/xtask/`, that depends on its crates; `cargo
//!   tree -e normal` lists what it compiles, over the workspace's lock file, each crate counted
//!   once per version.
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

/// A build: the crates an app depends on, the crates, or `crate/feature` pairs, it must not
/// compile, the crates it compiles with exactly the features listed, the count of crates it stays
/// below, and the build whose set of crates it differs from.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Build {
    name: String,
    crates: Vec<Dependency>,
    forbid: Vec<String>,
    exact: Vec<Dependency>,
    fewer_than: Option<usize>,
    differs_from: Option<String>,
    matcher: Option<Matcher>,
}

/// A build's matcher: its crates (the core and the plug-ins without `resolve`, siros-credman),
/// what it compiles none of beside its build's exclusions, and the crates it compiles with exactly
/// the features listed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Matcher {
    crates: Vec<Dependency>,
    forbid: Vec<String>,
    exact: Vec<Dependency>,
}

/// What one probe compiles: its crates, each once, and each crate's features.
struct Tree {
    crates: Vec<(String, String)>,
    features: Vec<(String, String)>,
}

impl Tree {
    /// The tree of a probe's manifest.
    fn of(manifest: &Path) -> Result<Self, Failure> {
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
        Ok(Self {
            crates: compiled(&tree("normal")?),
            features: enabled(&tree("normal,features")?),
        })
    }

    /// The excluded crates and `crate/feature` pairs it compiles.
    fn forbidden<'b>(&self, forbid: &'b [String]) -> Vec<&'b str> {
        forbid
            .iter()
            .filter(|forbidden| match forbidden.split_once('/') {
                Some(pair) => self
                    .features
                    .iter()
                    .any(|(name, feature)| (name.as_str(), feature.as_str()) == pair),
                None => self.crates.iter().any(|(name, _)| name == *forbidden),
            })
            .map(String::as_str)
            .collect()
    }

    /// Each exact crate it compiles with other features, with the features it compiles.
    fn inexact(&self, exact: &[Dependency]) -> Vec<String> {
        exact
            .iter()
            .filter_map(|exact| {
                let mut compiled: Vec<&str> = self
                    .features
                    .iter()
                    .filter(|(name, _)| *name == exact.name)
                    .map(|(_, feature)| feature.as_str())
                    .collect();
                compiled.sort_unstable();
                let mut want: Vec<&str> = exact.features.iter().map(String::as_str).collect();
                want.sort_unstable();
                (compiled != want).then(|| format!("{} [{}]", exact.name, compiled.join(", ")))
            })
            .collect()
    }
}

/// `n of m`, with the failing entries named.
fn listed(found: &[impl AsRef<str>], of: usize) -> String {
    let named: Vec<&str> = found.iter().map(AsRef::as_ref).collect();
    if named.is_empty() {
        format!("0 of {of}")
    } else {
        format!("{} of {of}: {}", named.len(), named.join(", "))
    }
}

/// A crate and features: one a build depends on, without its default features, with the features
/// it turns on; or one a build compiles with these features and no other.
#[derive(Clone, Deserialize)]
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

/// Each build's tree against its row: none of its excluded crates, each exact crate with its
/// features alone, fewer crates than its bound, another set than the build it names; its
/// matcher's tree none of the excluded crates and each of its exact crates with its features
/// alone; true when every build holds.
fn builds(workspace: &Workspace) -> Result<bool, Failure> {
    let table = workspace.table()?;
    let mut compiled_sets: Vec<(&str, Vec<(String, String)>)> = Vec::new();
    let mut holds = true;
    for (place, build) in table.builds.iter().enumerate() {
        let tree = Tree::of(&probe(workspace, &format!("build-{place}"), &build.crates)?)?;
        let found = tree.forbidden(&build.forbid);
        let inexact = tree.inexact(&build.exact);
        let crates = tree.crates;
        let bounded = build.fewer_than.is_none_or(|bound| crates.len() < bound);
        let distinct = match &build.differs_from {
            None => true,
            Some(other) => {
                let (_, theirs) = compiled_sets
                    .iter()
                    .find(|(name, _)| name == other)
                    .ok_or_else(|| {
                        Failure::Read(format!(
                            "{} differs from {other}, which no earlier row names",
                            build.name
                        ))
                    })?;
                *theirs != crates
            }
        };
        println!(
            "build {}: {} crates{}; forbidden {}; inexact {}{}",
            build.name,
            crates.len(),
            build
                .fewer_than
                .map(|bound| format!(" (fewer than {bound}: {})", verdict(bounded)))
                .unwrap_or_default(),
            listed(&found, build.forbid.len()),
            listed(&inexact, build.exact.len()),
            build
                .differs_from
                .as_ref()
                .map(|other| format!("; differs from {other}: {}", verdict(distinct)))
                .unwrap_or_default(),
        );
        holds &= found.is_empty() && inexact.is_empty() && bounded && distinct;
        if let Some(matcher) = &build.matcher {
            let tree = Tree::of(&probe(
                workspace,
                &format!("matcher-{place}"),
                &matcher.crates,
            )?)?;
            let forbid: Vec<String> = build
                .forbid
                .iter()
                .chain(&matcher.forbid)
                .cloned()
                .collect();
            let found = tree.forbidden(&forbid);
            let inexact = tree.inexact(&matcher.exact);
            println!(
                "build {} matcher: {} crates; forbidden {}; inexact {}",
                build.name,
                tree.crates.len(),
                listed(&found, forbid.len()),
                listed(&inexact, matcher.exact.len()),
            );
            holds &= found.is_empty() && inexact.is_empty();
        }
        compiled_sets.push((build.name.as_str(), crates));
    }
    Ok(holds)
}

/// Writes the probe package of a build under `target/xtask/`, over the workspace's lock file;
/// its manifest's path.
fn probe(
    workspace: &Workspace,
    directory: &str,
    crates: &[Dependency],
) -> Result<PathBuf, Failure> {
    let directory = workspace.root.join("target").join("xtask").join(directory);
    let source = directory.join("src");
    fs::create_dir_all(&source).map_err(|e| Failure::Io(source.clone(), e))?;
    let mut manifest = format!(
        "[package]\nname = \"{PROBE}\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[dependencies]\n"
    );
    for dependency in crates {
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
