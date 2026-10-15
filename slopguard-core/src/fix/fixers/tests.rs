use std::fs;
use std::path::{Path, PathBuf};

use tempfile::{tempdir, TempDir};

use crate::config::Config;
use crate::fix::{fix_paths, fix_snippet};
use crate::rule::{load_builtin_rules, Language, Rule};

fn builtin(id: &str) -> Rule {
    load_builtin_rules()
        .expect("builtin rules load")
        .into_iter()
        .find(|r| r.id.as_str() == id && r.language == Language::Rust)
        .unwrap_or_else(|| panic!("builtin rule {id}"))
}

fn fixed(id: &str, source: &str) -> String {
    fix_snippet(&builtin(id), source).expect("fix_snippet")
}

/// Assert that `id` leaves `source` untouched.
fn declines(id: &str, source: &str) {
    assert_eq!(
        fixed(id, source),
        source,
        "{id} should not rewrite:\n{source}"
    );
}

/// A crate in a temp dir: `Cargo.toml` with `manifest`, plus `files`.
fn project(manifest: &str, files: &[(&str, &str)]) -> TempDir {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), manifest).unwrap();
    for (name, content) in files {
        let path = dir.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
    dir
}

/// Run `--fix` with `rules` over the whole project, returning the new content
/// of `file` (unchanged when nothing was rewritten).
fn fix_project(dir: &Path, rules: &[Rule], unsafe_fixes: bool, file: &str) -> String {
    let report = fix_paths(
        &[dir.to_path_buf()],
        rules,
        &Config::default(),
        None,
        dir,
        unsafe_fixes,
    )
    .unwrap();
    let target: PathBuf = dir.join(file);
    report
        .files
        .into_iter()
        .find(|f| f.path == target)
        .map(|f| f.fixed)
        .unwrap_or_else(|| fs::read_to_string(target).unwrap())
}

const STRUM_DERIVE: &str =
    "[package]\nname = \"p\"\n\n[dependencies]\nstrum = { version = \"0.27\", features = [\"derive\"] }\n";

const AS_STR: &str = "pub enum Kind {
    Alpha,
    BetaGamma,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alpha => \"alpha\",
            Self::BetaGamma => \"beta_gamma\",
        }
    }
}
";

const AS_STR_FIXED_BODY: &str = "    pub fn as_str(&self) -> &'static str {
        self.into()
    }";

// --- strum_enum_str -------------------------------------------------------

#[test]
fn strum_fix_needs_strum_derive_in_the_manifest() {
    let rules = [builtin("no-manual-enum-str")];

    let without = project("[package]\nname = \"p\"\n", &[("src/kind.rs", AS_STR)]);
    assert_eq!(
        fix_project(without.path(), &rules, false, "src/kind.rs"),
        AS_STR
    );

    let no_feature = project(
        "[package]\nname = \"p\"\n[dependencies]\nstrum = \"0.27\"\n",
        &[("src/kind.rs", AS_STR)],
    );
    assert_eq!(
        fix_project(no_feature.path(), &rules, false, "src/kind.rs"),
        AS_STR
    );

    let with = project(STRUM_DERIVE, &[("src/kind.rs", AS_STR)]);
    let out = fix_project(with.path(), &rules, false, "src/kind.rs");
    assert!(out.starts_with(
        "#[derive(strum::IntoStaticStr)]\n#[strum(serialize_all = \"snake_case\")]\npub enum Kind {"
    ));
    assert!(out.contains(AS_STR_FIXED_BODY), "{out}");
}

#[test]
fn strum_fix_reads_strum_macros_and_workspace_inheritance() {
    let rules = [builtin("no-manual-enum-str")];
    let macros = project(
        "[package]\nname = \"p\"\n[dependencies]\nstrum_macros = \"0.27\"\n",
        &[("src/kind.rs", AS_STR)],
    );
    let out = fix_project(macros.path(), &rules, false, "src/kind.rs");
    assert!(
        out.starts_with("#[derive(strum_macros::IntoStaticStr)]"),
        "{out}"
    );

    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"m\"]\n[workspace.dependencies]\nstrum = { version = \"0.27\", features = [\"derive\"] }\n",
    )
    .unwrap();
    fs::create_dir_all(dir.path().join("m/src")).unwrap();
    fs::write(
        dir.path().join("m/Cargo.toml"),
        "[package]\nname = \"m\"\n[dependencies]\nstrum = { workspace = true }\n",
    )
    .unwrap();
    fs::write(dir.path().join("m/src/kind.rs"), AS_STR).unwrap();
    let out = fix_project(dir.path(), &rules, false, "m/src/kind.rs");
    assert!(out.starts_with("#[derive(strum::IntoStaticStr)]"), "{out}");
}

#[test]
fn display_fix_is_unsafe_and_runs_only_with_unsafe_fixes() {
    let source = "use std::fmt::{self, Formatter};

pub enum Kind {
    Alpha,
    Beta,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Kind::Alpha => write!(f, \"alpha\"),
            Kind::Beta => write!(f, \"beta\"),
        }
    }
}

impl fmt::Debug for Other {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(\"other\")
    }
}
";
    let rules = [builtin("no-manual-display")];
    let dir = project(STRUM_DERIVE, &[("src/kind.rs", source)]);
    assert_eq!(
        fix_project(dir.path(), &rules, false, "src/kind.rs"),
        source
    );

    let out = fix_project(dir.path(), &rules, true, "src/kind.rs");
    assert_eq!(
        out,
        "use std::fmt;

#[derive(strum::Display)]
#[strum(serialize_all = \"snake_case\")]
pub enum Kind {
    Alpha,
    Beta,
}

impl fmt::Debug for Other {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(\"other\")
    }
}
"
    );
}

#[test]
fn display_and_as_str_on_one_enum_both_land() {
    let source = "pub enum Kind {
    Alpha,
    Beta,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alpha => \"alpha\",
            Self::Beta => \"beta\",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Alpha => \"alpha\",
            Self::Beta => \"beta\",
        })
    }
}
";
    let rules = [builtin("no-manual-enum-str"), builtin("no-manual-display")];
    let dir = project(STRUM_DERIVE, &[("src/kind.rs", source)]);
    let out = fix_project(dir.path(), &rules, true, "src/kind.rs");
    assert_eq!(out.matches("serialize_all").count(), 1, "{out}");
    assert!(
        out.contains("#[derive(strum::")
            && out.contains("strum::Display")
            && out.contains("strum::IntoStaticStr"),
        "{out}"
    );
    assert!(!out.contains("impl fmt::Display"), "{out}");
    assert!(out.contains(AS_STR_FIXED_BODY), "{out}");
}

#[test]
fn strum_fix_declines_what_the_derive_would_change() {
    let id = "no-manual-enum-str";
    // Escape sequence: the source text is not the value.
    declines(
        id,
        "enum K { A }\nimpl K {\n    fn as_str(&self) -> &'static str {\n        match self {\n            Self::A => \"a\\n\",\n        }\n    }\n}\n",
    );
    // A variant carrying data.
    declines(
        id,
        "enum K { A(u8), B }\nimpl K {\n    fn as_str(&self) -> &'static str {\n        match self {\n            Self::A => \"a\",\n            Self::B => \"b\",\n        }\n    }\n}\n",
    );
    // A strum attribute on a variant overrides its derived name.
    declines(
        id,
        "enum K {\n    #[strum(serialize = \"x\")]\n    A,\n}\nimpl K {\n    fn as_str(&self) -> &'static str {\n        match self {\n            Self::A => \"a\",\n        }\n    }\n}\n",
    );
    // The enum's own serialize_all would produce other strings.
    declines(
        id,
        "#[strum(serialize_all = \"kebab-case\")]\nenum K { AbCd }\nimpl K {\n    fn as_str(&self) -> &'static str {\n        match self {\n            Self::AbCd => \"ab_cd\",\n        }\n    }\n}\n",
    );
    // A new serialize_all would change what the existing EnumString parses.
    declines(
        id,
        "#[derive(strum::EnumString)]\nenum K { AbCd }\nimpl K {\n    fn as_str(&self) -> &'static str {\n        match self {\n            Self::AbCd => \"ab_cd\",\n        }\n    }\n}\n",
    );
    // The enum is declared in another module.
    declines(
        id,
        "mod inner { pub enum K { A } }\nimpl K {\n    fn as_str(&self) -> &'static str {\n        match self {\n            Self::A => \"a\",\n        }\n    }\n}\n",
    );
    // A generic enum.
    declines(
        id,
        "enum K<T> { A, B(T) }\nimpl<T> K<T> {\n    fn as_str(&self) -> &'static str {\n        match self {\n            Self::A => \"a\",\n        }\n    }\n}\n",
    );
    // A Display arm writing a format string with braces.
    declines(
        "no-manual-display",
        "enum K { A }\nimpl fmt::Display for K {\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\n        match self {\n            Self::A => write!(f, \"{{a}}\"),\n        }\n    }\n}\n",
    );
}

#[test]
fn strum_fix_reuses_an_existing_derive() {
    let out = fixed(
        "no-manual-enum-str",
        "use strum::IntoStaticStr;\n\n#[derive(IntoStaticStr)]\nenum K {\n    A,\n}\n\nimpl K {\n    fn as_str(&self) -> &'static str {\n        match self {\n            Self::A => \"A\",\n        }\n    }\n}\n",
    );
    assert_eq!(
        out,
        "use strum::IntoStaticStr;\n\n#[derive(IntoStaticStr)]\nenum K {\n    A,\n}\n\nimpl K {\n    fn as_str(&self) -> &'static str {\n        self.into()\n    }\n}\n"
    );
}

// --- merge_match_arms -----------------------------------------------------

#[test]
fn merges_onto_an_existing_or_pattern() {
    let out = fixed(
        "merge-identical-match-arms",
        "fn f(k: K) -> u8 {\n    match k {\n        K::A | K::B => 1,\n        K::C => 1,\n        _ => 0,\n    }\n}\n",
    );
    assert_eq!(
        out,
        "fn f(k: K) -> u8 {\n    match k {\n        K::A | K::B | K::C => 1,\n        _ => 0,\n    }\n}\n"
    );
}

#[test]
fn match_arm_merge_declines_bindings_guards_and_comments() {
    let id = "merge-identical-match-arms";
    declines(id, "fn f(e: E) {\n    match e {\n        E::A { id } => g(),\n        E::B { id } => g(),\n    }\n}\n");
    declines(id, "fn f(e: E) {\n    match e {\n        E::A(ref x) => g(),\n        E::B(ref x) => g(),\n    }\n}\n");
    declines(id, "fn f(n: u8) {\n    match n {\n        n @ 1..=2 => g(),\n        3 => g(),\n        _ => {}\n    }\n}\n");
    declines(id, "fn f(e: E) {\n    match e {\n        E::A => g(),\n        // B is rare\n        E::B => g(),\n    }\n}\n");
    declines(id, "fn f(e: E) {\n    match e {\n        E::A if ready() => g(),\n        E::B => g(),\n        _ => {}\n    }\n}\n");
}

// --- derive_clone ---------------------------------------------------------

#[test]
fn derive_clone_inserts_a_derive_below_other_attributes() {
    let out = fixed(
        "no-derivable-clone",
        "#[repr(C)]\nstruct P {\n    x: u8,\n}\n\nimpl Clone for P {\n    fn clone(&self) -> Self {\n        P { x: self.x }\n    }\n}\n\nfn main() {}\n",
    );
    assert_eq!(
        out,
        "#[repr(C)]\n#[derive(Clone)]\nstruct P {\n    x: u8,\n}\n\nfn main() {}\n"
    );
}

#[test]
fn derive_clone_declines_without_a_local_non_generic_struct() {
    let id = "no-derivable-clone";
    declines(id, "impl Clone for P {\n    fn clone(&self) -> Self {\n        Self { x: self.x.clone() }\n    }\n}\n");
    declines(
        id,
        "struct P<T> { x: T }\nimpl Clone for P {\n    fn clone(&self) -> Self {\n        Self { x: self.x.clone() }\n    }\n}\n",
    );
    declines(
        id,
        "#[derive(Clone)]\nstruct P { x: u8 }\nimpl Clone for P {\n    fn clone(&self) -> Self {\n        Self { x: self.x }\n    }\n}\n",
    );
}

// --- explicit_reexport ----------------------------------------------------

#[test]
fn reexport_reads_the_module_file() {
    let lib = "mod models;\nmod store;\n\npub use models::*;\npub use store::*;\n";
    let dir = project(
        "[package]\nname = \"p\"\n",
        &[
            ("src/lib.rs", lib),
            ("src/models.rs", "pub struct User;\npub(super) fn hidden() {}\nfn private() {}\npub use inner::Role as UserRole;\nmod inner { pub struct Role; }\n"),
            ("src/store/mod.rs", "pub trait Store {}\npub const LIMIT: u8 = 1;\npub mod sql;\n"),
            ("src/store/sql.rs", ""),
        ],
    );
    let rules = [builtin("no-glob-reexport")];
    let out = fix_project(dir.path(), &rules, false, "src/lib.rs");
    // models has a pub(super) item: the glob also re-exports it inside the
    // crate, so it stays a glob.
    assert_eq!(
        out,
        "mod models;\nmod store;\n\npub use models::*;\npub use store::{LIMIT, Store, sql};\n"
    );
}

#[test]
fn reexport_declines_ambiguous_or_unreadable_globs() {
    let rules = [builtin("no-glob-reexport")];
    let overlap = "mod a;\nmod b;\npub use a::*;\npub use b::*;\n";
    let dir = project(
        "[package]\nname = \"p\"\n",
        &[
            ("src/lib.rs", overlap),
            ("src/a.rs", "pub struct Shared;\n"),
            ("src/b.rs", "pub struct Shared;\npub struct OnlyB;\n"),
        ],
    );
    assert_eq!(
        fix_project(dir.path(), &rules, false, "src/lib.rs"),
        overlap
    );

    let id = "no-glob-reexport";
    declines(
        id,
        "mod m {\n    pub struct A;\n    make_items!();\n}\npub use m::*;\n",
    );
    declines(id, "mod m {\n    pub use other::*;\n}\npub use m::*;\n");
    declines(id, "pub use crate::m::*;\n");
    declines(id, "pub use serde::*;\n");
    declines(
        id,
        "mod m {\n    pub struct A;\n}\nstruct A;\npub use m::*;\n",
    );
}

#[test]
fn reexport_expands_a_nested_inline_module() {
    let out = fixed(
        "no-glob-reexport",
        "mod a {\n    pub mod b {\n        pub fn run() {}\n    }\n}\npub use a::b::*;\n",
    );
    assert_eq!(
        out,
        "mod a {\n    pub mod b {\n        pub fn run() {}\n    }\n}\npub use a::b::run;\n"
    );
}
