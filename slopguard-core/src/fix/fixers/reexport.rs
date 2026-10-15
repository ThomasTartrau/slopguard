//! Expand `pub use module::*;` into `pub use module::{A, B};`.
//!
//! The list is read from the module's source (an inline `mod` block, or the
//! `module.rs` / `module/mod.rs` file next to the current one), so it is exact
//! at fix time. The fixer gives up whenever the glob could export something the
//! source does not spell out: a `#[cfg]` item, a macro invocation that may
//! expand to items, a nested glob, a `pub(crate)` item the glob re-exports at
//! crate visibility, or a name another glob of the same scope also provides.

use std::collections::BTreeSet;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};

use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_core::{Doc, Node};
use ast_grep_language::SupportLang;

use super::syntax::{replace, source_of};
use super::{FixEnv, RawEdit};

/// The directory holding the files of the modules `file` declares: its own
/// directory for a crate root or a `mod.rs`, `<dir>/<stem>` otherwise.
fn module_dir(file: &Path) -> Option<PathBuf> {
    let parent = file.parent()?;
    let name = file.file_name()?.to_str()?;
    if matches!(name, "lib.rs" | "main.rs" | "mod.rs") {
        Some(parent.to_path_buf())
    } else {
        Some(parent.join(file.file_stem()?))
    }
}

/// A module located by source: the text holding it, the inline `mod` blocks
/// to walk down inside that text, and the directory of its child files.
#[derive(Clone)]
struct ModuleLoc {
    text: String,
    inline: Vec<String>,
    dir: Option<PathBuf>,
}

/// The visibility of an item: `None` for private, otherwise its text (`pub`,
/// `pub(crate)`, ...).
fn visibility<D: Doc>(item: &Node<'_, D>) -> Option<String> {
    item.children()
        .find(|c| c.kind() == "visibility_modifier")
        .map(|v| v.text().split_whitespace().collect())
}

/// The `mod <name>` items of `scope`, when exactly one exists.
fn child_module<'r, D: Doc>(scope: &Node<'r, D>, name: &str) -> Option<Node<'r, D>> {
    let mut found = scope
        .children()
        .filter(|c| c.kind() == "mod_item" && c.field("name").is_some_and(|n| n.text() == name));
    let module = found.next()?;
    found.next().is_none().then_some(module)
}

/// Walk down the inline `mod` blocks named by `path` from `root`.
fn descend<'r, D: Doc>(root: Node<'r, D>, path: &[String]) -> Option<Node<'r, D>> {
    path.iter().try_fold(root, |scope, name| {
        child_module(&scope, name)?.field("body")
    })
}

/// Whether a `mod` item carries a `#[path = ...]` attribute, which moves its
/// file away from the conventional location.
fn has_path_attribute<D: Doc>(module: &Node<'_, D>) -> bool {
    let mut current = module.prev();
    while let Some(prev) = current {
        if prev.kind() != "attribute_item" {
            break;
        }
        if prev.text().replace(' ', "").starts_with("#[path") {
            return true;
        }
        current = prev.prev();
    }
    false
}

/// Locate the module `segments` (relative to `from`), stepping into inline
/// blocks or reading `name.rs` / `name/mod.rs` from disk.
fn resolve(mut from: ModuleLoc, segments: &[String]) -> Option<ModuleLoc> {
    for segment in segments {
        let ast = SupportLang::Rust.ast_grep(&from.text);
        let scope = descend(ast.root(), &from.inline)?;
        let module = child_module(&scope, segment)?;
        if has_path_attribute(&module) {
            return None;
        }
        let dir = from.dir.as_ref().map(|d| d.join(segment));
        if module.field("body").is_some() {
            from.inline.push(segment.clone());
            from.dir = dir;
            continue;
        }
        let parent = from.dir.as_ref()?;
        let text = [
            parent.join(format!("{segment}.rs")),
            parent.join(segment).join("mod.rs"),
        ]
        .iter()
        .find_map(|file| read_to_string(file).ok())?;
        from = ModuleLoc {
            text,
            inline: Vec::new(),
            dir,
        };
    }
    Some(from)
}

/// The names a `use` argument binds: `None` when one of them is a glob or an
/// underscore import, which cannot be listed.
fn use_names<D: Doc>(argument: &Node<'_, D>, out: &mut BTreeSet<String>) -> Option<()> {
    match &*argument.kind() {
        "identifier" => {
            out.insert(argument.text().to_string());
        }
        "scoped_identifier" => {
            out.insert(argument.field("name")?.text().to_string());
        }
        "use_as_clause" => {
            let alias = argument.field("alias")?.text().to_string();
            if alias == "_" {
                return None;
            }
            out.insert(alias);
        }
        "scoped_use_list" | "use_list" => {
            let list = if argument.kind() == "use_list" {
                argument.clone()
            } else {
                argument.field("list")?
            };
            for item in list.named_children() {
                if item.kind() == "self" {
                    let path = argument.field("path")?;
                    let last = path.text().rsplit("::").next()?.to_string();
                    out.insert(last);
                } else {
                    use_names(&item, out)?;
                }
            }
        }
        _ => return None,
    }
    Some(())
}

/// Item kinds a glob import can bring in under the item's own name.
const NAMED_ITEMS: &[&str] = &[
    "function_item",
    "struct_item",
    "enum_item",
    "union_item",
    "trait_item",
    "type_item",
    "const_item",
    "static_item",
    "mod_item",
];

/// How [`exported_names`] treats what a glob may or may not bring in.
#[derive(Clone, Copy, PartialEq)]
enum Reading {
    /// The exact set, for the glob being expanded: a `#[cfg]` item or a
    /// restricted-visibility item (re-exported at crate visibility) makes it
    /// unknowable.
    Exact,
    /// A superset, for checking another glob of the same scope for overlap:
    /// those items count as exported.
    Superset,
}

/// Every name the visible items of `scope` bind, which is what a glob import
/// of the module brings in. `None` when that set cannot be read from the
/// source: anything outside the known item kinds (a macro call that may expand
/// to items, an `extern` block) makes it unknowable.
fn exported_names<D: Doc>(scope: &Node<'_, D>, reading: Reading) -> Option<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for item in scope.named_children() {
        let visible = match visibility(&item).as_deref() {
            None => false,
            Some("pub") => true,
            Some(_) if reading == Reading::Superset => true,
            Some(_) => return None,
        };
        let kind = item.kind();
        match &*kind {
            "line_comment"
            | "block_comment"
            | "inner_attribute_item"
            | "impl_item"
            | "macro_definition"
            | "empty_statement" => {}
            "attribute_item" => {
                let is_cfg = item.text().replace(' ', "").starts_with("#[cfg(");
                if is_cfg && reading == Reading::Exact {
                    return None;
                }
            }
            "use_declaration" => {
                if visible {
                    use_names(&item.field("argument")?, &mut names)?;
                }
            }
            kind if NAMED_ITEMS.contains(&kind) => {
                if visible {
                    names.insert(item.field("name")?.text().to_string());
                }
            }
            _ => return None,
        }
    }
    Some(names)
}

/// The names bound in `scope` by its own items and non-glob imports. A glob
/// does not re-export a name they bind in the same namespace, and namespaces
/// are not tracked here, so such a name blocks the fix.
fn local_names<D: Doc>(scope: &Node<'_, D>) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for item in scope.named_children() {
        if item.kind() == "use_declaration" {
            if let Some(argument) = item.field("argument") {
                let mut bound = BTreeSet::new();
                if use_names(&argument, &mut bound).is_some() {
                    names.extend(bound);
                }
            }
        } else if let Some(name) = item.field("name") {
            names.insert(name.text().to_string());
        }
    }
    names
}

/// The module segments a glob argument names, relative to the current module:
/// `None` for a path through `crate` or `super`.
fn glob_segments<D: Doc>(wildcard: &Node<'_, D>) -> Option<Vec<String>> {
    let path = wildcard.named_children().next()?;
    let segments: Vec<String> = path
        .text()
        .split("::")
        .map(|s| s.trim().to_string())
        .skip_while(|s| s == "self")
        .collect();
    let crosses_up = segments.iter().any(|s| s == "crate" || s == "super");
    (!segments.is_empty() && !crosses_up).then_some(segments)
}

pub(super) fn fix<D: Doc>(use_declaration: &Node<'_, D>, env: &FixEnv<'_>) -> Option<Vec<RawEdit>> {
    if visibility(use_declaration).as_deref() != Some("pub") {
        return None;
    }
    let wildcard = use_declaration.field("argument")?;
    if wildcard.kind() != "use_wildcard" {
        return None;
    }
    let scope = use_declaration.parent()?;
    let mut inline: Vec<String> = use_declaration
        .ancestors()
        .filter(|a| a.kind() == "mod_item")
        .filter_map(|m| m.field("name").map(|n| n.text().to_string()))
        .collect();
    inline.reverse();
    let dir = env
        .path
        .and_then(module_dir)
        .map(|dir| inline.iter().fold(dir, |d, name| d.join(name)));
    let here = ModuleLoc {
        text: source_of(use_declaration).to_string(),
        inline,
        dir,
    };
    let names_of = |glob: &Node<'_, D>, reading: Reading| -> Option<BTreeSet<String>> {
        let target = resolve(here.clone(), &glob_segments(glob)?)?;
        let ast = SupportLang::Rust.ast_grep(&target.text);
        exported_names(&descend(ast.root(), &target.inline)?, reading)
    };

    let names = names_of(&wildcard, Reading::Exact)?;
    if !local_names(&scope).is_disjoint(&names) {
        return None;
    }
    for other in scope.children().filter(|c| c.kind() == "use_declaration") {
        let Some(other_glob) = other
            .field("argument")
            .filter(|a| a.kind() == "use_wildcard")
        else {
            continue;
        };
        if other_glob.range() == wildcard.range() {
            continue;
        }
        if !names_of(&other_glob, Reading::Superset)?.is_disjoint(&names) {
            return None;
        }
    }
    if names.is_empty() {
        return None;
    }

    let path = wildcard.named_children().next()?.text().to_string();
    let list: Vec<_> = names.into_iter().collect();
    let expanded = match list.as_slice() {
        [single] => format!("{path}::{single}"),
        many => format!("{path}::{{{}}}", many.join(", ")),
    };
    let range = wildcard.range();
    Some(vec![replace(range.start, range.end, expanded)])
}
