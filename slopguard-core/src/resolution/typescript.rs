//! TypeScript import support: extract `import ... from "x"` and `require("x")`
//! from a parsed file, and resolve a module specifier against `package.json`, a
//! relative path on disk, a Node builtin, or a tsconfig path alias.

use std::path::{Path, PathBuf};

use ast_grep_core::{AstGrep, Doc};

use super::manifest::ManifestResolver;
use super::{first_line, FileImports, ImportRef, LanguageSupport};

/// Node.js builtin modules, resolved without a `package.json` entry. Any
/// `node:`-prefixed specifier is also a builtin.
const NODE_BUILTINS: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "sys",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

/// TypeScript source file extensions tried when resolving a relative import.
const TS_EXTENSIONS: &[&str] = &["ts", "tsx", "d.ts", "js", "jsx", "mjs", "cjs"];

fn is_node_builtin(spec: &str) -> bool {
    spec.strip_prefix("node:").is_some() || NODE_BUILTINS.contains(&spec)
}

/// The package name a bare TypeScript specifier belongs to. `lodash/fp` ->
/// `lodash`, `@scope/pkg/sub` -> `@scope/pkg`.
fn ts_package_name(spec: &str) -> String {
    if let Some(scoped) = spec.strip_prefix('@') {
        let mut parts = scoped.splitn(3, '/');
        match (parts.next(), parts.next()) {
            (Some(scope), Some(name)) => format!("@{scope}/{name}"),
            _ => spec.to_string(),
        }
    } else {
        spec.split('/').next().unwrap_or(spec).to_string()
    }
}

/// Strip a single pair of surrounding quotes from a string literal's text.
fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' || first == b'\'' || first == b'`') && last == first {
            return text[1..text.len() - 1].to_string();
        }
    }
    text.to_string()
}

/// Whether a relative TypeScript import resolves to a file on disk. Tries the
/// specifier as-is, with each source extension appended, and as a directory
/// `index.*`.
fn relative_ts_resolves(file_dir: &Path, spec: &str) -> bool {
    let base = file_dir.join(spec);
    if base.is_file() {
        return true;
    }
    for ext in TS_EXTENSIONS {
        if PathBuf::from(format!("{}.{ext}", base.display())).is_file() {
            return true;
        }
    }
    for ext in TS_EXTENSIONS {
        if base.join(format!("index.{ext}")).is_file() {
            return true;
        }
    }
    false
}

/// TypeScript import support.
pub struct TypeScript;

impl LanguageSupport for TypeScript {
    /// Collect the imports of one parsed TypeScript file: `import ... from "x"`
    /// and `require("x")`. Statement-level `import type` and `export ... from`
    /// are skipped, so type-only imports and re-exports are never reported.
    fn extract_imports<D: Doc>(&self, root: &AstGrep<D>) -> FileImports {
        let mut imports = Vec::new();
        for node in root.root().dfs() {
            match &*node.kind() {
                "import_statement" => {
                    if node.text().trim_start().starts_with("import type") {
                        continue;
                    }
                    let Some(source) = node.field("source") else {
                        continue;
                    };
                    let start = node.start_pos();
                    let end = node.end_pos();
                    imports.push(ImportRef {
                        specifier: unquote(&source.text()),
                        line: start.line() + 1,
                        column: start.byte_point().1 + 1,
                        end_line: end.line() + 1,
                        end_column: end.byte_point().1 + 1,
                        matched_text: first_line(&node.text()),
                    });
                }
                "call_expression" => {
                    let Some(func) = node.field("function") else {
                        continue;
                    };
                    if func.text().as_ref() != "require" {
                        continue;
                    }
                    let Some(args) = node.field("arguments") else {
                        continue;
                    };
                    let Some(literal) = args.children().find(|c| c.kind().as_ref() == "string")
                    else {
                        continue;
                    };
                    let start = node.start_pos();
                    let end = node.end_pos();
                    imports.push(ImportRef {
                        specifier: unquote(&literal.text()),
                        line: start.line() + 1,
                        column: start.byte_point().1 + 1,
                        end_line: end.line() + 1,
                        end_column: end.byte_point().1 + 1,
                        matched_text: first_line(&node.text()),
                    });
                }
                _ => {}
            }
        }
        FileImports {
            imports,
            local_names: Vec::new(),
        }
    }

    /// Whether a TypeScript import resolves against `package.json`, a relative
    /// path on disk, a Node builtin, or a tsconfig path alias. `local_names` is
    /// unused for TypeScript.
    fn resolves(
        &self,
        import: &ImportRef,
        _local_names: &[String],
        file_dir: &Path,
        manifests: &mut ManifestResolver,
    ) -> bool {
        let spec = import.specifier.as_str();
        if spec == "." || spec == ".." || spec.starts_with("./") || spec.starts_with("../") {
            return relative_ts_resolves(file_dir, spec);
        }
        if is_node_builtin(spec) || manifests.ts_alias_matches(file_dir, spec) {
            return true;
        }
        match manifests.package_json_deps(file_dir) {
            Some(deps) => deps.contains(&ts_package_name(spec)),
            None => true,
        }
    }
}
