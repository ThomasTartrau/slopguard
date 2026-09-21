//! Top-level scan orchestration: collect files, fan out per-file scans (cached
//! or not), assemble cross-file findings, and shape the [`ScanResult`].

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use ast_grep_language::SupportLang;
use rayon::prelude::*;

use crate::cache::{file_content_hash, rules_hash, CacheEntry, CacheStore};
use crate::config::Config;
use crate::cross_file::FileSymbols;
use crate::disable::unused_disable_findings;
use crate::finding::{CacheStats, Finding, ScanResult, ScanStats};
use crate::resolution::FileImports;
use crate::rule::{Rule, Severity};
use crate::test_filter::TestPaths;

use super::{
    append_cross_file, append_resolution, build_glob_set, compile_rules, explicit_files, scan_file,
    walk_files, CompiledRules, FileScan, ScanError,
};

/// Count errors and warnings in one pass.
pub fn count_severities(findings: &[Finding]) -> (usize, usize) {
    let mut errors = 0;
    let mut warnings = 0;
    for finding in findings {
        match finding.severity {
            Severity::Error => errors += 1,
            Severity::Warning => warnings += 1,
        }
    }
    (errors, warnings)
}

/// Sort findings by location and drop duplicates from overlapping rules.
fn normalize_findings(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| (&a.file, a.line, a.column).cmp(&(&b.file, b.line, b.column)));
    findings.dedup_by(|a, b| {
        a.rule_id == b.rule_id && a.file == b.file && a.line == b.line && a.column == b.column
    });
}

/// Scan an already-collected file list without touching the cache.
///
/// Symbol collection is driven by the active rules alone, never by
/// `run_cross_file`: a partial scan must still cache a complete contribution.
fn scan_collected(
    files: Vec<(PathBuf, SupportLang)>,
    compiled: &CompiledRules,
    run_cross_file: bool,
    apply_disable: bool,
) -> ScanResult {
    let (per_file, project) = compiled.engines(apply_disable);
    let collect_symbols = project.iter().any(|e| e.needs_symbols());
    let collect_imports = !compiled.resolution.is_empty();
    let scans: Vec<(PathBuf, FileScan)> = files
        .par_iter()
        .map(|(path, lang)| {
            let scan = scan_file(
                path,
                *lang,
                &per_file,
                &compiled.test_paths,
                collect_symbols,
                collect_imports,
                apply_disable,
            );
            (path.clone(), scan)
        })
        .collect();

    let mut findings: Vec<Finding> = Vec::new();
    let mut contributions: Vec<(PathBuf, FileSymbols)> = Vec::new();
    let mut import_contributions: Vec<(PathBuf, FileImports)> = Vec::new();
    for (path, scan) in scans {
        findings.extend(scan.findings);
        if collect_symbols {
            contributions.push((path.clone(), scan.symbols));
        }
        if collect_imports {
            import_contributions.push((path, scan.imports));
        }
    }
    append_cross_file(&mut findings, &project, run_cross_file, &contributions);
    append_resolution(
        &mut findings,
        compiled,
        &import_contributions,
        apply_disable,
    );
    normalize_findings(&mut findings);

    let (errors, warnings) = count_severities(&findings);

    ScanResult {
        findings,
        stats: ScanStats {
            errors,
            warnings,
            total: errors + warnings,
            files_scanned: files.len(),
            baseline_filtered: 0,
            diff_base: None,
            files_changed: None,
        },
        cache_stats: None,
    }
}

/// Scan an already-collected file list, reusing cached findings for files
/// whose content hash is unchanged.
///
/// `prune` drops cache entries that no longer correspond to a scanned file. A
/// partial scan must pass `false`: it never saw the other files, so their
/// entries are still valid.
fn scan_collected_cached(
    files: Vec<(PathBuf, SupportLang)>,
    compiled: &CompiledRules,
    rules: &[Rule],
    cache_dir: &Path,
    prune: bool,
    run_cross_file: bool,
) -> ScanResult {
    // The cached path always applies disable comments: the raw pass used by
    // `--report-unused-disable` runs uncached, so the cache only ever stores
    // suppressed findings.
    let (per_file, project) = compiled.engines(true);
    let collect_symbols = project.iter().any(|e| e.needs_symbols());
    let collect_imports = !compiled.resolution.is_empty();
    let current_rules_hash = rules_hash(rules);
    let store = CacheStore::with_dir(cache_dir.to_path_buf()).scoped_to_rules(&current_rules_hash);
    let rules_changed = store
        .check_rules_changed(&current_rules_hash)
        .unwrap_or(true);

    let file_contents: Vec<(PathBuf, SupportLang, Vec<u8>, String)> = files
        .into_iter()
        .filter_map(|(path, lang)| {
            let content = fs::read(&path).ok()?;
            let hash = file_content_hash(&content);
            Some((path, lang, content, hash))
        })
        .collect();

    let mut cached_count = 0usize;
    let mut changed_count = 0usize;
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut contributions: Vec<(PathBuf, FileSymbols)> = Vec::new();
    let mut import_contributions: Vec<(PathBuf, FileImports)> = Vec::new();

    struct FileWork {
        path: PathBuf,
        lang: SupportLang,
        hash: String,
    }

    let mut to_scan: Vec<FileWork> = Vec::new();

    for (path, lang, _content, hash) in file_contents.iter() {
        if !rules_changed {
            if let Some(entry) = store.get(hash) {
                cached_count += 1;
                all_findings.extend(entry.findings);
                if collect_symbols {
                    contributions.push((path.clone(), entry.symbols));
                }
                if collect_imports {
                    import_contributions.push((path.clone(), entry.imports));
                }
                continue;
            }
        }
        changed_count += 1;
        to_scan.push(FileWork {
            path: path.clone(),
            lang: *lang,
            hash: hash.clone(),
        });
    }

    let scanned: Vec<(PathBuf, String, FileScan)> = to_scan
        .par_iter()
        .map(|work| {
            let scan = scan_file(
                &work.path,
                work.lang,
                &per_file,
                &compiled.test_paths,
                collect_symbols,
                collect_imports,
                true,
            );
            (work.path.clone(), work.hash.clone(), scan)
        })
        .collect();

    for (path, hash, scan) in scanned {
        let entry = CacheEntry {
            findings: scan.findings,
            symbols: scan.symbols,
            imports: scan.imports,
        };
        store.put(&hash, &entry).ok();
        all_findings.extend(entry.findings);
        if collect_symbols {
            contributions.push((path.clone(), entry.symbols));
        }
        if collect_imports {
            import_contributions.push((path, entry.imports));
        }
    }

    // Cross-file and resolution evaluation are never cached: they re-run on every
    // scan (cross-file from the assembled index, resolution from the manifests on
    // disk, so a manifest edit is reflected even for an unchanged file).
    append_cross_file(&mut all_findings, &project, run_cross_file, &contributions);
    append_resolution(&mut all_findings, compiled, &import_contributions, true);

    if prune {
        let current_hashes: Vec<String> =
            file_contents.iter().map(|(_, _, _, h)| h.clone()).collect();
        store.cleanup(&current_hashes).ok();
    }

    normalize_findings(&mut all_findings);

    let (errors, warnings) = count_severities(&all_findings);

    let files_scanned = cached_count + changed_count;

    ScanResult {
        findings: all_findings,
        stats: ScanStats {
            errors,
            warnings,
            total: errors + warnings,
            files_scanned,
            baseline_filtered: 0,
            diff_base: None,
            files_changed: None,
        },
        cache_stats: Some(CacheStats {
            cached: cached_count,
            changed: changed_count,
        }),
    }
}

/// Scan the given paths for rule violations.
pub fn scan(paths: &[PathBuf], rules: &[Rule], config: &Config) -> Result<ScanResult, ScanError> {
    let test_paths = TestPaths::new(&config.scan.test_paths)?;
    let compiled = compile_rules(rules, test_paths)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    Ok(scan_collected(
        walk_files(paths, &ignores),
        &compiled,
        true,
        true,
    ))
}

/// Scan with file-level caching. Files whose content hash matches a cached
/// entry (and whose rules have not changed) return cached findings without
/// reparsing.
///
/// `cache_dir` is the directory where cache files are stored. When a custom
/// cache directory is specified (via `--cache-dir`, `SLOPGUARD_CACHE_DIR`,
/// or `scan.cache_dir` in config), pass it directly. Otherwise pass the
/// project root and use `CacheStore::new` which appends `.slopguard-cache`.
pub fn scan_cached(
    paths: &[PathBuf],
    rules: &[Rule],
    config: &Config,
    cache_dir: &Path,
) -> Result<ScanResult, ScanError> {
    let test_paths = TestPaths::new(&config.scan.test_paths)?;
    let compiled = compile_rules(rules, test_paths)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    Ok(scan_collected_cached(
        walk_files(paths, &ignores),
        &compiled,
        rules,
        cache_dir,
        true,
        true,
    ))
}

/// Scan an explicit list of files instead of walking directories.
///
/// Used by `--diff`, where git already produced the exact file set. Paths that
/// no longer exist or that slopguard cannot parse are silently skipped.
///
/// Cross-file rules are not evaluated here. `--diff` sees only the changed
/// files, so the project index would be incomplete and its impl counts wrong.
/// Symbol contributions are still collected and cached, so a later full scan is
/// not penalised.
pub fn scan_files(
    files: &[PathBuf],
    rules: &[Rule],
    config: &Config,
) -> Result<ScanResult, ScanError> {
    let test_paths = TestPaths::new(&config.scan.test_paths)?;
    let compiled = compile_rules(rules, test_paths)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    Ok(scan_collected(
        explicit_files(files, &ignores),
        &compiled,
        false,
        true,
    ))
}

/// Compute `unused-disable` findings for the given walked paths: a full raw scan
/// (disable comments not applied) whose findings reveal which directives would
/// have suppressed something. Cross-file rules run, as in [`scan`].
///
/// This is the walk (non-diff) variant used by `--report-unused-disable`. It is
/// uncached on purpose: the cache stores suppressed findings, which cannot tell
/// which directives were consumed.
pub fn scan_unused_disables(
    paths: &[PathBuf],
    rules: &[Rule],
    config: &Config,
) -> Result<Vec<Finding>, ScanError> {
    let test_paths = TestPaths::new(&config.scan.test_paths)?;
    let compiled = compile_rules(rules, test_paths)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    let files = walk_files(paths, &ignores);
    let raw = scan_collected(files.clone(), &compiled, true, false);
    Ok(unused_from_raw(&files, &raw.findings))
}

/// Explicit-file (diff) variant of [`scan_unused_disables`]. Cross-file rules do
/// not run, matching [`scan_files`], so only the changed files are considered.
pub fn scan_files_unused_disables(
    files: &[PathBuf],
    rules: &[Rule],
    config: &Config,
) -> Result<Vec<Finding>, ScanError> {
    let test_paths = TestPaths::new(&config.scan.test_paths)?;
    let compiled = compile_rules(rules, test_paths)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    let collected = explicit_files(files, &ignores);
    let raw = scan_collected(collected.clone(), &compiled, false, false);
    Ok(unused_from_raw(&collected, &raw.findings))
}

/// Group raw findings by file and, for each collected file, report the disable
/// directives that suppressed nothing. Files that cannot be read are skipped.
fn unused_from_raw(files: &[(PathBuf, SupportLang)], raw: &[Finding]) -> Vec<Finding> {
    let mut by_file: HashMap<&Path, Vec<Finding>> = HashMap::new();
    for finding in raw {
        by_file
            .entry(finding.file.as_path())
            .or_default()
            .push(finding.clone());
    }
    let empty: Vec<Finding> = Vec::new();
    let mut out = Vec::new();
    for (path, _lang) in files {
        let Ok(source) = fs::read_to_string(path) else {
            continue;
        };
        let file_raw = by_file.get(path.as_path()).unwrap_or(&empty);
        out.extend(unused_disable_findings(path, &source, file_raw));
    }
    out
}

/// Cached variant of [`scan_files`]. Cache pruning is skipped: a partial scan
/// must not evict the entries of files it did not look at.
///
/// Cross-file rules are not evaluated here. `--diff` sees only the changed
/// files, so the project index would be incomplete and its impl counts wrong.
/// Symbol contributions are still collected and cached, so a later full scan is
/// not penalised.
pub fn scan_files_cached(
    files: &[PathBuf],
    rules: &[Rule],
    config: &Config,
    cache_dir: &Path,
) -> Result<ScanResult, ScanError> {
    let test_paths = TestPaths::new(&config.scan.test_paths)?;
    let compiled = compile_rules(rules, test_paths)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    Ok(scan_collected_cached(
        explicit_files(files, &ignores),
        &compiled,
        rules,
        cache_dir,
        false,
        false,
    ))
}
