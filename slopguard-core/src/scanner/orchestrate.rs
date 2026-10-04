//! Top-level scan orchestration: collect files, fan out per-file scans (cached
//! or not), assemble cross-file findings, and shape the [`ScanResult`].

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use ast_grep_language::SupportLang;
use log::debug;
use rayon::prelude::*;

use crate::cache::{file_content_hash, rules_hash, CacheEntry, CacheKey, CacheStore};
use crate::config::Config;
use crate::cross_file::FileSymbols;
use crate::disable::unused_disable_findings;
use crate::finding::{CacheStats, Finding, ScanResult, ScanStats};
use crate::resolution::FileImports;
use crate::rule::{Rule, Severity};

use super::project::{append_cross_file, index_only_files};
use super::{
    append_resolution, build_glob_set, compile_rules, explicit_files, scan_file, walk_files,
    CompiledRules, FileScan, ScanError,
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

/// The files a scan reports on, plus the ones it only reads to complete the
/// cross-file index (see [`index_only_files`]).
struct ScanSet {
    files: Vec<(PathBuf, SupportLang)>,
    index_only: Vec<(PathBuf, SupportLang)>,
}

impl ScanSet {
    /// A directory walk of `paths`. File targets among them widen the index to
    /// their project.
    fn walk(
        paths: &[PathBuf],
        compiled: &CompiledRules,
        config: &Config,
    ) -> Result<Self, ScanError> {
        let ignores = build_glob_set(&config.scan.ignores)?;
        let files = walk_files(paths, &ignores);
        let index_only = index_only_files(compiled, paths, &files, &ignores);
        Ok(Self { files, index_only })
    }

    /// An explicit file list (`--diff`). Every file widens the index to its
    /// project.
    fn explicit(
        targets: &[PathBuf],
        compiled: &CompiledRules,
        config: &Config,
    ) -> Result<Self, ScanError> {
        let ignores = build_glob_set(&config.scan.ignores)?;
        let files = explicit_files(targets, &ignores);
        let index_only = index_only_files(compiled, targets, &files, &ignores);
        Ok(Self { files, index_only })
    }

    /// The paths whose findings are reported.
    fn reported(&self) -> HashSet<&Path> {
        self.files.iter().map(|(path, _)| path.as_path()).collect()
    }
}

/// Scan a collected file set without touching the cache.
///
/// Index-only files are parsed for their symbols alone: nothing of theirs is
/// reported, and nothing is stored.
fn scan_collected(set: &ScanSet, compiled: &CompiledRules, apply_disable: bool) -> ScanResult {
    let (per_file, project) = compiled.engines(apply_disable);
    let collect_symbols = project.iter().any(|e| e.needs_symbols());
    let collect_imports = !compiled.resolution.is_empty();
    let scans: Vec<(PathBuf, FileScan)> = set
        .files
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
    if collect_symbols {
        let test_paths = &compiled.test_paths;
        let extra: Vec<(PathBuf, FileSymbols)> = set
            .index_only
            .par_iter()
            .map(|(path, lang)| {
                let scan = scan_file(path, *lang, &[], test_paths, true, false, apply_disable);
                (path.clone(), scan.symbols)
            })
            .collect();
        contributions.extend(extra);
    }
    append_cross_file(&mut findings, &project, &contributions, &set.reported());
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
            files_scanned: set.files.len(),
            baseline_filtered: 0,
            diff_base: None,
            files_changed: None,
        },
        cache_stats: None,
    }
}

/// Scan a collected file set, reusing cached findings for files whose content
/// hash is unchanged.
///
/// Index-only files go through the cache like the others (a miss is scanned in
/// full and stored, which warms the cache for the next run), but only their
/// symbols are used and they are left out of the stats.
///
/// `prune` drops cache entries that no longer correspond to a scanned file. A
/// partial scan must pass `false`: it never saw the other files, so their
/// entries are still valid.
fn scan_collected_cached(
    set: &ScanSet,
    compiled: &CompiledRules,
    rules: &[Rule],
    cache_dir: &Path,
    key: CacheKey,
    prune: bool,
) -> ScanResult {
    // The cached path always applies disable comments: the raw pass used by
    // `--report-unused-disable` runs uncached, so the cache only ever stores
    // suppressed findings.
    let (per_file, project) = compiled.engines(true);
    let collect_symbols = project.iter().any(|e| e.needs_symbols());
    let collect_imports = !compiled.resolution.is_empty();
    let current_rules_hash = rules_hash(rules);
    let store =
        CacheStore::with_dir(cache_dir.to_path_buf(), key).scoped_to_rules(&current_rules_hash);
    let rules_changed = store
        .check_rules_changed(&current_rules_hash)
        .unwrap_or(true);

    struct FileWork<'a> {
        path: &'a Path,
        lang: SupportLang,
        hash: String,
        /// False for an index-only file: its findings are not reported.
        reported: bool,
    }

    let reported = set.files.iter().map(|file| (file, true));
    let index_only = set.index_only.iter().map(|file| (file, false));
    let work: Vec<FileWork> = reported
        .chain(index_only)
        .filter_map(|((path, lang), reported)| {
            let content = fs::read(path).ok()?;
            Some(FileWork {
                path,
                lang: *lang,
                hash: file_content_hash(&content),
                reported,
            })
        })
        .collect();

    let mut cached_count = 0usize;
    let mut changed_count = 0usize;
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut contributions: Vec<(PathBuf, FileSymbols)> = Vec::new();
    let mut import_contributions: Vec<(PathBuf, FileImports)> = Vec::new();
    let mut take = |file: &FileWork, entry: CacheEntry| {
        if file.reported {
            all_findings.extend(entry.findings);
            if collect_imports {
                import_contributions.push((file.path.to_path_buf(), entry.imports));
            }
        }
        if collect_symbols {
            contributions.push((file.path.to_path_buf(), entry.symbols));
        }
    };

    let mut to_scan: Vec<&FileWork> = Vec::new();
    for file in &work {
        match (!rules_changed).then(|| store.get(&file.hash)).flatten() {
            Some(entry) => {
                cached_count += usize::from(file.reported);
                take(file, entry);
            }
            None => {
                changed_count += usize::from(file.reported);
                to_scan.push(file);
            }
        }
    }

    let scanned: Vec<(&FileWork, FileScan)> = to_scan
        .into_par_iter()
        .map(|file| {
            let scan = scan_file(
                file.path,
                file.lang,
                &per_file,
                &compiled.test_paths,
                collect_symbols,
                collect_imports,
                true,
            );
            (file, scan)
        })
        .collect();

    for (file, scan) in scanned {
        let entry = CacheEntry {
            findings: scan.findings,
            symbols: scan.symbols,
            imports: scan.imports,
        };
        store.put(&file.hash, &entry).ok();
        take(file, entry);
    }

    // Cross-file and resolution evaluation are never cached: they re-run on every
    // scan (cross-file from the assembled index, resolution from the manifests on
    // disk, so a manifest edit is reflected even for an unchanged file).
    append_cross_file(&mut all_findings, &project, &contributions, &set.reported());
    append_resolution(&mut all_findings, compiled, &import_contributions, true);

    if prune {
        let current_hashes: Vec<String> = work.iter().map(|file| file.hash.clone()).collect();
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
///
/// A file among `paths` (as the pre-commit hook passes them) is reported on its
/// own, but the cross-file index still covers its whole project.
pub fn scan(paths: &[PathBuf], rules: &[Rule], config: &Config) -> Result<ScanResult, ScanError> {
    let compiled = compile_rules(rules, config)?;
    let set = ScanSet::walk(paths, &compiled, config)?;
    Ok(scan_collected(&set, &compiled, true))
}

/// Scan with file-level caching. Files whose content hash matches a cached
/// entry (and whose rules have not changed) return cached findings without
/// reparsing.
///
/// `cache_dir` is the directory where cache files are stored, used as is (the
/// CLI defaults it to a per-project directory under the user cache, see
/// [`crate::cache::project_cache_dir`]). Entries are signed with the user's
/// [`CacheKey`]; when that key cannot be loaded or created, the scan runs
/// uncached rather than trusting unsigned entries.
///
/// Stale entries are pruned only when every path is a directory: a file target
/// (the pre-commit hook) is a partial scan and must keep the other entries.
pub fn scan_cached(
    paths: &[PathBuf],
    rules: &[Rule],
    config: &Config,
    cache_dir: &Path,
) -> Result<ScanResult, ScanError> {
    match CacheKey::load_or_create_default() {
        Ok(key) => scan_cached_with_key(paths, rules, config, cache_dir, key),
        Err(err) => {
            debug!("cache key unavailable ({err}), scanning without cache");
            scan(paths, rules, config)
        }
    }
}

/// [`scan_cached`] with an explicit signing key instead of the user's.
pub fn scan_cached_with_key(
    paths: &[PathBuf],
    rules: &[Rule],
    config: &Config,
    cache_dir: &Path,
    key: CacheKey,
) -> Result<ScanResult, ScanError> {
    let compiled = compile_rules(rules, config)?;
    let set = ScanSet::walk(paths, &compiled, config)?;
    let prune = paths.iter().all(|path| path.is_dir());
    Ok(scan_collected_cached(
        &set, &compiled, rules, cache_dir, key, prune,
    ))
}

/// Scan an explicit list of files instead of walking directories.
///
/// Used by `--diff`, where git already produced the exact file set. Paths that
/// no longer exist or that slopguard cannot parse are silently skipped.
///
/// Cross-file rules still see the whole project: the index is completed from
/// the project each file belongs to, and only the findings located in the
/// given files are reported.
pub fn scan_files(
    files: &[PathBuf],
    rules: &[Rule],
    config: &Config,
) -> Result<ScanResult, ScanError> {
    let compiled = compile_rules(rules, config)?;
    let set = ScanSet::explicit(files, &compiled, config)?;
    Ok(scan_collected(&set, &compiled, true))
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
    let compiled = compile_rules(rules, config)?;
    let set = ScanSet::walk(paths, &compiled, config)?;
    let raw = scan_collected(&set, &compiled, false);
    Ok(unused_from_raw(&set.files, &raw.findings))
}

/// Explicit-file (diff) variant of [`scan_unused_disables`]. Cross-file rules
/// run over the whole project, as in [`scan_files`], and only the changed files
/// are checked for unused directives.
pub fn scan_files_unused_disables(
    files: &[PathBuf],
    rules: &[Rule],
    config: &Config,
) -> Result<Vec<Finding>, ScanError> {
    let compiled = compile_rules(rules, config)?;
    let set = ScanSet::explicit(files, &compiled, config)?;
    let raw = scan_collected(&set, &compiled, false);
    Ok(unused_from_raw(&set.files, &raw.findings))
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
/// must not evict the entries of files it did not look at. Like
/// [`scan_cached`], it runs uncached when the user's [`CacheKey`] is
/// unavailable.
pub fn scan_files_cached(
    files: &[PathBuf],
    rules: &[Rule],
    config: &Config,
    cache_dir: &Path,
) -> Result<ScanResult, ScanError> {
    match CacheKey::load_or_create_default() {
        Ok(key) => scan_files_cached_with_key(files, rules, config, cache_dir, key),
        Err(err) => {
            debug!("cache key unavailable ({err}), scanning without cache");
            scan_files(files, rules, config)
        }
    }
}

/// [`scan_files_cached`] with an explicit signing key instead of the user's.
pub fn scan_files_cached_with_key(
    files: &[PathBuf],
    rules: &[Rule],
    config: &Config,
    cache_dir: &Path,
    key: CacheKey,
) -> Result<ScanResult, ScanError> {
    let compiled = compile_rules(rules, config)?;
    let set = ScanSet::explicit(files, &compiled, config)?;
    Ok(scan_collected_cached(
        &set, &compiled, rules, cache_dir, key, false,
    ))
}
