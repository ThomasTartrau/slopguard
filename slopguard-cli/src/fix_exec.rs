//! `scan --fix`: apply autofix-safe rewrites in place (or preview them with
//! `--dry-run`) once the git tree is known clean, then re-scan to report what
//! could not be fixed.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use similar::TextDiff;
use slopguard_core::baseline::{project_root, Baseline};
use slopguard_core::fix::fix_paths;
use slopguard_core::git::{self, GitError};
use slopguard_core::rule::load_effective_rules;
use slopguard_core::sanitize::sanitize_control;

use crate::baseline_cmd::{apply_baseline, resolve_baseline};
use crate::scan_exec::{
    retain_requested_rules, scan_with_rules, under_requested_paths, ScanTargets,
};
use crate::{resolve_config, resolve_config_sources, AppError};

/// Options for the `scan --fix` flow, a subset of `ScanOpts`. Caching,
/// escalation, output format and severity threshold do not apply to rewriting.
pub(crate) struct FixOpts {
    pub paths: Vec<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub cli_disable: Vec<String>,
    pub cli_enable: Vec<String>,
    pub cli_test_paths: Vec<String>,
    pub rule_filter: Option<String>,
    pub no_ai: bool,
    pub no_baseline: bool,
    pub baseline_path: Option<PathBuf>,
    pub dry_run: bool,
    pub allow_dirty: bool,
    pub offline: bool,
}

/// Refuse to rewrite files when the working tree has uncommitted changes under
/// the scanned paths. Outside a git repository uncommitted work cannot be
/// protected, so it refuses too. `--dry-run` and `--allow-dirty` skip this
/// entirely.
fn guard_clean_tree(paths: &[PathBuf]) -> Result<(), AppError> {
    // Probe the repository that holds the scanned paths, not the process cwd, so
    // `slopguard scan /elsewhere --fix` guards the tree it will actually rewrite.
    let probe_dir = |p: &Path| -> PathBuf {
        let dir = if p.is_dir() {
            p.to_path_buf()
        } else {
            p.parent().map(Path::to_path_buf).unwrap_or_default()
        };
        // A bare filename has an empty parent; `git -C ""` would fail to spawn.
        if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        }
    };
    let probe = paths
        .first()
        .map(|p| probe_dir(p))
        .unwrap_or_else(|| PathBuf::from("."));
    let dirty = match git::dirty_files(&probe) {
        Ok(dirty) => dirty,
        Err(GitError::NotARepository { .. }) => {
            // CLI diagnostic to stderr, not application logging.
            // slopguard-disable-next-line no-println-in-prod
            eprintln!(
                "error: scanned paths are not inside a git repository, so uncommitted \
                 changes cannot be protected; pass --allow-dirty to rewrite anyway, or \
                 preview with --dry-run"
            );
            return Err(AppError::Io(io::Error::other(
                "refusing to --fix outside a git repository",
            )));
        }
        Err(err) => return Err(err.into()),
    };
    let under = under_requested_paths(dirty, paths);
    if under.is_empty() {
        return Ok(());
    }
    // CLI diagnostic to stderr, not application logging.
    // slopguard-disable-next-line no-println-in-prod
    eprintln!(
        "error: {} uncommitted change(s) under the scanned paths; commit or stash \
         them, pass --allow-dirty to rewrite anyway, or preview with --dry-run",
        under.len()
    );
    Err(AppError::Io(io::Error::other(
        "refusing to --fix a dirty working tree",
    )))
}

/// Apply autofix-safe rewrites in place (or preview them with `--dry-run`).
///
/// Returns `true` when findings remain after the rewrite (exit code 1), `false`
/// when the tree is clean of findings or when previewing.
pub(crate) fn run_fix(opts: FixOpts) -> Result<bool, AppError> {
    let FixOpts {
        paths,
        config_path,
        cli_disable,
        cli_enable,
        cli_test_paths,
        rule_filter,
        no_ai,
        no_baseline,
        baseline_path,
        dry_run,
        allow_dirty,
        offline,
    } = opts;

    let mut config = resolve_config(config_path.as_deref())?;
    config.rules.disable.extend(cli_disable);
    config.rules.enable.extend(cli_enable);
    config.scan.test_paths.extend(cli_test_paths);

    // Sources are resolved (and fetched) once: the verification re-scan below
    // reuses these rules, so it checks the exact ruleset that was applied.
    let sources = resolve_config_sources(&config, offline)?;
    let mut rules = load_effective_rules(&config, &sources)?;
    retain_requested_rules(&mut rules, rule_filter.as_deref(), no_ai)?;

    if !dry_run && !allow_dirty {
        guard_clean_tree(&paths)?;
    }

    let resolved = resolve_baseline(no_baseline, baseline_path.clone())?;
    let (baseline, baseline_root): (Option<&Baseline>, PathBuf) = match &resolved {
        Some((bl, root)) => (Some(bl), root.clone()),
        None => {
            let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            (None, project_root(&cwd))
        }
    };

    let report = fix_paths(&paths, &rules, &config, baseline, &baseline_root)?;

    let stdout = io::stdout();
    let mut out = stdout.lock();

    if dry_run {
        for file in &report.files {
            let rel = file.path.display().to_string();
            let diff = TextDiff::from_lines(file.original.as_str(), file.fixed.as_str());
            let unified = diff
                .unified_diff()
                .header(&format!("a/{rel}"), &format!("b/{rel}"))
                .to_string();
            write!(out, "{}", sanitize_control(&unified))?;
        }
        writeln!(
            out,
            "Would apply {} fix(es) across {} file(s) (dry run, nothing written)",
            report.applied,
            report.files_changed()
        )?;
        return Ok(false);
    }

    for file in &report.files {
        fs::write(&file.path, &file.fixed)?;
    }

    // Re-scan from disk to report what could not be fixed; this drives the exit
    // code (0 only when no finding remains).
    let mut result = scan_with_rules(
        ScanTargets::Walk(paths),
        rules,
        &config,
        true,
        None,
        false,
        None,
    )?;
    apply_baseline(&mut result, no_baseline, baseline_path)?;
    let remaining = result.findings.len();

    writeln!(
        out,
        "Applied {} fix(es) across {} file(s); {} finding(s) remaining",
        report.applied,
        report.files_changed(),
        remaining
    )?;

    Ok(remaining > 0)
}
