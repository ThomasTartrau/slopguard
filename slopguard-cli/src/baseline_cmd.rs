//! The `baseline` subcommand and the baseline filtering applied by `scan`.

use std::env;
use std::mem::take;
use std::path::PathBuf;

use slopguard_core::baseline::{
    self, find_baseline_file, load, project_root, Baseline, BASELINE_FILE,
};
use slopguard_core::finding::ScanResult;
use slopguard_core::scanner::count_severities;

use crate::{collect_findings, AppError, CollectOpts};

pub struct BaselineOpts {
    pub paths: Vec<PathBuf>,
    pub output: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub cli_disable: Vec<String>,
    pub cli_enable: Vec<String>,
    pub no_cache: bool,
    pub cache_dir: Option<PathBuf>,
    pub no_ai: bool,
}

/// Recount errors and warnings after findings were removed.
///
/// `files_scanned` is preserved: those files really were scanned, only their
/// findings were suppressed.
fn recompute_stats(result: &mut ScanResult, baseline_filtered: usize) {
    let (errors, warnings) = count_severities(&result.findings);
    result.stats.errors = errors;
    result.stats.warnings = warnings;
    result.stats.total = errors + warnings;
    result.stats.baseline_filtered = baseline_filtered;
}

/// Resolve which baseline to apply, and the root its paths are relative to.
///
/// `--no-baseline` disables it, `--baseline <path>` forces a specific file
/// (an error if missing, never a silent full scan), otherwise the file is
/// looked up in the working directory and its parents.
fn resolve_baseline(
    no_baseline: bool,
    baseline_path: Option<PathBuf>,
) -> Result<Option<(Baseline, PathBuf)>, AppError> {
    if no_baseline {
        return Ok(None);
    }

    let path = match baseline_path {
        Some(explicit) => explicit,
        None => {
            let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            match find_baseline_file(&cwd) {
                Some(found) => found,
                None => return Ok(None),
            }
        }
    };

    let baseline = load(&path)?;
    let root = path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(Some((baseline, root)))
}

/// Drop the findings already recorded in the baseline and update the stats.
///
/// Returns `true` when a baseline was resolved and applied, `false` when none
/// applies (`--no-baseline`, or no baseline file found).
pub fn apply_baseline(
    result: &mut ScanResult,
    no_baseline: bool,
    baseline_path: Option<PathBuf>,
) -> Result<bool, AppError> {
    if let Some((bl, root)) = resolve_baseline(no_baseline, baseline_path)? {
        let (kept, filtered) = baseline::filter(take(&mut result.findings), &bl, &root);
        result.findings = kept;
        recompute_stats(result, filtered);
        return Ok(true);
    }
    Ok(false)
}

/// Scan and record every current finding into a baseline file.
///
/// Always exits successfully when the file could be written, findings or not:
/// capturing them is the point.
pub fn run_baseline(opts: BaselineOpts) -> Result<(), AppError> {
    let BaselineOpts {
        paths,
        output,
        config_path,
        cli_disable,
        cli_enable,
        no_cache,
        cache_dir,
        no_ai,
    } = opts;

    let (result, _config) = collect_findings(CollectOpts {
        paths,
        config_path,
        cli_disable,
        cli_enable,
        rule_filter: None,
        no_cache,
        cache_dir,
        no_ai,
        diff: false,
        diff_base: None,
    })?;

    let out_path = match output {
        Some(explicit) => explicit,
        None => {
            let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            project_root(&cwd).join(BASELINE_FILE)
        }
    };
    let root = out_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let baseline = baseline::build(&result.findings, &root);
    baseline::write(&baseline, &out_path)?;

    println!(
        "Wrote {} findings to {}",
        result.findings.len(),
        out_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::tempdir;

    use slopguard_core::baseline::BaselineError;

    use super::resolve_baseline;
    use crate::AppError;

    #[test]
    fn no_baseline_flag_skips_resolution() {
        let resolved = resolve_baseline(true, Some(Path::new("nope.json").to_path_buf()))
            .expect("--no-baseline should not read any file");
        assert!(resolved.is_none());
    }

    #[test]
    fn missing_explicit_baseline_is_an_error() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.json");

        match resolve_baseline(false, Some(missing)) {
            Err(AppError::Baseline(BaselineError::Io { .. })) => {}
            other => panic!("expected an I/O baseline error, got {other:?}"),
        }
    }
}
