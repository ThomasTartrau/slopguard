//! Command-line surface: the clap definitions for every subcommand.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "slopguard",
    about = "Catch AI-generated code patterns and common issues"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, ValueEnum)]
pub enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, ValueEnum)]
pub enum SeverityThreshold {
    Error,
    Warning,
}

#[derive(Clone, ValueEnum)]
pub enum CategoryFilter {
    Slop,
    Security,
    Correctness,
}

#[derive(Clone, ValueEnum)]
pub enum LanguageFilter {
    Rust,
    Typescript,
}

/// Config preset selected by `slopguard init --preset <name>`.
#[derive(Clone, Copy, ValueEnum)]
pub enum PresetArg {
    Default,
    Strict,
    Relaxed,
    Ai,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan files for findings
    Scan {
        /// Paths to scan (defaults to current directory)
        #[arg(default_value = ".")]
        paths: Vec<PathBuf>,

        /// Output format
        #[arg(long)]
        format: Option<Format>,

        /// Only exit non-zero for findings at or above this severity
        #[arg(long, default_value = "warning")]
        severity_threshold: SeverityThreshold,

        /// Path to a specific slopguard.toml config file
        #[arg(long)]
        config: Option<PathBuf>,

        /// Disable colored output
        #[arg(long)]
        no_colors: bool,

        /// Disable specific rules (overrides config, repeatable)
        #[arg(long = "disable", value_name = "RULE_ID")]
        cli_disable: Vec<String>,

        /// Enable specific rules even if disabled by default or config (repeatable)
        #[arg(long = "enable", value_name = "RULE_ID")]
        cli_enable: Vec<String>,

        /// Scan with only this rule
        #[arg(long = "rule", value_name = "RULE_ID")]
        rule_filter: Option<String>,

        /// Disable file caching and force a full rescan
        #[arg(long)]
        no_cache: bool,

        /// Directory to store the scan cache (overrides SLOPGUARD_CACHE_DIR and config)
        #[arg(long, value_name = "PATH")]
        cache_dir: Option<PathBuf>,

        /// Skip AI rules entirely (no LLM calls), even if a provider is configured
        #[arg(long)]
        no_ai: bool,

        /// Ignore the baseline file and report every finding
        #[arg(long, conflicts_with = "baseline_path")]
        no_baseline: bool,

        /// Path to a specific baseline file
        #[arg(long = "baseline", value_name = "PATH")]
        baseline_path: Option<PathBuf>,
    },
    /// Capture current findings into a baseline file
    Baseline {
        /// Paths to scan (defaults to current directory)
        #[arg(default_value = ".")]
        paths: Vec<PathBuf>,

        /// Where to write the baseline (defaults to <project root>/.slopguard-baseline.json)
        #[arg(long, short = 'o', value_name = "PATH")]
        output: Option<PathBuf>,

        /// Path to a specific slopguard.toml config file
        #[arg(long)]
        config: Option<PathBuf>,

        /// Disable specific rules (overrides config, repeatable)
        #[arg(long = "disable", value_name = "RULE_ID")]
        cli_disable: Vec<String>,

        /// Enable specific rules even if disabled by default or config (repeatable)
        #[arg(long = "enable", value_name = "RULE_ID")]
        cli_enable: Vec<String>,

        /// Disable file caching and force a full rescan
        #[arg(long)]
        no_cache: bool,

        /// Directory to store the scan cache
        #[arg(long, value_name = "PATH")]
        cache_dir: Option<PathBuf>,

        /// Skip AI rules entirely (no LLM calls)
        #[arg(long)]
        no_ai: bool,
    },
    /// Generate a slopguard.toml config file
    Init {
        /// Overwrite existing slopguard.toml
        #[arg(long)]
        force: bool,

        /// Config preset to generate. Pass --preset with no value to list the presets.
        #[arg(long, value_name = "NAME", num_args = 0..=1)]
        preset: Option<Option<PresetArg>>,
    },
    /// Validate inline tests for all rules
    Test {
        /// Path to a specific slopguard.toml config file
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Show details of a specific rule
    Explain {
        /// The rule id to explain
        rule_id: String,

        /// Output format
        #[arg(long)]
        format: Option<Format>,

        /// Path to a specific slopguard.toml config file
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// List active rules
    List {
        /// Show all rules including disabled ones
        #[arg(long)]
        all: bool,

        /// Filter by category
        #[arg(long)]
        category: Option<CategoryFilter>,

        /// Filter by language
        #[arg(long)]
        language: Option<LanguageFilter>,

        /// Path to a specific slopguard.toml config file
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parses_scan_subcommand() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan", "."])
            .expect("scan subcommand should parse");
    }

    #[test]
    fn cli_parses_scan_subcommand_default_path() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan"])
            .expect("scan subcommand should parse without explicit path");
    }

    #[test]
    fn cli_parses_scan_with_format() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan", "--format", "json", "."])
            .expect("scan with --format json should parse");
    }

    #[test]
    fn cli_parses_scan_with_severity_threshold() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan", "--severity-threshold", "error", "."])
            .expect("scan with --severity-threshold should parse");
    }

    #[test]
    fn cli_parses_scan_with_config() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan", "--config", "my.toml", "."])
            .expect("scan with --config should parse");
    }

    #[test]
    fn cli_parses_scan_with_no_colors() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan", "--no-colors", "."])
            .expect("scan with --no-colors should parse");
    }

    #[test]
    fn cli_parses_init_subcommand() {
        Cli::command()
            .try_get_matches_from(["slopguard", "init"])
            .expect("init subcommand should parse");
    }

    #[test]
    fn cli_parses_init_with_preset() {
        Cli::command()
            .try_get_matches_from(["slopguard", "init", "--preset", "strict"])
            .expect("init with --preset strict should parse");
    }

    #[test]
    fn cli_parses_init_with_bare_preset() {
        Cli::command()
            .try_get_matches_from(["slopguard", "init", "--preset"])
            .expect("init with a valueless --preset should parse");
    }

    #[test]
    fn cli_parses_init_with_preset_and_force() {
        Cli::command()
            .try_get_matches_from(["slopguard", "init", "--preset", "relaxed", "--force"])
            .expect("init with --preset and --force should parse");
    }

    #[test]
    fn cli_rejects_unknown_preset() {
        let result =
            Cli::command().try_get_matches_from(["slopguard", "init", "--preset", "bogus"]);
        assert!(result.is_err(), "unknown preset should be rejected");
    }

    #[test]
    fn cli_parses_test_subcommand() {
        Cli::command()
            .try_get_matches_from(["slopguard", "test"])
            .expect("test subcommand should parse");
    }

    #[test]
    fn cli_parses_baseline_subcommand() {
        Cli::command()
            .try_get_matches_from(["slopguard", "baseline", "."])
            .expect("baseline subcommand should parse");
    }

    #[test]
    fn cli_parses_baseline_with_output() {
        Cli::command()
            .try_get_matches_from(["slopguard", "baseline", "-o", "custom.json", "."])
            .expect("baseline with --output should parse");
    }

    #[test]
    fn cli_parses_scan_with_no_baseline() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan", "--no-baseline", "."])
            .expect("scan with --no-baseline should parse");
    }

    #[test]
    fn cli_parses_scan_with_baseline_path() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan", "--baseline", "custom.json", "."])
            .expect("scan with --baseline should parse");
    }

    #[test]
    fn cli_rejects_no_baseline_with_baseline_path() {
        let result = Cli::command().try_get_matches_from([
            "slopguard",
            "scan",
            "--no-baseline",
            "--baseline",
            "custom.json",
            ".",
        ]);
        assert!(
            result.is_err(),
            "--no-baseline and --baseline should conflict"
        );
    }

    #[test]
    fn cli_parses_list_subcommand() {
        Cli::command()
            .try_get_matches_from(["slopguard", "list"])
            .expect("list subcommand should parse");
    }
}
