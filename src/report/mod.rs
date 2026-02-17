use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::config::EngagementConfig;
use crate::finding::FindingsManager;

pub mod markdown;
pub mod json;

/// Trait for report generators that produce output files from engagement results.
pub trait ReportGenerator {
    /// Generate the report, writing it to the output directory.
    /// Returns the path to the generated file.
    fn generate(
        &self,
        config: &EngagementConfig,
        findings: &FindingsManager,
        output_dir: &Path,
    ) -> Result<PathBuf>;

    /// The name/format of this report generator.
    fn format_name(&self) -> &str;
}

/// Get all built-in report generators.
pub fn default_generators() -> Vec<Box<dyn ReportGenerator>> {
    vec![
        Box::new(markdown::MarkdownReport),
        Box::new(json::JsonReport),
    ]
}
