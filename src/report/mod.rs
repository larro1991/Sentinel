use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::config::EngagementConfig;
use crate::finding::FindingsManager;

pub mod markdown;
pub mod json;
pub mod html;
pub mod csv;
pub mod sarif;

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

/// Get the default report generators (markdown + JSON).
pub fn default_generators() -> Vec<Box<dyn ReportGenerator>> {
    vec![
        Box::new(markdown::MarkdownReport),
        Box::new(json::JsonReport),
    ]
}

/// Get all available report generators.
pub fn all_generators() -> Vec<Box<dyn ReportGenerator>> {
    vec![
        Box::new(markdown::MarkdownReport),
        Box::new(json::JsonReport),
        Box::new(html::HtmlReport),
        Box::new(csv::CsvReport),
        Box::new(sarif::SarifReport),
    ]
}
