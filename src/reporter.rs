use difig::{FileArtifact, ForensicReport, TimelineEvent};
use serde_json;
use std::fs;
use std::path::Path;

pub struct Reporter;

impl Reporter {
    pub fn new() -> Self {
        Reporter
    }

    pub fn generate_report(
        &self,
        artifacts: Vec<FileArtifact>,
        target_path: &Path,
    ) -> ForensicReport {
        let total_bytes: u64 = artifacts.iter().map(|a| a.size).sum();
        let files_with_errors = artifacts.iter().filter(|a| a.error.is_some()).count();
        let signature_warnings = artifacts.iter().filter(|a| a.signature_warning).count();
        let yara_matches_found: usize = artifacts.iter().map(|a| a.yara_matches.len()).sum();
        let high_entropy_files = artifacts
            .iter()
            .filter(|a| a.entropy_score.map(|e| e > 7.5).unwrap_or(false))
            .count();
        let browser_artifacts_found = artifacts
            .iter()
            .filter(|a| a.browser_artifact.is_some())
            .count();
        let lnk_files_analyzed = artifacts.iter().filter(|a| a.lnk_data.is_some()).count();

        let mut timeline: Vec<TimelineEvent> = Vec::new();
        for artifact in &artifacts {
            timeline.extend(artifact.timeline_events.clone());
        }
        timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        let mut report = ForensicReport::new(
            env!("CARGO_PKG_VERSION").to_string(),
            target_path.to_string_lossy().to_string(),
        );

        report.total_files_scanned = artifacts.len();
        report.total_bytes_scanned = total_bytes;
        report.files_with_errors = files_with_errors;
        report.signature_warnings = signature_warnings;
        report.yara_matches_found = yara_matches_found;
        report.high_entropy_files = high_entropy_files;
        report.browser_artifacts_found = browser_artifacts_found;
        report.lnk_files_analyzed = lnk_files_analyzed;
        report.artifacts = artifacts;
        report.timeline = timeline;

        report
    }

    pub fn save_report(&self, report: &ForensicReport, output_path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(report)
            .map_err(|e| format!("Failed to serialize report: {}", e))?;

        fs::write(output_path, json).map_err(|e| format!("Failed to write report: {}", e))?;

        Ok(())
    }

    pub fn save_report_path(
        &self,
        report: &ForensicReport,
        output_path: String,
    ) -> Result<std::path::PathBuf, String> {
        let path = Path::new(&output_path).to_path_buf();

        if path.is_dir() {
            let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
            let filename = format!("forensic_report_{}.json", timestamp);
            let full_path = path.join(filename);
            self.save_report(report, &full_path)?;
            Ok(full_path)
        } else {
            self.save_report(report, &path)?;
            Ok(path)
        }
    }

    fn escape_csv_field(value: &str) -> String {
        let field = if value.starts_with('=')
            || value.starts_with('+')
            || value.starts_with('-')
            || value.starts_with('@')
        {
            format!("'{}", value)
        } else {
            value.to_string()
        };
        if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r')
        {
            format!("\"{}\"", field.replace('"', "\"\""))
        } else {
            field
        }
    }

    pub fn generate_timeline_csv(
        &self,
        timeline: &[TimelineEvent],
        output_path: &Path,
    ) -> Result<(), String> {
        let mut csv = String::from("timestamp,event_type,source,description\n");

        for event in timeline {
            csv.push_str(&format!(
                "{},{},{},{}\n",
                Self::escape_csv_field(&event.timestamp),
                Self::escape_csv_field(&event.event_type),
                Self::escape_csv_field(&event.source),
                Self::escape_csv_field(&event.description),
            ));
        }

        fs::write(output_path, csv).map_err(|e| format!("Failed to write CSV: {}", e))?;
        Ok(())
    }

    pub fn save_timeline_path(
        &self,
        timeline: &[TimelineEvent],
        output_dir: String,
    ) -> Result<std::path::PathBuf, String> {
        let path = Path::new(&output_dir).to_path_buf();
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("timeline_{}.csv", timestamp);
        let full_path = path.join(filename);
        self.generate_timeline_csv(timeline, &full_path)?;
        Ok(full_path)
    }

    pub fn generate_summary(&self, report: &ForensicReport) -> String {
        let mut summary = String::new();

        summary.push_str("=== FORENSIC SCAN SUMMARY ===\n\n");
        summary.push_str(&format!("Tool Version:    {}\n", report.tool_version));
        summary.push_str(&format!("Scan Timestamp:  {}\n", report.scan_timestamp));
        summary.push_str(&format!("Target Path:     {}\n", report.target_path));
        summary.push_str(&format!(
            "Total Files:     {}\n",
            report.total_files_scanned
        ));
        summary.push_str(&format!(
            "Total Bytes:     {}\n",
            report.total_bytes_scanned
        ));
        summary.push_str(&format!(
            "Errors:          {}\n\n",
            report.files_with_errors
        ));

        summary.push_str("=== ANOMALIES ===\n");
        summary.push_str(&format!(
            "Signature Warnings: {}\n",
            report.signature_warnings
        ));
        summary.push_str(&format!(
            "YARA Matches:       {}\n",
            report.yara_matches_found
        ));
        summary.push_str(&format!(
            "High Entropy Files: {}\n",
            report.high_entropy_files
        ));
        summary.push_str(&format!(
            "Browser Artifacts:  {}\n",
            report.browser_artifacts_found
        ));
        summary.push_str(&format!(
            "LNK Files Analyzed: {}\n\n",
            report.lnk_files_analyzed
        ));

        let high_severity: usize = report
            .artifacts
            .iter()
            .filter(|a| a.yara_matches.iter().any(|m| m.severity == "high"))
            .count();

        if high_severity > 0 {
            summary.push_str(&format!(
                "WARNING: {} files with HIGH severity YARA matches!\n",
                high_severity
            ));
        }

        let hidden_count = report.artifacts.iter().filter(|a| a.is_hidden).count();
        if hidden_count > 0 {
            summary.push_str(&format!(
                "Hidden Files: {} (may warrant investigation)\n",
                hidden_count
            ));
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::Builder;

    #[test]
    fn test_report_generation() {
        let temp_dir = Builder::new().prefix("difig").tempdir().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "test").unwrap();

        let reporter = Reporter::new();
        let artifacts = vec![FileArtifact {
            path: test_file,
            size: 4,
            sha256_hash: Some(String::from("abc123")),
            sha1_hash: None,
            md5_hash: None,
            modified_time: String::from("2024-01-01T00:00:00Z"),
            created_time: None,
            accessed_time: None,
            changed_time: None,
            file_type: String::from("txt"),
            actual_type: String::new(),
            entropy_score: None,
            permissions: None,
            is_hidden: false,
            is_symbolic_link: false,
            error: None,
            signature_warning: false,
            signature_details: None,
            yara_matches: Vec::new(),
            steganography_analysis: None,
            browser_artifact: None,
            lnk_data: None,
            timeline_events: Vec::new(),
            mobile_artifact: None,
            memory_artifact: None,
            carved_data: None,
            endpoint_data: None,
        }];

        let report = reporter.generate_report(artifacts, temp_dir.path());

        assert_eq!(report.total_files_scanned, 1);
        assert_eq!(report.total_bytes_scanned, 4);
        assert_eq!(report.files_with_errors, 0);
    }

    #[test]
    fn test_report_save() {
        let temp_dir = Builder::new().prefix("difig").tempdir().unwrap();
        let output_file = temp_dir.path().join("report.json");

        let reporter = Reporter::new();
        let report = ForensicReport::new(String::from("0.1.0"), String::from("/test"));

        let result = reporter.save_report(&report, &output_file);
        assert!(result.is_ok());
        assert!(output_file.exists());

        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("ForensicReport") || content.contains("tool_version"));
    }

    #[test]
    fn test_timeline_csv() {
        let temp_dir = Builder::new().prefix("difig").tempdir().unwrap();
        let output_file = temp_dir.path().join("timeline.csv");

        let reporter = Reporter::new();
        let timeline = vec![
            TimelineEvent {
                timestamp: String::from("2024-01-01T10:00:00Z"),
                event_type: String::from("created"),
                source: String::from("filesystem"),
                description: String::from("Test file created"),
                artifact_type: None,
            },
            TimelineEvent {
                timestamp: String::from("2024-01-01T11:00:00Z"),
                event_type: String::from("modified"),
                source: String::from("filesystem"),
                description: String::from("Test file modified"),
                artifact_type: None,
            },
        ];

        let result = reporter.generate_timeline_csv(&timeline, &output_file);
        assert!(result.is_ok());
        assert!(output_file.exists());

        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("created"));
        assert!(content.contains("modified"));
    }

    #[test]
    fn test_summary_generation() {
        let reporter = Reporter::new();
        let report = ForensicReport::new(String::from("0.2.0"), String::from("/test"));

        let summary = reporter.generate_summary(&report);
        assert!(summary.contains("FORENSIC SCAN SUMMARY"));
        assert!(summary.contains("0.2.0"));
    }
}
