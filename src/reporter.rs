use difig::FileArtifact;
use difig::ForensicReport;
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

        let mut report = ForensicReport::new(
            env!("CARGO_PKG_VERSION").to_string(),
            target_path.to_string_lossy().to_string(),
        );

        report.total_files_scanned = artifacts.len();
        report.total_bytes_scanned = total_bytes;
        report.files_with_errors = files_with_errors;
        report.artifacts = artifacts;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempdir::TempDir;

    #[test]
    fn test_report_generation() {
        let temp_dir = TempDir::new("difig").unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "test").unwrap();

        let reporter = Reporter::new();
        let artifacts = vec![FileArtifact {
            path: test_file,
            size: 4,
            sha256_hash: Some(String::from("abc123")),
            modified_time: String::from("2024-01-01T00:00:00Z"),
            created_time: None,
            accessed_time: None,
            file_type: String::from("txt"),
            entropy_score: None,
            permissions: None,
            is_hidden: false,
            error: None,
        }];

        let report = reporter.generate_report(artifacts, temp_dir.path());

        assert_eq!(report.total_files_scanned, 1);
        assert_eq!(report.total_bytes_scanned, 4);
        assert_eq!(report.files_with_errors, 0);
    }

    #[test]
    fn test_report_save() {
        let temp_dir = TempDir::new("difig").unwrap();
        let output_file = temp_dir.path().join("report.json");

        let reporter = Reporter::new();
        let report = ForensicReport::new(String::from("0.1.0"), String::from("/test"));

        let result = reporter.save_report(&report, &output_file);
        assert!(result.is_ok());
        assert!(output_file.exists());

        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("ForensicReport") || content.contains("tool_version"));
    }
}
