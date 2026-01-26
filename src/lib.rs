use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileArtifact {
    pub path: PathBuf,
    pub size: u64,
    pub sha256_hash: Option<String>,
    pub modified_time: String,
    pub created_time: Option<String>,
    pub accessed_time: Option<String>,
    pub file_type: String,
    pub entropy_score: Option<f32>,
    pub permissions: Option<String>,
    pub is_hidden: bool,
    pub error: Option<String>,
}

impl Default for FileArtifact {
    fn default() -> Self {
        FileArtifact {
            path: PathBuf::new(),
            size: 0,
            sha256_hash: None,
            modified_time: String::new(),
            created_time: None,
            accessed_time: None,
            file_type: String::new(),
            entropy_score: None,
            permissions: None,
            is_hidden: false,
            error: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ForensicReport {
    pub tool_version: String,
    pub scan_timestamp: String,
    pub target_path: String,
    pub total_files_scanned: usize,
    pub total_bytes_scanned: u64,
    pub files_with_errors: usize,
    pub artifacts: Vec<FileArtifact>,
}

impl ForensicReport {
    pub fn new(tool_version: String, target_path: String) -> Self {
        ForensicReport {
            tool_version,
            scan_timestamp: chrono::Utc::now().to_rfc3339(),
            target_path,
            total_files_scanned: 0,
            total_bytes_scanned: 0,
            files_with_errors: 0,
            artifacts: Vec::new(),
        }
    }
}

pub fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut byte_counts = [0u64; 256];
    for &byte in data {
        byte_counts[byte as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &byte_counts {
        if count > 0 {
            let probability = count as f64 / total;
            entropy -= probability * probability.log2();
        }
    }

    entropy as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy_empty() {
        let result = calculate_entropy(&[]);
        assert_eq!(result, 0.0);
    }

    #[test]
    fn test_calculate_entropy_random() {
        let data = vec![0u8; 1024];
        let entropy = calculate_entropy(&data);
        assert!(entropy < 1.0, "Repeated bytes should have low entropy");
    }

    #[test]
    fn test_calculate_entropy_high() {
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let entropy = calculate_entropy(&data);
        assert!(
            entropy > 7.5,
            "Random-looking data should have high entropy"
        );
    }
}
