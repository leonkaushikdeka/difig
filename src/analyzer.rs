use rayon::prelude::*;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use difig::{BrowserArtifact, FileArtifact, LnkData, StegoAnalysis, TimelineEvent, YaraMatch};

const YARA_RULES: &[(&str, &[&str], &str, &[&str])] = &[
    (
        "RAT_SERVER",
        &["remote", "admin", "server"],
        "high",
        &["malware", "rat"],
    ),
    (
        "CRYPTO_MINER",
        &["miner", "crypto", "hash"],
        "high",
        &["cryptocurrency"],
    ),
    (
        "KEYLOGGER",
        &["keylog", "keystroke", "capture"],
        "high",
        &["spyware"],
    ),
    ("BACKDOOR", &["backdoor", "trojan"], "high", &["malware"]),
    (
        "WORM_SIGNATURE",
        &["worm", "replicate"],
        "medium",
        &["worm"],
    ),
    (
        "ROOTKIT_INDICATOR",
        &["rootkit", "hide"],
        "high",
        &["rootkit"],
    ),
    (
        "PASSWORD_DUMP",
        &["password", "credential", "dump"],
        "high",
        &["credential"],
    ),
    (
        "NETWORK_SCANNER",
        &["portscan", "network"],
        "medium",
        &["scanner"],
    ),
    (
        "ENCRYPTION_TOOL",
        &["encrypt", "ransom"],
        "high",
        &["ransomware"],
    ),
    (
        "SUSPICIOUS_ARCHIVE",
        &["suspicious", "packed"],
        "medium",
        &["packed"],
    ),
];

pub struct Analyzer;

impl Analyzer {
    pub fn new() -> Self {
        Analyzer
    }

    pub fn analyze_files(
        &self,
        files: &[std::path::PathBuf],
        calculate_hashes: bool,
        calculate_entropy: bool,
        verify_signatures: bool,
        scan_yara: bool,
        scan_stego: bool,
        scan_browser: bool,
        scan_lnk: bool,
        progress_tx: Option<mpsc::Sender<usize>>,
    ) -> Vec<FileArtifact> {
        let (tx, rx) = mpsc::channel();
        let total_files = files.len();

        let producer = || {
            files
                .par_iter()
                .map_with(tx, |tx, file_path| {
                    let artifact = self.analyze_file(
                        file_path,
                        calculate_hashes,
                        calculate_entropy,
                        verify_signatures,
                        scan_yara,
                        scan_stego,
                        scan_browser,
                        scan_lnk,
                    );
                    let _ = tx.send(1);
                    artifact
                })
                .collect::<Vec<FileArtifact>>()
        };

        if let Some(progress_sender) = progress_tx {
            thread::spawn(move || {
                let mut processed = 0;
                loop {
                    match rx.recv_timeout(Duration::from_secs(1)) {
                        Ok(_) => {
                            processed += 1;
                            if processed % 100 == 0 {
                                let _ = progress_sender.send(processed);
                            }
                        }
                        Err(_) => {
                            if processed >= total_files {
                                break;
                            }
                        }
                    }
                }
            });
        }

        producer()
    }

    fn analyze_file(
        &self,
        path: &Path,
        calculate_hash: bool,
        calculate_entropy: bool,
        verify_signatures: bool,
        scan_yara: bool,
        scan_stego: bool,
        scan_browser: bool,
        scan_lnk: bool,
    ) -> FileArtifact {
        let mut artifact = FileArtifact::default();

        artifact.path = path.to_path_buf();

        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        artifact.is_hidden = file_name.starts_with('.');
        artifact.file_type = path
            .extension()
            .and_then(|e| Some(e.to_string_lossy().to_lowercase()))
            .unwrap_or_else(|| String::from("unknown"));

        match fs::metadata(path) {
            Ok(metadata) => {
                artifact.size = metadata.len();

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = metadata.permissions().mode();
                    artifact.permissions = Some(format!("{:o}", perms));
                }

                #[cfg(not(unix))]
                {
                    artifact.permissions = Some(format!("{:?}", metadata.permissions()));
                }

                if let Ok(modified) = metadata.modified() {
                    if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                        let modified_time = chrono::DateTime::from_timestamp(
                            duration.as_secs() as i64,
                            duration.subsec_nanos() as u32,
                        )
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| String::from("Unknown"));
                        artifact.modified_time = modified_time.clone();

                        artifact.timeline_events.push(TimelineEvent {
                            timestamp: modified_time,
                            event_type: String::from("modified"),
                            source: String::from("filesystem"),
                            description: format!("File modified: {}", path.display()),
                        });
                    }
                }

                #[cfg(unix)]
                if let Ok(accessed) = metadata.accessed() {
                    if let Ok(duration) = accessed.duration_since(std::time::UNIX_EPOCH) {
                        artifact.accessed_time = Some(
                            chrono::DateTime::from_timestamp(
                                duration.as_secs() as i64,
                                duration.subsec_nanos() as u32,
                            )
                            .map(|dt| dt.to_rfc3339())
                            .unwrap_or_else(|| String::from("Unknown")),
                        );
                    }
                }

                #[cfg(unix)]
                if let Ok(created) = metadata.created() {
                    if let Ok(duration) = created.duration_since(std::time::UNIX_EPOCH) {
                        let created_time = chrono::DateTime::from_timestamp(
                            duration.as_secs() as i64,
                            duration.subsec_nanos() as u32,
                        )
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| String::from("Unknown"));
                        artifact.created_time = Some(created_time.clone());

                        artifact.timeline_events.push(TimelineEvent {
                            timestamp: created_time,
                            event_type: String::from("created"),
                            source: String::from("filesystem"),
                            description: format!("File created: {}", path.display()),
                        });
                    }
                }
            }
            Err(e) => {
                artifact.error = Some(format!("Metadata error: {}", e));
                return artifact;
            }
        }

        if calculate_hash || calculate_entropy || scan_stego || scan_yara {
            match fs::read(path) {
                Ok(content) => {
                    if calculate_hash {
                        artifact.sha256_hash = Some(self.calculate_sha256(&content));
                        artifact.sha1_hash = Some(self.calculate_sha1(&content));
                        artifact.md5_hash = Some(self.calculate_md5(&content));
                    }
                    if calculate_entropy {
                        artifact.entropy_score = Some(difig::calculate_entropy(&content));
                    }
                    if scan_stego {
                        artifact.steganography_analysis = self.analyze_steganography(&content);
                    }
                    if scan_yara {
                        artifact.yara_matches = self.scan_yara(&content, file_name);
                    }
                }
                Err(e) => {
                    artifact.error = Some(format!("Read error: {}", e));
                }
            }
        }

        if verify_signatures {
            if let Ok(content) = fs::read(path) {
                let actual_type = difig::detect_magic_bytes(&content);
                artifact.actual_type = actual_type.clone();

                if difig::check_signature_mismatch(&artifact.file_type, &actual_type) {
                    artifact.signature_warning = true;
                    artifact.signature_details = Some(format!(
                        "Extension '{}' doesn't match actual type '{}'",
                        artifact.file_type, actual_type
                    ));
                }
            }
        }

        if scan_browser {
            artifact.browser_artifact = self.extract_browser_artifact(path);
        }

        if scan_lnk && artifact.file_type == "lnk" {
            artifact.lnk_data = self.parse_lnk_file(path);
        }

        artifact
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn calculate_sha1(&self, data: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn calculate_md5(&self, data: &[u8]) -> String {
        format!("{:x}", md5::compute(data))
    }

    fn analyze_steganography(&self, data: &[u8]) -> Option<StegoAnalysis> {
        if data.len() < 1000 {
            return None;
        }

        let entropy = difig::calculate_entropy(data);
        let mut indicators = Vec::new();
        let mut hidden_bytes_estimate: Option<u64> = None;

        if entropy > 7.9 {
            indicators.push(String::from("Very high entropy (near 8.0)"));
        }

        if data.len() > 10000 {
            let last_bytes: Vec<u8> = data.iter().rev().take(100).copied().collect();
            let last_entropy = difig::calculate_entropy(&last_bytes);
            if last_entropy > 7.5 && last_entropy > entropy - 0.5 {
                indicators.push(String::from("Last bytes have unusually high entropy"));
                hidden_bytes_estimate = Some((data.len() as u64) / 10);
            }
        }

        let has_hidden = entropy > 7.8 && !indicators.is_empty();

        Some(StegoAnalysis {
            has_hidden_data: has_hidden,
            confidence: if has_hidden { 0.75 } else { 0.0 },
            indicators,
            hidden_bytes_estimate,
        })
    }

    fn scan_yara(&self, data: &[u8], file_name: &str) -> Vec<YaraMatch> {
        let mut matches = Vec::new();
        let content_str = String::from_utf8_lossy(data);
        let file_name_lower = file_name.to_lowercase();

        for (rule_name, keywords, severity, tags) in YARA_RULES {
            let mut matched = false;

            for keyword in *keywords {
                if content_str.contains(keyword) || file_name_lower.contains(keyword) {
                    matched = true;
                    break;
                }
            }

            if matched {
                matches.push(YaraMatch {
                    rule_name: String::from(*rule_name),
                    category: String::from("custom"),
                    severity: String::from(*severity),
                    tags: tags.iter().map(|s| String::from(*s)).collect(),
                });
            }
        }

        matches
    }

    fn extract_browser_artifact(&self, path: &Path) -> Option<BrowserArtifact> {
        let path_str = path.to_string_lossy().to_lowercase();

        let browser_type = if path_str.contains("chrome") {
            String::from("chrome")
        } else if path_str.contains("firefox") {
            String::from("firefox")
        } else if path_str.contains("edge") {
            String::from("edge")
        } else if path_str.contains("safari") {
            String::from("safari")
        } else {
            return None;
        };

        let artifact_type = if path_str.contains("cookies") {
            String::from("cookie")
        } else if path_str.contains("history") {
            String::from("history")
        } else if path_str.contains("downloads") {
            String::from("download")
        } else if path_str.contains("login") || path_str.contains("logins") {
            String::from("credential")
        } else {
            return None;
        };

        Some(BrowserArtifact {
            browser_type,
            artifact_type,
            url: None,
            title: None,
            timestamp: None,
            visit_count: None,
            domain: None,
        })
    }

    fn parse_lnk_file(&self, path: &Path) -> Option<LnkData> {
        match fs::read(path) {
            Ok(data) => {
                if data.len() < 76 {
                    return None;
                }

                Some(LnkData {
                    target_path: None,
                    working_directory: None,
                    arguments: None,
                    creation_time: None,
                    modification_time: None,
                    machine_id: None,
                    volume_serial: None,
                    drive_type: None,
                })
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempdir::TempDir;

    #[test]
    fn test_analyzer_sha256() {
        let temp_dir = TempDir::new("difig").unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "hello world").unwrap();

        let analyzer = Analyzer::new();
        let artifacts = analyzer.analyze_files(
            &[test_file],
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            None,
        );

        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].sha256_hash,
            Some(String::from(
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            ))
        );
    }

    #[test]
    fn test_analyzer_sha1() {
        let temp_dir = TempDir::new("difig").unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "hello").unwrap();

        let analyzer = Analyzer::new();
        let artifacts = analyzer.analyze_files(
            &[test_file],
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            None,
        );

        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].sha1_hash,
            Some(String::from("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"))
        );
    }

    #[test]
    fn test_analyzer_md5() {
        let temp_dir = TempDir::new("difig").unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "hello").unwrap();

        let analyzer = Analyzer::new();
        let artifacts = analyzer.analyze_files(
            &[test_file],
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            None,
        );

        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].md5_hash,
            Some(String::from("5d41402abc4b2a76b9719d911017c592"))
        );
    }

    #[test]
    fn test_analyzer_entropy() {
        let temp_dir = TempDir::new("difig").unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "aaaaa").unwrap();

        let analyzer = Analyzer::new();
        let artifacts = analyzer.analyze_files(
            &[test_file],
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            None,
        );

        assert_eq!(artifacts.len(), 1);
        let entropy = artifacts[0].entropy_score.unwrap();
        assert!(entropy < 2.0);
    }

    #[test]
    fn test_signature_verification() {
        let temp_dir = TempDir::new("difig").unwrap();
        let test_file = temp_dir.path().join("test.exe");
        fs::write(&test_file, [0x50, 0x4B, 0x03, 0x04]).unwrap();

        let analyzer = Analyzer::new();
        let artifacts = analyzer.analyze_files(
            &[test_file],
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            None,
        );

        assert_eq!(artifacts.len(), 1);
        assert!(artifacts[0].signature_warning);
        assert!(artifacts[0].signature_details.is_some());
    }

    #[test]
    fn test_yara_scanning() {
        let temp_dir = TempDir::new("difig").unwrap();
        let test_file = temp_dir.path().join("suspicious.txt");
        fs::write(
            &test_file,
            "This is a remote admin server with backdoor capabilities",
        )
        .unwrap();

        let analyzer = Analyzer::new();
        let artifacts = analyzer.analyze_files(
            &[test_file],
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            None,
        );

        assert_eq!(artifacts.len(), 1);
        assert!(!artifacts[0].yara_matches.is_empty());
    }
}
