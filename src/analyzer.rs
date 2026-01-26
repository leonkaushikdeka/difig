use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use difig::FileArtifact;

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
        progress_tx: Option<mpsc::Sender<usize>>,
    ) -> Vec<FileArtifact> {
        let (tx, rx) = mpsc::channel();
        let total_files = files.len();

        let producer = || {
            files
                .par_iter()
                .map_with(tx, |tx, file_path| {
                    let artifact =
                        self.analyze_file(file_path, calculate_hashes, calculate_entropy);
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
                                let percentage = (processed * 100) / total_files;
                                let _ = progress_sender.send(percentage);
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
    ) -> FileArtifact {
        let mut artifact = FileArtifact::default();

        artifact.path = path.to_path_buf();

        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        artifact.is_hidden = file_name.starts_with('.');

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
                        artifact.modified_time = chrono::DateTime::from_timestamp(
                            duration.as_secs() as i64,
                            duration.subsec_nanos() as u32,
                        )
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| String::from("Unknown"));
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
                            .unwrap_or_else(|_e| String::from("Unknown")),
                        );
                    }
                }

                #[cfg(unix)]
                if let Ok(created) = metadata.created() {
                    if let Ok(duration) = created.duration_since(std::time::UNIX_EPOCH) {
                        artifact.created_time = Some(
                            chrono::DateTime::from_timestamp(
                                duration.as_secs() as i64,
                                duration.subsec_nanos() as u32,
                            )
                            .map(|dt| dt.to_rfc3339())
                            .unwrap_or_else(|_e| String::from("Unknown")),
                        );
                    }
                }
            }
            Err(e) => {
                artifact.error = Some(format!("Metadata error: {}", e));
                return artifact;
            }
        }

        artifact.file_type = self.detect_file_type(path);

        if calculate_hash || calculate_entropy {
            match fs::read(path) {
                Ok(content) => {
                    if calculate_hash {
                        artifact.sha256_hash = Some(self.calculate_sha256(&content));
                    }
                    if calculate_entropy {
                        artifact.entropy_score = Some(difig::calculate_entropy(&content));
                    }
                }
                Err(e) => {
                    artifact.error = Some(format!("Read error: {}", e));
                }
            }
        }

        artifact
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        hex::encode(result)
    }

    fn detect_file_type(&self, path: &Path) -> String {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            return ext.to_lowercase();
        }

        let default = String::from("unknown");

        match fs::File::open(path) {
            Ok(mut file) => {
                let mut buffer = [0u8; 512];
                if let Ok(bytes_read) = file.read(&mut buffer) {
                    return self.detect_magic_bytes(&buffer[..bytes_read]);
                }
                default
            }
            Err(_) => default,
        }
    }

    fn detect_magic_bytes(&self, data: &[u8]) -> String {
        if data.len() >= 4 {
            if &data[0..4] == b"\x89PNG" {
                return String::from("png");
            }
            if &data[0..3] == b"\xff\xd8\xff" {
                return String::from("jpg");
            }
            if &data[0..2] == b"\x1f\x8b" {
                return String::from("gz");
            }
            if &data[0..4] == b"PK\x03\x04" {
                return String::from("zip");
            }
            if &data[0..4] == b"\x7fELF" {
                return String::from("elf");
            }
            if &data[0..2] == b"#!" {
                return String::from("script");
            }
        }

        String::from("binary")
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
        let artifacts = analyzer.analyze_files(&[test_file], true, false, None);

        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].sha256_hash,
            Some(String::from(
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            ))
        );
    }

    #[test]
    fn test_analyzer_entropy() {
        let temp_dir = TempDir::new("difig").unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "aaaaa").unwrap();

        let analyzer = Analyzer::new();
        let artifacts = analyzer.analyze_files(&[test_file], false, true, None);

        assert_eq!(artifacts.len(), 1);
        let entropy = artifacts[0].entropy_score.unwrap();
        assert!(
            entropy < 2.0,
            "Repeated 'a' characters should have low entropy"
        );
    }
}
