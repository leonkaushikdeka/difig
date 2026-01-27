use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileArtifact {
    pub path: PathBuf,
    pub size: u64,
    pub sha256_hash: Option<String>,
    pub sha1_hash: Option<String>,
    pub md5_hash: Option<String>,
    pub modified_time: String,
    pub created_time: Option<String>,
    pub accessed_time: Option<String>,
    pub changed_time: Option<String>,
    pub file_type: String,
    pub actual_type: String,
    pub entropy_score: Option<f32>,
    pub permissions: Option<String>,
    pub is_hidden: bool,
    pub is_symbolic_link: bool,
    pub error: Option<String>,
    pub signature_warning: bool,
    pub signature_details: Option<String>,
    pub yara_matches: Vec<YaraMatch>,
    pub steganography_analysis: Option<StegoAnalysis>,
    pub browser_artifact: Option<BrowserArtifact>,
    pub lnk_data: Option<LnkData>,
    pub timeline_events: Vec<TimelineEvent>,
    pub mobile_artifact: Option<MobileArtifact>,
    pub memory_artifact: Option<MemoryArtifact>,
    pub carved_data: Option<CarvedData>,
    pub endpoint_data: Option<EndpointData>,
}

impl Default for FileArtifact {
    fn default() -> Self {
        FileArtifact {
            path: PathBuf::new(),
            size: 0,
            sha256_hash: None,
            sha1_hash: None,
            md5_hash: None,
            modified_time: String::new(),
            created_time: None,
            accessed_time: None,
            changed_time: None,
            file_type: String::new(),
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub category: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StegoAnalysis {
    pub has_hidden_data: bool,
    pub confidence: f32,
    pub indicators: Vec<String>,
    pub hidden_bytes_estimate: Option<u64>,
    pub lsb_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserArtifact {
    pub browser_type: String,
    pub artifact_type: String,
    pub url: Option<String>,
    pub title: Option<String>,
    pub timestamp: Option<String>,
    pub visit_count: Option<u32>,
    pub domain: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnkData {
    pub target_path: Option<String>,
    pub working_directory: Option<String>,
    pub arguments: Option<String>,
    pub creation_time: Option<String>,
    pub modification_time: Option<String>,
    pub machine_id: Option<String>,
    pub volume_serial: Option<String>,
    pub drive_type: Option<String>,
    pub relative_path: Option<String>,
    pub icon_location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub event_type: String,
    pub source: String,
    pub description: String,
    pub artifact_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReport {
    pub tool_version: String,
    pub scan_timestamp: String,
    pub target_path: String,
    pub total_files_scanned: usize,
    pub total_bytes_scanned: u64,
    pub files_with_errors: usize,
    pub signature_warnings: usize,
    pub yara_matches_found: usize,
    pub high_entropy_files: usize,
    pub browser_artifacts_found: usize,
    pub lnk_files_analyzed: usize,
    pub mobile_artifacts_found: usize,
    pub memory_artifacts_found: usize,
    pub carved_files_found: usize,
    pub endpoint_alerts: usize,
    pub artifacts: Vec<FileArtifact>,
    pub hash_database_matches: Vec<HashMatch>,
    pub timeline: Vec<TimelineEvent>,
    pub case_info: Option<CaseInfo>,
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
            signature_warnings: 0,
            yara_matches_found: 0,
            high_entropy_files: 0,
            browser_artifacts_found: 0,
            lnk_files_analyzed: 0,
            mobile_artifacts_found: 0,
            memory_artifacts_found: 0,
            carved_files_found: 0,
            endpoint_alerts: 0,
            artifacts: Vec::new(),
            hash_database_matches: Vec::new(),
            timeline: Vec::new(),
            case_info: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashMatch {
    pub hash: String,
    pub hash_type: String,
    pub file_path: PathBuf,
    pub category: String,
    pub description: String,
    pub is_malicious: bool,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInfo {
    pub case_id: String,
    pub case_name: String,
    pub examiner: String,
    pub description: Option<String>,
    pub evidence_ids: Vec<String>,
    pub chain_of_custody: Vec<CustodyEntry>,
    pub notes: Vec<CaseNote>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    pub timestamp: String,
    pub action: String,
    pub person: String,
    pub location: String,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseNote {
    pub id: String,
    pub timestamp: String,
    pub author: String,
    pub content: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileArtifact {
    pub device_type: String,
    pub os_version: Option<String>,
    pub artifact_type: String,
    pub data: serde_json::Value,
    pub user_id: Option<String>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryArtifact {
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub artifact_type: String,
    pub data: serde_json::Value,
    pub offset: Option<u64>,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedData {
    pub file_type: String,
    pub offset: u64,
    pub size: u64,
    pub confidence: f32,
    pub carved_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointData {
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub parent_pid: Option<u32>,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub network_connections: Vec<NetworkConnection>,
    pub registry_keys: Vec<RegistryKey>,
    pub loaded_dlls: Vec<String>,
    pub artifact_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub protocol: String,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKey {
    pub key_path: String,
    pub key_name: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub value_type: Option<String>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvingSignature {
    pub extension: &'static str,
    pub magic_bytes: &'static [u8],
    pub magic_bytes_mask: Option<&'static [u8]>,
    pub min_size: u64,
    pub max_size: Option<u64>,
    pub description: &'static str,
}

pub fn get_carving_signatures() -> Vec<CarvingSignature> {
    vec![
        CarvingSignature {
            extension: "jpg",
            magic_bytes: &[0xFF, 0xD8, 0xFF, 0xE0],
            magic_bytes_mask: None,
            min_size: 10,
            max_size: None,
            description: "JPEG image",
        },
        CarvingSignature {
            extension: "png",
            magic_bytes: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            magic_bytes_mask: None,
            min_size: 8,
            max_size: None,
            description: "PNG image",
        },
        CarvingSignature {
            extension: "gif",
            magic_bytes: &[0x47, 0x49, 0x46, 0x38, 0x39, 0x61],
            magic_bytes_mask: None,
            min_size: 6,
            max_size: None,
            description: "GIF image",
        },
        CarvingSignature {
            extension: "pdf",
            magic_bytes: &[0x25, 0x50, 0x44, 0x46],
            magic_bytes_mask: None,
            min_size: 4,
            max_size: None,
            description: "PDF document",
        },
        CarvingSignature {
            extension: "zip",
            magic_bytes: &[0x50, 0x4B, 0x03, 0x04],
            magic_bytes_mask: None,
            min_size: 4,
            max_size: None,
            description: "ZIP archive",
        },
        CarvingSignature {
            extension: "exe",
            magic_bytes: &[0x4D, 0x5A],
            magic_bytes_mask: None,
            min_size: 2,
            max_size: None,
            description: "Windows executable",
        },
        CarvingSignature {
            extension: "mp3",
            magic_bytes: &[0xFF, 0xFB],
            magic_bytes_mask: None,
            min_size: 2,
            max_size: None,
            description: "MP3 audio",
        },
        CarvingSignature {
            extension: "mp3",
            magic_bytes: &[0x49, 0x44, 0x33],
            magic_bytes_mask: None,
            min_size: 3,
            max_size: None,
            description: "MP3 audio (ID3)",
        },
        CarvingSignature {
            extension: "wav",
            magic_bytes: &[0x52, 0x49, 0x46, 0x46],
            magic_bytes_mask: None,
            min_size: 4,
            max_size: None,
            description: "WAV audio",
        },
        CarvingSignature {
            extension: "bmp",
            magic_bytes: &[0x42, 0x4D],
            magic_bytes_mask: None,
            min_size: 2,
            max_size: None,
            description: "BMP image",
        },
        CarvingSignature {
            extension: "tif",
            magic_bytes: &[0x49, 0x49, 0x2A, 0x00],
            magic_bytes_mask: None,
            min_size: 4,
            max_size: None,
            description: "TIFF image (little-endian)",
        },
        CarvingSignature {
            extension: "tif",
            magic_bytes: &[0x4D, 0x4D, 0x00, 0x2A],
            magic_bytes_mask: None,
            min_size: 4,
            max_size: None,
            description: "TIFF image (big-endian)",
        },
        CarvingSignature {
            extension: "gz",
            magic_bytes: &[0x1F, 0x8B],
            magic_bytes_mask: None,
            min_size: 2,
            max_size: None,
            description: "GZIP archive",
        },
        CarvingSignature {
            extension: "rar",
            magic_bytes: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
            magic_bytes_mask: None,
            min_size: 6,
            max_size: None,
            description: "RAR archive",
        },
        CarvingSignature {
            extension: "7z",
            magic_bytes: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
            magic_bytes_mask: None,
            min_size: 6,
            max_size: None,
            description: "7-Zip archive",
        },
        CarvingSignature {
            extension: "html",
            magic_bytes: &[0x3C, 0x68, 0x74, 0x6D, 0x6C],
            magic_bytes_mask: None,
            min_size: 5,
            max_size: None,
            description: "HTML document",
        },
        CarvingSignature {
            extension: "xml",
            magic_bytes: &[0x3C, 0x78, 0x6D, 0x6C],
            magic_bytes_mask: None,
            min_size: 4,
            max_size: None,
            description: "XML document",
        },
        CarvingSignature {
            extension: "json",
            magic_bytes: &[0x7B],
            magic_bytes_mask: None,
            min_size: 1,
            max_size: None,
            description: "JSON document",
        },
        CarvingSignature {
            extension: "elf",
            magic_bytes: &[0x7F, 0x45, 0x4C, 0x46],
            magic_bytes_mask: None,
            min_size: 4,
            max_size: None,
            description: "ELF executable",
        },
        CarvingSignature {
            extension: "avi",
            magic_bytes: &[0x52, 0x49, 0x46, 0x46],
            magic_bytes_mask: None,
            min_size: 4,
            max_size: None,
            description: "AVI video",
        },
        CarvingSignature {
            extension: "doc",
            magic_bytes: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
            magic_bytes_mask: None,
            min_size: 8,
            max_size: None,
            description: "Microsoft Office document",
        },
        CarvingSignature {
            extension: "lnk",
            magic_bytes: &[0x4C, 0x00, 0x00, 0x00],
            magic_bytes_mask: Some(&[0xFF, 0x00, 0x00, 0x00]),
            min_size: 20,
            max_size: None,
            description: "Windows shortcut",
        },
    ]
}

pub fn generate_case_id() -> String {
    let mut hasher = DefaultHasher::new();
    chrono::Utc::now().hash(&mut hasher);
    let hash = hasher.finish();
    format!("{:08x}", hash)
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

pub fn detect_magic_bytes(data: &[u8]) -> String {
    if data.len() < 2 {
        return String::from("unknown");
    }

    match data {
        [0x89, 0x50, 0x4E, 0x47, ..] => String::from("png"),
        [0xFF, 0xD8, 0xFF, ..] => String::from("jpg"),
        [0x47, 0x49, 0x46, 0x38, ..] => String::from("gif"),
        [0x52, 0x41, 0x52, 0x21, ..] => String::from("rar"),
        [0x1F, 0x8B, ..] => String::from("gz"),
        [0x50, 0x4B, 0x03, 0x04, ..] => String::from("zip"),
        [0x50, 0x4B, 0x05, 0x06, ..] => String::from("zip"),
        [0x50, 0x4B, 0x07, 0x08, ..] => String::from("zip"),
        [0x7F, 0x45, 0x4C, 0x46, ..] => String::from("elf"),
        [0x4D, 0x5A, ..] => String::from("exe"),
        [0x25, 0x50, 0x44, 0x46, ..] => String::from("pdf"),
        [0x49, 0x44, 0x33, ..] => String::from("mp3"),
        [0xFF, 0xFB, ..] => String::from("mp3"),
        [0x42, 0x4D, ..] => String::from("bmp"),
        [0x49, 0x49, 0x2A, 0x00, ..] => String::from("tif"),
        [0x4D, 0x4D, 0x00, 0x2A, ..] => String::from("tif"),
        [0x7B, 0x0D, 0x0A, ..] => String::from("json"),
        [0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45, ..] => String::from("html"),
        [0x3C, 0x68, 0x74, 0x6D, 0x6C, ..] => String::from("html"),
        [0xEF, 0xBB, 0xBF, 0x3C, ..] => String::from("html"),
        [0xD0, 0xCF, 0x11, 0xE0, ..] => String::from("ole"),
        _ => String::from("binary"),
    }
}

pub fn check_signature_mismatch(extension: &str, actual_type: &str) -> bool {
    if extension == "unknown" || actual_type == "binary" {
        return false;
    }
    let ext = extension.to_lowercase();
    let actual = actual_type.to_lowercase();

    let common_mismatches = [
        ("exe", "zip"),
        ("exe", "pdf"),
        ("doc", "exe"),
        ("docx", "exe"),
        ("pdf", "exe"),
        ("jpg", "exe"),
        ("png", "exe"),
        ("txt", "exe"),
    ];

    common_mismatches
        .iter()
        .any(|(e, a)| *e == ext && *a == actual)
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
    fn test_calculate_entropy_repeated() {
        let data = vec![0u8; 1024];
        let entropy = calculate_entropy(&data);
        assert!(entropy < 1.0, "Repeated bytes should have low entropy");
    }

    #[test]
    fn test_calculate_entropy_random() {
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let entropy = calculate_entropy(&data);
        assert!(
            entropy > 7.5,
            "Random-looking data should have high entropy"
        );
    }

    #[test]
    fn test_detect_magic_bytes_png() {
        let png_header = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_magic_bytes(&png_header), "png");
    }

    #[test]
    fn test_detect_magic_bytes_jpg() {
        let jpg_header = vec![0xFF, 0xD8, 0xFF, 0xE0];
        assert_eq!(detect_magic_bytes(&jpg_header), "jpg");
    }

    #[test]
    fn test_detect_magic_bytes_zip() {
        let zip_header = vec![0x50, 0x4B, 0x03, 0x04];
        assert_eq!(detect_magic_bytes(&zip_header), "zip");
    }

    #[test]
    fn test_signature_mismatch() {
        assert!(check_signature_mismatch("exe", "zip"));
        assert!(check_signature_mismatch("pdf", "exe"));
        assert!(!check_signature_mismatch("png", "jpg"));
        assert!(!check_signature_mismatch("txt", "binary"));
    }

    #[test]
    fn test_generate_case_id() {
        let id = generate_case_id();
        assert!(id.len() >= 6 && id.len() <= 16);
    }

    #[test]
    fn test_carving_signatures_count() {
        let sigs = get_carving_signatures();
        assert!(
            sigs.len() >= 20,
            "Should have at least 20 carving signatures, got {}",
            sigs.len()
        );
    }
}
