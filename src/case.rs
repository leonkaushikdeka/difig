use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::engine::general_purpose;
use base64::Engine;
use difig::{CaseInfo, CaseNote, CustodyEntry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedCase {
    pub case_info: CaseInfo,
    pub encrypted_data: String,
    pub checksum: String,
}

pub struct CaseManager;

impl CaseManager {
    pub fn new() -> Self {
        CaseManager
    }

    pub fn create_case(
        &self,
        name: String,
        examiner: String,
        description: Option<String>,
    ) -> CaseInfo {
        CaseInfo {
            case_id: difig::generate_case_id(),
            case_name: name,
            examiner,
            description,
            evidence_ids: Vec::new(),
            chain_of_custody: Vec::new(),
            notes: Vec::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn add_evidence(&self, case: &mut CaseInfo, evidence_id: String) {
        case.evidence_ids.push(evidence_id);
        case.updated_at = chrono::Utc::now().to_rfc3339();
    }

    pub fn add_custody_entry(
        &self,
        case: &mut CaseInfo,
        action: String,
        person: String,
        location: String,
        signature: Option<String>,
    ) {
        let entry = CustodyEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            action,
            person,
            location,
            signature,
        };
        case.chain_of_custody.push(entry);
        case.updated_at = chrono::Utc::now().to_rfc3339();
    }

    pub fn add_note(
        &self,
        case: &mut CaseInfo,
        author: String,
        content: String,
        tags: Vec<String>,
    ) {
        let note = CaseNote {
            id: format!("note_{}", chrono::Utc::now().timestamp_nanos()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            author,
            content,
            tags,
        };
        case.notes.push(note);
        case.updated_at = chrono::Utc::now().to_rfc3339();
    }

    pub fn save_case(&self, case: &CaseInfo, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(case)
            .map_err(|e| format!("Failed to serialize case: {}", e))?;

        fs::write(path, json).map_err(|e| format!("Failed to write case: {}", e))?;

        Ok(())
    }

    pub fn load_case(&self, path: &Path) -> Result<CaseInfo, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read case: {}", e))?;

        serde_json::from_str(&content).map_err(|e| format!("Failed to parse case: {}", e))
    }

    pub fn export_case_for_sharing(
        &self,
        case: &CaseInfo,
        output_path: &Path,
    ) -> Result<(), String> {
        let json = serde_json::to_string_pretty(case)
            .map_err(|e| format!("Failed to serialize case: {}", e))?;

        let encrypted = self.encrypt_data(&json);

        let export = EncryptedCase {
            case_info: CaseInfo {
                case_id: case.case_id.clone(),
                case_name: case.case_name.clone(),
                examiner: case.examiner.clone(),
                description: case.description.clone(),
                evidence_ids: case.evidence_ids.clone(),
                chain_of_custody: Vec::new(),
                notes: Vec::new(),
                created_at: case.created_at.clone(),
                updated_at: case.updated_at.clone(),
            },
            encrypted_data: encrypted,
            checksum: self.calculate_checksum(&json),
        };

        let export_json = serde_json::to_string_pretty(&export)
            .map_err(|e| format!("Failed to serialize export: {}", e))?;

        fs::write(output_path, export_json)
            .map_err(|e| format!("Failed to write export: {}", e))?;

        Ok(())
    }

    fn derive_key(&self) -> Key<Aes256Gcm> {
        let key_str = std::env::var("DIFIG_ENCRYPTION_KEY")
            .unwrap_or_else(|_| String::from("CHANGE_ME_DIFIG_DEFAULT_KEY_32B!"));
        let hash = Sha256::digest(key_str.as_bytes());
        *Key::<Aes256Gcm>::from_slice(&hash)
    }

    fn encrypt_data(&self, data: &str) -> String {
        let key = self.derive_key();
        let cipher = Aes256Gcm::new(&key);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let pid = std::process::id();

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&now.as_nanos().to_le_bytes()[..8]);
        nonce_bytes[8..12].copy_from_slice(&pid.to_le_bytes()[..4]);

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, data.as_bytes())
            .expect("encryption failure");

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        general_purpose::STANDARD.encode(&result)
    }

    fn decrypt_data(&self, encrypted_data: &str) -> Result<String, String> {
        let key = self.derive_key();
        let cipher = Aes256Gcm::new(&key);

        let data = general_purpose::STANDARD.decode(encrypted_data)
            .map_err(|e| format!("Failed to decode encrypted data: {}", e))?;

        if data.len() < 12 {
            return Err("Invalid encrypted data: too short".to_string());
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {}", e))
    }

    fn calculate_checksum(&self, data: &str) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    pub fn generate_chain_of_custody_report(&self, case: &CaseInfo) -> String {
        let mut report = String::new();

        report.push_str("========================================\n");
        report.push_str("       CHAIN OF CUSTODY REPORT\n");
        report.push_str("========================================\n\n");

        report.push_str(&format!("Case ID:     {}\n", case.case_id));
        report.push_str(&format!("Case Name:   {}\n", case.case_name));
        report.push_str(&format!("Examiner:    {}\n", case.examiner));
        report.push_str(&format!("Created:     {}\n", case.created_at));
        report.push_str("\n");

        report.push_str("Evidence Items:\n");
        for (i, evid) in case.evidence_ids.iter().enumerate() {
            report.push_str(&format!("  {}. {}\n", i + 1, evid));
        }
        report.push_str("\n");

        report.push_str("Chain of Custody Entries:\n");
        report.push_str("----------------------------------------\n");
        for (i, entry) in case.chain_of_custody.iter().enumerate() {
            report.push_str(&format!("Entry #{}\n", i + 1));
            report.push_str(&format!("  Timestamp:  {}\n", entry.timestamp));
            report.push_str(&format!("  Action:     {}\n", entry.action));
            report.push_str(&format!("  Person:     {}\n", entry.person));
            report.push_str(&format!("  Location:   {}\n", entry.location));
            if let Some(ref sig) = entry.signature {
                report.push_str(&format!("  Signature:  {}\n", sig));
            }
            report.push_str("\n");
        }

        report
    }

    pub fn generate_summary_report(&self, case: &CaseInfo) -> String {
        let mut report = String::new();

        report.push_str("========================================\n");
        report.push_str("         FORENSIC CASE SUMMARY\n");
        report.push_str("========================================\n\n");

        report.push_str(&format!("Case ID:       {}\n", case.case_id));
        report.push_str(&format!("Case Name:     {}\n", case.case_name));
        report.push_str(&format!("Examiner:      {}\n", case.examiner));
        if let Some(ref desc) = case.description {
            report.push_str(&format!("Description:   {}\n", desc));
        }
        report.push_str(&format!("Created:       {}\n", case.created_at));
        report.push_str(&format!("Last Updated:  {}\n", case.updated_at));
        report.push_str("\n");

        report.push_str("Statistics:\n");
        report.push_str(&format!(
            "  Evidence Items:    {}\n",
            case.evidence_ids.len()
        ));
        report.push_str(&format!(
            "  Custody Entries:   {}\n",
            case.chain_of_custody.len()
        ));
        report.push_str(&format!("  Examiner Notes:    {}\n", case.notes.len()));
        report.push_str("\n");

        if !case.notes.is_empty() {
            report.push_str("Recent Notes:\n");
            report.push_str("----------------------------------------\n");
            for note in case.notes.iter().rev().take(5) {
                report.push_str(&format!("[{}] {}:\n", note.timestamp, note.author));
                report.push_str(&format!("  {}\n", note.content));
                if !note.tags.is_empty() {
                    report.push_str(&format!("  Tags: {:?}\n", note.tags));
                }
                report.push_str("\n");
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::Builder;

    #[test]
    fn test_create_case() {
        let manager = CaseManager::new();
        let case = manager.create_case(
            String::from("Test Case"),
            String::from("John Doe"),
            Some(String::from("Test investigation")),
        );

        assert_eq!(case.case_name, "Test Case");
        assert_eq!(case.examiner, "John Doe");
        assert!(!case.case_id.is_empty());
    }

    #[test]
    fn test_add_evidence() {
        let manager = CaseManager::new();
        let mut case =
            manager.create_case(String::from("Test Case"), String::from("John Doe"), None);

        manager.add_evidence(&mut case, String::from("EVIDENCE_001"));
        manager.add_evidence(&mut case, String::from("EVIDENCE_002"));

        assert_eq!(case.evidence_ids.len(), 2);
    }

    #[test]
    fn test_add_custody() {
        let manager = CaseManager::new();
        let mut case =
            manager.create_case(String::from("Test Case"), String::from("John Doe"), None);

        manager.add_custody_entry(
            &mut case,
            String::from("Acquired"),
            String::from("John Doe"),
            String::from("Lab A"),
            Some(String::from("JD-1234")),
        );

        assert_eq!(case.chain_of_custody.len(), 1);
    }

    #[test]
    fn test_add_note() {
        let manager = CaseManager::new();
        let mut case =
            manager.create_case(String::from("Test Case"), String::from("John Doe"), None);

        manager.add_note(
            &mut case,
            String::from("John Doe"),
            String::from("Found suspicious file"),
            vec![String::from("suspicious")],
        );

        assert_eq!(case.notes.len(), 1);
    }

    #[test]
    fn test_save_load_case() {
        let temp_dir = Builder::new().prefix("difig").tempdir().unwrap();
        let case_file = temp_dir.path().join("case.json");

        let manager = CaseManager::new();
        let mut case = manager.create_case(
            String::from("Test Case"),
            String::from("John Doe"),
            Some(String::from("Test investigation")),
        );
        manager.add_evidence(&mut case, String::from("EVIDENCE_001"));
        manager.add_note(
            &mut case,
            String::from("John Doe"),
            String::from("Test note"),
            Vec::new(),
        );

        manager.save_case(&case, &case_file).unwrap();
        let loaded = manager.load_case(&case_file).unwrap();

        assert_eq!(loaded.case_name, case.case_name);
        assert_eq!(loaded.examiner, case.examiner);
        assert_eq!(loaded.evidence_ids, case.evidence_ids);
    }

    #[test]
    fn test_custody_report() {
        let manager = CaseManager::new();
        let mut case =
            manager.create_case(String::from("Test Case"), String::from("John Doe"), None);
        manager.add_custody_entry(
            &mut case,
            String::from("Acquired"),
            String::from("John Doe"),
            String::from("Lab A"),
            None,
        );

        let report = manager.generate_chain_of_custody_report(&case);
        assert!(report.contains("CHAIN OF CUSTODY"));
        assert!(report.contains("Test Case"));
    }

    #[test]
    fn test_summary_report() {
        let manager = CaseManager::new();
        let mut case = manager.create_case(
            String::from("Test Case"),
            String::from("John Doe"),
            Some(String::from("Test investigation")),
        );
        manager.add_note(
            &mut case,
            String::from("John Doe"),
            String::from("Test note"),
            Vec::new(),
        );

        let report = manager.generate_summary_report(&case);
        assert!(report.contains("FORENSIC CASE SUMMARY"));
        assert!(report.contains("Test Case"));
    }
}
