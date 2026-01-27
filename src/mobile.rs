use difig::MobileArtifact;
use regex::Regex;
use serde_json::json;
use std::fs;
use std::path::Path;

pub struct MobileForensics;

impl MobileForensics {
    pub fn new() -> Self {
        MobileForensics
    }

    pub fn analyze_mobile_backup(&self, path: &Path) -> Vec<MobileArtifact> {
        let mut artifacts = Vec::new();

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if entry.path().is_file() {
                    if let Some(artifact) = self.extract_mobile_artifact(&entry.path()) {
                        artifacts.push(artifact);
                    }
                }
            }
        }

        artifacts
    }

    fn extract_mobile_artifact(&self, path: &Path) -> Option<MobileArtifact> {
        let path_str = path.to_string_lossy().to_lowercase();
        let file_name = path.file_name()?.to_string_lossy().to_string();

        if path_str.contains("sms") || path_str.contains("message") || path_str.contains("chat") {
            return Some(MobileArtifact {
                device_type: self.detect_device_type(&path_str),
                os_version: None,
                artifact_type: String::from("sms_messages"),
                data: self.extract_sms_data(path),
                user_id: None,
                timestamp: None,
            });
        }

        if path_str.contains("call") || path_str.contains("contact") {
            return Some(MobileArtifact {
                device_type: self.detect_device_type(&path_str),
                os_version: None,
                artifact_type: String::from("call_history"),
                data: self.extract_call_data(path),
                user_id: None,
                timestamp: None,
            });
        }

        if path_str.contains("contact") || path_str.contains("address") || path_str.contains("ab") {
            return Some(MobileArtifact {
                device_type: self.detect_device_type(&path_str),
                os_version: None,
                artifact_type: String::from("contacts"),
                data: self.extract_contact_data(path),
                user_id: None,
                timestamp: None,
            });
        }

        if path_str.contains("location") || path_str.contains("gps") || path_str.contains("geo") {
            return Some(MobileArtifact {
                device_type: self.detect_device_type(&path_str),
                os_version: None,
                artifact_type: String::from("location_data"),
                data: self.extract_location_data(path),
                user_id: None,
                timestamp: None,
            });
        }

        if path_str.contains("wifi") || path_str.contains("network") {
            return Some(MobileArtifact {
                device_type: self.detect_device_type(&path_str),
                os_version: None,
                artifact_type: String::from("wifi_networks"),
                data: self.extract_wifi_data(path),
                user_id: None,
                timestamp: None,
            });
        }

        if path_str.contains("app_usage") || path_str.contains("usage") {
            return Some(MobileArtifact {
                device_type: self.detect_device_type(&path_str),
                os_version: None,
                artifact_type: String::from("app_usage"),
                data: json!({"source": file_name}),
                user_id: None,
                timestamp: None,
            });
        }

        None
    }

    fn detect_device_type(&self, path: &str) -> String {
        if path.contains("ios") || path.contains("iphone") || path.contains("ipad") {
            String::from("iOS")
        } else if path.contains("android") || path.contains("samsung") || path.contains("google") {
            String::from("Android")
        } else {
            String::from("Unknown")
        }
    }

    fn extract_sms_data(&self, path: &Path) -> serde_json::Value {
        let content = fs::read_to_string(path).unwrap_or_default();
        let mut messages = Vec::new();

        let phone_regex = Regex::new(r"\+?[0-9]{10,15}").unwrap();
        let date_regex = Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}").unwrap();

        for line in content.lines() {
            if !line.trim().is_empty() {
                let phone = phone_regex.find(line).map(|m| m.as_str().to_string());
                let date = date_regex.find(line).map(|m| m.as_str().to_string());
                let is_sent = line.to_lowercase().contains("sent") || line.contains("→");
                let is_received = line.to_lowercase().contains("received") || line.contains("←");

                messages.push(json!({
                    "content": line[..std::cmp::min(line.len(), 200)].to_string(),
                    "phone": phone,
                    "timestamp": date,
                    "direction": if is_sent { "sent" } else if is_received { "received" } else { "unknown" }
                }));
            }
        }

        json!({
            "message_count": messages.len(),
            "messages": messages
        })
    }

    fn extract_call_data(&self, path: &Path) -> serde_json::Value {
        let content = fs::read_to_string(path).unwrap_or_default();
        let mut calls = Vec::new();

        let phone_regex = Regex::new(r"\+?[0-9]{10,15}").unwrap();
        let date_regex = Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}").unwrap();

        for line in content.lines() {
            if !line.trim().is_empty() {
                let phone = phone_regex.find(line).map(|m| m.as_str().to_string());
                let date = date_regex.find(line).map(|m| m.as_str().to_string());
                let is_outgoing = line.to_lowercase().contains("outgoing")
                    || line.to_lowercase().contains("dialed");
                let is_incoming = line.to_lowercase().contains("incoming")
                    || line.to_lowercase().contains("received");
                let is_missed = line.to_lowercase().contains("missed");

                let call_type = if is_missed {
                    String::from("missed")
                } else if is_outgoing {
                    String::from("outgoing")
                } else if is_incoming {
                    String::from("incoming")
                } else {
                    String::from("unknown")
                };

                calls.push(json!({
                    "phone": phone,
                    "timestamp": date,
                    "type": call_type,
                    "raw": line[..std::cmp::min(line.len(), 200)].to_string()
                }));
            }
        }

        json!({
            "call_count": calls.len(),
            "calls": calls
        })
    }

    fn extract_contact_data(&self, path: &Path) -> serde_json::Value {
        let content = fs::read_to_string(path).unwrap_or_default();
        let mut contacts = Vec::new();

        for line in content.lines() {
            if !line.trim().is_empty() {
                contacts.push(json!({
                    "raw": line[..std::cmp::min(line.len(), 200)].to_string()
                }));
            }
        }

        json!({
            "contact_count": contacts.len(),
            "contacts": contacts
        })
    }

    fn extract_location_data(&self, path: &Path) -> serde_json::Value {
        let content = fs::read_to_string(path).unwrap_or_default();
        let mut locations = Vec::new();

        let gps_regex = Regex::new(r"(-?\d+\.\d+)[,\s]+(-?\d+\.\d+)").unwrap();
        let date_regex = Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}").unwrap();

        for line in content.lines() {
            if !line.trim().is_empty() {
                if let Some(gps) = gps_regex.captures(line) {
                    let lat = gps.get(1).map(|m| m.as_str().parse::<f64>().unwrap_or(0.0));
                    let lon = gps.get(2).map(|m| m.as_str().parse::<f64>().unwrap_or(0.0));
                    let date = date_regex.find(line).map(|m| m.as_str().to_string());

                    locations.push(json!({
                        "latitude": lat,
                        "longitude": lon,
                        "timestamp": date,
                        "raw": line[..std::cmp::min(line.len(), 200)].to_string()
                    }));
                }
            }
        }

        json!({
            "location_count": locations.len(),
            "locations": locations
        })
    }

    fn extract_wifi_data(&self, path: &Path) -> serde_json::Value {
        json!({
            "network_count": 0,
            "networks": Vec::<serde_json::Value>::new()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempdir::TempDir;

    #[test]
    fn test_mobile_sms_extraction() {
        let temp_dir = TempDir::new("difig").unwrap();
        let sms_file = temp_dir.path().join("sms.txt");
        fs::write(&sms_file, "2024-01-01T10:00:00 From: +1234567890 Hello World\n2024-01-01T10:05:00 To: +0987654321 Test message").unwrap();

        let mobile = MobileForensics::new();
        let artifacts = mobile.analyze_mobile_backup(temp_dir.path());

        assert!(!artifacts.is_empty());
        let sms_artifact = artifacts.iter().find(|a| a.artifact_type == "sms_messages");
        assert!(sms_artifact.is_some());
    }

    #[test]
    fn test_mobile_call_extraction() {
        let temp_dir = TempDir::new("difig").unwrap();
        let call_file = temp_dir.path().join("calls.txt");
        fs::write(
            &call_file,
            "2024-01-01T10:00:00 +1234567890 outgoing\n2024-01-01T11:00:00 +0987654321 missed",
        )
        .unwrap();

        let mobile = MobileForensics::new();
        let artifacts = mobile.analyze_mobile_backup(temp_dir.path());

        assert!(!artifacts.is_empty());
    }
}
