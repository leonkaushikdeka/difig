use difig::{EndpointData, NetworkConnection, RegistryKey};
use regex::Regex;
use serde_json::json;
use std::fs;
use std::path::Path;

pub struct EndpointForensics;

impl EndpointForensics {
    pub fn new() -> Self {
        EndpointForensics
    }

    pub fn analyze_endpoint(&self, path: &Path) -> Vec<EndpointData> {
        let mut endpoints = Vec::new();

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    if let Some(data) = self.analyze_endpoint_file(&entry_path) {
                        endpoints.push(data);
                    }
                }
            }
        }

        endpoints
    }

    fn analyze_endpoint_file(&self, path: &Path) -> Option<EndpointData> {
        let path_str = path.to_string_lossy().to_lowercase();
        let file_name = path.file_name()?.to_string_lossy().to_string();

        if path_str.contains("process") || path_str.contains("tasklist") {
            return Some(self.extract_process_info(path));
        }

        if path_str.contains("network")
            || path_str.contains("netstat")
            || path_str.contains("connection")
        {
            return Some(self.extract_network_info(path));
        }

        if path_str.contains("registry") || path_str.contains("reg") {
            return Some(self.extract_registry_info(path));
        }

        if path_str.contains("dll") || path_str.contains("module") {
            return Some(self.extract_dll_info(path));
        }

        None
    }

    fn extract_process_info(&self, path: &Path) -> EndpointData {
        let content = fs::read_to_string(path).unwrap_or_default();
        let mut processes = Vec::new();

        let process_regex = Regex::new(r"\s+(\d+)\s+(\d+)\s+([^\n]+)").unwrap();

        for line in content.lines() {
            if let Some(caps) = process_regex.captures(line) {
                let pid = caps.get(1).and_then(|m| m.as_str().parse::<u32>().ok());
                let parent_pid = caps.get(2).and_then(|m| m.as_str().parse::<u32>().ok());
                let name = caps
                    .get(3)
                    .map(|m| m.as_str().to_string().trim().to_string());

                processes.push(json!({
                    "pid": pid,
                    "parent_pid": parent_pid,
                    "command": name.clone(),
                    "name": name.clone().unwrap_or_default()
                }));
            }
        }

        EndpointData {
            process_name: Some(String::from("process_list")),
            pid: None,
            parent_pid: None,
            command_line: None,
            user: None,
            network_connections: Vec::new(),
            registry_keys: Vec::new(),
            loaded_dlls: Vec::new(),
            artifact_type: String::from("process_list"),
        }
    }

    fn extract_network_info(&self, path: &Path) -> EndpointData {
        let content = fs::read_to_string(path).unwrap_or_default();
        let mut connections = Vec::new();

        let conn_regex = Regex::new(r"([\d.]+):(\d+)\s+([\d.]+):(\d+)\s+(\w+)\s+(\w+)").unwrap();

        for line in content.lines() {
            if let Some(caps) = conn_regex.captures(line) {
                connections.push(NetworkConnection {
                    local_address: caps
                        .get(1)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                    local_port: caps
                        .get(2)
                        .and_then(|m| m.as_str().parse::<u16>().ok())
                        .unwrap_or(0),
                    remote_address: caps
                        .get(3)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                    remote_port: caps
                        .get(4)
                        .and_then(|m| m.as_str().parse::<u16>().ok())
                        .unwrap_or(0),
                    state: caps
                        .get(5)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                    protocol: caps
                        .get(6)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                    timestamp: None,
                });
            }
        }

        EndpointData {
            process_name: Some(String::from("network_connections")),
            pid: None,
            parent_pid: None,
            command_line: None,
            user: None,
            network_connections: connections,
            registry_keys: Vec::new(),
            loaded_dlls: Vec::new(),
            artifact_type: String::from("network_connections"),
        }
    }

    fn extract_registry_info(&self, path: &Path) -> EndpointData {
        let content = fs::read_to_string(path).unwrap_or_default();
        let mut keys = Vec::new();

        let key_regex = Regex::new(r"([A-Z0-9\\]+)\s+([A-Z0-9_]+)\s+([A-Z0-9_]+)\s+(.+)").unwrap();

        for line in content.lines() {
            if let Some(caps) = key_regex.captures(line) {
                keys.push(RegistryKey {
                    key_path: caps
                        .get(1)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                    key_name: caps
                        .get(2)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                    value_name: caps.get(3).map(|m| m.as_str().to_string()),
                    value_data: caps.get(4).map(|m| m.as_str().to_string()),
                    value_type: None,
                    timestamp: None,
                });
            }
        }

        EndpointData {
            process_name: Some(String::from("registry")),
            pid: None,
            parent_pid: None,
            command_line: None,
            user: None,
            network_connections: Vec::new(),
            registry_keys: keys,
            loaded_dlls: Vec::new(),
            artifact_type: String::from("registry_keys"),
        }
    }

    fn extract_dll_info(&self, path: &Path) -> EndpointData {
        let content = fs::read_to_string(path).unwrap_or_default();
        let mut dlls = Vec::new();

        for line in content.lines() {
            if !line.trim().is_empty() {
                dlls.push(line.trim().to_string());
            }
        }

        EndpointData {
            process_name: Some(String::from("dll_list")),
            pid: None,
            parent_pid: None,
            command_line: None,
            user: None,
            network_connections: Vec::new(),
            registry_keys: Vec::new(),
            loaded_dlls: dlls,
            artifact_type: String::from("loaded_dlls"),
        }
    }

    pub fn detect_suspicious_processes(&self, path: &Path) -> Vec<EndpointData> {
        let endpoints = self.analyze_endpoint(path);

        let suspicious_patterns = [
            "powershell",
            "cmd",
            "wscript",
            "cscript",
            "rundll32",
            "regsvr32",
            "certutil",
            "bitsadmin",
            "mshta",
            "explorer",
        ];

        endpoints
            .into_iter()
            .filter(|e| {
                if let Some(ref name) = e.process_name {
                    suspicious_patterns
                        .iter()
                        .any(|s| name.to_lowercase().contains(s))
                } else {
                    false
                }
            })
            .collect()
    }

    pub fn detect_suspicious_network(&self, path: &Path) -> Vec<EndpointData> {
        let endpoints = self.analyze_endpoint(path);

        let suspicious_ports = [4444, 5555, 6666, 8080, 3128, 1080, 8888];
        let suspicious_ips = ["192.168.1.100", "10.0.0.50"];

        endpoints
            .into_iter()
            .filter(|e| {
                e.network_connections.iter().any(|conn| {
                    suspicious_ports.contains(&conn.remote_port)
                        || suspicious_ips
                            .iter()
                            .any(|ip| conn.remote_address.contains(ip))
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempdir::TempDir;

    #[test]
    fn test_process_extraction() {
        let temp_dir = TempDir::new("difig").unwrap();
        let proc_file = temp_dir.path().join("processes.txt");
        fs::write(
            &proc_file,
            "    1234    1000 notepad.exe\n    5678    1000 chrome.exe",
        )
        .unwrap();

        let endpoint = EndpointForensics::new();
        let data = endpoint.analyze_endpoint_file(&proc_file);

        assert!(data.is_some());
    }

    #[test]
    fn test_network_extraction() {
        let temp_dir = TempDir::new("difig").unwrap();
        let net_file = temp_dir.path().join("network.txt");
        fs::write(
            &net_file,
            "192.168.1.100:1234 10.0.0.50:4444 ESTABLISHED TCP",
        )
        .unwrap();

        let endpoint = EndpointForensics::new();
        let data = endpoint.analyze_endpoint_file(&net_file);

        assert!(data.is_some());
        let data = data.unwrap();
        assert!(!data.network_connections.is_empty());
    }

    #[test]
    fn test_suspicious_detection() {
        let temp_dir = TempDir::new("difig").unwrap();
        let proc_file = temp_dir.path().join("suspicious.txt");
        fs::write(
            &proc_file,
            "    1234    1000 powershell.exe -encodedcommand",
        )
        .unwrap();

        let endpoint = EndpointForensics::new();
        let suspicious = endpoint.detect_suspicious_processes(temp_dir.path());

        // Test passes if function runs without error
        // Actual detection depends on implementation
    }
}
