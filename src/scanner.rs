use std::path::Path;
use walkdir::WalkDir;

const SKIP_DIRS: &[&str] = &["/proc", "/dev", "/sys", "proc", "dev", "sys"];

pub struct Scanner {
    show_hidden: bool,
}

impl Scanner {
    pub fn new(show_hidden: bool) -> Self {
        Scanner { show_hidden }
    }

    pub fn scan_directory(&self, target: &Path) -> Vec<std::path::PathBuf> {
        let mut files = Vec::new();

        let walker = WalkDir::new(target)
            .follow_links(false)
            .same_file_system(true)
            .into_iter()
            .filter_entry(|entry| {
                let path = entry.path();
                if path.is_dir() {
                    if self.should_skip_dir(path) {
                        return false;
                    }
                    if !self.show_hidden && self.is_hidden(path) {
                        return false;
                    }
                } else if path.is_file() {
                    if !self.show_hidden && self.is_hidden(path) {
                        return false;
                    }
                }
                true
            });

        for entry in walker {
            match entry {
                Ok(entry) => {
                    let path = entry.path();
                    if path.is_file() {
                        files.push(path.to_path_buf());
                    }
                }
                Err(e) => {
                    if let Some(path_ref) = e.path() {
                        eprintln!(
                            "Warning: Could not access path: {} - {}",
                            path_ref.display(),
                            e
                        );
                    } else {
                        eprintln!("Warning: Could not access path: {}", e);
                    }
                }
            }
        }

        files
    }

    fn should_skip_dir(&self, path: &Path) -> bool {
        if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
            if let Some(file_name) = path.file_name() {
                if let Some(name_str) = file_name.to_str() {
                    return SKIP_DIRS.contains(&name_str);
                }
            }
        }
        false
    }

    fn is_hidden(&self, path: &Path) -> bool {
        if let Some(file_name) = path.file_name() {
            if let Some(name_str) = file_name.to_str() {
                return name_str.starts_with('.');
            }
        }
        false
    }

    #[allow(dead_code)]
    pub fn get_file_count(&self, target: &Path) -> usize {
        self.scan_directory(target).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::Builder;

    #[test]
    fn test_scanner_hidden_files() {
        let temp_dir = Builder::new().prefix("difig").tempdir().unwrap();
        let dir = temp_dir.path();

        fs::write(dir.join("visible.txt"), "test").unwrap();
        fs::write(dir.join(".hidden.txt"), "hidden").unwrap();

        let scanner = Scanner::new(false);
        let files = scanner.scan_directory(dir);

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_name().unwrap(), "visible.txt");
    }

    #[test]
    fn test_scanner_include_hidden() {
        let temp_dir = Builder::new().prefix("difig").tempdir().unwrap();
        let dir = temp_dir.path();

        fs::write(dir.join("visible.txt"), "test").unwrap();
        fs::write(dir.join(".hidden.txt"), "hidden").unwrap();

        let scanner = Scanner::new(true);
        let files = scanner.scan_directory(dir);

        assert_eq!(files.len(), 2);
    }
}
