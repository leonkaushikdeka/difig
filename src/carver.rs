use difig::{CarvedData, CarvingSignature};
use rayon::prelude::*;
use std::fs;
use std::io::{Read, Seek};
use std::path::Path;

pub struct Carver;

impl Carver {
    pub fn new() -> Self {
        Carver
    }

    pub fn carve_file(&self, path: &Path, output_dir: &Path, min_size: usize) -> Vec<CarvedData> {
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };

        if data.len() < min_size {
            return Vec::new();
        }

        let mut carved_files = Vec::new();
        let chunk_size = 8192;
        let signatures = difig::get_carving_signatures();

        for chunk_start in (0..(data.len().saturating_sub(min_size))).step_by(chunk_size) {
            let chunk_end = std::cmp::min(chunk_start + chunk_size * 10, data.len());
            let chunk = &data[chunk_start..chunk_end];

            for sig in signatures.iter() {
                if let Some(offset) = self.find_signature(chunk, sig) {
                    let absolute_offset = chunk_start + offset;
                    let estimated_size = self.estimate_file_size(&data, absolute_offset, sig);

                    if estimated_size >= sig.min_size {
                        let carved = CarvedData {
                            file_type: sig.extension.to_string(),
                            offset: absolute_offset as u64,
                            size: estimated_size,
                            confidence: 0.85,
                            carved_path: None,
                        };
                        carved_files.push(carved);
                    }
                }
            }
        }

        carved_files
    }

    pub fn carve_disk_image(&self, image_path: &Path, output_dir: &Path) -> Vec<CarvedData> {
        std::fs::create_dir_all(output_dir).ok();

        let carved = self.carve_file(image_path, output_dir, 1024);
        let carved_dir = output_dir.join("carved");

        let results: Vec<CarvedData> = carved
            .into_par_iter()
            .map(|mut carvable| {
                let output_name = format!(
                    "carved_{}_{}_{}.{}",
                    carvable.offset,
                    carvable.size,
                    chrono::Utc::now().timestamp_nanos(),
                    carvable.file_type
                );
                let output_path = carved_dir.join(&output_name);

                if let Ok(data) =
                    self.extract_carved_data(image_path, carvable.offset, carvable.size)
                {
                    if fs::write(&output_path, &data).is_ok() {
                        carvable.carved_path = Some(output_path);
                    }
                }

                carvable
            })
            .collect();

        results
    }

    fn find_signature(&self, data: &[u8], sig: &CarvingSignature) -> Option<usize> {
        let sig_len = sig.magic_bytes.len();
        if data.len() < sig_len {
            return None;
        }

        let mask = sig.magic_bytes_mask.as_deref().unwrap_or(&[0xFFu8; 16]);
        let mask_len = std::cmp::min(sig_len, mask.len());

        for i in 0..=(data.len().saturating_sub(sig_len)) {
            let mut match_count = 0;
            for j in 0..mask_len {
                if mask[j] == 0xFF {
                    if data[i + j] == sig.magic_bytes[j] {
                        match_count += 1;
                    } else {
                        break;
                    }
                }
            }
            if match_count >= mask_len {
                return Some(i);
            }
        }

        None
    }

    fn estimate_file_size(&self, data: &[u8], offset: usize, sig: &CarvingSignature) -> u64 {
        if let Some(max) = sig.max_size {
            return std::cmp::min(max, (data.len().saturating_sub(offset)) as u64);
        }

        let mut size = sig.min_size;
        let end_limit = std::cmp::min(data.len(), offset + 10 * 1024 * 1024);

        for i in (offset + sig.min_size as usize)..end_limit {
            if data[i] == 0x00 && data[i + 1] == 0x00 && data[i + 2] == 0x00 && data[i + 3] == 0x00
            {
                break;
            }
            size += 1;
        }

        size as u64
    }

    fn extract_carved_data(
        &self,
        image_path: &Path,
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>, std::io::Error> {
        let file = fs::File::open(image_path)?;
        let mut reader = std::io::BufReader::new(file);
        let mut buffer = vec![0u8; size as usize];

        reader.seek(std::io::SeekFrom::Start(offset))?;
        reader.read_exact(&mut buffer)?;

        Ok(buffer)
    }

    pub fn get_signature_count(&self) -> usize {
        difig::get_carving_signatures().len()
    }

    pub fn list_signatures(&self) -> Vec<String> {
        difig::get_carving_signatures()
            .iter()
            .map(|s| format!("{} - {}", s.extension, s.description))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::Builder;

    #[test]
    fn test_carver_basic() {
        let temp_dir = Builder::new().prefix("difig").tempdir().unwrap();
        let test_file = temp_dir.path().join("test.bin");

        let mut data = Vec::new();
        data.extend_from_slice(&[0x00u8; 100]);
        data.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
        data.extend_from_slice(&[0xFFu8; 500]);
        fs::write(&test_file, &data).unwrap();

        let carver = Carver::new();
        let carved = carver.carve_file(&test_file, temp_dir.path(), 10);

        assert!(carved.iter().any(|c| c.file_type == "jpg"));
    }

    #[test]
    fn test_carver_signature_count() {
        let carver = Carver::new();
        let count = carver.get_signature_count();
        assert!(
            count >= 20,
            "Expected at least 20 signatures, got {}",
            count
        );
    }

    #[test]
    fn test_carver_list_signatures() {
        let carver = Carver::new();
        let signatures = carver.list_signatures();

        assert!(signatures.iter().any(|s| s.contains("jpg")));
        assert!(signatures.iter().any(|s| s.contains("png")));
        assert!(signatures.iter().any(|s| s.contains("pdf")));
        assert!(signatures.iter().any(|s| s.contains("zip")));
    }
}
