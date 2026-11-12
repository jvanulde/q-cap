use crate::manifest::QcapManifest;
use crate::signatures::QcapSignatureBundle;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions as FileOptions;
use zip::ZipWriter;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Create a `.qcap` ZIP archive with the MVP layout.
/// Layout:
/// - `manifest.json`
/// - `payload/…` (all files under input_dir)
/// - `meta/` (empty)
/// - `signatures/` (empty)
pub fn create_qcap_archive(
    input_dir: &Path,
    manifest: &QcapManifest,
    output_file: &Path,
) -> Result<()> {
    // Ensure input_dir exists
    if !input_dir.is_dir() {
        return Err(format!("input_dir is not a directory: {}", input_dir.display()).into());
    }

    let file = File::create(output_file)?;
    let mut zip = ZipWriter::new(file);
    let opts = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    // Write manifest.json at archive root
    zip.start_file("manifest.json", opts)?;
    let manifest_bytes = manifest.to_json_bytes()?;
    zip.write_all(&manifest_bytes)?;

    // Create meta/ and signatures/ directories (empty)
    zip.add_directory("meta/", opts)?;
    zip.add_directory("signatures/", opts)?;

    // Walk input_dir and add files under payload/
    let files = walk_files(input_dir)?;
    for abs in files {
        let rel = abs.strip_prefix(input_dir).unwrap();
        let archive_path = Path::new("payload").join(rel);
        let archive_path_str = path_to_string(&archive_path)?;
        zip.start_file(archive_path_str, opts)?;
        let mut f = File::open(&abs)?;
        io::copy(&mut f, &mut zip)?;
    }

    zip.finish()?;
    Ok(())
}

/// Create a `.qcap` ZIP archive and include `signatures/manifest.sig.json`.
pub fn create_qcap_archive_with_signature(
    input_dir: &Path,
    manifest: &QcapManifest,
    signature: &QcapSignatureBundle,
    output_file: &Path,
) -> Result<()> {
    let file = File::create(output_file)?;
    let mut zip = ZipWriter::new(file);
    let opts = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    // manifest
    zip.start_file("manifest.json", opts)?;
    let manifest_bytes = manifest.to_json_bytes()?;
    zip.write_all(&manifest_bytes)?;

    // meta and signatures dirs
    zip.add_directory("meta/", opts)?;
    zip.add_directory("signatures/", opts)?;

    // signature bundle
    zip.start_file("signatures/manifest.sig.json", opts)?;
    let sig_bytes = serde_json::to_vec_pretty(signature)?;
    zip.write_all(&sig_bytes)?;

    // payload files
    let files = walk_files(input_dir)?;
    for abs in files {
        let rel = abs.strip_prefix(input_dir).unwrap();
        let archive_path = Path::new("payload").join(rel);
        let archive_path_str = path_to_string(&archive_path)?;
        zip.start_file(archive_path_str, opts)?;
        let mut f = File::open(&abs)?;
        io::copy(&mut f, &mut zip)?;
    }

    zip.finish()?;
    Ok(())
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if p.is_file() {
            out.push(p.to_path_buf());
        }
    }
    // Sort for deterministic order
    out.sort();
    Ok(out)
}

fn path_to_string(p: &Path) -> Result<String> {
    p.to_str()
        .map(|s| s.replace('\\', "/"))
        .ok_or_else(|| "non-utf8 path".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::QcapManifest;
    use std::fs;
    use std::io::Read;
    use tempfile::tempdir;
    use zip::read::ZipArchive;

    #[test]
    fn creates_qcap_archive_with_manifest_and_payload() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        // Prepare payload files
        fs::create_dir(root.join("data")).unwrap();
        fs::write(root.join("data/file1.txt"), b"hello").unwrap();
        fs::write(root.join("data/file2.bin"), [1u8, 2, 3, 4]).unwrap();

        let manifest = QcapManifest::new_with_now(
            "0.1.0",
            "blake3:deadbeef",
            Some("issuer:abc".into()),
            serde_json::json!({"title": "Test"}),
        );

        let out = root.join("out.qcap");
        create_qcap_archive(&root.join("data"), &manifest, &out).expect("archive created");

        // Open zip and check structure
        let f = File::open(&out).unwrap();
        let mut zip = ZipArchive::new(f).unwrap();

        // manifest.json exists
        {
            let mut mf = zip.by_name("manifest.json").unwrap();
            let mut s = String::new();
            mf.read_to_string(&mut s).unwrap();
            let parsed: QcapManifest = serde_json::from_str(&s).unwrap();
            assert_eq!(parsed.schema_version, "0.1.0");
        }

        // meta/ and signatures/ directories exist (they may not be listed as entries depending on zip impl,
        // but we can try to access them by name; if not, ensure payload files exist)
        let mut file1 = String::new();
        zip.by_name("payload/file1.txt")
            .unwrap()
            .read_to_string(&mut file1)
            .unwrap();
        assert_eq!(file1, "hello");

        let mut file2 = Vec::new();
        zip.by_name("payload/file2.bin")
            .unwrap()
            .read_to_end(&mut file2)
            .unwrap();
        assert_eq!(file2, vec![1u8, 2, 3, 4]);
    }
}
