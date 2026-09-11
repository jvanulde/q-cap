use assert_cmd::Command;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use tempfile::tempdir;
use zip::ZipArchive;

fn write_seed_hex(path: &PathBuf) {
    // Deterministic 32-byte seed for reproducible tests
    fs::write(
        path,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    )
    .unwrap();
}

fn write_identity_seed(identity_path: &PathBuf, seed_path: &PathBuf) {
    let identity_json: serde_json::Value =
        serde_json::from_slice(&fs::read(identity_path).unwrap()).unwrap();
    fs::write(seed_path, identity_json["signing_seed"].as_str().unwrap()).unwrap();
}

#[test]
fn pack_then_verify_ok() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let payload = root.join("payload");
    fs::create_dir_all(&payload).unwrap();
    fs::write(payload.join("a.txt"), b"hello").unwrap();
    fs::write(payload.join("b.bin"), [1u8, 2, 3, 4]).unwrap();

    let out = root.join("demo.qcap");
    let seed = root.join("seed.hex");
    write_seed_hex(&seed);

    // Pack
    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "pack",
            payload.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--key",
            seed.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(out.exists(), "qcap created");

    // Verify
    let verify = Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args(["verify", out.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(
        String::from_utf8_lossy(&verify).contains("Verification: OK"),
        "verify reports success"
    );
}

#[test]
fn verify_fails_on_tamper() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let payload = root.join("payload");
    fs::create_dir_all(&payload).unwrap();
    fs::write(payload.join("a.txt"), b"hello").unwrap();
    fs::write(payload.join("b.bin"), [1u8, 2, 3, 4]).unwrap();

    let out = root.join("demo.qcap");
    let seed = root.join("seed.hex");
    write_seed_hex(&seed);

    // Pack
    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "pack",
            payload.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--key",
            seed.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Tamper: rewrite payload/a.txt within the zip
    {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&out)
            .unwrap();
        let mut zip = ZipArchive::new(f).unwrap();
        {
            let mut file = zip.by_name("payload/a.txt").unwrap();
            // Read original to satisfy borrow; then write new content via replace operation
            let mut _buf = Vec::new();
            use std::io::Read;
            file.read_to_end(&mut _buf).unwrap();
        }
        // ZipArchive doesn't support in-place modification easily; instead, extract and rebuild quick tamper:
    }
    // Simpler tamper: recreate archive with changed payload content
    let tampered = root.join("demo_tampered.qcap");
    {
        // Extract original and rewrite file
        let f = fs::File::open(&out).unwrap();
        let mut zip = ZipArchive::new(f).unwrap();
        let extract_dir = root.join("extract");
        fs::create_dir_all(&extract_dir).unwrap();
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i).unwrap();
            let name = entry.name().to_string();
            let dest = extract_dir.join(&name);
            if entry.is_dir() {
                fs::create_dir_all(&dest).ok();
            } else {
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent).ok();
                }
                let mut buf = Vec::new();
                use std::io::Read;
                entry.read_to_end(&mut buf).unwrap();
                fs::write(&dest, &buf).unwrap();
            }
        }
        // Overwrite payload file
        fs::write(extract_dir.join("payload/a.txt"), b"tampered").unwrap();
        // Repack minimal: rebuild zip from extracted tree
        let file = fs::File::create(&tampered).unwrap();
        let mut zw = zip::ZipWriter::new(file);
        let opts =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for entry in walkdir::WalkDir::new(&extract_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            let rel = p.strip_prefix(&extract_dir).unwrap();
            let name = rel.to_str().unwrap().replace('\\', "/");
            if entry.file_type().is_dir() {
                zw.add_directory(name.clone(), opts).ok();
            } else {
                zw.start_file(name.clone(), opts).unwrap();
                let bytes = fs::read(p).unwrap();
                use std::io::Write;
                zw.write_all(&bytes).unwrap();
            }
        }
        zw.finish().unwrap();
    }

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args(["verify", tampered.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn grant_and_open_flow() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let payload = root.join("payload");
    fs::create_dir_all(&payload).unwrap();
    fs::write(payload.join("a.txt"), b"hello").unwrap();
    fs::write(payload.join("b.bin"), [1u8, 2, 3, 4]).unwrap();

    let out_qcap = root.join("demo.qcap");
    let seed = root.join("seed.hex");
    let cap = root.join("cap.json");
    let issuer = root.join("issuer.identity.json");
    let identity = root.join("recipient.identity.json");
    let export_dir = root.join("exported");

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "init",
            "--name",
            "issuer",
            "--out",
            issuer.to_str().unwrap(),
        ])
        .assert()
        .success();
    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "init",
            "--name",
            "recipient",
            "--out",
            identity.to_str().unwrap(),
        ])
        .assert()
        .success();
    write_identity_seed(&issuer, &seed);
    let identity_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&identity).unwrap()).unwrap();
    let audience = identity_json["signing_public_key"].as_str().unwrap()[0..16].to_string();

    // Pack
    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "pack",
            payload.to_str().unwrap(),
            "--out",
            out_qcap.to_str().unwrap(),
            "--key",
            seed.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Grant
    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "grant",
            out_qcap.to_str().unwrap(),
            "--allow",
            "read",
            "--audience",
            &audience,
            "--expires",
            "unix-seconds:9999999999",
            "--issuer",
            issuer.to_str().unwrap(),
            "--out",
            cap.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(cap.exists(), "cap token created");

    // Open
    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "open",
            out_qcap.to_str().unwrap(),
            "--cap",
            cap.to_str().unwrap(),
            "--identity",
            identity.to_str().unwrap(),
            "--out",
            export_dir.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(export_dir.join("a.txt").exists());
    assert!(export_dir.join("b.bin").exists());
}

#[test]
fn revoked_capability_blocks_open() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let payload = root.join("payload");
    fs::create_dir_all(&payload).unwrap();
    fs::write(payload.join("a.txt"), b"hello").unwrap();

    let out_qcap = root.join("demo.qcap");
    let seed = root.join("seed.hex");
    let cap = root.join("cap.json");
    let revocations = root.join("revocations.json");
    let issuer = root.join("issuer.identity.json");
    let identity = root.join("recipient.identity.json");
    let export_dir = root.join("exported");

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "init",
            "--name",
            "issuer",
            "--out",
            issuer.to_str().unwrap(),
        ])
        .assert()
        .success();
    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "init",
            "--name",
            "recipient",
            "--out",
            identity.to_str().unwrap(),
        ])
        .assert()
        .success();
    write_identity_seed(&issuer, &seed);
    let identity_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&identity).unwrap()).unwrap();
    let audience = identity_json["signing_public_key"].as_str().unwrap()[0..16].to_string();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "pack",
            payload.to_str().unwrap(),
            "--out",
            out_qcap.to_str().unwrap(),
            "--key",
            seed.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "grant",
            out_qcap.to_str().unwrap(),
            "--allow",
            "read",
            "--audience",
            &audience,
            "--expires",
            "unix-seconds:9999999999",
            "--issuer",
            issuer.to_str().unwrap(),
            "--out",
            cap.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "revoke",
            "--cap",
            cap.to_str().unwrap(),
            "--issuer",
            issuer.to_str().unwrap(),
            "--out",
            revocations.to_str().unwrap(),
            "--reason",
            "rotation",
        ])
        .assert()
        .success();
    assert!(revocations.exists(), "revocation list created");

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "open",
            out_qcap.to_str().unwrap(),
            "--cap",
            cap.to_str().unwrap(),
            "--identity",
            identity.to_str().unwrap(),
            "--revocations",
            revocations.to_str().unwrap(),
            "--out",
            export_dir.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn seal_grant_open_exports_only_allowed_paths() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let payload = root.join("payload");
    fs::create_dir_all(payload.join("reports")).unwrap();
    fs::create_dir_all(payload.join("secrets")).unwrap();
    fs::write(payload.join("reports/summary.txt"), b"allowed").unwrap();
    fs::write(payload.join("secrets/private.txt"), b"blocked").unwrap();

    let issuer = root.join("issuer.identity.json");
    let recipient = root.join("recipient.identity.json");
    let qcap = root.join("sealed.qcap");
    let cap = root.join("cap.json");
    let export_dir = root.join("exported");
    let geopackage = payload.join("reports/observations.gpkg");

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "init",
            "--name",
            "issuer",
            "--out",
            issuer.to_str().unwrap(),
        ])
        .assert()
        .success();
    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "init",
            "--name",
            "recipient",
            "--out",
            recipient.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args(["sample-geopackage", "--out", geopackage.to_str().unwrap()])
        .assert()
        .success();
    assert!(
        fs::read(&geopackage)
            .unwrap()
            .starts_with(b"SQLite format 3\0"),
        "sample GeoPackage is a SQLite database"
    );

    let recipient_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&recipient).unwrap()).unwrap();
    let audience = recipient_json["signing_public_key"].as_str().unwrap()[0..16].to_string();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "seal",
            payload.to_str().unwrap(),
            "--issuer",
            issuer.to_str().unwrap(),
            "--recipient",
            recipient.to_str().unwrap(),
            "--out",
            qcap.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "grant",
            qcap.to_str().unwrap(),
            "--issuer",
            issuer.to_str().unwrap(),
            "--audience",
            &audience,
            "--path",
            "reports/*",
            "--out",
            cap.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "open",
            qcap.to_str().unwrap(),
            "--cap",
            cap.to_str().unwrap(),
            "--identity",
            recipient.to_str().unwrap(),
            "--out",
            export_dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(export_dir.join("reports/summary.txt").exists());
    assert_eq!(
        fs::read(&geopackage).unwrap(),
        fs::read(export_dir.join("reports/observations.gpkg")).unwrap(),
        "GeoPackage should export byte-for-byte unchanged"
    );
    assert!(!export_dir.join("secrets/private.txt").exists());
}

#[test]
fn open_rejects_capability_from_untrusted_signer() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let payload = root.join("payload");
    fs::create_dir_all(&payload).unwrap();
    fs::write(payload.join("a.txt"), b"hello").unwrap();

    let issuer = root.join("issuer.identity.json");
    let recipient = root.join("recipient.identity.json");
    let attacker = root.join("attacker.identity.json");
    let qcap = root.join("sealed.qcap");
    let cap = root.join("attacker-cap.json");
    let export_dir = root.join("exported");

    for (name, path) in [
        ("issuer", &issuer),
        ("recipient", &recipient),
        ("attacker", &attacker),
    ] {
        Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
            .args(["init", "--name", name, "--out", path.to_str().unwrap()])
            .assert()
            .success();
    }

    let recipient_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&recipient).unwrap()).unwrap();
    let audience = recipient_json["signing_public_key"].as_str().unwrap()[0..16].to_string();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "seal",
            payload.to_str().unwrap(),
            "--issuer",
            issuer.to_str().unwrap(),
            "--recipient",
            recipient.to_str().unwrap(),
            "--out",
            qcap.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "grant",
            qcap.to_str().unwrap(),
            "--issuer",
            attacker.to_str().unwrap(),
            "--audience",
            &audience,
            "--out",
            cap.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "open",
            qcap.to_str().unwrap(),
            "--cap",
            cap.to_str().unwrap(),
            "--identity",
            recipient.to_str().unwrap(),
            "--out",
            export_dir.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn revoke_rejects_issuer_that_did_not_sign_capability() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let payload = root.join("payload");
    fs::create_dir_all(&payload).unwrap();
    fs::write(payload.join("a.txt"), b"hello").unwrap();

    let issuer = root.join("issuer.identity.json");
    let recipient = root.join("recipient.identity.json");
    let attacker = root.join("attacker.identity.json");
    let qcap = root.join("sealed.qcap");
    let cap = root.join("cap.json");
    let revocations = root.join("revocations.json");

    for (name, path) in [
        ("issuer", &issuer),
        ("recipient", &recipient),
        ("attacker", &attacker),
    ] {
        Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
            .args(["init", "--name", name, "--out", path.to_str().unwrap()])
            .assert()
            .success();
    }

    let recipient_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&recipient).unwrap()).unwrap();
    let audience = recipient_json["signing_public_key"].as_str().unwrap()[0..16].to_string();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "seal",
            payload.to_str().unwrap(),
            "--issuer",
            issuer.to_str().unwrap(),
            "--recipient",
            recipient.to_str().unwrap(),
            "--out",
            qcap.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "grant",
            qcap.to_str().unwrap(),
            "--issuer",
            issuer.to_str().unwrap(),
            "--audience",
            &audience,
            "--out",
            cap.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "revoke",
            "--cap",
            cap.to_str().unwrap(),
            "--issuer",
            attacker.to_str().unwrap(),
            "--out",
            revocations.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn verify_rejects_tampered_manifest_metadata() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let payload = root.join("payload");
    fs::create_dir_all(&payload).unwrap();
    fs::write(payload.join("a.txt"), b"hello").unwrap();

    let out = root.join("demo.qcap");
    let tampered = root.join("tampered.qcap");
    let seed = root.join("seed.hex");
    write_seed_hex(&seed);

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args([
            "pack",
            payload.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--key",
            seed.to_str().unwrap(),
        ])
        .assert()
        .success();

    rewrite_manifest_title(&out, &tampered, "tampered title");

    Command::new(assert_cmd::cargo::cargo_bin!("qcap-cli"))
        .args(["verify", tampered.to_str().unwrap()])
        .assert()
        .failure();
}

fn rewrite_manifest_title(source: &PathBuf, dest: &PathBuf, title: &str) {
    let f = fs::File::open(source).unwrap();
    let mut zip = ZipArchive::new(f).unwrap();
    let out = fs::File::create(dest).unwrap();
    let mut zw = zip::ZipWriter::new(out);
    let opts =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).unwrap();
        let name = entry.name().to_string();
        if entry.is_dir() {
            zw.add_directory(name, opts).unwrap();
            continue;
        }

        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        if name == "manifest.json" {
            let mut manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            manifest["metadata"] = serde_json::json!({ "title": title });
            bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        }
        zw.start_file(name, opts).unwrap();
        zw.write_all(&bytes).unwrap();
    }
    zw.finish().unwrap();
}
