use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use qcap_core::archive::create_qcap_archive_with_signature;
use qcap_core::capabilities::CapabilityToken;
use qcap_core::manifest::{PayloadFile, QcapManifest, RecipientStanza};
use qcap_core::payload_merkle::compute_payload_merkle_root;
use qcap_core::signatures::{sign_merkle_root, verify_signature, QcapSignatureBundle};
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tempfile::tempdir;
use walkdir::WalkDir;
use x25519_dalek::{PublicKey, StaticSecret};
use zip::read::ZipArchive;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser)]
#[command(name = "qcap", version, about = "Q-Cap CLI (MVP)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Demo: hash input bytes
    Hash { input: String },
    /// Generate a local identity with signing and recipient encryption keys
    Init {
        #[arg(short = 'o', long = "out")]
        out: PathBuf,
        #[arg(long = "name", default_value = "local")]
        name: String,
    },
    /// Pack a plaintext directory into a signed .qcap archive
    Pack {
        input_dir: PathBuf,
        #[arg(short = 'o', long = "out")]
        out: PathBuf,
        #[arg(short = 'k', long = "key")]
        key: PathBuf,
    },
    /// Seal a directory into an encrypted .qcap archive for a recipient
    Seal {
        input_dir: PathBuf,
        #[arg(short = 'o', long = "out")]
        out: PathBuf,
        #[arg(long = "issuer")]
        issuer: PathBuf,
        #[arg(long = "recipient")]
        recipient: PathBuf,
    },
    /// Verify a .qcap archive
    Verify { file: PathBuf },
    /// Inspect a .qcap archive and print summary
    Inspect { file: PathBuf },
    /// Grant a capability token bound to a .qcap's Merkle root
    Grant {
        file: PathBuf,
        #[arg(long = "allow", default_value = "read")]
        allow: String,
        #[arg(long = "path", default_value = "*")]
        path: String,
        #[arg(long = "audience")]
        audience: String,
        #[arg(long = "expires", default_value = "unix-seconds:9999999999")]
        expires: String,
        #[arg(long = "issuer")]
        issuer: PathBuf,
        #[arg(short = 'o', long = "out")]
        out: PathBuf,
    },
    /// Open a .qcap after verifying a capability token, exporting allowed payload
    Open {
        file: PathBuf,
        #[arg(long = "cap")]
        cap: PathBuf,
        #[arg(long = "identity")]
        identity: PathBuf,
        #[arg(long = "revocations")]
        revocations: Option<PathBuf>,
        #[arg(long = "revocations-url", conflicts_with = "revocations")]
        revocations_url: Option<String>,
        #[arg(short = 'o', long = "out")]
        out: PathBuf,
    },
    /// Revoke a capability token by adding it to a signed revocation list
    Revoke {
        #[arg(long = "cap")]
        cap: PathBuf,
        #[arg(long = "issuer")]
        issuer: PathBuf,
        #[arg(short = 'o', long = "out")]
        out: PathBuf,
        #[arg(long = "reason", default_value = "revoked")]
        reason: String,
    },
    /// Publish a .qcap to a registry
    Publish {
        file: PathBuf,
        #[arg(long = "registry", default_value = "http://127.0.0.1:8080")]
        registry: String,
        #[arg(long = "token", env = "QCAP_REGISTRY_TOKEN")]
        token: Option<String>,
    },
    /// Publish a signed revocations.json to a registry issuer endpoint
    PublishRevocations {
        file: PathBuf,
        #[arg(long = "issuer")]
        issuer: Option<String>,
        #[arg(long = "registry", default_value = "http://127.0.0.1:8080")]
        registry: String,
        #[arg(long = "token", env = "QCAP_REGISTRY_TOKEN")]
        token: Option<String>,
    },
    /// Fetch a .qcap from a registry
    Fetch {
        artifact: String,
        #[arg(short = 'o', long = "out")]
        out: PathBuf,
        #[arg(long = "registry", default_value = "http://127.0.0.1:8080")]
        registry: String,
    },
    /// Fetch a signed revocations.json from a registry issuer endpoint
    FetchRevocations {
        issuer: String,
        #[arg(short = 'o', long = "out")]
        out: PathBuf,
        #[arg(long = "registry", default_value = "http://127.0.0.1:8080")]
        registry: String,
    },
    /// Create a tiny valid GeoPackage fixture for MVP demos and tests
    SampleGeopackage {
        #[arg(short = 'o', long = "out")]
        out: PathBuf,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Identity {
    name: String,
    signing_seed: String,
    signing_public_key: String,
    encryption_secret: String,
    encryption_public_key: String,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Hash { input } => {
            println!("{}", qcap_core::merkle_root_demo(input.as_bytes()));
        }
        Commands::Init { out, name } => {
            let identity = Identity::generate(name);
            write_json(&out, &identity)?;
            println!(
                "Identity created\n- id: {}\n- out: {}",
                identity.id(),
                out.display()
            );
        }
        Commands::Pack {
            input_dir,
            out,
            key,
        } => pack_plain(&input_dir, &out, &key)?,
        Commands::Seal {
            input_dir,
            out,
            issuer,
            recipient,
        } => seal(&input_dir, &out, &issuer, &recipient)?,
        Commands::Verify { file } => {
            let report = verify_archive(&file)?;
            println!(
                "Verification: OK\n- merkle root: {}\n- signer: {}\n- encrypted: {}\n- payload files: {}",
                report.manifest.merkle_root,
                report.signer_short(),
                report.manifest.encrypted,
                report.payload_files
            );
        }
        Commands::Inspect { file } => inspect(&file)?,
        Commands::Grant {
            file,
            allow,
            path,
            audience,
            expires,
            issuer,
            out,
        } => grant(&file, &allow, &path, &audience, &expires, &issuer, &out)?,
        Commands::Open {
            file,
            cap,
            identity,
            revocations,
            revocations_url,
            out,
        } => open_archive(
            &file,
            &cap,
            &identity,
            revocations.as_deref(),
            revocations_url.as_deref(),
            &out,
        )?,
        Commands::Revoke {
            cap,
            issuer,
            out,
            reason,
        } => revoke(&cap, &issuer, &out, &reason)?,
        Commands::Publish {
            file,
            registry,
            token,
        } => publish(&file, &registry, token.as_deref())?,
        Commands::PublishRevocations {
            file,
            issuer,
            registry,
            token,
        } => publish_revocations(&file, issuer.as_deref(), &registry, token.as_deref())?,
        Commands::Fetch {
            artifact,
            out,
            registry,
        } => fetch(&artifact, &out, &registry)?,
        Commands::FetchRevocations {
            issuer,
            out,
            registry,
        } => fetch_revocations(&issuer, &out, &registry)?,
        Commands::SampleGeopackage { out } => sample_geopackage(&out)?,
    }
    Ok(())
}

impl Identity {
    fn generate(name: String) -> Self {
        let mut signing_seed = [0u8; 32];
        OsRng.fill_bytes(&mut signing_seed);
        let signing = SigningKey::from_bytes(&signing_seed);

        let enc_secret = StaticSecret::random_from_rng(OsRng);
        let enc_public = PublicKey::from(&enc_secret);

        Self {
            name,
            signing_seed: hex::encode(signing_seed),
            signing_public_key: hex::encode(signing.verifying_key().to_bytes()),
            encryption_secret: hex::encode(enc_secret.to_bytes()),
            encryption_public_key: hex::encode(enc_public.to_bytes()),
        }
    }

    fn signing_key(&self) -> Result<SigningKey> {
        let bytes = decode_32(&self.signing_seed, "signing_seed")?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    fn encryption_secret(&self) -> Result<StaticSecret> {
        Ok(StaticSecret::from(decode_32(
            &self.encryption_secret,
            "encryption_secret",
        )?))
    }

    fn encryption_public(&self) -> Result<PublicKey> {
        Ok(PublicKey::from(decode_32(
            &self.encryption_public_key,
            "encryption_public_key",
        )?))
    }

    fn id(&self) -> String {
        self.signing_public_key.chars().take(16).collect()
    }
}

struct VerifyReport {
    manifest: QcapManifest,
    signature: QcapSignatureBundle,
    payload_files: usize,
}

impl VerifyReport {
    fn signer_short(&self) -> String {
        self.signature.public_key.chars().take(16).collect()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RevocationList {
    schema_version: String,
    revoked: Vec<RevocationEntry>,
    signature: String,
    public_key: String,
    algorithm: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct RevocationEntry {
    cap_root: String,
    capability_signature: String,
    revoked_at: String,
    reason: String,
}

fn pack_plain(input_dir: &Path, out: &Path, key: &Path) -> Result<()> {
    let root = compute_payload_merkle_root(input_dir)?;
    let manifest = QcapManifest::new_with_now("0.1.0", &root, None, serde_json::json!({}));
    let signing_key = signing_key_from_seed_file(key)?;
    let sig_bundle = sign_merkle_root(&root, &signing_key);
    create_qcap_archive_with_signature(input_dir, &manifest, &sig_bundle, out)?;
    println!(
        "Packed {}\n- merkle root: {}\n- output: {}",
        input_dir.display(),
        root,
        out.display()
    );
    Ok(())
}

fn seal(input_dir: &Path, out: &Path, issuer_path: &Path, recipient_path: &Path) -> Result<()> {
    if !input_dir.is_dir() {
        return Err(format!("input_dir is not a directory: {}", input_dir.display()).into());
    }

    let issuer: Identity = read_json(issuer_path)?;
    let recipient: Identity = read_json(recipient_path)?;
    let mut content_key = [0u8; 32];
    OsRng.fill_bytes(&mut content_key);
    let package_id = random_id();

    let tmp = tempdir()?;
    let encrypted_root = tmp.path().join("payload");
    fs::create_dir_all(&encrypted_root)?;
    let mut files = Vec::new();

    for abs in walk_files(input_dir)? {
        let rel = rel_path(input_dir, &abs)?;
        let plaintext = fs::read(&abs)?;
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = encrypt(&content_key, &nonce, rel.as_bytes(), &plaintext)?;
        let dest = encrypted_root.join(&rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest, &ciphertext)?;
        files.push(PayloadFile {
            path: rel,
            size: ciphertext.len() as u64,
            nonce: hex::encode(nonce),
            ciphertext_hash: blake3_prefixed(&ciphertext),
        });
    }

    let merkle_root = compute_payload_merkle_root(&encrypted_root)?;
    let recipients = vec![wrap_content_key(&content_key, &package_id, &recipient)?];
    let manifest = QcapManifest::new_sealed(
        "0.2.0",
        package_id.clone(),
        &merkle_root,
        Some(issuer.id()),
        serde_json::json!({ "title": "Q-Cap MVP sealed package" }),
        files,
        recipients,
    );
    let sig = sign_merkle_root(&merkle_root, &issuer.signing_key()?);

    create_qcap_archive_with_signature(&encrypted_root, &manifest, &sig, out)?;
    println!(
        "Sealed {}\n- package id: {}\n- merkle root: {}\n- recipient: {}\n- output: {}",
        input_dir.display(),
        package_id,
        merkle_root,
        recipient.id(),
        out.display()
    );
    Ok(())
}

fn grant(
    file: &Path,
    allow: &str,
    path: &str,
    audience: &str,
    expires: &str,
    issuer_path: &Path,
    out: &Path,
) -> Result<()> {
    let report = verify_archive(file)?;
    let issuer: Identity = read_json(issuer_path)?;
    let allow_spec = format!("{allow};path={path};aud={audience}");
    let cap = CapabilityToken::grant(
        &report.manifest.merkle_root,
        &allow_spec,
        expires,
        &issuer.signing_key()?,
    );
    write_json(out, &cap)?;
    println!(
        "Granted capability\n- cap_root: {}\n- allow: {}\n- path: {}\n- audience: {}\n- expires: {}\n- out: {}",
        report.manifest.merkle_root,
        allow,
        path,
        audience,
        expires,
        out.display()
    );
    Ok(())
}

fn revoke(cap_path: &Path, issuer_path: &Path, out: &Path, reason: &str) -> Result<()> {
    let cap: CapabilityToken = read_json(cap_path)?;
    cap.verify()?;
    let issuer: Identity = read_json(issuer_path)?;
    let signing_key = issuer.signing_key()?;

    let mut list = if out.exists() {
        let list: RevocationList = read_json(out)?;
        list.verify()?;
        list
    } else {
        RevocationList::empty(&signing_key)
    };

    let entry = RevocationEntry {
        cap_root: cap.cap_root.clone(),
        capability_signature: cap.signature.clone(),
        revoked_at: unix_timestamp(),
        reason: reason.to_string(),
    };

    if !list
        .revoked
        .iter()
        .any(|existing| existing.capability_signature == entry.capability_signature)
    {
        list.revoked.push(entry);
    }
    list.sign(&signing_key);
    write_json(out, &list)?;
    println!(
        "Revoked capability\n- cap_root: {}\n- revocations: {}\n- out: {}",
        cap.cap_root,
        list.revoked.len(),
        out.display()
    );
    Ok(())
}

fn open_archive(
    file: &Path,
    cap_path: &Path,
    identity_path: &Path,
    revocations_path: Option<&Path>,
    revocations_url: Option<&str>,
    out: &Path,
) -> Result<()> {
    let report = verify_archive(file)?;
    let identity: Identity = read_json(identity_path)?;
    let cap: CapabilityToken = read_json(cap_path)?;
    cap.verify()?;
    if let Some(revocations) = load_revocations(revocations_path, revocations_url)? {
        revocations.verify()?;
        if revocations.revokes(&cap) {
            return Err("capability has been revoked".into());
        }
    }

    let access = Access::parse(&cap.allow)?;
    if cap.cap_root != report.manifest.merkle_root {
        return Err("capability root does not match archive".into());
    }
    if access.operation != "read" {
        return Err("capability does not allow read".into());
    }
    if access.audience != identity.id() {
        return Err("capability audience does not match identity".into());
    }
    enforce_expiry(&cap.expires)?;

    fs::create_dir_all(out)?;
    if report.manifest.encrypted {
        open_encrypted(file, &report.manifest, &identity, &access, out)?;
    } else {
        open_plain(file, &access, out)?;
    }
    println!("Open: OK\n- exported to: {}", out.display());
    Ok(())
}

fn open_encrypted(
    file: &Path,
    manifest: &QcapManifest,
    identity: &Identity,
    access: &Access,
    out: &Path,
) -> Result<()> {
    let package_id = manifest
        .package_id
        .as_deref()
        .ok_or("sealed archive missing package_id")?;
    let stanza = manifest
        .recipients
        .iter()
        .find(|r| r.recipient == identity.encryption_public_key)
        .ok_or("identity is not a recipient for this archive")?;
    let content_key = unwrap_content_key(stanza, package_id, identity)?;

    let f = fs::File::open(file)?;
    let mut zip = ZipArchive::new(f)?;
    let mut exported = 0usize;
    for spec in &manifest.files {
        if !access.allows_path(&spec.path) {
            continue;
        }
        let zip_name = format!("payload/{}", spec.path);
        let mut entry = zip.by_name(&zip_name)?;
        let mut ciphertext = Vec::new();
        entry.read_to_end(&mut ciphertext)?;
        if blake3_prefixed(&ciphertext) != spec.ciphertext_hash {
            return Err(format!("ciphertext hash mismatch: {}", spec.path).into());
        }
        let nonce = decode_24(&spec.nonce, "file nonce")?;
        let plaintext = decrypt(&content_key, &nonce, spec.path.as_bytes(), &ciphertext)?;
        write_safe(out, &spec.path, &plaintext)?;
        exported += 1;
    }
    if exported == 0 {
        return Err("capability did not allow any files".into());
    }
    Ok(())
}

fn open_plain(file: &Path, access: &Access, out: &Path) -> Result<()> {
    let f = fs::File::open(file)?;
    let mut zip = ZipArchive::new(f)?;
    let mut exported = 0usize;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();
        if !name.starts_with("payload/") || entry.is_dir() {
            continue;
        }
        let rel = &name[8..];
        if !access.allows_path(rel) {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        write_safe(out, rel, &bytes)?;
        exported += 1;
    }
    if exported == 0 {
        return Err("capability did not allow any files".into());
    }
    Ok(())
}

fn verify_archive(file: &Path) -> Result<VerifyReport> {
    let f = fs::File::open(file)?;
    let mut zip = ZipArchive::new(f)?;
    let manifest = read_manifest(&mut zip)?;
    let signature = read_signature(&mut zip)?;
    verify_signature(&signature)?;

    let tmp = tempdir()?;
    let mut payload_files = 0usize;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();
        if !name.starts_with("payload/") || entry.is_dir() {
            continue;
        }
        let rel = &name[8..];
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        write_safe(tmp.path(), rel, &bytes)?;
        payload_files += 1;
    }

    let recomputed = compute_payload_merkle_root(tmp.path())?;
    if recomputed != manifest.merkle_root || recomputed != signature.merkle_root {
        return Err(format!(
            "Merkle root mismatch: recomputed={}, manifest={}, signature={}",
            recomputed, manifest.merkle_root, signature.merkle_root
        )
        .into());
    }

    Ok(VerifyReport {
        manifest,
        signature,
        payload_files,
    })
}

fn inspect(file: &Path) -> Result<()> {
    let report = verify_archive(file)?;
    println!(
        "Q-Cap Inspect\n- schema_version: {}\n- package_id: {}\n- merkle_root: {}\n- issuer: {}\n- created_at: {}\n- signer: {}\n- encrypted: {}\n- payload files: {}\n- recipients: {}",
        report.manifest.schema_version,
        report.manifest.package_id.as_deref().unwrap_or("(none)"),
        report.manifest.merkle_root,
        report.manifest.issuer.as_deref().unwrap_or("(none)"),
        report.manifest.created_at,
        report.signer_short(),
        report.manifest.encrypted,
        report.payload_files,
        report.manifest.recipients.len()
    );
    Ok(())
}

fn publish(file: &Path, registry: &str, token: Option<&str>) -> Result<()> {
    let url = format!("{}/artifacts", registry.trim_end_matches('/'));
    let bytes = fs::read(file)?;
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("artifact path has no UTF-8 file name")?;
    let mut request = ureq::post(&url)
        .set("Content-Type", "application/qcap+zip")
        .set("X-Qcap-Name", name);
    if let Some(token) = token.filter(|value| !value.is_empty()) {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    let response: PublishResponse = request.send_bytes(&bytes)?.into_json()?;
    println!(
        "Published\n- artifact: {}\n- url: {}{}",
        response.name,
        registry.trim_end_matches('/'),
        response.path
    );
    Ok(())
}

fn fetch(artifact: &str, out: &Path, registry: &str) -> Result<()> {
    let artifact = artifact.trim_start_matches('/');
    let url = format!(
        "{}/artifacts/{}",
        registry.trim_end_matches('/'),
        artifact.trim_start_matches("artifacts/")
    );
    let response = ureq::get(&url).call()?;
    let mut bytes = Vec::new();
    response.into_reader().read_to_end(&mut bytes)?;
    fs::write(out, bytes)?;
    println!(
        "Fetched\n- artifact: {}\n- out: {}",
        artifact,
        out.display()
    );
    Ok(())
}

fn publish_revocations(
    file: &Path,
    issuer: Option<&str>,
    registry: &str,
    token: Option<&str>,
) -> Result<()> {
    let revocations: RevocationList = read_json(file)?;
    revocations.verify()?;
    let issuer = issuer
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| revocations.public_key.clone());
    let url = revocations_url(registry, &issuer);
    let bytes = fs::read(file)?;
    let mut request = ureq::post(&url).set("Content-Type", "application/qcap-revocations+json");
    if let Some(token) = token.filter(|value| !value.is_empty()) {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    let response: RevocationResponse = request.send_bytes(&bytes)?.into_json()?;
    println!(
        "Published revocations\n- issuer: {}\n- url: {}{}",
        response.issuer,
        registry.trim_end_matches('/'),
        response.path
    );
    Ok(())
}

fn fetch_revocations(issuer: &str, out: &Path, registry: &str) -> Result<()> {
    let url = revocations_url(registry, issuer);
    let revocations = fetch_revocations_from_url(&url)?;
    write_json(out, &revocations)?;
    println!(
        "Fetched revocations\n- issuer: {}\n- out: {}",
        issuer,
        out.display()
    );
    Ok(())
}

fn load_revocations(
    revocations_path: Option<&Path>,
    revocations_url: Option<&str>,
) -> Result<Option<RevocationList>> {
    match (revocations_path, revocations_url) {
        (Some(path), None) => Ok(Some(read_json(path)?)),
        (None, Some(url)) => Ok(Some(fetch_revocations_from_url(url)?)),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err("use either --revocations or --revocations-url, not both".into()),
    }
}

fn fetch_revocations_from_url(url: &str) -> Result<RevocationList> {
    let response = ureq::get(url).call()?;
    let revocations: RevocationList = response.into_json()?;
    revocations.verify()?;
    Ok(revocations)
}

fn revocations_url(registry: &str, issuer: &str) -> String {
    let issuer = issuer.trim().trim_matches('/');
    format!(
        "{}/revocations/{}/revocations.json",
        registry.trim_end_matches('/'),
        issuer
    )
}

fn sample_geopackage(out: &Path) -> Result<()> {
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    if out.exists() {
        fs::remove_file(out)?;
    }

    let conn = Connection::open(out)?;
    conn.pragma_update(None, "application_id", 0x4750_4b47i64)?;
    conn.pragma_update(None, "user_version", 10_300i64)?;
    conn.execute_batch(
        r#"
        CREATE TABLE gpkg_spatial_ref_sys (
            srs_name TEXT NOT NULL,
            srs_id INTEGER NOT NULL PRIMARY KEY,
            organization TEXT NOT NULL,
            organization_coordsys_id INTEGER NOT NULL,
            definition TEXT NOT NULL,
            description TEXT
        );

        CREATE TABLE gpkg_contents (
            table_name TEXT NOT NULL PRIMARY KEY,
            data_type TEXT NOT NULL,
            identifier TEXT UNIQUE,
            description TEXT DEFAULT '',
            last_change DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            min_x DOUBLE,
            min_y DOUBLE,
            max_x DOUBLE,
            max_y DOUBLE,
            srs_id INTEGER,
            CONSTRAINT fk_gc_r_srs_id FOREIGN KEY (srs_id)
                REFERENCES gpkg_spatial_ref_sys(srs_id)
        );

        CREATE TABLE gpkg_geometry_columns (
            table_name TEXT NOT NULL,
            column_name TEXT NOT NULL,
            geometry_type_name TEXT NOT NULL,
            srs_id INTEGER NOT NULL,
            z TINYINT NOT NULL,
            m TINYINT NOT NULL,
            PRIMARY KEY (table_name, column_name),
            CONSTRAINT fk_ggc_tn FOREIGN KEY (table_name)
                REFERENCES gpkg_contents(table_name),
            CONSTRAINT fk_ggc_srs FOREIGN KEY (srs_id)
                REFERENCES gpkg_spatial_ref_sys(srs_id)
        );

        CREATE TABLE observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            geom BLOB NOT NULL
        );
        "#,
    )?;

    conn.execute(
        "INSERT INTO gpkg_spatial_ref_sys VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            "Undefined Cartesian SRS",
            -1i64,
            "NONE",
            -1i64,
            "undefined",
            "undefined Cartesian coordinate reference system"
        ],
    )?;
    conn.execute(
        "INSERT INTO gpkg_spatial_ref_sys VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            "Undefined geographic SRS",
            0i64,
            "NONE",
            0i64,
            "undefined",
            "undefined geographic coordinate reference system"
        ],
    )?;
    conn.execute(
        "INSERT INTO gpkg_spatial_ref_sys VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            "WGS 84 geodetic",
            4326i64,
            "EPSG",
            4326i64,
            "GEOGCS[\"WGS 84\",DATUM[\"World Geodetic System 1984\",SPHEROID[\"WGS 84\",6378137,298.257223563]],PRIMEM[\"Greenwich\",0],UNIT[\"degree\",0.0174532925199433]]",
            "longitude/latitude coordinates in decimal degrees"
        ],
    )?;
    conn.execute(
        "INSERT INTO gpkg_contents (table_name, data_type, identifier, description, last_change, min_x, min_y, max_x, max_y, srs_id)
         VALUES ('observations', 'features', 'observations', 'Q-Cap MVP sample point layer', '2026-06-27T00:00:00.000Z', -123.1207, 49.2827, -123.1207, 49.2827, 4326)",
        [],
    )?;
    conn.execute(
        "INSERT INTO gpkg_geometry_columns VALUES ('observations', 'geom', 'POINT', 4326, 0, 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO observations (name, geom) VALUES (?1, ?2)",
        params![
            "Vancouver sample point",
            geopackage_point_blob(-123.1207, 49.2827)
        ],
    )?;

    println!("GeoPackage created\n- output: {}", out.display());
    Ok(())
}

fn geopackage_point_blob(x: f64, y: f64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(29);
    bytes.extend_from_slice(b"GP");
    bytes.push(0);
    bytes.push(1);
    bytes.extend_from_slice(&4326i32.to_le_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&x.to_le_bytes());
    bytes.extend_from_slice(&y.to_le_bytes());
    bytes
}

#[derive(Deserialize)]
struct PublishResponse {
    name: String,
    path: String,
}

#[derive(Deserialize)]
struct RevocationResponse {
    issuer: String,
    path: String,
}

#[derive(Debug)]
struct Access {
    operation: String,
    path: String,
    audience: String,
}

impl Access {
    fn parse(input: &str) -> Result<Self> {
        let mut parts = input.split(';');
        let operation = parts.next().unwrap_or_default().to_string();
        let mut path = "*".to_string();
        let mut audience = String::new();
        for part in parts {
            if let Some(value) = part.strip_prefix("path=") {
                path = value.to_string();
            } else if let Some(value) = part.strip_prefix("aud=") {
                audience = value.to_string();
            }
        }
        if audience.is_empty() {
            return Err("capability missing audience".into());
        }
        Ok(Self {
            operation,
            path,
            audience,
        })
    }

    fn allows_path(&self, candidate: &str) -> bool {
        glob_match(&self.path, candidate)
    }
}

fn wrap_content_key(
    key: &[u8; 32],
    package_id: &str,
    recipient: &Identity,
) -> Result<RecipientStanza> {
    let recipient_public = recipient.encryption_public()?;
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);
    let wrap_key = derive_wrap_key(shared.as_bytes(), package_id);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let wrapped = encrypt(&wrap_key, &nonce, package_id.as_bytes(), key)?;
    Ok(RecipientStanza {
        recipient: recipient.encryption_public_key.clone(),
        ephemeral_public_key: hex::encode(ephemeral_public.to_bytes()),
        nonce: hex::encode(nonce),
        wrapped_key: hex::encode(wrapped),
        algorithm: "x25519-blake3-xchacha20poly1305".to_string(),
    })
}

fn unwrap_content_key(
    stanza: &RecipientStanza,
    package_id: &str,
    identity: &Identity,
) -> Result<[u8; 32]> {
    let ephemeral = PublicKey::from(decode_32(
        &stanza.ephemeral_public_key,
        "ephemeral_public_key",
    )?);
    let shared = identity.encryption_secret()?.diffie_hellman(&ephemeral);
    let wrap_key = derive_wrap_key(shared.as_bytes(), package_id);
    let nonce = decode_24(&stanza.nonce, "recipient nonce")?;
    let wrapped = hex::decode(&stanza.wrapped_key)?;
    let key = decrypt(&wrap_key, &nonce, package_id.as_bytes(), &wrapped)?;
    if key.len() != 32 {
        return Err("unwrapped content key has wrong length".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&key);
    Ok(out)
}

fn encrypt(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "encryption failed".into())
}

fn decrypt(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "decryption failed".into())
}

fn derive_wrap_key(shared: &[u8; 32], package_id: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"qcap-wrap-key-v1");
    h.update(shared);
    h.update(package_id.as_bytes());
    *h.finalize().as_bytes()
}

fn read_manifest(zip: &mut ZipArchive<fs::File>) -> Result<QcapManifest> {
    let mut mf = zip.by_name("manifest.json")?;
    let mut bytes = Vec::new();
    mf.read_to_end(&mut bytes)?;
    Ok(QcapManifest::from_json_bytes(&bytes)?)
}

fn read_signature(zip: &mut ZipArchive<fs::File>) -> Result<QcapSignatureBundle> {
    let mut sf = zip.by_name("signatures/manifest.sig.json")?;
    let mut s = String::new();
    sf.read_to_string(&mut s)?;
    Ok(serde_json::from_str(&s)?)
}

fn signing_key_from_seed_file(path: &Path) -> Result<SigningKey> {
    let key_hex = fs::read_to_string(path)?;
    Ok(SigningKey::from_bytes(&decode_32(key_hex.trim(), "seed")?))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn decode_32(value: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        return Err(format!("{label} must be 32 bytes").into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_24(value: &str, label: &str) -> Result<[u8; 24]> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 24 {
        return Err(format!("{label} must be 24 bytes").into());
    }
    let mut out = [0u8; 24];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            out.push(entry.path().to_path_buf());
        }
    }
    out.sort();
    Ok(out)
}

fn rel_path(root: &Path, abs: &Path) -> Result<String> {
    let rel = abs.strip_prefix(root)?;
    let s = rel
        .to_str()
        .ok_or("payload path is not valid UTF-8")?
        .replace('\\', "/");
    validate_relative_path(&s)?;
    Ok(s)
}

fn write_safe(root: &Path, rel: &str, bytes: &[u8]) -> Result<()> {
    validate_relative_path(rel)?;
    let dest = root.join(rel);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(dest, bytes)?;
    Ok(())
}

fn validate_relative_path(rel: &str) -> Result<()> {
    let path = Path::new(rel);
    if path.is_absolute() || rel.is_empty() {
        return Err(format!("unsafe payload path: {rel}").into());
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(format!("unsafe payload path: {rel}").into());
        }
    }
    Ok(())
}

fn blake3_prefixed(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("qcap_{}", hex::encode(bytes))
}

fn enforce_expiry(expires: &str) -> Result<()> {
    if let Some(raw) = expires.strip_prefix("unix-seconds:") {
        let expiry: u64 = raw.parse()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if now > expiry {
            return Err("capability has expired".into());
        }
        return Ok(());
    }
    Err("unsupported expiry format; use unix-seconds:<ts>".into())
}

impl RevocationList {
    fn empty(key: &SigningKey) -> Self {
        let mut list = Self {
            schema_version: "0.1.0".to_string(),
            revoked: Vec::new(),
            signature: String::new(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            algorithm: "ed25519".to_string(),
        };
        list.sign(key);
        list
    }

    fn sign(&mut self, key: &SigningKey) {
        self.public_key = hex::encode(key.verifying_key().to_bytes());
        self.algorithm = "ed25519".to_string();
        let sig: Signature = key.sign(self.signing_payload().as_bytes());
        self.signature = hex::encode(sig.to_bytes());
    }

    fn verify(&self) -> Result<()> {
        if self.algorithm != "ed25519" {
            return Err("unsupported revocation list algorithm".into());
        }
        let pk_bytes = hex::decode(&self.public_key)?;
        let sig_bytes = hex::decode(&self.signature)?;
        let pk = VerifyingKey::from_bytes(
            pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "bad revocation public key")?,
        )?;
        let sig = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "bad revocation signature")?,
        );
        pk.verify(self.signing_payload().as_bytes(), &sig)
            .map_err(|_| "revocation list signature verify failed".into())
    }

    fn revokes(&self, cap: &CapabilityToken) -> bool {
        self.revoked.iter().any(|entry| {
            entry.capability_signature == cap.signature && entry.cap_root == cap.cap_root
        })
    }

    fn signing_payload(&self) -> String {
        let mut lines = vec![format!("schema_version={}", self.schema_version)];
        for entry in &self.revoked {
            lines.push(format!(
                "{}|{}|{}|{}",
                entry.cap_root, entry.capability_signature, entry.revoked_at, entry.reason
            ));
        }
        lines.join("\n")
    }
}

fn unix_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix-seconds:{seconds}")
}

fn glob_match(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" || pattern == candidate {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return candidate.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return candidate.ends_with(suffix);
    }
    false
}
