//! Spikes for understanding filename encryption.
//! Run with ./target/debug/examples/path_encryption --key-hex 0001020304050607080900010203040506070809000102030405060708090102 --src ./target --dst /tmp/target encrypt

use aead::{Aead, KeyInit, Payload};
use aes_siv::{Aes256SivAead, Nonce}; // 512-bit key, 128-bit nonce (SIV: reuse-safe)
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use blake3;
use clap::{Parser, Subcommand};
use hkdf::Hkdf;
use sha2::Sha256;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

/// Version tag baked into AD and filename prefixes
const VERSION: &str = "v1";
/// Fixed 128-bit nonce for SIV (allowed/misuse-resistant)
const ZERO_NONCE: [u8; 16] = [0u8; 16];
/// Per-entry type flag for AD
#[derive(Copy, Clone)]
enum EntryType { File, Dir, Symlink }
impl EntryType {
    fn byte(self) -> u8 {
        match self { EntryType::File => 1, EntryType::Dir => 2, EntryType::Symlink => 3 }
    }
}

/// CLI
#[derive(Parser)]
#[command(name = "namecrypt-spike")]
#[command(about = "Deterministic, authenticated filename encryption bound to parent path")]
struct Cli {
    /// 32-byte hex master key (64 hex chars). Use `openssl rand -hex 32`.
    #[arg(long, value_name = "HEX")]
    key_hex: String,

    /// Depth (number of leading path components to leave clear). 0 means encrypt from root of --src.
    #[arg(long, default_value_t = 0)]
    depth: usize,

    /// Source root to read
    #[arg(long)]
    src: PathBuf,

    /// Destination root to write (mirror). Use a different directory than --src.
    #[arg(long)]
    dst: PathBuf,

    /// Mode: encrypt a clear tree into encrypted tree, or decrypt an encrypted tree back to clear
    #[command(subcommand)]
    cmd: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Mirror cleartext tree at --src into encrypted tree at --dst
    Encrypt,
    /// Mirror encrypted tree at --src into cleartext tree at --dst
    Decrypt,
}

struct Keys {
    /// 64-byte key for Aes256SivAead
    siv_key: [u8; 64],
}
fn derive_keys(master_key_32: &[u8; 32]) -> Keys {
    let hk = Hkdf::<Sha256>::new(Some(b"namecrypt-v1"), master_key_32);
    let mut siv_key = [0u8; 64];
    hk.expand(b"names-aes256-siv", &mut siv_key).unwrap();
    Keys { siv_key }
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32 bytes (64 hex chars), got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Build AD from (encrypted absolute parent path, entry type, version)
fn ad_for(parent_enc_abs: &Path, ty: EntryType) -> [u8; 32] {
    let s = format!("{}|{}|{}", VERSION, ty.byte(), parent_enc_abs.display());
    *blake3::hash(s.as_bytes()).as_bytes()
}

/// Base64url encode with version prefix
fn encode_name(ct: &[u8]) -> String {
    format!("{}-{}", VERSION, B64.encode(ct))
}
/// Decode and check version prefix; return ciphertext bytes
fn decode_name(encoded: &str) -> Result<Vec<u8>> {
    let (ver, rest) = encoded.split_once('-').ok_or_else(|| anyhow!("missing version prefix"))?;
    if ver != VERSION {
        return Err(anyhow!("unsupported version: {}", ver));
    }
    Ok(B64.decode(rest)?)
}

/// Long-name handling: if encoded component >255 bytes, spill to sidecar
fn maybe_stub_component(dir: &Path, encoded: &str) -> Result<OsStringOrStub> {
    if encoded.len() <= 255 {
        return Ok(OsStringOrStub::OsString(encoded.into()));
    }
    // Sidecar strategy
    let digest = blake3::hash(encoded.as_bytes());
    let short = &digest.to_hex()[..24]; // 12 bytes hex
    let stub = format!("{}-l-{}", VERSION, short);
    let sidecar = dir.join(format!(".{}.name.{}", VERSION, short));
    fs::write(&sidecar, encoded)?;
    Ok(OsStringOrStub::OsString(stub.into()))
}

enum OsStringOrStub {
    OsString(std::ffi::OsString),
}

fn encrypt_component(
    cipher: &Aes256SivAead,
    parent_enc_abs: &Path,
    clear_name: &OsStr,
    ty: EntryType,
) -> Result<String> {
    let ad = ad_for(parent_enc_abs, ty);
    let nonce = Nonce::from_slice(&ZERO_NONCE);
    let pt = clear_name.as_encoded_bytes();
    let ct = cipher.encrypt(nonce, Payload { msg: pt, aad: &ad })
        .expect("`cipher.encrypt()` failed");
    Ok(encode_name(&ct))
}

fn decrypt_component(
    cipher: &Aes256SivAead,
    parent_enc_abs: &Path,
    enc_name_or_stub: &OsStr,
    ty: EntryType,
) -> Result<std::ffi::OsString> {
    let s = enc_name_or_stub.to_string_lossy();
    let mut encoded = s.to_string();

    // Handle stub via sidecar
    if let Some(rest) = s.strip_prefix(&format!("{}-l-", VERSION)) {
        let sidecar = parent_enc_abs.join(format!(".{}.name.{}", VERSION, rest));
        encoded = fs::read_to_string(&sidecar)
            .with_context(|| format!("missing sidecar {:?}", sidecar))?;
    }

    let ct = decode_name(&encoded)?;
    let ad = ad_for(parent_enc_abs, ty);
    let nonce = Nonce::from_slice(&ZERO_NONCE);
    let pt = cipher.decrypt(nonce, Payload { msg: &ct, aad: &ad })
        .expect("`cipher.decrypt()` failed");
    Ok(std::ffi::OsString::from_vec(pt))
}

fn typ_of(md: &fs::Metadata) -> EntryType {
    if md.is_dir() { EntryType::Dir }
    else if md.is_file() { EntryType::File }
    else { EntryType::Symlink } // simplification
}

fn encrypt_tree(cli: &Cli, keys: &Keys) -> Result<()> {
    let cipher = Aes256SivAead::new_from_slice(&keys.siv_key).unwrap();

    for entry in WalkDir::new(&cli.src).into_iter().filter_map(|e| e.ok()) {
        let src_path = entry.path();
        let rel = rel_components(&cli.src, src_path)?;
        let md = fs::symlink_metadata(src_path)?;
        let ty = typ_of(&md);

        // Build encrypted path component-by-component
        let mut enc_abs = cli.dst.clone(); // current parent encrypted absolute path
        let mut clear_parent = PathBuf::new();
        let mut idx = 0usize;

        let rel_len = rel.len();
        for comp in rel {
            let is_dir_component = match ty {
                EntryType::Dir => true,
                _ => false,
            } && idx == rel_len - 1;

            let comp_ty = if is_dir_component { EntryType::Dir } else { EntryType::File };

            if idx < cli.depth {
                enc_abs.push(&comp);
                clear_parent.push(&comp);
            } else {
                // Encrypt this component, AD bound to current encrypted parent path
                let enc_name = encrypt_component(&cipher, &enc_abs, comp.as_os_str(), comp_ty)?;
                let enc_name_os = match maybe_stub_component(&enc_abs, &enc_name)? {
                    OsStringOrStub::OsString(os) => os,
                };
                enc_abs.push(&enc_name_os);
                clear_parent.push(&comp);
            }
            idx += 1;
        }

        // Create as directory or empty file
        if md.is_dir() {
            fs::create_dir_all(&enc_abs)?;
        } else if md.is_file() {
            if let Some(parent) = enc_abs.parent() { fs::create_dir_all(parent)?; }
            // create empty file to keep counts (don’t copy contents in this spike)
            let _ = File::create(&enc_abs)?;
        }

        println!("{} -> {}",
                 src_path.display(),
                 enc_abs.display());

        // Round-trip test for the leaf name (only if the leaf looks encrypted)
        if let (Some(enc_parent), Some(enc_leaf)) = (enc_abs.parent(), enc_abs.file_name()) {
            let leaf_str = enc_leaf.to_string_lossy();
            let looks_encrypted =
                leaf_str.starts_with(&format!("{VERSION}-")) || leaf_str.starts_with(&format!("{VERSION}-l-"));
            if looks_encrypted {
                let dec = decrypt_component(&cipher, enc_parent, enc_leaf, ty)?;
                println!("      decrypted leaf: {}", Path::new(&dec).display());
            }
        }
    }
    Ok(())
}

fn decrypt_tree(cli: &Cli, keys: &Keys) -> Result<()> {
    let cipher = Aes256SivAead::new_from_slice(&keys.siv_key).unwrap();

    for entry in WalkDir::new(&cli.src).into_iter().filter_map(|e| e.ok()) {
        let enc_path = entry.path();
        let rel = rel_components(&cli.src, enc_path)?;
        let md = fs::symlink_metadata(enc_path)?;
        let ty = typ_of(&md);

        let mut cur_enc_parent = cli.src.clone(); // parent encrypted absolute path where the entry lives
        let mut dec_abs = cli.dst.clone();
        let mut idx = 0usize;

        for comp in rel {
            if idx < cli.depth {
                dec_abs.push(&comp);
                cur_enc_parent.push(&comp);
            } else {
                let dec = decrypt_component(&cipher, &cur_enc_parent, comp.as_os_str(), EntryType::File)?;
                dec_abs.push(&dec);
                cur_enc_parent.push(&comp);
            }
            idx += 1;
        }

        if md.is_dir() {
            fs::create_dir_all(&dec_abs)?;
        } else if md.is_file() {
            if let Some(parent) = dec_abs.parent() { fs::create_dir_all(parent)?; }
            let _ = File::create(&dec_abs)?;
        }

        println!("{} -> {}",
                 enc_path.display(),
                 dec_abs.display());
    }
    Ok(())
}

/// Helper: relative components from root to path (skips root)
fn rel_components<'a>(root: &Path, path: &'a Path) -> Result<Vec<Component<'a>>> {
    let rel = path.strip_prefix(root)
        .with_context(|| format!("{} is not under {}", path.display(), root.display()))?;
    Ok(rel.components().collect())
}

fn main() -> Result<()> {
    // tiny local hex parser to avoid extra crate; put here to keep code self-contained
    mod hex {
        pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
            if s.len() % 2 != 0 { return Err(()); }
            let mut out = Vec::with_capacity(s.len()/2);
            let bytes = s.as_bytes();
            for i in (0..bytes.len()).step_by(2) {
                let hi = from_hex(bytes[i])?;
                let lo = from_hex(bytes[i+1])?;
                out.push((hi << 4) | lo);
            }
            Ok(out)
        }
        fn from_hex(b: u8) -> Result<u8, ()> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                b'A'..=b'F' => Ok(b - b'A' + 10),
                _ => Err(())
            }
        }
    }

    let cli = Cli::parse();
    let master32 = parse_hex32(&cli.key_hex)?;
    let keys = derive_keys(&master32);

    match cli.cmd {
        Mode::Encrypt => encrypt_tree(&cli, &keys),
        Mode::Decrypt => decrypt_tree(&cli, &keys),
    }
}
