#![feature(fs_read_write)]
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate rustbreak;

extern crate ring;
extern crate openssl;
extern crate base32;

use ring::{digest, hkdf, hmac, aead};
use ring::constant_time::verify_slices_are_equal;
use ring::hmac::SigningKey;
use ring::rand::{SecureRandom, SystemRandom};
use openssl::sha;
use openssl::symm::{Cipher, Mode, Crypter};

use rustbreak::Database;

use std::fs::{self, File, remove_file};
use std::io::prelude::*;
use std::io::{SeekFrom, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::convert::AsRef;
pub mod error;

const SUBKEY_INFO: &[u8] = b"crypto-szu";

#[derive(Serialize, Deserialize, Debug)]
struct MetaData {
    filename: String,
    tag: Option<Vec<u8>>,
}

fn path_to_string<P: AsRef<Path>>(path: P) -> String {
    path.as_ref().to_str().unwrap().to_string()
}

fn base32_encode(data: &[u8]) -> String {
    base32::encode(base32::Alphabet::Crockford, data)
}

fn base32_decode(data: &str) -> Option<Vec<u8>> {
    base32::decode(base32::Alphabet::Crockford, data)
}

/// Derive subkey with SHA-256 hkdf(RFC5869).
/// key: master key
/// salt: non-secret random value
/// keysize: sub key size
fn make_subkey(key: &str, salt: &[u8], keysize: usize) -> Vec<u8> {
    let salt = SigningKey::new(&digest::SHA256, salt);
    let mut subkey = Vec::with_capacity(keysize);
    subkey.resize(keysize, 0);
    hkdf::extract_and_expand(&salt, key.as_bytes(), SUBKEY_INFO, &mut subkey);
    subkey
}

/// Encrypt file with AES128-CFB128 and authorize ciphertext with SHA-256 HMAC.
fn encrypt_file<P: AsRef<Path>>(path: P, key: &str, db: &Database<String>) -> error::Result<()> {
    let hash = hash_file(&path)?;
    let base32_hash = base32_encode(&hash);
    let subkey = make_subkey(key, &hash, 16);
    let signing_key = make_subkey(key, &hash, 32);
    let mut iv = [0; 16];
    SystemRandom::new().fill(&mut iv)?;
    let mut encrypter = Crypter::new(Cipher::aes_128_cfb128(), Mode::Encrypt, &subkey, Some(&iv))?;
    let signing_key = hmac::SigningKey::new(&digest::SHA256, &signing_key);
    let mut signing_ctx = hmac::SigningContext::with_key(&signing_key);

    let mut input = File::open(&path)?;
    let mut output_path = PathBuf::new();
    output_path.push(path.as_ref().parent().unwrap());
    output_path.push(&base32_hash);
    let mut output = File::create(&output_path)?;
    let mut plaintext = [0u8; 1024];
    let mut ciphertext = [0u8; 1024 + 16];

    output.write_all(&iv)?;
    while let Ok(n) = input.read(&mut plaintext) {
        if n == 0 {
            break;
        }
        let count = encrypter.update(&plaintext[..n], &mut ciphertext)?;
        signing_ctx.update(&ciphertext[..count]);
        output.write_all(&ciphertext[..count])?;
    }
    let count = encrypter.finalize(&mut ciphertext)?;
    output.write_all(&ciphertext[..count])?;
    let signature = signing_ctx.sign();
    db.insert(
        &base32_hash,
        MetaData {
            filename: path_to_string(&path.as_ref().file_name().unwrap()),
            tag: Some(signature.as_ref().to_vec()),
        },
    )?;

    remove_file(&path)?;
    Ok(())
}

/// Verify Ciphertext with SHA-256 HMAC and decrypt file with AES128-CFB128.
fn decrypt_file<P: AsRef<Path>>(path: P, key: &str, db: &Database<String>) -> error::Result<()> {
    let base32_hash = path_to_string(path.as_ref().file_name().unwrap());
    let hash = base32_decode(&base32_hash).unwrap();
    let metadata: MetaData = db.retrieve(&base32_hash)?;
    let subkey = make_subkey(key, &hash, 16);
    let signing_key = make_subkey(key, &hash, 32);
    let mut iv = [0; 16];

    let mut input = BufReader::new(File::open(&path)?);
    input.read_exact(&mut iv)?;

    let mut ciphertext = [0u8; 1024];
    let signing_key = hmac::SigningKey::new(&digest::SHA256, &signing_key);
    let mut signing_ctx = hmac::SigningContext::with_key(&signing_key);
    while let Ok(n) = input.read(&mut ciphertext) {
        if n == 0 {
            break;
        }
        signing_ctx.update(&ciphertext[..n]);
    }
    let signature = signing_ctx.sign();
    verify_slices_are_equal(signature.as_ref(), &metadata.tag.unwrap())?;

    let mut output_path = PathBuf::new();
    output_path.push(path.as_ref().parent().unwrap());
    output_path.push(&metadata.filename);
    // skip iv;
    input.seek(SeekFrom::Start(16))?;
    let mut output = BufWriter::new(File::create(output_path)?);
    let mut decrypter = Crypter::new(Cipher::aes_128_cfb128(), Mode::Decrypt, &subkey, Some(&iv))?;
    let mut plaintext = [0u8; 1024 + 16];

    while let Ok(n) = input.read(&mut ciphertext) {
        if n == 0 {
            break;
        }
        let count = decrypter.update(&ciphertext[..n], &mut plaintext)?;
        output.write_all(&plaintext[..count])?;
    }
    let count = decrypter.finalize(&mut plaintext)?;
    output.write_all(&plaintext[..count])?;
    remove_file(&path)?;

    Ok(())
}

fn hash_file<P: AsRef<Path>>(path: P) -> error::Result<[u8; 32]> {
    let mut hasher = sha::Sha256::new();
    let mut buf = [0u8; 1024];

    hasher.update(path.as_ref().to_str().unwrap().as_bytes());
    if path.as_ref().is_file() {
        let mut file = File::open(&path)?;
        while let Ok(n) = file.read(&mut buf) {
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    }
    let hash = hasher.finish();
    Ok(hash)
}

fn encrypt<P: AsRef<Path>>(path: P, password: &str, db: &Database<String>) -> error::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        // TODO: handle symlink
        if file_type.is_file() {
            if path.file_name().unwrap() != ".aefs-index" {
                encrypt_file(path, password, db)?;
            }
        } else if file_type.is_dir() {
            let mut new_path = PathBuf::new();
            new_path.push(path.parent().unwrap());
            new_path.push(base32_encode(&hash_file(&path)?));
            fs::rename(&path, &new_path)?;
            db.insert(
                &path_to_string(&new_path),
                MetaData {
                    filename: path_to_string(&path.file_name().unwrap()),
                    tag: None,
                },
            )?;
            encrypt(&new_path, password, db)?;
        }
    }
    Ok(())
}

fn decrypt<P: AsRef<Path>>(path: P, password: &str, db: &Database<String>) -> error::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        // TODO: handle symlink
        if file_type.is_file() {
            if path.file_name().unwrap() != ".aefs-index" {
                decrypt_file(path, password, db)?;
            }
        } else if file_type.is_dir() {
            let metadata: MetaData = db.retrieve(&path_to_string(&path))?;
            let mut new_path = PathBuf::new();
            new_path.push(path.parent().unwrap());
            new_path.push(metadata.filename);
            fs::rename(&path, &new_path)?;
            decrypt(&new_path, password, db)?;
        }
    }
    Ok(())
}

/// Encrypt database with chacha20-poly1305
/// The keys are 256 bits long and the nonces are 96 bits long.
/// The tags is 128 bits long.
fn encrypt_db<P: AsRef<Path>>(path: P, password: &str) -> error::Result<()> {
    let tag_len = 16;
    let mut nonce_and_salt = [0; 12 + 32];
    SystemRandom::new().fill(&mut nonce_and_salt)?;
    let nonce = &nonce_and_salt[..12];
    let salt = &nonce_and_salt[12..];
    let subkey = make_subkey(password, salt, 32);
    let sealing_key = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &subkey)?;
    let mut in_out = fs::read(&path)?;
    in_out.extend([0; 16].iter());
    aead::seal_in_place(&sealing_key, nonce, &nonce_and_salt, &mut in_out, tag_len)?;
    let mut output_file = File::create(&path)?;
    output_file.write_all(&nonce_and_salt)?;
    output_file.write_all(&in_out)?;
    Ok(())
}

/// Decrypt database with chacha20-poly1305
/// The keys are 256 bits long and the nonces are 96 bits long.
/// The tags is 128 bits long.
fn decrypt_db<P: AsRef<Path>>(path: P, password: &str) -> error::Result<()> {
    let mut in_out = fs::read(&path)?;
    let nonce_and_salt = &in_out[..12 + 32].to_vec();
    let nonce = &nonce_and_salt[..12];
    let salt = &nonce_and_salt[12..];
    let subkey = make_subkey(password, salt, 32);
    let opening_key = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &subkey)?;
    let plaintext = aead::open_in_place(&opening_key, nonce, nonce_and_salt, 12 + 32, &mut in_out)?;
    fs::write(&path, plaintext)?;
    Ok(())
}

fn start() -> error::Result<()> {
    let encrypt_or_decrypt = std::env::args().nth(1).unwrap();
    let password = std::env::args().nth(2).unwrap();
    if encrypt_or_decrypt == "e" {
        let db = Database::open(".aefs-index").unwrap();
        encrypt(".", &password, &db)?;
        db.flush()?;
        encrypt_db(".aefs-index", &password)?;
    } else if encrypt_or_decrypt == "d" {
        decrypt_db(".aefs-index", &password)?;
        let db = Database::open(".aefs-index").unwrap();
        decrypt(".", &password, &db)?;
        remove_file(".aefs-index")?;
    }
    Ok(())
}

fn main() {
    start().unwrap();
}
