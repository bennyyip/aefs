#![allow(unused_imports, dead_code,unused_variables)]
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate rustbreak;

extern crate ring;
extern crate openssl;
extern crate base32;

use ring::{digest, hkdf, hmac};
use ring::constant_time::verify_slices_are_equal;
use ring::hmac::{Signature, SigningKey};
use ring::rand::{SecureRandom, SystemRandom};
use openssl::sha;
use openssl::symm::{Cipher, Mode, Crypter};

use rustbreak::{Database, Result};

use std::fs::{self, File, remove_file, rename};
use std::io::prelude::*;
use std::io::{SeekFrom, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::convert::AsRef;
use std::env;
pub mod error;

lazy_static! {
    static ref DB: Database<String>={
        Database::open(".aeadfs-index").unwrap()
    };
}
const SUBKEY_INFO: &'static [u8] = b"crypto-szu";

#[derive(Serialize, Deserialize, Debug)]
pub struct MetaData {
    path: String,
    tag: Option<Vec<u8>>,
}

fn base32_encode(data: &[u8]) -> String {
    base32::encode(base32::Alphabet::Crockford, data)
}

fn base32_decode(data: &str) -> Option<Vec<u8>> {
    base32::decode(base32::Alphabet::Crockford, data)
}

fn make_subkey(key: &str, salt: &[u8], keysize: usize) -> Vec<u8> {
    let salt = SigningKey::new(&digest::SHA256, salt);
    let mut subkey = Vec::with_capacity(keysize);
    subkey.resize(keysize, 0);
    hkdf::extract_and_expand(&salt, key.as_bytes(), SUBKEY_INFO, &mut subkey);
    subkey
}

fn decrypt_file<P: AsRef<Path>>(path: P, key: &str) -> error::Result<()> {
    let base32_hash = path.as_ref().file_name().unwrap().to_str().unwrap();
    let hash = base32_decode(base32_hash).unwrap();
    let metadata: MetaData = DB.retrieve(base32_hash)?;
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
    output_path.push(&metadata.path);
    println!(
        "decrypting {} to {}",
        path_to_string(&path),
        path_to_string(&output_path)
    );
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
    println!("{} decrypted to {}", path_to_string(&path), metadata.path);

    Ok(())
}

fn encrypt_file<P: AsRef<Path>>(path: P, key: &str) -> error::Result<()> {
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
    DB.insert(
        &base32_hash,
        MetaData {
            path: path_to_string(&path.as_ref().file_name().unwrap()),
            tag: Some(signature.as_ref().to_vec()),
        },
    )?;
    println!("{} encrypted to {}", path_to_string(&path), base32_hash);

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

fn encrypt<P: AsRef<Path>>(path: P) -> error::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_file() {
            encrypt_file(path, &"my_password")?;
        } else if file_type.is_dir() {
            let mut new_path = PathBuf::new();
            new_path.push(path.parent().unwrap());
            new_path.push(base32_encode(&hash_file(&path)?));
            println!(
                "move {} to {}",
                path.display(),
                new_path.display(),
            );
            fs::rename(&path, &new_path)?;
            DB.insert(
                &path_to_string(&new_path),
                MetaData {
                    path: path_to_string(&path.file_name().unwrap()),
                    tag: None,
                },
            )?;
            encrypt(&new_path)?;
        }
    }
    Ok(())
}

fn decrypt<P: AsRef<Path>>(path: P) -> error::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_file() {
            decrypt_file(path, &"my_password")?;
        } else if file_type.is_dir() {
            let dir_name = path.file_name().unwrap().to_str().unwrap();
            let metadata: MetaData = DB.retrieve(&path_to_string(&path))?;
            let mut new_path = PathBuf::new();
            new_path.push(path.parent().unwrap());
            new_path.push(metadata.path);
            println!(
                "moving {} to {}",
                path.display(),
                new_path.display()
            );
            fs::rename(&path, &new_path)?;
            decrypt(&new_path)?;
        }
    }
    Ok(())
}

fn start() -> error::Result<()> {

    if std::env::args().nth(1).unwrap() == "e" {
        encrypt("test-data")?;
        DB.flush()?;

    } else if std::env::args().nth(1).unwrap() == "d" {
        decrypt("test-data")?;
    }

    // let root = fs::canonicalize(".")?;
    // let path = Path::new("./test-data/ddl.png");
    // let path = fs::canonicalize(path)?;
    // let path = path.strip_prefix(&root)?;
    // encrypt_file(path, &"mypassword")?;

    // let path = "test-data/2MHCX1SPDHS13XJ4T5DZSKEY0Q31E3EGVYZMKA05QHYSVJTHPBFG";
    // println!("{:?}", path);
    // decrypt_file(path, &"mypassword").unwrap();

    Ok(())
}

fn main() {
    start().unwrap();
}

fn path_to_string<P: AsRef<Path>>(path: P) -> String {
    path.as_ref().to_str().unwrap().to_string()
}
