use super::keyring::Keyring;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use libsodium_rs::crypto_pwhash::scryptsalsa208sha256;
use libsodium_rs::crypto_secretbox::{self, Nonce};
use libsodium_rs::crypto_secretstream::{xchacha20poly1305::KEYBYTES, Key};
use libsodium_rs::random;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;

pub fn load_keyring(keyring_file: &str, master_password: String) -> Keyring {
    let secrets = load_secrets(keyring_file);
    let salt = secrets.salt;

    let master_key = build_master_key(master_password, salt);

    let hash_map = secrets
        .cipher_keyring
        .iter()
        .map(|(id, base64_cipher)| (to_u64(id), decode64(base64_cipher)))
        .map(|(id, cipher)| (id, decrypt(&master_key, cipher)))
        .map(|(id, byte_key)| (id, Key::from_bytes(&byte_key).expect("Invalid key")))
        .collect();

    Keyring::new(hash_map)
}

pub fn add_random_key_to_keyring(keyring_file: &str, master_password: String) {
    let mut secrets = load_secrets(keyring_file);
    let salt = secrets.salt.clone();

    let new_key = random_key();
    let master_key = build_master_key(master_password, salt);
    add_key(keyring_file, &master_key, new_key, &mut secrets);
}

fn add_key(
    keyring_file: &str,
    master_key: &crypto_secretbox::Key,
    key: [u8; 32],
    secrets: &mut Secrets,
) {
    let new_base64_cipher = base64_cipher(master_key, key);

    secrets
        .cipher_keyring
        .insert(next_id(secrets), new_base64_cipher);

    save_secrets(keyring_file, secrets)
}

fn random_key() -> [u8; KEYBYTES] {
    let mut key = [0u8; KEYBYTES];
    libsodium_rs::random::fill_bytes(&mut key);
    key
}

fn to_u64(id: &str) -> u64 {
    id.parse::<u64>().unwrap()
}

fn decode64(text: &str) -> Vec<u8> {
    STANDARD.decode(text).unwrap()
}

fn load_secrets(keyring_file: &str) -> Secrets {
    if let Ok(text_secrets) = std::fs::read_to_string(keyring_file) {
        toml::from_str(&text_secrets).unwrap()
    } else {
        let random_salt = random::bytes(scryptsalsa208sha256::SALTBYTES);
        Secrets {
            cipher_keyring: HashMap::new(),
            salt: STANDARD.encode(&random_salt),
        }
    }
}

fn decrypt(master_key: &crypto_secretbox::Key, nonce_cipher: Vec<u8>) -> [u8; KEYBYTES] {
    let nonce = Nonce::try_from_slice(&nonce_cipher[0..24]).unwrap();
    let cipher = &nonce_cipher[24..];

    crypto_secretbox::open(cipher, &nonce, master_key)
        .expect("could not decipher a key")
        .try_into()
        .unwrap()
}

fn build_master_key(master_password: String, salt: String) -> crypto_secretbox::Key {
    let salt_bytes = STANDARD
        .decode(&salt)
        .expect("Failed to decode salt from base64");
    let typed_salt: [u8; scryptsalsa208sha256::SALTBYTES] =
        salt_bytes.try_into().expect("Salt must be 16 bytes long");

    let key: [u8; KEYBYTES] = scryptsalsa208sha256::pwhash(
        KEYBYTES,
        master_password.as_bytes(),
        &typed_salt,
        scryptsalsa208sha256::OPSLIMIT_INTERACTIVE,
        scryptsalsa208sha256::MEMLIMIT_INTERACTIVE,
    )
    .unwrap()
    .try_into()
    .unwrap();

    crypto_secretbox::Key::from_bytes(&key).unwrap()
}

fn next_id(secrets: &Secrets) -> String {
    if let Some(max) = last_id(secrets) {
        (max + 1).to_string()
    } else {
        "0".to_string()
    }
}

fn last_id(secrets: &Secrets) -> Option<u64> {
    secrets
        .cipher_keyring
        .keys()
        .max()
        .map(|x| x.parse::<u64>().unwrap())
}

fn base64_cipher(master_key: &crypto_secretbox::Key, key: [u8; 32]) -> String {
    let (cipher, nonce) = encrypt(master_key, key);
    let nonce_cipher = concat(nonce, cipher);
    STANDARD.encode(nonce_cipher)
}

fn encrypt(master_key: &crypto_secretbox::Key, byte_key: [u8; 32]) -> (Vec<u8>, Nonce) {
    let nonce = Nonce::generate();
    let cipher = crypto_secretbox::seal(&byte_key, &nonce, master_key);

    (cipher, nonce)
}

fn concat(nonce: Nonce, mut cipher: Vec<u8>) -> Vec<u8> {
    let mut serialized = Vec::<u8>::from(nonce.as_bytes());
    serialized.append(&mut cipher);
    serialized
}

fn save_secrets(keyring_file: &str, secrets: &Secrets) {
    let text_secrets = toml::to_string(secrets).unwrap();
    std::fs::write(keyring_file, text_secrets).unwrap()
}

#[derive(Serialize, Deserialize, Debug)]
struct Secrets {
    #[serde(rename = "keys")]
    cipher_keyring: HashMap<String, String>,
    salt: String,
}
