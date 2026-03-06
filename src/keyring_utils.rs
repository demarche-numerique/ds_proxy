use super::keyring::Keyring;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use libsodium_rs::crypto_pwhash::scryptsalsa208sha256::{
    pwhash, MEMLIMIT_INTERACTIVE, OPSLIMIT_INTERACTIVE, SALTBYTES,
};
use libsodium_rs::crypto_secretbox::{self, Key, Nonce};
use libsodium_rs::crypto_secretstream::{self, xchacha20poly1305::KEYBYTES};
use libsodium_rs::random;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use std::collections::HashMap;
use std::convert::TryInto;

pub fn load_keyring(keyring_file: &str, master_password: String) -> Keyring {
    let secrets = load_secrets(keyring_file);
    let salt = secrets.salt;

    let master_key = build_master_key(master_password, &salt);

    let hash_map = secrets
        .cipher_keyring
        .iter()
        .map(|(id, base64_cipher)| (to_u64(id), decode64(base64_cipher)))
        .map(|(id, cipher)| (id, decrypt(&master_key, cipher)))
        .map(|(id, byte_key)| {
            (
                id,
                crypto_secretstream::Key::from_bytes(&byte_key).expect("Invalid key"),
            )
        })
        .collect();

    Keyring::new(hash_map)
}

pub fn rotate_password(keyring_file: &str, old_password: String) -> String {
    let secrets = load_secrets(keyring_file);
    let salt = secrets.salt;
    let old_master_key = build_master_key(old_password, &salt);

    let plain_keys: Vec<(String, [u8; KEYBYTES])> = secrets
        .cipher_keyring
        .iter()
        .map(|(id, b64)| (id.clone(), decrypt(&old_master_key, decode64(b64))))
        .collect();

    let new_password_bytes: [u8; KEYBYTES] = random::bytes(KEYBYTES).try_into().unwrap();
    let new_password = STANDARD.encode(new_password_bytes);

    // as the new password is randomly generated, we do not need a salt
    let new_master_key = build_master_key(new_password.clone(), &None);

    let new_cipher_keyring: HashMap<String, String> = plain_keys
        .into_iter()
        .map(|(id, key)| (id, base64_cipher(&new_master_key, key)))
        .collect();

    let new_secrets = Secrets {
        cipher_keyring: new_cipher_keyring,
        salt: None,
    };
    save_secrets(keyring_file, &new_secrets);

    new_password
}

pub fn add_random_key_to_keyring(keyring_file: &str, master_password: String) {
    let mut secrets = load_secrets(keyring_file);
    let salt = secrets.salt;

    let new_key = random_key();
    let master_key = build_master_key(master_password, &salt);
    add_key(keyring_file, &master_key, new_key, &mut secrets);
}

fn add_key(keyring_file: &str, master_key: &Key, key: [u8; 32], secrets: &mut Secrets) {
    let new_base64_cipher = base64_cipher(master_key, key);

    secrets
        .cipher_keyring
        .insert(next_id(secrets), new_base64_cipher);

    save_secrets(keyring_file, secrets)
}

fn random_key() -> [u8; KEYBYTES] {
    random::bytes(KEYBYTES).try_into().unwrap()
}

fn to_u64(id: &str) -> u64 {
    id.parse::<u64>().unwrap()
}

fn decode64(text: &str) -> Vec<u8> {
    STANDARD.decode(text).unwrap()
}

fn load_secrets(keyring_file: &str) -> Secrets {
    let text_secrets = std::fs::read_to_string(keyring_file)
        .unwrap_or_else(|_| panic!("keyring_file not found: {}", keyring_file));
    toml::from_str(&text_secrets).unwrap()
}

fn decrypt(master_key: &Key, nonce_cipher: Vec<u8>) -> [u8; KEYBYTES] {
    let nonce = Nonce::try_from_slice(&nonce_cipher[0..24]).unwrap();
    let cipher = &nonce_cipher[24..];

    crypto_secretbox::open(cipher, &nonce, master_key)
        .expect("could not decipher a key")
        .try_into()
        .unwrap()
}

fn build_master_key(master_password: String, salt: &Option<[u8; SALTBYTES]>) -> Key {
    match salt {
        Some(salt) => {
            let key: [u8; KEYBYTES] = pwhash(
                KEYBYTES,
                master_password.as_bytes(),
                salt,
                OPSLIMIT_INTERACTIVE,
                MEMLIMIT_INTERACTIVE,
            )
            .unwrap()
            .try_into()
            .unwrap();

            Key::from_bytes(&key).unwrap()
        }
        None => {
            let key: [u8; KEYBYTES] = decode64(&master_password).try_into().expect(
                "master password must be a valid base64-encoded 32-byte key when no salt is present",
            );
            Key::from_bytes(&key).unwrap()
        }
    }
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

fn base64_cipher(master_key: &Key, key: [u8; 32]) -> String {
    let (cipher, nonce) = encrypt(master_key, key);
    let nonce_cipher = concat(nonce, cipher);
    STANDARD.encode(nonce_cipher)
}

fn encrypt(master_key: &Key, byte_key: [u8; 32]) -> (Vec<u8>, Nonce) {
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

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct Secrets {
    #[serde(rename = "keys")]
    cipher_keyring: HashMap<String, String>,

    #[serde_as(as = "Option<Base64>")]
    #[serde(default)]
    salt: Option<[u8; SALTBYTES]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_keyring_file(password: &str, num_keys: usize) -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        let keyring_path = file.path().to_str().unwrap();

        // remove the file so add_random_key_to_keyring creates a fresh one
        std::fs::remove_file(keyring_path).unwrap();

        for _ in 0..num_keys {
            add_random_key_to_keyring(keyring_path, password.to_string());
        }

        file
    }

    #[test]
    fn rotate_password_preserves_keys() {
        libsodium_rs::ensure_init().unwrap();

        let old_password = "old_password";
        let file = create_keyring_file(old_password, 3);
        let keyring_path = file.path().to_str().unwrap();

        let keyring_before = load_keyring(keyring_path, old_password.to_string());

        let new_password = rotate_password(keyring_path, old_password.to_string());

        assert_ne!(new_password, old_password);

        let keyring_after = load_keyring(keyring_path, new_password);

        for id in 0..3u64 {
            let key_before = keyring_before.get_key_by_id(&id).unwrap();
            let key_after = keyring_after.get_key_by_id(&id).unwrap();
            assert_eq!(key_before.as_bytes(), key_after.as_bytes());
        }
    }

    #[test]
    #[should_panic]
    fn rotate_password_invalidates_old_password() {
        libsodium_rs::ensure_init().unwrap();

        let old_password = "old_password";
        let file = create_keyring_file(old_password, 1);
        let keyring_path = file.path().to_str().unwrap();

        rotate_password(keyring_path, old_password.to_string());

        // loading with old password should panic
        load_keyring(keyring_path, old_password.to_string());
    }
}
