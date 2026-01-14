use libsodium_rs::crypto_secretstream::xchacha20poly1305::Key;
use log::trace;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Keyring {
    keys: HashMap<u64, Key>,
}

impl Keyring {
    pub fn new(keys: HashMap<u64, Key>) -> Keyring {
        Keyring { keys }
    }

    pub fn get_last_key(&self) -> Option<(u64, Key)> {
        if let Some(id) = self.keys.keys().max() {
            trace!("returning key_id {} as last_key", id);
            self.get_key_by_id(id).map(|k| (*id, k))
        } else {
            None
        }
    }

    pub fn get_key_by_id(&self, id: &u64) -> Option<Key> {
        self.keys.get(id).map(|k| k.to_owned())
    }
}
