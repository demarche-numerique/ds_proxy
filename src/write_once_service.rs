use deadpool_redis::{redis::cmd, redis::AsyncCommands, Pool};

const LOCK_DURATION: u64 = 3600; // 1 hour

use sha2::{Digest, Sha256};

// Service that implements the "write once" functionality
// This service uses Redis to track resource uris that have been successfully
// accessed, preventing multiple accesses to the same resource. This is especially
// useful for temporary URLs that should only be valid for a single use.

#[derive(Clone)]
pub struct WriteOnceService {
    pool: Pool,
}

impl WriteOnceService {
    pub fn new(pool: Pool) -> Self {
        WriteOnceService { pool }
    }

    pub fn hash_key(path: &str) -> String {
        format!("locks:{:x}", Sha256::digest(path.as_bytes()))
    }
    pub async fn lock(&self, path: &str) -> Result<bool, String> {
        let key = Self::hash_key(path);
        let mut conn = self.get_redis_connection().await?;

        let result: Option<String> = cmd("SET")
            .arg(&key)
            .arg("true")
            .arg("EX")
            .arg(LOCK_DURATION)
            .arg("NX")
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        let already_exists = result.is_none(); // If None, key already exists
        Ok(!already_exists)
    }

    pub async fn unlock(&self, path: &str) -> Result<(), String> {
        self.get_redis_connection()
            .await?
            .del(Self::hash_key(path))
            .await
            .map_err(|e| e.to_string())
    }

    async fn get_redis_connection(&self) -> Result<deadpool_redis::Connection, String> {
        self.pool
            .get()
            .await
            .map_err(|e| format!("Failed to get Redis connection: {}", e))
    }
}
