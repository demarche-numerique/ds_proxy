use crate::redis_config::RedisConfig;
use deadpool_redis::{Config, Pool, Runtime};
use url::Url;

pub async fn configure_redis_pool(redis_config: RedisConfig) -> Pool {
    log::info!(
        "Redis URL provided: {}",
        without_password(&redis_config.url)
    );

    let mut cfg = Config::from_url(redis_config.url.clone());
    cfg.pool = Some(redis_config.pool_config);

    let pool = cfg
        .create_pool(Some(Runtime::Tokio1))
        .unwrap_or_else(|err| panic!("Failed to create Redis pool: {}", err));

    // Preload the pool to ensure redis is available
    pool.get()
        .await
        .unwrap_or_else(|err| panic!("Failed to get Redis connection: {}", err));

    pool
}

// A Redis URL may carry its password (redis://:secret@host); it has no
// business in the logs.
fn without_password(url: &Url) -> Url {
    let mut url = url.clone();
    let _ = url.set_password(None);
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_url_is_logged_without_its_password() {
        let url = Url::parse("rediss://user:secret@redis.internal:6380/2").unwrap();
        assert_eq!(
            without_password(&url).as_str(),
            "rediss://user@redis.internal:6380/2"
        );

        let url = Url::parse("redis://127.0.0.1:5555").unwrap();
        assert_eq!(without_password(&url).as_str(), "redis://127.0.0.1:5555");
    }
}
