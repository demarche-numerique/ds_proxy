use deadpool_redis::{PoolConfig, Timeouts};
use std::time::Duration;
use url::Url;

use super::args;
use super::config::from_flag_or_env;

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: Url,
    pub pool_config: PoolConfig,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: Url::parse("redis://127.0.0.1").unwrap(),
            pool_config: PoolConfig {
                timeouts: Timeouts {
                    wait: Some(Duration::from_millis(200)),
                    create: Some(Duration::from_millis(200)),
                    recycle: Some(Duration::from_millis(200)),
                },
                ..PoolConfig::default()
            },
        }
    }
}

impl RedisConfig {
    pub fn create_redis_config(args: &args::Args) -> RedisConfig {
        let default_config = RedisConfig::default();
        let default_timeouts = default_config.pool_config.timeouts;

        RedisConfig {
            url: from_flag_or_env(&args.flag_redis_url, "REDIS_URL").unwrap_or(default_config.url),
            pool_config: PoolConfig {
                max_size: from_flag_or_env(&args.flag_redis_pool_max_size, "REDIS_POOL_MAX_SIZE")
                    .unwrap_or(default_config.pool_config.max_size),
                timeouts: Timeouts {
                    wait: from_flag_or_env(&args.flag_redis_timeout_wait, "REDIS_TIMEOUT_WAIT")
                        .map(Duration::from_millis)
                        .or(default_timeouts.wait),
                    create: from_flag_or_env(
                        &args.flag_redis_timeout_create,
                        "REDIS_TIMEOUT_CREATE",
                    )
                    .map(Duration::from_millis)
                    .or(default_timeouts.create),
                    recycle: from_flag_or_env(
                        &args.flag_redis_timeout_recycle,
                        "REDIS_TIMEOUT_RECYCLE",
                    )
                    .map(Duration::from_millis)
                    .or(default_timeouts.recycle),
                },
                ..default_config.pool_config
            },
        }
    }
}
