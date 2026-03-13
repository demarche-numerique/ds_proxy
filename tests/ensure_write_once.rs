extern crate ds_proxy;

use actix_web::guard::Get;
use actix_web::web::resource;
use actix_web::HttpResponse;
use ds_proxy::http::middlewares::ensure_write_once;
use ds_proxy::redis_config::RedisConfig;
use std::thread;
use url::Url;
mod helpers;
pub use helpers::*;

pub async fn mock_success() -> HttpResponse {
    let mut response = HttpResponse::Ok();

    response.body("Hello, world!")
}

pub async fn mock_found() -> HttpResponse {
    let mut response = HttpResponse::Found();
    response.insert_header(("Location", "http://example.com"));

    response.body("Redirecting...")
}

fn launch_redis_with_delay() -> ChildGuard {
    let redis = launch_redis(PrintServerLogs::No);
    thread::sleep(std::time::Duration::from_secs(4));
    redis
}

#[cfg(test)]
mod tests {

    use super::*;
    use actix_web::{middleware::from_fn, test, web, App};
    use deadpool_redis::redis::AsyncCommands;
    use ds_proxy::{redis_utils::configure_redis_pool, write_once_service::WriteOnceService};

    #[actix_web::test]
    #[serial(servers)]
    async fn test_ensure_write_once_blocks_same_path_regardless_of_query_params() {
        let _redis_process = launch_redis_with_delay();

        let config = RedisConfig {
            url: Url::parse("redis://127.0.0.1:5555").unwrap(),
            ..RedisConfig::default()
        };
        let redis_pool = configure_redis_pool(config).await;

        let mut actix_app = App::new().service(
            resource("/test-path")
                .guard(Get())
                .wrap(from_fn(ensure_write_once))
                .to(mock_success),
        );

        actix_app = actix_app.app_data(web::Data::new(WriteOnceService::new(redis_pool.clone())));

        match redis_pool.get().await {
            Ok(mut conn) => {
                let _: () = conn
                    .del(WriteOnceService::hash_key("/test-path"))
                    .await
                    .unwrap();
            }
            Err(_err) => panic!("Failed to get Redis connection"),
        }

        let app = test::init_service(actix_app).await;

        // First request: should pass and lock the path
        let req = test::TestRequest::get()
            .uri("/test-path?temp_url_expires=1234567890&a=1")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let bypass_attempts = [
            "/test-path?temp_url_expires=1234567890&a=1", // identical
            "/test-path?a=1&temp_url_expires=1234567890", // reordered
            "/test-path?temp_url_expires=1234567890&toto=plop1", // extra param
            "/test-path?temp_url_expires=9999999999",     // different values
        ];

        for uri in bypass_attempts {
            let req = test::TestRequest::get().uri(uri).to_request();
            let resp = test::try_call_service(&app, req).await;
            match resp {
                Ok(resp) => panic!("Expected 403 for {}, got {}", uri, resp.status()),
                Err(err) => assert_eq!(err.error_response().status(), 403),
            }
        }
    }

    #[actix_web::test]
    #[serial(servers)]
    async fn test_ensure_write_once_skips_private_uri() {
        let _redis_process = launch_redis_with_delay();

        let config = RedisConfig {
            url: Url::parse("redis://127.0.0.1:5555").unwrap(),
            ..RedisConfig::default()
        };
        let redis_pool = configure_redis_pool(config).await;

        let mut actix_app = App::new().service(
            resource("/test-path")
                .guard(Get())
                .wrap(from_fn(ensure_write_once))
                .to(mock_success),
        );

        actix_app = actix_app.app_data(web::Data::new(WriteOnceService::new(redis_pool.clone())));

        match redis_pool.get().await {
            Ok(mut conn) => {
                let _: () = conn
                    .del(WriteOnceService::hash_key("/test-path"))
                    .await
                    .unwrap();
            }
            Err(_err) => panic!("Failed to get Redis connection"),
        }

        let app = test::init_service(actix_app).await;

        // Private URIs (no temp_url_expires) bypass write_once entirely
        for _ in 0..2 {
            let req = test::TestRequest::get().uri("/test-path").to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);
        }
    }

    #[actix_web::test]
    #[serial(servers)]
    async fn test_ensure_write_once_unlocks_on_non_success_response() {
        let _redis_process = launch_redis_with_delay();
        let config = RedisConfig {
            url: Url::parse("redis://127.0.0.1:5555").unwrap(),
            ..RedisConfig::default()
        };
        let redis_pool = configure_redis_pool(config).await;

        let mut actix_app = App::new().service(
            resource("/test-not-success-path")
                .guard(Get())
                .wrap(from_fn(ensure_write_once))
                .to(mock_found),
        );

        actix_app = actix_app.app_data(web::Data::new(WriteOnceService::new(redis_pool)));

        let app = test::init_service(actix_app).await;

        // Non-success responses (302) should not consume the write-once token
        for _ in 0..2 {
            let req = test::TestRequest::get()
                .uri("/test-not-success-path?temp_url_expires=1234567890")
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 302);
        }
    }
}
