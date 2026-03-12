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
    async fn test_ensure_write_once_with_user_facing_uri_with_success() {
        let _redis_process = launch_redis_with_delay();

        let config = RedisConfig {
            url: Url::parse("redis://127.0.0.1:5555").unwrap(),
            ..RedisConfig::default()
        };
        let redis_pool = configure_redis_pool(config).await;

        let mut actix_app = App::new().service(
            resource("/test-success-path")
                .guard(Get())
                .wrap(from_fn(ensure_write_once))
                .to(mock_success),
        );

        log::info!("Redis pool available.");

        actix_app = actix_app.app_data(web::Data::new(WriteOnceService::new(redis_pool.clone())));

        // on clean la clé
        match redis_pool.get().await {
            Ok(mut conn) => conn
                .del(WriteOnceService::hash_key("/test-success-path"))
                .await
                .unwrap(),
            Err(_err) => panic!("Failed to get Redis connection"),
        }

        let app = test::init_service(actix_app).await;

        // Effectue une première requête (devrait passer, et de maniere sous-jacente, écrire dans Redis)
        let req = test::TestRequest::get()
            .uri("/test-success-path?temp_url_expires=1234567890")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // Effectue une seconde requête (devrait être refusée)
        let req = test::TestRequest::get()
            .uri("/test-success-path?temp_url_expires=1234567890")
            .to_request();
        let resp2 = test::try_call_service(&app, req).await;
        match resp2 {
            Ok(resp) => panic!(
                "Expected an error, but got a response, status: {}",
                resp.status()
            ),
            Err(err) => {
                assert_eq!(err.error_response().status(), 403);
            }
        }
    }

    #[actix_web::test]
    #[serial(servers)]
    async fn test_ensure_write_once_with_private_uri() {
        let _redis_process = launch_redis_with_delay();

        let config = RedisConfig {
            url: Url::parse("redis://127.0.0.1:5555").unwrap(),
            ..RedisConfig::default()
        };
        let redis_pool = configure_redis_pool(config).await;

        let mut actix_app = App::new().service(
            resource("/test-success-path")
                .guard(Get())
                .wrap(from_fn(ensure_write_once))
                .to(mock_success),
        );

        log::info!("Redis pool available.");

        actix_app = actix_app.app_data(web::Data::new(WriteOnceService::new(redis_pool.clone())));

        // on clean la clé
        match redis_pool.get().await {
            Ok(mut conn) => conn
                .del(WriteOnceService::hash_key("/test-success-path"))
                .await
                .unwrap(),
            Err(_err) => panic!("Failed to get Redis connection"),
        }

        let app = test::init_service(actix_app).await;

        // Effectue une première requête (devrait passer outre le write_once)
        let req = test::TestRequest::get()
            .uri("/test-success-path")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // Effectue une seconde requête (devrait passer aussi)
        let req = test::TestRequest::get()
            .uri("/test-success-path")
            .to_request();
        let resp2 = test::call_service(&app, req).await;
        assert_eq!(resp2.status(), 200);
    }

    #[actix_web::test]
    #[serial(servers)]
    async fn test_ensure_write_once_with_found() {
        let _redis_process = launch_redis_with_delay();
        let config = RedisConfig {
            url: Url::parse("redis://127.0.0.1:5555").unwrap(),
            ..RedisConfig::default()
        };
        let redis_pool = configure_redis_pool(config).await;

        // Prépare une application Actix Web avec le middleware
        let mut actix_app = App::new()
            .service(
                resource("/test-success-path")
                    .guard(Get())
                    .wrap(from_fn(ensure_write_once))
                    .to(mock_success),
            )
            .service(
                resource("/test-not-success-path")
                    .guard(Get())
                    .wrap(from_fn(ensure_write_once))
                    .to(mock_found),
            );

        actix_app = actix_app.app_data(web::Data::new(WriteOnceService::new(redis_pool)));

        let app = test::init_service(actix_app).await;

        let req = test::TestRequest::get()
            .uri("/test-not-success-path?temp_url_expires=1234567890")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 302);

        let req = test::TestRequest::get()
            .uri("/test-not-success-path?temp_url_expires=1234567890")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 302);
    }

    #[actix_web::test]
    #[serial(servers)]
    async fn test_ensure_write_once_bypass_via_query_param_reordering() {
        let _redis_process = launch_redis_with_delay();

        let config = RedisConfig {
            url: Url::parse("redis://127.0.0.1:5555").unwrap(),
            ..RedisConfig::default()
        };
        let redis_pool = configure_redis_pool(config).await;

        let mut actix_app = App::new().service(
            resource("/test-bypass-path")
                .guard(Get())
                .wrap(from_fn(ensure_write_once))
                .to(mock_success),
        );

        log::info!("Redis pool available.");

        actix_app = actix_app.app_data(web::Data::new(WriteOnceService::new(redis_pool.clone())));

        // Clean both possible keys
        match redis_pool.get().await {
            Ok(mut conn) => {
                let _: () = conn
                    .del(WriteOnceService::hash_key(
                        "/test-bypass-path?temp_url_expires=1234567890&a=1",
                    ))
                    .await
                    .unwrap();
                let _: () = conn
                    .del(WriteOnceService::hash_key(
                        "/test-bypass-path?a=1&temp_url_expires=1234567890",
                    ))
                    .await
                    .unwrap();
            }
            Err(_err) => panic!("Failed to get Redis connection"),
        }

        let app = test::init_service(actix_app).await;

        // First request with params in order: temp_url_expires, then a
        let req = test::TestRequest::get()
            .uri("/test-bypass-path?temp_url_expires=1234567890&a=1")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // Second request with params reordered: a, then temp_url_expires
        // This SHOULD be blocked (403) but currently passes (200) - demonstrating the vulnerability
        let req = test::TestRequest::get()
            .uri("/test-bypass-path?a=1&temp_url_expires=1234567890")
            .to_request();
        let resp2 = test::try_call_service(&app, req).await;
        match resp2 {
            Ok(resp) => panic!(
                "VULNERABILITY CONFIRMED: Query param reordering bypassed write-once protection. Expected 403, got {}",
                resp.status()
            ),
            Err(err) => {
                assert_eq!(err.error_response().status(), 403);
            }
        }
    }
}
