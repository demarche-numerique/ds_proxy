extern crate ds_proxy;

use actix_web::HttpResponse;
use actix_web::guard::Get;
use actix_web::web::resource;
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

pub async fn mock_bad_gateway() -> Result<HttpResponse, actix_web::Error> {
    Err(actix_web::error::ErrorBadGateway("upstream unreachable"))
}

fn launch_redis_with_delay() -> ChildGuard {
    let redis = launch_redis(PrintServerLogs::No);
    thread::sleep(std::time::Duration::from_secs(4));
    redis
}

#[cfg(test)]
mod tests {

    use super::*;
    use actix_web::{App, middleware::from_fn, test, web};
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
            "/test-path?temp_url%5Fexpires=1234567890",   // encoded key
            "/test-path?temp_url_sig=abc",                // signature only
            "/test-path?temp%5Furl%5Fsig=abc",            // encoded signature key
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
    async fn test_ensure_write_once_blocks_s3_presigned_url() {
        let _redis_process = launch_redis_with_delay();

        let config = RedisConfig {
            url: Url::parse("redis://127.0.0.1:5555").unwrap(),
            ..RedisConfig::default()
        };
        let redis_pool = configure_redis_pool(config).await;

        let mut actix_app = App::new().service(
            resource("/s3-path")
                .guard(Get())
                .wrap(from_fn(ensure_write_once))
                .to(mock_success),
        );

        actix_app = actix_app.app_data(web::Data::new(WriteOnceService::new(redis_pool.clone())));

        match redis_pool.get().await {
            Ok(mut conn) => {
                let _: () = conn
                    .del(WriteOnceService::hash_key("/s3-path"))
                    .await
                    .unwrap();
            }
            Err(_err) => panic!("Failed to get Redis connection"),
        }

        let app = test::init_service(actix_app).await;

        // First request: an S3 presigned URL (x-amz-expires) should pass and lock
        let req = test::TestRequest::get()
            .uri("/s3-path?X-Amz-Expires=60&X-Amz-Signature=abc")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // Subsequent presigned writes on the same path are denied, whatever the
        // parameter casing or encoding.
        let bypass_attempts = [
            "/s3-path?X-Amz-Expires=60&X-Amz-Signature=abc", // identical
            "/s3-path?x-amz-expires=60&x-amz-signature=def", // lowercased
            "/s3-path?X-Amz%2DExpires=60&X-Amz-Signature=abc", // encoded expiry key
            "/s3-path?X-Amz%2DExpires=60&X-Amz%2DSignature=abc", // both keys encoded
            "/s3-path?X-Amz-Signature=abc",                  // signature without expiry
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

    // A proxy-side failure (502 from an unreachable upstream) stored nothing:
    // the credential stays usable.
    #[actix_web::test]
    #[serial(servers)]
    async fn test_ensure_write_once_unlocks_on_handler_error() {
        let _redis_process = launch_redis_with_delay();
        let config = RedisConfig {
            url: Url::parse("redis://127.0.0.1:5555").unwrap(),
            ..RedisConfig::default()
        };
        let redis_pool = configure_redis_pool(config).await;

        let mut actix_app = App::new().service(
            resource("/error-path")
                .guard(Get())
                .wrap(from_fn(ensure_write_once))
                .to(mock_bad_gateway),
        );
        actix_app = actix_app.app_data(web::Data::new(WriteOnceService::new(redis_pool)));
        let app = test::init_service(actix_app).await;

        for _ in 0..2 {
            let req = test::TestRequest::get()
                .uri("/error-path?temp_url_expires=1234567890")
                .to_request();
            // actix turns the handler error into a plain 502 response; the
            // second attempt must get the same 502, not a 403 from the lock
            let status = match test::try_call_service(&app, req).await {
                Ok(resp) => resp.status(),
                Err(err) => err.error_response().status(),
            };
            assert_eq!(status, 502);
        }
    }

    // The lock outlives the credential: a URL presigned for seven days keeps
    // its path locked for seven days (plus the signature grace), not one hour.
    #[actix_web::test]
    #[serial(servers)]
    async fn test_ensure_write_once_lock_lasts_as_long_as_the_presigned_url() {
        let _redis_process = launch_redis_with_delay();

        let config = RedisConfig {
            url: Url::parse("redis://127.0.0.1:5555").unwrap(),
            ..RedisConfig::default()
        };
        let redis_pool = configure_redis_pool(config).await;

        let mut actix_app = App::new().service(
            resource("/week-path")
                .guard(Get())
                .wrap(from_fn(ensure_write_once))
                .to(mock_success),
        );

        actix_app = actix_app.app_data(web::Data::new(WriteOnceService::new(redis_pool.clone())));

        let key = WriteOnceService::hash_key("/week-path");
        let mut conn = redis_pool
            .get()
            .await
            .expect("Failed to get Redis connection");
        let _: () = conn.del(&key).await.unwrap();

        let app = test::init_service(actix_app).await;

        let date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let uri = format!(
            "/week-path?X-Amz-Date={}&X-Amz-Expires=604800&X-Amz-Signature=abc",
            date
        );
        let req = test::TestRequest::get().uri(&uri).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let ttl: i64 = conn.ttl(&key).await.unwrap();
        // seven days plus the 15 minute grace, minus the seconds this test took
        assert!(
            ttl > 604800 + 900 - 60 && ttl <= 604800 + 900,
            "lock ttl should follow the presigned validity, got {}",
            ttl
        );
    }

    // The lock is keyed on the resolved path: dot segments, encoded or not, do
    // not open a second write on the same object.
    #[actix_web::test]
    #[serial(servers)]
    async fn test_ensure_write_once_blocks_dot_segment_spellings_of_a_path() {
        let _redis_process = launch_redis_with_delay();

        let config = RedisConfig {
            url: Url::parse("redis://127.0.0.1:5555").unwrap(),
            ..RedisConfig::default()
        };
        let redis_pool = configure_redis_pool(config).await;

        let mut actix_app = App::new().service(
            resource("/{tail}*")
                .guard(Get())
                .wrap(from_fn(ensure_write_once))
                .to(mock_success),
        );

        actix_app = actix_app.app_data(web::Data::new(WriteOnceService::new(redis_pool.clone())));

        match redis_pool.get().await {
            Ok(mut conn) => {
                let _: () = conn
                    .del(WriteOnceService::hash_key("/bucket/item/file"))
                    .await
                    .unwrap();
            }
            Err(_err) => panic!("Failed to get Redis connection"),
        }

        let app = test::init_service(actix_app).await;

        // First request: should pass and lock the path
        let req = test::TestRequest::get()
            .uri("/bucket/item/file?X-Amz-Expires=60&X-Amz-Signature=abc")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let bypass_attempts = [
            "/bucket/item/./file?X-Amz-Expires=60&X-Amz-Signature=abc",
            "/bucket/./item/file?X-Amz-Expires=60&X-Amz-Signature=abc",
            "/bucket/item/%2e/file?X-Amz-Expires=60&X-Amz-Signature=abc",
            "/bucket/item/%2E/file?X-Amz-Expires=60&X-Amz-Signature=abc",
            "/bucket/item/../item/file?X-Amz-Expires=60&X-Amz-Signature=abc",
            "/bucket/item/%2e%2e/item/file?X-Amz-Expires=60&X-Amz-Signature=abc",
            "/bucket/other/../item/file?X-Amz-Expires=60&X-Amz-Signature=abc",
        ];

        for uri in bypass_attempts {
            let req = test::TestRequest::get().uri(uri).to_request();
            let resp = test::try_call_service(&app, req).await;
            match resp {
                Ok(resp) => panic!("Expected 403 for {}, got {}", uri, resp.status()),
                Err(err) => assert_eq!(err.error_response().status(), 403, "for {}", uri),
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
