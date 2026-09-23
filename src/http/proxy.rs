use super::super::config::HttpConfig;
use super::handlers::*;
use super::middlewares::*;
use crate::redis_utils::configure_redis_pool;
use crate::write_once_service::WriteOnceService;
use actix_web::guard::{Get, Put};
use actix_web::{
    App, HttpServer, middleware,
    middleware::from_fn,
    web::{Data, resource, scope},
};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

const SOCKET_MODE: u32 = 0o660;

#[actix_web::main]
pub async fn main(config: HttpConfig) -> std::io::Result<()> {
    let address = config.address;
    let socket_path = config.socket_path.clone();
    let redis_pool = if config.write_once {
        Some(configure_redis_pool(config.redis_config.clone()).await)
    } else {
        None
    };

    let mut server = HttpServer::new(move || {
        let mut awc_connector = awc::Connector::new().timeout(config.backend_connection_timeout); // max time to connect to remote host including dns name resolution
        if config.bypass_ssl_certificate_check {
            let mut ssl_builder = SslConnector::builder(SslMethod::tls()).unwrap();
            ssl_builder.set_verify(SslVerifyMode::NONE);
            let ssl_connector = ssl_builder.build();
            awc_connector = awc_connector.openssl(ssl_connector);
        }
        let mut app = App::new()
            .app_data(Data::new(
                awc::Client::builder()
                    .connector(awc_connector)
                    .timeout(RESPONSE_TIMEOUT) // the total time before a response must be received
                    // a redirect from the upstream is refused by the handlers, never followed
                    .disable_redirects()
                    .finish(),
            ))
            .app_data(Data::new(config.clone()))
            .wrap(access_log())
            .service(resource("/ping").guard(Get()).to(ping))
            .service({
                let scope = scope("/upstream")
                    .service(resource("").guard(Get()).to(fetch)) // for ex: used for listing bucket  (?list-type=2&encoding-type=url)
                    .service(resource("{name}*").guard(Get()).to(fetch));

                let upstream_put = resource("{name}*").guard(Put()).to(forward);

                let scope = if config.write_once {
                    scope.service(upstream_put.wrap(from_fn(ensure_write_once)))
                } else {
                    scope.service(upstream_put)
                }
                .service(resource("{name}*").to(simple_proxy));

                scope.wrap(from_fn(verify_s3_signature))
            })
            .service(
                scope("/local")
                    .service(resource("encrypt/{name}").guard(Put()).to(encrypt_to_file))
                    .service(resource("encrypt/{name}").guard(Get()).to(fetch_file)),
            );

        if config.write_once {
            app = app.app_data(Data::new(WriteOnceService::new(
                redis_pool.clone().unwrap(),
            )));
        }

        app
    })
    .keep_alive(actix_web::http::KeepAlive::Disabled);

    if let Some(address) = address {
        server = server.bind(address)?;
    }

    if let Some(path) = socket_path {
        server = server.bind_uds(&path).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("cannot bind unix socket {:?}: {}", path, e),
            )
        })?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(SOCKET_MODE)).map_err(
            |e| {
                std::io::Error::new(
                    e.kind(),
                    format!("cannot set permissions on unix socket {:?}: {}", path, e),
                )
            },
        )?;
    }

    server.run().await
}

// The default access log prints the request line with its query string,
// which is where presigned URLs carry their signature. Log the same line
// without the query: the credential must not end up in the logs.
fn access_log() -> middleware::Logger {
    middleware::Logger::new(r#"%a "%{REQUEST_LINE}xi" %s %b "%{Referer}i" "%{User-Agent}i" %T"#)
        .custom_request_replace("REQUEST_LINE", request_line)
}

fn request_line(req: &actix_web::dev::ServiceRequest) -> String {
    format!("{} {} {:?}", req.method(), req.path(), req.version())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn request_line_has_no_query_string() {
        let req = TestRequest::put()
            .uri("/upstream/bucket/key?X-Amz-Signature=secret&X-Amz-Expires=60")
            .to_srv_request();

        assert_eq!(request_line(&req), "PUT /upstream/bucket/key HTTP/1.1");
    }
}
