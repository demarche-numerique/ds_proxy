use super::s3_config::S3Config;
use super::{args, keyring::Keyring, keyring_utils::load_keyring};
use crate::redis_config::RedisConfig;
use actix_web::HttpRequest;
use awc::ClientRequest;
use aws_sdk_s3::config::Credentials;
use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;

// match nginx default (proxy_buffer_size in ngx_stream_proxy_module)
pub const DEFAULT_CHUNK_SIZE: usize = 16 * 1024;
pub const DEFAULT_LOCAL_ENCRYPTION_DIRECTORY: &str = "ds_proxy/local_encryption/";

#[allow(clippy::large_enum_variant)]
pub enum Config {
    Decrypt(DecryptConfig),
    Encrypt(EncryptConfig),
    Http(HttpConfig),
    AddKeyConfig(AddKeyConfig),
    RotatePassword(RotatePasswordConfig),
    InitKeyring(InitKeyringConfig),
}

#[derive(Debug, Clone)]
pub struct DecryptConfig {
    pub keyring: Keyring,
    pub input_file: String,
    pub output_file: String,
}

#[derive(Debug, Clone)]
pub struct EncryptConfig {
    pub keyring: Keyring,
    pub input_file: String,
    pub output_file: String,
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    // Resolved upstream per flavor. In single mode exactly one is Some and every
    // request uses it; in dual mode both are Some and requests are routed by
    // their detected flavor.
    pub s3_upstream_base_url: Option<Url>,
    pub swift_upstream_base_url: Option<Url>,
    // True only when both an S3 upstream and an explicit Swift upstream are
    // configured together with S3 credentials: requests are then dispatched per
    // their detected flavor. Otherwise the proxy serves a single backend.
    pub dual: bool,
    pub keyring: Keyring,
    pub address: SocketAddr,
    pub local_encryption_directory: PathBuf,
    pub s3_config: Option<S3Config>,
    pub backend_connection_timeout: Duration,
    pub write_once: bool,
    pub redis_config: RedisConfig,
    pub bypass_ssl_certificate_check: bool,
}

#[derive(Debug, Clone)]
pub struct AddKeyConfig {
    pub password: String,
    pub keyring_file: String,
}

#[derive(Debug, Clone)]
pub struct RotatePasswordConfig {
    pub password: String,
    pub keyring_file: String,
}

#[derive(Debug, Clone)]
pub struct InitKeyringConfig {
    pub keyring_file: String,
}

impl Config {
    pub fn create_config(args: &args::Args) -> Config {
        if args.cmd_init_keyring {
            let keyring_file = string_from(&args.flag_keyring_file, "DS_KEYRING");
            return Config::InitKeyring(InitKeyringConfig { keyring_file });
        }

        let password = match &args.flag_password_file {
            Some(password_file) => read_file_content(password_file),
            None => env::var("DS_PASSWORD")
                .expect("Missing password, use DS_PASSWORD env or --password-file cli argument"),
        };

        let keyring_file = string_from(&args.flag_keyring_file, "DS_KEYRING");

        if args.cmd_add_key {
            return Config::AddKeyConfig(AddKeyConfig {
                password,
                keyring_file,
            });
        }

        if args.cmd_rotate_password {
            return Config::RotatePassword(RotatePasswordConfig {
                password,
                keyring_file,
            });
        }

        let keyring = load_keyring(&keyring_file, password);

        if args.cmd_encrypt {
            Config::Encrypt(EncryptConfig {
                keyring,
                input_file: args.arg_input_file.clone().unwrap(),
                output_file: args.arg_output_file.clone().unwrap(),
            })
        } else if args.cmd_decrypt {
            Config::Decrypt(DecryptConfig {
                keyring,
                input_file: args.arg_input_file.clone().unwrap(),
                output_file: args.arg_output_file.clone().unwrap(),
            })
        } else {
            let local_encryption_directory = match &args.flag_local_encryption_directory {
                Some(directory) => PathBuf::from(directory),
                None => match env::var("DS_LOCAL_ENCRYPTION_DIRECTORY") {
                    Ok(directory) => PathBuf::from(directory),
                    _ => {
                        let mut path_buf = PathBuf::new();
                        path_buf.push(env::temp_dir());
                        path_buf.push(DEFAULT_LOCAL_ENCRYPTION_DIRECTORY);
                        path_buf
                    }
                },
            };

            std::fs::create_dir_all(local_encryption_directory.clone()).unwrap_or_else(|why| {
                panic!(
                    "Cannot create tmp directory {:?}: {}",
                    local_encryption_directory, why
                )
            });

            // --upstream-url is the shared default; a flavor-specific flag
            // overrides it for that flavor.
            let raw_upstream = optional_string_from(&args.flag_upstream_url, "DS_UPSTREAM_URL");
            let raw_s3_upstream =
                optional_string_from(&args.flag_s3_upstream_url, "DS_S3_UPSTREAM_URL");
            let raw_swift_upstream =
                optional_string_from(&args.flag_swift_upstream_url, "DS_SWIFT_UPSTREAM_URL");

            let s3_upstream_base_url = raw_s3_upstream
                .or_else(|| raw_upstream.clone())
                .map(normalize_and_parse_upstream_url);
            let swift_upstream_base_url = raw_swift_upstream
                .clone()
                .or_else(|| raw_upstream.clone())
                .map(normalize_and_parse_upstream_url);

            let s3_connect_base_url =
                optional_string_from(&args.flag_s3_connect_url, "DS_S3_CONNECT_URL")
                    .map(|raw| Url::parse(&raw).expect("DS_S3_CONNECT_URL is not a valid URL"));
            if let Some(connect) = &s3_connect_base_url {
                log::info!("s3_connect_base_url: {}", connect);
            }

            let address = match &args.flag_address {
                Some(address) => match address.to_socket_addrs() {
                    Ok(mut sockets) => Some(sockets.next().unwrap()),
                    _ => panic!("Unable to parse the address"),
                },
                None => match (env::var("DS_ADDRESS")
                    .expect("Missing address, use DS_ADDRESS env or --address cli argument"))
                .to_socket_addrs()
                {
                    Ok(mut sockets) => Some(sockets.next().unwrap()),
                    _ => panic!("Unable to parse the address"),
                },
            }
            .unwrap();

            let backend_connection_timeout = match &args.flag_backend_connection_timeout {
                Some(timeout_u64) => Duration::from_secs(*timeout_u64),
                None => match env::var("BACKEND_CONNECTION_TIMEOUT") {
                    Ok(timeout_string) => Duration::from_secs(
                        timeout_string
                            .parse()
                            .expect("BACKEND_CONNECTION_TIMEOUT is not a u64"),
                    ),
                    _ => Duration::from_secs(1),
                },
            };
            log::info!(
                "backend_connection_timeout: {:?}",
                backend_connection_timeout
            );

            let write_once = bool_from(args.flag_write_once, "WRITE_ONCE");

            let bypass_ssl_certificate_check = bool_from(
                args.flag_bypass_ssl_certificate_check,
                "BYPASS_SSL_CERTIFICATE_CHECK",
            );
            log::info!(
                "bypass_ssl_certificate_check: {:?}",
                bypass_ssl_certificate_check
            );

            let s3_config = match (
                &args.flag_s3_access_key,
                &args.flag_s3_secret_key,
                &args.flag_s3_region,
            ) {
                (Some(s3_access_key), Some(s3_secret_key), Some(region)) => {
                    let bypass_signature_check = bool_from(
                        args.flag_bypass_s3_signature_check,
                        "BYPASS_S3_SIGNATURE_CHECK",
                    );

                    Some(S3Config::new(
                        Credentials::new(
                            s3_access_key,
                            s3_secret_key,
                            None,
                            None,
                            "cli-credentials",
                        ),
                        region.to_string(),
                        bypass_signature_check,
                        s3_connect_base_url,
                    ))
                }
                (None, None, None) => {
                    if s3_connect_base_url.is_some() {
                        log::warn!("s3_connect_url is set but no S3 credentials: ignoring it");
                    }
                    None
                }
                _ => panic!(
                    "Incomplete S3 configuration: --s3-access-key, --s3-secret-key and \
                     --s3-region must be provided together"
                ),
            };

            // Dual mode requires an explicit Swift upstream *and* the ability to
            // sign S3 traffic. An explicit Swift upstream without credentials
            // degrades to Swift-only.
            let dual = raw_swift_upstream.is_some() && s3_config.is_some();
            if raw_swift_upstream.is_some() && s3_config.is_none() {
                log::warn!(
                    "--swift-upstream-url set without S3 credentials: running in Swift-only \
                     mode (no S3 traffic)"
                );
            }

            if s3_config.is_some() && s3_upstream_base_url.is_none() {
                panic!(
                    "S3 credentials provided but no S3 upstream: set --upstream-url \
                     or --s3-upstream-url"
                );
            }
            if s3_config.is_none() && swift_upstream_base_url.is_none() {
                panic!(
                    "No upstream configured: set --upstream-url, --s3-upstream-url \
                     or --swift-upstream-url"
                );
            }

            log::info!(
                "mode: {}",
                if dual {
                    "dual S3+Swift"
                } else if s3_config.is_some() {
                    "S3"
                } else {
                    "Swift"
                }
            );

            Config::Http(HttpConfig {
                keyring,
                s3_upstream_base_url,
                swift_upstream_base_url,
                dual,
                address,
                local_encryption_directory,
                s3_config,
                backend_connection_timeout,
                write_once,
                redis_config: RedisConfig::create_redis_config(args),
                bypass_ssl_certificate_check,
            })
        }
    }
}

fn bool_from(flag: bool, env_var: &str) -> bool {
    if flag {
        true
    } else {
        match env::var(env_var) {
            Ok(var_string) => var_string
                .parse()
                .unwrap_or_else(|_| panic!("{} is not a boolean", env_var)),
            _ => false,
        }
    }
}

fn optional_string_from(flag: &Option<String>, env_var: &str) -> Option<String> {
    flag.clone().or_else(|| env::var(env_var).ok())
}

fn string_from(flag: &Option<String>, env_var: &str) -> String {
    if let Some(value) = flag {
        value.to_string()
    } else {
        env::var(env_var).unwrap_or_else(|_| panic!("Missing {}, use env or cli argument", env_var))
    }
}

// ensure upstream_url ends with a "/ to avoid
// upstream url: "https://upstream/dir"
// request: "https://proxy/file"
// "https://upstream/dir".join('file') => https://upstream/file
// instead ".../upstream/dir/".join('file') => https://upstream/dir/file
fn normalize_and_parse_upstream_url(mut url: String) -> Url {
    if !url.ends_with('/') {
        url.push('/');
    }
    Url::parse(&url).unwrap()
}

impl HttpConfig {
    // The upstream a request is forwarded to. Flavor-aware routing lands in a
    // later commit; for now every request uses the S3 upstream when present,
    // otherwise the Swift one. At least one is guaranteed to be set.
    fn base_upstream(&self) -> &Url {
        self.s3_upstream_base_url
            .as_ref()
            .or(self.swift_upstream_base_url.as_ref())
            .expect("at least one upstream must be configured")
    }

    pub fn create_upstream_url(&self, req: &HttpRequest) -> String {
        let raw_path = req.uri().path();
        // Strip the /upstream/ prefix to get the raw tail, preserving original encoding
        let tail = raw_path
            .strip_prefix("/upstream/")
            .or_else(|| raw_path.strip_prefix("/upstream"))
            .unwrap_or("");

        let base = self.base_upstream().as_str(); // always ends with '/'
        let url = if req.query_string().is_empty() {
            format!("{}{}", base, tail)
        } else {
            format!("{}{}?{}", base, tail, req.query_string())
        };

        log::debug!("Created upstream url: {}", url);

        url
    }

    // Points an already-signed request at the connect target, if one is
    // configured. Only the dialed scheme/host/port change; the signature and the
    // Host header stay on the upstream.
    pub fn apply_s3_connect_url(&self, req: ClientRequest) -> ClientRequest {
        let connection_url = self.connection_url(&req.get_uri().to_string());
        req.uri(connection_url)
    }

    fn connection_url(&self, upstream_url: &str) -> String {
        let connect = self
            .s3_config
            .as_ref()
            .and_then(|c| c.connect_base_url.as_ref());

        match connect {
            None => upstream_url.to_string(),
            Some(connect) => {
                let mut url = Url::parse(upstream_url).expect("upstream url should be valid");
                url.set_scheme(connect.scheme())
                    .expect("connect scheme should be valid");
                url.set_host(connect.host_str())
                    .expect("connect host should be valid");
                url.set_port(connect.port_or_known_default())
                    .expect("connect port should be valid");
                let url = url.to_string();
                log::debug!("Created connection url: {}", url);
                url
            }
        }
    }

    pub fn local_encryption_path_for(&self, req: &HttpRequest) -> Option<PathBuf> {
        let name = req.match_info().get("name").unwrap();
        let safe_name = Path::new(name).file_name()?;

        let mut filepath = self.local_encryption_directory.clone();
        filepath.push(safe_name);

        Some(filepath)
    }
}

fn read_file_content(path_string: &str) -> String {
    match std::fs::read(path_string) {
        Err(why) => panic!("couldn't open {}: {}", path_string, why),
        Ok(file) => String::from_utf8(file).unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn local_encryption_path_for() {
        let config = default_config("https://upstream.com/");

        let test_path = |name: &str, expected: Option<&str>| {
            let req = TestRequest::default()
                .param("name", name.to_string())
                .to_http_request();

            assert_eq!(
                config
                    .local_encryption_path_for(&req)
                    .map(|x| x.to_str().unwrap().to_string()),
                expected.map(|x| x.to_string())
            );
        };

        test_path("a_file", Some("ds_proxy/local_encryption/a_file"));

        test_path("../a_file", Some("ds_proxy/local_encryption/a_file"));

        test_path(
            "dir/subdir/a_file.txt",
            Some("ds_proxy/local_encryption/a_file.txt"),
        );

        test_path("..", None);

        test_path("/", None);

        test_path("", None);
    }

    #[test]
    fn test_normalize_and_parse_upstream_url() {
        assert_eq!(
            normalize_and_parse_upstream_url("https://upstream.com/dir".to_string()),
            Url::parse("https://upstream.com/dir/").unwrap()
        );
    }

    #[test]
    fn test_create_upstream_url() {
        let config = default_config("https://upstream.com/");
        let jailed_config = default_config("https://upstream.com/jail/cell/");

        // Simple file
        let req = TestRequest::default()
            .uri("/upstream/file")
            .to_http_request();
        assert_eq!(
            config.create_upstream_url(&req),
            "https://upstream.com/file"
        );
        assert_eq!(
            jailed_config.create_upstream_url(&req),
            "https://upstream.com/jail/cell/file"
        );

        // Subdirectory
        let req = TestRequest::default()
            .uri("/upstream/sub/dir/file")
            .to_http_request();
        assert_eq!(
            config.create_upstream_url(&req),
            "https://upstream.com/sub/dir/file"
        );
        assert_eq!(
            jailed_config.create_upstream_url(&req),
            "https://upstream.com/jail/cell/sub/dir/file"
        );

        // Query string preserved
        let req = TestRequest::default()
            .uri("/upstream/bucket/file.zip?p1=ok1&p2=ok2")
            .to_http_request();
        assert_eq!(
            config.create_upstream_url(&req),
            "https://upstream.com/bucket/file.zip?p1=ok1&p2=ok2"
        );

        // No name — returns base URL
        let req = TestRequest::default().uri("/upstream").to_http_request();
        assert_eq!(config.create_upstream_url(&req), "https://upstream.com/");

        // Encoding preserved transparently (no decode → re-encode cycle)
        let req = TestRequest::default()
            .uri("/upstream/plop%20plop%27plop.png")
            .to_http_request();
        assert_eq!(
            config.create_upstream_url(&req),
            "https://upstream.com/plop%20plop%27plop.png"
        );

        // ".." forwarded as-is (not resolved) — upstream handles it
        let req = TestRequest::default()
            .uri("/upstream/../escape")
            .to_http_request();
        assert_eq!(
            config.create_upstream_url(&req),
            "https://upstream.com/../escape"
        );
        assert_eq!(
            jailed_config.create_upstream_url(&req),
            "https://upstream.com/jail/cell/../escape"
        );
    }

    // Proof that Url::join is vulnerable to scheme-relative SSRF (RFC 3986 §4.2)
    #[test]
    fn test_ssrf_url_join_replaces_host() {
        let base = Url::parse("https://upstream.com/jail/cell/").unwrap();
        let ssrf = base.join("//evil.com:8080/secret").unwrap();
        assert_eq!(ssrf.host_str().unwrap(), "evil.com");
    }

    // With string concatenation, the host is NEVER replaced
    #[test]
    fn test_ssrf_eliminated_by_concatenation() {
        let config = default_config("https://upstream.com/");

        let req = TestRequest::default()
            .uri("/upstream///evil.com:8080/secret")
            .to_http_request();

        let url = config.create_upstream_url(&req);
        assert!(
            url.starts_with("https://upstream.com/"),
            "host must always be upstream.com, got: {}",
            url
        );
    }

    #[test]
    fn test_connection_url() {
        // Without a connect target, the connection url is the upstream unchanged.
        let config = default_config("https://s3.sbg.io.cloud.ovh.net/");
        let upstream = "https://s3.sbg.io.cloud.ovh.net/bucket/file?x=1";
        assert_eq!(config.connection_url(upstream), upstream);

        // With a connect target, only scheme/host/port are swapped; path and query stay.
        let mut connected = default_config("https://s3.sbg.io.cloud.ovh.net/");
        connected.s3_config = Some(s3_config_with_connect("http://192.168.33.70:8006"));
        assert_eq!(
            connected.connection_url(upstream),
            "http://192.168.33.70:8006/bucket/file?x=1"
        );

        // A connect target without explicit port falls back to the scheme default.
        let mut connected_default_port = default_config("https://s3.sbg.io.cloud.ovh.net/");
        connected_default_port.s3_config = Some(s3_config_with_connect("http://192.168.33.70"));
        assert_eq!(
            connected_default_port.connection_url(upstream),
            "http://192.168.33.70/bucket/file?x=1"
        );
    }

    fn s3_config_with_connect(connect: &str) -> S3Config {
        use aws_sdk_s3::config::Credentials;
        S3Config::new(
            Credentials::new("key", "secret", None, None, "test"),
            "region".to_string(),
            true,
            Some(Url::parse(connect).unwrap()),
        )
    }

    fn default_config(upstream_base_url: &str) -> HttpConfig {
        let keyring = Keyring::new(HashMap::new());

        HttpConfig {
            keyring,
            s3_upstream_base_url: Some(normalize_and_parse_upstream_url(
                upstream_base_url.to_string(),
            )),
            swift_upstream_base_url: None,
            dual: false,
            address: "127.0.0.1:1234".to_socket_addrs().unwrap().next().unwrap(),
            local_encryption_directory: PathBuf::from(DEFAULT_LOCAL_ENCRYPTION_DIRECTORY),
            s3_config: None,
            backend_connection_timeout: Duration::from_secs(1),
            write_once: false,
            redis_config: RedisConfig::default(),
            bypass_ssl_certificate_check: true,
        }
    }
}
