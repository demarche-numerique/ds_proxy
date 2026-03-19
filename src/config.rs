use super::s3_config::S3Config;
use super::{args, keyring::Keyring, keyring_utils::load_keyring};
use crate::redis_config::RedisConfig;
use actix_web::HttpRequest;
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
    pub upstream_base_url: Url,
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

impl Config {
    pub fn create_config(args: &args::Args) -> Config {
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

            let raw_upstream_base_url = string_from(&args.flag_upstream_url, "DS_UPSTREAM_URL");
            let upstream_base_url = normalize_and_parse_upstream_url(raw_upstream_base_url);

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

            let s3_config = if let (Some(s3_access_key), Some(s3_secret_key), Some(region)) = (
                &args.flag_s3_access_key,
                &args.flag_s3_secret_key,
                &args.flag_s3_region,
            ) {
                let bypass_signature_check = bool_from(
                    args.flag_bypass_s3_signature_check,
                    "BYPASS_S3_SIGNATURE_CHECK",
                );

                let config = S3Config::new(
                    Credentials::new(s3_access_key, s3_secret_key, None, None, "cli-credentials"),
                    region.to_string(),
                    bypass_signature_check,
                );
                Some(config)
            } else {
                None
            };

            Config::Http(HttpConfig {
                keyring,
                upstream_base_url,
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
    pub fn create_upstream_url(&self, req: &HttpRequest) -> String {
        let raw_path = req.uri().path();
        // Strip the /upstream/ prefix to get the raw tail, preserving original encoding
        let tail = raw_path
            .strip_prefix("/upstream/")
            .or_else(|| raw_path.strip_prefix("/upstream"))
            .unwrap_or("");

        let base = self.upstream_base_url.as_str(); // always ends with '/'
        let url = if req.query_string().is_empty() {
            format!("{}{}", base, tail)
        } else {
            format!("{}{}?{}", base, tail, req.query_string())
        };

        log::debug!("Created upstream url: {}", url);

        url
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

    fn default_config(upstream_base_url: &str) -> HttpConfig {
        let keyring = Keyring::new(HashMap::new());

        HttpConfig {
            keyring,
            upstream_base_url: normalize_and_parse_upstream_url(upstream_base_url.to_string()),
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
