use serde::Deserialize;
use url::Url;

pub const USAGE: &str = "
DS encryption proxy.

Usage:
  ds_proxy encrypt <input-file> <output-file> [--password-file=<password-file>] [--salt=<salt>] [--keyring-file=<keyring-file>]
  ds_proxy decrypt <input-file> <output-file> [--password-file=<password-file>] [--salt=<salt>] [--keyring-file=<keyring-file>]
  ds_proxy proxy [--address=<address>] [--bypass-ssl-certificate-check] [--password-file=<password-file>] [--salt=<salt>] [--upstream-url=<upstream-url>] [--local-encryption-directory=<local-encryption-directory>] [--write-once] [--keyring-file=<keyring-file>] [--s3-access-key=<s3-access-key>] [--s3-secret-key=<s3-secret-key>] [--s3-region=<s3-region>] [--bypass-s3-signature-check] [--backend-connection-timeout=<backend-connection-timeout>] [--redis-url=<redis-url>] [--redis-timeout-wait=<redis-timeout-wait>] [--redis-timeout-create=<redis-timeout-create>] [--redis-timeout-recycle=<redis-timeout-recycle>] [--redis-pool-max-size=<redis-pool-max-size>]
  ds_proxy add-key [--password-file=<password-file>] [--salt=<salt>] [--keyring-file=<keyring-file>]
  ds_proxy (-h | --help)
  ds_proxy --version

Options:
  -h --help             Show this screen.
  --version             Show version.
";

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Args {
    pub flag_address: Option<String>,
    pub arg_input_file: Option<String>,
    pub flag_keyring_file: Option<String>,
    pub arg_output_file: Option<String>,
    pub flag_password_file: Option<String>,
    pub flag_salt: Option<String>,
    pub flag_upstream_url: Option<String>,
    pub flag_local_encryption_directory: Option<String>,
    pub flag_s3_access_key: Option<String>,
    pub flag_s3_secret_key: Option<String>,
    pub flag_s3_region: Option<String>,
    pub flag_bypass_s3_signature_check: bool,
    pub flag_backend_connection_timeout: Option<u64>,
    pub cmd_encrypt: bool,
    pub cmd_decrypt: bool,
    pub cmd_proxy: bool,
    pub cmd_add_key: bool,
    pub flag_redis_url: Option<Url>,
    pub flag_write_once: bool,
    pub flag_redis_timeout_wait: Option<u64>,
    pub flag_redis_timeout_create: Option<u64>,
    pub flag_redis_timeout_recycle: Option<u64>,
    pub flag_redis_pool_max_size: Option<usize>,
    pub flag_bypass_ssl_certificate_check: bool,
}
