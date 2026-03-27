extern crate ds_proxy;
extern crate env_logger;
extern crate libsodium_rs;
extern crate log;

use docopt::Docopt;
use ds_proxy::args::{Args, USAGE};
use ds_proxy::config::{Config, Config::*};
use ds_proxy::keyring_utils::{add_random_key_to_keyring, init_keyring, rotate_password};
use ds_proxy::{file, http};
use log::info;
use std::env;
use std::io::IsTerminal;

fn main() {
    env_logger::init();

    if let Ok(url) = env::var("DS_PROXY_SENTRY_URL") {
        info!("Sentry will be notified on {}", url);
        let _guard = sentry::init(url);
    }

    libsodium_rs::ensure_init().unwrap();

    let docopt: Docopt = Docopt::new(USAGE)
        .unwrap_or_else(|e| e.exit())
        .version(Some(env!("GIT_HASH").to_string()));

    let args: Args = docopt.deserialize().unwrap_or_else(|e| e.exit());

    let config = Config::create_config(&args);

    match config {
        Encrypt(config) => file::encrypt(config),
        Decrypt(config) => file::decrypt(config),
        AddKeyConfig(config) => add_random_key_to_keyring(&config.keyring_file, config.password),
        RotatePassword(config) => {
            let new_password = rotate_password(&config.keyring_file, config.password);
            if std::io::stdout().is_terminal() {
                eprintln!("rotation done, new password:");
                println!("{}", new_password);
            } else {
                print!("{}", new_password);
            }
        }
        InitKeyring(config) => {
            let password = init_keyring(&config.keyring_file);
            if std::io::stdout().is_terminal() {
                eprintln!("keyring initialized with the following password:");
                println!("{}", password);
            } else {
                print!("{}", password);
            }
        }
        Http(config) => http::main(config).unwrap(),
    }
}
