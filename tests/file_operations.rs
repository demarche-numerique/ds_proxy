use assert_cmd::cargo;
use assert_cmd::prelude::*;
use assert_fs::TempDir;
use assert_fs::prelude::*;
use std::fs::read;
use std::process::Command;

mod helpers;
pub use helpers::*;

#[test]
fn encrypt_and_decrypt() {
    let temp = TempDir::new().unwrap();

    let encrypted = temp.child("computer.svg.enc");
    let decrypted = temp.child("computer.dec.svg");

    let encrypted_path = encrypted.path();
    let decrypted_path = decrypted.path();

    let mut encrypt_cmd = Command::new(cargo::cargo_bin!("ds_proxy"));
    encrypt_cmd
        .arg("encrypt")
        .arg(COMPUTER_SVG_PATH)
        .arg(encrypted_path)
        .env("DS_KEYRING", DS_KEYRING)
        .env("DS_PASSWORD", PASSWORD)
        .assert()
        .success();

    let mut decrypt_cmd = Command::new(cargo::cargo_bin!("ds_proxy"));
    decrypt_cmd
        .arg("decrypt")
        .arg(encrypted_path)
        .arg(decrypted_path)
        .env("DS_KEYRING", DS_KEYRING)
        .env("DS_PASSWORD", PASSWORD)
        .assert()
        .success();

    let decrypted_bytes = read(decrypted_path).unwrap();

    assert_eq!(COMPUTER_SVG_BYTES, decrypted_bytes);
}

#[test]
fn decrypt_witness_file() {
    let temp = TempDir::new().unwrap();

    let decrypted = temp.child("computer.dec.svg");
    let decrypted_path = decrypted.path();

    let mut decrypt_cmd = Command::new(cargo::cargo_bin!("ds_proxy"));
    decrypt_cmd
        .arg("decrypt")
        .arg(ENCRYPTED_COMPUTER_SVG_PATH)
        .arg(decrypted_path)
        .env("DS_KEYRING", DS_KEYRING)
        .env("DS_PASSWORD", PASSWORD)
        .assert()
        .success();

    let decrypted_bytes = read(decrypted_path).unwrap();

    assert_eq!(decrypted_bytes, COMPUTER_SVG_BYTES);
}

#[test]
fn the_app_crashes_on_a_missing_password() {
    let temp = TempDir::new().unwrap();

    let decrypted = temp.child("computer.dec.svg");
    let decrypted_path = decrypted.path();

    let mut decrypt_cmd = Command::new(cargo::cargo_bin!("ds_proxy"));
    decrypt_cmd
        .arg("proxy")
        .arg(ENCRYPTED_COMPUTER_SVG_PATH)
        .arg(decrypted_path)
        .env("DS_KEYRING", DS_KEYRING);

    decrypt_cmd.assert().failure();
}

// A password file that is not UTF-8 stops the app, without the file's
// bytes ending up in the error output.
#[test]
fn the_app_crashes_on_a_binary_password_file_without_printing_it() {
    let temp = TempDir::new().unwrap();

    let password_file = temp.child("password");
    password_file
        .write_binary(&[0xff, 0xfe, b's', b'e', b'c', b'r', b'e', b't'])
        .unwrap();

    let decrypted = temp.child("computer.dec.svg");

    let output = Command::new(cargo::cargo_bin!("ds_proxy"))
        .arg("decrypt")
        .arg(ENCRYPTED_COMPUTER_SVG_PATH)
        .arg(decrypted.path())
        .arg("--password-file")
        .arg(password_file.path())
        .env("DS_KEYRING", DS_KEYRING)
        .output()
        .unwrap();

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("is not valid UTF-8"), "stderr: {}", stderr);
    assert!(
        !stderr.contains("255, 254") && !stderr.contains("secret"),
        "the password file leaked into stderr: {}",
        stderr
    );
}

#[test]
fn the_app_crashes_with_an_invalid_password() {
    let temp = TempDir::new().unwrap();

    let password = "this is not the expected password";

    let decrypted = temp.child("computer.dec.svg");
    let decrypted_path = decrypted.path();

    let mut decrypt_cmd = Command::new(cargo::cargo_bin!("ds_proxy"));
    decrypt_cmd
        .arg("proxy")
        .arg(ENCRYPTED_COMPUTER_SVG_PATH)
        .arg(decrypted_path)
        .env("DS_KEYRING", DS_KEYRING)
        .env("DS_PASSWORD", password);

    decrypt_cmd.assert().failure();
}
