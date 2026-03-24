use std::process::Command;
/*
build script for the project
*/
fn main() {
    // taken from https://stackoverflow.com/questions/43753491/include-git-commit-hash-as-string-into-rust-program
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let git_hash = String::from_utf8(output.stdout).unwrap().trim().to_string();

    let tag = Command::new("git")
        .args(["describe", "--tags", "--exact-match", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8(o.stdout).unwrap().trim().to_string())
            } else {
                None
            }
        });

    let version = match tag {
        Some(t) => format!("{} {}", t, git_hash),
        None => git_hash,
    };

    println!("cargo:rustc-env=GIT_HASH={}", version);
}
