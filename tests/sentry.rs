use assert_cmd::cargo;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn a_panic_is_reported_to_sentry() {
    let sentry = TcpListener::bind("127.0.0.1:0").unwrap();
    let dsn = format!("http://public@{}/1", sentry.local_addr().unwrap());
    let received = thread::spawn(move || first_request_line(sentry));

    // Without a password the configuration panics, after Sentry is set up.
    let output = Command::new(cargo::cargo_bin!("ds_proxy"))
        .args(["decrypt", "input", "output"])
        .env("DS_PROXY_SENTRY_URL", dsn)
        .env_remove("DS_PASSWORD")
        .output()
        .unwrap();
    assert!(!output.status.success());

    let request_line = received.join().unwrap().expect("no event reached Sentry");
    assert!(
        request_line.starts_with("POST /api/1/envelope/"),
        "unexpected request: {}",
        request_line
    );
}

// Answers the first request like Sentry would: the client waits for the
// response before it exits.
fn first_request_line(listener: TcpListener) -> Option<String> {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);

    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(_) => return None,
        }
    };

    stream.set_nonblocking(false).unwrap();
    let mut request = [0; 1024];
    let n = stream.read(&mut request).unwrap();
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .unwrap();

    let request = String::from_utf8_lossy(&request[..n]);
    request.lines().next().map(str::to_string)
}
