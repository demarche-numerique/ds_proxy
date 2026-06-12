use std::process::{Command, Output};
use std::{thread, time};

const RETURNED_HEADER: &str = "/tmp/curl_headers";

pub fn curl_get_status(url: &str) -> String {
    let stdout = Command::new("curl")
        .arg("-XGET")
        .arg(url)
        .arg("--path-as-is")
        .arg("-o")
        .arg("/dev/null")
        .arg("-s")
        .arg("-w")
        .arg("%{http_code}")
        .output()
        .expect("failed to perform download")
        .stdout;

    std::str::from_utf8(&stdout).unwrap().to_string()
}

pub fn curl_put(file_path: &str, url: &str) -> Output {
    let cmd = Command::new("curl")
        .arg("-XPUT")
        .arg(url)
        .arg("--data-binary")
        .arg(format!("@{}", file_path))
        // checksum of the cleartext data, it must be removed by the proxy
        // as the encrypted body no longer matches it
        .arg("-H")
        .arg("Content-MD5: Q2hlY2tJbnRlZ3JpdHk=")
        .arg("--dump-header")
        .arg(RETURNED_HEADER)
        .output()
        .expect("failed to perform upload");

    // add sleep to let node write the file on the disk
    thread::sleep(time::Duration::from_millis(100));

    if !cmd.status.success() {
        panic!("unable to upload file {}", url);
    }

    cmd
}

pub fn curl_get_content_length_header(url: &str) -> usize {
    let response = curl_get_headers(url);

    response
        .split("\r\n")
        .find(|x| x.starts_with("content-length"))
        .unwrap()
        .replace("content-length: ", "")
        .parse::<usize>()
        .ok()
        .unwrap()
}

pub fn curl_get_headers(url: &str) -> std::string::String {
    let response = Command::new("curl")
        .arg("-I")
        .arg("-XGET")
        .arg(url)
        .output()
        .expect("failed to perform download")
        .stdout;

    String::from_utf8_lossy(&response).to_string()
}

pub fn curl_get(url: &str) -> Output {
    Command::new("curl")
        .arg("-XGET")
        .arg(url)
        .output()
        .expect("failed to perform download")
}

pub fn curl_head(url: &str) -> Output {
    Command::new("curl")
        .arg("-I")
        .arg("-XHEAD")
        .arg(url)
        .output()
        .expect("failed to perform download")
}

pub fn curl_range_get(url: &str, range_start: usize, range_end: usize) -> Output {
    let range_arg = format!("Range: bytes={}-{}", range_start, range_end);

    Command::new("curl")
        .arg("-XGET")
        .arg(url)
        .arg("-H")
        .arg(range_arg)
        .arg("-vv")
        .output()
        .expect("failed to perform download")
}

pub fn curl_socket_get(url: &str) -> Output {
    Command::new("curl")
        .arg("-XGET")
        .arg("--unix-socket")
        .arg("/tmp/actix-uds.socket")
        .arg(url)
        .output()
        .expect("failed to perform download")
}

pub fn node_received_header(header: &str) -> Option<String> {
    let last_put_headers = curl_get("localhost:3333/last_put_headers").stdout;
    let last_put_headers_string = String::from_utf8_lossy(&last_put_headers);

    use serde_json::Value;
    let lookup: std::collections::HashMap<String, Value> =
        serde_json::from_str(&last_put_headers_string).unwrap();

    lookup.get(header).map(|h| h.to_string())
}

pub fn returned_header(header: &str) -> String {
    read_lines(RETURNED_HEADER)
        .find(|x| x.as_ref().unwrap().contains(header))
        .unwrap()
        .unwrap()
        .split(": ")
        .nth(1)
        .unwrap()
        .to_string()
}

fn read_lines<P>(filename: P) -> std::io::Lines<std::io::BufReader<std::fs::File>>
where
    P: AsRef<std::path::Path>,
{
    use std::io::BufRead;
    let file = std::fs::File::open(filename).unwrap();
    std::io::BufReader::new(file).lines()
}
