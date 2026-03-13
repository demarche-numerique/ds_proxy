mod helpers;
pub use helpers::*;

#[test]
#[serial(servers)]
fn traversal_attack_is_avoided() {
    let _proxy_node_and_redis = ProxyAndNode::start();

    let curl_download = curl_get_status("localhost:4444/upstream/../../out_of_jail.txt");
    println!("curl_download: {:?}", curl_download);
    assert_eq!(curl_download, "404");
}

#[test]
#[serial(servers)]
fn traversal_attack_with_encoded_characters_is_avoided() {
    let _proxy_node_and_redis = ProxyAndNode::start();

    let curl_download = curl_get_status("localhost:4444/upstream/..%2f..%2fout_of_jail.txt");
    println!("curl_download: {:?}", curl_download);
    assert_eq!(curl_download, "404");
}

#[test]
#[serial(servers)]
fn traversal_attack_with_double_encoded_slash_is_avoided() {
    let _proxy_node_and_redis = ProxyAndNode::start();

    // %252f = double encoded / (%25 = %, so %252f → %2f → /)
    let curl_download = curl_get_status("localhost:4444/upstream/..%252f..%252fout_of_jail.txt");
    println!("curl_download: {:?}", curl_download);
    assert_eq!(curl_download, "404");
}

#[test]
#[serial(servers)]
fn traversal_attack_with_mixed_encoding_is_avoided() {
    let _proxy_node_and_redis = ProxyAndNode::start();

    // Mix of encoded (.%2f) and non-encoded (../)
    let curl_download = curl_get_status("localhost:4444/upstream/..%2f../../out_of_jail.txt");
    println!("curl_download: {:?}", curl_download);
    assert_eq!(curl_download, "404");
}

#[test]
#[serial(servers)]
fn traversal_attack_with_encoded_dot_is_avoided() {
    let _proxy_node_and_redis = ProxyAndNode::start();

    // %2e = encoded . (both dots encoded)
    let curl_download = curl_get_status("localhost:4444/upstream/%2e%2e/%2e%2e/out_of_jail.txt");
    println!("curl_download: {:?}", curl_download);
    assert_eq!(curl_download, "404");
}

#[test]
#[serial(servers)]
fn traversal_attack_with_uppercase_encoding_is_avoided() {
    let _proxy_node_and_redis = ProxyAndNode::start();

    // %2F (uppercase) instead of %2f (lowercase)
    let curl_download = curl_get_status("localhost:4444/upstream/..%2F..%2Fout_of_jail.txt");
    println!("curl_download: {:?}", curl_download);
    assert_eq!(curl_download, "404");
}
