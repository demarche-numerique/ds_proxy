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
