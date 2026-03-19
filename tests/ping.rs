use std::fs::File;
use std::{thread, time};

mod helpers;
pub use helpers::*;

#[test]
#[serial(servers)]
fn ping() {
    /*
    This test:
     - spawns a ds proxy
     - curl /ping and expect to fetch a 200
     - add a maintenance file
     - curl /ping and expect to fetch a 404 which should trigger a maintenance mode
       on a upper stream proxy
    */
    let _proxy_server = launch_proxy(PrintServerLogs::No, None, None, false);
    thread::sleep(time::Duration::from_secs(2));

    let maintenance_file_path = "maintenance";

    ensure_is_absent(maintenance_file_path);

    assert_eq!(curl_get_status("localhost:4444/ping"), "200");

    File::create(maintenance_file_path)
        .unwrap_or_else(|_| panic!("Unable to create {} !", maintenance_file_path));

    assert_eq!(curl_get_status("localhost:4444/ping"), "404");

    ensure_is_absent(maintenance_file_path);
}
