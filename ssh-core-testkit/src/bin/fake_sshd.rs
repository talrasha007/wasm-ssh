//! Standalone TCP-listening wrapper around `FakeServer`, for exercising the JS side of this
//! project (the `SshClient` class) against a real socket without needing a real `sshd`. Not part
//! of the crate's public library API - built only for test harnesses to spawn as a subprocess.
//!
//! Usage: `fake_sshd <port> <username> <password>`. Accepts connections sequentially (one at a
//! time, looping forever) since test harnesses only need to drive one session per process.

use std::io::{Read, Write};
use std::net::TcpListener;

use ssh_core_testkit::FakeServer;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args.get(1).map(|s| s.parse().expect("port must be a u16")).unwrap_or(2222);
    let username = args.get(2).cloned().unwrap_or_else(|| "bob".to_string());
    let password = args.get(3).cloned().unwrap_or_else(|| "hunter2".to_string());

    let listener = TcpListener::bind(("127.0.0.1", port)).expect("failed to bind");
    // Test harnesses watch stdout for this exact line to know when it's safe to connect.
    println!("LISTENING {port}");
    std::io::stdout().flush().ok();

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        stream.set_nodelay(true).ok();

        let mut server = FakeServer::new(42, &username, &password);
        if stream.write_all(&server.initial_outgoing()).is_err() {
            continue;
        }

        let mut buf = [0u8; 8192];
        loop {
            let n = match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let outgoing = server.feed(&buf[..n]);
            if !outgoing.is_empty() && stream.write_all(&outgoing).is_err() {
                break;
            }
        }
    }
}
