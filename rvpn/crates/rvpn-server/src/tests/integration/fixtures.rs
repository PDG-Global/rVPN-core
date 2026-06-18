//! Test fixtures and test data

use std::net::TcpListener;

/// Find an available port on localhost
pub fn find_available_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Test HTTP server that echoes back request info
pub const TEST_HTTP_SERVER: &str = r#"
use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:TEST_PORT").unwrap();
    println!("Test HTTP server listening on 127.0.0.1:TEST_PORT");
    
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).unwrap();
        
        let request = String::from_utf8_lossy(&buf[..n]);
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain\r\n\
             Connection: close\r\n\
             \r\n\
             Echo: {}",
            request.lines().next().unwrap_or("")
        );
        
        stream.write_all(response.as_bytes()).unwrap();
    }
}
"#;

/// Expected response patterns
pub mod patterns {
    pub const HTTP_OK: &str = "HTTP/1.1 200 OK";
    pub const SOCKS5_GREETING: &[u8] = &[0x05, 0x00]; // SOCKS5, no auth
    pub const SOCKS5_SUCCESS: &[u8] = &[0x05, 0x00, 0x00, 0x01]; // Success + IPv4
}

/// Test URLs and endpoints
pub mod endpoints {
    pub const HTTPBIN_GET: &str = "http://httpbin.org/get";
    pub const HTTPBIN_IP: &str = "http://httpbin.org/ip";
    pub const EXAMPLE_COM: &str = "http://example.com";
}

/// Sample routing rules for testing
pub mod routing_rules {
    pub const CHINA_DOMAINS: &[&str] = &[
        ".cn",
        ".baidu.com",
        ".taobao.com",
    ];
    
    pub const BLOCKED_DOMAINS: &[&str] = &[
        "malware.example.com",
        "ads.example.com",
    ];
}
