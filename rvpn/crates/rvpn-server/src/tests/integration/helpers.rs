//! Helper functions for integration tests

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Perform SOCKS5 handshake with a proxy
pub fn socks5_handshake(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
) -> anyhow::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr)?;
    
    // Send SOCKS5 greeting
    stream.write_all(&[0x05, 0x01, 0x00])?; // Version 5, 1 method, no auth
    stream.flush()?;
    
    // Read server response
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf)?;
    
    if buf[0] != 0x05 || buf[1] != 0x00 {
        anyhow::bail!("SOCKS5 handshake failed: {:?}", buf);
    }
    
    // Send CONNECT request
    let host_bytes = target_host.as_bytes();
    let mut request = vec![
        0x05, // Version
        0x01, // CONNECT command
        0x00, // Reserved
        0x03, // Domain name address type
        host_bytes.len() as u8,
    ];
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&target_port.to_be_bytes());
    
    stream.write_all(&request)?;
    stream.flush()?;
    
    // Read response - SOCKS5 response can be variable length
    let mut response_header = [0u8; 4];
    stream.read_exact(&mut response_header)?;
    
    if response_header[0] != 0x05 || response_header[1] != 0x00 {
        anyhow::bail!("SOCKS5 CONNECT failed: ver={} rep={}", response_header[0], response_header[1]);
    }
    
    // Read the rest of the address based on ATYP
    match response_header[3] {
        0x01 => { // IPv4
            let mut addr_port = [0u8; 6];
            stream.read_exact(&mut addr_port)?;
        }
        0x03 => { // Domain name
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf)?;
            let mut addr_port = vec![0u8; len_buf[0] as usize + 2];
            stream.read_exact(&mut addr_port)?;
        }
        0x04 => { // IPv6
            let mut addr_port = [0u8; 18];
            stream.read_exact(&mut addr_port)?;
        }
        _ => {
            anyhow::bail!("SOCKS5 unknown address type: {}", response_header[3]);
        }
    }
    
    Ok(stream)
}

/// Send HTTP request through SOCKS5 proxy
pub fn http_request_through_proxy(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
    request: &str,
) -> anyhow::Result<String> {
    let mut stream = socks5_handshake(proxy_addr, target_host, target_port)?;
    
    stream.write_all(request.as_bytes())?;
    
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    
    Ok(response)
}

/// Check if proxy is accepting connections
pub fn is_proxy_ready(proxy_addr: &str) -> bool {
    TcpStream::connect(proxy_addr).is_ok()
}

/// Wait for proxy to be ready
pub fn wait_for_proxy(proxy_addr: &str, timeout_secs: u64) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    
    while start.elapsed().as_secs() < timeout_secs {
        if is_proxy_ready(proxy_addr) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    
    anyhow::bail!("Proxy did not become ready within {} seconds", timeout_secs)
}

/// Make a simple HTTP GET request
pub fn simple_http_get(host: &str, port: u16, path: &str) -> anyhow::Result<String> {
    let mut stream = TcpStream::connect(format!("{}:{}", host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    
    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         \r\n",
        path, host
    );
    
    stream.write_all(request.as_bytes())?;
    
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    
    Ok(response)
}

/// Parse HTTP response status code
pub fn parse_status_code(response: &str) -> Option<u16> {
    let first_line = response.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

/// Check if response indicates success (2xx status)
pub fn is_success_response(response: &str) -> bool {
    match parse_status_code(response) {
        Some(code) => (200..300).contains(&code),
        None => false,
    }
}

/// Test data generators
pub mod test_data {
    use rand::Rng;
    
    /// Generate random bytes
    pub fn random_bytes(len: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        (0..len).map(|_| rng.gen()).collect()
    }
    
    /// Generate random string
    pub fn random_string(len: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
        
        (0..len)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
    
    /// Generate test HTTP request
    pub fn test_http_request(host: &str) -> String {
        format!(
            "GET /test HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: R-VPN-Test/1.0\r\n\
             Accept: */*\r\n\
             Connection: close\r\n\
             \r\n",
            host
        )
    }
}

/// Metrics and monitoring helpers
pub mod metrics {
    use std::time::Instant;
    
    /// Simple timer for measuring operation duration
    pub struct Timer {
        start: Instant,
    }
    
    impl Timer {
        pub fn new() -> Self {
            Self {
                start: Instant::now(),
            }
        }
        
        pub fn elapsed_ms(&self) -> u128 {
            self.start.elapsed().as_millis()
        }
        
        pub fn elapsed_secs(&self) -> f64 {
            self.start.elapsed().as_secs_f64()
        }
    }
    
    impl Default for Timer {
        fn default() -> Self {
            Self::new()
        }
    }
}
