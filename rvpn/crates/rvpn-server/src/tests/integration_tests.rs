//! Full integration tests for R-VPN
//!
//! These tests:
//! 1. Generate server and client keys
//! 2. Create configuration files
//! 3. Spin up server and client processes
//! 4. Test traffic routing through the proxy

use std::io::{Read, Write};
use std::time::Duration;

use crate::tests::integration::*;

/// Test complete end-to-end flow:
/// - Generate keys
/// - Create configs
/// - Start server
/// - Start client
/// - Route traffic through proxy
#[tokio::test]
#[serial_test::serial]
async fn test_full_proxy_routing() -> anyhow::Result<()> {
    // Add overall test timeout
    let result = tokio::time::timeout(Duration::from_secs(120), test_full_proxy_routing_inner()).await;
    match result {
        Ok(r) => r,
        Err(_) => anyhow::bail!("Test timed out after 120 seconds"),
    }
}

async fn test_full_proxy_routing_inner() -> anyhow::Result<()> {
    // Initialize test environment
    let mut env = TestEnvironment::new()?;
    
    // Find available ports
    let server_port = fixtures::find_available_port()?;
    let socks5_port = fixtures::find_available_port()?;
    let server_addr = format!("127.0.0.1:{}", server_port);
    let socks5_addr = format!("127.0.0.1:{}", socks5_port);
    
    println!("Server will listen on: {}", server_addr);
    println!("SOCKS5 proxy will listen on: {}", socks5_addr);
    
    // Step 1: Generate server identity key
    println!("Generating server key...");
    let server_key = generate_server_key(&env)?;
    assert!(server_key.exists(), "Server key should exist");
    println!("✓ Server key generated at: {:?}", server_key);
    
    // Step 2: Generate client identity key
    println!("Generating client key...");
    let client_key = generate_client_key(&env)?;
    assert!(client_key.exists(), "Client key should exist");
    println!("✓ Client key generated at: {:?}", client_key);
    
    // Step 3: Generate server prekey bundle
    println!("Generating prekey bundle...");
    let prekey_bundle = generate_prekey_bundle(&env, &server_key)?;
    assert!(prekey_bundle.exists(), "Prekey bundle should exist");
    println!("✓ Prekey bundle generated at: {:?}", prekey_bundle);
    
    // Step 4: Create server configuration
    println!("Creating server config...");
    let server_config = create_server_config(&env, &server_addr, &server_key)?;
    println!("✓ Server config created at: {:?}", server_config);
    
    // Step 5: Create client configuration
    println!("Creating client config...");
    let client_config = create_client_config(
        &env,
        &server_addr,
        &client_key,
        &prekey_bundle,
        socks5_port,
    )?;
    println!("✓ Client config created at: {:?}", client_config);
    
    // Step 6: Start R-VPN server
    println!("Starting R-VPN server...");
    start_server(&mut env, &server_config)?;
    
    // Give server time to start
    sleep(Duration::from_secs(2)).await;
    
    // Verify server is running
    if let Some(ref mut server) = env.server {
        assert!(is_running(server), "Server should be running");
        println!("✓ R-VPN server started and running");
    } else {
        anyhow::bail!("Server process not found");
    }
    
    // Verify server is listening before starting client
    println!("Verifying server is listening...");
    helpers::wait_for_proxy(&server_addr, 10)?;
    println!("✓ Server is accepting connections");
    
    // Step 7: Start R-VPN client
    println!("Starting R-VPN client...");
    start_client(&mut env, &client_config)?;
    
    // Give client time to connect
    sleep(Duration::from_secs(5)).await;
    
    // Verify client is running
    if let Some(ref mut client) = env.client {
        // Try to get stderr output
        use std::io::Read;
        if let Some(mut stderr) = client.stderr.take() {
            let mut buf = String::new();
            let _ = stderr.read_to_string(&mut buf);
            if !buf.is_empty() {
                println!("Client stderr: {}", buf);
            }
        }
        
        if !is_running(client) {
            // Get exit status
            let status = client.try_wait().unwrap_or(None);
            println!("Client exit status: {:?}", status);
            anyhow::bail!("Client exited unexpectedly");
        }
        println!("✓ R-VPN client started and running");
    } else {
        anyhow::bail!("Client process not found");
    }
    
    // Step 8: Wait for SOCKS5 proxy to be ready
    println!("Waiting for SOCKS5 proxy to be ready...");
    helpers::wait_for_proxy(&socks5_addr, 30)?;
    println!("✓ SOCKS5 proxy is ready");
    
    // Give client more time to fully establish connection
    sleep(Duration::from_secs(3)).await;
    
    // Step 9: Test SOCKS5 handshake and proxy connect
    // This tests the full encrypted tunnel including X3DH handshake,
    // Double Ratchet encryption, and proxy message routing.
    println!("Testing SOCKS5 proxy through encrypted tunnel...");
    
    // Test 1: SOCKS5 greeting
    let mut stream = std::net::TcpStream::connect(&socks5_addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    
    // Send SOCKS5 greeting
    stream.write_all(&[0x05, 0x01, 0x00])?; // Version 5, 1 method, no auth
    stream.flush()?;
    
    // Read server response
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf)?;
    
    if buf[0] != 0x05 || buf[1] != 0x00 {
        anyhow::bail!("SOCKS5 handshake failed: {:?}", buf);
    }
    
    println!("✓ SOCKS5 handshake successful");
    
    // Test 2: SOCKS5 CONNECT request (triggers encrypted proxy connect)
    // We connect to an external address that should work from the server side
    // Using Cloudflare's DNS server as a reliable test target
    let target_host = "1.1.1.1";
    let target_port = 53u16;
    
    println!("Testing SOCKS5 CONNECT to {}:{}...", target_host, target_port);
    
    // Send CONNECT request with IPv4 address
    let mut request = vec![
        0x05, // Version
        0x01, // CONNECT command
        0x00, // Reserved
        0x01, // IPv4 address type
    ];
    // Add IP address (1.1.1.1)
    request.extend_from_slice(&[1, 1, 1, 1]);
    // Add port in network byte order
    request.extend_from_slice(&target_port.to_be_bytes());
    
    stream.write_all(&request)?;
    stream.flush()?;
    
    // Read CONNECT response (10 bytes for IPv4)
    let mut response = [0u8; 10];
    stream.read_exact(&mut response)?;
    
    // Check response
    if response[0] != 0x05 {
        anyhow::bail!("SOCKS5 response version mismatch: {}", response[0]);
    }
    
    match response[1] {
        0x00 => {
            println!("✓ SOCKS5 CONNECT successful (encrypted proxy connect worked)");
        }
        0x01 => anyhow::bail!("SOCKS5 CONNECT failed: general failure"),
        0x02 => anyhow::bail!("SOCKS5 CONNECT failed: connection not allowed"),
        0x03 => anyhow::bail!("SOCKS5 CONNECT failed: network unreachable"),
        0x04 => anyhow::bail!("SOCKS5 CONNECT failed: host unreachable"),
        0x05 => anyhow::bail!("SOCKS5 CONNECT failed: connection refused"),
        code => anyhow::bail!("SOCKS5 CONNECT failed: error code {:#x}", code),
    }
    
    // Close the connection
    drop(stream);
    
    println!("✓ Encrypted proxy tunnel test passed");
    
    // Cleanup
    println!("Cleaning up...");
    env.cleanup();
    println!("✓ Test completed successfully");
    
    Ok(())
}

/// Test key generation commands work correctly
#[test]
#[serial_test::serial]
fn test_key_generation() -> anyhow::Result<()> {
    let env = TestEnvironment::new()?;
    
    // Generate server key
    let server_key = generate_server_key(&env)?;
    assert!(server_key.exists());
    
    // Verify key format
    let key_content = std::fs::read_to_string(&server_key)?;
    assert!(key_content.starts_with("R-VPN-IDENTITY-v1"));
    
    // Generate client key
    let client_key = generate_client_key(&env)?;
    assert!(client_key.exists());
    
    let key_content = std::fs::read_to_string(&client_key)?;
    assert!(key_content.starts_with("R-VPN-IDENTITY-v1"));
    
    Ok(())
}

/// Test prekey bundle generation
#[test]
#[serial_test::serial]
fn test_prekey_bundle_generation() -> anyhow::Result<()> {
    let env = TestEnvironment::new()?;
    
    // Generate server key
    let server_key = generate_server_key(&env)?;
    
    // Generate prekey bundle
    let bundle = generate_prekey_bundle(&env, &server_key)?;
    assert!(bundle.exists());
    
    // Verify bundle format
    let bundle_content = std::fs::read_to_string(&bundle)?;
    let bundle_json: serde_json::Value = serde_json::from_str(&bundle_content)?;
    
    assert!(bundle_json.get("identity_key").is_some());
    assert!(bundle_json.get("signed_prekey").is_some());
    assert!(bundle_json.get("prekey_signature").is_some());
    
    Ok(())
}

/// Test configuration file generation
#[test]
#[serial_test::serial]
fn test_config_generation() -> anyhow::Result<()> {
    let env = TestEnvironment::new()?;
    
    // Generate keys
    let server_key = generate_server_key(&env)?;
    let client_key = generate_client_key(&env)?;
    let bundle = generate_prekey_bundle(&env, &server_key)?;
    
    // Create server config
    let server_config = create_server_config(&env, "127.0.0.1:8080", &server_key)?;
    assert!(server_config.exists());
    
    let config_content = std::fs::read_to_string(&server_config)?;
    assert!(config_content.contains("bind_address"));
    assert!(config_content.contains("identity_key_file"));
    
    // Create client config
    let client_config = create_client_config(
        &env,
        "ws://127.0.0.1:8080/connect",
        &client_key,
        &bundle,
        1080,
    )?;
    assert!(client_config.exists());
    
    let config_content = std::fs::read_to_string(&client_config)?;
    assert!(config_content.contains("server_address"));
    assert!(config_content.contains("socks5"));
    
    Ok(())
}
/// Helper function for sleep
async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}
