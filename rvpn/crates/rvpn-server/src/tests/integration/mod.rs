//! Integration tests for R-VPN
//!
//! These tests spin up real server and client instances to test
//! end-to-end functionality including key exchange, connection,
//! and traffic routing.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Get the path to the rvpn-server binary (prefer pre-built, fallback to cargo)
fn get_server_binary() -> (Command, Vec<String>) {
    // Check for pre-built binary first
    let project_root = get_project_root();
    let debug_binary = project_root.join("target/debug/rvpn-server");
    let release_binary = project_root.join("target/release/rvpn-server");
    
    if debug_binary.exists() {
        let cmd = Command::new(debug_binary);
        return (cmd, vec![]);
    }
    
    if release_binary.exists() {
        let cmd = Command::new(release_binary);
        return (cmd, vec![]);
    }
    
    // Fallback to cargo run
    let mut cmd = Command::new("cargo");
    let args = vec![
        "run".to_string(),
        "--bin".to_string(),
        "rvpn-server".to_string(),
        "--".to_string(),
    ];
    cmd.current_dir(&project_root);
    (cmd, args)
}

/// Get the path to the rvpn client binary (prefer pre-built, fallback to cargo)
fn get_client_binary() -> (Command, Vec<String>) {
    // Check for pre-built binary first
    let project_root = get_project_root();
    let debug_binary = project_root.join("target/debug/rvpn");
    let release_binary = project_root.join("target/release/rvpn");
    
    if debug_binary.exists() {
        let cmd = Command::new(debug_binary);
        return (cmd, vec![]);
    }
    
    if release_binary.exists() {
        let cmd = Command::new(release_binary);
        return (cmd, vec![]);
    }
    
    // Fallback to cargo run
    let mut cmd = Command::new("cargo");
    let args = vec![
        "run".to_string(),
        "-p".to_string(),
        "rvpn-client".to_string(),
        "--bin".to_string(),
        "rvpn".to_string(),
        "--".to_string(),
    ];
    cmd.current_dir(&project_root);
    (cmd, args)
}

/// Get the project root directory (workspace root)
fn get_project_root() -> PathBuf {
    // Start from CARGO_MANIFEST_DIR and go up to find the workspace root
    // The workspace root has a Cargo.toml with [workspace] section
    let start_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap());
    
    let mut dir = start_dir.clone();
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            // Check if this is the workspace root by looking for [workspace] section
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                if content.contains("[workspace]") {
                    return dir;
                }
            }
        }
        if !dir.pop() {
            // Fallback to original directory
            return start_dir;
        }
    }
}

pub mod fixtures;
pub mod helpers;

/// Test environment that manages temporary files and processes
pub struct TestEnvironment {
    /// Temporary directory for test files
    pub temp_dir: tempfile::TempDir,
    /// Server process handle
    pub server: Option<Child>,
    /// Client process handle
    pub client: Option<Child>,
}

impl TestEnvironment {
    /// Create a new test environment
    pub fn new() -> anyhow::Result<Self> {
        let temp_dir = tempfile::tempdir()?;
        
        Ok(Self {
            temp_dir,
            server: None,
            client: None,
        })
    }
    
    /// Get path to a file in the temp directory
    pub fn path(&self, filename: &str) -> PathBuf {
        self.temp_dir.path().join(filename)
    }
    
    /// Kill all spawned processes
    pub fn cleanup(&mut self) {
        if let Some(mut server) = self.server.take() {
            let _ = server.kill();
            let _ = server.wait();
        }
        if let Some(mut client) = self.client.take() {
            let _ = client.kill();
            let _ = client.wait();
        }
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Generate server identity key
pub fn generate_server_key(env: &TestEnvironment) -> anyhow::Result<PathBuf> {
    let key_path = env.path("server_identity.key");
    let project_root = get_project_root();
    
    let (mut cmd, prefix_args) = get_server_binary();
    let mut args = prefix_args;
    args.push("keygen".to_string());
    
    let output = cmd
        .args(&args)
        .current_dir(&project_root)
        .env("RUST_LOG", "error")
        .output()?;
    
    if !output.status.success() {
        anyhow::bail!("Failed to generate server key: {}", 
            String::from_utf8_lossy(&output.stderr));
    }
    
    // The keygen command creates server_identity.key in current directory
    // Move it to our temp dir
    let default_key = project_root.join("server_identity.key");
    if default_key.exists() {
        std::fs::rename(&default_key, &key_path)?;
    }
    
    Ok(key_path)
}

/// Generate client identity key
pub fn generate_client_key(env: &TestEnvironment) -> anyhow::Result<PathBuf> {
    let key_path = env.path("client_identity.key");
    let project_root = get_project_root();
    
    let (mut cmd, prefix_args) = get_client_binary();
    let mut args = prefix_args;
    args.push("keygen".to_string());
    args.push("--output".to_string());
    args.push(key_path.to_str().unwrap().to_string());
    
    let output = cmd
        .args(&args)
        .current_dir(&project_root)
        .env("RUST_LOG", "error")
        .output()?;
    
    if !output.status.success() {
        anyhow::bail!("Failed to generate client key: {}",
            String::from_utf8_lossy(&output.stderr));
    }
    
    Ok(key_path)
}

/// Generate server prekey bundle
pub fn generate_prekey_bundle(
    env: &TestEnvironment,
    identity_path: &Path,
) -> anyhow::Result<PathBuf> {
    let bundle_path = env.path("prekey-bundle.json");
    let project_root = get_project_root();
    
    let (mut cmd, prefix_args) = get_server_binary();
    let mut args = prefix_args;
    args.push("prekey-bundle".to_string());
    args.push("--identity".to_string());
    args.push(identity_path.to_str().unwrap().to_string());
    args.push("--output".to_string());
    args.push(bundle_path.to_str().unwrap().to_string());
    
    let output = cmd
        .args(&args)
        .current_dir(&project_root)
        .env("RUST_LOG", "error")
        .output()?;
    
    if !output.status.success() {
        anyhow::bail!("Failed to generate prekey bundle: {}",
            String::from_utf8_lossy(&output.stderr));
    }
    
    Ok(bundle_path)
}

/// Create server configuration file
pub fn create_server_config(
    env: &TestEnvironment,
    bind_address: &str,
    identity_path: &Path,
) -> anyhow::Result<PathBuf> {
    let config_path = env.path("server.toml");
    
    // Note: ServerConfig uses [server] section
    let config = format!(r#"
[server]
bind_address = "{}"
identity_key_file = "{}"
http_port = 8080
redirect_http_to_https = false

[server.network]
nat_enabled = true
dhcp_range = "10.200.0.0/24"
dns_servers = ["1.1.1.1"]

[server.rate_limit]
max_connections_per_ip = 10
max_handshakes_per_minute = 20
"#, bind_address, identity_path.display());
    
    std::fs::write(&config_path, config)?;
    
    Ok(config_path)
}

/// Create client configuration file
pub fn create_client_config(
    env: &TestEnvironment,
    server_address: &str,
    identity_path: &Path,
    prekey_bundle: &Path,
    socks5_port: u16,
) -> anyhow::Result<PathBuf> {
    let config_path = env.path("client.toml");
    
    // Use ws:// for plain WebSocket (no TLS) for testing
    let ws_url = format!("ws://{}/connect", server_address);
    
    // Note: ClientConfig doesn't use [client] section - fields are at root
    let config = format!(r#"
server_address = "{}"
identity_key_file = "{}"
prekey_bundle = "{}"

[socks5]
listen_address = "127.0.0.1:{}"
udp_associate = true
auth_enabled = false
"#, ws_url, identity_path.display(), prekey_bundle.display(), socks5_port);
    
    std::fs::write(&config_path, config)?;
    
    Ok(config_path)
}

/// Start the server process
pub fn start_server(
    env: &mut TestEnvironment,
    config_path: &Path,
) -> anyhow::Result<()> {
    let project_root = get_project_root();
    
    let (mut cmd, prefix_args) = get_server_binary();
    let mut args = prefix_args;
    args.push("--config".to_string());
    args.push(config_path.to_str().unwrap().to_string());
    
    let child = cmd
        .args(&args)
        .current_dir(&project_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    
    env.server = Some(child);
    
    // Wait for server to start
    std::thread::sleep(Duration::from_secs(2));
    
    Ok(())
}

/// Start the client process
pub fn start_client(
    env: &mut TestEnvironment,
    config_path: &Path,
) -> anyhow::Result<()> {
    let project_root = get_project_root();
    
    let (mut cmd, prefix_args) = get_client_binary();
    let mut args = prefix_args;
    args.push("--config".to_string());
    args.push(config_path.to_str().unwrap().to_string());
    
    let child = cmd
        .args(&args)
        .current_dir(&project_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    
    env.client = Some(child);
    
    // Wait for client to start
    std::thread::sleep(Duration::from_secs(2));
    
    Ok(())
}

/// Check if a process is still running
pub fn is_running(child: &mut Child) -> bool {
    match child.try_wait() {
        Ok(None) => true,
        _ => false,
    }
}
