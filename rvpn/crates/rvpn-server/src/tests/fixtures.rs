//! Test fixtures and utilities

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use rvpn_core::protocol::{HandshakeMessage, ProtocolVersion, AuthMethod};

/// Create valid identity and prekey files for a test configuration.
pub fn configure_test_keys(config: &mut crate::config::ServerConfig, directory: &std::path::Path) {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use rvpn_core::crypto::{IdentityKey, X3DHResponder};

    let identity = IdentityKey::generate();
    let identity_data = format!(
        "R-VPN-IDENTITY-v1\n{}\n{}\n",
        BASE64.encode(identity.verifying_key.as_bytes()),
        BASE64.encode(identity.signing_key.to_bytes())
    );
    let identity_path = directory.join("server_identity.key");
    crate::private_files::atomic_write_private(&identity_path, identity_data.as_bytes()).unwrap();
    let responder = X3DHResponder::from_identity(identity);
    let private_json = serde_json::json!({
        "signed_prekey_private": BASE64.encode(responder.get_signed_prekey_private())
    });
    let bundle_path = directory.join("prekey-bundle.json");
    crate::private_files::atomic_write_private(&bundle_path, b"{}").unwrap();
    crate::private_files::atomic_write_private(
        &bundle_path.with_extension("private.json"),
        private_json.to_string().as_bytes(),
    )
    .unwrap();
    config.identity_key_file = identity_path;
    config.prekey_bundle_file = Some(bundle_path);
}

/// Start a test server
pub async fn start_test_server(port: u16) -> Result<Arc<RwLock<crate::handler::VpnHandler>>> {
    use crate::config::ServerConfig;
    use crate::handler::VpnHandler;

    let directory = tempfile::tempdir()?;
    let mut config = ServerConfig {
        bind_address: format!("127.0.0.1:{}", port),
        ..Default::default()
    };
    configure_test_keys(&mut config, directory.path());

    let handler = Arc::new(RwLock::new(VpnHandler::new(config)?));
    Ok(handler)
}

/// Connect to server via WebSocket
pub async fn connect_to_server(addr: SocketAddr) -> Result<(
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
)> {
    let url = format!("ws://{}", addr);
    let (ws_stream, _) = connect_async(&url).await?;
    Ok((ws_stream,))
}

/// Perform X3DH handshake as client
pub async fn client_handshake(
    ws_stream: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};

    // Send Hello
    let hello = HandshakeMessage::Hello {
        version: ProtocolVersion::CURRENT,
        auth_method: AuthMethod::X3DH,
        ephemeral_key: Some(vec![0u8; 32]),
        identity_key: Some(vec![0u8; 32]),
        session_token: None,
        connection_nonce: Some(vec![0u8; 16]),
        capabilities: Some(rvpn_core::crypto::x3dh::CAP_RATCHET_V2),
    };

    let hello_bytes = serde_json::to_vec(&hello)?;
    ws_stream.send(Message::Binary(hello_bytes)).await?;

    // Wait for ServerHello
    let msg = ws_stream.next().await.ok_or_else(|| anyhow::anyhow!("Connection closed"))??;
    let _server_hello: HandshakeMessage = serde_json::from_slice(&msg.into_data())?;

    Ok(())
}

/// Test data constants
pub mod test_data {
    /// Test IPv4 addresses
    pub mod ips {
        /// China IP (Baidu)
        pub const CHINA: &str = "220.181.38.148";
        /// US IP (Google)
        pub const US: &str = "142.250.185.78";
        /// Local IP
        pub const LOCAL: &str = "192.168.1.1";
        /// Cloudflare DNS
        pub const CLOUDFLARE: &str = "1.1.1.1";
    }

    /// Test domains
    pub mod domains {
        /// China domain
        pub const CHINA: &str = "baidu.com";
        /// US domain
        pub const US: &str = "google.com";
        /// Local domain
        pub const LOCAL: &str = "localhost";
    }

    /// Test ports
    pub mod ports {
        pub const HTTP: u16 = 80;
        pub const HTTPS: u16 = 443;
        pub const DNS: u16 = 53;
    }
}

/// Async test runtime
#[cfg(test)]
pub mod runtime {
    use tokio::runtime::Runtime;

    /// Get a test runtime
    pub fn test_runtime() -> Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to build test runtime")
    }
}
