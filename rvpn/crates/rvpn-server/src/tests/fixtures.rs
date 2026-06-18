//! Test fixtures and utilities

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use rvpn_core::protocol::{HandshakeMessage, ProtocolVersion, AuthMethod};

/// Start a test server
pub async fn start_test_server(port: u16) -> Result<Arc<RwLock<crate::handler::VpnHandler>>> {
    use crate::config::ServerConfig;
    use crate::handler::VpnHandler;

    let config = ServerConfig {
        bind_address: format!("127.0.0.1:{}", port),
        ..Default::default()
    };

    let handler = Arc::new(RwLock::new(VpnHandler::new(config)?));
    Ok(handler)
}

/// Connect to server via WebSocket
pub async fn connect_to_server(addr: SocketAddr) -> Result<(
    tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
)> {
    let url = format!("ws://{}", addr);
    let (ws_stream, _) = connect_async(&url).await?;
    Ok(ws_stream)
}

/// Perform X3DH handshake as client
pub async fn client_handshake(
    ws_stream: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
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
