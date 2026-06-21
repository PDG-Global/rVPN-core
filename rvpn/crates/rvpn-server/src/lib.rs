//! R-VPN Server Library

pub mod config;
pub mod handler;
pub mod tun_server;

#[cfg(test)]
pub mod tests;

// Re-export tun_writer at crate root for easier access
pub use tun_writer::TunWriter;

/// Type-erased TUN writer for use in handler.rs
/// This allows passing TUN write capability without exposing the concrete TunServer type
mod tun_writer {
    use anyhow::Result;
    use std::net::IpAddr;
    use std::pin::Pin;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    pub trait TunWriter: Send + Sync {
        fn write_to_tun(
            &self,
            packet: &[u8],
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;
        fn register_client(
            &self,
            client_ip: IpAddr,
            sender: mpsc::Sender<Vec<u8>>,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;
        fn unregister_client(
            &self,
            client_ip: IpAddr,
            client_id: &str,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;
        fn allocate_ip(
            &self,
            client_id: String,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<IpAddr>> + Send + '_>>;
    }

    // Implement TunWriter for Arc<T> where T: TunWriter
    impl<T: TunWriter + Send + Sync + 'static> TunWriter for Arc<T> {
        fn write_to_tun(
            &self,
            packet: &[u8],
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            (**self).write_to_tun(packet)
        }
        fn register_client(
            &self,
            client_ip: IpAddr,
            sender: mpsc::Sender<Vec<u8>>,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            (**self).register_client(client_ip, sender)
        }
        fn unregister_client(
            &self,
            client_ip: IpAddr,
            client_id: &str,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            (**self).unregister_client(client_ip, client_id)
        }
        fn allocate_ip(
            &self,
            client_id: String,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<IpAddr>> + Send + '_>> {
            (**self).allocate_ip(client_id)
        }
    }

    // Implement TunWriter for RwLock<TunServer>
    impl TunWriter for tokio::sync::RwLock<crate::tun_server::TunServer> {
        fn write_to_tun(
            &self,
            packet: &[u8],
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            let pkt = packet.to_vec();
            Box::pin(async move {
                let ts = self.read().await;
                ts.write_to_tun(&pkt).await
            })
        }
        fn register_client(
            &self,
            client_ip: IpAddr,
            sender: mpsc::Sender<Vec<u8>>,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async move {
                let ts = self.read().await;
                ts.register_client(client_ip, sender).await
            })
        }
        fn unregister_client(
            &self,
            client_ip: IpAddr,
            client_id: &str,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            let client_id = client_id.to_string();
            Box::pin(async move {
                let ts = self.read().await;
                ts.unregister_client(client_ip, &client_id).await
            })
        }
        fn allocate_ip(
            &self,
            client_id: String,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<IpAddr>> + Send + '_>> {
            let client_id = client_id.clone();
            Box::pin(async move {
                let ts = self.read().await;
                ts.allocate_ip(&client_id).await
            })
        }
    }

    // Implement TunWriter for the actual TunServer
    impl TunWriter for crate::tun_server::TunServer {
        fn write_to_tun(
            &self,
            packet: &[u8],
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            let pkt = packet.to_vec();
            Box::pin(async move {
                let ts = self;
                ts.write_to_tun(&pkt).await
            })
        }
        fn register_client(
            &self,
            client_ip: IpAddr,
            sender: mpsc::Sender<Vec<u8>>,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            Box::pin(self.register_client(client_ip, sender))
        }
        fn unregister_client(
            &self,
            client_ip: IpAddr,
            client_id: &str,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            let client_id = client_id.to_string();
            Box::pin(async move {
                let ts = self;
                ts.unregister_client(client_ip, &client_id).await
            })
        }
        fn allocate_ip(
            &self,
            client_id: String,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<IpAddr>> + Send + '_>> {
            Box::pin(async move {
                let ts = self;
                ts.allocate_ip(&client_id).await
            })
        }
    }
}
