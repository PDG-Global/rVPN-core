//! Shared test infrastructure for rvpn-client integration tests.

use std::sync::Arc;
use anyhow::Result;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

pub fn generate_test_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("localhost".to_owned()),
    );
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

pub async fn start_plain_ws_server() -> Result<(std::net::SocketAddr, oneshot::Sender<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    tokio::spawn(async move {
        tokio::select! {
            result = listener.accept() => {
                if let Ok((stream, _)) = result {
                    if let Ok(ws_stream) = tokio_tungstenite::accept_async(stream).await {
                        use futures::{SinkExt, StreamExt};
                        let (mut write, mut read) = ws_stream.split();
                        while let Some(Ok(msg)) = read.next().await {
                            if msg.is_text() || msg.is_binary() {
                                if write.send(msg).await.is_err() { break; }
                            }
                        }
                    }
                }
            }
            _ = shutdown_rx => {}
        }
    });

    Ok((addr, shutdown_tx))
}

pub async fn start_tls_ws_server() -> Result<(std::net::SocketAddr, oneshot::Sender<()>, Vec<u8>)> {
    let (cert_der, key_der) = generate_test_cert()?;

    // Use mozilla_intermediate_v5 which enables TLS 1.3
    let mut acc = boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())?;
    let cert = boring::x509::X509::from_der(&cert_der)?;
    acc.set_certificate(&cert)?;
    let key = boring::pkey::PKey::private_key_from_der(&key_der)?;
    acc.set_private_key(&key)?;
    acc.check_private_key()?;
    acc.set_alpn_select_callback(|_ssl, protocols| {
        if protocols.windows(8).any(|w| w == b"\x08http/1.1") {
            Ok(b"http/1.1")
        } else {
            Ok(b"http/1.1")
        }
    });
    let acceptor = acc.build();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    tokio::spawn(async move {
        let acceptor = Arc::new(acceptor);
        tokio::select! {
            result = listener.accept() => {
                if let Ok((tcp_stream, _)) = result {
                    match tokio_boring::accept(&acceptor, tcp_stream).await {
                        Ok(tls_stream) => {
                            if let Ok(ws_stream) = tokio_tungstenite::accept_async(tls_stream).await {
                                use futures::{SinkExt, StreamExt};
                                let (mut write, mut read) = ws_stream.split();
                                while let Some(Ok(msg)) = read.next().await {
                                    if msg.is_text() || msg.is_binary() {
                                        if write.send(msg).await.is_err() { break; }
                                    }
                                }
                            }
                        }
                        Err(e) => eprintln!("Test server TLS error: {:?}", e),
                    }
                }
            }
            _ = shutdown_rx => {}
        }
    });

    Ok((addr, shutdown_tx, cert_der))
}
