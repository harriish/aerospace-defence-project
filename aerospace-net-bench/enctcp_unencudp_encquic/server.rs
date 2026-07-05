use std::net::SocketAddr;
use std::sync::Arc;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap_or_else(|_| {});

    let tcp_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let quic_addr: SocketAddr = "127.0.0.1:8081".parse()?;
    let udp_addr: SocketAddr = "127.0.0.1:8082".parse()?;

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.der().to_vec();
    let priv_key_der = cert.key_pair.serialize_der();

    let server_crypto = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert_der)], 
                rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key_der.into())
            )?
    );

    println!("🚀 Starting Balanced Multi-Protocol Servers...");

    // 1. Encrypted TLS-over-TCP Server (Port 8080) using tokio-rustls
    let tls_acceptor = TlsAcceptor::from(server_crypto.clone());
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(tcp_addr).await.unwrap();
        println!("🟢 Encrypted TLS-over-TCP Server active on {}", tcp_addr);
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                        let mut buf = vec![0u8; 65536];
                        while let Ok(n) = tls_stream.read(&mut buf).await {
                            if n == 0 { break; }
                            if tls_stream.write_all(&buf[..n]).await.is_err() { break; }
                        }
                    }
                });
            }
        }
    });

    // 2. RAW Unencrypted UDP Echo Server (Port 8082)
    tokio::spawn(async move {
        let socket = tokio::net::UdpSocket::bind(udp_addr).await.unwrap();
        println!("🟨 Raw Unencrypted UDP Server active on {}", udp_addr);
        let mut buf = vec![0u8; 65536];
        loop {
            if let Ok((len, src)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..len], &src).await;
            }
        }
    });

    // 3. Encrypted QUIC Server (Port 8081)
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from((*server_crypto).clone())?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(10).try_into()?));
    server_config.transport_config(Arc::new(transport_config));

    let endpoint = quinn::Endpoint::server(server_config, quic_addr)?;
    println!("🟢 Encrypted QUIC Server active on {}", quic_addr);

    while let Some(conn) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Ok(connection) = conn.await {
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65536];
                        while let Ok(Some(n)) = recv.read(&mut buf).await {
                            if n == 0 { break; }
                            let _ = send.write_all(&buf[..n]).await;
                        }
                    });
                }
            }
        });
    }
    Ok(())
}
