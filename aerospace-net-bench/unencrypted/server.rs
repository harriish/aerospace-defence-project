use std::net::SocketAddr;
use std::sync::Arc;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Manually install the process-level crypto provider required by modern rustls
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap_or_else(|_| println!("⚠️ CryptoProvider already installed"));

    let tcp_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let quic_addr: SocketAddr = "127.0.0.1:8081".parse()?;

    println!("🚀 Starting Aerospace Benchmark Servers...");
    
    // Spawn TCP Echo Server
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(tcp_addr).await.unwrap();
        println!("🟢 TCP Server listening on {}", tcp_addr);
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 { break; }
                        let _ = socket.write_all(&buf[..n]).await;
                    }
                });
            }
        }
    });

    // Run QUIC Server
    run_quic_server(quic_addr).await?;
    Ok(())
}

async fn run_quic_server(addr: SocketAddr) -> Result<()> {
    let server_config = configure_server()?;
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    println!("🟢 Raw QUIC Server listening on {}", addr);

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

fn configure_server() -> Result<quinn::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.der().to_vec();
    let priv_key_der = cert.key_pair.serialize_der();

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der)], 
            rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key_der.into())
        )?;
    
    // Convert the standard rustls config directly into Quinn's crypto provider
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    
    // Configure idle timeout settings within Quinn's protocol engine
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(10).try_into()?));
    server_config.transport_config(Arc::new(transport_config));
    
    Ok(server_config)
}
