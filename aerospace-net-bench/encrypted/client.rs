use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use anyhow::Result;
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "tcp")]
    protocol: String,

    #[arg(short = 's', long, default_value_t = 1024)]
    payload_size: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap_or_else(|_| {});

    let args = Args::parse();
    let payload = vec![0u8; args.payload_size];

    match args.protocol.as_str() {
        "tcp" => run_encrypted_tcp_test(&payload).await?,
        "quic" => run_encrypted_quic_test(&payload).await?,
        _ => println!("❌ Use --protocol tcp or --protocol quic"),
    }
    Ok(())
}

async fn run_encrypted_tcp_test(payload: &[u8]) -> Result<()> {
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    
    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_crypto));
    let domain = rustls::pki_types::ServerName::try_from("localhost")?.to_owned();

    let start_conn = Instant::now();
    // Step 1: Establish basic TCP socket link
    let tcp_stream = tokio::net::TcpStream::connect(addr).await?;
    // Step 2: Negotiate TLS 1.3 handshake on top of the established link
    let mut tls_stream = connector.connect(domain, tcp_stream).await?;
    let conn_duration = start_conn.elapsed();

    let start_tx = Instant::now();
    tls_stream.write_all(payload).await?;
    let mut buf = vec![0u8; payload.len()];
    tls_stream.read_exact(&mut buf).await?;
    let tx_duration = start_tx.elapsed();

    println!("📊 TLS-OVER-TCP RESULTS:");
    println!("   Handshake/Connection Time: {:?}", conn_duration);
    println!("   Data Round-Trip Time:      {:?}", tx_duration);
    Ok(())
}

async fn run_encrypted_quic_test(payload: &[u8]) -> Result<()> {
    let server_addr: SocketAddr = "127.0.0.1:8081".parse()?;
    let bind_addr: SocketAddr = "127.0.0.1:0".parse()?;
    
    let mut crypto_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    crypto_config.enable_early_data = true; 

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    println!("🔒 [QUIC] Attempting 1st Connection (Initial 1-RTT Setup)...");
    let connection1 = endpoint.connect(server_addr, "localhost")?.await?;
    println!("🟢 1st Connection Established.");

    connection1.close(0u32.into(), b"session_saved");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    println!("⚡ [QUIC] Reconnecting via 0-RTT Early Resumption...");
    let start_conn = Instant::now();
    let connection2 = endpoint.connect(server_addr, "localhost")?.await?;
    let conn_duration = start_conn.elapsed();

    let start_tx = Instant::now();
    let (mut send, mut recv) = connection2.open_bi().await?;
    send.write_all(payload).await?;
    send.finish()?;
    
    let mut buf = vec![0u8; payload.len()];
    recv.read_exact(&mut buf).await?;
    let tx_duration = start_tx.elapsed();

    println!("📊 0-RTT QUIC RESULTS:");
    println!("   Handshake/Connection Time: {:?}", conn_duration);
    println!("   Data Round-Trip Time:      {:?}", tx_duration);
    Ok(())
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}
