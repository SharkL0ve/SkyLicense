use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

// Server certificate SHA-256 fingerprint for pinning
// Replace with your actual server certificate fingerprint
const PINNED_CERT_HASH: &[u8; 32] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

/// Custom certificate verifier that pins to a specific certificate fingerprint
#[derive(Debug)]
struct PinnedCertVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

impl PinnedCertVerifier {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| format!("TLS verifier build error: {}", e))?;
        Ok(Self { inner })
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // First do standard WebPKI verification
        self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

        // Then verify certificate pin
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let cert_hash = hasher.finalize();

        // Skip pin check if using placeholder (development mode)
        if PINNED_CERT_HASH != &[0u8; 32] {
            if cert_hash.as_slice() != PINNED_CERT_HASH {
                return Err(rustls::Error::General("Certificate pin mismatch".to_string()));
            }
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Create a TLS-wrapped TCP connection to the server
pub async fn connect_tls(host: &str, port: &str) -> Result<TlsStream<TcpStream>, String> {
    let addr = format!("{}:{}", host, port);

    let tcp_stream = TcpStream::connect(&addr)
        .await
        .map_err(|_| "SOCKET_ERROR_CONNECT".to_string())?;

    let verifier = PinnedCertVerifier::new()
        .map_err(|e| format!("TLS_ERROR_VERIFIER: {}", e))?;

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| "TLS_ERROR_SERVERNAME".to_string())?;

    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| format!("TLS_ERROR_HANDSHAKE: {}", e))?;

    Ok(tls_stream)
}
