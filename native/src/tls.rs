//! Authentication transport.
//!
//! TLS 1.3 is mandatory in normal builds. Plain TCP exists only behind the
//! explicit `insecure-plaintext` Cargo feature so an attacker cannot trigger a
//! runtime downgrade through configuration or environment variables.

#[cfg(not(feature = "insecure-plaintext"))]
use rustls::pki_types::ServerName;
#[cfg(not(feature = "insecure-plaintext"))]
use rustls::{ClientConfig, RootCertStore};
#[cfg(not(feature = "insecure-plaintext"))]
use sha2::{Digest, Sha256};
use std::pin::Pin;
#[cfg(not(feature = "insecure-plaintext"))]
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
#[cfg(not(feature = "insecure-plaintext"))]
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

#[cfg(not(feature = "insecure-plaintext"))]
const CERTIFICATE_PIN: Option<&str> = option_env!("SKYLICENSE_CERT_SHA256");
#[cfg(not(feature = "insecure-plaintext"))]
const NEXT_CERTIFICATE_PIN: Option<&str> = option_env!("SKYLICENSE_CERT_SHA256_NEXT");

pub enum AuthStream {
    Tls(TlsStream<TcpStream>),
    #[cfg(feature = "insecure-plaintext")]
    Plain(TcpStream),
}

impl AsyncRead for AuthStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_read(context, buffer),
            #[cfg(feature = "insecure-plaintext")]
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for AuthStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_write(context, buffer),
            #[cfg(feature = "insecure-plaintext")]
            Self::Plain(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_flush(context),
            #[cfg(feature = "insecure-plaintext")]
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(context),
            #[cfg(feature = "insecure-plaintext")]
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

#[cfg(not(feature = "insecure-plaintext"))]
#[derive(Debug)]
struct PinnedCertVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    pin: Option<[u8; 32]>,
    next_pin: Option<[u8; 32]>,
}

#[cfg(not(feature = "insecure-plaintext"))]
impl PinnedCertVerifier {
    fn new(require_pin: bool) -> Result<Self, String> {
        let pin = CERTIFICATE_PIN.map(parse_sha256).transpose()?;
        let next_pin = NEXT_CERTIFICATE_PIN.map(parse_sha256).transpose()?;
        if require_pin && pin.is_none() {
            return Err(
                "strict profile requires SKYLICENSE_CERT_SHA256 at compile time".to_string(),
            );
        }
        if next_pin.is_some() && pin.is_none() {
            return Err(
                "SKYLICENSE_CERT_SHA256 is required when SKYLICENSE_CERT_SHA256_NEXT is set"
                    .to_string(),
            );
        }
        if pin
            .as_ref()
            .zip(next_pin.as_ref())
            .is_some_and(|(primary, next)| constant_time_equal(primary, next))
        {
            return Err(
                "SKYLICENSE_CERT_SHA256_NEXT must differ from SKYLICENSE_CERT_SHA256".to_string(),
            );
        }

        let roots = trust_roots(std::env::var_os("SKYLICENSE_NATIVE_CA_CERT_FILE").as_deref())?;
        let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| format!("TLS verifier build error: {error}"))?;
        Ok(Self {
            inner,
            pin,
            next_pin,
        })
    }
}

/// Explicit private-CA support for local/enterprise deployments. The ordinary
/// WebPKI validity/hostname checks and compiled certificate pins still apply.
#[cfg(not(feature = "insecure-plaintext"))]
fn trust_roots(private_ca: Option<&std::ffi::OsStr>) -> Result<RootCertStore, String> {
    use std::io::Read;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = private_ca {
        let path = std::path::Path::new(path);
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "private CA certificate file is unavailable".to_string())?;
        if !path.is_absolute()
            || !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 1024 * 1024
        {
            return Err("private CA must be an absolute regular PEM file of at most 1 MiB".into());
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|_| "private CA certificate cannot be opened".to_string())?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "private CA certificate cannot be read".to_string())?;
        if bytes.len() > 1024 * 1024 {
            return Err("private CA certificate exceeds size limit".into());
        }
        let mut count = 0;
        for certificate in rustls_pemfile::certs(&mut bytes.as_slice()) {
            roots
                .add(certificate.map_err(|_| "invalid private CA PEM".to_string())?)
                .map_err(|_| "invalid private CA certificate".to_string())?;
            count += 1;
        }
        if count == 0 {
            return Err("private CA file contains no certificates".into());
        }
    }
    Ok(roots)
}

#[cfg(not(feature = "insecure-plaintext"))]
impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        if let Some(pin) = self.pin {
            let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
            if !matches_certificate_pin(&digest, &pin, self.next_pin.as_ref()) {
                return Err(rustls::Error::General(
                    "server certificate pin mismatch".to_string(),
                ));
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

pub async fn connect(host: &str, port: &str) -> Result<AuthStream, String> {
    let port = port
        .parse::<u16>()
        .map_err(|_| "SOCKET_ERROR_PORT".to_string())?;
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|error| format!("SOCKET_ERROR_CONNECT: {error}"))?;
    tcp.set_nodelay(true)
        .map_err(|error| format!("SOCKET_ERROR_NODELAY: {error}"))?;

    #[cfg(feature = "insecure-plaintext")]
    {
        crate::security::report(crate::security::SecurityEvidence::new(
            crate::security::EvidenceKind::RuntimeFailure,
            crate::security::EvidenceConfidence::High,
            "transport.plaintext_build",
            "authentication transport was compiled with insecure-plaintext",
        ));
        return Ok(AuthStream::Plain(tcp));
    }

    #[cfg(not(feature = "insecure-plaintext"))]
    {
        let verifier = PinnedCertVerifier::new(crate::security::policy().require_certificate_pin)?;
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| "TLS_ERROR_SERVERNAME".to_string())?;
        let stream = TlsConnector::from(Arc::new(config))
            .connect(server_name, tcp)
            .await
            .map_err(|error| format!("TLS_ERROR_HANDSHAKE: {error}"))?;
        Ok(AuthStream::Tls(stream))
    }
}

#[cfg(all(test, not(feature = "insecure-plaintext")))]
mod private_ca_tests {
    use super::*;

    #[test]
    fn public_roots_remain_available_and_relative_ca_paths_fail() {
        assert!(!trust_roots(None).unwrap().is_empty());
        assert!(trust_roots(Some(std::ffi::OsStr::new("Cargo.toml"))).is_err());
    }

    #[test]
    fn malformed_and_oversized_private_ca_files_fail_closed() {
        use std::io::Write;
        let path =
            std::env::temp_dir().join(format!("skylicense-ca-{}.pem", rand::random::<u128>()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"not a certificate").unwrap();
        assert!(trust_roots(Some(path.as_os_str())).is_err());
        file.set_len(1024 * 1024 + 1).unwrap();
        assert!(trust_roots(Some(path.as_os_str())).is_err());
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(any(not(feature = "insecure-plaintext"), test))]
fn parse_sha256(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("SKYLICENSE_CERT_SHA256 must be exactly 64 hexadecimal characters".to_string());
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid certificate pin".to_string())?;
    }
    Ok(output)
}

#[cfg(any(not(feature = "insecure-plaintext"), test))]
fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

#[cfg(any(not(feature = "insecure-plaintext"), test))]
fn matches_certificate_pin(digest: &[u8; 32], primary: &[u8; 32], next: Option<&[u8; 32]>) -> bool {
    let primary_matches = constant_time_equal(digest, primary);
    let next_matches = next
        .map(|candidate| constant_time_equal(digest, candidate))
        .unwrap_or(false);
    primary_matches | next_matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_certificate_pin_strictly() {
        assert_eq!(parse_sha256(&"ab".repeat(32)).unwrap(), [0xAB; 32]);
        assert!(parse_sha256("00").is_err());
        assert!(parse_sha256(&"xz".repeat(32)).is_err());
    }

    #[test]
    fn pin_comparison_distinguishes_digests() {
        assert!(constant_time_equal(&[1; 32], &[1; 32]));
        assert!(!constant_time_equal(&[1; 32], &[2; 32]));
    }

    #[test]
    fn certificate_rotation_accepts_primary_or_next_pin() {
        let primary = [1; 32];
        let next = [2; 32];
        assert!(matches_certificate_pin(&primary, &primary, Some(&next)));
        assert!(matches_certificate_pin(&next, &primary, Some(&next)));
        assert!(!matches_certificate_pin(&[3; 32], &primary, Some(&next)));
        assert!(!matches_certificate_pin(&next, &primary, None));
    }

    #[cfg(all(feature = "security-compatible", not(feature = "insecure-plaintext")))]
    #[tokio::test]
    #[ignore = "requires external network access"]
    async fn public_webpki_tls13_handshake() {
        assert!(
            CERTIFICATE_PIN.is_none() && NEXT_CERTIFICATE_PIN.is_none(),
            "public WebPKI test must be compiled without certificate pins"
        );
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            connect("www.cloudflare.com", "443"),
        )
        .await;
        assert!(matches!(result, Ok(Ok(AuthStream::Tls(_)))));
    }
}
