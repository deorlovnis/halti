//! A TLS client that trusts the hub by its pin, as `wire` says a client does: the certificate's
//! key must hash to the pin, and nothing else in the certificate is checked. The handshake's
//! signature is still checked with that key, so a server that has the certificate without the key
//! fails. A machine's link connects with it; until the link exists, the tests do.

#![cfg_attr(not(test), allow(dead_code))]

use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme, StreamOwned};
use sha2::{Digest, Sha256};

use super::{ALPN, CERT_NAME, provider};

/// Trusts a certificate whose key hashes to the pin, and only that.
#[derive(Debug)]
struct Pinned {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        let hash: [u8; 32] = Sha256::digest(cert.subject_public_key_info().as_ref()).into();
        if hash == self.pin { Ok(ServerCertVerified::assertion()) } else { Err(Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)) }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS 1.3 to the hub with this pin.
pub fn client_config(pin: [u8; 32]) -> Arc<ClientConfig> {
    let provider = provider();
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned { pin, provider }))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(config)
}

/// A connection to the hub at `address`, its handshake done: an error if the hub's key isn't the
/// pinned one.
pub fn connect(address: &str, pin: [u8; 32], wait: Duration) -> Result<StreamOwned<ClientConnection, TcpStream>> {
    let tcp = TcpStream::connect(address).with_context(|| format!("connecting to {address}"))?;
    tcp.set_read_timeout(Some(wait))?;
    tcp.set_write_timeout(Some(wait))?;
    let name = ServerName::try_from(CERT_NAME).expect("a DNS name");
    let conn = ClientConnection::new(client_config(pin), name)?;
    let mut stream = StreamOwned::new(conn, tcp);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock).context("TLS with the hub")?;
    }
    Ok(stream)
}
