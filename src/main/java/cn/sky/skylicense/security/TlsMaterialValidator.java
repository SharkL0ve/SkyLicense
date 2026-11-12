package cn.sky.skylicense.security;

import io.netty.handler.ssl.JdkSslContext;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Cryptographically validates the TLS chain and its private key before listeners start. */
public final class TlsMaterialValidator {
    private static final String TLS_PROTOCOL = "TLSv1.3";
    private static final String SERVER_AUTH_EKU = "1.3.6.1.5.5.7.3.1";
    private static final String ANY_EKU = "2.5.29.37.0";
    private static final int HANDSHAKE_TIMEOUT_MILLIS = 5_000;
    private static final long MAX_CERTIFICATE_CHAIN_BYTES = 1024L * 1024L;
    private static final byte[][] PRIVATE_KEY_MARKERS = {
            "-----BEGIN PRIVATE KEY-----".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
            "-----BEGIN ENCRYPTED PRIVATE KEY-----".getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII),
            "-----BEGIN RSA PRIVATE KEY-----".getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII),
            "-----BEGIN EC PRIVATE KEY-----".getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII),
            "-----BEGIN DSA PRIVATE KEY-----".getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII),
            "-----BEGIN OPENSSH PRIVATE KEY-----".getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII)
    };

    private TlsMaterialValidator() {
    }

    public static Summary validate(
            Path certificateChain,
            Path privateKey,
            String password,
            String serverName
    ) {
        try {
            List<X509Certificate> certificates = readCertificates(certificateChain);
            validateCertificateChain(certificates);
            verifyPrivateKeyMatch(
                    certificateChain, privateKey, password, certificates.get(0), serverName);

            X509Certificate leaf = certificates.get(0);
            return new Summary(
                    sha256(leaf.getEncoded()),
                    leaf.getSubjectX500Principal().getName(),
                    leaf.getNotBefore().toInstant(),
                    leaf.getNotAfter().toInstant(),
                    certificates.size(),
                    countServerNames(leaf),
                    serverName);
        } catch (IllegalStateException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalStateException("TLS certificate/private-key validation failed", error);
        }
    }

    private static List<X509Certificate> readCertificates(Path certificateChain) throws Exception {
        long size = Files.size(certificateChain);
        if (size <= 0 || size > MAX_CERTIFICATE_CHAIN_BYTES) {
            throw new IllegalStateException("TLS certificate chain has an invalid size");
        }
        byte[] encoded = Files.readAllBytes(certificateChain);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> parsed;
        try (InputStream input = new ByteArrayInputStream(encoded)) {
            rejectPrivateKeyMaterial(encoded);
            parsed = factory.generateCertificates(input);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
        if (parsed.isEmpty()) {
            throw new IllegalStateException("TLS certificate chain does not contain a certificate");
        }
        List<X509Certificate> certificates = new ArrayList<>(parsed.size());
        for (Certificate certificate : parsed) {
            if (!(certificate instanceof X509Certificate x509)) {
                throw new IllegalStateException("TLS certificate chain contains a non-X.509 certificate");
            }
            certificates.add(x509);
        }
        return List.copyOf(certificates);
    }

    private static void rejectPrivateKeyMaterial(byte[] encoded) {
        for (byte[] marker : PRIVATE_KEY_MARKERS) {
            if (contains(encoded, marker)) {
                throw new IllegalStateException(
                        "TLS certificate chain must not contain private-key material");
            }
        }
    }

    private static boolean contains(byte[] value, byte[] marker) {
        if (marker.length == 0 || marker.length > value.length) {
            return false;
        }
        int last = value.length - marker.length;
        for (int offset = 0; offset <= last; offset++) {
            int difference = 0;
            for (int index = 0; index < marker.length; index++) {
                difference |= value[offset + index] ^ marker[index];
            }
            if (difference == 0) {
                return true;
            }
        }
        return false;
    }

    private static void validateCertificateChain(List<X509Certificate> certificates) throws Exception {
        Set<String> fingerprints = new HashSet<>();
        for (int index = 0; index < certificates.size(); index++) {
            X509Certificate certificate = certificates.get(index);
            certificate.checkValidity();
            if (!fingerprints.add(sha256(certificate.getEncoded()))) {
                throw new IllegalStateException("TLS certificate chain contains a duplicate certificate");
            }
            if (index == 0) {
                validateLeafCertificate(certificate);
            } else {
                validateIssuerCertificate(certificate);
            }
            if (index + 1 < certificates.size()) {
                X509Certificate issuer = certificates.get(index + 1);
                if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                    throw new IllegalStateException("TLS certificate chain is not ordered leaf-first");
                }
                certificate.verify(issuer.getPublicKey());
            }
        }
    }

    private static void validateLeafCertificate(X509Certificate leaf) throws Exception {
        if (leaf.getBasicConstraints() >= 0) {
            throw new IllegalStateException("TLS leaf certificate must not be a CA certificate");
        }
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null && (keyUsage.length == 0 || !keyUsage[0])) {
            throw new IllegalStateException("TLS leaf certificate must permit digital signatures");
        }
        List<String> extendedKeyUsage = leaf.getExtendedKeyUsage();
        if (extendedKeyUsage != null
                && !extendedKeyUsage.contains(SERVER_AUTH_EKU)
                && !extendedKeyUsage.contains(ANY_EKU)) {
            throw new IllegalStateException("TLS leaf certificate is not valid for server authentication");
        }
        if (countServerNames(leaf) == 0) {
            throw new IllegalStateException("TLS leaf certificate must contain a DNS or IP SAN");
        }
    }

    private static void validateIssuerCertificate(X509Certificate issuer) {
        if (issuer.getBasicConstraints() < 0) {
            throw new IllegalStateException("TLS issuer certificate is not a CA certificate");
        }
        boolean[] keyUsage = issuer.getKeyUsage();
        if (keyUsage != null && (keyUsage.length <= 5 || !keyUsage[5])) {
            throw new IllegalStateException("TLS issuer certificate cannot sign certificates");
        }
    }

    private static int countServerNames(X509Certificate certificate) throws Exception {
        Collection<List<?>> names = certificate.getSubjectAlternativeNames();
        if (names == null) {
            return 0;
        }
        int count = 0;
        for (List<?> name : names) {
            if (name.size() >= 2 && name.get(0) instanceof Integer type
                    && (type == 2 || type == 7)) {
                count++;
            }
        }
        return count;
    }

    private static void verifyPrivateKeyMatch(
            Path certificateChain,
            Path privateKey,
            String password,
            X509Certificate leaf,
            String serverName
    ) throws Exception {
        SslContext nettyContext = SslContextBuilder
                .forServer(certificateChain.toFile(), privateKey.toFile(), password)
                .sslProvider(SslProvider.JDK)
                .protocols(TLS_PROTOCOL)
                .build();
        if (!(nettyContext instanceof JdkSslContext serverContext)) {
            throw new IllegalStateException("TLS preflight requires the JDK SSL provider");
        }

        SSLContext clientContext = trustedClientContext(leaf);
        InetAddress loopback = InetAddress.getLoopbackAddress();
        ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "skylicense-tls-preflight");
            thread.setDaemon(true);
            return thread;
        });
        Future<Void> serverHandshake = null;
        try (SSLServerSocket listener = (SSLServerSocket) serverContext.context()
                .getServerSocketFactory()
                .createServerSocket(0, 1, loopback)) {
            listener.setEnabledProtocols(new String[]{TLS_PROTOCOL});
            listener.setSoTimeout(HANDSHAKE_TIMEOUT_MILLIS);
            serverHandshake = executor.submit(() -> {
                try (SSLSocket socket = (SSLSocket) listener.accept()) {
                    socket.setEnabledProtocols(new String[]{TLS_PROTOCOL});
                    socket.setSoTimeout(HANDSHAKE_TIMEOUT_MILLIS);
                    socket.startHandshake();
                }
                return null;
            });

            try (Socket transport = new Socket()) {
                transport.connect(
                        new InetSocketAddress(loopback, listener.getLocalPort()),
                        HANDSHAKE_TIMEOUT_MILLIS);
                try (SSLSocket socket = (SSLSocket) clientContext.getSocketFactory()
                        .createSocket(
                                transport,
                                serverName,
                                listener.getLocalPort(),
                                true)) {
                    socket.setEnabledProtocols(new String[]{TLS_PROTOCOL});
                    socket.setSoTimeout(HANDSHAKE_TIMEOUT_MILLIS);
                    SSLParameters parameters = socket.getSSLParameters();
                    parameters.setEndpointIdentificationAlgorithm("HTTPS");
                    socket.setSSLParameters(parameters);
                    socket.startHandshake();
                }
            }
            awaitServerHandshake(serverHandshake);
        } finally {
            if (serverHandshake != null && !serverHandshake.isDone()) {
                serverHandshake.cancel(true);
            }
            executor.shutdownNow();
        }
    }

    private static SSLContext trustedClientContext(X509Certificate leaf) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("server", leaf);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        SSLContext context = SSLContext.getInstance(TLS_PROTOCOL);
        context.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
        return context;
    }

    private static void awaitServerHandshake(Future<Void> handshake) throws Exception {
        try {
            handshake.get(HANDSHAKE_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (ExecutionException error) {
            Throwable cause = error.getCause();
            if (cause instanceof Exception exception) {
                throw exception;
            }
            throw new IllegalStateException("TLS server preflight failed", cause);
        } catch (TimeoutException error) {
            throw new IllegalStateException("TLS private-key match handshake timed out", error);
        }
    }

    private static String sha256(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    public record Summary(
            String leafSha256,
            String leafSubject,
            Instant notBefore,
            Instant notAfter,
            int chainLength,
            int subjectAlternativeNameCount,
            String serverName
    ) {
    }
}
