package cn.sky.skylicense.encrypt;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * ECDH Key Exchange and Challenge-Response protocol utilities
 */
public class ChallengeUtil {

    private static final String ECDH_ALGORITHM = "X25519";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final byte[] HKDF_LABEL =
            "SkyLicense v4 session".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] RESOURCE_KEY_LABEL =
            "SkyLicense v4 resource key\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] METHOD_KEY_LABEL =
            "SkyLicense v4 method key\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] RESOURCE_AAD_LABEL =
            "SkyLicense v4 resource aad\0".getBytes(StandardCharsets.US_ASCII);
    private static final int CONTEXT_ID_LENGTH = 32;
    private static final int MAX_CONTEXT_STRING_BYTES = 4096;

    private KeyPair serverKeyPair;
    private byte[] sharedSecret;
    private byte[] sessionKey;

    /**
     * Generate server ECDH key pair
     */
    public byte[] generateServerKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ECDH_ALGORITHM);
        serverKeyPair = kpg.generateKeyPair();
        return serverKeyPair.getPublic().getEncoded();
    }

    /**
     * Derive shared secret from client's public key
     */
    public void deriveSharedSecret(byte[] clientPublicKeyBytes) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(ECDH_ALGORITHM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPublicKeyBytes);
        PublicKey clientPublicKey = kf.generatePublic(keySpec);

        KeyAgreement ka = KeyAgreement.getInstance(ECDH_ALGORITHM);
        ka.init(serverKeyPair.getPrivate());
        ka.doPhase(clientPublicKey, true);
        sharedSecret = ka.generateSecret();
        boolean allZero = true;
        for (byte value : sharedSecret) {
            allZero &= value == 0;
        }
        if (allZero) {
            destroy();
            throw new InvalidKeyException("X25519 produced an all-zero shared secret");
        }
    }

    /**
     * Derive session key from shared secret + nonces
     */
    public byte[] deriveSessionKey(byte[] clientNonce, byte[] serverNonce) throws Exception {
        sessionKey = deriveSessionKeyMaterial(sharedSecret, clientNonce, serverNonce);
        Arrays.fill(sharedSecret, (byte) 0);
        sharedSecret = null;
        return sessionKey.clone();
    }

    static byte[] deriveSessionKeyMaterial(
            byte[] inputKeyMaterial,
            byte[] clientNonce,
            byte[] serverNonce
    ) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update("SkyLicense-HKDF-Salt".getBytes(StandardCharsets.US_ASCII));
        digest.update(clientNonce);
        digest.update(serverNonce);
        byte[] salt = digest.digest();

        Mac extract = Mac.getInstance(HMAC_ALGORITHM);
        extract.init(new SecretKeySpec(salt, HMAC_ALGORITHM));
        byte[] pseudoRandomKey = extract.doFinal(inputKeyMaterial);

        Mac expand = Mac.getInstance(HMAC_ALGORITHM);
        expand.init(new SecretKeySpec(pseudoRandomKey, HMAC_ALGORITHM));
        expand.update(HKDF_LABEL);
        expand.update(clientNonce);
        expand.update(serverNonce);
        expand.update((byte) 1);
        byte[] derivedKey = expand.doFinal();

        Arrays.fill(salt, (byte) 0);
        Arrays.fill(pseudoRandomKey, (byte) 0);
        return derivedKey;
    }

    /**
     * Generate a random challenge for the client
     */
    public static byte[] generateChallenge() {
        byte[] challenge = new byte[32];
        SECURE_RANDOM.nextBytes(challenge);
        return challenge;
    }

    /**
     * Generate a random nonce
     */
    public static byte[] generateNonce() {
        byte[] nonce = new byte[32];
        SECURE_RANDOM.nextBytes(nonce);
        return nonce;
    }

    /**
     * Verify client's challenge response
     */
    public boolean verifyChallengeResponse(
            byte[] clientResponse,
            byte[] challenge,
            byte[] clientNonce,
            byte[] sessionId,
            int securityEpoch,
            byte[] buildId,
            long timestamp
    ) throws Exception {
        if (sessionId == null || sessionId.length != 32
                || securityEpoch <= 0 || buildId == null || buildId.length != 32) {
            return false;
        }
        byte[] expected = computeChallengeResponse(
                sessionKey,
                challenge,
                clientNonce,
                sessionId,
                securityEpoch,
                buildId,
                timestamp);
        boolean valid = MessageDigest.isEqual(clientResponse, expected);
        Arrays.fill(expected, (byte) 0);
        return valid;
    }

    static byte[] computeChallengeResponse(
            byte[] sessionKey,
            byte[] challenge,
            byte[] clientNonce,
            byte[] sessionId,
            int securityEpoch,
            byte[] buildId,
            long timestamp
    ) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(sessionKey, HMAC_ALGORITHM));
        mac.update("SkyLicense v4 challenge\0".getBytes(StandardCharsets.US_ASCII));
        mac.update(challenge);
        mac.update(clientNonce);
        mac.update(sessionId);
        mac.update(new byte[]{
                (byte) (securityEpoch >> 24),
                (byte) (securityEpoch >> 16),
                (byte) (securityEpoch >> 8),
                (byte) securityEpoch
        });
        mac.update(buildId);
        mac.update(longToBytes(timestamp));
        return mac.doFinal();
    }

    /**
     * Compute HMAC for heartbeat verification
     */
    public static boolean verifyHeartbeat(byte[] sessionKey, byte[] payload, byte[] signature) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(sessionKey, HMAC_ALGORITHM));
        byte[] expected = mac.doFinal(payload);
        try {
            return MessageDigest.isEqual(expected, signature);
        } finally {
            Arrays.fill(expected, (byte) 0);
        }
    }

    public static byte[] signHeartbeatResponse(
            byte[] sessionKey,
            byte[] sessionId,
            long clientTimestamp,
            int response
    ) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(sessionKey, HMAC_ALGORITHM));
        mac.update("SkyLicense heartbeat response".getBytes(StandardCharsets.US_ASCII));
        mac.update(sessionId);
        mac.update(longToBytes(clientTimestamp));
        mac.update((byte) response);
        return mac.doFinal();
    }

    public static boolean verifyDeliveryAcknowledgement(
            byte[] sessionKey,
            byte[] sessionId,
            long clientTimestamp,
            int status,
            byte[] signature
    ) throws Exception {
        byte[] expected = computeDeliveryAcknowledgement(
                sessionKey, sessionId, clientTimestamp, status);
        try {
            return MessageDigest.isEqual(expected, signature);
        } finally {
            Arrays.fill(expected, (byte) 0);
        }
    }

    static byte[] computeDeliveryAcknowledgement(
            byte[] sessionKey,
            byte[] sessionId,
            long clientTimestamp,
            int status
    ) throws Exception {
        if (sessionKey == null || sessionKey.length != CONTEXT_ID_LENGTH
                || sessionId == null || sessionId.length != CONTEXT_ID_LENGTH
                || status < 0 || status > 0xff) {
            throw new IllegalArgumentException("invalid delivery acknowledgement context");
        }
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(sessionKey, HMAC_ALGORITHM));
        mac.update("SkyLicense v4 delivery ack\0".getBytes(StandardCharsets.US_ASCII));
        mac.update(sessionId);
        mac.update(longToBytes(clientTimestamp));
        mac.update((byte) status);
        return mac.doFinal();
    }

    public static byte[] deriveResourceTransportKey(
            byte[] sessionKey,
            byte[] sessionId,
            int securityEpoch,
            byte[] buildId,
            String pluginName,
            String pluginVersion
    ) throws Exception {
        return deriveContextKey(
                RESOURCE_KEY_LABEL,
                sessionKey,
                sessionId,
                securityEpoch,
                buildId,
                pluginName,
                pluginVersion);
    }

    public static byte[] deriveMethodKey(
            byte[] sessionKey,
            byte[] sessionId,
            int securityEpoch,
            byte[] buildId,
            String pluginName,
            String pluginVersion
    ) throws Exception {
        return deriveContextKey(
                METHOD_KEY_LABEL,
                sessionKey,
                sessionId,
                securityEpoch,
                buildId,
                pluginName,
                pluginVersion);
    }

    public static byte[] buildResourceAssociatedData(
            byte[] sessionId,
            int securityEpoch,
            byte[] buildId,
            String pluginName,
            String pluginVersion
    ) {
        byte[] context = buildResourceContext(
                sessionId, securityEpoch, buildId, pluginName, pluginVersion);
        try {
            ByteBuffer output = ByteBuffer.allocate(
                    Math.addExact(RESOURCE_AAD_LABEL.length, context.length));
            output.put(RESOURCE_AAD_LABEL);
            output.put(context);
            return output.array();
        } finally {
            Arrays.fill(context, (byte) 0);
        }
    }

    private static byte[] deriveContextKey(
            byte[] label,
            byte[] sessionKey,
            byte[] sessionId,
            int securityEpoch,
            byte[] buildId,
            String pluginName,
            String pluginVersion
    ) throws Exception {
        if (sessionKey == null || sessionKey.length != CONTEXT_ID_LENGTH) {
            throw new IllegalArgumentException("session key must contain 32 bytes");
        }
        byte[] context = buildResourceContext(
                sessionId, securityEpoch, buildId, pluginName, pluginVersion);
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(sessionKey, HMAC_ALGORITHM));
            mac.update(label);
            mac.update(context);
            return mac.doFinal();
        } finally {
            Arrays.fill(context, (byte) 0);
        }
    }

    private static byte[] buildResourceContext(
            byte[] sessionId,
            int securityEpoch,
            byte[] buildId,
            String pluginName,
            String pluginVersion
    ) {
        if (sessionId == null || sessionId.length != CONTEXT_ID_LENGTH
                || buildId == null || buildId.length != CONTEXT_ID_LENGTH
                || securityEpoch <= 0
                || pluginName == null || pluginName.isBlank()
                || pluginVersion == null || pluginVersion.isBlank()) {
            throw new IllegalArgumentException("invalid resource-key context");
        }
        byte[] pluginBytes = pluginName.getBytes(StandardCharsets.UTF_8);
        byte[] versionBytes = pluginVersion.getBytes(StandardCharsets.UTF_8);
        if (pluginBytes.length > MAX_CONTEXT_STRING_BYTES
                || versionBytes.length > MAX_CONTEXT_STRING_BYTES) {
            throw new IllegalArgumentException("resource-key context field is too long");
        }
        int length = Math.addExact(
                CONTEXT_ID_LENGTH + Integer.BYTES + CONTEXT_ID_LENGTH + Integer.BYTES * 2,
                Math.addExact(pluginBytes.length, versionBytes.length));
        ByteBuffer context = ByteBuffer.allocate(length);
        context.put(sessionId);
        context.putInt(securityEpoch);
        context.put(buildId);
        context.putInt(pluginBytes.length).put(pluginBytes);
        context.putInt(versionBytes.length).put(versionBytes);
        return context.array();
    }

    public byte[] getSessionKey() {
        return sessionKey == null ? null : sessionKey.clone();
    }

    public void destroy() {
        if (sharedSecret != null) {
            Arrays.fill(sharedSecret, (byte) 0);
            sharedSecret = null;
        }
        if (sessionKey != null) {
            Arrays.fill(sessionKey, (byte) 0);
            sessionKey = null;
        }
        serverKeyPair = null;
    }

    private static byte[] longToBytes(long value) {
        return new byte[]{
                (byte) (value >> 56),
                (byte) (value >> 48),
                (byte) (value >> 40),
                (byte) (value >> 32),
                (byte) (value >> 24),
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value
        };
    }
}
