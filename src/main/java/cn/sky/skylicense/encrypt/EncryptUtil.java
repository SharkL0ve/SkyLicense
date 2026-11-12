package cn.sky.skylicense.encrypt;

import cn.sky.skylicense.resource.MethodInfo;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

/** Protocol-v4 bytecode transformation and direct-key AEAD helpers. */
public final class EncryptUtil {
    static final byte[] RESOURCE_MAGIC = "SKYRES04".getBytes(StandardCharsets.US_ASCII);
    static final byte[] METHOD_LOOKUP_MAGIC = "SKYMTH04".getBytes(StandardCharsets.US_ASCII);
    static final byte[] METHOD_STRING_MAGIC = "SKYSTR04".getBytes(StandardCharsets.US_ASCII);
    static final byte[] METHOD_LOOKUP_AAD =
            "SkyLicense v4 method lookup\0".getBytes(StandardCharsets.US_ASCII);
    static final byte[] METHOD_STRING_AAD =
            "SkyLicense v4 method string\0".getBytes(StandardCharsets.US_ASCII);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int KEY_LENGTH = 32;
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / Byte.SIZE;

    private EncryptUtil() {
    }

    public static byte[] compress(byte[] bytes) throws IOException {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes must not be null");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(output)) {
            gzip.write(bytes);
        }
        return output.toByteArray();
    }

    public static byte[] intToByteArray(int value) {
        return new byte[]{
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value
        };
    }

    public static byte[] encryptClass(
            String pluginName,
            byte[] bytecode,
            Map<String, MethodInfo> methodMap,
            byte[] methodKey,
            String className,
            String interfaceName
    ) {
        ClassReader reader = new ClassReader(bytecode);
        ClassNode transformedClass = new ClassNode();
        ClassVisitor visitor = new EncryptClassVisitor(
                transformedClass,
                pluginName,
                methodKey,
                className,
                interfaceName,
                methodMap);
        reader.accept(visitor, ClassReader.EXPAND_FRAMES);
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        transformedClass.accept(writer);
        return writer.toByteArray();
    }

    public static byte[] encryptResource(
            byte[] plaintext,
            byte[] key,
            byte[] associatedData
    ) throws GeneralSecurityException {
        return encryptEnvelope(plaintext, key, associatedData, RESOURCE_MAGIC);
    }

    public static byte[] encryptMethodLookup(byte[] plaintext, byte[] key)
            throws GeneralSecurityException {
        return encryptEnvelope(plaintext, key, METHOD_LOOKUP_AAD, METHOD_LOOKUP_MAGIC);
    }

    public static byte[] encryptMethodString(byte[] plaintext, byte[] key)
            throws GeneralSecurityException {
        return encryptEnvelope(plaintext, key, METHOD_STRING_AAD, METHOD_STRING_MAGIC);
    }

    static byte[] encryptEnvelopeWithNonce(
            byte[] plaintext,
            byte[] key,
            byte[] associatedData,
            byte[] magic,
            byte[] nonce
    ) throws GeneralSecurityException {
        validateEnvelopeInputs(plaintext, key, associatedData, magic, nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
        cipher.updateAAD(associatedData);
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] envelope = new byte[magic.length + nonce.length + ciphertext.length];
        System.arraycopy(magic, 0, envelope, 0, magic.length);
        System.arraycopy(nonce, 0, envelope, magic.length, nonce.length);
        System.arraycopy(ciphertext, 0, envelope, magic.length + nonce.length, ciphertext.length);
        Arrays.fill(ciphertext, (byte) 0);
        return envelope;
    }

    static byte[] decryptEnvelope(
            byte[] envelope,
            byte[] key,
            byte[] associatedData,
            byte[] expectedMagic
    ) throws GeneralSecurityException {
        if (envelope == null
                || envelope.length < expectedMagic.length + NONCE_LENGTH + TAG_LENGTH_BYTES) {
            throw new GeneralSecurityException("encrypted envelope is truncated");
        }
        byte[] actualMagic = Arrays.copyOfRange(envelope, 0, expectedMagic.length);
        try {
            if (!MessageDigest.isEqual(actualMagic, expectedMagic)) {
                throw new GeneralSecurityException("encrypted envelope has an invalid magic");
            }
        } finally {
            Arrays.fill(actualMagic, (byte) 0);
        }
        byte[] nonce = Arrays.copyOfRange(
                envelope, expectedMagic.length, expectedMagic.length + NONCE_LENGTH);
        try {
            validateEnvelopeInputs(new byte[0], key, associatedData, expectedMagic, nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
            cipher.updateAAD(associatedData);
            return cipher.doFinal(envelope, expectedMagic.length + NONCE_LENGTH,
                    envelope.length - expectedMagic.length - NONCE_LENGTH);
        } finally {
            Arrays.fill(nonce, (byte) 0);
        }
    }

    private static byte[] encryptEnvelope(
            byte[] plaintext,
            byte[] key,
            byte[] associatedData,
            byte[] magic
    ) throws GeneralSecurityException {
        byte[] nonce = new byte[NONCE_LENGTH];
        SECURE_RANDOM.nextBytes(nonce);
        try {
            return encryptEnvelopeWithNonce(plaintext, key, associatedData, magic, nonce);
        } finally {
            Arrays.fill(nonce, (byte) 0);
        }
    }

    private static void validateEnvelopeInputs(
            byte[] plaintext,
            byte[] key,
            byte[] associatedData,
            byte[] magic,
            byte[] nonce
    ) {
        if (plaintext == null || associatedData == null || magic == null || nonce == null) {
            throw new IllegalArgumentException("AEAD inputs must not be null");
        }
        if (key == null || key.length != KEY_LENGTH) {
            throw new IllegalArgumentException("AEAD key must contain 32 bytes");
        }
        if (magic.length != 8) {
            throw new IllegalArgumentException("AEAD magic must contain 8 bytes");
        }
        if (nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("AEAD nonce must contain 12 bytes");
        }
    }
}
