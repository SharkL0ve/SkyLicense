package cn.sky.license;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.lang.invoke.MethodType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.GZIPInputStream;

/** Java 17+ protocol-v4 client. No native anti-debugging or hardware attestation. */
public final class BasicLicenseClient extends ClassLoader implements AutoCloseable {
    public static final String BUILD_ID = "7f10d350d700568181fc244d4f3b779c75ab57316ae8e0e573a1802b815c33f0";
    public static final int SECURITY_EPOCH = 1;
    private static final int MAX_RESOURCE = 128 * 1024 * 1024;
    private static final int MAX_CLASS = 16 * 1024 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Object SESSION_LOCK = new Object();
    private static BasicLicenseClient owner;

    // The server rewrites protected method calls to this exact public bridge.
    public static volatile Bridge authLib;
    public interface Bridge { Object authenticate(Object receiver, String token); }

    private final PluginProxy proxy;
    private final SSLContext tls;
    private final byte[] buildId = hex(BUILD_ID);
    private final Map<String, byte[]> definitions = new HashMap<>();
    private final Map<String, String[]> methods = new HashMap<>();
    private final ScheduledExecutorService heartbeat;
    private volatile boolean active;
    private volatile boolean attempted;
    private volatile long lastHeartbeat;
    private volatile int heartbeatCount;
    private volatile String lastError = "";
    private byte[] sessionKey;
    private byte[] methodKey;
    private byte[] sessionId;
    private String host;
    private int port;
    private String plugin;
    private String hwid;
    private long lastTimestamp;

    public BasicLicenseClient(PluginProxy proxy) {
        super(Objects.requireNonNull(proxy, "proxy").getClass().getClassLoader());
        this.proxy = proxy;
        try {
            this.tls = createTlsContext();
        } catch (Exception error) {
            throw new IllegalStateException("Unable to configure verified TLS", error);
        }
        heartbeat = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "skylicense-basic-heartbeat");
            thread.setDaemon(true);
            return thread;
        });
    }

    public boolean isSessionActive() {
        return active && System.nanoTime() - lastHeartbeat < TimeUnit.SECONDS.toNanos(85);
    }

    public int getHeartbeatCount() { return heartbeatCount; }
    public String getLastError() { return lastError; }

    public Response authenticate(String endpoint, String name, String version) {
        synchronized (SESSION_LOCK) {
            if (attempted) return Response.SESSION_ALREADY_INITIALIZED;
            if (owner != null) return Response.AUTHENTICATION_IN_PROGRESS;
            owner = this;
            attempted = true;
        }
        Response outcome = Response.UNKNOWN_ERROR;
        String stage = "configuration";
        try {
            URI address = new URI("tls://" + endpoint);
            host = address.getHost();
            port = address.getPort() == -1 ? 13331 : address.getPort();
            if (host == null || address.getUserInfo() != null || address.getQuery() != null
                    || address.getFragment() != null || !address.getPath().isEmpty()
                    || port < 1 || port > 65535 || !safeIdentity(name) || !safeIdentity(version)) {
                throw new IllegalArgumentException("invalid endpoint or program identity");
            }
            if (host.startsWith("[")) host = host.substring(1, host.length() - 1);
            plugin = name;
            String code;
            try (InputStream input = getParent().getResourceAsStream("license.dat")) {
                if (input == null) throw new FileNotFoundException("license.dat");
                byte[] encoded = readBounded(input, 1024 * 1024);
                try { code = LicenseFileCodec.decode(encoded, LicenseFileCodec.secretFromEnvironment()); }
                finally { clear(encoded); }
            }
            if (!code.matches("[A-Za-z0-9][A-Za-z0-9._+\\-]{0,255}")) {
                throw new IllegalArgumentException("invalid license file credential");
            }
            hwid = deploymentIdentity(proxy.getDataFolder().toPath());
            stage = "TLS connection";
            try (SSLSocket socket = connect()) {
                DataInputStream input = new DataInputStream(socket.getInputStream());
                DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                KeyPair pair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
                byte[] publicEncoding = pair.getPublic().getEncoded();
                byte[] nonce = random(32);
                output.writeInt(4);
                output.write(publicEncoding, publicEncoding.length - 32, 32);
                output.write(nonce);
                output.writeInt(SECURITY_EPOCH);
                output.write(buildId);
                writeUtf16(output, hwid);
                writeUtf16(output, name + "@" + version + "@" + code + "$$"
                        + BasicLicenseClient.class.getName().replace('.', '/') + "$$"
                        + Bridge.class.getName().replace('.', '/'));
                code = null;
                output.writeInt(0);
                output.write(new byte[16]);
                output.flush();
                stage = "authorization";
                String decision = readUtf16(input, 128);
                if (!"ACCEPT".equals(decision)) {
                    outcome = Response.translate(decision);
                    return outcome;
                }
                stage = "challenge";
                byte[] serverPublic = readBytes(input, 32);
                byte[] serverNonce = readBytes(input, 32);
                byte[] challenge = readBytes(input, 32);
                sessionId = readBytes(input, 32);
                byte[] prefix = hex("302a300506032b656e032100");
                KeyAgreement agreement = KeyAgreement.getInstance("X25519");
                agreement.init(pair.getPrivate());
                agreement.doPhase(KeyFactory.getInstance("X25519").generatePublic(
                        new X509EncodedKeySpec(concat(prefix, serverPublic))), true);
                byte[] shared = agreement.generateSecret();
                byte[] salt = digest(concat(ascii("SkyLicense-HKDF-Salt"), nonce, serverNonce));
                byte[] prk = hmac(salt, shared);
                sessionKey = hmac(prk, ascii("SkyLicense v4 session"), nonce, serverNonce, new byte[]{1});
                clear(shared); clear(salt); clear(prk);
                long timestamp = System.currentTimeMillis() / 1000;
                output.writeInt(0x534b4352);
                output.writeLong(timestamp);
                output.write(hmac(sessionKey, ascii("SkyLicense v4 challenge\0"), challenge, nonce,
                        sessionId, intBytes(SECURITY_EPOCH), buildId, longBytes(timestamp)));
                output.flush();
                clear(challenge); clear(nonce);
                byte[] context = context(name, version);
                byte[] transportKey = hmac(sessionKey, ascii("SkyLicense v4 resource key\0"), context);
                methodKey = hmac(sessionKey, ascii("SkyLicense v4 method key\0"), context);
                stage = "resource delivery";
                int length = bounded(input.readInt(), 36, MAX_RESOURCE);
                byte[] ciphertext = readBytes(input, length);
                byte[] plaintext;
                try { plaintext = decrypt(ciphertext, transportKey,
                        concat(ascii("SkyLicense v4 resource aad\0"), context), "SKYRES04"); }
                finally { clear(ciphertext); clear(transportKey); clear(context); }
                String[] entry;
                try { entry = installPayload(plaintext); }
                finally { clear(plaintext); }
                active = true;
                lastHeartbeat = System.nanoTime();
                authLib = this::dispatch;
                stage = "initial heartbeat";
                heartbeatOnce();
                heartbeat.scheduleWithFixedDelay(this::heartbeatTick, 20, 20, TimeUnit.SECONDS);
                stage = "entry";
                Method method = Class.forName(entry[0].replace('/', '.'), true, this).getMethod(entry[1]);
                if (!Modifier.isStatic(method.getModifiers())) throw new NoSuchMethodException("entry is not static");
                method.invoke(null);
                if (!isSessionActive()) throw new SecurityException("session expired during entry");
                stage = "delivery ACK";
                timestamp = System.currentTimeMillis() / 1000;
                output.writeInt(0x534b4441);
                output.writeLong(timestamp);
                output.write(sessionId);
                output.writeByte(1);
                output.write(hmac(sessionKey, ascii("SkyLicense v4 delivery ack\0"), sessionId,
                        longBytes(timestamp), new byte[]{1}));
                output.flush();
                if (input.readUnsignedByte() != 1) throw new IOException("ACK not confirmed");
                outcome = Response.ACCEPT;
                return outcome;
            }
        } catch (Exception | LinkageError error) {
            lastError = stage + ": " + error.getClass().getSimpleName();
            if ("entry".equals(stage)) return Response.ENTRY_POINT_EXCEPTION;
            if ("delivery ACK".equals(stage)) return Response.DELIVERY_ACK_ERROR;
            if ("TLS connection".equals(stage)) return Response.SOCKET_ERROR_CONNECT;
            return Response.RESOURCE_ERROR;
        } finally {
            if (outcome != Response.ACCEPT) close();
        }
    }

    private SSLSocket connect() throws Exception {
        SSLSocket socket = (SSLSocket) tls.getSocketFactory().createSocket();
        try {
            socket.setSoTimeout(30_000);
            socket.connect(new InetSocketAddress(host, port), 10_000);
            socket.setEnabledProtocols(new String[]{"TLSv1.3"});
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);
            socket.startHandshake();
            String pin = System.getenv("SKYLICENSE_BASIC_CERT_SHA256");
            if (pin != null && !MessageDigest.isEqual(hex(pin), digest(
                    socket.getSession().getPeerCertificates()[0].getEncoded()))) {
                throw new GeneralSecurityException("TLS certificate pin mismatch");
            }
            return socket;
        } catch (Exception error) {
            socket.close();
            throw error;
        }
    }

    private static SSLContext createTlsContext() throws Exception {
        String caFile = System.getenv("SKYLICENSE_BASIC_CA_CERT_FILE");
        if (caFile == null) return SSLContext.getDefault();
        Path path = Paths.get(caFile);
        if (!path.isAbsolute() || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                || Files.size(path) > 1024 * 1024) throw new IOException("invalid CA certificate file");
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, null);
        try (InputStream input = Files.newInputStream(path)) {
            int index = 0;
            for (java.security.cert.Certificate certificate : CertificateFactory.getInstance("X.509").generateCertificates(input)) {
                store.setCertificateEntry("ca-" + index++, certificate);
            }
            if (index == 0) throw new IOException("empty CA certificate file");
        }
        TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(store);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(null, managers.getTrustManagers(), null);
        return context;
    }

    private synchronized String[] installPayload(byte[] plaintext) throws Exception {
        DataInputStream input = new DataInputStream(new ByteArrayInputStream(plaintext));
        if (!Arrays.equals(readBytes(input, 8), ascii("SKYCLS04"))) throw new IOException("invalid resource format");
        int count = bounded(input.readInt(), 1, 20_000);
        long total = 0;
        for (int index = 0; index < count; index++) {
            String name = readUtf8(input, 1024).replace('/', '.');
            if (name.startsWith("java.") || name.startsWith("jdk.") || name.startsWith("sun.")
                    || name.startsWith("cn.sky.license.") || name.contains("..")) throw new IOException("reserved class namespace");
            int expanded = bounded(input.readInt(), 1, MAX_CLASS);
            total += expanded;
            if (total > MAX_RESOURCE) throw new IOException("resource expands beyond limit");
            byte[] compressed = readBytes(input, bounded(input.readInt(), 1, MAX_CLASS));
            byte[] bytes;
            try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
                bytes = readBounded(gzip, expanded);
            } finally { clear(compressed); }
            if (bytes.length != expanded || definitions.put(name, bytes) != null) throw new IOException("invalid or duplicate class");
        }
        String[] entry = {readUtf8(input, 1024), readUtf8(input, 1024)};
        count = bounded(input.readInt(), 0, 1_000_000);
        for (int index = 0; index < count; index++) {
            String key = readUtf8(input, 1024);
            String[] metadata = {readUtf8(input, 1024), readUtf8(input, 1024 * 1024), readUtf8(input, 16_384)};
            if (methods.put(key, metadata) != null) throw new IOException("duplicate method token");
        }
        if (input.read() != -1) throw new IOException("resource contains trailing data");
        return entry;
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        synchronized (getClassLoadingLock(name)) {
            Class<?> loaded = findLoadedClass(name);
            if (loaded == null) {
                boolean own;
                synchronized (this) { own = definitions.containsKey(name); }
                loaded = own ? findClass(name) : super.loadClass(name, false);
            }
            if (resolve) resolveClass(loaded);
            return loaded;
        }
    }

    @Override
    protected synchronized Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] bytes = definitions.remove(name);
        if (bytes == null || !isSessionActive()) throw new ClassNotFoundException(name);
        try { return defineClass(name, bytes, 0, bytes.length); }
        finally { clear(bytes); }
    }

    private Object dispatch(Object receiver, String token) {
        try {
            String[] metadata;
            char type;
            byte[] key;
            synchronized (this) {
                if (!isSessionActive()) throw new SecurityException("license session is inactive");
                String prefix = "@" + plugin + "@";
                if (token == null || !token.startsWith(prefix) || token.length() > 2 * 1024 * 1024) {
                    throw new SecurityException("invalid method token");
                }
                type = token.charAt(prefix.length());
                key = methodKey.clone();
                byte[] hash = decrypt(Base64.getDecoder().decode(token.substring(prefix.length() + 1)),
                        key, ascii("SkyLicense v4 method lookup\0"), "SKYMTH04");
                try { metadata = methods.get(new String(hash, StandardCharsets.UTF_8) + type); }
                finally { clear(hash); }
                if (metadata == null) { clear(key); throw new SecurityException("unknown method token"); }
            }
            try {
                if (type == 'l') {
                    byte[] text = decrypt(Base64.getDecoder().decode(metadata[1]), key,
                            ascii("SkyLicense v4 method string\0"), "SKYSTR04");
                    try { return new String(text, StandardCharsets.UTF_8); }
                    finally { clear(text); }
                }
            } finally { clear(key); }
            Class<?> declaring = Class.forName(metadata[0].replace('/', '.'), true, this);
            MethodType descriptor = MethodType.fromMethodDescriptorString(metadata[2], this);
            Method method = resolveMethod(declaring, metadata[1], descriptor);
            if (!method.trySetAccessible() && (!Modifier.isPublic(method.getModifiers())
                    || !Modifier.isPublic(declaring.getModifiers()))) throw new IllegalAccessException("inaccessible protected method");
            switch (type) {
                case 'I': case '0': return method.invoke(null);
                case 'i': case 'O': return method.invoke(null, receiver);
                case '1': case '|': return method.invoke(receiver);
                default: throw new SecurityException("unsupported method token type");
            }
        } catch (InvocationTargetException error) {
            return BasicLicenseClient.<RuntimeException, Object>rethrow(error.getCause());
        } catch (Throwable error) {
            return BasicLicenseClient.<RuntimeException, Object>rethrow(error);
        }
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable, T> T rethrow(Throwable error) throws E { throw (E) error; }

    static Method resolveMethod(Class<?> ownerClass, String name, MethodType descriptor) throws NoSuchMethodException {
        for (Method candidate : ownerClass.getDeclaredMethods()) {
            if (candidate.getName().equals(name) && candidate.getReturnType() == descriptor.returnType()
                    && Arrays.equals(candidate.getParameterTypes(), descriptor.parameterArray())) return candidate;
        }
        if (ownerClass.getSuperclass() != null) {
            try { return resolveMethod(ownerClass.getSuperclass(), name, descriptor); }
            catch (NoSuchMethodException ignored) { /* Search default interface methods next. */ }
        }
        for (Class<?> parentInterface : ownerClass.getInterfaces()) {
            try { return resolveMethod(parentInterface, name, descriptor); }
            catch (NoSuchMethodException ignored) { /* Search the next inherited interface. */ }
        }
        throw new NoSuchMethodException(name + descriptor);
    }

    private synchronized void heartbeatOnce() throws Exception {
        if (!active) throw new SecurityException("inactive session");
        long timestamp = Math.max(System.currentTimeMillis() / 1000, lastTimestamp + 1);
        byte[] evidence = digest(ascii("SkyLicense basic Java v4 lease"));
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream fields = new DataOutputStream(buffer);
        fields.writeByte(1); fields.write(sessionId); fields.writeLong(timestamp);
        fields.write(evidence); writeUtf16(fields, hwid);
        byte[] payload = buffer.toByteArray();
        try (SSLSocket socket = connect()) {
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());
            output.writeInt(0x534b4842); output.writeInt(payload.length); output.write(payload);
            output.write(hmac(sessionKey, payload)); output.flush();
            DataInputStream input = new DataInputStream(socket.getInputStream());
            int response = input.readUnsignedByte();
            byte[] signature = readBytes(input, 32);
            if (!MessageDigest.isEqual(signature, hmac(sessionKey, ascii("SkyLicense heartbeat response"),
                    sessionId, longBytes(timestamp), new byte[]{(byte) response}))) throw new SecurityException("invalid heartbeat signature");
            if (response != 2) throw new SecurityException("session revoked");
            lastTimestamp = timestamp;
            lastHeartbeat = System.nanoTime();
            heartbeatCount++;
        }
    }

    private void heartbeatTick() {
        try { heartbeatOnce(); }
        catch (Exception error) {
            lastError = "heartbeat: " + error.getClass().getSimpleName();
            if (error instanceof SecurityException || !isSessionActive()) {
                close();
                try { proxy.disablePlugin(); }
                catch (RuntimeException ignored) { /* Session is already revoked even if host callback fails. */ }
            }
        }
    }

    @Override
    public void close() {
        synchronized (this) {
            active = false;
            clear(sessionKey); clear(methodKey); clear(sessionId);
            for (byte[] bytes : definitions.values()) clear(bytes);
            definitions.clear(); methods.clear();
        }
        heartbeat.shutdownNow();
        synchronized (SESSION_LOCK) { if (owner == this) owner = null; }
    }

    private byte[] context(String name, String version) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(buffer);
        output.write(sessionId); output.writeInt(SECURITY_EPOCH); output.write(buildId);
        byte[] bytes = name.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length); output.write(bytes);
        bytes = version.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length); output.write(bytes);
        return buffer.toByteArray();
    }

    private static String deploymentIdentity(Path directory) throws Exception {
        Path root = directory.toAbsolutePath().normalize();
        BasicPrivateFiles.directory(root);
        Path identity = root.resolve("basic-installation.id");
        if (!Files.exists(identity, LinkOption.NOFOLLOW_LINKS)) {
            try { Files.write(identity, random(32), StandardOpenOption.CREATE_NEW); }
            catch (java.nio.file.FileAlreadyExistsException ignored) { /* Another client provisioned this installation. */ }
        }
        BasicPrivateFiles.file(identity);
        byte[] bytes = Files.readAllBytes(identity);
        if (bytes.length != 32) throw new IOException("invalid installation identity");
        try { return Base64.getEncoder().encodeToString(digest(concat(ascii("SkyLicense basic installation v1\0"), bytes))); }
        finally { clear(bytes); }
    }

    static byte[] decrypt(byte[] envelope, byte[] key, byte[] aad, String magic) throws GeneralSecurityException {
        if (envelope.length < 36 || !Arrays.equals(Arrays.copyOf(envelope, 8), ascii(magic))) {
            throw new GeneralSecurityException("invalid encrypted envelope");
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, envelope, 8, 12));
        cipher.updateAAD(aad);
        return cipher.doFinal(envelope, 20, envelope.length - 20);
    }

    static byte[] hmac(byte[] key, byte[]... values) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        for (byte[] value : values) mac.update(value);
        return mac.doFinal();
    }

    static byte[] readBounded(InputStream input, int limit) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) {
            if ((long) output.size() + read > limit) throw new IOException("input exceeds size limit");
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private static byte[] readBytes(DataInputStream input, int length) throws IOException {
        byte[] bytes = new byte[length]; input.readFully(bytes); return bytes;
    }
    private static String readUtf8(DataInputStream input, int max) throws IOException {
        return new String(readBytes(input, bounded(input.readInt(), 0, max)), StandardCharsets.UTF_8);
    }
    private static String readUtf16(DataInputStream input, int max) throws IOException {
        int length = bounded(input.readInt(), 1, max);
        StringBuilder text = new StringBuilder(length);
        for (int i = 0; i < length; i++) text.append(input.readChar());
        return text.toString();
    }
    private static void writeUtf16(DataOutputStream output, String value) throws IOException {
        output.writeInt(value.length()); output.writeChars(value);
    }
    private static int bounded(int value, int min, int max) throws IOException {
        if (value < min || value > max) throw new IOException("length out of range");
        return value;
    }
    private static byte[] random(int count) { byte[] bytes = new byte[count]; RANDOM.nextBytes(bytes); return bytes; }
    private static byte[] digest(byte[] bytes) throws NoSuchAlgorithmException { return MessageDigest.getInstance("SHA-256").digest(bytes); }
    private static byte[] ascii(String value) { return value.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] intBytes(int value) { return ByteBuffer.allocate(4).putInt(value).array(); }
    private static byte[] longBytes(long value) { return ByteBuffer.allocate(8).putLong(value).array(); }
    private static byte[] concat(byte[]... values) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (byte[] value : values) output.write(value, 0, value.length);
        return output.toByteArray();
    }
    private static void clear(byte[] bytes) { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
    private static boolean safeIdentity(String value) { return value != null && value.matches("[A-Za-z0-9][A-Za-z0-9._+\\-]{0,63}"); }
    private static byte[] hex(String text) {
        if (!text.matches("[0-9a-fA-F]{64}|302a300506032b656e032100")) throw new IllegalArgumentException("invalid hex value");
        byte[] bytes = new byte[text.length() / 2];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        return bytes;
    }

    public static void main(String[] args) {
        System.out.println("basic_build_id=" + BUILD_ID);
        System.out.println("basic_security_epoch=" + SECURITY_EPOCH);
        System.out.println("requires_java=17+");
    }
}
