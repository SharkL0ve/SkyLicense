package cn.sky.skylicense.netty;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.encrypt.ChallengeUtil;
import cn.sky.skylicense.encrypt.EncryptUtil;
import cn.sky.skylicense.resource.ResourceManager;
import cn.sky.skylicense.security.NativeIdentifierValidator;
import cn.sky.skylicense.security.StartupSecurity;
import cn.sky.skylicense.web.service.NativeLicenseService;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.util.ReferenceCountUtil;

import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/** Handles the TLS-protected protocol-v4 authentication and lease channel. */
public final class SocketHandler extends ChannelInboundHandlerAdapter {
    static final String READ_TIMEOUT_HANDLER_NAME = "authenticationReadTimeout";
    static final int INITIAL_READ_TIMEOUT_SECONDS = 15;
    private static final int RESOURCE_PREPARATION_TIMEOUT_SECONDS = 60;
    private static final int HEARTBEAT_PING = 0x01;
    private static final int HEARTBEAT_PONG = 0x02;
    private static final int HEARTBEAT_REVOKE = 0xFF;
    private static final int DELIVERY_ACK_SUCCESS = 0x01;
    private static final int DELIVERY_ACK_CONFIRMED = 0x01;
    private static final int DELIVERY_ACK_TIMEOUT_SECONDS = 30;
    private static final long DELIVERY_ACK_CLOCK_SKEW_SECONDS = 30;
    private static final int KEY_LENGTH = 32;
    private static final int RESERVED_HELLO_BYTES = 16;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int RESOURCE_WORKERS = Math.max(
            2, Math.min(8, Runtime.getRuntime().availableProcessors()));
    private static final AtomicInteger RESOURCE_WORKER_SEQUENCE = new AtomicInteger();
    private static final Object RESOURCE_EXECUTOR_LOCK = new Object();
    private static volatile ThreadPoolExecutor resourceExecutor = createResourceExecutor();
    private static final AuthenticationRateLimiter AUTH_RATE_LIMITER =
            new AuthenticationRateLimiter(
                    50_000,
                    5,
                    1.0 / 30.0,
                    Duration.ofMinutes(10));
    private static final AuthenticationRateLimiter HEARTBEAT_RATE_LIMITER =
            new AuthenticationRateLimiter(
                    50_000,
                    200,
                    50.0,
                    Duration.ofMinutes(10));

    private static final String WRONG_INFO = "WRONG_INFO";
    private static final String PLUGIN_NOT = "PLUGIN_NOT";
    private static final String ACCEPT = "ACCEPT";
    private static final String BUSY = "BUSY";
    private static final String WRONG_KEY = "WRONG_KEY";
    private static final String PROGRAM_NOT_MATCH = "PROGRAM_NOT_MATCH";
    private static final String NOT_ADDRESS = "NOT_ADRESS";
    private static final String BLACKLIST = "BLACKLIST";
    private static final String DAILY_AUTH_LIMIT = "DAILY_AUTH_LIMIT";

    private PendingAuth pendingAuth;
    private final AtomicReference<PendingDelivery> pendingDelivery = new AtomicReference<>();

    public static void clearAll() {
        AUTH_RATE_LIMITER.clear();
        HEARTBEAT_RATE_LIMITER.clear();
    }

    public static NativeRateLimitStats rateLimitStats() {
        AuthenticationRateLimiter.Snapshot authentication = AUTH_RATE_LIMITER.snapshot();
        AuthenticationRateLimiter.Snapshot heartbeat = HEARTBEAT_RATE_LIMITER.snapshot();
        return new NativeRateLimitStats(
                authentication.trackedAddresses(),
                authentication.throttledRejections(),
                authentication.capacityRejections(),
                heartbeat.trackedAddresses(),
                heartbeat.throttledRejections(),
                heartbeat.capacityRejections());
    }

    public record NativeRateLimitStats(
            int authTrackedAddresses,
            long authThrottledRejections,
            long authCapacityRejections,
            int heartbeatTrackedAddresses,
            long heartbeatThrottledRejections,
            long heartbeatCapacityRejections
    ) {
    }

    /** Ensures resource workers are available for a fresh server lifecycle. */
    public static void startResourceExecutor() {
        synchronized (RESOURCE_EXECUTOR_LOCK) {
            if (resourceExecutor == null || resourceExecutor.isShutdown()) {
                resourceExecutor = createResourceExecutor();
            }
        }
    }

    /** Stops resource workers and clears queued challenge material before database shutdown. */
    public static void shutdownResourceExecutor() {
        ThreadPoolExecutor executor;
        synchronized (RESOURCE_EXECUTOR_LOCK) {
            executor = resourceExecutor;
            resourceExecutor = null;
        }
        if (executor == null) {
            return;
        }
        List<Runnable> abandoned = executor.shutdownNow();
        for (Runnable task : abandoned) {
            if (task instanceof ResourceDeliveryTask deliveryTask) {
                deliveryTask.cancelBeforeStart();
            }
        }
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                SkyLicense.LOG.warn("Resource worker executor did not terminate within shutdown deadline");
            }
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            SkyLicense.LOG.warn("Interrupted while stopping resource workers");
        }
    }

    private static ThreadPoolExecutor createResourceExecutor() {
        return new ThreadPoolExecutor(
                RESOURCE_WORKERS,
                RESOURCE_WORKERS,
                30,
                TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(64),
                runnable -> {
                    Thread thread = new Thread(
                            runnable,
                            "skylicense-resource-" + RESOURCE_WORKER_SEQUENCE.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }

    @Override
    public void channelRead(ChannelHandlerContext context, Object message) {
        if (!(message instanceof ByteBuf input)) {
            ReferenceCountUtil.release(message);
            context.close();
            return;
        }
        InetSocketAddress remoteAddress = (InetSocketAddress) context.channel().remoteAddress();
        String clientIp = NativeIdentifierValidator.canonicalPeerAddress(remoteAddress.getAddress());
        boolean debug = SkyLicense.configuration().getStorage().isDebug();

        if (pendingAuth != null) {
            handleChallengeResponse(context, input, clientIp, debug);
            return;
        }
        PendingDelivery delivery = pendingDelivery.get();
        if (delivery != null) {
            handleDeliveryAcknowledgement(context, input, clientIp, debug, delivery);
            return;
        }
        if (input.readableBytes() >= Integer.BYTES
                && input.getInt(input.readerIndex()) == SecurityFrameDecoder.HEARTBEAT_MAGIC) {
            if (!HEARTBEAT_RATE_LIMITER.tryAcquire(clientIp)) {
                input.release();
                context.close();
                return;
            }
            handleHeartbeat(context, input, clientIp, debug);
            return;
        }
        if (!AUTH_RATE_LIMITER.tryAcquire(clientIp)) {
            input.release();
            writeStringAndClose(context, BUSY);
            return;
        }
        handleAuthenticationHello(context, input, clientIp, debug);
    }

    private void handleAuthenticationHello(
            ChannelHandlerContext context,
            ByteBuf input,
            String clientIp,
            boolean debug
    ) {
        ClientHello hello = null;
        try {
            hello = parseClientHello(input);
            String pluginIdentifier = ResourceManager.identifier(
                    hello.pluginName, hello.pluginVersion);
            if (!ResourceManager.containsPlugin(pluginIdentifier)) {
                SkyLicense.LOG.warn("Authentication requested an unknown plugin resource");
                writeStringAndClose(context, PLUGIN_NOT);
                return;
            }

            NativeLicenseService.Decision decision = SkyLicense.instance
                    .getNativeLicenseService()
                    .preAuthorize(
                            hello.userName,
                            clientIp,
                            hello.hwid,
                            hello.pluginName);
            String rejection = rejectionFor(decision);
            if (rejection != null) {
                writeStringAndClose(context, rejection);
                return;
            }

            PendingAuth pending = createPendingAuth(hello, pluginIdentifier);
            pendingAuth = pending;
            writeString(context, ACCEPT);
            context.writeAndFlush(pending.serverHandshakeFrame());
            if (debug) {
                SkyLicense.LOG.info("[DEBUG] Protocol-v4 challenge issued");
            }
        } catch (Exception error) {
            if (debug) {
                SkyLicense.LOG.warn("[DEBUG] Authentication hello rejected: " + error.getMessage());
            }
            if (pendingAuth != null) {
                pendingAuth.destroy();
                pendingAuth = null;
            }
            writeStringAndClose(context, WRONG_KEY);
        } finally {
            input.release();
            if (hello != null) {
                hello.destroy();
            }
        }
    }

    private static ClientHello parseClientHello(ByteBuf input) {
        byte[] clientPublicKey = null;
        byte[] clientNonce = null;
        byte[] buildId = null;
        byte[] reserved = null;
        boolean retainedByResult = false;
        try {
            int protocolVersion = input.readInt();
            if (protocolVersion != SecurityFrameDecoder.PROTOCOL_V4) {
                throw new IllegalArgumentException("unsupported authentication protocol");
            }

            clientPublicKey = new byte[KEY_LENGTH];
            input.readBytes(clientPublicKey);
            if (allZero(clientPublicKey)) {
                throw new IllegalArgumentException("client X25519 public key is invalid");
            }
            clientNonce = new byte[KEY_LENGTH];
            input.readBytes(clientNonce);
            int securityEpoch = input.readInt();
            buildId = new byte[KEY_LENGTH];
            input.readBytes(buildId);
            if (!StartupSecurity.isClientBuildAllowed(
                    SkyLicense.configuration().getStorage(), securityEpoch, buildId)) {
                throw new SecurityException("client build is not allowlisted");
            }

            String hwid = readUtf16String(input);
            String pluginData = readUtf16String(input);
            if (!isValidHwid(hwid)) {
                throw new IllegalArgumentException("HWID format is invalid");
            }
            int reservedPort = input.readInt();
            reserved = new byte[RESERVED_HELLO_BYTES];
            input.readBytes(reserved);
            if (reservedPort != 0 || !allZero(reserved) || input.isReadable()) {
                throw new IllegalArgumentException("reserved hello fields must be zero");
            }

            String[] fields = pluginData.split("@", -1);
            if (fields.length != 3
                    || fields[0].isBlank()
                    || fields[1].isBlank()
                    || fields[2].isBlank()) {
                throw new IllegalArgumentException("plugin authentication data is malformed");
            }
            String[] relocation = fields[2].split("\\$\\$", -1);
            if (relocation.length != 3
                    || relocation[0].isBlank()
                    || relocation[1].isBlank()
                    || relocation[2].isBlank()) {
                throw new IllegalArgumentException("plugin relocation data is malformed");
            }
            if (!isValidResourceIdentity(fields[0])
                    || !isValidResourceIdentity(fields[1])
                    || !isValidLicenseCode(relocation[0])
                    || !isValidInternalClassName(relocation[1])
                    || !isValidInternalClassName(relocation[2])) {
                throw new IllegalArgumentException("plugin identity or relocation is invalid");
            }
            ClientHello hello = new ClientHello(
                    clientPublicKey,
                    clientNonce,
                    securityEpoch,
                    buildId,
                    hwid,
                    fields[0],
                    fields[1],
                    relocation[0],
                    relocation[1],
                    relocation[2]);
            retainedByResult = true;
            return hello;
        } finally {
            clear(reserved);
            if (!retainedByResult) {
                clear(clientPublicKey);
                clear(clientNonce);
                clear(buildId);
            }
        }
    }

    private static PendingAuth createPendingAuth(ClientHello hello, String pluginIdentifier)
            throws Exception {
        ChallengeUtil challengeUtil = new ChallengeUtil();
        byte[] sessionKey = null;
        byte[] clientPublicKeyEncoding = null;
        byte[] serverPublicKeyEncoding = null;
        byte[] serverPublicKey = null;
        byte[] serverNonce = null;
        byte[] challenge = null;
        byte[] sessionId = null;
        try {
            serverPublicKeyEncoding = challengeUtil.generateServerKeyPair();
            serverPublicKey = Arrays.copyOfRange(
                    serverPublicKeyEncoding,
                    serverPublicKeyEncoding.length - KEY_LENGTH,
                    serverPublicKeyEncoding.length);
            serverNonce = ChallengeUtil.generateNonce();
            challenge = ChallengeUtil.generateChallenge();
            sessionId = new byte[KEY_LENGTH];
            SECURE_RANDOM.nextBytes(sessionId);

            byte[] x509Prefix = new byte[]{
                    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
                    0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
            };
            clientPublicKeyEncoding = new byte[x509Prefix.length + KEY_LENGTH];
            System.arraycopy(x509Prefix, 0, clientPublicKeyEncoding, 0, x509Prefix.length);
            System.arraycopy(
                    hello.clientPublicKey,
                    0,
                    clientPublicKeyEncoding,
                    x509Prefix.length,
                    KEY_LENGTH);
            challengeUtil.deriveSharedSecret(clientPublicKeyEncoding);
            sessionKey = challengeUtil.deriveSessionKey(hello.clientNonce, serverNonce);

            PendingAuth pending = new PendingAuth(
                    challengeUtil,
                    challenge,
                    hello.clientNonce,
                    sessionId,
                    sessionKey,
                    hello.userName,
                    hello.pluginName,
                    hello.pluginVersion,
                    pluginIdentifier,
                    hello.className,
                    hello.interfaceName,
                    hello.hwid,
                    hello.securityEpoch,
                    hello.buildId,
                    serverPublicKey,
                    serverNonce);
            return pending;
        } catch (Exception error) {
            challengeUtil.destroy();
            throw error;
        } finally {
            if (sessionKey != null) {
                Arrays.fill(sessionKey, (byte) 0);
            }
            if (clientPublicKeyEncoding != null) {
                Arrays.fill(clientPublicKeyEncoding, (byte) 0);
            }
            if (serverPublicKeyEncoding != null) {
                Arrays.fill(serverPublicKeyEncoding, (byte) 0);
            }
            clear(serverPublicKey);
            clear(serverNonce);
            clear(challenge);
            clear(sessionId);
        }
    }

    private void handleChallengeResponse(
            ChannelHandlerContext context,
            ByteBuf input,
            String clientIp,
            boolean debug
    ) {
        PendingAuth pending = pendingAuth;
        pendingAuth = null;
        byte[] response = null;
        boolean ownershipTransferred = false;
        try {
            if (input.readInt() != SecurityFrameDecoder.CHALLENGE_RESPONSE_MAGIC) {
                throw new IllegalArgumentException("invalid challenge response magic");
            }
            long timestamp = input.readLong();
            response = new byte[KEY_LENGTH];
            input.readBytes(response);
            if (input.isReadable()) {
                throw new IllegalArgumentException("challenge response contains trailing data");
            }
            long now = System.currentTimeMillis() / 1000L;
            if (timestamp < now - 30
                    || timestamp > now + 30
                    || !pending.challengeUtil.verifyChallengeResponse(
                    response,
                    pending.challenge,
                    pending.clientNonce,
                    pending.sessionId,
                    pending.securityEpoch,
                    pending.buildId,
                    timestamp)) {
                throw new SecurityException("challenge response verification failed");
            }

            pending.clearChallengeMaterial();
            context.pipeline().replace(
                    READ_TIMEOUT_HANDLER_NAME,
                    READ_TIMEOUT_HANDLER_NAME,
                    new ReadTimeoutHandler(RESOURCE_PREPARATION_TIMEOUT_SECONDS));
            ThreadPoolExecutor executor = resourceExecutor;
            if (executor == null) {
                throw new RejectedExecutionException("resource workers are stopping");
            }
            executor.execute(new ResourceDeliveryTask(context, pending, clientIp, debug));
            ownershipTransferred = true;
        } catch (RejectedExecutionException error) {
            SkyLicense.LOG.warn("Resource worker queue is full; rejecting " + clientIp);
            context.close();
        } catch (Exception error) {
            SkyLicense.LOG.warn("Challenge verification failed for " + clientIp + ": "
                    + error.getMessage());
            context.close();
        } finally {
            input.release();
            clear(response);
            if (!ownershipTransferred) {
                pending.destroy();
            }
        }
    }

    private void deliverResource(
            ChannelHandlerContext context,
            PendingAuth pending,
            String clientIp,
            boolean debug
    ) {
        byte[] transportKey = null;
        byte[] methodKey = null;
        byte[] associatedData = null;
        byte[] resource = null;
        byte[] encryptedResource = null;
        String resourceContentSha256 = null;
        boolean sessionRegistered = false;
        boolean authorizationCommitted = false;
        long authorizationLogId = 0;
        PendingDelivery delivery = null;
        try {
            if (!context.channel().isActive()) {
                return;
            }
            if (!StartupSecurity.isClientBuildAllowed(
                    SkyLicense.configuration().getStorage(),
                    pending.securityEpoch,
                    pending.buildId)) {
                throw new SecurityException("client build policy changed during challenge");
            }
            transportKey = ChallengeUtil.deriveResourceTransportKey(
                    pending.sessionKey,
                    pending.sessionId,
                    pending.securityEpoch,
                    pending.buildId,
                    pending.pluginName,
                    pending.pluginVersion);
            methodKey = ChallengeUtil.deriveMethodKey(
                    pending.sessionKey,
                    pending.sessionId,
                    pending.securityEpoch,
                    pending.buildId,
                    pending.pluginName,
                    pending.pluginVersion);
            associatedData = ChallengeUtil.buildResourceAssociatedData(
                    pending.sessionId,
                    pending.securityEpoch,
                    pending.buildId,
                    pending.pluginName,
                    pending.pluginVersion);
            ResourceManager.GeneratedResource generatedResource =
                    ResourceManager.getPluginClassesWithIdentity(
                    pending.pluginIdentifier,
                    pending.className,
                    pending.interfaceName,
                    methodKey);
            if (generatedResource == null) {
                throw new IllegalStateException("plugin resource could not be generated");
            }
            resource = generatedResource.payload();
            resourceContentSha256 = generatedResource.contentSha256();
            if (resource == null || resource.length == 0) {
                throw new IllegalStateException("plugin resource could not be generated");
            }
            encryptedResource = EncryptUtil.encryptResource(
                    resource, transportKey, associatedData);
            if (!context.channel().isActive()) {
                return;
            }

            NativeLicenseService.Decision authorization = SkyLicense.instance
                    .getNativeLicenseService()
                    .completeAuthorization(
                            pending.userName,
                            clientIp,
                            pending.hwid,
                            pending.pluginName);
            if (!authorization.allowed()) {
                throw new SecurityException(
                        "authorization changed during challenge: " + authorization.result());
            }
            authorizationCommitted = true;
            authorizationLogId = authorization.authLogId();

            if (!StartupSecurity.isClientBuildAllowed(
                    SkyLicense.configuration().getStorage(),
                    pending.securityEpoch,
                    pending.buildId)) {
                throw new SecurityException("client build policy changed before session registration");
            }

            if (!SessionManager.registerSessionWithCurrentPolicy(
                    pending.sessionId,
                    clientIp,
                    pending.userName,
                    pending.pluginName,
                    pending.pluginVersion,
                    resourceContentSha256,
                    authorizationLogId,
                    pending.sessionKey,
                    pending.hwid,
                    pending.securityEpoch,
                    pending.buildId)) {
                throw new IllegalStateException("session capacity reached");
            }
            sessionRegistered = true;

            long committedAuthorizationLogId = authorizationLogId;
            delivery = new PendingDelivery(
                    pending.sessionId,
                    () -> SkyLicense.instance.getNativeLicenseService()
                            .recordDeliverySuccess(committedAuthorizationLogId),
                    rollbackSessionId -> {
                        try {
                            SessionManager.destroySession(rollbackSessionId);
                            recordDeliveryFailure(committedAuthorizationLogId);
                        } finally {
                            clear(rollbackSessionId);
                        }
                    });
            if (!pendingDelivery.compareAndSet(null, delivery)) {
                throw new IllegalStateException("delivery acknowledgement is already pending");
            }
            sessionRegistered = false;
            authorizationCommitted = false;

            PendingDelivery installedDelivery = delivery;
            context.pipeline().replace(
                    READ_TIMEOUT_HANDLER_NAME,
                    READ_TIMEOUT_HANDLER_NAME,
                    new ReadTimeoutHandler(DELIVERY_ACK_TIMEOUT_SECONDS));
            ScheduledFuture<?> timeout = context.executor().schedule(() -> {
                failPendingDelivery(installedDelivery, "delivery acknowledgement timed out");
                context.close();
            }, DELIVERY_ACK_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            installedDelivery.setTimeout(timeout);
            if (!context.channel().isActive() || !installedDelivery.isWaiting()) {
                failPendingDelivery(installedDelivery, "authentication channel closed before delivery");
                context.close();
                return;
            }

            synchronized (ResourceManager.class) {
                synchronized (SessionManager.class) {
                    SessionManager.SessionInfo registered =
                            SessionManager.getSession(pending.sessionId);
                    if (!context.channel().isActive()
                            || !installedDelivery.isWaiting()
                            || registered == null
                            || !registered.isActive()
                            || !StartupSecurity.isClientBuildAllowed(
                            SkyLicense.configuration().getStorage(),
                            pending.securityEpoch,
                            pending.buildId)
                            || !ResourceManager.contentMatches(
                            pending.pluginIdentifier,
                            resourceContentSha256)) {
                        throw new SecurityException(
                                "resource or client policy changed before ciphertext release");
                    }

                    // The client controls whether an ACK is sent. Commit binding
                    // and quota before releasing ciphertext so omitting ACK cannot
                    // refund an authorization after the resource was obtained.
                    SkyLicense.instance.getNativeLicenseService()
                            .commitResourceRelease(committedAuthorizationLogId);

                    ByteBuf output = context.alloc().buffer(
                            encryptedResource.length + Integer.BYTES);
                    output.writeInt(encryptedResource.length);
                    output.writeBytes(encryptedResource);
                    context.writeAndFlush(output).addListener(future -> {
                        if (!future.isSuccess()) {
                            failPendingDelivery(
                                    installedDelivery, "protected resource write failed");
                            context.close();
                        }
                    });
                }
            }
            if (debug) {
                SkyLicense.LOG.info(
                        "[DEBUG] Challenge verified; waiting for delivery acknowledgement");
            }
        } catch (Exception error) {
            if (delivery != null) {
                failPendingDelivery(delivery, "resource delivery setup failed");
            } else if (sessionRegistered) {
                SessionManager.destroySession(pending.sessionId);
            }
            if (delivery == null && authorizationCommitted) {
                recordDeliveryFailure(authorizationLogId);
            }
            SkyLicense.LOG.warn("Resource delivery failed: " + error.getMessage());
            context.close();
        } finally {
            clear(transportKey);
            clear(methodKey);
            clear(associatedData);
            clear(resource);
            clear(encryptedResource);
            pending.destroy();
        }
    }

    private void handleDeliveryAcknowledgement(
            ChannelHandlerContext context,
            ByteBuf input,
            String clientIp,
            boolean debug,
            PendingDelivery delivery
    ) {
        byte[] sessionId = null;
        byte[] signature = null;
        byte[] sessionKey = null;
        try {
            if (input.readInt() != SecurityFrameDecoder.DELIVERY_ACK_MAGIC) {
                throw new IllegalArgumentException("invalid delivery acknowledgement magic");
            }
            long timestamp = input.readLong();
            sessionId = new byte[KEY_LENGTH];
            input.readBytes(sessionId);
            int status = input.readUnsignedByte();
            signature = new byte[KEY_LENGTH];
            input.readBytes(signature);
            if (input.isReadable()) {
                throw new IllegalArgumentException(
                        "delivery acknowledgement contains trailing data");
            }

            long now = System.currentTimeMillis() / 1000L;
            if (timestamp < now - DELIVERY_ACK_CLOCK_SKEW_SECONDS
                    || timestamp > now + DELIVERY_ACK_CLOCK_SKEW_SECONDS
                    || status != DELIVERY_ACK_SUCCESS
                    || !delivery.matchesSessionId(sessionId)
                    || !delivery.beginConfirmation()) {
                throw new SecurityException("delivery acknowledgement context is invalid");
            }

            SessionManager.SessionInfo session = SessionManager.getSession(sessionId);
            if (session == null || !session.isActive()) {
                throw new SecurityException("delivery acknowledgement session is unavailable");
            }
            sessionKey = session.getSessionKey();
            if (!ChallengeUtil.verifyDeliveryAcknowledgement(
                    sessionKey, sessionId, timestamp, status, signature)) {
                throw new SecurityException("delivery acknowledgement HMAC mismatch");
            }

            // Persist success before telling the client that ACCEPT is final.
            if (!delivery.commitSuccess()) {
                throw new SecurityException("delivery acknowledgement was already finalized");
            }

            ByteBuf confirmation = context.alloc().buffer(1);
            confirmation.writeByte(DELIVERY_ACK_CONFIRMED);
            context.writeAndFlush(confirmation).addListener(future -> {
                try {
                    if (future.isSuccess() && delivery.complete()) {
                        if (debug) {
                            SkyLicense.LOG.info(
                                    "[DEBUG] Client confirmed protected resource initialization");
                        }
                    } else {
                        delivery.fail();
                    }
                } finally {
                    pendingDelivery.compareAndSet(delivery, null);
                    context.close();
                }
            });
        } catch (Exception error) {
            if (debug) {
                SkyLicense.LOG.warn("Invalid delivery acknowledgement: " + error.getMessage());
            }
            failPendingDelivery(delivery, "delivery acknowledgement was rejected");
            context.close();
        } finally {
            clear(sessionId);
            clear(signature);
            clear(sessionKey);
            input.release();
        }
    }

    private void handleHeartbeat(
            ChannelHandlerContext context,
            ByteBuf input,
            String clientIp,
            boolean debug
    ) {
        byte[] sessionKey = null;
        byte[] payload = null;
        byte[] signature = null;
        byte[] sessionId = null;
        byte[] environmentEvidence = null;
        ByteBuf fields = null;
        try {
            input.readInt();
            int payloadLength = input.readInt();
            if (payloadLength <= 0
                    || payloadLength > 8192
                    || input.readableBytes() != payloadLength + KEY_LENGTH) {
                throw new IllegalArgumentException("invalid heartbeat frame length");
            }
            payload = new byte[payloadLength];
            signature = new byte[KEY_LENGTH];
            input.readBytes(payload);
            input.readBytes(signature);

            fields = Unpooled.wrappedBuffer(payload);
            int type = fields.readUnsignedByte();
            sessionId = new byte[KEY_LENGTH];
            fields.readBytes(sessionId);
            long timestamp = fields.readLong();
            environmentEvidence = new byte[KEY_LENGTH];
            fields.readBytes(environmentEvidence);
            int hwidLength = fields.readInt();
            if (type != HEARTBEAT_PING
                    || hwidLength < 1
                    || hwidLength > 4096
                    || fields.readableBytes() != hwidLength * 2) {
                throw new IllegalArgumentException("invalid heartbeat payload");
            }
            char[] hwidCharacters = new char[hwidLength];
            for (int index = 0; index < hwidLength; index++) {
                hwidCharacters[index] = fields.readChar();
            }
            String hwid = new String(hwidCharacters);
            Arrays.fill(hwidCharacters, '\0');

            SessionManager.SessionInfo session = SessionManager.getSession(sessionId);
            if (session == null) {
                context.close();
                return;
            }
            sessionKey = session.getSessionKey();
            if (!ChallengeUtil.verifyHeartbeat(sessionKey, payload, signature)) {
                throw new SecurityException("heartbeat HMAC mismatch");
            }
            if (!session.getClientIp().equals(clientIp)
                    || !StartupSecurity.isClientBuildAllowed(
                    SkyLicense.configuration().getStorage(),
                    session.getSecurityEpoch(),
                    session.getBuildId())
                    || !ResourceManager.contentMatches(
                    session.getPluginIdentifier(),
                    session.getResourceContentSha256())
                    || !SkyLicense.instance.getNativeLicenseService().isSessionAuthorized(
                    session.getUserName(),
                    clientIp,
                    hwid,
                    session.getPluginName(),
                    session.getAuthLogId())
                    || !session.acceptHeartbeat(timestamp, hwid, environmentEvidence)) {
                session.revoke();
                try {
                    sendHeartbeatResponse(
                            context, HEARTBEAT_REVOKE, sessionKey, sessionId, timestamp);
                } finally {
                    SessionManager.destroySession(sessionId);
                }
                return;
            }

            sendHeartbeatResponse(context, HEARTBEAT_PONG, sessionKey, sessionId, timestamp);
            if (debug) {
                SkyLicense.LOG.info("[DEBUG] Authenticated heartbeat accepted");
            }
        } catch (Exception error) {
            if (debug) {
                SkyLicense.LOG.warn("Invalid heartbeat: " + error.getMessage());
            }
            context.close();
        } finally {
            if (fields != null) {
                fields.release();
            }
            clear(sessionKey);
            clear(payload);
            clear(signature);
            clear(sessionId);
            clear(environmentEvidence);
            input.release();
        }
    }

    private static void sendHeartbeatResponse(
            ChannelHandlerContext context,
            int response,
            byte[] sessionKey,
            byte[] sessionId,
            long clientTimestamp
    ) throws Exception {
        byte[] signature = ChallengeUtil.signHeartbeatResponse(
                sessionKey, sessionId, clientTimestamp, response);
        ByteBuf output = context.alloc().buffer(1 + signature.length);
        output.writeByte(response);
        output.writeBytes(signature);
        clear(signature);
        context.writeAndFlush(output).addListener(ChannelFutureListener.CLOSE);
    }

    @Override
    public void channelInactive(ChannelHandlerContext context) throws Exception {
        if (pendingAuth != null) {
            pendingAuth.destroy();
            pendingAuth = null;
        }
        PendingDelivery delivery = pendingDelivery.getAndSet(null);
        if (delivery != null) {
            delivery.fail();
        }
        super.channelInactive(context);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
        PendingDelivery delivery = pendingDelivery.getAndSet(null);
        if (delivery != null) {
            delivery.fail();
        }
        context.close();
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext context) {
        context.flush();
    }

    private static String rejectionFor(NativeLicenseService.Decision decision) {
        if (decision == null || decision.allowed()) {
            return null;
        }
        if (decision.result() == null) {
            return WRONG_INFO;
        }
        return switch (decision.result()) {
            case "DAILY_AUTH_LIMIT" -> DAILY_AUTH_LIMIT;
            case "PROGRAM_MISMATCH" -> PROGRAM_NOT_MATCH;
            case "IP_LIMIT", "HWID_LIMIT", "BINDING_REVOKED" -> NOT_ADDRESS;
            case "BANNED", "BANNED_BY_IP", "BANNED_BY_QQ", "BANNED_BY_HWID",
                    "BANNED_BY_CODE", "EXPIRED", "PROGRAM_DISABLED", "USER_DISABLED" -> BLACKLIST;
            default -> WRONG_INFO;
        };
    }

    private static void recordDeliveryFailure(long authLogId) {
        try {
            SkyLicense.instance.getNativeLicenseService()
                    .recordDeliveryFailure(authLogId);
        } catch (RuntimeException error) {
            SkyLicense.LOG.error("Unable to audit resource delivery failure", error);
        }
    }

    private void failPendingDelivery(PendingDelivery delivery, String reason) {
        pendingDelivery.compareAndSet(delivery, null);
        if (delivery.fail()) {
            SkyLicense.LOG.warn(reason);
        }
    }

    private static String readUtf16String(ByteBuf input) {
        int length = input.readInt();
        if (length < 1 || length > 4096) {
            throw new IllegalArgumentException("string length is outside the allowed range");
        }
        char[] characters = new char[length];
        try {
            for (int index = 0; index < length; index++) {
                characters[index] = input.readChar();
            }
            return new String(characters);
        } finally {
            Arrays.fill(characters, '\0');
        }
    }

    static boolean isValidHwid(String value) {
        return NativeIdentifierValidator.isValidHwid(value);
    }

    static boolean isValidResourceIdentity(String value) {
        return NativeIdentifierValidator.isValidResourceIdentity(value);
    }

    static boolean isValidLicenseCode(String value) {
        return NativeIdentifierValidator.isValidLicenseCode(value);
    }

    static boolean isValidInternalClassName(String value) {
        return NativeIdentifierValidator.isValidInternalClassName(value);
    }

    private static void writeString(ChannelHandlerContext context, String content) {
        ByteBuf output = context.alloc().buffer(Integer.BYTES + content.length() * 2);
        output.writeInt(content.length());
        for (int index = 0; index < content.length(); index++) {
            output.writeChar(content.charAt(index));
        }
        context.writeAndFlush(output);
    }

    private static void writeStringAndClose(ChannelHandlerContext context, String content) {
        ByteBuf output = context.alloc().buffer(Integer.BYTES + content.length() * 2);
        output.writeInt(content.length());
        for (int index = 0; index < content.length(); index++) {
            output.writeChar(content.charAt(index));
        }
        context.writeAndFlush(output).addListener(ChannelFutureListener.CLOSE);
    }

    private static boolean allZero(byte[] value) {
        int aggregate = 0;
        for (byte item : value) {
            aggregate |= item;
        }
        return aggregate == 0;
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private final class ResourceDeliveryTask implements Runnable {
        private final ChannelHandlerContext context;
        private final PendingAuth pending;
        private final String clientIp;
        private final boolean debug;

        private ResourceDeliveryTask(
                ChannelHandlerContext context,
                PendingAuth pending,
                String clientIp,
                boolean debug
        ) {
            this.context = context;
            this.pending = pending;
            this.clientIp = clientIp;
            this.debug = debug;
        }

        @Override
        public void run() {
            deliverResource(context, pending, clientIp, debug);
        }

        private void cancelBeforeStart() {
            pending.destroy();
            context.close();
        }
    }

    static final class PendingDelivery {
        private static final int WAITING = 0;
        private static final int CONFIRMING = 1;
        private static final int COMPLETE = 2;
        private static final int FAILED = 3;

        private final byte[] sessionId;
        private final AtomicInteger state = new AtomicInteger(WAITING);
        private Runnable successFinalizer;
        private Consumer<byte[]> failureFinalizer;
        private boolean successCommitted;
        private volatile ScheduledFuture<?> timeout;

        PendingDelivery(
                byte[] sessionId,
                Runnable successFinalizer,
                Consumer<byte[]> failureFinalizer
        ) {
            if (sessionId == null || sessionId.length != KEY_LENGTH
                    || successFinalizer == null || failureFinalizer == null) {
                throw new IllegalArgumentException("invalid pending-delivery state");
            }
            this.sessionId = sessionId.clone();
            this.successFinalizer = successFinalizer;
            this.failureFinalizer = failureFinalizer;
        }

        synchronized boolean matchesSessionId(byte[] candidate) {
            return state.get() == WAITING
                    && candidate != null
                    && MessageDigest.isEqual(sessionId, candidate);
        }

        synchronized boolean isWaiting() {
            return state.get() == WAITING;
        }

        synchronized boolean beginConfirmation() {
            if (!state.compareAndSet(WAITING, CONFIRMING)) {
                return false;
            }
            cancelTimeout();
            return true;
        }

        synchronized boolean commitSuccess() {
            if (state.get() != CONFIRMING || successCommitted) {
                return false;
            }
            successFinalizer.run();
            successCommitted = true;
            successFinalizer = null;
            return true;
        }

        synchronized boolean complete() {
            if (!successCommitted || !state.compareAndSet(CONFIRMING, COMPLETE)) {
                return false;
            }
            finish();
            return true;
        }

        synchronized boolean fail() {
            while (true) {
                int current = state.get();
                if (current == COMPLETE || current == FAILED) {
                    return false;
                }
                if (state.compareAndSet(current, FAILED)) {
                    Consumer<byte[]> currentFinalizer = failureFinalizer;
                    failureFinalizer = null;
                    successFinalizer = null;
                    try {
                        currentFinalizer.accept(sessionId.clone());
                    } finally {
                        finish();
                    }
                    return true;
                }
            }
        }

        synchronized void setTimeout(ScheduledFuture<?> timeout) {
            this.timeout = timeout;
            if (state.get() != WAITING) {
                timeout.cancel(false);
            }
        }

        private void cancelTimeout() {
            ScheduledFuture<?> current = timeout;
            if (current != null) {
                current.cancel(false);
            }
        }

        private void finish() {
            cancelTimeout();
            successFinalizer = null;
            failureFinalizer = null;
            clear(sessionId);
        }
    }

    private static final class ClientHello {
        private final byte[] clientPublicKey;
        private final byte[] clientNonce;
        private final int securityEpoch;
        private final byte[] buildId;
        private final String hwid;
        private final String pluginName;
        private final String pluginVersion;
        private final String userName;
        private final String className;
        private final String interfaceName;

        private ClientHello(
                byte[] clientPublicKey,
                byte[] clientNonce,
                int securityEpoch,
                byte[] buildId,
                String hwid,
                String pluginName,
                String pluginVersion,
                String userName,
                String className,
                String interfaceName
        ) {
            this.clientPublicKey = clientPublicKey;
            this.clientNonce = clientNonce;
            this.securityEpoch = securityEpoch;
            this.buildId = buildId;
            this.hwid = hwid;
            this.pluginName = pluginName;
            this.pluginVersion = pluginVersion;
            this.userName = userName;
            this.className = className;
            this.interfaceName = interfaceName;
        }

        private void destroy() {
            clear(clientPublicKey);
            clear(clientNonce);
            clear(buildId);
        }
    }

    private static final class PendingAuth {
        private final ChallengeUtil challengeUtil;
        private final byte[] challenge;
        private final byte[] clientNonce;
        private final byte[] sessionId;
        private final byte[] sessionKey;
        private final String userName;
        private final String pluginName;
        private final String pluginVersion;
        private final String pluginIdentifier;
        private final String className;
        private final String interfaceName;
        private final String hwid;
        private final int securityEpoch;
        private final byte[] buildId;
        private final byte[] serverPublicKey;
        private final byte[] serverNonce;

        private PendingAuth(
                ChallengeUtil challengeUtil,
                byte[] challenge,
                byte[] clientNonce,
                byte[] sessionId,
                byte[] sessionKey,
                String userName,
                String pluginName,
                String pluginVersion,
                String pluginIdentifier,
                String className,
                String interfaceName,
                String hwid,
                int securityEpoch,
                byte[] buildId,
                byte[] serverPublicKey,
                byte[] serverNonce
        ) {
            this.challengeUtil = challengeUtil;
            this.challenge = challenge.clone();
            this.clientNonce = clientNonce.clone();
            this.sessionId = sessionId.clone();
            this.sessionKey = sessionKey.clone();
            this.userName = userName;
            this.pluginName = pluginName;
            this.pluginVersion = pluginVersion;
            this.pluginIdentifier = pluginIdentifier;
            this.className = className;
            this.interfaceName = interfaceName;
            this.hwid = hwid;
            this.securityEpoch = securityEpoch;
            this.buildId = buildId.clone();
            this.serverPublicKey = serverPublicKey.clone();
            this.serverNonce = serverNonce.clone();
        }

        private ByteBuf serverHandshakeFrame() {
            ByteBuf output = Unpooled.buffer(KEY_LENGTH * 4);
            output.writeBytes(serverPublicKey);
            output.writeBytes(serverNonce);
            output.writeBytes(challenge);
            output.writeBytes(sessionId);
            return output;
        }

        private void destroy() {
            clearChallengeMaterial();
            clear(sessionId);
            clear(sessionKey);
            clear(buildId);
        }

        private void clearChallengeMaterial() {
            challengeUtil.destroy();
            clear(challenge);
            clear(clientNonce);
            clear(serverPublicKey);
            clear(serverNonce);
        }
    }
}
