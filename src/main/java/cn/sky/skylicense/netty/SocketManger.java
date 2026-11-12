package cn.sky.skylicense.netty;

import cn.sky.skylicense.SkyLicense;
import cn.sky.skylicense.security.StartupSecurity;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.timeout.ReadTimeoutHandler;

import java.io.File;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class SocketManger {
    private final int port;
    private final AtomicBoolean stopping = new AtomicBoolean();
    private volatile Channel serverChannel;
    private volatile EventLoopGroup acceptorGroup;
    private volatile EventLoopGroup workerGroup;

    public SocketManger(int port) {
        this.port = port;
    }

    public void startNetty() {
        startNetty(null);
    }

    /** Starts the listener and reports the bind result before blocking on shutdown. */
    public void startNetty(CompletableFuture<Void> startup) {
        EventLoopGroup acceptor = new NioEventLoopGroup();
        EventLoopGroup worker = new NioEventLoopGroup();
        acceptorGroup = acceptor;
        workerGroup = worker;

        try {
            SslContext tlsContext = createTlsContext();
            if (stopping.get()) {
                throw new IllegalStateException("authentication listener was stopped before bind");
            }
            ServerBootstrap bootstrap = new ServerBootstrap();
            bootstrap.group(acceptor, worker)
                    .channel(NioServerSocketChannel.class)
                    .localAddress(port)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel channel) {
                            channel.pipeline().addLast(tlsContext.newHandler(channel.alloc()));
                            channel.pipeline().addLast(
                                    SocketHandler.READ_TIMEOUT_HANDLER_NAME,
                                    new ReadTimeoutHandler(
                                            SocketHandler.INITIAL_READ_TIMEOUT_SECONDS));
                            channel.pipeline().addLast(new SecurityFrameDecoder());
                            channel.pipeline().addLast(new SocketHandler());
                        }
            });
            ChannelFuture future = bootstrap.bind().sync();
            serverChannel = future.channel();
            if (stopping.get()) {
                future.channel().close().syncUninterruptibly();
                return;
            }
            if (startup != null) {
                startup.complete(null);
            }
            SkyLicense.LOG.info("Authentication server listening with mandatory TLS 1.3");
            future.channel().closeFuture().syncUninterruptibly();
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            completeStartupFailure(startup, error);
            SkyLicense.LOG.error("Authentication server interrupted", error);
        } catch (Exception error) {
            completeStartupFailure(startup, error);
            SkyLicense.LOG.error(
                    "Authentication TLS startup failed; authentication port remains closed",
                    error
            );
        } finally {
            completeStartupFailure(
                    startup,
                    new IllegalStateException("Authentication listener stopped before startup completed"));
            serverChannel = null;
            shutdownGroup(acceptor);
            shutdownGroup(worker);
            acceptorGroup = null;
            workerGroup = null;
        }
    }

    /** Stops the listener and both event-loop groups; safe to call more than once. */
    public void stop() {
        stopAccepting();
        shutdownGroup(acceptorGroup);
        shutdownGroup(workerGroup);
    }

    /** Returns true only while the authentication listener can accept new clients. */
    public boolean isAcceptingConnections() {
        Channel channel = serverChannel;
        return !stopping.get()
                && channel != null
                && channel.isOpen()
                && channel.isActive();
    }

    /** Closes only the listening channel so no new authentication connection is accepted. */
    public void stopAccepting() {
        stopping.set(true);
        Channel channel = serverChannel;
        if (channel != null) {
            channel.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
        }
    }

    private static void shutdownGroup(EventLoopGroup group) {
        if (group == null) {
            return;
        }
        group.shutdownGracefully(0, 5, TimeUnit.SECONDS).awaitUninterruptibly(5, TimeUnit.SECONDS);
    }

    private static void completeStartupFailure(
            CompletableFuture<Void> startup,
            Throwable failure
    ) {
        if (startup != null && !startup.isDone()) {
            startup.completeExceptionally(failure);
        }
    }

    private static SslContext createTlsContext() throws Exception {
        String certificatePath = SkyLicense.configuration()
                .getStorage()
                .getAuthTlsCertificateChain();
        String privateKeyPath = SkyLicense.configuration()
                .getStorage()
                .getAuthTlsPrivateKey();
        File certificate = new File(certificatePath).getCanonicalFile();
        File privateKey = new File(privateKeyPath).getCanonicalFile();
        if (!certificate.isFile() || !privateKey.isFile()) {
            throw new IllegalStateException(
                    "TLS certificate/key missing: " + certificate + " / " + privateKey);
        }

        String password = StartupSecurity.tlsPrivateKeyPassword();
        return SslContextBuilder
                .forServer(
                        certificate,
                        privateKey,
                        password == null || password.isEmpty() ? null : password)
                .sslProvider(SslProvider.JDK)
                .protocols("TLSv1.3")
                .build();
    }
}
