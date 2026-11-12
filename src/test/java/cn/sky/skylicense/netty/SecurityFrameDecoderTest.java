package cn.sky.skylicense.netty;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.CorruptedFrameException;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class SecurityFrameDecoderTest {
    @Test
    void fragmentedV4HelloIsEmittedOnlyWhenComplete() {
        ByteBuf source = protocolV4Hello();
        byte[] bytes = new byte[source.readableBytes()];
        source.readBytes(bytes).release();

        EmbeddedChannel channel = new EmbeddedChannel(new SecurityFrameDecoder());
        assertFalse(channel.writeInbound(Unpooled.wrappedBuffer(bytes, 0, 7)));
        assertFalse(channel.writeInbound(Unpooled.wrappedBuffer(bytes, 7, 19)));
        assertTrue(channel.writeInbound(
                Unpooled.wrappedBuffer(bytes, 26, bytes.length - 26)));

        ByteBuf decoded = channel.readInbound();
        assertNotNull(decoded);
        assertEquals(bytes.length, decoded.readableBytes());
        decoded.release();
        assertNull(channel.readInbound());
        channel.finishAndReleaseAll();
    }

    @Test
    void heartbeatAndChallengeFramesHaveUnambiguousBoundaries() {
        EmbeddedChannel channel = new EmbeddedChannel(new SecurityFrameDecoder());
        ByteBuf heartbeat = Unpooled.buffer();
        heartbeat.writeInt(SecurityFrameDecoder.HEARTBEAT_MAGIC);
        heartbeat.writeInt(5);
        heartbeat.writeZero(5 + 32);
        ByteBuf challenge = Unpooled.buffer();
        challenge.writeInt(SecurityFrameDecoder.CHALLENGE_RESPONSE_MAGIC);
        challenge.writeLong(123);
        challenge.writeZero(32);

        assertTrue(channel.writeInbound(heartbeat, challenge));
        ByteBuf first = channel.readInbound();
        ByteBuf second = channel.readInbound();
        assertEquals(45, first.readableBytes());
        assertEquals(44, second.readableBytes());
        first.release();
        second.release();
        channel.finishAndReleaseAll();
    }

    @Test
    void deliveryAcknowledgementIsFixedLengthAndSupportsFragmentation() {
        ByteBuf source = Unpooled.buffer();
        source.writeInt(SecurityFrameDecoder.DELIVERY_ACK_MAGIC);
        source.writeLong(0x0102030405060708L);
        source.writeZero(32);
        source.writeByte(1);
        source.writeZero(32);
        byte[] bytes = new byte[source.readableBytes()];
        source.readBytes(bytes).release();

        EmbeddedChannel channel = new EmbeddedChannel(new SecurityFrameDecoder());
        assertFalse(channel.writeInbound(Unpooled.wrappedBuffer(bytes, 0, 17)));
        assertFalse(channel.writeInbound(Unpooled.wrappedBuffer(bytes, 17, 60 - 17)));
        assertTrue(channel.writeInbound(
                Unpooled.wrappedBuffer(bytes, 60, bytes.length - 60)));

        ByteBuf decoded = channel.readInbound();
        assertNotNull(decoded);
        assertEquals(77, decoded.readableBytes());
        assertEquals(SecurityFrameDecoder.DELIVERY_ACK_MAGIC, decoded.readInt());
        decoded.release();
        channel.finishAndReleaseAll();
    }

    @Test
    void deliveryAcknowledgementRejectsTrailingData() {
        EmbeddedChannel channel = new EmbeddedChannel(new SecurityFrameDecoder());
        ByteBuf frame = Unpooled.buffer();
        frame.writeInt(SecurityFrameDecoder.DELIVERY_ACK_MAGIC);
        frame.writeLong(1L);
        frame.writeZero(32);
        frame.writeByte(1);
        frame.writeZero(36);

        assertThrows(CorruptedFrameException.class, () -> channel.writeInbound(frame));
        assertThrows(CorruptedFrameException.class, channel::finishAndReleaseAll);
    }

    @Test
    void fragmentedV4HelloIncludesSignedBuildMetadata() {
        ByteBuf source = protocolV4Hello();
        byte[] bytes = new byte[source.readableBytes()];
        source.readBytes(bytes).release();

        EmbeddedChannel channel = new EmbeddedChannel(new SecurityFrameDecoder());
        assertFalse(channel.writeInbound(Unpooled.wrappedBuffer(bytes, 0, 70)));
        assertTrue(channel.writeInbound(
                Unpooled.wrappedBuffer(bytes, 70, bytes.length - 70)));

        ByteBuf decoded = channel.readInbound();
        assertNotNull(decoded);
        assertEquals(bytes.length, decoded.readableBytes());
        assertEquals(SecurityFrameDecoder.PROTOCOL_V4, decoded.readInt());
        decoded.release();
        channel.finishAndReleaseAll();
    }

    @Test
    void legacyProtocolIsRejectedBeforeItCanReachTheHandler() {
        EmbeddedChannel channel = new EmbeddedChannel(new SecurityFrameDecoder());
        ByteBuf legacy = Unpooled.buffer().writeInt(3).writeZero(128);
        assertThrows(CorruptedFrameException.class, () -> channel.writeInbound(legacy));
        assertThrows(CorruptedFrameException.class, channel::finishAndReleaseAll);
    }

    @Test
    void invalidHwidLengthIsRejectedBeforeTheFrameIsBuffered() {
        EmbeddedChannel channel = new EmbeddedChannel(new SecurityFrameDecoder());
        ByteBuf frame = Unpooled.buffer();
        frame.writeInt(SecurityFrameDecoder.PROTOCOL_V4);
        frame.writeZero(32 + 32);
        frame.writeInt(1);
        frame.writeZero(32);
        writeString(frame, "short");

        assertThrows(CorruptedFrameException.class, () -> channel.writeInbound(frame));
        assertThrows(CorruptedFrameException.class, channel::finishAndReleaseAll);
    }

    private static ByteBuf protocolV4Hello() {
        ByteBuf buffer = Unpooled.buffer();
        buffer.writeInt(SecurityFrameDecoder.PROTOCOL_V4);
        buffer.writeZero(32 + 32);
        buffer.writeInt(1);
        buffer.writeBytes(new byte[32]);
        byte[] fingerprint = new byte[32];
        fingerprint[31] = 1;
        writeString(buffer, Base64.getEncoder().encodeToString(fingerprint));
        writeString(buffer, "plugin@1@license$$Class$$Interface");
        buffer.writeInt(0);
        buffer.writeZero(16);
        return buffer;
    }

    private static void writeString(ByteBuf buffer, String value) {
        buffer.writeInt(value.length());
        for (int index = 0; index < value.length(); index++) {
            buffer.writeChar(value.charAt(index));
        }
    }
}
