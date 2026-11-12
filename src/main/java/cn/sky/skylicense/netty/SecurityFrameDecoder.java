package cn.sky.skylicense.netty;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.CorruptedFrameException;

import java.util.List;

/**
 * Cumulates fragmented TCP input and emits exactly one complete security
 * protocol message at a time. Only protocol v4 authentication is accepted;
 * challenge and heartbeat messages use unambiguous magic values.
 */
public final class SecurityFrameDecoder extends ByteToMessageDecoder {
    public static final int PROTOCOL_V4 = 4;
    public static final int CHALLENGE_RESPONSE_MAGIC = 0x534B4352; // SKCR
    public static final int HEARTBEAT_MAGIC = 0x534B4842; // SKHB
    public static final int DELIVERY_ACK_MAGIC = 0x534B4441; // SKDA

    private static final int HWID_CHARS = 44;
    private static final int MAX_PLUGIN_DATA_CHARS = 1_414;
    private static final int MAX_HEARTBEAT_PAYLOAD = 8192;
    private static final int CHALLENGE_RESPONSE_LENGTH = 4 + 8 + 32;
    private static final int DELIVERY_ACK_LENGTH = 4 + 8 + 32 + 1 + 32;

    @Override
    protected void decode(ChannelHandlerContext context, ByteBuf input, List<Object> output) {
        while (true) {
            int frameLength = frameLength(input);
            if (frameLength == 0 || input.readableBytes() < frameLength) {
                return;
            }
            output.add(input.readBytes(frameLength));
        }
    }

    private static int frameLength(ByteBuf input) {
        if (input.readableBytes() < 4) {
            return 0;
        }
        int start = input.readerIndex();
        int first = input.getInt(start);

        if (first == CHALLENGE_RESPONSE_MAGIC) {
            return CHALLENGE_RESPONSE_LENGTH;
        }
        if (first == HEARTBEAT_MAGIC) {
            if (input.readableBytes() < 8) {
                return 0;
            }
            int payloadLength = input.getInt(start + 4);
            requireRange(payloadLength, 1, MAX_HEARTBEAT_PAYLOAD, "heartbeat payload");
            return checkedLength(8L + payloadLength + 32L, "heartbeat frame");
        }
        if (first == DELIVERY_ACK_MAGIC) {
            return DELIVERY_ACK_LENGTH;
        }
        if (first == PROTOCOL_V4) {
            return protocolLength(input, start);
        }
        throw new CorruptedFrameException("unsupported authentication protocol");
    }

    private static int protocolLength(ByteBuf input, int start) {
        // Version + client public key + client nonce + security epoch + signed
        // build id + HWID character count.
        int hwidLengthOffset = checkedLength(start + 104L, "protocol metadata");
        if (input.writerIndex() < hwidLengthOffset + 4) {
            return 0;
        }
        int hwidLength = input.getInt(hwidLengthOffset);
        requireRange(hwidLength, HWID_CHARS, HWID_CHARS, "HWID");
        int pluginLengthOffset = checkedLength(
                hwidLengthOffset + 4L + hwidLength * 2L,
                "protocol HWID");
        if (input.writerIndex() < pluginLengthOffset + 4) {
            return 0;
        }
        int pluginLength = input.getInt(pluginLengthOffset);
        requireRange(pluginLength, 1, MAX_PLUGIN_DATA_CHARS, "plugin data");
        long end = pluginLengthOffset + 4L + pluginLength * 2L + 4L + 16L;
        return checkedLength(end - start, "v4 frame");
    }

    private static void requireRange(int value, int minimum, int maximum, String field) {
        if (value < minimum || value > maximum) {
            throw new CorruptedFrameException(field + " length is outside the allowed range");
        }
    }

    private static int checkedLength(long value, String field) {
        if (value < 0 || value > Integer.MAX_VALUE) {
            throw new CorruptedFrameException(field + " length overflow");
        }
        return (int) value;
    }
}
