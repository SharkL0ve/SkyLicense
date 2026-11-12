package cn.sky.skylicense.netty;

import cn.sky.skylicense.netty.packet.Packet;
import cn.sky.skylicense.netty.packet.PacketType;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageCodec;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class SocketCoder extends ByteToMessageCodec<Packet> {

    public final byte[] he = "GHER98GH934HBVUE8RBHFV23N9C9NUDEIG98O34CVN98M35E3YM8RX8M2Y8ER47TVYN8437HTC98M743Y87TYR349XC34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34N87T34987Y34YR7843YVTC4OSXPC23RV8943NY789CX23382YRH834YN87VTY78Y34N87CTR843Y87YCV783478BN87C78RTB3NYRC3Y2T7R83N487Y78V32".getBytes(StandardCharsets.UTF_8);
    public final long bl = he.length + 4 + 8;

    @Override
    protected void encode(ChannelHandlerContext ctx, Packet packet, ByteBuf byteBuf) {
        ByteBuf buf = ctx.alloc().buffer();
        buf.writeBytes(he);
        buf.writeInt(packet.getType().ordinal());
        buf.writeLong(packet.getLength());
        if (packet.getLength() != 0) {
            buf.writeBytes(packet.getContent());
        }
        byteBuf.writeBytes(buf);
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf byteBuf, List<Object> list) {
        if (byteBuf.readableBytes() >= bl) {
            int beginReader;

            while (true) {
                beginReader = byteBuf.readerIndex();
                byteBuf.markReaderIndex();
                ByteBuf tbt = PooledByteBufAllocator.DEFAULT.buffer().writeBytes(he);
                try {
                    if (ByteBufUtil.equals(byteBuf.readBytes(he.length), tbt)) {
                        break;
                    }
                } finally {
                    tbt.release();
                }
                byteBuf.readableBytes();
                byteBuf.readByte();
                if (byteBuf.readableBytes() < bl) {
                    return;
                }
            }
            Packet packet = new Packet(PacketType.values()[byteBuf.readInt()]);
            long len = byteBuf.readLong();
            if (byteBuf.readableBytes() < len) {
                byteBuf.readerIndex(beginReader);
                return;
            }
            if (len != 0) {
                byte[] buf = new byte[(int) len];
                byteBuf.readBytes(buf);
                packet.write(buf);
            }
            list.add(packet);
        }
    }
}
