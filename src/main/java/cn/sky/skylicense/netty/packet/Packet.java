package cn.sky.skylicense.netty.packet;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Packet implements Cloneable {

    private final PacketType type;
    private long length;
    private byte[] content;

    public Packet(PacketType type) {
        this.type = type;
    }

    public void write(String content) {
        this.content = content.getBytes(StandardCharsets.UTF_8);
        this.length = this.content.length;
    }

    public void write(byte[] content) {
        this.content = content.clone();
        this.length = content.length;
    }

    public long getLength() {
        return length;
    }

    public byte[] getContent() {
        return content;
    }

    public PacketType getType() {
        return type;
    }

    @Override
    public Packet clone() {
        try {
            Packet clone = (Packet) super.clone();
            clone.content = this.content == null ? null : this.content.clone();
            return clone;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError();
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || this.getClass() != obj.getClass()) return false;
        Packet other = (Packet) obj;
        if (type != other.type) return false;
        if (length != other.length) return false;
        if (!Arrays.equals(content, other.content)) return false;
        return true;
    }

    @Override
    public int hashCode() {
        int result = 31 * type.hashCode() + Long.hashCode(length);
        return 31 * result + Arrays.hashCode(content);
    }

    @Override
    public String toString() {
        String text = content == null ? "" : new String(content, StandardCharsets.UTF_8);
        return "Packet{" + "type=" + type + ", length=" + length + ", content=" + text + '}';
    }
}
