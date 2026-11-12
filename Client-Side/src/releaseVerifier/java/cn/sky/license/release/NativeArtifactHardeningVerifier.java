package cn.sky.license.release;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Structural release gate for the native libraries embedded in the SDK. */
public final class NativeArtifactHardeningVerifier {
    private static final long MAX_ARTIFACT_BYTES = 128L * 1024L * 1024L;

    private static final int PE_MACHINE_AMD64 = 0x8664;
    private static final int PE_MAGIC_64 = 0x20b;
    private static final int PE_FILE_DLL = 0x2000;
    private static final int PE_HIGH_ENTROPY_VA = 0x0020;
    private static final int PE_DYNAMIC_BASE = 0x0040;
    private static final int PE_NX_COMPAT = 0x0100;
    private static final int PE_GUARD_CF = 0x4000;
    private static final int PE_LOAD_CONFIG_DIRECTORY = 10;
    private static final int PE_SECTION_HEADER_BYTES = 40;

    private static final int ELF_CLASS_64 = 2;
    private static final int ELF_DATA_LITTLE_ENDIAN = 1;
    private static final int ELF_TYPE_SHARED_OBJECT = 3;
    private static final int ELF_MACHINE_X86_64 = 62;
    private static final int ELF_PROGRAM_HEADER_BYTES = 56;
    private static final long ELF_PT_LOAD = 1;
    private static final long ELF_PT_DYNAMIC = 2;
    private static final long ELF_PT_GNU_STACK = 0x6474e551L;
    private static final long ELF_PT_GNU_RELRO = 0x6474e552L;
    private static final long ELF_DT_NULL = 0;
    private static final long ELF_DT_BIND_NOW = 24;
    private static final long ELF_DT_FLAGS = 30;
    private static final long ELF_DT_FLAGS_1 = 0x6ffffffbL;
    private static final long ELF_DF_BIND_NOW = 0x8L;
    private static final long ELF_DF_1_NOW = 0x1L;
    private static final long ELF_PF_X = 0x1L;
    private static final long ELF_PF_W = 0x2L;

    public enum Platform {
        WINDOWS,
        LINUX
    }

    private NativeArtifactHardeningVerifier() {
    }

    public static void verify(Path artifact, Platform platform) throws IOException {
        if (artifact == null
                || !Files.isRegularFile(artifact, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Native artifact must be a regular file: " + artifact);
        }
        long size = Files.size(artifact);
        if (size <= 0 || size > MAX_ARTIFACT_BYTES) {
            throw new IOException("Native artifact has an invalid size: " + artifact);
        }
        byte[] bytes = Files.readAllBytes(artifact);
        verifyBytes(bytes, platform);
    }

    static void verifyBytes(byte[] bytes, Platform platform) throws IOException {
        if (platform == null) {
            throw new IOException("Native artifact platform is missing");
        }
        if (bytes == null || bytes.length == 0) {
            throw new IOException("Native artifact is empty");
        }
        switch (platform) {
            case WINDOWS:
                verifyPe64(bytes);
                break;
            case LINUX:
                verifyElf64(bytes);
                break;
            default:
                throw new IOException("Unsupported native artifact platform");
        }
    }

    private static void verifyPe64(byte[] bytes) throws IOException {
        requireRange(bytes, 0, 0x40, "DOS header");
        if ((bytes[0] & 0xff) != 'M' || (bytes[1] & 0xff) != 'Z') {
            throw new IOException("Windows artifact is not a DOS/PE image");
        }

        long peOffsetValue = readU32(bytes, 0x3c, "PE header offset");
        int peOffset = checkedOffset(peOffsetValue, bytes.length, "PE header offset");
        requireRange(bytes, peOffset, 24, "PE/COFF header");
        if ((bytes[peOffset] & 0xff) != 'P'
                || (bytes[peOffset + 1] & 0xff) != 'E'
                || bytes[peOffset + 2] != 0
                || bytes[peOffset + 3] != 0) {
            throw new IOException("Windows artifact has an invalid PE signature");
        }

        if (readU16(bytes, peOffset + 4, "PE machine") != PE_MACHINE_AMD64) {
            throw new IOException("Windows artifact is not x86-64");
        }
        int sectionCount = readU16(bytes, peOffset + 6, "PE section count");
        if (sectionCount <= 0 || sectionCount > 96) {
            throw new IOException("Windows artifact has an invalid section count");
        }
        int optionalHeaderBytes = readU16(
                bytes, peOffset + 20, "PE optional header size");
        int fileCharacteristics = readU16(
                bytes, peOffset + 22, "PE file characteristics");
        if ((fileCharacteristics & PE_FILE_DLL) == 0) {
            throw new IOException("Windows artifact is not marked as a DLL");
        }

        int optionalOffset = checkedOffset(
                ((long) peOffset) + 24L, bytes.length, "PE optional header");
        requireRange(
                bytes, optionalOffset, optionalHeaderBytes, "PE optional header");
        if (optionalHeaderBytes < 112 + (PE_LOAD_CONFIG_DIRECTORY + 1) * 8) {
            throw new IOException("Windows PE32+ optional header is truncated");
        }
        if (readU16(bytes, optionalOffset, "PE optional header magic") != PE_MAGIC_64) {
            throw new IOException("Windows artifact is not PE32+");
        }

        int dllCharacteristics = readU16(
                bytes, optionalOffset + 70, "PE DLL characteristics");
        requireFlag(dllCharacteristics, PE_HIGH_ENTROPY_VA, "HIGH_ENTROPY_VA");
        requireFlag(dllCharacteristics, PE_DYNAMIC_BASE, "DYNAMIC_BASE");
        requireFlag(dllCharacteristics, PE_NX_COMPAT, "NX_COMPAT");
        requireFlag(dllCharacteristics, PE_GUARD_CF, "GUARD_CF");

        long directoryCount = readU32(
                bytes, optionalOffset + 108, "PE data-directory count");
        if (directoryCount <= PE_LOAD_CONFIG_DIRECTORY) {
            throw new IOException("Windows artifact has no Load Configuration Directory");
        }
        int loadConfigEntry = optionalOffset + 112 + PE_LOAD_CONFIG_DIRECTORY * 8;
        long loadConfigRva = readU32(
                bytes, loadConfigEntry, "PE Load Configuration RVA");
        long loadConfigBytes = readU32(
                bytes, loadConfigEntry + 4, "PE Load Configuration size");
        if (loadConfigRva == 0 || loadConfigBytes < 4) {
            throw new IOException("Windows artifact has no usable Load Configuration Directory");
        }

        long sectionTableValue = ((long) optionalOffset) + optionalHeaderBytes;
        int sectionTable = checkedOffset(
                sectionTableValue, bytes.length, "PE section table");
        requireRange(
                bytes,
                sectionTable,
                ((long) sectionCount) * PE_SECTION_HEADER_BYTES,
                "PE section table");

        int loadConfigOffset = -1;
        for (int index = 0; index < sectionCount; index++) {
            int section = sectionTable + index * PE_SECTION_HEADER_BYTES;
            long virtualSize = readU32(bytes, section + 8, "PE section virtual size");
            long virtualAddress = readU32(bytes, section + 12, "PE section RVA");
            long rawSize = readU32(bytes, section + 16, "PE section raw size");
            long rawOffset = readU32(bytes, section + 20, "PE section raw offset");
            long span = Math.max(virtualSize, rawSize);
            if (span == 0
                    || loadConfigRva < virtualAddress
                    || loadConfigRva - virtualAddress >= span) {
                continue;
            }
            long relative = loadConfigRva - virtualAddress;
            if (relative > rawSize || loadConfigBytes > rawSize - relative) {
                continue;
            }
            long fileOffset = checkedAdd(rawOffset, relative, "PE Load Configuration offset");
            requireRange(
                    bytes,
                    fileOffset,
                    loadConfigBytes,
                    "PE Load Configuration Directory");
            loadConfigOffset = checkedOffset(
                    fileOffset, bytes.length, "PE Load Configuration offset");
            break;
        }
        if (loadConfigOffset < 0) {
            throw new IOException(
                    "Windows Load Configuration Directory is not backed by a PE section");
        }
        long declaredLoadConfigBytes = readU32(
                bytes, loadConfigOffset, "PE Load Configuration declared size");
        if (declaredLoadConfigBytes < 4 || declaredLoadConfigBytes > loadConfigBytes) {
            throw new IOException("Windows Load Configuration Directory is malformed");
        }
    }

    private static void requireFlag(int value, int flag, String name) throws IOException {
        if ((value & flag) == 0) {
            throw new IOException("Windows artifact is missing " + name);
        }
    }

    private static void verifyElf64(byte[] bytes) throws IOException {
        requireRange(bytes, 0, 64, "ELF header");
        if ((bytes[0] & 0xff) != 0x7f
                || bytes[1] != 'E'
                || bytes[2] != 'L'
                || bytes[3] != 'F') {
            throw new IOException("Linux artifact is not an ELF image");
        }
        if ((bytes[4] & 0xff) != ELF_CLASS_64) {
            throw new IOException("Linux artifact is not ELF64");
        }
        if ((bytes[5] & 0xff) != ELF_DATA_LITTLE_ENDIAN) {
            throw new IOException("Linux artifact is not little-endian ELF");
        }
        if ((bytes[6] & 0xff) != 1 || readU32(bytes, 20, "ELF version") != 1) {
            throw new IOException("Linux artifact has an invalid ELF version");
        }
        if (readU16(bytes, 16, "ELF type") != ELF_TYPE_SHARED_OBJECT) {
            throw new IOException("Linux artifact is not a shared object");
        }
        if (readU16(bytes, 18, "ELF machine") != ELF_MACHINE_X86_64) {
            throw new IOException("Linux artifact is not x86-64");
        }

        long programTableOffset = readU64(bytes, 32, "ELF program-header offset");
        int programHeaderBytes = readU16(bytes, 54, "ELF program-header size");
        int programHeaderCount = readU16(bytes, 56, "ELF program-header count");
        if (programHeaderBytes < ELF_PROGRAM_HEADER_BYTES
                || programHeaderCount <= 0
                || programHeaderCount == 0xffff) {
            throw new IOException("Linux artifact has an invalid program-header table");
        }
        long programTableBytes = checkedMultiply(
                programHeaderBytes, programHeaderCount, "ELF program-header table size");
        requireRange(
                bytes,
                programTableOffset,
                programTableBytes,
                "ELF program-header table");
        int programTable = checkedOffset(
                programTableOffset, bytes.length, "ELF program-header offset");

        boolean loadFound = false;
        boolean relroFound = false;
        boolean stackFound = false;
        boolean dynamicFound = false;
        boolean bindNowFound = false;
        for (int index = 0; index < programHeaderCount; index++) {
            int header = programTable + index * programHeaderBytes;
            long type = readU32(bytes, header, "ELF program-header type");
            long flags = readU32(bytes, header + 4, "ELF program-header flags");
            long offset = readU64(bytes, header + 8, "ELF segment offset");
            long fileSize = readU64(bytes, header + 32, "ELF segment file size");
            long memorySize = readU64(bytes, header + 40, "ELF segment memory size");
            if (fileSize > 0) {
                requireRange(bytes, offset, fileSize, "ELF segment");
            }

            if (type == ELF_PT_LOAD) {
                loadFound = true;
                if ((flags & (ELF_PF_X | ELF_PF_W)) == (ELF_PF_X | ELF_PF_W)) {
                    throw new IOException("Linux artifact contains an RWX LOAD segment");
                }
            } else if (type == ELF_PT_GNU_RELRO) {
                if (memorySize == 0) {
                    throw new IOException("Linux GNU_RELRO segment is empty");
                }
                relroFound = true;
            } else if (type == ELF_PT_GNU_STACK) {
                if ((flags & ELF_PF_X) != 0) {
                    throw new IOException("Linux GNU_STACK is executable");
                }
                stackFound = true;
            } else if (type == ELF_PT_DYNAMIC) {
                dynamicFound = true;
                if (containsBindNow(bytes, offset, fileSize)) {
                    bindNowFound = true;
                }
            }
        }

        if (!loadFound) {
            throw new IOException("Linux artifact contains no LOAD segment");
        }
        if (!relroFound) {
            throw new IOException("Linux artifact is missing GNU_RELRO");
        }
        if (!stackFound) {
            throw new IOException("Linux artifact is missing GNU_STACK");
        }
        if (!dynamicFound || !bindNowFound) {
            throw new IOException("Linux artifact is missing BIND_NOW");
        }
    }

    private static boolean containsBindNow(
            byte[] bytes,
            long dynamicOffset,
            long dynamicBytes
    ) throws IOException {
        if (dynamicBytes < 16 || dynamicBytes % 16 != 0) {
            throw new IOException("Linux PT_DYNAMIC segment is malformed");
        }
        requireRange(bytes, dynamicOffset, dynamicBytes, "ELF PT_DYNAMIC segment");
        int offset = checkedOffset(
                dynamicOffset, bytes.length, "ELF PT_DYNAMIC offset");
        int entries = checkedOffset(
                dynamicBytes / 16, Integer.MAX_VALUE, "ELF PT_DYNAMIC entry count");
        boolean terminatorFound = false;
        boolean bindNowFound = false;
        for (int index = 0; index < entries; index++) {
            int entry = offset + index * 16;
            long tag = readI64(bytes, entry, "ELF dynamic tag");
            long value = readU64(bytes, entry + 8, "ELF dynamic value");
            if (tag == ELF_DT_NULL) {
                terminatorFound = true;
                break;
            }
            if (tag == ELF_DT_BIND_NOW
                    || (tag == ELF_DT_FLAGS && (value & ELF_DF_BIND_NOW) != 0)
                    || (tag == ELF_DT_FLAGS_1 && (value & ELF_DF_1_NOW) != 0)) {
                bindNowFound = true;
            }
        }
        if (!terminatorFound) {
            throw new IOException("Linux PT_DYNAMIC segment has no DT_NULL terminator");
        }
        return bindNowFound;
    }

    private static int readU16(byte[] bytes, int offset, String field) throws IOException {
        requireRange(bytes, offset, 2, field);
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
    }

    private static long readU32(byte[] bytes, int offset, String field) throws IOException {
        requireRange(bytes, offset, 4, field);
        return ((long) bytes[offset] & 0xffL)
                | (((long) bytes[offset + 1] & 0xffL) << 8)
                | (((long) bytes[offset + 2] & 0xffL) << 16)
                | (((long) bytes[offset + 3] & 0xffL) << 24);
    }

    private static long readU64(byte[] bytes, int offset, String field) throws IOException {
        long value = readI64(bytes, offset, field);
        if (value < 0) {
            throw new IOException(field + " exceeds the supported 63-bit range");
        }
        return value;
    }

    private static long readI64(byte[] bytes, int offset, String field) throws IOException {
        requireRange(bytes, offset, 8, field);
        long value = 0;
        for (int index = 0; index < 8; index++) {
            value |= ((long) bytes[offset + index] & 0xffL) << (index * 8);
        }
        return value;
    }

    private static int checkedOffset(long value, int maximum, String field) throws IOException {
        if (value < 0 || value > maximum || value > Integer.MAX_VALUE) {
            throw new IOException(field + " is outside the artifact");
        }
        return (int) value;
    }

    private static long checkedAdd(long left, long right, String field) throws IOException {
        if (left < 0 || right < 0 || left > Long.MAX_VALUE - right) {
            throw new IOException(field + " overflows");
        }
        return left + right;
    }

    private static long checkedMultiply(long left, long right, String field) throws IOException {
        if (left < 0 || right < 0 || (right != 0 && left > Long.MAX_VALUE / right)) {
            throw new IOException(field + " overflows");
        }
        return left * right;
    }

    private static void requireRange(
            byte[] bytes,
            long offset,
            long length,
            String field
    ) throws IOException {
        if (offset < 0
                || length < 0
                || offset > bytes.length
                || length > ((long) bytes.length) - offset) {
            throw new IOException(field + " is truncated or outside the artifact");
        }
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length == 0 || arguments.length % 2 != 0) {
            throw new IllegalArgumentException(
                    "usage: NativeArtifactHardeningVerifier "
                            + "--windows <SkyLicense_64.dll> --linux <libSkyLicense_64.so>");
        }
        for (int index = 0; index < arguments.length; index += 2) {
            Platform platform;
            if ("--windows".equals(arguments[index])) {
                platform = Platform.WINDOWS;
            } else if ("--linux".equals(arguments[index])) {
                platform = Platform.LINUX;
            } else {
                throw new IllegalArgumentException(
                        "Unsupported native artifact platform: " + arguments[index]);
            }
            Path artifact = Paths.get(arguments[index + 1]);
            verify(artifact, platform);
            System.out.println(
                    "native_hardening_verified="
                            + platform.name().toLowerCase()
                            + ":"
                            + artifact.toAbsolutePath().normalize());
        }
    }
}
