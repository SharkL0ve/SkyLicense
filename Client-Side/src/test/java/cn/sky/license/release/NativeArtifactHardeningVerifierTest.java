package cn.sky.license.release;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class NativeArtifactHardeningVerifierTest {
    private static final int PE_OFFSET = 0x80;
    private static final int PE_OPTIONAL_OFFSET = PE_OFFSET + 24;
    private static final int PE_DLL_CHARACTERISTICS = PE_OPTIONAL_OFFSET + 70;
    private static final int PE_LOAD_CONFIG_ENTRY =
            PE_OPTIONAL_OFFSET + 112 + 10 * 8;
    private static final int PE_SECTION_TABLE = PE_OPTIONAL_OFFSET + 0xf0;
    private static final int PE_LOAD_CONFIG_RAW_OFFSET = 0x200;

    private static final int ELF_PROGRAM_TABLE = 64;
    private static final int ELF_LOAD_HEADER = ELF_PROGRAM_TABLE;
    private static final int ELF_RELRO_HEADER = ELF_PROGRAM_TABLE + 56;
    private static final int ELF_STACK_HEADER = ELF_PROGRAM_TABLE + 112;
    private static final int ELF_DYNAMIC_HEADER = ELF_PROGRAM_TABLE + 168;
    private static final int ELF_DYNAMIC_OFFSET = 0x240;

    @Test
    void acceptsHardenedPe32PlusDll() {
        assertDoesNotThrow(() -> NativeArtifactHardeningVerifier.verifyBytes(
                validPe(), NativeArtifactHardeningVerifier.Platform.WINDOWS));
    }

    @Test
    void rejectsPeWithoutRequiredMitigationFlags() {
        int[] flags = {0x0020, 0x0040, 0x0100, 0x4000};
        for (int flag : flags) {
            byte[] artifact = validPe();
            putU16(artifact, PE_DLL_CHARACTERISTICS,
                    readU16(artifact, PE_DLL_CHARACTERISTICS) & ~flag);
            assertThrows(IOException.class, () -> NativeArtifactHardeningVerifier.verifyBytes(
                    artifact, NativeArtifactHardeningVerifier.Platform.WINDOWS));
        }
    }

    @Test
    void rejectsPeWithUnmappedLoadConfiguration() {
        byte[] artifact = validPe();
        putU32(artifact, PE_LOAD_CONFIG_ENTRY, 0x7000);
        assertThrows(IOException.class, () -> NativeArtifactHardeningVerifier.verifyBytes(
                artifact, NativeArtifactHardeningVerifier.Platform.WINDOWS));
    }

    @Test
    void rejectsTruncatedOrWrongPeFormat() {
        byte[] truncated = Arrays.copyOf(validPe(), 0x100);
        assertThrows(IOException.class, () -> NativeArtifactHardeningVerifier.verifyBytes(
                truncated, NativeArtifactHardeningVerifier.Platform.WINDOWS));

        byte[] wrongFormat = validPe();
        putU16(wrongFormat, PE_OPTIONAL_OFFSET, 0x10b);
        assertThrows(IOException.class, () -> NativeArtifactHardeningVerifier.verifyBytes(
                wrongFormat, NativeArtifactHardeningVerifier.Platform.WINDOWS));
    }

    @Test
    void acceptsHardenedElf64SharedObject() {
        assertDoesNotThrow(() -> NativeArtifactHardeningVerifier.verifyBytes(
                validElf(), NativeArtifactHardeningVerifier.Platform.LINUX));
    }

    @Test
    void rejectsElfWithoutRelroStackOrBindNow() {
        byte[] noRelro = validElf();
        putU32(noRelro, ELF_RELRO_HEADER, 0);
        assertThrows(IOException.class, () -> NativeArtifactHardeningVerifier.verifyBytes(
                noRelro, NativeArtifactHardeningVerifier.Platform.LINUX));

        byte[] executableStack = validElf();
        putU32(executableStack, ELF_STACK_HEADER + 4, 7);
        assertThrows(IOException.class, () -> NativeArtifactHardeningVerifier.verifyBytes(
                executableStack, NativeArtifactHardeningVerifier.Platform.LINUX));

        byte[] noBindNow = validElf();
        putI64(noBindNow, ELF_DYNAMIC_OFFSET, 1);
        assertThrows(IOException.class, () -> NativeArtifactHardeningVerifier.verifyBytes(
                noBindNow, NativeArtifactHardeningVerifier.Platform.LINUX));
    }

    @Test
    void rejectsElfWithRwxLoadOrWrongClass() {
        byte[] rwx = validElf();
        putU32(rwx, ELF_LOAD_HEADER + 4, 7);
        assertThrows(IOException.class, () -> NativeArtifactHardeningVerifier.verifyBytes(
                rwx, NativeArtifactHardeningVerifier.Platform.LINUX));

        byte[] wrongClass = validElf();
        wrongClass[4] = 1;
        assertThrows(IOException.class, () -> NativeArtifactHardeningVerifier.verifyBytes(
                wrongClass, NativeArtifactHardeningVerifier.Platform.LINUX));
    }

    private static byte[] validPe() {
        byte[] artifact = new byte[0x400];
        artifact[0] = 'M';
        artifact[1] = 'Z';
        putU32(artifact, 0x3c, PE_OFFSET);
        artifact[PE_OFFSET] = 'P';
        artifact[PE_OFFSET + 1] = 'E';
        putU16(artifact, PE_OFFSET + 4, 0x8664);
        putU16(artifact, PE_OFFSET + 6, 1);
        putU16(artifact, PE_OFFSET + 20, 0xf0);
        putU16(artifact, PE_OFFSET + 22, 0x2000);
        putU16(artifact, PE_OPTIONAL_OFFSET, 0x20b);
        putU32(artifact, PE_OPTIONAL_OFFSET + 108, 16);
        putU16(artifact, PE_DLL_CHARACTERISTICS, 0x4160);
        putU32(artifact, PE_LOAD_CONFIG_ENTRY, 0x1000);
        putU32(artifact, PE_LOAD_CONFIG_ENTRY + 4, 0x100);

        putU32(artifact, PE_SECTION_TABLE + 8, 0x200);
        putU32(artifact, PE_SECTION_TABLE + 12, 0x1000);
        putU32(artifact, PE_SECTION_TABLE + 16, 0x200);
        putU32(artifact, PE_SECTION_TABLE + 20, PE_LOAD_CONFIG_RAW_OFFSET);
        putU32(artifact, PE_LOAD_CONFIG_RAW_OFFSET, 0x100);
        return artifact;
    }

    private static byte[] validElf() {
        byte[] artifact = new byte[0x300];
        artifact[0] = 0x7f;
        artifact[1] = 'E';
        artifact[2] = 'L';
        artifact[3] = 'F';
        artifact[4] = 2;
        artifact[5] = 1;
        artifact[6] = 1;
        putU16(artifact, 16, 3);
        putU16(artifact, 18, 62);
        putU32(artifact, 20, 1);
        putU64(artifact, 32, ELF_PROGRAM_TABLE);
        putU16(artifact, 52, 64);
        putU16(artifact, 54, 56);
        putU16(artifact, 56, 4);

        putU32(artifact, ELF_LOAD_HEADER, 1);
        putU32(artifact, ELF_LOAD_HEADER + 4, 5);
        putU64(artifact, ELF_LOAD_HEADER + 8, 0);
        putU64(artifact, ELF_LOAD_HEADER + 32, 0x200);
        putU64(artifact, ELF_LOAD_HEADER + 40, 0x200);

        putU32(artifact, ELF_RELRO_HEADER, 0x6474e552L);
        putU32(artifact, ELF_RELRO_HEADER + 4, 4);
        putU64(artifact, ELF_RELRO_HEADER + 8, 0x200);
        putU64(artifact, ELF_RELRO_HEADER + 32, 0x20);
        putU64(artifact, ELF_RELRO_HEADER + 40, 0x20);

        putU32(artifact, ELF_STACK_HEADER, 0x6474e551L);
        putU32(artifact, ELF_STACK_HEADER + 4, 6);

        putU32(artifact, ELF_DYNAMIC_HEADER, 2);
        putU32(artifact, ELF_DYNAMIC_HEADER + 4, 6);
        putU64(artifact, ELF_DYNAMIC_HEADER + 8, ELF_DYNAMIC_OFFSET);
        putU64(artifact, ELF_DYNAMIC_HEADER + 32, 0x30);
        putI64(artifact, ELF_DYNAMIC_OFFSET, 30);
        putU64(artifact, ELF_DYNAMIC_OFFSET + 8, 8);
        putI64(artifact, ELF_DYNAMIC_OFFSET + 16, 0);
        return artifact;
    }

    private static int readU16(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
    }

    private static void putU16(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) value;
        bytes[offset + 1] = (byte) (value >>> 8);
    }

    private static void putU32(byte[] bytes, int offset, long value) {
        for (int index = 0; index < 4; index++) {
            bytes[offset + index] = (byte) (value >>> (index * 8));
        }
    }

    private static void putU64(byte[] bytes, int offset, long value) {
        for (int index = 0; index < 8; index++) {
            bytes[offset + index] = (byte) (value >>> (index * 8));
        }
    }

    private static void putI64(byte[] bytes, int offset, long value) {
        putU64(bytes, offset, value);
    }
}
