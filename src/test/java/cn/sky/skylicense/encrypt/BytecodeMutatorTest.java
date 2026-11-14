package cn.sky.skylicense.encrypt;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import static org.junit.jupiter.api.Assertions.*;

class BytecodeMutatorTest {
    @Test
    void mutatedDefaultInterfacesRemainLoadableWithoutIllegalFields() {
        byte[] original = fixture("fixture/DefaultInterface", Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT);
        for (int i = 0; i < 32; i++) {
            Class<?> type = new Loader().define(BytecodeMutator.mutate(original));
            assertTrue(type.isInterface());
            assertEquals(0, type.getDeclaredFields().length);
            assertDoesNotThrow(() -> type.getMethod("answer"));
        }
    }

    @Test
    void mutatedAnnotationsRemainLoadable() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_ANNOTATION | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT,
                "fixture/Annotation", null, "java/lang/Object", new String[]{"java/lang/annotation/Annotation"});
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "value", "()Ljava/lang/String;", null, null).visitEnd();
        writer.visitEnd();
        Class<?> type = new Loader().define(BytecodeMutator.mutate(writer.toByteArray()));
        assertTrue(type.isAnnotation());
        assertEquals(0, type.getDeclaredFields().length);
    }

    @Test
    void ordinaryClassesKeepTheirExecutableBehaviorAndUniqueFields() throws Exception {
        byte[] original = fixture("fixture/Ordinary", Opcodes.ACC_PUBLIC);
        for (int i = 0; i < 32; i++) {
            Class<?> type = new Loader().define(BytecodeMutator.mutate(original));
            assertEquals(42, type.getMethod("answer").invoke(null));
            java.util.Set<String> names = new java.util.HashSet<>();
            for (java.lang.reflect.Field field : type.getDeclaredFields()) assertTrue(names.add(field.getName()));
        }
    }

    private static byte[] fixture(String name, int access) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, access, name, null, "java/lang/Object", null);
        int methodAccess = Opcodes.ACC_PUBLIC | ((access & Opcodes.ACC_INTERFACE) == 0 ? Opcodes.ACC_STATIC : 0);
        MethodVisitor method = writer.visitMethod(methodAccess, "answer", "()I", null, null);
        method.visitCode();
        method.visitIntInsn(Opcodes.BIPUSH, 42);
        method.visitInsn(Opcodes.IRETURN);
        method.visitMaxs(1, 1);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static final class Loader extends ClassLoader {
        Class<?> define(byte[] bytes) { return defineClass(null, bytes, 0, bytes.length); }
    }
}
