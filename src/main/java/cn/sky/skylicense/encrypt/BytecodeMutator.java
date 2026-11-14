package cn.sky.skylicense.encrypt;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import java.security.SecureRandom;

/**
 * Polymorphic bytecode mutation engine.
 * Each time resources are sent, the bytecode is slightly different,
 * making signature-based universal cracks impossible.
 */
public class BytecodeMutator {
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Apply random mutations to bytecode that preserve semantics
     */
    public static byte[] mutate(byte[] originalBytecode) {
        try {
            ClassReader cr = new ClassReader(originalBytecode);
            ClassNode cn = new ClassNode();
            cr.accept(cn, 0);

            // Apply mutations
            for (MethodNode method : cn.methods) {
                if (method.instructions.size() > 0) {
                    insertDeadCode(method);
                    reorderIndependentInstructions(method);
                    addOpaquePredicates(method);
                }
            }

            // Add dummy fields
            addDummyFields(cn);

            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
            cn.accept(cw);
            return cw.toByteArray();
        } catch (Exception e) {
            // If mutation fails, return original
            return originalBytecode;
        }
    }

    /**
     * Insert dead code blocks that never execute
     */
    private static void insertDeadCode(MethodNode method) {
        if (method.instructions.size() < 5) return;

        int insertCount = RANDOM.nextInt(3) + 1;
        for (int i = 0; i < insertCount; i++) {
            int position = RANDOM.nextInt(Math.max(1, method.instructions.size() - 2)) + 1;
            AbstractInsnNode target = method.instructions.get(position);

            // Only insert before certain safe instruction types
            if (target.getOpcode() < 0) continue;

            InsnList deadCode = generateDeadCodeBlock();
            method.instructions.insertBefore(target, deadCode);
        }
    }

    /**
     * Generate a dead code block with an opaque predicate
     */
    private static InsnList generateDeadCodeBlock() {
        InsnList list = new InsnList();
        LabelNode skipLabel = new LabelNode();

        // Opaque predicate: (random_const * 2) % 2 == 0 is always true
        // So the dead branch is never taken
        int constant = RANDOM.nextInt(1000) * 2; // Always even
        list.add(new LdcInsnNode(constant));
        list.add(new InsnNode(Opcodes.ICONST_2));
        list.add(new InsnNode(Opcodes.IREM));
        list.add(new JumpInsnNode(Opcodes.IFEQ, skipLabel)); // Always jumps

        // Dead code that never executes
        list.add(new InsnNode(Opcodes.NOP));
        list.add(new InsnNode(Opcodes.NOP));

        list.add(skipLabel);
        return list;
    }

    /**
     * Reorder independent instructions (NOP insertion between them)
     */
    private static void reorderIndependentInstructions(MethodNode method) {
        // Insert random NOPs between instructions
        int nopCount = RANDOM.nextInt(2) + 1;
        for (int i = 0; i < nopCount; i++) {
            if (method.instructions.size() < 3) break;
            int pos = RANDOM.nextInt(method.instructions.size() - 1) + 1;
            AbstractInsnNode node = method.instructions.get(pos);
            if (node.getOpcode() >= 0) {
                method.instructions.insertBefore(node, new InsnNode(Opcodes.NOP));
            }
        }
    }

    /**
     * Add opaque predicates that always evaluate to the same value
     */
    private static void addOpaquePredicates(MethodNode method) {
        // Only add to methods with enough instructions
        if (method.instructions.size() < 10) return;
        if (RANDOM.nextInt(3) != 0) return; // 33% chance

        // Find a safe insertion point
        int pos = RANDOM.nextInt(Math.max(1, method.instructions.size() / 2));
        AbstractInsnNode target = method.instructions.get(pos);
        if (target.getOpcode() < 0) return;

        InsnList predicate = new InsnList();
        LabelNode continueLabel = new LabelNode();

        // x^2 >= 0 is always true for integers
        int val = RANDOM.nextInt(100) + 1;
        predicate.add(new LdcInsnNode(val));
        predicate.add(new LdcInsnNode(val));
        predicate.add(new InsnNode(Opcodes.IMUL));
        predicate.add(new JumpInsnNode(Opcodes.IFGE, continueLabel)); // Always true
        predicate.add(new InsnNode(Opcodes.NOP)); // Dead
        predicate.add(continueLabel);

        method.instructions.insertBefore(target, predicate);
    }

    /**
     * Add dummy fields with random names
     */
    private static void addDummyFields(ClassNode cn) {
        // Interface/annotation fields must be public static final, and module
        // descriptors cannot contain ordinary fields. Do not alter their ABI.
        if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_MODULE)) != 0) return;
        java.util.Set<String> names = new java.util.HashSet<>();
        for (FieldNode field : cn.fields) names.add(field.name);
        int fieldCount = Math.min(RANDOM.nextInt(3) + 1, 65535 - cn.fields.size());
        for (int i = 0; i < fieldCount; i++) {
            String name;
            do { name = generateRandomFieldName(); } while (!names.add(name));
            String desc = RANDOM.nextBoolean() ? "I" : "J";
            int access = Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC;
            cn.fields.add(new FieldNode(access, name, desc, null, null));
        }
    }

    private static String generateRandomFieldName() {
        // Use confusing names that look like obfuscated code
        String[] prefixes = {"a", "b", "c", "I", "l", "O", "Il", "lI", "OO"};
        String prefix = prefixes[RANDOM.nextInt(prefixes.length)];
        return prefix + Integer.toHexString(RANDOM.nextInt(0xFFFF));
    }
}
