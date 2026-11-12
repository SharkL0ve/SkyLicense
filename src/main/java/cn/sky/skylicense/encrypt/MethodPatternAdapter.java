

package cn.sky.skylicense.encrypt;

import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;

public class MethodPatternAdapter extends MethodVisitor {
	protected static final int SEEN_NOTHING = 0;
	protected int state;

	public MethodPatternAdapter(int api, int access, String desc, MethodVisitor methodVisitor) {
		super(api, methodVisitor);
	}

	@Override
	public void visitInsn(int opcode) {
		this.visitInsn();
		super.visitInsn(opcode);
	}

	@Override
	public void visitIntInsn(int opcode, int operand) {
		this.visitInsn();
		super.visitIntInsn(opcode, operand);
	}

	@Override
	public void visitVarInsn(int opcode, int var) {
		this.visitInsn();
		super.visitVarInsn(opcode, var);
	}

	@Override
	public void visitTypeInsn(int opcode, String type) {
		this.visitInsn();
		super.visitTypeInsn(opcode, type);
	}

	@Override
	public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
		this.visitInsn();
		super.visitFieldInsn(opcode, owner, name, descriptor);
	}

	@Override
	public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
		this.visitInsn();
		super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
	}

	@Override
	public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrapMethodHandle, Object... bootstrapMethodArguments) {
		this.visitInsn();
		super.visitInvokeDynamicInsn(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments);
	}

	@Override
	public void visitJumpInsn(int opcode, Label label) {
		this.visitInsn();
		super.visitJumpInsn(opcode, label);
	}

	@Override
	public void visitLdcInsn(Object value) {
		this.visitInsn();
		super.visitLdcInsn(value);
	}

	@Override
	public void visitIincInsn(int var, int increment) {
		this.visitInsn();
		super.visitIincInsn(var, increment);
	}

	@Override
	public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
		this.visitInsn();
		super.visitTableSwitchInsn(min, max, dflt, labels);
	}

	@Override
	public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
		this.visitInsn();
		super.visitLookupSwitchInsn(dflt, keys, labels);
	}

	@Override
	public void visitMultiANewArrayInsn(String descriptor, int numDimensions) {
		this.visitInsn();
		super.visitMultiANewArrayInsn(descriptor, numDimensions);
	}

	@Override
	public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
		this.visitInsn();
		super.visitTryCatchBlock(start, end, handler, type);
	}

	@Override
	public void visitLabel(Label label) {
		this.visitInsn();
		super.visitLabel(label);
	}

	@Override
	public void visitFrame(int type, int numLocal, Object[] local, int numStack, Object[] stack) {
		this.visitInsn();
		super.visitFrame(type, numLocal, local, numStack, stack);
	}

	@Override
	public void visitMaxs(int maxStack, int maxLocals) {
		this.visitInsn();
		super.visitMaxs(maxStack, maxLocals);
	}

	protected void visitInsn() {
	}
}
