package cn.sky.skylicense.encrypt;

import cn.sky.skylicense.SkyLicense;
import com.google.common.base.CharMatcher;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ThreadLocalRandom;

public class MethodEncrypter extends MethodPatternAdapter {
	private static final Type OBJECT_TYPE = Type.getObjectType("java/lang/Object");
	private static final char CALL_STATIC_VOID_VOID = 'I';  // 静态方法，无返回值，无参数
	private static final char CALL_STATIC_OBJECT_VOID = 'i';  // 静态方法，无返回值，有参数
	private static final char CALL_STATIC_VOID_OBJECT = '0';  // 静态方法，无返回值，有参数，参数为Object
	private static final char CALL_STATIC_OBJECT_OBJECT = 'O';  // 静态方法，有返回值，有参数，参数为Object
	private static final char CALL_VIRTUAL_VOID = '1';  // 虚方法，无返回值
	private static final char CALL_VIRTUAL_OBJECT = '|';  // 虚方法，有返回值
	private static final char STRING_ENCRYPT = 'l';  // 字符串加密
	private static final char INVALID = ' ';  // 无效指令
	private final EncryptClassVisitor cv;
	private static final int SEEN_ALOAD = 1;  // 已加载本地变量
	private static final int SEEN_ACONST_NULL = 2;  // 已加载null
	private static final int SEEN_LDC_STRING = 3;  // 已加载字符串
	private int var;
	private String cst;
	private final boolean thisIsStatic;

	public MethodEncrypter(int api, int access, String desc, MethodVisitor methodVisitor, EncryptClassVisitor classVisitor) {
		super(api, access, desc, methodVisitor);
		this.cv = classVisitor;
		this.thisIsStatic = (access & 8) != 0;
	}

	private void writeGetAuthLib() {
		this.mv.visitFieldInsn(Opcodes.GETSTATIC, this.cv.getClassName(), "authLib", "L" + this.cv.getInterfaceName() + ";");
	}

	private void writeLoadRandomValue() {
		int random = ThreadLocalRandom.current().nextInt();
		if (this.thisIsStatic || random % 4 == 0) {
			this.mv.visitLdcInsn("@" + this.cv.getPluginName() + "@" + Base64.getEncoder().encodeToString(String.valueOf(random).getBytes(StandardCharsets.UTF_8)));
		} else {
			this.mv.visitVarInsn(Opcodes.ALOAD, 0);
		}
	}

	@Override
	public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
		try {
			CharMatcher matcher = CharMatcher.ascii();
			if (matcher.matchesAllOf(owner) && matcher.matchesAllOf(name) && matcher.matchesAllOf(desc)) {
				boolean returnVoid = false;
				Type returnType = Type.getReturnType(desc);
				if (returnType.equals(Type.VOID_TYPE)) {
					returnVoid = true;
				} else if (returnType.getSort() != 10) {
					super.visitMethodInsn(opcode, owner, name, desc, itf);
					return;
				}

				Type[] argTypes = Type.getArgumentTypes(desc);
				if (argTypes.length > 1) {
					super.visitMethodInsn(opcode, owner, name, desc, itf);
				} else {
					char funcType = (char) 32;
					if (argTypes.length == 0 && opcode == Opcodes.INVOKESTATIC) {
						this.visitInsn();
						funcType = (char) (returnVoid ? 73 : 48);
						String hash = this.cv.addMethod(owner, name, desc, funcType);
						this.writeGetAuthLib();
						this.writeLoadRandomValue();
						this.mv.visitLdcInsn("@" + this.cv.getPluginName() + "@" + funcType + hash);
						this.mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, this.cv.getInterfaceName(), "authenticate", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;", true);
						if (returnVoid) {
							this.mv.visitInsn(Opcodes.POP);
						} else if (!returnType.equals(OBJECT_TYPE)) {
							this.mv.visitTypeInsn(Opcodes.CHECKCAST, returnType.getInternalName());
						}
					} else {
						if (argTypes.length == 1 && opcode == Opcodes.INVOKESTATIC && argTypes[0].getSort() == 10) {
							funcType = (char) (returnVoid ? 105 : 79);
						} else if (argTypes.length == 0 && opcode == Opcodes.INVOKEVIRTUAL) {
							funcType = (char) (returnVoid ? 49 : 124);
						}

						if (funcType != ' ' && this.state != 0) {
							String hash = this.cv.addMethod(owner, name, desc, funcType);
							this.writeGetAuthLib();
							switch (this.state) {
								case 1 -> this.mv.visitVarInsn(Opcodes.ALOAD, this.var);
								case 2 -> this.mv.visitInsn(Opcodes.F_APPEND);
								case 3 -> {
									this.writeGetAuthLib();
									this.writeLoadRandomValue();
									String stringHash = this.cv.addMethod(
											"0@",
											Base64.getEncoder().encodeToString(EncryptUtil.encryptMethodString(
													this.cst.getBytes(StandardCharsets.UTF_8),
													this.cv.getMethodKey())),
											"1",
											'l');
									//SkyLicense.LOG.info("hash:" + stringHash + " -> str:" + this.cst + " base:" + Base64.getEncoder().encodeToString(this.cst.getBytes(StandardCharsets.UTF_8)));
									this.mv.visitLdcInsn("@" + this.cv.getPluginName() + "@" + 'l' + stringHash);
									this.mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, this.cv.getInterfaceName(), "authenticate", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;", true);
									this.mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String");
								}
							}

							this.mv.visitLdcInsn("@" + this.cv.getPluginName() + "@" + funcType + hash);
							this.mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, this.cv.getInterfaceName(), "authenticate", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;", true);
							if (returnVoid) {
								this.mv.visitInsn(Opcodes.POP);
							} else if (!returnType.equals(OBJECT_TYPE)) {
								this.mv.visitTypeInsn(Opcodes.CHECKCAST, returnType.getInternalName());
							}

							this.state = 0;
						} else {
							super.visitMethodInsn(opcode, owner, name, desc, itf);
						}
					}
				}
			} else {
				super.visitMethodInsn(opcode, owner, name, desc, itf);
			}
		} catch (Exception e) {
			SkyLicense.LOG.error("visitMethodInsn error", e);
		}
	}

	@Override
	public void visitVarInsn(int opcode, int var) {
		if (opcode == Opcodes.ALOAD) {
            switch (this.state) {
                case 0 -> {
                    this.state = 1;
                    this.var = var;
                    return;
                }
                case 1 -> {
                    this.mv.visitVarInsn(Opcodes.ALOAD, this.var);
                    this.var = var;
                    return;
                }
                case 2 -> {
                    this.mv.visitInsn(Opcodes.F_APPEND);
                    this.state = 1;
                    this.var = var;
                    return;
                }
                case 3 -> {
                    this.mv.visitLdcInsn(this.cst);
                    this.state = 1;
                    this.var = var;
                    return;
                }
            }
		}

		super.visitVarInsn(opcode, var);
	}

	@Override
	public void visitLdcInsn(Object cst) {
		if (cst instanceof String) {
            switch (this.state) {
                case 0 -> {
                    this.state = 3;
                    this.cst = (String) cst;
                    return;
                }
                case 1 -> {
                    this.mv.visitVarInsn(Opcodes.ALOAD, this.var);
                    this.state = 3;
                    this.cst = (String) cst;
                    return;
                }
                case 2 -> {
                    this.mv.visitInsn(Opcodes.F_APPEND);
                    this.state = 3;
                    this.cst = (String) cst;
                    return;
                }
                case 3 -> {
                    this.mv.visitLdcInsn(this.cst);
                    this.cst = (String) cst;
                    return;
                }
            }
		}

		super.visitLdcInsn(cst);
	}

	@Override
	public void visitInsn(int opcode) {
		if (opcode == Opcodes.F_APPEND) {
            switch (this.state) {
                case 0 -> {
                    this.state = 2;
                    return;
                }
                case 1 -> {
                    this.mv.visitVarInsn(Opcodes.ALOAD, this.var);
                    this.state = 2;
                    return;
                }
                case 2 -> {
                    this.mv.visitInsn(Opcodes.F_APPEND);
                    return;
                }
                case 3 -> {
                    this.mv.visitLdcInsn(this.cst);
                    this.state = 2;
                    return;
                }
            }
		}

		super.visitInsn(opcode);
	}

	@Override
	protected void visitInsn() {
        switch (this.state) {
            case 1 -> this.mv.visitVarInsn(Opcodes.ALOAD, this.var);
            case 2 -> this.mv.visitInsn(Opcodes.F_APPEND);
            case 3 -> {
                if (this.cst.isEmpty()) {
                    this.mv.visitLdcInsn(this.cst);
                } else {
                    this.writeGetAuthLib();
                    this.writeLoadRandomValue();
					String hash = null;
					try {
						hash = this.cv.addMethod(
								"0@",
								Base64.getEncoder().encodeToString(EncryptUtil.encryptMethodString(
										this.cst.getBytes(StandardCharsets.UTF_8),
										this.cv.getMethodKey())),
								"1",
								'l');
					} catch (Exception e) {
						SkyLicense.LOG.error("visitInsn error", e);
					}
					this.mv.visitLdcInsn("@" + this.cv.getPluginName() + "@" + 'l' + hash);
                    this.mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, this.cv.getInterfaceName(), "authenticate", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;", true);
                    this.mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String");
                }
            }
        }

		this.state = 0;
	}
}
