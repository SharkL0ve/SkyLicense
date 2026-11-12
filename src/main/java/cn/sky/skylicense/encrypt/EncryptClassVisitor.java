package cn.sky.skylicense.encrypt;

import cn.sky.skylicense.resource.MethodInfo;
import lombok.Getter;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.tree.ClassNode;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@Getter
public class EncryptClassVisitor extends ClassVisitor {
	private final String pluginName;
	private final byte[] methodKey;
	private final String className;
	private final String interfaceName;
	private final Map<String, MethodInfo> encryptMethods;

	public EncryptClassVisitor(
			ClassNode classNode,
			String pluginName,
			byte[] methodKey,
			String className,
			String interfaceName,
			Map<String, MethodInfo> encryptMethods
	) {
		super(589824, classNode);
		this.pluginName = pluginName;
		this.methodKey = methodKey;
		this.className = className;
		this.interfaceName = interfaceName;
		this.encryptMethods = encryptMethods;
	}

	@Override
	public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
		MethodVisitor mv = this.cv.visitMethod(access, name, desc, signature, exceptions);
		if (mv != null && !"<init>".equals(name) && !"<clinit>".equals(name)) {
			boolean isAbstractMethod = (access & 1024) != 0;
			boolean isNativeMethod = (access & 256) != 0;
			if (!isAbstractMethod && !isNativeMethod) {
				mv = new MethodEncrypter(589824, access, desc, mv, this);
			}
		}

		return mv;
	}

	public String addMethod(String className, String methodName, String desc, char type) throws Exception {
		MethodInfo methodInfo = new MethodInfo();
		methodInfo.setClassName(className);
		methodInfo.setMethodName(methodName);
		methodInfo.setType(type);
		methodInfo.setMethodDesc(desc);
		UUID uuid = UUID.randomUUID();

		String hash;
		for (hash = this.uuidToBase64(uuid); this.encryptMethods.containsKey(hash + type); hash = this.uuidToBase64(uuid)) {
			uuid = UUID.randomUUID();
		}

		//SkyLicense.LOG.info("key:" + hash + " -> info:" + methodInfo);
		this.encryptMethods.put(hash + type, methodInfo);
		return Base64.getEncoder().encodeToString(
				EncryptUtil.encryptMethodLookup(hash.getBytes(StandardCharsets.UTF_8), this.methodKey));
	}

	public String uuidToBase64(UUID uuid) {
		ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
		bb.putLong(uuid.getMostSignificantBits());
		bb.putLong(uuid.getLeastSignificantBits());
		return Base64.getEncoder().encodeToString(bb.array());
	}

}
