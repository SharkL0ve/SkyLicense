package cn.sky.skylicense.resource;

import cn.sky.skylicense.SkyLicense;
import com.google.re2j.Pattern;
import lombok.Data;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

@Data
public class Resource {
    private static final String PROFILE_ENTRY = "settings.yml";
    private static final int MAX_JAR_ENTRIES = 20_000;
    private static final long MAX_JAR_FILE_BYTES = 64L * 1024 * 1024;
    private static final int MAX_CLASS_BYTES = 16 * 1024 * 1024;
    private static final int MAX_TOTAL_CLASS_BYTES = 64 * 1024 * 1024;
    private static final int MAX_PROFILE_BYTES = 64 * 1024;
    private static final int MAX_CLASS_NAME_BYTES = 1_024;
    private static final int MAX_KEEP_PATTERNS = 256;
    private static final int MAX_PATTERN_CHARACTERS = 512;
    private static final Pattern SAFE_IDENTITY_PATTERN =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+\\-]{0,63}");

    private String identifier;
    private String contentSha256;
    private EntryInfo entryInfo;
    private List<ByteCode> byteCodes;

    public static Resource fromJar(File file, boolean logDetails) {
        try {
            if (file == null
                    || !Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("resource JAR must be a regular file");
            }
            long fileSize = Files.size(file.toPath());
            if (fileSize <= 0 || fileSize > MAX_JAR_FILE_BYTES) {
                throw new IOException("resource JAR must not exceed 64 MiB");
            }
        } catch (Exception error) {
            SkyLicense.LOG.error("Rejected invalid or unsafe resource JAR: " + file, error);
            return null;
        }
        try (JarFile jar = new JarFile(file, false)) {
            return readJar(jar, logDetails);
        } catch (Exception error) {
            SkyLicense.LOG.error("Rejected invalid or unsafe resource JAR: " + file, error);
            return null;
        }
    }

    private static Resource readJar(JarFile jar, boolean logDetails) throws Exception {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        DirectedGraph graph = new DirectedGraph();
        EntryInfo info = null;
        byte[] profileDigest = null;
        boolean profileSeen = false;
        int entryCount = 0;
        int totalClassBytes = 0;

        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            entryCount = Math.addExact(entryCount, 1);
            if (entryCount > MAX_JAR_ENTRIES) {
                throw new IOException("resource JAR contains too many entries");
            }
            if (entry.isDirectory()) {
                continue;
            }

            String name = entry.getName();
            if (name.endsWith(".class")) {
                String className = validateClassEntryName(name);
                byte[] code;
                try (InputStream input = jar.getInputStream(entry)) {
                    code = readBounded(input, MAX_CLASS_BYTES, "class entry");
                }
                totalClassBytes = Math.addExact(totalClassBytes, code.length);
                if (totalClassBytes > MAX_TOTAL_CLASS_BYTES) {
                    throw new IOException("resource JAR expands beyond the class-data limit");
                }
                ClassReader reader = new ClassReader(code);
                if (!reader.getClassName().equals(className)) {
                    throw new IOException("class entry name does not match its bytecode name");
                }
                if (classes.putIfAbsent(className, code) != null) {
                    throw new IOException("resource JAR contains a duplicate class");
                }
                graph.putNode(className);
            } else if (PROFILE_ENTRY.equals(name)) {
                if (profileSeen) {
                    throw new IOException("resource JAR contains duplicate settings.yml entries");
                }
                profileSeen = true;
                byte[] profile;
                try (InputStream input = jar.getInputStream(entry)) {
                    profile = readBounded(input, MAX_PROFILE_BYTES, "settings.yml");
                }
                try {
                    profileDigest = MessageDigest.getInstance("SHA-256").digest(profile);
                    info = parseProfile(profile);
                } finally {
                    java.util.Arrays.fill(profile, (byte) 0);
                }
            }
        }

        validateProfile(info);
        validateEntryPoint(info, classes);
        List<Pattern> keepPatterns = compileKeepPatterns(info.getKeepClasses());
        Map<String, Set<String>> dependencies = new HashMap<>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            ClassReader reader = new ClassReader(entry.getValue());
            String superClassName = reader.getSuperName();
            if (classes.containsKey(superClassName)) {
                dependencies.computeIfAbsent(entry.getKey(), ignored -> new HashSet<>())
                        .add(superClassName);
            }
            for (String interfaceName : reader.getInterfaces()) {
                if (classes.containsKey(interfaceName)) {
                    dependencies.computeIfAbsent(entry.getKey(), ignored -> new HashSet<>())
                            .add(interfaceName);
                }
            }
        }
        for (Map.Entry<String, Set<String>> entry : dependencies.entrySet()) {
            for (String dependency : entry.getValue()) {
                graph.addEdge(entry.getKey(), dependency);
            }
        }

        List<ByteCode> byteCodes = new ArrayList<>(classes.size());
        for (String className : graph.topoSort()) {
            byte[] code = classes.get(className);
            if (code == null) {
                throw new IOException("dependency graph referenced a missing class");
            }
            ByteCode byteCode = new ByteCode();
            byteCode.setCode(code);
            byteCode.setClassName(className);
            for (Pattern pattern : keepPatterns) {
                if (pattern.matcher(className).matches()) {
                    byteCode.setKeep(true);
                    break;
                }
            }
            byteCodes.add(byteCode);
        }

        if (logDetails) {
            SkyLicense.LOG.info(
                    "File - {} - Inclusion Class - {} - bytes - {}",
                    jar.getName(), byteCodes.size(), totalClassBytes);
            SkyLicense.LOG.info(
                    " -> Plugin: {}, Version: {}, Entry: {}({})",
                    info.getName(), info.getVersion(), info.getEntryClass(), info.getEntryPoint());
        }

        Resource resource = new Resource();
        resource.setIdentifier(ResourceManager.identifier(info.getName(), info.getVersion()));
        resource.setContentSha256(contentSha256(profileDigest, classes));
        resource.setEntryInfo(info);
        resource.setByteCodes(byteCodes);
        return resource;
    }

    private static String contentSha256(
            byte[] profileDigest,
            Map<String, byte[]> classes
    ) throws Exception {
        if (profileDigest == null) {
            throw new IOException("settings.yml content digest is missing");
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update("SkyLicense protected resource v1\0"
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        updateDigest(digest, profileDigest);
        for (Map.Entry<String, byte[]> entry : new TreeMap<>(classes).entrySet()) {
            updateDigest(
                    digest,
                    entry.getKey().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            updateDigest(digest, entry.getValue());
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void updateDigest(MessageDigest digest, byte[] value) {
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value.length).array());
        digest.update(value);
    }

    private static EntryInfo parseProfile(byte[] profile) {
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        options.setAllowRecursiveKeys(false);
        options.setMaxAliasesForCollections(10);
        options.setNestingDepthLimit(20);
        options.setCodePointLimit(MAX_PROFILE_BYTES);
        options.setTagInspector(tag -> false);
        Yaml yaml = new Yaml(new Constructor(EntryInfo.class, options));
        return yaml.load(new ByteArrayInputStream(profile));
    }

    private static void validateProfile(EntryInfo info) throws IOException {
        if (info == null
                || !isSafeIdentity(info.getName())
                || !isSafeIdentity(info.getVersion())
                || !isBoundedText(info.getEntryClass(), 512)
                || !isBoundedText(info.getEntryPoint(), 128)) {
            throw new IOException(
                    "settings.yml contains missing, unsafe, or oversized identity fields");
        }
        if (info.getKeepClasses() != null && info.getKeepClasses().size() > MAX_KEEP_PATTERNS) {
            throw new IOException("settings.yml contains too many keep patterns");
        }
    }

    private static boolean isSafeIdentity(String value) {
        return value != null && SAFE_IDENTITY_PATTERN.matches(value);
    }

    private static void validateEntryPoint(EntryInfo info, Map<String, byte[]> classes)
            throws IOException {
        byte[] entryClass = classes.get(info.getEntryClass());
        if (entryClass == null) {
            throw new IOException("settings.yml EntryClass is not present in the resource JAR");
        }

        boolean[] validEntryPoint = {false};
        new ClassReader(entryClass).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(
                    int access,
                    String name,
                    String descriptor,
                    String signature,
                    String[] exceptions
            ) {
                int requiredAccess = Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC;
                if (info.getEntryPoint().equals(name)
                        && "()V".equals(descriptor)
                        && (access & requiredAccess) == requiredAccess) {
                    validEntryPoint[0] = true;
                }
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);

        if (!validEntryPoint[0]) {
            throw new IOException(
                    "settings.yml EntryPoint must be a public static no-argument void method");
        }
    }

    private static List<Pattern> compileKeepPatterns(List<String> patterns) throws IOException {
        List<Pattern> compiled = new ArrayList<>();
        if (patterns == null) {
            return compiled;
        }
        for (String pattern : patterns) {
            if (!isBoundedText(pattern, MAX_PATTERN_CHARACTERS)) {
                throw new IOException("settings.yml contains an invalid keep pattern");
            }
            try {
                compiled.add(Pattern.compile(pattern));
            } catch (RuntimeException error) {
                throw new IOException("settings.yml contains an unsupported keep pattern", error);
            }
        }
        return compiled;
    }

    private static String validateClassEntryName(String name) throws IOException {
        if (name.length() <= ".class".length()
                || name.length() > MAX_CLASS_NAME_BYTES
                || name.startsWith("/")
                || name.indexOf('\\') >= 0
                || name.contains("../")
                || name.contains("/./")) {
            throw new IOException("resource JAR contains an unsafe class entry name");
        }
        return name.substring(0, name.length() - ".class".length());
    }

    private static boolean isBoundedText(String value, int maximumCharacters) {
        if (value == null || value.isBlank() || value.length() > maximumCharacters) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            if (Character.isISOControl(value.charAt(index))) {
                return false;
            }
        }
        return true;
    }

    private static byte[] readBounded(InputStream input, int maximumBytes, String field)
            throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(maximumBytes, 8_192));
        byte[] buffer = new byte[8_192];
        int total = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            total = Math.addExact(total, read);
            if (total > maximumBytes) {
                throw new IOException(field + " exceeds its decompressed size limit");
            }
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }
}
