package cn.sky.license;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.UUID;
import java.util.regex.Pattern;

public class SkyLicense extends ClassLoader {
    private static final byte[] START = new byte[]{-54, -2, -70, -66, 0, 0, 0, 52, 0, 28, 10, 0, 4, 0, 21, 10, 0, 22, 0, 23, 7, 0, 24, 7, 0, 25, 7, 0, 26, 1, 0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100, 101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101, 1, 0, 18, 76, 111, 99, 97, 108, 86, 97, 114, 105, 97, 98, 108, 101, 84, 97, 98, 108, 101, 1, 0, 4, 116, 104, 105, 115, 1, 0, 32, 76, 99, 110, 47, 115, 107, 121, 47, 108, 105, 99, 101, 110, 115, 101, 47, 97, 117, 116, 104, 108, 105, 98, 47, 65, 117, 116, 104, 76, 105, 98, 59, 1, 0, 4, 108, 111, 97, 100, 1, 0, 21, 40, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 86, 1, 0, 4, 110, 97, 109, 101, 1, 0, 18, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 1, 0, 12, 97, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116, 101, 1, 0, 56, 40, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 59, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 59, 1, 0, 10, 83, 111, 117, 114, 99, 101, 70, 105, 108, 101, 1, 0, 12, 65, 117, 116, 104, 76, 105, 98, 46, 106, 97, 118, 97, 12, 0, 6, 0, 7, 7, 0, 27, 12, 0, 13, 0, 14, 1, 0, 30, 99, 110, 47, 115, 107, 121, 47, 108, 105, 99, 101, 110, 115, 101, 47, 97, 117, 116, 104, 108, 105, 98, 47, 65, 117, 116, 104, 76, 105, 98, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 1};

    private static final byte[] END = new byte[]{1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 121, 115, 116, 101, 109, 0, 33, 0, 3, 0, 4, 0, 1, 0, 5, 0, 0, 0, 3, 0, 1, 0, 6, 0, 7, 0, 1, 0, 8, 0, 0, 0, 47, 0, 1, 0, 1, 0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0, 2, 0, 9, 0, 0, 0, 6, 0, 1, 0, 0, 0, 3, 0, 10, 0, 0, 0, 12, 0, 1, 0, 0, 0, 5, 0, 11, 0, 12, 0, 0, 0, 1, 0, 13, 0, 14, 0, 1, 0, 8, 0, 0, 0, 61, 0, 1, 0, 2, 0, 0, 0, 5, 43, -72, 0, 2, -79, 0, 0, 0, 2, 0, 9, 0, 0, 0, 10, 0, 2, 0, 0, 0, 6, 0, 4, 0, 7, 0, 10, 0, 0, 0, 22, 0, 2, 0, 0, 0, 5, 0, 11, 0, 12, 0, 0, 0, 0, 0, 5, 0, 15, 0, 16, 0, 1, 1, 1, 0, 17, 0, 18, 0, 0, 0, 1, 0, 19, 0, 0, 0, 2, 0, 20};

    private static final int MAX_LICENSE_FILE_BYTES = 1024 * 1024;
    private static final int MAX_NATIVE_LIBRARY_BYTES = 128 * 1024 * 1024;
    private static final int INTEGRITY_MANIFEST_BYTES = 160;
    private static final int DEFAULT_AUTH_PORT = 13331;
    private static final long STALE_ARTIFACT_MILLIS = 7L * 24 * 60 * 60 * 1000;
    private static final Pattern SAFE_IDENTITY_PATTERN =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+\\-]{0,63}");

    // Protected classes are rewritten to read this field through GETSTATIC.
    public static volatile IAuthLib authLib;
    private final PluginProxy pluginProxy;

    @SuppressWarnings("this-escape") // defineClass uses this ClassLoader but does not publish it.
    public SkyLicense(PluginProxy pluginProxy) {
        super(pluginProxy.getClass().getClassLoader());
        this.pluginProxy = pluginProxy;
        String osName = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        String uniqueId = UUID.randomUUID().toString().replace("-", "");
        uniqueId = pluginProxy.getResourceType() == Resource.CLEAR_LOWERCASE || pluginProxy.getResourceType() == Resource.SAVE_LOWERCASE
                ? uniqueId.toLowerCase()
                : uniqueId.toUpperCase();
        File dataFolder = pluginProxy.getDataFolder();

        String libraryFileName;
        if (osName.contains("win")) {
            libraryFileName = String.format("SkyLicense_%s.dll", arch.contains("64") ? "64" : "32");
        } else if (osName.contains("nix") || osName.contains("nux")) {
            libraryFileName = String.format("libSkyLicense_%s.so", arch.contains("64") ? "64" : "32");
        } else {
            throw new IllegalStateException("Unsupported operating system: " + osName);
        }

        Path extractedLibrary = null;
        Path extractedManifest = null;
        try {
            Path libFolder = prepareNativeDirectory(dataFolder.toPath());
            cleanupStaleArtifacts(libFolder);
            Path libFile = libFolder.resolve(
                    uniqueId + (osName.contains("win") ? ".dll" : ".so"));
            Path manifestFile = libFolder.resolve(libFile.getFileName() + ".integrity");
            extractedLibrary = libFile;
            extractedManifest = manifestFile;
            extractRequiredResource(libraryFileName, libFile, MAX_NATIVE_LIBRARY_BYTES);
            extractRequiredResource(
                    libraryFileName + ".integrity",
                    manifestFile,
                    INTEGRITY_MANIFEST_BYTES);
            if (Files.size(manifestFile) != INTEGRITY_MANIFEST_BYTES) {
                throw new IOException("Invalid native integrity manifest length");
            }
            restrictArtifactPermissions(libFile, true);
            restrictArtifactPermissions(manifestFile, false);

            String className = IAuthLib.class.getName().replace(".", "/");
            byte[] classData = new byte[START.length + 2 + className.length() * 3 + END.length];
            System.arraycopy(START, 0, classData, 0, START.length);

            int length = className.length();
            int offset = START.length;
            classData[offset++] = 0;
            classData[offset++] = (byte) length;
            for (int i = 0; i < length; i++) {
                char c = className.charAt(i);
                classData[offset++] = (byte) c;
            }

            System.arraycopy(END, 0, classData, offset, END.length);
            offset += END.length;
            byte[] encryptedClass = {
                    0x63 ^ 0x5A, 0x6E ^ 0x5A, 0x2E ^ 0x5A,
                    0x73 ^ 0x5A, 0x6B ^ 0x5A, 0x79 ^ 0x5A, 0x2E ^ 0x5A,
                    0x6C ^ 0x5A, 0x69 ^ 0x5A, 0x63 ^ 0x5A, 0x65 ^ 0x5A, 0x6E ^ 0x5A, 0x73 ^ 0x5A, 0x65 ^ 0x5A, 0x2E ^ 0x5A,
                    0x61 ^ 0x5A, 0x75 ^ 0x5A, 0x74 ^ 0x5A, 0x68 ^ 0x5A, 0x6C ^ 0x5A, 0x69 ^ 0x5A, 0x62 ^ 0x5A, 0x2E ^ 0x5A,
                    0x41 ^ 0x5A, 0x75 ^ 0x5A, 0x74 ^ 0x5A, 0x68 ^ 0x5A, 0x4C ^ 0x5A, 0x69 ^ 0x5A, 0x62 ^ 0x5A
            };
            StringBuilder sb = new StringBuilder();
            for (byte b : encryptedClass) {
                sb.append((char) (b ^ 0x5A));
            }
            String authLibClassName = sb.toString();
            Class<?> clazz = this.defineClass(authLibClassName, classData, 0, offset);
            authLib = (IAuthLib) clazz.getDeclaredConstructor().newInstance();
            authLib.load(libFile.toAbsolutePath().toString());

        } catch (Exception e) {
            deleteFailedExtraction(extractedManifest, e);
            deleteFailedExtraction(extractedLibrary, e);
            throw new IllegalStateException("Failed to initialize signed native authentication library", e);
        }
    }

    private void extractRequiredResource(String resourceName, Path destination, int maximumBytes)
            throws IOException {
        try (InputStream input = getClass().getResourceAsStream("/" + resourceName)) {
            if (input == null) {
                throw new FileNotFoundException("Required resource " + resourceName + " was not found");
            }
            Path temporary = Files.createTempFile(
                    destination.getParent(), ".sky-native-", ".part");
            try {
                restrictOwnerOnly(temporary, true, false);
                try (FileChannel channel = FileChannel.open(
                        temporary,
                        StandardOpenOption.WRITE,
                        StandardOpenOption.TRUNCATE_EXISTING,
                        LinkOption.NOFOLLOW_LINKS);
                     OutputStream output = Channels.newOutputStream(channel)) {
                    byte[] buffer = new byte[8192];
                    int read;
                    int total = 0;
                    while ((read = input.read(buffer)) != -1) {
                        total = Math.addExact(total, read);
                        if (total > maximumBytes) {
                            throw new IOException("Required resource " + resourceName + " is too large");
                        }
                        output.write(buffer, 0, read);
                    }
                    output.flush();
                    channel.force(true);
                } catch (ArithmeticException error) {
                    throw new IOException("Required resource length overflow", error);
                }
                try {
                    Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE);
                } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
                    Files.move(temporary, destination);
                }
            } finally {
                Files.deleteIfExists(temporary);
            }
        }
    }

    static Path prepareNativeDirectory(Path dataDirectory) throws IOException {
        Path normalized = dataDirectory.toAbsolutePath().normalize();
        rejectLinkComponents(normalized);
        Files.createDirectories(normalized);
        rejectLinkComponents(normalized);

        Path nativeDirectory = normalized.resolve("authlib");
        if (Files.exists(nativeDirectory, LinkOption.NOFOLLOW_LINKS)
                && !Files.isDirectory(nativeDirectory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Native library path is not a directory");
        }
        Files.createDirectories(nativeDirectory);
        rejectLinkComponents(nativeDirectory);
        // The directory itself is part of the load trust boundary. File ACLs
        // alone do not stop another account with directory write permission
        // from renaming a verified artifact between extraction and System.load.
        restrictOwnerOnly(nativeDirectory, true, true);
        rejectLinkComponents(nativeDirectory);
        return nativeDirectory;
    }

    private static void rejectLinkComponents(Path path) throws IOException {
        Path current = path.getRoot();
        for (Path component : path) {
            current = current == null ? component : current.resolve(component);
            if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                continue;
            }
            BasicFileAttributes attributes = Files.readAttributes(
                    current,
                    BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(current) || attributes.isOther()) {
                throw new IOException("Symbolic link or reparse component is not allowed: " + current);
            }
        }
    }

    private static void cleanupStaleArtifacts(Path directory) throws IOException {
        long cutoff = System.currentTimeMillis() - STALE_ARTIFACT_MILLIS;
        try (java.nio.file.DirectoryStream<Path> files = Files.newDirectoryStream(directory)) {
            for (Path file : files) {
                String name = file.getFileName().toString();
                if ((name.endsWith(".dll") || name.endsWith(".so") || name.endsWith(".integrity"))
                        && Files.getLastModifiedTime(file, LinkOption.NOFOLLOW_LINKS).toMillis() < cutoff) {
                    try {
                        Files.deleteIfExists(file);
                    } catch (java.nio.file.AccessDeniedException ignored) {
                        // A still-loaded Windows DLL is expected to remain until process exit.
                    }
                }
            }
        }
    }

    private static void restrictArtifactPermissions(Path path, boolean executable) throws IOException {
        restrictOwnerOnly(path, false, executable);
    }

    private static void restrictOwnerOnly(
            Path path,
            boolean writable,
            boolean executable
    ) throws IOException {
        PosixFileAttributeView posix = Files.getFileAttributeView(
                path,
                PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            EnumSet<PosixFilePermission> permissions = EnumSet.of(PosixFilePermission.OWNER_READ);
            if (writable) {
                permissions.add(PosixFilePermission.OWNER_WRITE);
            }
            if (executable) {
                permissions.add(PosixFilePermission.OWNER_EXECUTE);
            }
            Files.setPosixFilePermissions(path, permissions);
            return;
        }

        AclFileAttributeView acl = Files.getFileAttributeView(
                path,
                AclFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (acl != null) {
            UserPrincipal owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS);
            EnumSet<AclEntryPermission> permissions = EnumSet.of(
                    AclEntryPermission.READ_DATA,
                    AclEntryPermission.READ_ATTRIBUTES,
                    AclEntryPermission.READ_NAMED_ATTRS,
                    AclEntryPermission.READ_ACL,
                    AclEntryPermission.SYNCHRONIZE,
                    AclEntryPermission.DELETE);
            if (writable) {
                permissions.add(AclEntryPermission.WRITE_DATA);
                permissions.add(AclEntryPermission.APPEND_DATA);
                permissions.add(AclEntryPermission.WRITE_ATTRIBUTES);
                permissions.add(AclEntryPermission.WRITE_NAMED_ATTRS);
                permissions.add(AclEntryPermission.WRITE_ACL);
            }
            if (executable) {
                permissions.add(AclEntryPermission.EXECUTE);
            }
            AclEntry ownerEntry = AclEntry.newBuilder()
                    .setType(AclEntryType.ALLOW)
                    .setPrincipal(owner)
                    .setPermissions(permissions)
                    .build();
            acl.setAcl(Collections.singletonList(ownerEntry));
            return;
        }

        File file = path.toFile();
        if (!file.setReadable(false, false)
                || !file.setWritable(false, false)
                || !file.setExecutable(false, false)
                || !file.setReadable(true, true)
                || (writable && !file.setWritable(true, true))
                || (executable && !file.setExecutable(true, true))) {
            throw new IOException("Unable to restrict native artifact permissions: " + path);
        }
    }

    private static void deleteFailedExtraction(Path path, Exception failure) {
        if (path == null) {
            return;
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException cleanupError) {
            failure.addSuppressed(cleanupError);
        }
    }

    public String decryptAuthCode(byte[] encryptedData) {
        try {
            return LicenseFileCodec.decode(
                    encryptedData,
                    LicenseFileCodec.secretFromEnvironment());
        } catch (IllegalStateException error) {
            throw error;
        } catch (Exception e) {
            return null;
        }
    }


    public String read() {
        try {
            byte[] encryptedData;
            try (InputStream inputStream = SkyLicense.class.getClassLoader()
                    .getResourceAsStream("license.dat")) {
                if (inputStream == null) {
                    pluginProxy.info("Authorization dat does not exist!");
                    return null;
                }

                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                int nRead;
                int total = 0;
                byte[] data = new byte[4096];
                while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
                    total = Math.addExact(total, nRead);
                    if (total > MAX_LICENSE_FILE_BYTES) {
                        pluginProxy.info("Authorization dat is too large.");
                        return null;
                    }
                    buffer.write(data, 0, nRead);
                }
                encryptedData = buffer.toByteArray();
            }

            if (encryptedData.length == 0) {
                pluginProxy.info("Your authorization dat is wrong.");
                return null;
            }


            String authCode;
            try {
                authCode = decryptAuthCode(encryptedData);
            } finally {
                Arrays.fill(encryptedData, (byte) 0);
            }
            if (authCode == null || authCode.isEmpty()) {
                pluginProxy.info("Your authorization dat is wrong.");
                return null;
            }
            pluginProxy.info("Successfully read the authorization dat.");

            return authCode;

        } catch (IllegalStateException error) {
            throw error;
        } catch (Exception e) {
            pluginProxy.info("Your authorization dat is wrong.");
            return null;
        }
    }

    public Response authenticate(String authHost, String pluginName, String version) {
        try {
            URI endpoint = new URI("tls://" + authHost);
            String host = endpoint.getHost();
            int port = endpoint.getPort() < 0 ? DEFAULT_AUTH_PORT : endpoint.getPort();
            if (host == null || endpoint.getUserInfo() != null || endpoint.getQuery() != null
                    || endpoint.getFragment() != null || !endpoint.getPath().isEmpty()) {
                throw new IllegalArgumentException("Invalid authentication endpoint");
            }
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            } else if (host.indexOf(':') < 0) {
                host = IDN.toASCII(host);
            }
            return authenticate(host, port, pluginName, version);
        } catch (URISyntaxException error) {
            throw new IllegalArgumentException("Invalid authentication endpoint", error);
        }
    }

    public Response authenticate(String authHost, int port, String pluginName, String version) {
        String token = read();
        if (token == null) {
            return Response.RESOURCE_ERROR_UNCOMPRESS;
        }

        if (authHost == null || authHost.trim().isEmpty() || authHost.length() > 253
                || authHost.indexOf('@') >= 0 || port < 1 || port > 65535
                || pluginName == null || !SAFE_IDENTITY_PATTERN.matcher(pluginName).matches()
                || version == null || !SAFE_IDENTITY_PATTERN.matcher(version).matches()
                || token.indexOf('@') >= 0) {
            throw new IllegalArgumentException(
                    "authentication endpoint and plugin identity are invalid");
        }
        Object result = authLib.authenticate(this, authHost + '@' + port + '@' + pluginName + '@' + version + '@' + token + "$$" + SkyLicense.class.getName().replace(".", "/") + "$$" + IAuthLib.class.getName().replace(".", "/"));
        return Response.translate((String) result);
    }

    public interface IAuthLib {
        void load(String name);

        Object authenticate(Object var1, String var2);
    }

}
