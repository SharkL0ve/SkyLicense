package cn.sky.skylicense.web.service;

import cn.sky.skylicense.resource.EntryInfo;
import cn.sky.skylicense.resource.Resource;
import cn.sky.skylicense.resource.ResourceManager;
import cn.sky.skylicense.security.ResourceCatalog;
import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.ProgramVersion;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResourceUploadServiceTest {
    @TempDir
    Path temporaryDirectory;

    private WebDataAccessor accessor;
    private ResourceUploadService service;
    private WebUser owner;
    private Program program;

    @BeforeEach
    void setUp() throws Exception {
        ResourceManager.removeResource("UploadProduct", "1.0.0");
        accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("upload.db").toString());
        owner = WebUser.builder()
                .username("upload-owner")
                .password("not-used-by-this-test")
                .role("USER")
                .maxPrograms(5)
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getUserDao().create(owner);
        program = Program.builder()
                .userId(owner.getId())
                .name("UploadProduct")
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getProgramDao().create(program);
        service = new ResourceUploadService(accessor, temporaryDirectory.resolve("resources"));
        useOwner();
    }

    @AfterEach
    void tearDown() {
        UserContext.clear();
        ResourceManager.removeResource("UploadProduct", "1.0.0");
        if (accessor != null) {
            accessor.close();
        }
    }

    @Test
    void uploadedProfileMustExactlyMatchProgramAndVersion() {
        Program profileProgram = Program.builder().name("Product").build();
        Resource resource = resource("Product", "1.0.0");

        assertDoesNotThrow(() -> ResourceUploadService.validateResourceIdentity(
                profileProgram, "1.0.0", resource));
        assertThrows(BizException.class, () -> ResourceUploadService.validateResourceIdentity(
                profileProgram, "2.0.0", resource));
        assertThrows(BizException.class, () -> ResourceUploadService.validateResourceIdentity(
                profileProgram, "1.0.0", resource("product", "1.0.0")));
    }

    @Test
    void validJarIsPersistedAndLoadedAsOneVersion() throws Exception {
        ProgramVersion version = service.uploadVersion(
                program.getId(), "1.0.0", multipart("UploadProduct", "1.0.0"));

        assertNotNull(version.getId());
        assertEquals("1.0.0", version.getVersion());
        assertTrue(Files.isRegularFile(Path.of(version.getFilePath())));
        assertTrue(ResourceManager.containsPlugin(
                ResourceManager.identifier("UploadProduct", "1.0.0")));
        assertEquals(1, accessor.getProgramVersionDao().countOf());
        assertEquals(1, jarFiles().size());
    }

    @Test
    void unreferencedJarIsIgnoredAndQuarantinedDuringRecovery() throws Exception {
        Path resourceRoot = temporaryDirectory.resolve("resources");
        Files.createDirectories(resourceRoot);
        Path orphan = resourceRoot.resolve("orphan.jar");
        Files.write(orphan, jarBytes("UploadProduct", "1.0.0"));

        assertTrue(ResourceCatalog.reload(accessor, resourceRoot, false));
        assertFalse(ResourceManager.containsPlugin(
                ResourceManager.identifier("UploadProduct", "1.0.0")));

        assertEquals(1, ResourceCatalog.quarantineUnreferenced(accessor, resourceRoot));
        assertFalse(Files.exists(orphan));
        assertTrue(Files.isDirectory(temporaryDirectory.resolve("resources.quarantine")));
    }

    @Test
    void missingCatalogFileFailsReloadAndPreservesTheActiveSnapshot() throws Exception {
        ProgramVersion version = service.uploadVersion(
                program.getId(), "1.0.0", multipart("UploadProduct", "1.0.0"));
        Files.delete(Path.of(version.getFilePath()));

        assertFalse(ResourceCatalog.reload(
                accessor, temporaryDirectory.resolve("resources"), false));
        assertTrue(ResourceManager.containsPlugin(
                ResourceManager.identifier("UploadProduct", "1.0.0")));
    }

    @Test
    void concurrentUploadsOfTheSameVersionLeaveOneDatabaseRowAndFile() throws Exception {
        byte[] jar = jarBytes("UploadProduct", "1.0.0");
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<Object>> futures = new ArrayList<>();
            for (int index = 0; index < 2; index++) {
                futures.add(executor.submit(() -> {
                    useOwner();
                    try {
                        start.await(5, TimeUnit.SECONDS);
                        return service.uploadVersion(
                                program.getId(),
                                "1.0.0",
                                new BytesMultipartFile(jar, "resource.jar"));
                    } catch (Throwable error) {
                        return error;
                    } finally {
                        UserContext.clear();
                    }
                }));
            }
            start.countDown();
            int successes = 0;
            int conflicts = 0;
            for (Future<Object> future : futures) {
                Object result = future.get(15, TimeUnit.SECONDS);
                if (result instanceof ProgramVersion) {
                    successes++;
                } else {
                    assertInstanceOf(BizException.class, result);
                    conflicts++;
                }
            }
            assertEquals(1, successes);
            assertEquals(1, conflicts);
            assertEquals(1, accessor.getProgramVersionDao().countOf());
            assertEquals(1, jarFiles().size());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void deletingProgramWhileUploadIsInFlightLeavesNoOrphanArtifact() throws Exception {
        byte[] jar = jarBytes("UploadProduct", "1.0.0");
        CountDownLatch firstRead = new CountDownLatch(1);
        CountDownLatch releaseRead = new CountDownLatch(1);
        BlockingMultipartFile upload = new BlockingMultipartFile(jar, firstRead, releaseRead);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Object> uploadResult = executor.submit(() -> {
                useOwner();
                try {
                    return service.uploadVersion(program.getId(), "1.0.0", upload);
                } catch (Throwable error) {
                    return error;
                } finally {
                    UserContext.clear();
                }
            });
            assertTrue(firstRead.await(5, TimeUnit.SECONDS));

            Future<Object> deleteResult = executor.submit(() -> {
                useOwner();
                try {
                    new DataCascadeService(
                            accessor, temporaryDirectory.resolve("resources"))
                            .deleteProgram(program);
                    return null;
                } catch (Throwable error) {
                    return error;
                } finally {
                    UserContext.clear();
                }
            });
            assertEquals(null, deleteResult.get(15, TimeUnit.SECONDS));
            releaseRead.countDown();

            Object result = uploadResult.get(15, TimeUnit.SECONDS);
            assertInstanceOf(BizException.class, result);
            assertEquals(0, accessor.getProgramVersionDao().countOf());
            assertEquals(0, jarFiles().size());
            assertFalse(Files.exists(temporaryDirectory.resolve("resources.quarantine")));
        } finally {
            releaseRead.countDown();
            executor.shutdownNow();
        }
    }

    private static Resource resource(String name, String version) {
        EntryInfo entryInfo = new EntryInfo();
        entryInfo.setName(name);
        entryInfo.setVersion(version);
        Resource resource = new Resource();
        resource.setEntryInfo(entryInfo);
        return resource;
    }

    private void useOwner() {
        UserContext.set(new UserContext(
                owner.getId(), owner.getUsername(), owner.getRole(), "A".repeat(43)));
    }

    private MultipartFile multipart(String name, String version) throws IOException {
        return new BytesMultipartFile(jarBytes(name, version), "resource.jar");
    }

    private byte[] jarBytes(String name, String version) throws IOException {
        String className = ResourceUploadServiceTest.class.getName();
        String classEntry = className.replace('.', '/') + ".class";
        byte[] classBytes;
        try (InputStream input = ResourceUploadServiceTest.class.getClassLoader()
                .getResourceAsStream(classEntry)) {
            assertNotNull(input);
            classBytes = input.readAllBytes();
        }
        String profile = "Name: " + name + "\n"
                + "Version: " + version + "\n"
                + "EntryClass: " + className + "\n"
                + "EntryPoint: run\n"
                + "InfPort: false\n";
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            jar.putNextEntry(new JarEntry("settings.yml"));
            jar.write(profile.getBytes(StandardCharsets.UTF_8));
            jar.closeEntry();
            jar.putNextEntry(new JarEntry(classEntry));
            jar.write(classBytes);
            jar.closeEntry();
        }
        return output.toByteArray();
    }

    private List<Path> jarFiles() throws IOException {
        Path base = temporaryDirectory.resolve("resources");
        if (!Files.exists(base)) {
            return List.of();
        }
        try (var paths = Files.walk(base)) {
            return paths.filter(path -> Files.isRegularFile(path)
                            && path.getFileName().toString().endsWith(".jar"))
                    .toList();
        }
    }

    public static void run() {
        // Valid no-op entry point for the uploaded resource fixture.
    }

    private static class BytesMultipartFile implements MultipartFile {
        private final byte[] bytes;
        private final String filename;

        private BytesMultipartFile(byte[] bytes, String filename) {
            this.bytes = bytes;
            this.filename = filename;
        }

        @Override
        public String getName() {
            return "file";
        }

        @Override
        public String getOriginalFilename() {
            return filename;
        }

        @Override
        public String getContentType() {
            return "application/java-archive";
        }

        @Override
        public boolean isEmpty() {
            return bytes.length == 0;
        }

        @Override
        public long getSize() {
            return bytes.length;
        }

        @Override
        public byte[] getBytes() {
            return bytes.clone();
        }

        @Override
        public InputStream getInputStream() {
            return new ByteArrayInputStream(bytes);
        }

        @Override
        public void transferTo(File destination) throws IOException {
            Files.write(destination.toPath(), bytes);
        }
    }

    private static final class BlockingMultipartFile extends BytesMultipartFile {
        private final CountDownLatch firstRead;
        private final CountDownLatch releaseRead;

        private BlockingMultipartFile(
                byte[] bytes,
                CountDownLatch firstRead,
                CountDownLatch releaseRead
        ) {
            super(bytes, "resource.jar");
            this.firstRead = firstRead;
            this.releaseRead = releaseRead;
        }

        @Override
        public InputStream getInputStream() {
            InputStream delegate = super.getInputStream();
            return new java.io.FilterInputStream(delegate) {
                private boolean blocked;

                @Override
                public int read(byte[] buffer, int offset, int length) throws IOException {
                    if (!blocked) {
                        blocked = true;
                        firstRead.countDown();
                        try {
                            if (!releaseRead.await(15, TimeUnit.SECONDS)) {
                                throw new IOException("test upload release timed out");
                            }
                        } catch (InterruptedException error) {
                            Thread.currentThread().interrupt();
                            throw new IOException("test upload interrupted", error);
                        }
                    }
                    return super.read(buffer, offset, length);
                }
            };
        }
    }
}
