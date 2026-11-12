package cn.sky.skylicense.web.service;

import cn.sky.skylicense.resource.Resource;
import cn.sky.skylicense.resource.ResourceManager;
import cn.sky.skylicense.security.ResourceFileStore;
import cn.sky.skylicense.security.ResourceCatalog;
import cn.sky.skylicense.security.SecureFiles;
import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.ProgramVersion;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import com.j256.ormlite.dao.Dao;
import lombok.SneakyThrows;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

@Service
public class ResourceUploadService {
    private static final Logger LOG = LogManager.getLogger(ResourceUploadService.class);
    private static final String RESOURCE_BASE_DIR = "resources";
    private static final long MAX_UPLOAD_BYTES = 64L * 1024 * 1024;
    private static final Pattern VERSION_PATTERN =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+\\-]{0,63}");

    private final WebDataAccessor accessor;
    private final Path resourceBaseDirectory;

    @Autowired
    public ResourceUploadService(WebDataAccessor accessor) {
        this(accessor, Paths.get(RESOURCE_BASE_DIR));
    }

    ResourceUploadService(WebDataAccessor accessor, Path resourceBaseDirectory) {
        this.accessor = accessor;
        this.resourceBaseDirectory = resourceBaseDirectory.toAbsolutePath().normalize();
    }

    @SneakyThrows
    public ProgramVersion uploadVersion(long programId, String version, MultipartFile file) {
        UserContext context = requireContext();
        Program program = accessor.getProgramDao().queryForId(programId);
        if (program == null) {
            throw BizException.notFound("Program does not exist");
        }
        checkProgramOwnership(program);

        if (file == null || file.isEmpty() || file.getSize() < 0
                || file.getSize() > MAX_UPLOAD_BYTES) {
            throw new BizException("Upload must contain a JAR no larger than 64 MiB");
        }
        version = version == null ? null : version.trim();
        if (version == null || !VERSION_PATTERN.matcher(version).matches()) {
            throw new BizException("Version must contain 1-64 safe ASCII characters");
        }

        ProgramVersion existing = accessor.getProgramVersionDao().queryBuilder()
                .where().eq("program_id", programId)
                .and().eq("version", version)
                .queryForFirst();
        if (existing != null) {
            throw new BizException("Version already exists: " + version);
        }

        Path temporary = null;
        Path filePath = null;
        boolean moved = false;
        boolean retained = false;
        try {
            Path base = SecureFiles.preparePrivateDirectory(resourceBaseDirectory);
            Path userDirectory = SecureFiles.preparePrivateDirectory(
                    base.resolve(Long.toString(program.getUserId())));
            Path programDirectory = SecureFiles.preparePrivateDirectory(
                    userDirectory.resolve(Long.toString(programId)));
            temporary = SecureFiles.createPrivateTempFile(
                    programDirectory, ".upload-", ".jar.part");
            copyBounded(file, temporary);

            Resource resource = Resource.fromJar(temporary.toFile(), false);
            if (resource == null) {
                throw new BizException(
                        "JAR is invalid, unsafe, or does not contain a valid settings.yml");
            }
            validateResourceIdentity(program, version, resource);

            synchronized (ResourceManager.class) {
                // The initial existence/ownership checks happen before the
                // potentially expensive upload. Re-read all mutable metadata
                // under the resource lock so a concurrent delete or upload
                // cannot create an orphan row or bypass the identity check.
                Program currentProgram = accessor.getProgramDao().queryForId(programId);
                if (currentProgram == null) {
                    throw BizException.notFound("Program does not exist");
                }
                checkProgramOwnership(currentProgram);
                ProgramVersion concurrent = accessor.getProgramVersionDao()
                        .queryBuilder()
                        .where().eq("program_id", programId)
                        .and().eq("version", version)
                        .queryForFirst();
                if (concurrent != null) {
                    throw new BizException("Version already exists: " + version);
                }
                validateResourceIdentity(currentProgram, version, resource);
                if (ResourceManager.containsPlugin(
                        ResourceManager.identifier(currentProgram.getName(), version))) {
                    throw new BizException(
                            "A resource with the same program name and version is already loaded");
                }
                String fileName = UUID.randomUUID().toString() + ".jar";
                filePath = programDirectory.resolve(fileName);
                SecureFiles.atomicMoveNoReplace(temporary, filePath);
                moved = true;
                temporary = null;
                SecureFiles.makePrivateReadOnly(filePath);

                ProgramVersion programVersion = ProgramVersion.builder()
                        .programId(programId)
                        .version(version)
                        .fileName(fileName)
                        .filePath(filePath.toString())
                        .entryClass(resource.getEntryInfo().getEntryClass())
                        .entryPoint(resource.getEntryInfo().getEntryPoint())
                        .uploadTime(TimeUtil.getCurtTime())
                        .build();
                accessor.getProgramVersionDao().create(programVersion);
                if (!ResourceManager.installResource(resource)) {
                    accessor.getProgramVersionDao().deleteById(programVersion.getId());
                    throw new BizException(
                            "A resource with the same program name and version is already loaded");
                }
                retained = true;
                LOG.info(
                        "User {} uploaded version {} for program {}",
                        context.getUsername(), version, currentProgram.getName());
                return programVersion;
            }
        } finally {
            if (temporary != null) {
                Files.deleteIfExists(temporary);
            }
            if (moved && !retained && filePath != null) {
                Files.deleteIfExists(filePath);
            }
        }
    }

    private static void copyBounded(MultipartFile source, Path destination) throws IOException {
        try (InputStream input = source.getInputStream();
             FileChannel channel = FileChannel.open(
                     destination,
                     StandardOpenOption.WRITE,
                     StandardOpenOption.TRUNCATE_EXISTING,
                     LinkOption.NOFOLLOW_LINKS);
             OutputStream output = Channels.newOutputStream(channel)) {
            byte[] buffer = new byte[8_192];
            long total = 0;
            int read;
            while ((read = input.read(buffer)) != -1) {
                total = Math.addExact(total, read);
                if (total > MAX_UPLOAD_BYTES) {
                    throw new IOException("upload exceeds 64 MiB");
                }
                output.write(buffer, 0, read);
            }
            output.flush();
            channel.force(true);
        } catch (ArithmeticException error) {
            throw new IOException("upload length overflow", error);
        }
    }

    static void validateResourceIdentity(
            Program program,
            String version,
            Resource resource
    ) {
        if (!program.getName().equals(resource.getEntryInfo().getName())) {
            throw new BizException(
                    "settings.yml Name must exactly match the Web program name");
        }
        if (!version.equals(resource.getEntryInfo().getVersion())) {
            throw new BizException(
                    "settings.yml Version must exactly match the uploaded version");
        }
    }

    @SneakyThrows
    public List<ProgramVersion> listVersions(long programId) {
        Program program = accessor.getProgramDao().queryForId(programId);
        if (program == null) {
            throw BizException.notFound("Program does not exist");
        }
        checkProgramOwnership(program);
        return accessor.getProgramVersionDao().queryBuilder()
                .where().eq("program_id", programId)
                .queryBuilder()
                .orderBy("id", false)
                .query();
    }

    @SneakyThrows
    public void deleteVersion(long programId, long versionId) {
        synchronized (ResourceManager.class) {
            synchronized (cn.sky.skylicense.netty.SessionManager.class) {
                synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
                    Program program = accessor.getProgramDao().queryForId(programId);
                    if (program == null) {
                        throw BizException.notFound("Program does not exist");
                    }
                    checkProgramOwnership(program);

                    Dao<ProgramVersion, Long> dao = accessor.getProgramVersionDao();
                    ProgramVersion programVersion = dao.queryForId(versionId);
                    if (programVersion == null || programVersion.getProgramId() != programId) {
                        throw BizException.notFound("Version does not exist");
                    }
                    if (dao.deleteById(versionId) != 1) {
                        throw BizException.notFound("Version does not exist");
                    }
                    ResourceManager.removeResource(program.getName(), programVersion.getVersion());
                    if (programVersion.getFilePath() != null
                            && !programVersion.getFilePath().isBlank()) {
                        try {
                            ResourceFileStore.deleteCommitted(
                                    resourceBaseDirectory,
                                    Paths.get(programVersion.getFilePath()));
                        } catch (IOException error) {
                            LOG.warn(
                                    "Version metadata was deleted but resource cleanup failed: {}",
                                    programVersion.getFilePath(),
                                    error);
                        }
                    }
                }
            }
        }
    }

    public void reloadResources() {
        UserContext context = requireContext();
        if (!context.isAdmin()) {
            throw BizException.forbidden("Only administrators may reload resources");
        }
        if (!ResourceCatalog.reload(accessor, resourceBaseDirectory, true)) {
            throw new BizException(
                    "Resource reload failed; the previous active resource set was preserved");
        }
    }

    private void checkProgramOwnership(Program program) {
        UserContext context = requireContext();
        if (!context.isAdmin() && program.getUserId() != context.getUserId()) {
            throw BizException.forbidden("Program access denied");
        }
    }

    private static UserContext requireContext() {
        UserContext context = UserContext.get();
        if (context == null) {
            throw BizException.unauthorized("Authentication is required");
        }
        return context;
    }
}
