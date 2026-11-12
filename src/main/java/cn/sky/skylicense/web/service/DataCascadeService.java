package cn.sky.skylicense.web.service;

import cn.sky.skylicense.resource.ResourceManager;
import cn.sky.skylicense.security.ResourceFileStore;
import cn.sky.skylicense.netty.SessionManager;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.ProgramVersion;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.misc.TransactionManager;
import com.j256.ormlite.stmt.DeleteBuilder;
import lombok.SneakyThrows;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/** Transactional database cascades followed by safe protected-resource cleanup. */
@Service
public class DataCascadeService {
    private static final Logger LOG = LogManager.getLogger(DataCascadeService.class);

    private final WebDataAccessor accessor;
    private final Path resourceBaseDirectory;

    @Autowired
    public DataCascadeService(WebDataAccessor accessor) {
        this(accessor, Paths.get("resources"));
    }

    DataCascadeService(WebDataAccessor accessor, Path resourceBaseDirectory) {
        this.accessor = accessor;
        this.resourceBaseDirectory = resourceBaseDirectory.toAbsolutePath().normalize();
    }

    @SneakyThrows
    public void deleteProgram(Program program) {
        if (program == null) {
            throw new IllegalArgumentException("program is required");
        }
        synchronized (ResourceManager.class) {
            synchronized (SessionManager.class) {
                synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
                    Program current = accessor.getProgramDao().queryForId(program.getId());
                    if (current == null) {
                        throw BizException.notFound("程序不存在");
                    }
                    List<ResourceArtifact> artifacts = artifactsForPrograms(List.of(current));
                    deleteRowsAndArtifactsLocked(artifacts, () -> {
                        deleteProgramRows(current.getId());
                        accessor.getProgramDao().deleteById(current.getId());
                        return null;
                    });
                }
            }
        }
    }

    @SneakyThrows
    public void deleteUser(WebUser user) {
        if (user == null) {
            throw new IllegalArgumentException("user is required");
        }
        synchronized (ResourceManager.class) {
            synchronized (SessionManager.class) {
                synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
                    WebUser current = accessor.getUserDao().queryForId(user.getId());
                    if (current == null) {
                        throw BizException.notFound("用户不存在");
                    }
                    List<Program> programs = accessor.getProgramDao().queryBuilder()
                            .where().eq("user_id", current.getId()).query();
                    List<ResourceArtifact> artifacts = artifactsForPrograms(programs);
                    deleteRowsAndArtifactsLocked(artifacts, () -> {
                        deleteByColumn(accessor.getAuthLogDao(), "user_id", current.getId());
                        deleteByColumn(accessor.getSessionDao(), "user_id", current.getId());
                        deleteByColumn(accessor.getMfaChallengeDao(), "user_id", current.getId());
                        deleteByColumn(accessor.getLicenseDao(), "user_id", current.getId());
                        deleteByColumn(accessor.getBanRecordDao(), "operator_id", current.getId());
                        for (Program program : programs) {
                            deleteProgramRows(program.getId());
                        }
                        deleteByColumn(accessor.getProgramDao(), "user_id", current.getId());
                        accessor.getUserDao().deleteById(current.getId());
                        return null;
                    });
                }
            }
        }
    }

    private void deleteRowsAndArtifactsLocked(
            List<ResourceArtifact> artifacts,
            java.util.concurrent.Callable<Void> databaseDelete
    ) throws Exception {
        // The committed database catalog is the loading authority. Committing
        // deletion first makes a later crash leave only an inert orphan file.
        TransactionManager.callInTransaction(
                accessor.getConnectionSource(), databaseDelete);
        cleanupArtifacts(artifacts);
    }

    private List<ResourceArtifact> artifactsForPrograms(List<Program> programs)
            throws SQLException {
        List<ResourceArtifact> artifacts = new ArrayList<>();
        for (Program program : programs) {
            List<ProgramVersion> versions = accessor.getProgramVersionDao().queryBuilder()
                    .where().eq("program_id", program.getId()).query();
            for (ProgramVersion version : versions) {
                artifacts.add(new ResourceArtifact(
                        program.getName(),
                        version.getVersion(),
                        version.getFilePath()));
            }
        }
        return artifacts;
    }

    private void deleteProgramRows(long programId) throws SQLException {
        deleteByColumn(accessor.getAuthLogDao(), "program_id", programId);
        deleteByColumn(accessor.getLicenseDao(), "program_id", programId);
        deleteByColumn(accessor.getBanRecordDao(), "program_id", programId);
        deleteByColumn(accessor.getProgramVersionDao(), "program_id", programId);
    }

    private static <T, ID> void deleteByColumn(
            Dao<T, ID> dao,
            String column,
            Object value
    ) throws SQLException {
        DeleteBuilder<T, ID> builder = dao.deleteBuilder();
        builder.where().eq(column, value);
        builder.delete();
    }

    private void cleanupArtifacts(List<ResourceArtifact> artifacts) {
        for (ResourceArtifact artifact : artifacts) {
            ResourceManager.removeResource(artifact.name(), artifact.version());
            try {
                if (artifact.filePath() != null && !artifact.filePath().isBlank()) {
                    ResourceFileStore.deleteCommitted(
                            resourceBaseDirectory, Paths.get(artifact.filePath()));
                }
            } catch (IOException error) {
                LOG.warn(
                        "Database rows were deleted but resource cleanup failed for {}",
                        artifact.filePath(),
                        error);
            }
        }
    }

    private record ResourceArtifact(String name, String version, String filePath) {
    }

}
