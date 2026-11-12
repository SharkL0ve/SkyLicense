package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dto.request.CreateProgramRequest;
import cn.sky.skylicense.web.dto.request.UpdateProgramRequest;
import cn.sky.skylicense.web.dto.response.PageResult;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.SelectArg;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Pattern;

@Service
public class ProgramService {
    private static final Pattern PROGRAM_NAME_PATTERN =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+\\-]{0,63}");

    private final WebDataAccessor accessor;
    private final DataCascadeService dataCascadeService;

    public ProgramService(
            WebDataAccessor accessor,
            DataCascadeService dataCascadeService
    ) {
        this.accessor = accessor;
        this.dataCascadeService = dataCascadeService;
    }

    @SneakyThrows
    public synchronized Program createProgram(CreateProgramRequest request) {
        UserContext ctx = UserContext.get();
        if (ctx == null) {
            throw BizException.unauthorized("Authentication is required");
        }
        Dao<Program, Long> dao = accessor.getProgramDao();
        String name = requireValidProgramName(request.getName());

        // 检查程序数量限制
        WebUser user = accessor.getUserDao().queryForId(ctx.getUserId());
        if (user == null || user.getStatus() != 1) {
            throw BizException.unauthorized("User is missing or disabled");
        }
        long count = dao.queryBuilder().where().eq("user_id", ctx.getUserId()).countOf();
        if (count >= user.getMaxPrograms()) {
            throw new BizException("已达到最大程序数量限制（" + user.getMaxPrograms() + "）");
        }

        // 检查同名程序
        Program existing = findByNameIgnoreCase(dao, name, 0);
        if (existing != null) {
            throw new BizException("程序名称已被使用；名称必须全局唯一");
        }

        Program program = Program.builder()
                .userId(ctx.getUserId())
                .name(name)
                .description(request.getDescription())
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();

        dao.create(program);
        return program;
    }

    @SneakyThrows
    public PageResult<Program> listPrograms(int page, int pageSize) {
        UserContext ctx = UserContext.get();
        Dao<Program, Long> dao = accessor.getProgramDao();

        long total;
        List<Program> programs;

        if (ctx.isAdmin()) {
            total = dao.countOf();
            programs = dao.queryBuilder()
                    .offset((long) (page - 1) * pageSize)
                    .limit((long) pageSize)
                    .orderBy("id", false)
                    .query();
        } else {
            total = dao.queryBuilder().where().eq("user_id", ctx.getUserId()).countOf();
            programs = dao.queryBuilder()
                    .where().eq("user_id", ctx.getUserId())
                    .queryBuilder()
                    .offset((long) (page - 1) * pageSize)
                    .limit((long) pageSize)
                    .orderBy("id", false)
                    .query();
        }

        return PageResult.of(programs, total, page, pageSize);
    }

    @SneakyThrows
    public Program getProgram(long id) {
        Program program = accessor.getProgramDao().queryForId(id);
        if (program == null) {
            throw BizException.notFound("程序不存在");
        }
        checkOwnership(program);
        return program;
    }

    @SneakyThrows
    public Program updateProgram(long id, UpdateProgramRequest request) {
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            Dao<Program, Long> dao = accessor.getProgramDao();
            Program program = dao.queryForId(id);
            if (program == null) {
                throw BizException.notFound("程序不存在");
            }
            checkOwnership(program);

            if (request.getName() != null && !request.getName().isBlank()) {
                String name = requireValidProgramName(request.getName());
                if (!program.getName().equals(name)) {
                    long versionCount = accessor.getProgramVersionDao().queryBuilder()
                            .where().eq("program_id", id).countOf();
                    if (versionCount > 0) {
                        throw new BizException("已有上传版本的程序不能重命名");
                    }
                    Program conflict = findByNameIgnoreCase(dao, name, id);
                    if (conflict != null) {
                        throw new BizException("程序名称已被使用；名称必须全局唯一");
                    }
                    program.setName(name);
                }
            }
            if (request.getDescription() != null) {
                program.setDescription(request.getDescription());
            }

            dao.update(program);
            return program;
        }
    }

    @SneakyThrows
    public void deleteProgram(long id) {
        Dao<Program, Long> dao = accessor.getProgramDao();
        Program program = dao.queryForId(id);
        if (program == null) {
            throw BizException.notFound("程序不存在");
        }
        checkOwnership(program);
        dataCascadeService.deleteProgram(program);
    }

    @SneakyThrows
    public void toggleStatus(long id, int status) {
        if (status != 0 && status != 1) {
            throw new BizException("状态只能是0或1");
        }
        synchronized (NativeLicenseService.AUTHORIZATION_LOCK) {
            Dao<Program, Long> dao = accessor.getProgramDao();
            Program program = dao.queryForId(id);
            if (program == null) {
                throw BizException.notFound("程序不存在");
            }
            checkOwnership(program);
            program.setStatus(status);
            dao.update(program);
        }
    }

    private void checkOwnership(Program program) {
        UserContext ctx = UserContext.get();
        if (!ctx.isAdmin() && program.getUserId() != ctx.getUserId()) {
            throw BizException.forbidden("无权操作此程序");
        }
    }

    @SneakyThrows
    private static Program findByNameIgnoreCase(
            Dao<Program, Long> dao,
            String name,
            long excludedId
    ) {
        if (excludedId > 0) {
            return dao.queryBuilder().where()
                    .raw("LOWER(name) = LOWER(?) AND id <> ?",
                            new SelectArg("name", name),
                            new SelectArg("id", excludedId))
                    .queryForFirst();
        }
        return dao.queryBuilder().where()
                .raw("LOWER(name) = LOWER(?)", new SelectArg("name", name))
                .queryForFirst();
    }

    private static String requireValidProgramName(String value) {
        String name = value == null ? "" : value.trim();
        if (!PROGRAM_NAME_PATTERN.matcher(name).matches()) {
            throw new BizException(
                    "程序名称必须是 1-64 位安全 ASCII 字符，且只能包含字母、数字、点、下划线、加号和连字符");
        }
        return name;
    }
}
