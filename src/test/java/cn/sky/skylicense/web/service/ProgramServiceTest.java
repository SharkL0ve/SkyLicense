package cn.sky.skylicense.web.service;

import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.dto.request.CreateProgramRequest;
import cn.sky.skylicense.web.dto.request.UpdateProgramRequest;
import cn.sky.skylicense.web.entity.Program;
import cn.sky.skylicense.web.entity.ProgramVersion;
import cn.sky.skylicense.web.entity.WebUser;
import cn.sky.skylicense.web.exception.BizException;
import cn.sky.skylicense.web.security.UserContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProgramServiceTest {
    @TempDir
    Path temporaryDirectory;

    private WebDataAccessor accessor;
    private ProgramService service;
    private WebUser firstUser;
    private WebUser secondUser;

    @BeforeEach
    void setUp() throws Exception {
        accessor = new WebDataAccessor();
        accessor.connect(temporaryDirectory.resolve("program.db").toString());
        service = new ProgramService(
                accessor,
                new DataCascadeService(accessor, temporaryDirectory.resolve("resources")));
        firstUser = createUser("first");
        secondUser = createUser("second");
    }

    @AfterEach
    void tearDown() {
        UserContext.clear();
        if (accessor != null) {
            accessor.close();
        }
    }

    @Test
    void programNamesAreSafeAndGloballyUniqueIgnoringCase() {
        use(firstUser);
        Program created = service.createProgram(request("SharedName"));
        assertEquals("SharedName", created.getName());

        use(secondUser);
        assertThrows(BizException.class, () -> service.createProgram(request("sharedname")));
        assertThrows(BizException.class, () -> service.createProgram(request("unsafe@name")));
    }

    @Test
    void aProgramCanOnlyBeRenamedBeforeItsFirstVersion() throws Exception {
        use(firstUser);
        Program created = service.createProgram(request("OriginalName"));

        Program renamed = service.updateProgram(created.getId(), updateRequest("Renamed"));
        assertEquals("Renamed", renamed.getName());

        accessor.getProgramVersionDao().create(ProgramVersion.builder()
                .programId(created.getId())
                .version("1.0.0")
                .fileName("resource.jar")
                .filePath("resources/resource.jar")
                .entryClass("test/Entry")
                .entryPoint("run")
                .uploadTime(TimeUtil.getCurtTime())
                .build());

        assertThrows(
                BizException.class,
                () -> service.updateProgram(created.getId(), updateRequest("TooLate")));
    }

    @Test
    void programStatusAcceptsOnlyBinaryValues() {
        use(firstUser);
        Program created = service.createProgram(request("StatusProgram"));

        assertThrows(BizException.class, () -> service.toggleStatus(created.getId(), 2));
        assertEquals(1, service.getProgram(created.getId()).getStatus());
    }

    private WebUser createUser(String username) throws Exception {
        WebUser user = WebUser.builder()
                .username(username)
                .password("not-used-by-this-test")
                .role("USER")
                .maxPrograms(5)
                .status(1)
                .createTime(TimeUtil.getCurtTime())
                .build();
        accessor.getUserDao().create(user);
        return user;
    }

    private static void use(WebUser user) {
        UserContext.set(new UserContext(
                user.getId(), user.getUsername(), user.getRole(), "A".repeat(43)));
    }

    private static CreateProgramRequest request(String name) {
        CreateProgramRequest request = new CreateProgramRequest();
        request.setName(name);
        request.setDescription("test");
        return request;
    }

    private static UpdateProgramRequest updateRequest(String name) {
        UpdateProgramRequest request = new UpdateProgramRequest();
        request.setName(name);
        request.setDescription("test");
        return request;
    }
}
