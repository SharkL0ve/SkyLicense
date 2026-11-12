package cn.sky.skylicense.web.config;

import cn.sky.skylicense.utils.TimeUtil;
import cn.sky.skylicense.web.dao.WebDataAccessor;
import cn.sky.skylicense.web.entity.WebUser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

class DatabaseConfigTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void renamedAdministratorDoesNotTriggerBootstrapCreation() throws Exception {
        WebDataAccessor accessor = new WebDataAccessor();
        try {
            accessor.connect(temporaryDirectory.resolve("bootstrap.db").toString());
            accessor.getUserDao().create(WebUser.builder()
                    .username("renamed-admin")
                    .password("hash")
                    .role("ADMIN")
                    .maxPrograms(10)
                    .status(1)
                    .createTime(TimeUtil.getCurtTime())
                    .build());

            assertDoesNotThrow(() -> new DatabaseConfig().initDefaultAdmin(accessor));
            assertEquals(1, accessor.getUserDao().countOf());
        } finally {
            accessor.close();
        }
    }
}
