package cn.sky.skylicense.web.dto;

import cn.sky.skylicense.web.dto.query.AuthLogQuery;
import cn.sky.skylicense.web.dto.query.LicenseQuery;
import cn.sky.skylicense.web.dto.request.CreateLicenseRequest;
import cn.sky.skylicense.web.dto.request.UpdateLicenseRequest;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QueryValidationTest {
    @Test
    void rejectsOversizedAndMalformedLicenseFilters() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            LicenseQuery valid = new LicenseQuery();
            valid.setStatus("active");
            valid.setIp("2001:db8::1");
            valid.setHwid("AbCd+/=");
            valid.setSortBy("lastAuthTime");
            valid.setOrder("desc");
            assertTrue(validator.validate(valid).isEmpty());

            LicenseQuery invalid = new LicenseQuery();
            invalid.setStatus("all");
            invalid.setIp("127.0.0.1%_");
            invalid.setKeyword("x".repeat(257));
            invalid.setSortBy("random()" );
            assertFalse(validator.validate(invalid).isEmpty());
        }
    }

    @Test
    void rejectsMalformedAuthLogFilters() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            AuthLogQuery valid = new AuthLogQuery();
            valid.setCode("LICENSE-01");
            valid.setResult("DELIVERY_UNCONFIRMED");
            valid.setStartTime("2026-01-01-00:00");
            valid.setProgramId(1L);
            assertTrue(validator.validate(valid).isEmpty());

            AuthLogQuery invalid = new AuthLogQuery();
            invalid.setCode("bad@code");
            invalid.setResult("ok");
            invalid.setEndTime("not-a-time");
            invalid.setProgramId(0L);
            assertFalse(validator.validate(invalid).isEmpty());
        }
    }

    @Test
    void licenseQqMustBeNumericAndBounded() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();

            CreateLicenseRequest validCreate = new CreateLicenseRequest();
            validCreate.setQq("10001");
            assertTrue(validator.validate(validCreate).isEmpty());

            CreateLicenseRequest invalidCreate = new CreateLicenseRequest();
            invalidCreate.setQq("qq-10001");
            assertFalse(validator.validate(invalidCreate).isEmpty());

            UpdateLicenseRequest invalidUpdate = new UpdateLicenseRequest();
            invalidUpdate.setQq("9".repeat(21));
            assertFalse(validator.validate(invalidUpdate).isEmpty());
        }
    }
}
