package cn.sky.license;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertSame;

class ResponseTest {
    @Test
    void bindingRejectionIsNotMisreportedAsAnEndpointError() {
        assertSame(Response.NOT_ADDRESS, Response.translate("NOT_ADRESS"));
        assertSame(Response.WRONG_ADDRESS, Response.translate("WRONG_ADDRESS"));
    }

    @Test
    void dailyAuthenticationLimitHasAStableSdkResponse() {
        assertSame(Response.DAILY_AUTH_LIMIT, Response.translate("DAILY_AUTH_LIMIT"));
    }

    @Test
    void entryPointFailuresHaveStableSdkResponses() {
        assertSame(Response.ENTRY_CLASS_NOT_FOUND, Response.translate("ENTRY_CLASS_NOT_FOUND"));
        assertSame(Response.ENTRY_POINT_NOT_FOUND, Response.translate("ENTRY_POINT_NOT_FOUND"));
        assertSame(Response.ENTRY_POINT_EXCEPTION, Response.translate("ENTRY_POINT_EXCEPTION"));
    }

    @Test
    void deliveryAcknowledgementFailureIsTerminalForTheCurrentProcess() {
        assertSame(Response.DELIVERY_ACK_ERROR, Response.translate("DELIVERY_ACK_ERROR"));
        org.junit.jupiter.api.Assertions.assertFalse(Response.DELIVERY_ACK_ERROR.retry());
    }

    @Test
    void duplicateAndConcurrentAuthenticationHaveStableSdkResponses() {
        assertSame(
                Response.SESSION_ALREADY_INITIALIZED,
                Response.translate("SESSION_ALREADY_INITIALIZED"));
        assertSame(
                Response.AUTHENTICATION_IN_PROGRESS,
                Response.translate("AUTHENTICATION_IN_PROGRESS"));
        org.junit.jupiter.api.Assertions.assertFalse(Response.SESSION_ALREADY_INITIALIZED.retry());
        org.junit.jupiter.api.Assertions.assertFalse(Response.AUTHENTICATION_IN_PROGRESS.retry());
    }

    @Test
    void nativeErrorDetailsAreMappedByCodeWithoutLeakingTheDetail() {
        assertSame(
                Response.SOCKET_ERROR_CONNECT,
                Response.translate("KEY_EXCHANGE_ERROR: secret detail"));
        assertSame(
                Response.SOCKET_ERROR_RECEIVE,
                Response.translate("SOCKET_ERROR_READ: private network detail"));
        assertSame(
                Response.RESOURCE_RELEASE_ERROR,
                Response.translate("SOCKET_ERROR_RESOURCE_DATA: interrupted"));
        org.junit.jupiter.api.Assertions.assertFalse(Response.RESOURCE_RELEASE_ERROR.retry());
        assertSame(
                Response.RESOURCE_ERROR,
                Response.translate("RESOURCE_ERROR_KEY_DERIVATION"));
        assertSame(Response.UNKNOWN_ERROR, Response.translate("future-internal-error"));
        assertSame(Response.UNKNOWN_ERROR, Response.translate(null));
    }
}
