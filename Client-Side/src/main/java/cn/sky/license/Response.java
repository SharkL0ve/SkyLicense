package cn.sky.license;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class Response {
    public static final Response WRONG_ADDRESS = new Response("&cWrong Authentication Address.", false);
    public static final Response WRONG_INFO = new Response("&cAuthentication failures.", false);
    public static final Response ACCEPT = new Response("&aAuthentication Success, thank you for your support!", false);
    public static final Response BUSY = new Response("&cVerify that the server is busy", true);
    public static final Response WRONG_KEY = new Response("&cYou have provided incorrect verification information.", false);
    public static final Response INVALID_REQUEST = new Response("&cThe authentication request is invalid.", false);
    public static final Response CLIENT_BUILD_ERROR = new Response("&cThis client build is not usable.", false);
    public static final Response SESSION_REVOKED = new Response("&cThe protected session has been revoked.", false);
    public static final Response SESSION_ALREADY_INITIALIZED = new Response(
            "&cA protected license session is already active in this JVM.", false);
    public static final Response AUTHENTICATION_IN_PROGRESS = new Response(
            "&cAnother license authentication is already in progress.", false);
    public static final Response HWID_ERROR = new Response("&cUnable to collect a stable machine identity.", false);
    public static final Response HEARTBEAT_ERROR = new Response("&cThe protected session lease expired.", false);
    public static final Response RESOURCE_ERROR = new Response("&cThe protected resource could not be loaded.", false);
    public static final Response RESOURCE_RELEASE_ERROR = new Response(
            "&cProtected resource delivery was interrupted; restart this JVM before retrying.", false);
    public static final Response PROTECTION_ERROR = new Response("&cRuntime protection could not be activated.", false);
    public static final Response UNKNOWN_ERROR = new Response("&cAuthentication failed.", false);

    public static final Response PLUGIN_NOT = new Response("&cThe program or version is empty.",false);

    public static final Response BLACKLIST = new Response("&cYour license status is Banned.",false);

    public static final Response NOT_ADDRESS = new Response(
            "&cThe IP or machine binding is unavailable; contact the license issuer.", false);
    /** @deprecated Kept as a source-compatible alias for the historical typo. */
    @Deprecated
    public static final Response NOT_ADRESS = NOT_ADDRESS;

    public static final Response PROGRAM_NOT_MATCH = new Response("&cYour license does not belong to this application",false);
    public static final Response DAILY_AUTH_LIMIT = new Response(
            "&cThe daily authentication limit has been reached.", false);

    //c
    public static final Response SOCKET_ERROR_RECEIVE = new Response("&cAuthentication server, no response.", true);
    public static final Response SOCKET_ERROR_SEND = new Response("&cFailed to send authentication server message...", true);
    public static final Response SOCKET_ERROR_INIT = new Response("&cSocket initialization failure.", false);
    public static final Response ENTRY_CLASS_NOT_FOUND = new Response("&cResource initialization failure : ENTRY_CLASS_NOT_FOUND", false);
    public static final Response ENTRY_POINT_EXCEPTION = new Response("&cResource initialization failure : ENTRY_POINT_EXCEPTION", false);
    public static final Response ENTRY_POINT_NOT_FOUND = new Response("&cResource initialization failure :ENTRY_POINT_NOT_FOUND", false);
    public static final Response DELIVERY_ACK_ERROR = new Response(
            "&cThe server did not confirm protected resource initialization.", false);
    public static final Response SOCKET_ERROR_CONNECT = new Response("&cFailed to verify server connection, will try again later.", true);
    public static final Response RESOURCE_ERROR_SAVING = new Response("&cResource cache failure.", false);
    public static final Response RESOURCE_ERROR_UNCOMPRESS = new Response("&cResource decompression failure.", false);
    public static final Response BUKKIT_PORT_UNAVAILABLE = new Response("&cUnable to get local port number.", false);
    public static final Response SOCKET_ERROR_WSA = new Response("&cSocket WSA initialization failure.", false);
    private static final Map<String, Response> RESPONSES = new HashMap<>();
    private final String message;
    private final boolean shouldRetry;

    static {
        RESPONSES.put("ACCEPT", ACCEPT);
        RESPONSES.put("BUSY", BUSY);
        RESPONSES.put("WRONG_INFO", WRONG_INFO);
        RESPONSES.put("NOT_ADRESS", NOT_ADDRESS);
        RESPONSES.put("WRONG_KEY", WRONG_KEY);
        RESPONSES.put("PLUGIN_NOT",PLUGIN_NOT);
        RESPONSES.put("WRONG_ADDRESS", WRONG_ADDRESS);
        RESPONSES.put("BLACKLIST", BLACKLIST);
        RESPONSES.put("PROGRAM_NOT_MATCH", PROGRAM_NOT_MATCH);
        RESPONSES.put("DAILY_AUTH_LIMIT", DAILY_AUTH_LIMIT);
        RESPONSES.put("BUKKIT_PORT_UNAVAILABLE", BUKKIT_PORT_UNAVAILABLE);
        RESPONSES.put("SOCKET_ERROR_INIT", SOCKET_ERROR_INIT);
        RESPONSES.put("SOCKET_ERROR_WSA", SOCKET_ERROR_WSA);
        RESPONSES.put("SOCKET_ERROR_CONNECT", SOCKET_ERROR_CONNECT);
        RESPONSES.put("SOCKET_ERROR_SEND", SOCKET_ERROR_SEND);
        RESPONSES.put("SOCKET_ERROR_RECEIVE", SOCKET_ERROR_RECEIVE);
        RESPONSES.put("RESOURCE_ERROR_UNCOMPRESS", RESOURCE_ERROR_UNCOMPRESS);
        RESPONSES.put("RESOURCE_ERROR_SAVING", RESOURCE_ERROR_SAVING);
        RESPONSES.put("ENTRY_CLASS_NOT_FOUND", ENTRY_CLASS_NOT_FOUND);
        RESPONSES.put("ENTRY_POINT_NOT_FOUND", ENTRY_POINT_NOT_FOUND);
        RESPONSES.put("ENTRY_POINT_EXCEPTION", ENTRY_POINT_EXCEPTION);
        RESPONSES.put("DELIVERY_ACK_ERROR", DELIVERY_ACK_ERROR);
        RESPONSES.put("INVALID_REQUEST", INVALID_REQUEST);
        RESPONSES.put("CLIENT_BUILD_ERROR", CLIENT_BUILD_ERROR);
        RESPONSES.put("SESSION_REVOKED", SESSION_REVOKED);
        RESPONSES.put("SESSION_ALREADY_INITIALIZED", SESSION_ALREADY_INITIALIZED);
        RESPONSES.put("AUTHENTICATION_IN_PROGRESS", AUTHENTICATION_IN_PROGRESS);
        RESPONSES.put("HWID_ERROR", HWID_ERROR);
        RESPONSES.put("HEARTBEAT_ERROR", HEARTBEAT_ERROR);
        RESPONSES.put("PROTECTION_ERROR", PROTECTION_ERROR);
        RESPONSES.put("RESOURCE_ERROR_SIZE", RESOURCE_ERROR);
        RESPONSES.put("RESOURCE_ERROR_KEY_DERIVATION", RESOURCE_ERROR);
        RESPONSES.put("RESOURCE_ERROR_CLASSLOADER", RESOURCE_ERROR);
        RESPONSES.put("RESOURCE_ERROR_UNCOMPRESS", RESOURCE_ERROR);
        RESPONSES.put("RESOURCE_ERROR_SAVING", RESOURCE_ERROR_SAVING);
        RESPONSES.put("SOCKET_ERROR_TIMEOUT", SOCKET_ERROR_RECEIVE);
    }

    private static final Map<String, Response> PREFIX_RESPONSES = prefixResponses();

    private static Map<String, Response> prefixResponses() {
        Map<String, Response> responses = new LinkedHashMap<>();
        responses.put("CLIENT_BUILD_ERROR:", CLIENT_BUILD_ERROR);
        responses.put("HWID_ERROR:", HWID_ERROR);
        responses.put("HEARTBEAT_ERROR:", HEARTBEAT_ERROR);
        responses.put("PROTECTION_ERROR:", PROTECTION_ERROR);
        responses.put("KEY_EXCHANGE_ERROR:", SOCKET_ERROR_CONNECT);
        responses.put("CHALLENGE_ERROR:", SOCKET_ERROR_CONNECT);
        responses.put("CLOCK_ERROR:", SOCKET_ERROR_CONNECT);
        responses.put("SOCKET_ERROR_CONNECT:", SOCKET_ERROR_CONNECT);
        responses.put("SOCKET_ERROR_TIMEOUT:", SOCKET_ERROR_RECEIVE);
        responses.put("SOCKET_ERROR_READ:", SOCKET_ERROR_RECEIVE);
        responses.put("SOCKET_ERROR_WRITE:", SOCKET_ERROR_SEND);
        responses.put("SOCKET_ERROR_CHALLENGE_WRITE:", SOCKET_ERROR_SEND);
        responses.put("SOCKET_ERROR_ECDH:", SOCKET_ERROR_RECEIVE);
        responses.put("SOCKET_ERROR_NONCE:", SOCKET_ERROR_RECEIVE);
        responses.put("SOCKET_ERROR_SESSION:", SOCKET_ERROR_RECEIVE);
        responses.put("SOCKET_ERROR_RESOURCE_LEN:", SOCKET_ERROR_RECEIVE);
        responses.put("SOCKET_ERROR_RESOURCE_DATA:", RESOURCE_RELEASE_ERROR);
        responses.put("RESOURCE_ERROR_", RESOURCE_ERROR);
        return responses;
    }

    private Response(String message, boolean shouldRetry) {
        this.shouldRetry = shouldRetry;
        this.message = message.replace('&', '§');
    }

    public static Response translate(String raw) {
        if (raw == null || raw.isEmpty()) {
            return UNKNOWN_ERROR;
        }
        Response response = RESPONSES.get(raw);
        if (response != null) {
            return response;
        }
        for (Map.Entry<String, Response> entry : PREFIX_RESPONSES.entrySet()) {
            if (raw.startsWith(entry.getKey())) {
                return entry.getValue();
            }
        }
        return UNKNOWN_ERROR;
    }

    public boolean retry() {
        return this.shouldRetry;
    }

    public String toString() {
        return this.message;
    }

}
