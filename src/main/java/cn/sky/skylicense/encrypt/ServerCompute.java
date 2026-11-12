package cn.sky.skylicense.encrypt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Server-side computation engine.
 * Critical logic fragments are executed on the server and only results are returned.
 * This makes offline cracking impossible - the program literally cannot function
 * without the server providing computation results.
 */
public class ServerCompute {
    private static final ConcurrentHashMap<String, ComputeTask> REGISTERED_TASKS = new ConcurrentHashMap<>();
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Register a server-side computation task
     */
    public static void registerTask(String taskId, ComputeTask task) {
        REGISTERED_TASKS.put(taskId, task);
    }

    /**
     * Execute a computation on behalf of the client
     * @param taskId The task identifier
     * @param input The client's input data
     * @param sessionKey The session key for verification
     * @return Encrypted result
     */
    public static byte[] compute(String taskId, byte[] input, byte[] sessionKey) throws Exception {
        ComputeTask task = REGISTERED_TASKS.get(taskId);
        if (task == null) {
            throw new IllegalArgumentException("Unknown compute task: " + taskId);
        }

        // Execute the computation
        byte[] result = task.execute(input);

        // Sign the result with session key so client can verify authenticity
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sessionKey, "HmacSHA256"));
        byte[] signature = mac.doFinal(result);

        // Return: [result_length(4)][result][signature(32)]
        byte[] output = new byte[4 + result.length + 32];
        output[0] = (byte) (result.length >> 24);
        output[1] = (byte) (result.length >> 16);
        output[2] = (byte) (result.length >> 8);
        output[3] = (byte) result.length;
        System.arraycopy(result, 0, output, 4, result.length);
        System.arraycopy(signature, 0, output, 4 + result.length, 32);

        return output;
    }

    /**
     * Generate a one-time token for a computation request
     */
    public static String generateComputeToken(String sessionId) {
        byte[] tokenBytes = new byte[16];
        RANDOM.nextBytes(tokenBytes);
        return Base64.getEncoder().encodeToString(tokenBytes);
    }

    @FunctionalInterface
    public interface ComputeTask {
        byte[] execute(byte[] input) throws Exception;
    }
}
