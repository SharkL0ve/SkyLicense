package cn.sky.skylicense.web.exception;

import lombok.Getter;

@Getter
public class BizException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final int code;

    public BizException(int code, String message) {
        super(message);
        this.code = code;
    }

    public BizException(String message) {
        this(400, message);
    }

    public static BizException notFound(String message) {
        return new BizException(404, message);
    }

    public static BizException forbidden(String message) {
        return new BizException(403, message);
    }

    public static BizException unauthorized(String message) {
        return new BizException(401, message);
    }
}
