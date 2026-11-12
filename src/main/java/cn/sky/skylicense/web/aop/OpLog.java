package cn.sky.skylicense.web.aop;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注需要记录操作日志的方法
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface OpLog {
    String action();
    String target() default "";

    /** Allows the deliberately public login endpoint to audit before a session exists. */
    boolean allowAnonymous() default false;
}
