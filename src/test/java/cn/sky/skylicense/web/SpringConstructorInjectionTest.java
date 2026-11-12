package cn.sky.skylicense.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.stereotype.Component;

import java.lang.reflect.Constructor;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SpringConstructorInjectionTest {
    @Test
    void scannedComponentsWithMultipleConstructorsDeclareOneInjectionConstructor()
            throws Exception {
        ClassPathScanningCandidateComponentProvider scanner =
                new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(Component.class, true, true));

        for (var candidate : scanner.findCandidateComponents("cn.sky.skylicense.web")) {
            Class<?> component = Class.forName(candidate.getBeanClassName());
            Constructor<?>[] constructors = component.getDeclaredConstructors();
            if (constructors.length <= 1) {
                continue;
            }
            long injectionConstructors = Arrays.stream(constructors)
                    .filter(constructor -> constructor.isAnnotationPresent(Autowired.class))
                    .count();
            assertEquals(
                    1L,
                    injectionConstructors,
                    () -> component.getName()
                            + " must declare exactly one @Autowired constructor");
        }
    }
}
