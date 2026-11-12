package cn.sky.skylicense.web.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;

import java.io.IOException;

@Configuration
public class StaticResourceConfig implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**")
                .addResourceLocations("classpath:/static/")
                .resourceChain(true)
                .addResolver(new PathResourceResolver() {
                    @Override
                    protected Resource getResource(String resourcePath, Resource location) throws IOException {
                        // /api 路径交给 Controller 处理
                        if (resourcePath.startsWith("api")) {
                            return null;
                        }

                        Resource requested = location.createRelative(resourcePath);
                        if (requested.exists() && requested.isReadable()) {
                            return requested;
                        }

                        // 只有非静态资源路径（无扩展名或非已知扩展名）才 fallback 到 index.html
                        // 有扩展名的文件请求如果不存在就返回 null（404）
                        if (hasFileExtension(resourcePath)) {
                            return null;
                        }

                        // SPA 路由 fallback
                        return new ClassPathResource("/static/index.html");
                    }

                    private boolean hasFileExtension(String path) {
                        int lastSlash = path.lastIndexOf('/');
                        int lastDot = path.lastIndexOf('.');
                        return lastDot > lastSlash && lastDot < path.length() - 1;
                    }
                });
    }
}
