package cn.sky.skylicense.web.config;

import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.ConfigurationSource;
import org.apache.logging.log4j.core.config.xml.XmlConfiguration;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogConfigurationTest {
    @Test
    void logConfigurationUsesBoundedDualTriggerRollingAndSafeEncoding() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        Document document;
        try (InputStream input = getClass().getClassLoader()
                .getResourceAsStream("log4j2.xml")) {
            assertNotNull(input);
            document = factory.newDocumentBuilder().parse(input);
        }

        Element properties = (Element) document.getElementsByTagName("Properties").item(0);
        String pattern = property(properties, "log.pattern");
        String filePattern = property(properties, "file.pattern");
        assertTrue(pattern.contains("%enc{%message}{CRLF}"));
        assertTrue(pattern.contains("%enc{%throwable}{CRLF}"));
        assertFalse(filePattern.contains("YYYY"));
        assertTrue(filePattern.contains("%i"));

        Element rolling = (Element) document.getElementsByTagName("RollingFile").item(0);
        assertEquals("logs/latest.log", property(properties, "file.filename"));
        assertEquals("${file.filename}", rolling.getAttribute("fileName"));
        assertEquals("${file.pattern}", rolling.getAttribute("filePattern"));
        assertEquals(1, rolling.getElementsByTagName("TimeBasedTriggeringPolicy").getLength());
        assertEquals(1, rolling.getElementsByTagName("SizeBasedTriggeringPolicy").getLength());
        Element sizePolicy = (Element) rolling
                .getElementsByTagName("SizeBasedTriggeringPolicy").item(0);
        assertEquals("50 MB", sizePolicy.getAttribute("size"));

        NodeList deleteActions = rolling.getElementsByTagName("Delete");
        assertEquals(1, deleteActions.getLength());
        Element delete = (Element) deleteActions.item(0);
        assertEquals("logs/archive", delete.getAttribute("basePath"));
        assertEquals("1", delete.getAttribute("maxDepth"));
        assertEquals(1, delete.getElementsByTagName("IfLastModified").getLength());
        assertEquals(1, delete.getElementsByTagName("IfAccumulatedFileSize").getLength());
        assertEquals(1, delete.getElementsByTagName("IfAccumulatedFileCount").getLength());

        ConfigurationSource source = ConfigurationSource.fromResource(
                "log4j2.xml", getClass().getClassLoader());
        assertNotNull(source);
        LoggerContext context = new LoggerContext("log-configuration-test");
        XmlConfiguration configuration = new XmlConfiguration(context, source);
        try {
            configuration.initialize();
            assertNotNull(configuration.getAppender("console"));
            assertNotNull(configuration.getAppender("file"));
            assertEquals(2, configuration.getAppenders().size());
        } finally {
            configuration.stop();
            context.close();
        }
    }

    private static String property(Element properties, String name) {
        NodeList nodes = properties.getElementsByTagName("Property");
        for (int index = 0; index < nodes.getLength(); index++) {
            Element property = (Element) nodes.item(index);
            if (name.equals(property.getAttribute("name"))) {
                return property.getTextContent();
            }
        }
        throw new AssertionError("Missing log property: " + name);
    }
}
