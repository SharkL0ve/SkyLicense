package cn.sky.skylicense.security;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeploymentTemplateTest {
    private static final Path WINDOWS_TEMPLATE =
            Path.of("deployment", "windows", "SkyLicense.xml");

    @Test
    void winswCredentialsFollowTheConfiguredDeploymentRoot() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        Document document;
        try (var input = Files.newInputStream(WINDOWS_TEMPLATE)) {
            document = factory.newDocumentBuilder().parse(input);
        }

        Map<String, String> environment = new LinkedHashMap<>();
        NodeList nodes = document.getElementsByTagName("env");
        for (int index = 0; index < nodes.getLength(); index++) {
            Element element = (Element) nodes.item(index);
            environment.put(element.getAttribute("name"), element.getAttribute("value"));
        }

        assertEquals(
                "%BASE%\\secrets\\operation-log-hmac.txt",
                environment.get("SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE"));
        assertEquals(
                "%BASE%\\secrets\\mfa-encryption-key.txt",
                environment.get("SKYLICENSE_MFA_ENCRYPTION_KEY_FILE"));
        assertTrue(environment.values().stream()
                .allMatch(value -> value.startsWith("%BASE%\\secrets\\")));
        assertEquals(
                "%BASE%",
                document.getElementsByTagName("workingdirectory").item(0).getTextContent());

        String xml = Files.readString(WINDOWS_TEMPLATE, StandardCharsets.UTF_8);
        assertFalse(xml.contains("C:\\ProgramData\\SkyLicense\\secrets\\"));
        assertTrue(xml.contains("%BASE%\\secrets\\bootstrap-admin.txt"));
        assertTrue(xml.contains("%BASE%\\secrets\\tls-key-password.txt"));
    }
}
