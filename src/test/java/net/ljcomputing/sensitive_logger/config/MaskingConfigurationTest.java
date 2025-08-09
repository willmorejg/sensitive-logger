/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.

James G Willmore - LJ Computing - (C) 2025
*/
package net.ljcomputing.sensitive_logger.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import net.ljcomputing.sensitive_logger.logging.DataMaskingPatternLayout;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Test class for Spring configuration properties and beans.
 *
 * @author James G Willmore
 * @since 1.0.0
 */
@SpringBootTest
@TestPropertySource(
        properties = {
            "logging.masking.pattern.token=(token:)([\\\\w\\\\-._]+)",
            "logging.masking.pattern.password=(password:)([\\\\w\\\\-._]+)",
            "logging.masking.pattern.test=(test:)([\\\\w\\\\-._]+)",
            "logging.masking.masking-char=#"
        })
class MaskingConfigurationTest {

    @Autowired private MaskingPatternProperties maskingPatternProperties;

    @Autowired private DataMaskingPatternLayout dataMaskingPatternLayout;

    @Test
    void testMaskingPatternPropertiesLoaded() {
        assertNotNull(maskingPatternProperties);
        assertTrue(maskingPatternProperties.hasPatterns());

        Map<String, String> patterns = maskingPatternProperties.getPatterns();
        // Should have at least our test patterns, but may have more from application.properties
        assertTrue(patterns.size() >= 3);

        // Check that our test patterns are present
        assertTrue(patterns.containsKey("token"));
        assertTrue(patterns.containsKey("password"));
        assertTrue(patterns.containsKey("test"));

        assertEquals("(token:)([\\w\\-._]+)", patterns.get("token"));
        assertEquals("(password:)([\\w\\-._]+)", patterns.get("password"));
        assertEquals("(test:)([\\w\\-._]+)", patterns.get("test"));
    }

    @Test
    void testMaskingCharLoaded() {
        assertEquals("#", maskingPatternProperties.getMaskingChar());
    }

    @Test
    void testDataMaskingPatternLayoutBean() {
        assertNotNull(dataMaskingPatternLayout);

        // The layout should have been configured with the patterns from properties
        assertTrue(dataMaskingPatternLayout.getMaskPatterns().size() >= 3);
        assertEquals("#", dataMaskingPatternLayout.getMaskingChar());
    }

    @Test
    void testPatternRetrieval() {
        String tokenPattern = maskingPatternProperties.getPatternByName("token");
        assertNotNull(tokenPattern);
        assertEquals("(token:)([\\w\\-._]+)", tokenPattern);

        String nonExistentPattern = maskingPatternProperties.getPatternByName("nonexistent");
        assertNull(nonExistentPattern);
    }

    @Test
    void testAddPattern() {
        int originalSize = maskingPatternProperties.getPatterns().size();

        maskingPatternProperties.addPattern("newPattern", "(new: )(\\w+)");

        assertEquals(originalSize + 1, maskingPatternProperties.getPatterns().size());
        assertEquals("(new: )(\\w+)", maskingPatternProperties.getPatternByName("newPattern"));
    }
}
