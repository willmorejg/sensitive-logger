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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit test class for MaskingPatternProperties (not Spring Boot integration test).
 *
 * @author James G Willmore
 * @since 1.0.0
 */
class MaskingPatternPropertiesUnitTest {

    @Test
    void testBasicProperties() {
        MaskingPatternProperties properties = new MaskingPatternProperties();

        // Test default values
        assertEquals("*", properties.getMaskingChar());
        assertFalse(properties.hasPatterns());
        assertTrue(properties.getPatterns().isEmpty());
    }

    @Test
    void testSetMaskingChar() {
        MaskingPatternProperties properties = new MaskingPatternProperties();

        properties.setMaskingChar("#");
        assertEquals("#", properties.getMaskingChar());
    }

    @Test
    void testSetPatterns() {
        MaskingPatternProperties properties = new MaskingPatternProperties();

        Map<String, String> patterns = new HashMap<>();
        patterns.put("token", "(token:)([\\w\\-._]+)");
        patterns.put("password", "(password:)([\\w\\-._]+)");

        properties.setPatterns(patterns);

        assertTrue(properties.hasPatterns());
        assertEquals(2, properties.getPatterns().size());
        assertEquals("(token:)([\\w\\-._]+)", properties.getPatternByName("token"));
        assertEquals("(password:)([\\w\\-._]+)", properties.getPatternByName("password"));
    }

    @Test
    void testAddPattern() {
        MaskingPatternProperties properties = new MaskingPatternProperties();

        properties.addPattern("test", "(test:)([\\w]+)");

        assertTrue(properties.hasPatterns());
        assertEquals(1, properties.getPatterns().size());
        assertEquals("(test:)([\\w]+)", properties.getPatternByName("test"));
    }

    @Test
    void testGetPatternByName() {
        MaskingPatternProperties properties = new MaskingPatternProperties();

        assertNull(properties.getPatternByName("nonexistent"));

        properties.addPattern("test", "(test:)([\\w]+)");
        assertEquals("(test:)([\\w]+)", properties.getPatternByName("test"));
    }

    @Test
    void testSetPattern() {
        MaskingPatternProperties properties = new MaskingPatternProperties();

        Map<String, String> patterns = new HashMap<>();
        patterns.put("api-key", "(api-key:)([\\w\\-._]+)");

        properties.setPattern(patterns);

        assertTrue(properties.hasPatterns());
        assertEquals(1, properties.getPatterns().size());
        assertEquals("(api-key:)([\\w\\-._]+)", properties.getPatternByName("api-key"));
    }

    @Test
    void testGetPattern() {
        MaskingPatternProperties properties = new MaskingPatternProperties();

        Map<String, String> patterns = new HashMap<>();
        patterns.put("secret", "(secret:)([\\w\\-._]+)");

        properties.setPattern(patterns);

        Map<String, String> retrieved = properties.getPattern();
        assertEquals(1, retrieved.size());
        assertTrue(retrieved.containsKey("secret"));
        assertEquals("(secret:)([\\w\\-._]+)", retrieved.get("secret"));
    }
}
