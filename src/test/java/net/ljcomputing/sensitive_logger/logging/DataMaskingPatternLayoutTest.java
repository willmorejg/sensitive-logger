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
package net.ljcomputing.sensitive_logger.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggingEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class DataMaskingPatternLayoutTest {

    private DataMaskingPatternLayout layout;
    private LoggerContext loggerContext;
    private Logger logger;

    @BeforeEach
    void setUp() {
        layout = new DataMaskingPatternLayout();
        layout.setPattern("%msg");

        loggerContext = new LoggerContext();
        logger = loggerContext.getLogger("test");
        layout.setContext(loggerContext);
        layout.start();
    }

    @Test
    void testBasicMasking() {
        // Test credit card masking with 2 groups: identifier and value
        layout.addMaskPattern("(Credit card: )(\\d{4}-\\d{4}-\\d{4}-\\d{4})");

        ILoggingEvent event = createLoggingEvent("Credit card: 1234-5678-9012-3456");
        String result = layout.doLayout(event);

        assertEquals("Credit card: *******************", result);
    }

    @Test
    void testEmailMasking() {
        // Test email masking with 2 groups: identifier and value
        layout.addMaskPattern("(Contact: )(\\w+@\\w+\\.\\w+)");

        ILoggingEvent event = createLoggingEvent("Contact: user@example.com for support");
        String result = layout.doLayout(event);

        assertEquals("Contact: **************** for support", result);
    }

    @Test
    void testMultiplePatterns() {
        // Test multiple patterns with 2 groups each
        layout.addMaskPattern(
                "(Credit card: )(\\d{4}-\\d{4}-\\d{4}-\\d{4}),(Contact: )(\\w+@\\w+\\.\\w+)");

        ILoggingEvent event =
                createLoggingEvent("Card: 1234-5678-9012-3456, Email: user@example.com");
        String result = layout.doLayout(event);

        // Only the patterns with proper identifiers will match
        assertEquals("Card: 1234-5678-9012-3456, Email: user@example.com", result);
    }

    @Test
    void testCustomMaskingCharacter() {
        layout.setMaskingChar("X");
        layout.addMaskPattern("(Credit card: )(\\d{4}-\\d{4}-\\d{4}-\\d{4})");

        ILoggingEvent event = createLoggingEvent("Credit card: 1234-5678-9012-3456");
        String result = layout.doLayout(event);

        assertEquals("Credit card: XXXXXXXXXXXXXXXXXXX", result);
    }

    @Test
    void testNoPatterns() {
        ILoggingEvent event = createLoggingEvent("No sensitive data here");
        String result = layout.doLayout(event);

        assertEquals("No sensitive data here", result);
    }

    @Test
    void testEmptyMessage() {
        layout.addMaskPattern("(Credit card: )(\\d{4}-\\d{4}-\\d{4}-\\d{4})");

        ILoggingEvent event = createLoggingEvent("");
        String result = layout.doLayout(event);

        assertEquals("", result);
    }

    @Test
    void testInvalidPattern() {
        // Test that invalid patterns are handled gracefully
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> {
                            layout.addMaskPattern("(invalid[regex");
                        });
        assertNotNull(exception.getMessage());
    }

    @Test
    void testInvalidGroupCount() {
        // Test that patterns with wrong number of groups are rejected
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> {
                            layout.addMaskPattern("(\\d{4})"); // Only 1 group
                        });
        assertTrue(exception.getMessage().contains("exactly 2 capture groups"));
    }

    @Test
    void testMaskingCharAccessors() {
        assertEquals("*", layout.getMaskingChar());

        layout.setMaskingChar("#");
        assertEquals("#", layout.getMaskingChar());

        layout.setMaskingChar("ABC"); // Should use only first character
        assertEquals("A", layout.getMaskingChar());

        layout.setMaskingChar(""); // Should be ignored
        assertEquals("A", layout.getMaskingChar());
    }

    @Test
    void testGetMaskPatterns() {
        assertTrue(layout.getMaskPatterns().isEmpty());

        layout.addMaskPattern("(Card: )(\\d{4}-\\d{4}-\\d{4}-\\d{4})");
        layout.addMaskPattern("(Email: )(\\w+@\\w+\\.\\w+)");

        assertEquals(2, layout.getMaskPatterns().size());
        assertTrue(layout.getMaskPatterns().contains("(Card: )(\\d{4}-\\d{4}-\\d{4}-\\d{4})"));
        assertTrue(layout.getMaskPatterns().contains("(Email: )(\\w+@\\w+\\.\\w+)"));
    }

    @Test
    void testSetMaskPatternsWithMap() {
        java.util.Map<String, String> patterns = new java.util.HashMap<>();
        patterns.put("token", "(token: )([\\w\\-._]+)");
        patterns.put("password", "(password: )([\\w\\-._]+)");
        patterns.put("credit-card", "(card: )(\\d{4}-\\d{4}-\\d{4}-\\d{4})");

        layout.setMaskPatterns(patterns);

        assertEquals(3, layout.getMaskPatterns().size());
        assertTrue(layout.getMaskPatterns().contains("(token: )([\\w\\-._]+)"));
        assertTrue(layout.getMaskPatterns().contains("(password: )([\\w\\-._]+)"));
        assertTrue(layout.getMaskPatterns().contains("(card: )(\\d{4}-\\d{4}-\\d{4}-\\d{4})"));
    }

    @Test
    void testSetMaskPatternsReplacesExisting() {
        // First add some patterns
        layout.addMaskPattern("(old: )(\\w+)");
        assertEquals(1, layout.getMaskPatterns().size());

        // Now set new patterns via map - should replace existing
        java.util.Map<String, String> patterns = new java.util.HashMap<>();
        patterns.put("new", "(new: )(\\w+)");

        layout.setMaskPatterns(patterns);

        assertEquals(1, layout.getMaskPatterns().size());
        assertTrue(layout.getMaskPatterns().contains("(new: )(\\w+)"));
        assertTrue(!layout.getMaskPatterns().contains("(old: )(\\w+)"));
    }

    @Test
    void testSetMaskPatternsWithEmptyMap() {
        layout.addMaskPattern("(existing: )(\\w+)");
        assertEquals(1, layout.getMaskPatterns().size());

        layout.setMaskPatterns(new java.util.HashMap<>());

        // Empty map should be ignored, patterns remain
        assertEquals(1, layout.getMaskPatterns().size());
    }

    @Test
    void testSetMaskPatternsWithInvalidPattern() {
        java.util.Map<String, String> patterns = new java.util.HashMap<>();
        patterns.put("valid", "(valid: )(\\w+)");
        patterns.put("invalid", "(invalid[regex"); // Invalid regex

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class, () -> layout.setMaskPatterns(patterns));
        assertNotNull(exception.getMessage());
    }

    private ILoggingEvent createLoggingEvent(String message) {
        LoggingEvent event = new LoggingEvent();
        event.setLoggerName(logger.getName());
        event.setLevel(Level.INFO);
        event.setMessage(message);
        event.setTimeStamp(System.currentTimeMillis());
        return event;
    }
}
