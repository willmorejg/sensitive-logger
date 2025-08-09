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

import java.util.HashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for data masking patterns.
 *
 * <p>This class binds to application properties with the prefix "logging.masking.pattern" and
 * provides access to multiple masking patterns that can be configured via application.properties.
 *
 * <p>Example configuration:
 *
 * <pre>
 * logging.masking.pattern.token=(?i)(["']?token["']?\\s*[:=]\\s*["']?)([\\w\\-._]+)
 * logging.masking.pattern.password=(?i)(["']?password["']?\\s*[:=]\\s*["']?)([\\w\\-._]+)
 * logging.masking.pattern.credit-card=(credit[\\s]*card[\\s]*[:=]\\s*)(\\d{4}-\\d{4}-\\d{4}-\\d{4})
 * </pre>
 *
 * @author James G Willmore
 * @since 1.0.0
 */
@Component
@ConfigurationProperties(prefix = "logging.masking")
public class MaskingPatternProperties {

    /**
     * Map of pattern names to regex patterns. Each pattern should have exactly 2 capture groups: -
     * Group 1: The identifier to preserve - Group 2: The value to redact
     */
    private Map<String, String> pattern = new HashMap<>();

    /** The character used for masking sensitive data. */
    private String maskingChar = "*";

    /**
     * Gets the map of masking patterns.
     *
     * @return the patterns map
     */
    public Map<String, String> getPatterns() {
        return pattern;
    }

    /**
     * Sets the map of masking patterns.
     *
     * @param patterns the patterns map
     */
    public void setPatterns(Map<String, String> patterns) {
        this.pattern = patterns;
    }

    /**
     * Gets the pattern map (Spring Boot binding method).
     *
     * @return the pattern map
     */
    public Map<String, String> getPattern() {
        return pattern;
    }

    /**
     * Sets the pattern map (Spring Boot binding method).
     *
     * @param pattern the pattern map
     */
    public void setPattern(Map<String, String> pattern) {
        this.pattern = pattern;
    }

    /**
     * Gets the masking character.
     *
     * @return the masking character
     */
    public String getMaskingChar() {
        return maskingChar;
    }

    /**
     * Sets the masking character.
     *
     * @param maskingChar the masking character
     */
    public void setMaskingChar(String maskingChar) {
        this.maskingChar = maskingChar;
    }

    /**
     * Convenience method to add a pattern.
     *
     * @param name the pattern name
     * @param pattern the regex pattern
     */
    public void addPattern(String name, String pattern) {
        this.pattern.put(name, pattern);
    }

    /**
     * Convenience method to get a specific pattern.
     *
     * @param name the pattern name
     * @return the regex pattern, or null if not found
     */
    public String getPatternByName(String name) {
        return this.pattern.get(name);
    }

    /**
     * Checks if any patterns are configured.
     *
     * @return true if patterns exist, false otherwise
     */
    public boolean hasPatterns() {
        return pattern != null && !pattern.isEmpty();
    }
}
