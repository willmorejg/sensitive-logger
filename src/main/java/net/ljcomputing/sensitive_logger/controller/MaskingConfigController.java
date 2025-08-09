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
package net.ljcomputing.sensitive_logger.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.HashMap;
import java.util.Map;
import net.ljcomputing.sensitive_logger.config.MaskingPatternProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller demonstrating masking pattern configuration and usage.
 *
 * <p>This controller provides endpoints to view the current masking configuration and test the
 * masking functionality with various patterns.
 *
 * @author James G Willmore
 * @since 1.0.0
 */
@RestController
@RequestMapping("/api/masking")
@Tag(
        name = "Masking Configuration",
        description = "Endpoints for managing and testing data masking patterns")
public class MaskingConfigController {

    private static final Logger logger = LoggerFactory.getLogger(MaskingConfigController.class);

    private final MaskingPatternProperties maskingPatternProperties;

    public MaskingConfigController(MaskingPatternProperties maskingPatternProperties) {
        this.maskingPatternProperties = maskingPatternProperties;
    }

    /**
     * Get the current masking configuration.
     *
     * @return current masking patterns and settings
     */
    @GetMapping("/config")
    @Operation(
            summary = "Get masking configuration",
            description = "Returns the currently configured masking patterns and settings")
    public ResponseEntity<Map<String, Object>> getMaskingConfig() {
        Map<String, Object> config = new HashMap<>();
        config.put("patterns", maskingPatternProperties.getPatterns());
        config.put("maskingChar", maskingPatternProperties.getMaskingChar());
        config.put("patternCount", maskingPatternProperties.getPatterns().size());

        logger.info(
                "Returning masking configuration with {} patterns",
                maskingPatternProperties.getPatterns().size());

        return ResponseEntity.ok(config);
    }

    /**
     * Test masking with a sensitive message.
     *
     * @param message the message to log (may contain sensitive data)
     * @return confirmation of logging
     */
    @PostMapping("/test")
    @Operation(
            summary = "Test data masking",
            description = "Logs the provided message to test masking patterns")
    public ResponseEntity<Map<String, String>> testMasking(
            @Parameter(
                            description = "Message to log and test masking",
                            example = "User login with token=abc123 and password=secret456")
                    @RequestBody
                    String message) {

        logger.info("Testing masking with message: {}", message);

        Map<String, String> response = new HashMap<>();
        response.put("status", "Message logged successfully");
        response.put("message", "Check the logs to see the masking in action");
        response.put("originalMessage", message);

        return ResponseEntity.ok(response);
    }

    /**
     * Test masking with multiple sensitive data types.
     *
     * @return confirmation of logging various sensitive data
     */
    @PostMapping("/test-all")
    @Operation(
            summary = "Test all masking patterns",
            description =
                    "Logs messages containing various types of sensitive data to test all"
                            + " configured patterns")
    public ResponseEntity<Map<String, String>> testAllPatterns() {

        // Test token masking
        logger.info("Token test: Authorization token=abc123def456");
        logger.info("Token JSON: {\"token\": \"xyz789ghi012\"}");

        // Test password masking
        logger.info("Password test: User password=supersecret123");
        logger.info("Password JSON: {\"password\": \"mypassword456\"}");

        // Test API key masking
        logger.info("API Key test: Request api-key=sk-1234567890abcdef");
        logger.info("API Key JSON: {\"api_key\": \"ak-fedcba0987654321\"}");

        // Test secret masking
        logger.info("Secret test: Application secret=topsecret999");
        logger.info("Secret JSON: {\"secret\": \"confidential888\"}");

        // Test credit card masking
        logger.info("Credit card test: Payment credit card=1234-5678-9012-3456");
        logger.info("Credit card JSON: {\"credit_card\": \"4111 1111 1111 1111\"}");

        Map<String, String> response = new HashMap<>();
        response.put("status", "All pattern tests logged successfully");
        response.put("message", "Check the logs to see all masking patterns in action");
        response.put(
                "patterns", String.join(", ", maskingPatternProperties.getPatterns().keySet()));

        return ResponseEntity.ok(response);
    }

    /**
     * Get a specific pattern configuration.
     *
     * @param patternName the name of the pattern to retrieve
     * @return the pattern configuration or 404 if not found
     */
    @GetMapping("/pattern/{patternName}")
    @Operation(
            summary = "Get specific pattern",
            description = "Returns the regex pattern for a specific masking pattern name")
    public ResponseEntity<Map<String, String>> getPattern(
            @Parameter(description = "Name of the pattern", example = "token") @PathVariable
                    String patternName) {

        String pattern = maskingPatternProperties.getPatternByName(patternName);
        if (pattern == null) {
            logger.warn("Pattern '{}' not found", patternName);
            return ResponseEntity.notFound().build();
        }

        Map<String, String> response = new HashMap<>();
        response.put("name", patternName);
        response.put("pattern", pattern);

        logger.info("Retrieved pattern '{}': {}", patternName, pattern);

        return ResponseEntity.ok(response);
    }
}
