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

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.HashMap;
import java.util.Map;
import net.ljcomputing.sensitive_logger.config.MaskingPatternProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Test class for MaskingConfigController.
 *
 * @author James G Willmore
 * @since 1.0.0
 */
@WebMvcTest(MaskingConfigController.class)
class MaskingConfigControllerTest {

    @Autowired private MockMvc mockMvc;

    @MockBean private MaskingPatternProperties maskingPatternProperties;

    @Test
    void testGetMaskingConfig() throws Exception {
        Map<String, String> patterns = new HashMap<>();
        patterns.put("token", "(?i)(token:)([\\w\\-._]+)");
        patterns.put("password", "(?i)(password:)([\\w\\-._]+)");

        when(maskingPatternProperties.getPatterns()).thenReturn(patterns);
        when(maskingPatternProperties.getMaskingChar()).thenReturn("*");

        mockMvc.perform(get("/api/masking/config"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.patternCount").value(2))
                .andExpect(jsonPath("$.maskingChar").value("*"))
                .andExpect(jsonPath("$.patterns.token").value("(?i)(token:)([\\w\\-._]+)"))
                .andExpect(jsonPath("$.patterns.password").value("(?i)(password:)([\\w\\-._]+)"));
    }

    @Test
    void testTestMasking() throws Exception {
        String testMessage = "User login with token=abc123";

        // Mock the dependencies even though they're not used in the response
        Map<String, String> patterns = new HashMap<>();
        patterns.put("token", "(?i)(token:)([\\w\\-._]+)");
        when(maskingPatternProperties.getPatterns()).thenReturn(patterns);

        mockMvc.perform(
                        post("/api/masking/test")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("\"" + testMessage + "\""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("Message logged successfully"))
                .andExpect(jsonPath("$.originalMessage").value("\"" + testMessage + "\""));
    }

    @Test
    void testTestAllPatterns() throws Exception {
        Map<String, String> patterns = new HashMap<>();
        patterns.put("token", "pattern1");
        patterns.put("password", "pattern2");

        when(maskingPatternProperties.getPatterns()).thenReturn(patterns);

        mockMvc.perform(post("/api/masking/test-all"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("All pattern tests logged successfully"))
                .andExpect(jsonPath("$.patterns").exists());
    }

    @Test
    void testGetPatternFound() throws Exception {
        when(maskingPatternProperties.getPatternByName("token"))
                .thenReturn("(?i)(token:)([\\w\\-._]+)");

        mockMvc.perform(get("/api/masking/pattern/token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("token"))
                .andExpect(jsonPath("$.pattern").value("(?i)(token:)([\\w\\-._]+)"));
    }

    @Test
    void testGetPatternNotFound() throws Exception {
        when(maskingPatternProperties.getPatternByName("nonexistent")).thenReturn(null);

        mockMvc.perform(get("/api/masking/pattern/nonexistent")).andExpect(status().isNotFound());
    }
}
