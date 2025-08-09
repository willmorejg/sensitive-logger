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
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** REST controller for demonstrating sensitive data logging capabilities. */
@RestController
@RequestMapping("/api/logging")
@Tag(
        name = "Logging Demo",
        description = "API for demonstrating sensitive data logging and masking")
public class LoggingDemoController {

    private static final Logger logger = LoggerFactory.getLogger(LoggingDemoController.class);

    @Operation(
            summary = "Log a simple message",
            description = "Logs a simple message and returns it")
    @ApiResponses(
            value = {
                @ApiResponse(responseCode = "200", description = "Message logged successfully"),
                @ApiResponse(responseCode = "400", description = "Invalid input")
            })
    @PostMapping("/message")
    public ResponseEntity<Map<String, String>> logMessage(
            @Parameter(description = "The message to log", required = true) @RequestBody
                    Map<String, String> request) {

        String message = request.get("message");
        if (message == null || message.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Message cannot be empty"));
        }

        logger.info("User message: {}", message);

        Map<String, String> response = new HashMap<>();
        response.put("status", "logged");
        response.put("message", message);
        response.put("timestamp", String.valueOf(System.currentTimeMillis()));

        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Log sensitive data",
            description = "Logs a message containing sensitive data that should be masked")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Sensitive data logged successfully"),
                @ApiResponse(responseCode = "400", description = "Invalid input")
            })
    @PostMapping("/sensitive")
    public ResponseEntity<Map<String, String>> logSensitiveData(
            @Parameter(description = "Data containing sensitive information", required = true)
                    @RequestBody
                    Map<String, String> request) {

        String email = request.get("email");
        String phone = request.get("phone");
        String creditCard = request.get("creditCard");
        String message = request.get("message");

        if (message == null || message.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Message cannot be empty"));
        }

        // Log the message - this will demonstrate the masking functionality
        logger.info(
                "Processing sensitive data - Email: {}, Phone: {}, Credit Card: {}, Message: {}",
                email,
                phone,
                creditCard,
                message);
        logger.info("request: {}", request);

        Map<String, String> response = new HashMap<>();
        response.put("status", "processed");
        response.put("message", "Sensitive data logged with masking");
        response.put("timestamp", String.valueOf(System.currentTimeMillis()));

        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Get application info",
            description = "Returns basic information about the application")
    @GetMapping("/info")
    public ResponseEntity<Map<String, String>> getInfo() {
        Map<String, String> info = new HashMap<>();
        info.put("application", "Sensitive Logger");
        info.put("version", "1.0.0");
        info.put("description", "Demonstrates sensitive data logging with masking capabilities");

        logger.debug("Application info requested");

        return ResponseEntity.ok(info);
    }
}
