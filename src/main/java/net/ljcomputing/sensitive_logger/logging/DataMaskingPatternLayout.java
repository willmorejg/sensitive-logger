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

import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.ILoggingEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

/**
 * A PatternLayout that masks sensitive data in log messages based on configurable regex patterns.
 *
 * <p>This layout extends {@link PatternLayout} to provide data masking capabilities. It requires
 * regex patterns with exactly 2 capture groups: the first group identifies what to preserve (e.g.,
 * the field name "token"), and the second group identifies what to redact (e.g., the actual token
 * value).
 *
 * <p>Example configuration in logback.xml:
 *
 * <pre>
 * &lt;appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender"&gt;
 *   &lt;encoder class="ch.qos.logback.core.encoder.LayoutWrappingEncoder"&gt;
 *     &lt;layout class="net.ljcomputing.sensitive_logger.logging.DataMaskingPatternLayout"&gt;
 *       &lt;pattern&gt;%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n&lt;/pattern&gt;
 *       &lt;maskPattern&gt;(token[:=]\\s*)([\\w\\-._]+)&lt;/maskPattern&gt;
 *       &lt;maskingChar&gt;*&lt;/maskingChar&gt;
 *     &lt;/layout&gt;
 *   &lt;/encoder&gt;
 * &lt;/appender&gt;
 * </pre>
 *
 * <p>In the above example, the pattern matches "token=abc123" and will produce "token=***" where
 * the first group "(token[:=]\\s*)" is preserved and the second group "([\\w\\-._]+)" is replaced
 * with masking characters.
 *
 * @author James G Willmore
 * @since 1.0.0
 */
public class DataMaskingPatternLayout extends PatternLayout {

    private static final String DEFAULT_MASKING_CHAR = "*";
    private static final String PATTERN_DELIMITER = ",";

    private final List<String> maskPatterns = new ArrayList<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private Pattern compiledPattern;
    private String maskingChar = DEFAULT_MASKING_CHAR;

    /**
     * Adds mask patterns for identifying sensitive data.
     *
     * @param maskPattern A comma-separated list of regex patterns for masking sensitive data. Each
     *     pattern must contain exactly 2 capturing groups: the first group for the identifier to
     *     preserve, and the second group for the value to redact.
     * @throws IllegalArgumentException if the pattern is null, empty, contains invalid regex, or
     *     doesn't have exactly 2 capture groups
     */
    public void addMaskPattern(final String maskPattern) {
        if (maskPattern == null || maskPattern.trim().isEmpty()) {
            addWarn("Mask pattern cannot be null or empty");
            return;
        }

        lock.writeLock().lock();
        try {
            final List<String> newPatterns = parsePatterns(maskPattern);
            validatePatterns(newPatterns);

            maskPatterns.addAll(newPatterns);
            recompilePattern();

            addInfo("Added " + newPatterns.size() + " mask pattern(s)");
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Sets the character used for masking sensitive data.
     *
     * @param maskingChar The character to use for masking (default: '*')
     */
    public void setMaskingChar(final String maskingChar) {
        if (maskingChar == null || maskingChar.isEmpty()) {
            addWarn(
                    "Masking character cannot be null or empty, using default: "
                            + DEFAULT_MASKING_CHAR);
            return;
        }

        lock.writeLock().lock();
        try {
            if (maskingChar.length() > 1) {
                addWarn(
                        "Masking character should be a single character, using first character: "
                                + maskingChar.charAt(0));
                this.maskingChar = String.valueOf(maskingChar.charAt(0));
            } else {
                this.maskingChar = maskingChar;
            }

            addInfo("Set masking character to: '" + this.maskingChar + "'");
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Gets the current masking character.
     *
     * @return the masking character
     */
    public String getMaskingChar() {
        lock.readLock().lock();
        try {
            return maskingChar;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Gets a copy of the current mask patterns.
     *
     * @return a list of mask patterns
     */
    public List<String> getMaskPatterns() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(maskPatterns);
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public String doLayout(final ILoggingEvent event) {
        final String originalMessage = super.doLayout(event);
        return maskSensitiveData(originalMessage);
    }

    /**
     * Masks sensitive data in the given message using the configured patterns.
     *
     * @param message the message to mask
     * @return the masked message
     */
    private String maskSensitiveData(final String message) {
        if (message == null || message.isEmpty()) {
            return message;
        }

        lock.readLock().lock();
        try {
            final Pattern pattern = compiledPattern;
            if (pattern == null) {
                return message;
            }
            return performMasking(message, pattern);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Performs the actual masking operation on the message. Expects patterns with exactly 2 capture
     * groups: - Group 1: The identifier/key to preserve (e.g., "token") - Group 2: The value to
     * redact (e.g., "abc123")
     *
     * @param message the message to mask
     * @param pattern the compiled pattern to match against
     * @return the masked message
     */
    private String performMasking(final String message, final Pattern pattern) {
        final StringBuilder maskedMessage = new StringBuilder(message);
        final Matcher matcher = pattern.matcher(message);
        final char maskChar = maskingChar.charAt(0); // Get mask char within read lock scope

        // Process matches from end to beginning to avoid index shifting issues
        final List<MaskingInfo> maskingOperations = new ArrayList<>();

        while (matcher.find()) {
            // Ensure we have exactly 2 groups as expected
            if (matcher.groupCount() == 2 && matcher.group(1) != null && matcher.group(2) != null) {
                // Group 1 is preserved (identifier/key)
                // Group 2 is redacted (sensitive value)
                final int valueStart = matcher.start(2);
                final int valueEnd = matcher.end(2);
                maskingOperations.add(new MaskingInfo(valueStart, valueEnd));
            }
        }

        // Sort by start position in descending order to process from end to beginning
        maskingOperations.sort((a, b) -> Integer.compare(b.start, a.start));

        // Apply masking only to the second capture group (the value)
        for (final MaskingInfo operation : maskingOperations) {
            maskRange(maskedMessage, operation.start, operation.end, maskChar);
        }

        return maskedMessage.toString();
    }

    /**
     * Masks a range of characters in the StringBuilder.
     *
     * @param sb the StringBuilder to modify
     * @param start the start index (inclusive)
     * @param end the end index (exclusive)
     * @param maskChar the character to use for masking
     */
    private void maskRange(
            final StringBuilder sb, final int start, final int end, final char maskChar) {
        for (int i = start; i < end && i < sb.length(); i++) {
            sb.setCharAt(i, maskChar);
        }
    }

    /**
     * Parses a comma-separated list of patterns.
     *
     * @param maskPattern the pattern string to parse
     * @return a list of individual patterns
     */
    private List<String> parsePatterns(final String maskPattern) {
        return Arrays.stream(maskPattern.split(PATTERN_DELIMITER))
                .map(String::trim)
                .filter(pattern -> !pattern.isEmpty())
                .collect(Collectors.toList());
    }

    /**
     * Validates that all patterns are valid regex patterns with exactly 2 capture groups.
     *
     * @param patterns the patterns to validate
     * @throws IllegalArgumentException if any pattern is invalid or doesn't have exactly 2 capture
     *     groups
     */
    private void validatePatterns(final List<String> patterns) {
        for (final String pattern : patterns) {
            try {
                final Pattern testPattern = Pattern.compile(pattern);
                final int groupCount = getGroupCount(testPattern);

                if (groupCount != 2) {
                    final String errorMsg =
                            "Pattern must have exactly 2 capture groups (found "
                                    + groupCount
                                    + "): "
                                    + pattern
                                    + " - First group should match the identifier to keep, second"
                                    + " group should match the value to redact";
                    addError(errorMsg);
                    throw new IllegalArgumentException(errorMsg);
                }
            } catch (final PatternSyntaxException e) {
                final String errorMsg =
                        "Invalid regex pattern: " + pattern + " - " + e.getMessage();
                addError(errorMsg);
                throw new IllegalArgumentException(errorMsg, e);
            }
        }
    }

    /**
     * Gets the number of capture groups in a compiled pattern by creating a test matcher.
     *
     * @param pattern the compiled pattern
     * @return the number of capture groups
     */
    private int getGroupCount(final Pattern pattern) {
        // Create a matcher with an empty string to get group count
        return pattern.matcher("").groupCount();
    }

    /** Recompiles the combined pattern from all mask patterns. */
    private void recompilePattern() {
        if (maskPatterns.isEmpty()) {
            compiledPattern = null;
            return;
        }

        try {
            final String combinedPattern = maskPatterns.stream().collect(Collectors.joining("|"));
            compiledPattern = Pattern.compile(combinedPattern, Pattern.MULTILINE);
            addInfo("Compiled pattern with " + maskPatterns.size() + " mask pattern(s)");
        } catch (final PatternSyntaxException e) {
            addError("Failed to compile combined pattern: " + e.getMessage());
            compiledPattern = null;
        }
    }

    /** Simple data class to hold masking operation information. */
    private static class MaskingInfo {
        final int start;
        final int end;

        MaskingInfo(final int start, final int end) {
            this.start = start;
            this.end = end;
        }
    }
}
