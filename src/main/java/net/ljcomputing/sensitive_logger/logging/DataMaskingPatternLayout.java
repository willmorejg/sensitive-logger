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
import net.ljcomputing.sensitive_logger.config.MaskingPatternProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.lang.NonNull;

/**
 * A PatternLayout that masks sensitive data in log messages based on configurable regex patterns.
 *
 * <p>This layout extends {@link PatternLayout} to provide data masking capabilities. It requires
 * regex patterns with exactly 2 capture groups: the first group identifies what to preserve (e.g.,
 * the field name "token"), and the second group identifies what to redact (e.g., the actual token
 * value).
 *
 * <p>The layout can automatically discover and load masking patterns from Spring configuration
 * properties when used in a Spring context.
 *
 * <p>Example configuration in logback.xml:
 *
 * <pre>
 * &lt;appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender"&gt;
 *   &lt;encoder class="ch.qos.logback.core.encoder.LayoutWrappingEncoder"&gt;
 *     &lt;layout class="net.ljcomputing.sensitive_logger.logging.DataMaskingPatternLayout"&gt;
 *       &lt;pattern&gt;%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n&lt;/pattern&gt;
 *       &lt;autoConfigureFromSpring&gt;true&lt;/autoConfigureFromSpring&gt;
 *     &lt;/layout&gt;
 *   &lt;/encoder&gt;
 * &lt;/appender&gt;
 * </pre>
 *
 * @author James G Willmore
 * @since 1.0.0
 */
public class DataMaskingPatternLayout extends PatternLayout implements ApplicationContextAware {

    private static final String DEFAULT_MASKING_CHAR = "*";
    private static final String PATTERN_DELIMITER = ",";

    // Static registry for all layout instances
    private static final List<DataMaskingPatternLayout> REGISTERED_LAYOUTS = new ArrayList<>();

    private final List<String> maskPatterns = new ArrayList<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private Pattern compiledPattern;
    private String maskingChar = DEFAULT_MASKING_CHAR;
    private ApplicationContext applicationContext;
    private boolean autoConfigureFromSpring = false;
    private boolean springConfigurationLoaded = false;

    /** Constructor - register this instance in the static registry. */
    public DataMaskingPatternLayout() {
        synchronized (REGISTERED_LAYOUTS) {
            REGISTERED_LAYOUTS.add(this);
        }
    }

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
     * Sets multiple mask patterns from a map of pattern names to regex patterns.
     *
     * @param patternMap A map where keys are pattern names and values are regex patterns. Each
     *     pattern must contain exactly 2 capturing groups.
     * @throws IllegalArgumentException if any pattern is invalid or doesn't have exactly 2 capture
     *     groups
     */
    public void setMaskPatterns(final java.util.Map<String, String> patternMap) {
        if (patternMap == null || patternMap.isEmpty()) {
            addWarn("Pattern map is null or empty");
            return;
        }

        lock.writeLock().lock();
        try {
            // Clear existing patterns
            maskPatterns.clear();

            // Validate and add all patterns
            final List<String> newPatterns = new ArrayList<>(patternMap.values());
            validatePatterns(newPatterns);

            maskPatterns.addAll(newPatterns);
            recompilePattern();

            addInfo("Set " + newPatterns.size() + " mask pattern(s) from configuration");
        } finally {
            lock.writeLock().unlock();
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

    /**
     * Sets the ApplicationContext for Spring integration.
     *
     * @param applicationContext the Spring application context
     */
    @Override
    public void setApplicationContext(@NonNull final ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
        if (autoConfigureFromSpring) {
            loadPatternsFromSpring();
        }
    }

    /**
     * Enables automatic configuration from Spring properties.
     *
     * @param autoConfigureFromSpring true to enable auto-configuration
     */
    public void setAutoConfigureFromSpring(boolean autoConfigureFromSpring) {
        this.autoConfigureFromSpring = autoConfigureFromSpring;
        if (autoConfigureFromSpring && applicationContext != null && !springConfigurationLoaded) {
            loadPatternsFromSpring();
        }
    }

    /** Loads masking patterns from Spring configuration properties. */
    private void loadPatternsFromSpring() {
        if (applicationContext == null || springConfigurationLoaded) {
            return;
        }

        try {
            MaskingPatternProperties properties =
                    applicationContext.getBean(MaskingPatternProperties.class);
            if (properties.hasPatterns()) {
                lock.writeLock().lock();
                try {
                    // Clear existing patterns and load from Spring
                    maskPatterns.clear();
                    maskPatterns.addAll(properties.getPatterns().values());

                    // Set masking character
                    this.maskingChar = properties.getMaskingChar();

                    // Recompile patterns
                    recompilePattern();

                    springConfigurationLoaded = true;
                    addInfo(
                            "Loaded "
                                    + maskPatterns.size()
                                    + " patterns from Spring configuration");
                } finally {
                    lock.writeLock().unlock();
                }
            }
        } catch (Exception e) {
            addWarn("Failed to load patterns from Spring configuration: " + e.getMessage());
        }
    }

    @Override
    public String doLayout(final ILoggingEvent event) {
        // Ensure patterns are loaded from Spring if auto-configuration is enabled
        if (autoConfigureFromSpring && !springConfigurationLoaded && applicationContext != null) {
            loadPatternsFromSpring();
        }

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
            // With alternation (|), we need to find which groups are non-null
            // Each pattern has 2 groups, so we look for pairs
            for (int i = 1; i < matcher.groupCount(); i += 2) {
                String key = matcher.group(i); // Group i: identifier/key
                String value = matcher.group(i + 1); // Group i+1: sensitive value

                if (key != null && value != null) {
                    // Group i+1 is the sensitive value to redact
                    final int valueStart = matcher.start(i + 1);
                    final int valueEnd = matcher.end(i + 1);
                    maskingOperations.add(new MaskingInfo(valueStart, valueEnd));
                    break; // Only one pattern can match at a time
                }
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

    /**
     * Check if this layout has been configured from Spring context.
     *
     * @return true if configured from Spring, false otherwise
     */
    public boolean isConfiguredFromSpring() {
        return applicationContext != null;
    }

    /**
     * Configure all registered DataMaskingPatternLayout instances with Spring patterns. This is
     * called by the Spring configuration to set up all layouts created by Logback.
     */
    public static void configureAllLayouts(
            ApplicationContext applicationContext,
            MaskingPatternProperties maskingPatternProperties) {
        synchronized (REGISTERED_LAYOUTS) {
            for (DataMaskingPatternLayout layout : REGISTERED_LAYOUTS) {
                if (layout.autoConfigureFromSpring) {
                    layout.setApplicationContext(applicationContext);

                    if (maskingPatternProperties.hasPatterns()) {
                        layout.setMaskPatterns(maskingPatternProperties.getPatterns());
                    }
                    layout.setMaskingChar(maskingPatternProperties.getMaskingChar());
                }
            }
        }
    }
}
