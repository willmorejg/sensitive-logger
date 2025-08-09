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

import ch.qos.logback.core.Appender;
import ch.qos.logback.core.AppenderBase;
import ch.qos.logback.core.Layout;
import ch.qos.logback.core.encoder.LayoutWrappingEncoder;
import java.lang.reflect.Field;
import net.ljcomputing.sensitive_logger.logging.DataMaskingPatternLayout;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.event.EventListener;

/**
 * Spring configuration for logging components.
 *
 * <p>This configuration provides automatic integration between Spring-managed masking patterns and
 * Logback configurations, eliminating the need for manual pattern enumeration in XML.
 */
@Configuration
public class LoggingConfiguration implements InitializingBean {

    private final ApplicationContext applicationContext;
    private final MaskingPatternProperties maskingPatternProperties;

    public LoggingConfiguration(
            ApplicationContext applicationContext,
            MaskingPatternProperties maskingPatternProperties) {
        this.applicationContext = applicationContext;
        this.maskingPatternProperties = maskingPatternProperties;
    }

    /** Called after all beans are initialized to configure existing Logback layouts. */
    @Override
    public void afterPropertiesSet() throws Exception {
        configureExistingDataMaskingLayouts();
    }

    /** Called when Spring application is fully ready - try configuring layouts again. */
    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        configureExistingDataMaskingLayouts();
    }

    /** Find and configure existing DataMaskingPatternLayout instances in Logback appenders. */
    @SuppressWarnings("unchecked")
    private void configureExistingDataMaskingLayouts() {
        DataMaskingPatternLayout.configureAllLayouts(applicationContext, maskingPatternProperties);
    }

    /** Configure the layout of an appender if it's a DataMaskingPatternLayout. */
    private void configureAppenderLayout(Appender<?> appender) {
        try {
            System.out.println("Checking appender: " + appender.getClass().getSimpleName());

            Layout<?> layout = null;

            // Check if appender has a direct layout
            if (appender instanceof AppenderBase) {
                try {
                    Field layoutField = AppenderBase.class.getDeclaredField("layout");
                    layoutField.setAccessible(true);
                    layout = (Layout<?>) layoutField.get(appender);
                } catch (Exception e) {
                    // Layout field might not exist, continue
                }
            }

            // Check if appender has an encoder with a layout (common case)
            if (layout == null) {
                try {
                    Field encoderField = appender.getClass().getDeclaredField("encoder");
                    encoderField.setAccessible(true);
                    Object encoder = encoderField.get(appender);

                    if (encoder instanceof LayoutWrappingEncoder) {
                        LayoutWrappingEncoder<?> layoutEncoder = (LayoutWrappingEncoder<?>) encoder;
                        Field layoutField = LayoutWrappingEncoder.class.getDeclaredField("layout");
                        layoutField.setAccessible(true);
                        layout = (Layout<?>) layoutField.get(layoutEncoder);
                    }
                } catch (Exception e) {
                    // Encoder field might not exist or not be LayoutWrappingEncoder
                }
            }

            System.out.println(
                    "Found layout: "
                            + (layout != null ? layout.getClass().getSimpleName() : "null"));

            if (layout instanceof DataMaskingPatternLayout) {
                DataMaskingPatternLayout maskingLayout = (DataMaskingPatternLayout) layout;

                System.out.println(
                        "Found DataMaskingPatternLayout, isConfiguredFromSpring: "
                                + maskingLayout.isConfiguredFromSpring());

                // Only configure if not already configured from Spring
                if (!maskingLayout.isConfiguredFromSpring()) {
                    System.out.println("Configuring layout from Spring...");
                    configureLayoutFromSpring(maskingLayout);
                } else {
                    System.out.println("Layout already configured from Spring");
                }
            }
        } catch (Exception e) {
            System.out.println("Error configuring appender layout: " + e.getMessage());
            // Silently continue - layout might not be accessible or might not be the right type
        }
    }

    /** Configure a DataMaskingPatternLayout with Spring-managed patterns. */
    private void configureLayoutFromSpring(DataMaskingPatternLayout layout) {
        System.out.println("configureLayoutFromSpring called");
        System.out.println("Patterns available: " + maskingPatternProperties.hasPatterns());

        if (maskingPatternProperties.hasPatterns()) {
            System.out.println("Setting patterns: " + maskingPatternProperties.getPatterns());
            layout.setMaskPatterns(maskingPatternProperties.getPatterns());
        }
        layout.setMaskingChar(maskingPatternProperties.getMaskingChar());
        layout.setApplicationContext(applicationContext);

        System.out.println("Layout configured with ApplicationContext");
    }

    /**
     * Create and configure the DataMaskingPatternLayout bean.
     *
     * @param maskingPatternProperties The masking pattern properties
     * @return The configured layout
     */
    @Bean
    @Primary
    public DataMaskingPatternLayout dataMaskingPatternLayout(
            MaskingPatternProperties maskingPatternProperties) {
        DataMaskingPatternLayout layout = new DataMaskingPatternLayout();

        // Set the default pattern
        layout.setPattern("%d{ISO8601} [%thread] %-5level %logger{36} - %msg%n");

        // Configure masking patterns and character
        if (maskingPatternProperties.hasPatterns()) {
            layout.setMaskPatterns(maskingPatternProperties.getPatterns());
        }
        layout.setMaskingChar(maskingPatternProperties.getMaskingChar());

        return layout;
    }
}
