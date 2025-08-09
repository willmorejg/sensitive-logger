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

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.encoder.LayoutWrappingEncoder;
import java.util.Iterator;
import net.ljcomputing.sensitive_logger.logging.DataMaskingPatternLayout;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

/**
 * Spring component that automatically configures DataMaskingPatternLayout instances with Spring
 * application context for automatic pattern loading.
 *
 * <p>This component finds all DataMaskingPatternLayout instances in the logging configuration and
 * provides them with the Spring ApplicationContext so they can automatically load masking patterns
 * from application properties.
 *
 * @author James G Willmore
 * @since 1.0.0
 */
@Component
public class LogbackSpringIntegrator implements ApplicationContextAware, BeanPostProcessor {

    private ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(@NonNull ApplicationContext applicationContext)
            throws BeansException {
        this.applicationContext = applicationContext;
        configureDataMaskingLayouts();
    }

    /** Finds and configures all DataMaskingPatternLayout instances in the Logback configuration. */
    private void configureDataMaskingLayouts() {
        try {
            LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();

            // Iterate through all loggers and appenders to find DataMaskingPatternLayout instances
            ch.qos.logback.classic.Logger rootLogger =
                    loggerContext.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME);
            configureAppenders(rootLogger);

            // Also check other loggers
            for (ch.qos.logback.classic.Logger logger : loggerContext.getLoggerList()) {
                configureAppenders(logger);
            }

        } catch (Exception e) {
            // Log error but don't fail application startup
            System.err.println(
                    "Failed to configure DataMaskingPatternLayout instances: " + e.getMessage());
        }
    }

    /** Configures DataMaskingPatternLayout instances in the given logger's appenders. */
    private void configureAppenders(ch.qos.logback.classic.Logger logger) {
        Iterator<Appender<ILoggingEvent>> appenderIterator = logger.iteratorForAppenders();
        while (appenderIterator.hasNext()) {
            Appender<ILoggingEvent> appender = appenderIterator.next();
            configureAppender(appender);
        }
    }

    /** Configures a single appender, looking for DataMaskingPatternLayout instances. */
    private void configureAppender(Appender<ILoggingEvent> appender) {
        // Check if this appender uses a LayoutWrappingEncoder with DataMaskingPatternLayout
        if (appender instanceof ch.qos.logback.core.encoder.LayoutWrappingEncoder) {
            LayoutWrappingEncoder<ILoggingEvent> encoder =
                    (LayoutWrappingEncoder<ILoggingEvent>) appender;
            if (encoder.getLayout() instanceof DataMaskingPatternLayout) {
                DataMaskingPatternLayout layout = (DataMaskingPatternLayout) encoder.getLayout();
                layout.setApplicationContext(applicationContext);
            }
        }

        // For other encoder types, we might need to use reflection or other methods
        // This is a simplified version that handles the most common case
        try {
            Object encoder = appender.getClass().getMethod("getEncoder").invoke(appender);
            if (encoder instanceof LayoutWrappingEncoder) {
                LayoutWrappingEncoder<ILoggingEvent> layoutEncoder =
                        (LayoutWrappingEncoder<ILoggingEvent>) encoder;
                if (layoutEncoder.getLayout() instanceof DataMaskingPatternLayout) {
                    DataMaskingPatternLayout layout =
                            (DataMaskingPatternLayout) layoutEncoder.getLayout();
                    layout.setApplicationContext(applicationContext);
                }
            }
        } catch (Exception e) {
            // Ignore - not all appenders have encoders
        }
    }
}
