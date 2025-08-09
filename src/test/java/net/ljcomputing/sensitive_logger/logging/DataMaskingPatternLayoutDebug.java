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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.LoggingEvent;

public class DataMaskingPatternLayoutDebug {
    public static void main(String[] args) {
        DataMaskingPatternLayout layout = new DataMaskingPatternLayout();
        layout.setPattern("%msg");

        LoggerContext loggerContext = new LoggerContext();
        Logger logger = loggerContext.getLogger("test");
        layout.setContext(loggerContext);
        layout.start();

        // Test credit card masking
        layout.addMaskPattern("(\\d{4}-\\d{4}-\\d{4}-\\d{4})");

        LoggingEvent event = new LoggingEvent();
        event.setLoggerName(logger.getName());
        event.setLevel(Level.INFO);
        event.setMessage("Credit card: 1234-5678-9012-3456");
        event.setTimeStamp(System.currentTimeMillis());

        String result = layout.doLayout(event);

        System.out.println("Original: Credit card: 1234-5678-9012-3456");
        System.out.println("Result:   " + result);
        System.out.println("Length original: " + "1234-5678-9012-3456".length());
        System.out.println("Result length: " + result.length());

        // Count asterisks
        long asteriskCount = result.chars().filter(ch -> ch == '*').count();
        System.out.println("Asterisk count: " + asteriskCount);
    }
}
