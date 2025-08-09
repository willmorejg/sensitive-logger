# Sensitive Logger

A Spring Boot application that demonstrates sensitive data logging with automatic masking capabilities using custom Logback layouts and Swagger UI for API documentation.

## Features

- **Custom Data Masking**: Automatically masks sensitive data in log messages using configurable regex patterns
- **Two-Group Pattern Matching**: Preserves identifiers while redacting sensitive values (e.g., `token=secret123` → `token=***`)
- **Swagger UI Integration**: Interactive API documentation and testing interface
- **Spring Boot Actuator**: Health checks and monitoring endpoints
- **Rolling File Logging**: Configurable log retention and archiving
- **Thread-Safe Design**: Concurrent logging with ReentrantReadWriteLock
- **Comprehensive Testing**: Unit tests with JUnit 5

## Quick Start

### Prerequisites

- Java 11 or higher
- Gradle 8.x

### Running the Application

```bash
# Clone the repository
git clone <repository-url>
cd sensitive-logger

# Run the application
./gradlew bootRun
```

The application will start on `http://localhost:8080`

### Accessing Swagger UI

Visit `http://localhost:8080/swagger-ui.html` to explore the API documentation and test endpoints interactively.

## API Endpoints

### Logging Demo Controller

- **GET** `/api/logging/info` - Get application information
- **POST** `/api/logging/message` - Log a simple message
- **POST** `/api/logging/sensitive` - Log sensitive data (demonstrates masking)

### Example Usage

```bash
# Test basic logging
curl -X POST http://localhost:8080/api/logging/message \
  -H "Content-Type: application/json" \
  -d '{"message": "User action performed"}'

# Test sensitive data masking
curl -X POST http://localhost:8080/api/logging/sensitive \
  -H "Content-Type: application/json" \
  -d '{
    "message": "User login with token=abc123",
    "email": "user@example.com",
    "phone": "555-1234",
    "creditCard": "4111-1111-1111-1111"
  }'
```

## Configuration

### Application Properties

```properties
# Application identification
spring.application.name=sensitive-logger
application.title=Sensitive Logger
application.version=1.0.0

# Token masking pattern (2 capture groups required)
# Group 1: identifier to preserve, Group 2: value to redact
logging.masking.pattern.token=(?i)(["']?token["']?\\\\s*[:=]\\\\s*["']?)([\\\\w\\\\-._]+)

# Swagger/OpenAPI configuration
springdoc.api-docs.path=/api-docs
springdoc.swagger-ui.path=/swagger-ui.html
springdoc.swagger-ui.operationsSorter=method
```

### Logback Configuration

The application uses `logback-spring.xml` for logging configuration with:

- **Console Appender**: Colorized output for development
- **File Appender**: Rolling file logs with custom masking layout
- **Data Masking**: Automatic redaction of sensitive data using `DataMaskingPatternLayout`

## Data Masking

### How It Works

The `DataMaskingPatternLayout` extends Logback's `PatternLayout` to provide automatic data masking using regex patterns with exactly 2 capture groups:

1. **Group 1**: The identifier to preserve (e.g., `"token":`, `token=`)
2. **Group 2**: The sensitive value to redact (e.g., `abc123`, `secret-key`)

### Supported Formats

- **JSON**: `"token": "secret123"` → `"token": "***"`
- **Key-Value**: `token=abc123` → `token=***`
- **Map Format**: `{token=secret}` → `{token=***}`

### Custom Patterns

Add custom masking patterns in `application.properties`:

```properties
# Credit card masking
logging.masking.pattern.creditcard=(card[\\s]*[:=][\\s]*)(\\d{4}-\\d{4}-\\d{4}-\\d{4})

# Email masking
logging.masking.pattern.email=(email[\\s]*[:=][\\s]*)([\\w._%+-]+@[\\w.-]+\\.[A-Za-z]{2,})
```

## Building and Testing

```bash
# Run all tests
./gradlew test

# Build the application
./gradlew build

# Run with specific profile
./gradlew bootRun --args='--spring.profiles.active=dev'
```

## Architecture

### Key Components

- **DataMaskingPatternLayout**: Custom Logback layout for sensitive data masking
- **LoggingDemoController**: REST controller demonstrating logging capabilities
- **OpenApiConfig**: Swagger/OpenAPI configuration
- **Thread Safety**: ReentrantReadWriteLock for concurrent access

### Project Structure

```text
src/
├── main/
│   ├── java/
│   │   └── net/ljcomputing/sensitive_logger/
│   │       ├── SensitiveLoggerApplication.java
│   │       ├── config/
│   │       │   └── OpenApiConfig.java
│   │       ├── controller/
│   │       │   └── LoggingDemoController.java
│   │       └── logging/
│   │           └── DataMaskingPatternLayout.java
│   └── resources/
│       ├── application.properties
│       ├── logback-spring.xml
│       └── banner.txt
└── test/
    └── java/
        └── net/ljcomputing/sensitive_logger/
            └── logging/
                └── DataMaskingPatternLayoutTest.java
```

## Dependencies

- **Spring Boot 2.7.18**: Web framework and auto-configuration
- **Spring Boot Actuator**: Monitoring and health checks
- **springdoc-openapi-ui 1.7.0**: OpenAPI 3 and Swagger UI
- **Logback**: Logging framework
- **JUnit 5**: Testing framework

## Logging

### Log Files

- **Location**: `${user.home}/logs/sensitive-logger.log`
- **Rotation**: Daily with 30-day retention
- **Size Limit**: 100MB total capacity
- **Archive**: `logs/archived/sensitive-logger.YYYY-MM-DD.log`

### Log Levels

- **Root**: WARN
- **Application (net.ljcomputing)**: DEBUG
- **Spring Framework**: WARN
- **Hibernate**: ERROR (SQL: DEBUG)

## Development

### Code Quality

- **Spotless**: Automatic code formatting
- **Google Java Format**: Code style enforcement
- **License Headers**: Automatic license header management

```bash
# Apply code formatting
./gradlew spotlessApply

# Check code formatting
./gradlew spotlessCheck
```

### Adding New Masking Patterns

1. Add pattern to `application.properties`
2. Ensure pattern has exactly 2 capture groups
3. Test with unit tests
4. Update documentation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run `./gradlew spotlessApply` for formatting
5. Submit a pull request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Authors

- **James G Willmore** - *LJ Computing* - [LJ Computing](https://ljcomputing.net)

## Acknowledgments

- Apache Software Foundation for the base license
- Spring Boot team for the excellent framework
- Logback team for the flexible logging framework
- springdoc team for OpenAPI integration
