# Stage 1: Build the Spring Boot application using Maven and Temurin JDK 17
FROM maven:3.9-eclipse-temurin-17 AS build

WORKDIR /app

# Cache dependencies layer
COPY pom.xml mvnw ./
COPY .mvn .mvn
RUN chmod +x mvnw && ./mvnw -B dependency:go-offline || true

# Copy project source and package the executable JAR (tests run during local CI/verification)
COPY . .
RUN chmod +x mvnw && ./mvnw -B clean package -DskipTests

# Stage 2: Minimal Java 17 JRE runtime
FROM eclipse-temurin:17-jre

WORKDIR /app

# Ensure runtime upload directory exists and copy initial seed assets if present
RUN mkdir -p /app/uploads
COPY --from=build /app/uploads /app/uploads/

# Copy the built jar unambiguously
COPY --from=build /app/target/alumni-management-*.jar /app/app.jar

# Render dynamic port binding and production profile activation
EXPOSE 8080

ENTRYPOINT ["sh", "-c", "java -Dserver.port=${PORT:-8080} -Dspring.profiles.active=${SPRING_PROFILES_ACTIVE:-prod} -jar /app/app.jar"]
