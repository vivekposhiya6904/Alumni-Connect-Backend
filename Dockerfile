
FROM maven:3.9-eclipse-temurin-17 AS build

WORKDIR /app

COPY . .

RUN chmod +x mvnw && ./mvnw -B clean package

FROM eclipse-temurin:17-jre

WORKDIR /app

COPY --from=build /app/target/*.jar /app/app.jar

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "java -Dserver.port=${PORT:-8080} -jar /app/app.jar"]
