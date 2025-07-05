#------------------- Stage 1: Build Stage -------------------#
FROM maven:3.9.8-eclipse-temurin-21-alpine AS builder
WORKDIR /app

COPY pom.xml .
RUN mvn dependency:go-offline

COPY src ./src
RUN mvn package -DskipTests

#------------------- Stage 2: Run Stage -------------------#
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# For better security, create a non-root user to run the application
RUN addgroup -S spring && adduser -S -G spring spring
USER spring

COPY --from=builder /app/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]