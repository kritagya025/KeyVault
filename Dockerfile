# syntax=docker/dockerfile:1

# ---- Build stage -------------------------------------------------------------
# Dependencies are resolved in their own layer so that editing source code does
# not force a re-download of the whole Maven repository on every rebuild.
FROM maven:3.9-eclipse-temurin-17 AS build

WORKDIR /build

COPY pom.xml ./
RUN mvn -B -ntp dependency:go-offline

COPY src ./src
RUN mvn -B -ntp clean package -DskipTests \
    && mv target/keyvault-*.jar target/keyvault.jar

# ---- Runtime stage -----------------------------------------------------------
FROM eclipse-temurin:17-jre-alpine AS runtime

# Run as an unprivileged user; nothing in the image needs root.
RUN addgroup -S keyvault && adduser -S -G keyvault keyvault

WORKDIR /app
COPY --from=build --chown=keyvault:keyvault /build/target/keyvault.jar ./keyvault.jar

USER keyvault
EXPOSE 8080

# Container memory limits, not the host's, should drive the heap size.
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75.0"

HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:8080/api/health || exit 1

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/keyvault.jar"]
