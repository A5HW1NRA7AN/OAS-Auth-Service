# OAS Auth Service. Jenkins builds this file directly with no separate Maven stage,
# so the build must be self-contained.

# ---- Stage 1: build ----
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app

# pom first, so the dependency layer is cached when only sources change.
COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn clean package -DskipTests -B

# ---- Stage 2: runtime ----
# Not -jre-alpine: those tags are amd64-only and will not run on arm64.
FROM eclipse-temurin:17-jre
WORKDIR /app

# Repackaging leaves the original as *.jar.original, so this matches exactly one file.
COPY --from=build /app/target/*.jar app.jar

# Platform contract: listen on 8080 by default, overridable via SERVER_PORT.
EXPOSE 8080

# Not root; the app writes nothing to disk.
RUN useradd --system --uid 10001 --create-home appuser
USER appuser

ENTRYPOINT ["java", "-jar", "app.jar"]
