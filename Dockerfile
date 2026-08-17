# OAS Auth Service — image built by the Jenkins pipeline and pushed to ECR.
#
# The pipeline has no separate Maven stage; it builds this file directly, so the
# build must be self-contained.

# ---- Stage 1: build ----
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app

# pom first, so the dependency layer is cached when only sources change.
COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn clean package -DskipTests -B

# ---- Stage 2: runtime ----
# eclipse-temurin:17-jre, not -jre-alpine: the Alpine tags are published for amd64
# only, so the Alpine variant cannot be built or run on arm64 (Apple Silicon) at all.
FROM eclipse-temurin:17-jre
WORKDIR /app

# Spring Boot repackaging leaves the pre-repackage artifact as *.jar.original, so this
# matches exactly one file.
COPY --from=build /app/target/*.jar app.jar

# Platform contract: listen on 8080 by default, overridable via SERVER_PORT.
EXPOSE 8080

# Not root. The app writes nothing to disk, so it needs no writable paths.
RUN useradd --system --uid 10001 --create-home appuser
USER appuser

ENTRYPOINT ["java", "-jar", "app.jar"]
