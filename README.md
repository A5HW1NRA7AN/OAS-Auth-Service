# Agri Catalogue Service

A Spring Boot microservice that manages and serves agricultural catalogue data — crops, livestock, soil, season, and related agri-input entities — backed by Elasticsearch for fast search and retrieval.

## Overview

The Agri Catalogue Service is part of the **OpenAgriStack** ecosystem. It exposes REST APIs to create, search, and manage reference/catalogue data used across the platform, such as crop types, crop categories, crop varieties, seeds, livestock, soil types, seasons, extension equipment, pesticides, insecticides, fertilizers, and locations.

## Features

- CRUD-style operations for agri catalogue entities
- Elasticsearch-backed search with configurable index mappings per entity
- Redis caching for search results with configurable TTL
- Externalized, per-entity Elasticsearch field configuration via `application.yml`/`application.properties`

## Tech Stack

- **Java** (Spring Boot)
- **Elasticsearch** — primary search/data store for catalogue entities
- **Redis** — caching layer for search results
- **Maven/Gradle** — build tooling
- **Lombok** — boilerplate reduction

## Supported Entities

- Seed
- Crop Type
- Crop Category
- Crop Variety
- Livestock
- Season
- Soil
- Extension Equipment
- Pesticide
- Insecticide
- Fertilizer
- Location

## Getting Started

### Prerequisites

- Java 11+ (or the version specified in `pom.xml`/`build.gradle`)
- Maven or Gradle
- A running Elasticsearch instance
- A running Redis instance

### Configuration

Update `application.yml`/`application.properties` with your environment-specific values, including:

- Elasticsearch connection settings (host/port)
- Redis connection settings and `spring.redis.cacheTtl`
- Per-entity Elasticsearch JSON field path properties (e.g. `elastic.required.field.<entity>.json.path`)

### Build

```bash
# Maven
mvn clean install

# Gradle
./gradlew build
```

### Run

```bash
# Maven
mvn spring-boot:run

# Gradle
./gradlew bootRun
```

### Seeding Catalogue Entities

A helper script is included to create catalogue entities in bulk:

```bash
./createEntities.sh
```

This loops through the supported entity list and invokes the catalogue creation command for each.

## Project Structure

```
src/main/java/com/catalogue/verg/
├── core/
│   └── util/             # Shared configuration and utility classes (e.g. VergProperties)
├── livestock/
│   └── service/impl/     # Livestock service implementation
├── cropCategory/
│   └── service/impl/     # Crop Category service implementation
├── cropType/
│   └── service/impl/     # Crop Type service implementation
├── cropVariety/
│   └── service/impl/     # Crop Variety service implementation
├── soil/
│   └── service/impl/     # Soil service implementation
├── seed/
│   └── service/impl/     # Seed service implementation
├── extensionservices/
│   └── service/impl/     # Extension service implementation
├── fertilizer/
│   └── service/impl/     # Fertilizer service implementation
├── location/
│   └── service/impl/     # Location service implementation           
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a pull request

## License

Specify your project license here.
