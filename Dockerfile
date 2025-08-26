# Build stage
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /workspace
COPY . /workspace
RUN mvn -q -DskipTests clean package

# Runtime
FROM eclipse-temurin:17-jre
WORKDIR /app

# Install tools needed by the worker (git, python, pip, semgrep, cyclonedx)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    git curl ca-certificates python3 python3-venv python3-pip \
    && pip3 install --no-cache-dir --break-system-packages semgrep \
    && curl -L -o /usr/local/bin/cyclonedx \
    https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.28.1/cyclonedx-linux-x64 \
    && chmod +x /usr/local/bin/cyclonedx \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /workspace/target/app.jar /app/app.jar
COPY scanner-scripts /app/scanner-scripts
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
