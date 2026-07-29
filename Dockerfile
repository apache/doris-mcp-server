# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# Keep the runtime base reproducible across rebuilds. Upgrade the explicit
# Python patch release and OCI digest together.
FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    g++ \
    pkg-config \
    default-libmysqlclient-dev \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy only runtime files. This keeps source-control metadata, local reports,
# tests, caches, and untracked operator files out of the production image.
COPY doris_mcp_server ./doris_mcp_server
COPY start_server.sh .
COPY LICENSE.txt .

# Convert line endings for shell scripts and ensure proper execution format
RUN find . -name "*.sh" -exec dos2unix {} \; && \
    find . -name "*.sh" -exec chmod +x {} \;

# Create necessary directories
RUN mkdir -p /app/logs /app/config /app/data

# Create non-root user
RUN groupadd -r doris && useradd -r -g doris doris
RUN chown -R doris:doris /app
USER doris

# The image-level probe reports process liveness. Deployments that route Doris
# traffic should override it with the /ready probe, as docker-compose.yml does.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl --fail --silent --show-error --max-time 3 \
        http://127.0.0.1:3000/live || exit 1

# Streamable HTTP, liveness, and readiness share the server's HTTP listener.
EXPOSE 3000

# Start command
CMD ["/app/start_server.sh"]
