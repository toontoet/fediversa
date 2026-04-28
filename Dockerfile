# Stage 1: Build the Go application
FROM golang:1.26-alpine AS builder

WORKDIR /app

# go-sqlite3 uses CGO, so the builder needs a C toolchain and SQLite headers.
RUN apk add --no-cache build-base sqlite-dev ca-certificates

# Copy Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the application binary. go-sqlite3 requires CGO, so this is built on Alpine
# with the C toolchain installed above.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags='-w -s' -o fediversa ./cmd/fediversa

# Stage 2: Create the final minimal image
FROM alpine:latest

WORKDIR /app

# Install SQLite libraries and certificates needed at runtime.
RUN apk add --no-cache sqlite-libs ca-certificates

# Copy the compiled binary from the builder stage
COPY --from=builder /app/fediversa .

# Copy migrations needed at runtime for embedded migrations
COPY internal/database/migrations ./migrations

# Create the directory for media storage (should ideally be a volume)
RUN mkdir -p media && chown nobody:nogroup media
VOLUME /app/media

# Create directory for database storage (should ideally be a volume)
# Database will be created at the path specified by DATABASE_PATH env var.
# If DATABASE_PATH is just "fediversa.db", it will be in /app/.
# Ensure the directory for the DB path is writable.
RUN mkdir -p db && chown nobody:nogroup db
# Example volume mount point if DB is in /app/db/fediversa.db
# VOLUME /app/db 

# Expose the default web server port
EXPOSE 8080 

# Set environment variables (defaults, can be overridden)
ENV DATABASE_PATH=/app/db/fediversa.db 
ENV SYNC_INTERVAL_MINUTES=5
ENV LISTEN_ADDR=:8080
ENV BASE_URL=http://localhost:8080
# Other ENV vars like API keys should be passed during `docker run` or via docker-compose

# Run as non-root user for security
USER nobody:nogroup

# Command to run the application
ENTRYPOINT ["/app/fediversa"]
