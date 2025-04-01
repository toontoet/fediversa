# Stage 1: Build the Go application
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the application binary
# Statically link and strip binary for smaller size
# Ensure CGO_ENABLED=0 for Alpine compatibility if using sqlite3 without modifications
# Note: CGO_ENABLED=0 might conflict with mattn/go-sqlite3 which uses Cgo.
# If building on Alpine for Alpine, CGO might be okay, but cross-compiling needs CGO_ENABLED=0.
# Let's assume building *on* Alpine for now.
# If issues arise, consider CGO_ENABLED=0 and a pure Go sqlite driver, or ensure build env matches target.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags='-w -s' -o fediversa cmd/fediversa/main.go

# Stage 2: Create the final minimal image
FROM alpine:latest

WORKDIR /app

# Install SQLite libraries needed by the CGO build of mattn/go-sqlite3
RUN apk add --no-cache sqlite-libs

# Copy the compiled binary from the builder stage
COPY --from=builder /app/fediversa .

# Copy migrations needed at runtime for embedded migrations
COPY migrations ./migrations

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
