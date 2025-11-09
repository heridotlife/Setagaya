# Build stage
FROM golang:1.25.4-alpine3.22@sha256:d3f0cf7723f3429e3f9ed846243970b20a2de7bae6a5b66fc5914e228d831bbb AS builder

# Install build dependencies and security updates
RUN apk update && apk upgrade && \
    apk add --no-cache git ca-certificates tzdata && \
    addgroup -g 1001 setagaya && \
    adduser -D -u 1001 -G setagaya setagaya

# Set working directory
WORKDIR /build

# Copy go mod files first for better layer caching
COPY setagaya/go.mod setagaya/go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY setagaya/ .

# Build the API server binary with security flags and optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o setagaya \
    ./main.go

# Runtime stage
FROM alpine:3.22@sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d

# Install security updates and create non-root user
RUN apk update && apk upgrade && \
    apk add --no-cache ca-certificates tzdata && \
    addgroup -g 1001 setagaya && \
    adduser -D -u 1001 -G setagaya setagaya

# Environment variables (using build args for better security)
ARG GCP_CREDENTIALS_PATH=/auth/setagaya-gcp.json
ENV GOOGLE_APPLICATION_CREDENTIALS=${GCP_CREDENTIALS_PATH}
ENV env=local

# Copy the binary from builder stage
COPY --from=builder --chmod=755 /build/setagaya /usr/local/bin/setagaya

# Create directories and copy UI files with proper ownership
RUN mkdir -p /templates /static
COPY --chmod=644 --chown=setagaya:setagaya setagaya/ui/templates/ /templates/
COPY --chmod=644 --chown=setagaya:setagaya setagaya/ui/static/ /static/

# Switch to non-root user
USER setagaya:setagaya

# Set working directory
WORKDIR /home/setagaya

# Expose application port
EXPOSE 8080

# Run the application
ENTRYPOINT ["/usr/local/bin/setagaya"]
