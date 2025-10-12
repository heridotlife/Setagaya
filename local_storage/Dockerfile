# Build stage
FROM golang:1.25.2-alpine3.22@sha256:06cdd34bd531b810650e47762c01e025eb9b1c7eadd191553b91c9f2d549fae8 AS builder

# Install security updates and required packages
RUN apk update && apk upgrade && apk add --no-cache git ca-certificates tzdata && \
    addgroup -g 1001 setagaya && \
    adduser -D -u 1001 -G setagaya setagaya

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY main.go ./

# Build the binary with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o storage .

# Final stage
FROM scratch

# Import from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd

# Copy the binary
COPY --from=builder /build/storage /storage

# Use non-root user
USER setagaya

# Expose port
EXPOSE 8080

# Run the binary
ENTRYPOINT ["/storage"]
