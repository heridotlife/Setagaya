# Dockerfile Security and Best Practices Improvements

This document outlines the security improvements and best practices implemented in the Setagaya project Dockerfiles.

## Overview of Changes

All Dockerfiles have been modernized to follow current security best practices and use the latest stable versions of
base images and tools.

## Key Improvements Applied

### 1. Updated Base Images

- **Go**: Upgraded from `golang:1.20` to `golang:1.25.1` (latest stable)
- **Alpine**: Upgraded to `alpine:3.22` (latest stable)
- **Ubuntu**: Upgraded from `18.04` to `22.04`
- **Grafana**: Upgraded from `8.5.27` to `11.2.1` (latest stable)
- **JMeter**: Upgraded from `3.3` to `5.6.3` (latest stable)
- **Java**: Upgraded from `openjdk:8` to `eclipse-temurin:21-jre-alpine` (latest LTS)

### 2. Multi-Stage Builds

- Implemented multi-stage builds for all Go applications
- Separates build environment from runtime environment
- Reduces final image size and attack surface
- Ensures only necessary binaries and dependencies are in production images

### 3. Security Hardening

#### Non-Root Users

- All containers run as non-root users
- Created dedicated users with minimal privileges
- Used consistent UID/GID (1001) across applications

#### Build Security

- Enabled static compilation with `CGO_ENABLED=0`
- Added security flags: `-ldflags='-w -s -extldflags "-static"'`
- Used `go mod verify` to ensure dependency integrity
- Implemented proper file permissions with `--chmod`

#### Runtime Security

- Removed unnecessary tools and packages from runtime images
- Used minimal base images (Alpine/scratch when possible)
- Added proper file ownership with `--chown`
- Implemented health checks for monitoring

### 4. Latest Go Features and Optimizations

- Updated to Go 1.25.1 with latest performance improvements
- Used `go mod download && go mod verify` for secure dependency management
- Optimized build flags for smaller, faster binaries
- Implemented proper Go module handling

### 5. Grafana Security Enhancements

```dockerfile
# Security-focused environment variables
ENV GF_SECURITY_DISABLE_GRAVATAR=true
ENV GF_SECURITY_COOKIE_SECURE=true
ENV GF_SECURITY_COOKIE_SAMESITE=strict
ENV GF_SECURITY_STRICT_TRANSPORT_SECURITY=true
ENV GF_SECURITY_CONTENT_TYPE_PROTECTION=true
ENV GF_SECURITY_X_CONTENT_TYPE_OPTIONS=nosniff
ENV GF_SECURITY_X_XSS_PROTECTION=true
```

### 6. Build Context Optimization

- Added comprehensive `.dockerignore` files
- Minimized build context for faster builds
- Excluded sensitive files and unnecessary artifacts

## File Structure

### Updated Dockerfiles

- `setagaya/Dockerfile` - Main API server (multi-stage build from source)
- `setagaya/Dockerfile.api` - Specific API server build
- `setagaya/Dockerfile.controller` - Controller service build
- `setagaya/Dockerfile.engines.jmeter` - JMeter engine with modern Java
- `local_storage/Dockerfile` - Storage service (scratch-based)
- `ingress-controller/Dockerfile` - Ingress controller (scratch-based)
- `grafana/Dockerfile` - Grafana with security enhancements

### Build Context Files

- `.dockerignore` - Global exclusions
- `setagaya/.dockerignore` - Setagaya-specific exclusions
- `local_storage/.dockerignore` - Storage-specific exclusions
- `ingress-controller/.dockerignore` - Ingress-specific exclusions

## Security Benefits

1. **Reduced Attack Surface**: Minimal runtime images with only essential components
2. **Non-Root Execution**: All containers run with unprivileged users
3. **Latest Security Patches**: Updated base images with current security fixes
4. **Static Binaries**: Self-contained executables with no external dependencies
5. **Verified Dependencies**: Go module verification ensures integrity
6. **Health Monitoring**: Built-in health checks for operational security

## Performance Benefits

1. **Smaller Images**: Multi-stage builds significantly reduce image sizes
2. **Faster Builds**: Optimized layer caching and build context
3. **Better Performance**: Latest Go version with performance improvements
4. **Efficient Resource Usage**: Minimal runtime footprint

## Compatibility

- All changes maintain backward compatibility with existing deployment scripts
- Makefile updated to use new Dockerfile structure
- Health checks added for better Kubernetes integration
- Environment variables preserved for configuration management

## Build Commands

```bash
# API Server
podman build -f setagaya/Dockerfile.api -t setagaya:api .

# Controller
podman build -f setagaya/Dockerfile.controller -t setagaya:controller .

# Storage Service
podman build -t setagaya:storage local_storage/

# Ingress Controller
podman build -t setagaya:ingress ingress-controller/

# JMeter Engine
podman build -f setagaya/Dockerfile.engines.jmeter -t setagaya:jmeter .

# Grafana
podman build -t setagaya:grafana grafana/
```

## Testing

All Dockerfiles have been tested and verified to build successfully with the new improvements while maintaining
functionality.
