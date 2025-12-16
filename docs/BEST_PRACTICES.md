# Setagaya Development Best Practices

This document consolidates best practices for development, security, and CI/CD workflows in the Setagaya platform.

## Table of Contents
- [CodeQL Analysis](#codeql-analysis)
- [Docker Security](#docker-security)
- [GitHub Actions Workflows](#github-actions-workflows)
- [Dependency Management](#dependency-management)

---

## CodeQL Analysis

### Manual Build Strategy

**Problem**: Autobuild was including Docker builds, causing timeouts and unnecessary overhead.

**Solution**: Explicit module-specific builds targeting only Go code.

```yaml
# Optimized Configuration
- name: Build Setagaya Main Module
  run: |
    cd setagaya
    go mod download
    go build -v ./...
    go test -c ./...  # Include test files for analysis

- name: Build Ingress Controller Module
  run: |
    cd ingress-controller
    go mod download
    go build -v ./...

- name: Build Local Storage Module
  run: |
    cd local_storage
    go mod download
    go build -v ./...
```

**Benefits**:
- **Timeout Reduction**: 360 minutes → 60 minutes (83% reduction)
- **Module-Specific Builds**: Targeted compilation avoiding Docker overhead
- **Enhanced Caching**: Multi-layer caching with SHA-based keys
- **Better Coverage**: Explicit test file compilation for analysis

### Project Structure Analysis

Setagaya uses a multi-module Go workspace:
- **setagaya/**: Main application (API + Controller)
- **ingress-controller/**: Kubernetes ingress controller
- **local_storage/**: Local storage service

Each module requires separate build steps for proper CodeQL analysis.

### Best Practices

1. **Multi-Module Support**: Explicit builds for each Go module
2. **Dependency Pre-loading**: `go mod download` before builds for optimal caching
3. **Verbose Output**: `-v` flag for better debugging
4. **Test Integration**: `go test -c` for comprehensive code analysis
5. **Failure Tolerance**: Graceful handling of test compilation failures

### Common Pitfalls to Avoid

1. **Single Build Command**: Don't try to build all modules from root
2. **Missing Test Files**: Include `go test -c` for better analysis
3. **Poor Cache Keys**: Use file hashes, not timestamps
4. **Excessive Timeout**: Manual builds rarely need >60 minutes

---

## Docker Security

### Security-Hardened Container Architecture

All Dockerfiles follow security best practices with modern base images and multi-stage builds.

### Base Images (2025 Standards)

- **Go**: `golang:1.25.1-alpine3.22@sha256:...` (pinned digests)
- **Alpine**: `alpine:3.22@sha256:...`
- **Java**: `eclipse-temurin:21-jre-alpine` (LTS)
- **Scratch**: For minimal Go binaries

### Multi-Stage Build Pattern

```dockerfile
# Build stage
FROM golang:1.25.1-alpine3.22 AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -ldflags='-w -s -extldflags "-static"' -o app

# Runtime stage
FROM alpine:3.22
RUN addgroup -g 1001 setagaya && \
    adduser -D -u 1001 -G setagaya setagaya
USER setagaya
COPY --from=builder --chown=setagaya:setagaya /build/app /app
ENTRYPOINT ["/app"]
```

### Security Hardening Checklist

- [x] Non-root user (UID 1001)
- [x] Static compilation (`CGO_ENABLED=0`)
- [x] Security flags: `-ldflags='-w -s -extldflags "-static"'`
- [x] Pinned base images with SHA256 digests
- [x] Minimal runtime images (Alpine/scratch)
- [x] No HEALTHCHECK (prevents OCI format warnings)
- [x] Proper file permissions (`--chown`)

### Matrix-Based Security Scanning

Parallel execution of container security scans:

```yaml
strategy:
  fail-fast: false
  matrix:
    include:
      - name: setagaya-api
        dockerfile: setagaya/Dockerfile
        context: .
        critical: true
      - name: setagaya-jmeter
        dockerfile: setagaya/Dockerfile.engines.jmeter
        context: .
        critical: true
      - name: setagaya-storage
        dockerfile: local_storage/Dockerfile
        context: ./local_storage
        critical: false
```

**Benefits**:
- Parallel execution (5 images simultaneously)
- Image-specific caching
- Smaller build contexts for microservices
- Enhanced security coverage (all images scanned)

### Docker Image Caching Strategy

```yaml
- name: Cache Docker layers
  uses: actions/cache@v3
  with:
    path: /tmp/.buildx-cache
    key: ${{ runner.os }}-buildx-${{ matrix.name }}-${{ hashFiles(matrix.dockerfile, '**/go.mod') }}
    restore-keys: |
      ${{ runner.os }}-buildx-${{ matrix.name }}-
```

---

## GitHub Actions Workflows

### Workflow Optimization Principles

1. **Parallel Execution**: Independent jobs run concurrently
2. **Smart Caching**: Multi-layer caching strategy
3. **Conditional Execution**: Run only when necessary
4. **Job Dependencies**: Sequential chains for cache reuse

### Caching Strategy

#### Go Module Caching
```yaml
- name: Set up Go
  uses: actions/setup-go@v4
  with:
    go-version: ${{ env.GO_VERSION }}
    cache: true  # Automatic caching based on go.mod/go.sum
```

**Benefit**: Eliminates repeated `go mod download` operations (~30-60s saved per job)

#### Docker Layer Caching
```yaml
- name: Cache Docker layers
  uses: actions/cache@v3
  with:
    path: /tmp/.buildx-cache
    key: ${{ runner.os }}-buildx-${{ hashFiles('**/Dockerfile*', '**/go.mod') }}
```

**Benefit**: ~3-8 minutes saved per build (image-specific caches)

#### JMeter Download Caching
```yaml
- name: Cache JMeter download
  if: contains(matrix.name, 'jmeter')
  uses: actions/cache@v3
  with:
    path: /tmp/jmeter-cache
    key: jmeter-5.6.3
```

**Benefit**: Avoids downloading 47MB archive on every run (~30-90s saved)

### Conditional Execution Pattern

```yaml
# Smart Docker scanning - only when relevant files change
if: github.event_name == 'schedule' ||
    contains(github.event.head_commit.modified, 'Dockerfile') ||
    contains(github.event.head_commit.modified, '.go')
```

### Performance Impact

**Before Optimizations**:
- Average workflow time: ~12-15 minutes
- Sequential Docker builds
- Repeated dependency downloads

**After Optimizations**:
- Average workflow time: ~8-10 minutes (33% improvement)
- Parallel Docker builds (matrix strategy)
- Smart caching across jobs

**Specific Improvements**:
- **gosec + govulncheck**: 4-5 min → 2-3 min (cache reuse)
- **CodeQL**: 15-20 min → 5-8 min (manual build optimization)
- **Docker Security**: 10-15 min → 6-8 min (parallel execution + caching)

### Security Scanning Integration

Three complementary security tools:

1. **Grype**: Container vulnerability scanning
2. **OpenSSF Scorecard**: Security posture assessment
3. **anchore-sbom-scan**: Software Bill of Materials analysis

All tools provide detailed summaries in GitHub Security tab with proper SARIF categorization.

---

## Dependency Management

### Go 1.25.1 Upgrade Strategy

Major version upgrades require coordinated dependency updates across all modules.

#### Key Updates in Go 1.25.1 Upgrade

**Major Upgrades**:
- Go runtime: 1.23.4 → 1.25.1
- Google Cloud SDK: v0.74.0 → v0.120.0
- gRPC: v1.34.0 → v1.74.2
- MySQL driver: v1.4.1 → v1.9.3
- Kubernetes libraries: v0.20.0 → v0.34.0 (ingress controller)

**Security Improvements**:
- Modern cryptography (edwards25519)
- Enhanced authentication (go-jose/v4, spiffe/go-spiffe)
- OpenTelemetry integration
- Removed legacy/deprecated dependencies

#### License Compliance

All dependencies use permissive open-source licenses:
- MIT License (majority)
- Apache-2.0 License
- BSD-3-Clause License
- No copyleft (GPL/LGPL) licenses

#### Vulnerability Assessment

- **Zero vulnerabilities** after upgrade (verified with govulncheck)
- All dependencies from trusted, well-maintained projects
- Regular security scanning via GitHub Actions

### Dependabot Configuration

Automated dependency updates configured in `.github/dependabot.yml`:

```yaml
updates:
  - package-ecosystem: "gomod"
    directory: "/setagaya"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "build"
      
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "ci"
```

### Dependency Consolidation Pattern

When multiple Dependabot PRs update related dependencies:

1. Review all pending updates
2. Test compatibility together
3. Consolidate into single PR
4. Use conventional commit format: `build: consolidate <package> updates`

**Benefits**:
- Reduced maintenance overhead
- Atomic updates (all related dependencies together)
- Consistency across modules
- Simplified testing

---

## Maintenance and Monitoring

### Regular Tasks

- **Weekly**: Review security scanning results
- **Monthly**: Review cache hit rates and workflow performance
- **Quarterly**: Update tool versions and assess optimizations
- **On Updates**: Validate configurations when dependencies change

### Success Metrics

- **Workflow Duration**: Track execution time trends
- **Cache Hit Rates**: Monitor cache effectiveness  
- **Security Coverage**: Ensure comprehensive scanning
- **Resource Usage**: Track GitHub Actions minute consumption

---

**Last Updated**: January 2025  
**Maintainer**: Setagaya Development Team

For additional context, see:
- [Technical Specifications](../TECHNICAL_SPECS.md)
- [Development Guidelines](../.github/instructions/copilot.instructions.md)
- [Security Policy](../SECURITY.md)
