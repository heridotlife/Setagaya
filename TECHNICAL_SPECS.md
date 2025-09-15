# Setagaya Load Testing Platform - Technical Specifications

## Project Overview

**Setagaya** is a distribute| Component              | Dockerfile                         | Base Image                                                                                                                                                              | Purpose                      |
|------------------------|-----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------|
| API Server             | `Dockerfile`                       | `golang:1.25.1-alpine3.22@sha256:546...`, `alpine:3.22@sha256:beefd...`                                                                                              | Main API and UI server        |
| API Server (Alt)       | `Dockerfile.api`                   | `golang:1.25.1-alpine3.22@sha256:546...`, `alpine:3.22@sha256:beefd...`                                                                                              | Dedicated API build           |
| Controller             | `Dockerfile.controller`            | `golang:1.25.1-alpine3.22@sha256:546...`, `alpine:3.22@sha256:beefd...`                                                                                              | Controller daemon             |
| JMeter Engine (Modern) | `Dockerfile.engines.jmeter`        | `eclipse-temurin:21-jre-alpine` | JMeter 5.6.3 + source build   |
| JMeter Engine (Legacy) | `Dockerfile.engines.jmeter.legacy` | `eclipse-temurin:21-jre-alpine` | JMeter 3.3 + pre-built binary |testing platform that orchestrates JMeter engines across Kubernetes clusters. The
system follows a controller-scheduler-engine pattern designed for scalable, enterprise-grade load testing.

- **Version:** 2.0.0-rc.1 (Security & Testing Improvements)
- **Language:** Go 1.25.1
- **Runtime:** Kubernetes-native with Docker/Podman support
- **License:** See [LICENSE](LICENSE) file
- **Repository:** https://github.com/hveda/Setagaya
- **Last Updated:** December 2025
- **Security:** Enhanced scanning with TruffleHog, CodeQL, and Trivy integration

## Architecture Overview

### Core Components

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Web UI    │◄──►│ API Server  │◄──►│ Controller  │
└─────────────┘    └─────────────┘    └─────────────┘
                           │                   │
                           ▼                   ▼
                   ┌─────────────┐    ┌─────────────┐
                   │  Scheduler  │◄──►│   Engines   │
                   └─────────────┘    └─────────────┘
                           │                   │
                           ▼                   ▼
                   ┌─────────────┐    ┌─────────────┐
                   │ Kubernetes  │    │   JMeter    │
                   └─────────────┘    └─────────────┘
```

### Component Details

#### 1. **Controller** (`setagaya/controller/`)

- **Purpose:** Main orchestration service managing test execution lifecycle
- **Binary:** `setagaya-controller`
- **Entry Point:** `./controller/cmd/main.go`
- **Key Responsibilities:**
  - Test lifecycle management (Deploy → Trigger → Terminate → Purge)
  - Real-time metrics aggregation from engines
  - Collection and plan coordination
  - Prometheus metrics exposition

#### 2. **API Server** (`setagaya/api/`)

- **Purpose:** REST API for web UI and external integrations
- **Binary:** `setagaya` (main binary)
- **Entry Point:** `./main.go`
- **Key Features:**
  - RESTful endpoints for CRUD operations
  - Server-sent events for live dashboard updates
  - LDAP authentication and authorization
  - File upload handling for test plans
- **API Documentation:** OpenAPI 3.0 specification in `docs/api/openapi.yaml`

#### 3. **Scheduler** (`setagaya/scheduler/`)

- **Purpose:** Kubernetes resource management
- **Key Features:**
  - Pod, service, and ingress lifecycle management
  - Node affinity and resource constraints
  - Deployment garbage collection (15-minute intervals)
  - Multi-cloud Kubernetes support

#### 4. **Engines** (`setagaya/engines/`)

- **Purpose:** Load generation executors
- **Supported Types:**
  - **JMeter Engine** (`jmeter/`): Apache JMeter with agent sidecar
  - **Agent Binary:** `setagaya-agent`
  - **Version Support:** JMeter 3.3 (legacy) and 5.6.3 (modern)

## Domain Model

### Hierarchy Structure

```
Project → Collection → Plan → ExecutionPlan
```

#### **Project**

- Top-level organizational unit
- Owner-based access control via LDAP groups
- Contains multiple collections

#### **Collection**

- Execution unit containing multiple plans running simultaneously
- Results converge at collection level for unified reporting
- States: Deploy → Trigger → Terminate → Purge

#### **Plan**

- Individual test configuration (JMX file)
- Defines test scenarios and parameters
- Can be executed across multiple engines

#### **ExecutionPlan**

- Specifies engines and concurrency per plan
- Maps plans to specific engine configurations
- Controls resource allocation and scaling

## Container Infrastructure

### Docker Images

| Component              | Dockerfile                         | Base Image                      | Purpose                       |
| ---------------------- | ---------------------------------- | ------------------------------- | ----------------------------- |
| API Server             | `Dockerfile`                       | `alpine:3.20`                   | Main API and UI server        |
| API Server (Alt)       | `Dockerfile.api`                   | `alpine:3.20`                   | Dedicated API build           |
| Controller             | `Dockerfile.controller`            | `alpine:3.20`                   | Controller daemon             |
| JMeter Engine (Modern) | `Dockerfile.engines.jmeter`        | `eclipse-temurin:21-jre-alpine` | JMeter 5.6.3 + source build   |
| JMeter Engine (Legacy) | `Dockerfile.engines.jmeter.legacy` | `eclipse-temurin:21-jre-alpine` | JMeter 3.3 + pre-built binary |
| Local Storage          | `local_storage/Dockerfile`         | `scratch`                       | Storage service               |
| Ingress Controller     | `ingress-controller/Dockerfile`    | `scratch`                       | Ingress management            |
| Grafana                | `grafana/Dockerfile`               | `grafana/grafana:latest`        | Metrics visualization         |

### Security Features

#### Container Security (2025)

- **Multi-stage builds:** Separate build and runtime environments
- **Non-root users:** All containers run as `setagaya` user (UID 1001)
- **Static compilation:** CGO_ENABLED=0 with security flags
- **Minimal base images:** Alpine and scratch for reduced attack surface
- **SHA-pinned base images:** All base images use cryptographic SHA checksums
- **No HEALTHCHECK:** Eliminates OCI format warnings, relies on Kubernetes health monitoring

#### Automated Security Scanning

- **Secret Scanning:** TruffleHog integration with event-aware configuration
  - PR scans: Compare base vs head commits
  - Push scans: Compare before vs after commits
  - Scheduled scans: Time-based repository scanning (7-day window)
- **Code Analysis:** CodeQL static analysis with manual build optimization
  - Multi-module Go project support
  - Enhanced caching for 60-minute timeout
  - Security-extended and quality queries
- **Vulnerability Scanning:** Trivy container image scanning
  - CRITICAL, HIGH, MEDIUM severity focus
  - SARIF integration with GitHub Security tab
  - Matrix-based scanning for all Docker images
- **Dependency Management:** Automated security updates via Dependabot
  - Daily Go module updates
  - Weekly Docker base image updates
  - Weekly GitHub Actions updates
- **Compliance Checking:**
  - Dockerfile security linting with Hadolint
  - Go security analysis with Gosec
  - License compliance validation

## Technology Stack

### Core Technologies

- **Language:** Go 1.25.1 (latest stable)
- **Container Runtime:** Docker/Podman compatible
- **Orchestration:** Kubernetes (any CNCF-compliant distribution)
- **Build System:** Multi-stage Docker builds
- **Package Management:** Go modules

### Dependencies

#### Core Dependencies (Latest Security Patches Applied)

- **Web Framework:** Native Go HTTP server
- **Metrics:** Prometheus client
- **Database:** MySQL driver v1.9.3 (security updates applied)
- **Authentication:** LDAP integration
- **Session Management:** Gorilla sessions v1.4.0 (security hardened)
- **Storage:** Pluggable (GCP Buckets, Nexus, Local)
- **Load Testing:** Apache JMeter 3.3/5.6.3

#### Security-Critical Dependencies

| Package | Version | Security Updates |
|---------|---------|------------------|
| `github.com/go-sql-driver/mysql` | v1.9.3 | DoS vulnerability fixes, auth improvements |
| `github.com/gorilla/sessions` | v1.4.0 | Cookie security enhancements, 3rd party compatibility |
| `github.com/sirupsen/logrus` | v1.9.3 | DoS vulnerability patches, writer improvements |
| `golang.org/x/crypto` | v0.35.0 | Critical cryptographic security updates |
| `golang.org/x/net` | v0.25.0 | Network security patches, HTTP/2 improvements |
| `google.golang.org/grpc` | v1.56.3 | gRPC security updates (CVE-2023-44487) |
| `google.golang.org/api` | v0.248.0 | Google API security improvements |
| `k8s.io/client-go` | v0.34.0 | Kubernetes client security updates |

#### Performance & Reliability

| Package | Version | Improvements |
|---------|---------|--------------|
| `go.uber.org/automaxprocs` | v1.6.0 | CPU quota rounding, cgroups v2 support |
| `grafana/grafana` | 12.1.1 | Latest security patches and features |

### Monitoring Stack

- **Metrics Collection:** Prometheus
- **Visualization:** Grafana
- **Dashboards:** Pre-configured for Setagaya metrics
- **Real-time Updates:** Server-sent events

## Configuration System

### Configuration Structure (`setagaya/config/`)

- **File:** `config.json` (runtime configuration)
- **Template:** `config_tmpl.json` (example configuration)
- **Environment:** `env=local` for development mode
- **Validation:** Automatic validation and defaults in `init()`
- **Documentation Links:** Configurable URLs for project documentation and help guides

### Documentation Integration

The platform includes configurable documentation links that appear in the UI:

- **`project_home`**: Link to project documentation or wiki
- **`upload_file_help`**: Link to file upload instructions
- **Default Values**: Generic placeholder URLs that can be customized per deployment

Example customization in Helm values:

```yaml
runtime:
  project_home: 'https://your-org.com/setagaya/docs'
  upload_file_help: 'https://your-org.com/setagaya/upload-guide'
```

### Key Configuration Areas

```json
{
  "project_home": "https://docs.example.com/setagaya/project-home",
  "upload_file_help": "https://docs.example.com/setagaya/file-upload-guide",
  "executor_config": {
    "jmeter": {
      "image": "setagaya:jmeter",
      "cpu": "1000m",
      "memory": "2Gi"
    }
  },
  "storage": {
    "type": "local|gcp|nexus",
    "config": {
      "bucket": "setagaya-storage",
      "region": "us-central1"
    }
  },
  "auth": {
    "no_auth": false,
    "ldap_config": {
      "host": "ldap.example.com",
      "port": 389,
      "base_dn": "dc=example,dc=com"
    }
  }
}
```

## Storage System

### Object Storage Interface (`setagaya/object_storage/`)

Abstracted storage system supporting multiple backends:

#### Supported Backends

- **Local Storage:** File system storage for development
- **GCP Buckets:** Google Cloud Storage for production
- **Nexus:** Artifact repository integration

#### Storage Operations

- **Test Plans:** Upload JMX files
- **Collections:** Upload YAML execution configurations
- **Results:** Store test output and metrics

#### Usage Pattern

```go
storage := object_storage.Client.Storage
storage.Upload(bucket, key, data)
data := storage.Download(bucket, key)
```

## API Documentation

### OpenAPI Specification

The Setagaya REST API is fully documented using OpenAPI 3.0 specification:

- **Location:** `docs/api/openapi.yaml`
- **Format:** OpenAPI 3.0.3
- **Coverage:** All endpoints, request/response schemas, and error codes
- **Authentication:** LDAP authentication documented with security schemes

### API Structure

The API follows RESTful principles with hierarchical resource organization:

#### Resource Hierarchy
```
Projects (Top-level organizational units)
├── Plans (Test configurations with JMeter files)
└── Collections (Execution units)
    ├── ExecutionPlans (Engine/concurrency configuration)
    ├── Files (Test data and configurations)
    └── Lifecycle Operations (Deploy → Trigger → Stop → Purge)
```

#### Core Endpoint Groups

- **`/api/projects`** - Project management and ownership
- **`/api/plans`** - Test plan creation and file management
- **`/api/collections`** - Test execution lifecycle and monitoring
- **`/api/files`** - File upload/download operations
- **`/api/usage`** - Platform usage statistics
- **`/api/admin`** - Administrative operations (requires admin privileges)
- **`/metrics`** - Prometheus metrics endpoint

#### Real-time Features

- **Server-Sent Events (SSE):** `/api/collections/{id}/stream` provides real-time metrics
- **Live Monitoring:** Engine status, active threads, throughput metrics
- **Event Stream Format:** JSON-formatted metrics with timestamp and collection/plan identifiers

#### Authentication Flow

1. **LDAP Authentication:** HTTP Basic Auth with LDAP credentials
2. **Ownership Validation:** Project access based on LDAP group membership
3. **Admin Privileges:** Configurable admin user list for platform-wide access
4. **Local Development:** Authentication can be disabled with `no_auth: true`

### API Usage Examples

#### Creating a Load Test Flow
```bash
# 1. Create project
curl -X POST http://localhost:8080/api/projects \
  -d "name=My Load Test&owner=engineering-team"

# 2. Create test plan
curl -X POST http://localhost:8080/api/plans \
  -d "name=API Test&project_id=123"

# 3. Upload JMeter file
curl -X PUT http://localhost:8080/api/plans/456/files \
  -F "planFile=@test-plan.jmx"

# 4. Create collection
curl -X POST http://localhost:8080/api/collections \
  -d "name=Performance Suite&project_id=123"

# 5. Configure execution
curl -X PUT http://localhost:8080/api/collections/789/config \
  -F "collectionYAML=@execution-config.yaml"

# 6. Deploy engines
curl -X POST http://localhost:8080/api/collections/789/deploy

# 7. Start test
curl -X POST http://localhost:8080/api/collections/789/trigger

# 8. Monitor (real-time stream)
curl http://localhost:8080/api/collections/789/stream
```

#### Error Handling

The API uses standard HTTP status codes with consistent JSON error responses:

```json
{
  "message": "Detailed error description"
}
```

Common status codes:
- `200` - Success
- `400` - Invalid request parameters
- `401` - Authentication required
- `403` - Insufficient permissions
- `404` - Resource not found
- `500` - Internal server error
- `501` - Not implemented

## Authentication & Authorization

### Multi-Layered Authentication Architecture (v2.0.0-rc.1)

Setagaya implements a comprehensive authentication system supporting both legacy LDAP and modern RBAC approaches:

#### RBAC (Role-Based Access Control) System (`setagaya/rbac/`)

**Enterprise Multi-Tenant Architecture (Phase 3-4 Implementation)**:

- **Tenant Management**: Complete CRUD operations for organizational boundaries
- **Role Hierarchy**: Service provider, tenant admin, tenant editor, tenant viewer roles
- **Permission Engine**: Fine-grained permissions with scope-based access control
- **Data Isolation**: Strict tenant-scoped queries ensuring complete data separation
- **Audit Trail**: Comprehensive logging of all authorization decisions
- **Performance Optimization**: Permission caching with TTL management

**RBAC Components**:
```go
// Core RBAC types
type UserContext struct {
    UserID            string
    IsServiceProvider bool
    TenantRoles       []UserTenantRole
    GlobalPermissions []string
}

type Tenant struct {
    ID              int64
    Name            string
    DisplayName     string
    Status          string
    QuotaConfig     map[string]interface{}
    BillingConfig   map[string]interface{}
}
```

**RBAC API Endpoints**:
- `POST /api/tenants` - Create tenant (service provider admin only)
- `GET /api/tenants` - List accessible tenants (tenant-scoped for users)
- `GET /api/tenants/{id}` - Get tenant details
- `PUT /api/tenants/{id}` - Update tenant (admin/tenant admin only)
- `DELETE /api/tenants/{id}` - Delete tenant (service provider admin only)

#### Legacy LDAP Integration (`setagaya/auth/`)

**Backward Compatibility Support**:

- **User Authentication:** LDAP directory services
- **Group Membership:** Project ownership via LDAP groups
- **Admin Users:** Bypass ownership checks
- **Development Mode:** `no_auth: true` for local testing

#### Hybrid Authorization Model (v2.0.0-rc.1)

**Runtime Authentication Switching**:
```go
// API middleware automatically selects authentication method
if s.enableRBAC && s.rbacIntegration != nil {
    r.HandlerFunc = s.rbacIntegration.GetMiddleware().AuthorizeRequest(r.HandlerFunc)
} else {
    r.HandlerFunc = s.authRequired(r.HandlerFunc) // Legacy LDAP
}
```

**Authorization Patterns**:

1. **RBAC Mode (Enterprise)**:
   - Multi-tenant data isolation
   - Role-based permission checking
   - Tenant-scoped resource access
   - Service provider global access

2. **Legacy Mode (LDAP)**:
   - Project ownership based on LDAP groups
   - Admin override capabilities
   - Resource isolation by owner validation

3. **Development Mode**:
   - Authentication bypass with `no_auth: true`
   - All operations permitted for testing

**Migration Strategy**:
- Seamless runtime switching between authentication systems
- Automatic tenant assignment for existing resources
- Zero-downtime migration from LDAP to RBAC
- Legacy Account objects converted to UserContext automatically

## Kubernetes Integration

### Resource Management

- **Namespaced Deployments:** Per collection/plan combination
- **Service Exposure:** Ingress controllers for engine metrics
- **Resource Constraints:** CPU/memory limits and requests
- **Node Affinity:** Configurable placement policies

### Deployment Lifecycle

1. **Deploy:** Create K8s resources, engines come online
2. **Trigger:** Start load generation across all engines
3. **Terminate:** Stop tests, keep engines for result collection
4. **Purge:** Remove all K8s resources and clean up storage

### RBAC Configuration

Located in `kubernetes/` directory:

- `clusterrole.yaml` - Cluster-level permissions
- `roles.yaml` - Namespace-specific roles
- `serviceaccount.yaml` - Service account definitions

## Development Workflow

### Local Development Setup

```bash
make              # Creates kind cluster, deploys all components
make expose       # Port-forwards Setagaya (8080) and Grafana (3000)
make setagaya     # Rebuilds and redeploys controller changes
make clean        # Destroys local cluster
```

### Auto-Formatting Infrastructure

The platform includes comprehensive development tooling for code quality:

#### Tools and Configuration

- **Prettier** (`.prettierrc.json`): Auto-formats YAML, Markdown, JSON, and JavaScript
- **yamllint** (`.yamllint.yml`): YAML validation with formatter-friendly rules
- **Git Hooks** (`.git/hooks/pre-commit`): Automatic formatting on commit
- **npm Scripts** (`package.json`): Development tool management

#### Development Commands

```bash
# Install all development tools
./scripts/setup-dev-tools.sh

# Format all files automatically
npm run format

# Lint and fix Markdown files
npm run lint:md
npm run lint:md:fix

# Validate YAML files
npm run lint:yaml

# Run all fixes
npm run fix
```

#### Git Hook Integration

The pre-commit hook automatically:

1. Runs prettier on staged YAML, Markdown, and JSON files
2. Validates YAML syntax with yamllint
3. Reports errors clearly with tool availability checking
4. Falls back gracefully when tools are unavailable

### Build Process

```bash
# Multi-stage Docker builds (recommended)
docker build -f setagaya/Dockerfile .

# Legacy pre-built binary approach
./setagaya/build.sh api        # API server binary
./setagaya/build.sh controller # Controller daemon binary
./setagaya/build.sh jmeter     # JMeter agent sidecar binary
```

### Testing

- **Unit Tests:** `*_test.go` files in model packages
- **Integration Tests:** Full deployment testing via kind
- **Database Tests:** Using `test_utils.go` utilities
- **Container Tests:** Multi-platform builds

## JMeter Engine Compatibility

### Version Support Matrix

| JMeter Version      | Dockerfile                         | Build Method     | Status                  |
| ------------------- | ---------------------------------- | ---------------- | ----------------------- |
| **5.6.3**           | `Dockerfile.engines.jmeter`        | Source build     | ✅ Modern (Recommended) |
| **3.3**             | `Dockerfile.engines.jmeter.legacy` | Pre-built binary | ✅ Legacy Support       |
| **Future versions** | Custom build with version ARG      | Source build     | ✅ Compatible           |

### Agent Architecture

- **Binary:** `setagaya-agent` (version-agnostic)
- **Path Detection:** Automatic via `JMETER_BIN` environment variable
- **Fallback:** Hardcoded JMeter 3.3 paths for backward compatibility
- **Executables:** `jmeter` and `stoptest.sh` discovery

### Environment Variables

```dockerfile
ENV JMETER_HOME=/opt/apache-jmeter-${JMETER_VERSION}
ENV JMETER_BIN=${JMETER_HOME}/bin
ENV PATH=${JMETER_BIN}:${PATH}
```

## Metrics and Monitoring

### Metrics Pipeline

```
Engine → Controller → API → WebUI/Grafana
```

### Real-time Metrics Flow

1. **Engines** stream metrics via HTTP to controller endpoints
2. **Controller** aggregates and forwards to Prometheus
3. **API** provides server-sent events for live dashboard updates
4. **Collection Metrics** identified by `collection_id` + `plan_id` labels

### Grafana Dashboards

Pre-configured dashboards in `grafana/dashboards/`:

- `setagaya.json` - Main platform dashboard
- `setagaya_perf.json` - Performance metrics
- `setagaya_engine.json` - Engine-specific metrics

## Error Handling

### Error Types

```go
// Typed errors from model package
var dbe *model.DBError
if errors.As(err, &dbe) {
    // Handle database-specific errors
}
```

### API Error Mapping

- `s.handleErrors(w, err)` - Maps internal errors to HTTP status codes
- Consistent error responses across all endpoints
- Detailed logging for debugging

## Database Integration

### MySQL Configuration

- **Migrations:** Stored in `setagaya/db/` with timestamp prefixes
- **Connection:** Global access via `config.SC.DBC`
- **Patterns:** Active record pattern in `setagaya/model/`
- **Testing:** Isolated test database setup

### Model Architecture

- **Base Models:** Common functionality in `model/common.go`
- **Validation:** Built-in validation for all models
- **Relationships:** Proper foreign key management
- **Transactions:** Support for complex operations

## Performance Characteristics

### Scalability

- **Horizontal Scaling:** Multiple engine pods per plan
- **Resource Isolation:** Kubernetes namespace separation
- **Load Distribution:** Configurable engine placement
- **Metrics Aggregation:** Efficient collection and storage

### Resource Requirements

- **Minimum:** 2 CPU cores, 4GB RAM for control plane
- **Engine Resources:** Configurable per test plan
- **Storage:** Dependent on test data and result retention
- **Network:** Low latency between components preferred

## Security Considerations

### GitHub Actions Security Automation (2025)

The platform includes comprehensive security automation via GitHub Actions workflows:

#### Security Workflows

Located in `.github/workflows/`:

- **`security-check.yml`**: Comprehensive security scanning including Gosec, CodeQL, dual container scanning (Trivy + Grype)
- **`security-monitoring.yml`**: Continuous security monitoring with OpenSSF Scorecard, anchore-sbom-scan, and enhanced Grype integration
- **`security-advisory.yml`**: Security advisory management and emergency response procedures
- **`code-quality.yml`**: Go linting, testing, Dockerfile validation, YAML checking
- **`pr-validation.yml`**: PR title validation, diff analysis, security impact assessment

#### Enhanced Security Tool Integration (2025)

- **Grype Integration**: Added comprehensive container vulnerability scanning with SARIF output
- **OpenSSF Scorecard Enhancement**: Detailed summaries and proper GitHub Security tab categorization
- **anchore-sbom-scan Improvement**: Robust SARIF validation and comprehensive vulnerability reporting
- **SARIF Validation**: Automated validation script (`.github/scripts/validate-sarif.sh`) for proper GitHub integration
- **GitHub Security Tab Organization**: Proper categorization with meaningful tool-specific summaries

#### GitHub Actions Security Features

- **Comprehensive Container Scanning**: Trivy and Grype dual-scanner integration for complete vulnerability coverage
- **Multi-tool Security Scanning**: Gosec, CodeQL, TruffleHog integration with enhanced SARIF reporting
- **SBOM Generation and Analysis**: Software Bill of Materials with anchore-sbom-scan vulnerability analysis
- **Security Posture Assessment**: OpenSSF Scorecard integration with detailed GitHub Security tab summaries
- **Automated Vulnerability Detection**: Weekly scans with critical issue escalation and actionable reporting
- **Dependency Management**: Dependabot integration for automated security updates
- **Container Security**: Dual-scanner approach (Trivy + Grype) with hardening validation
- **Emergency Response**: Automated security advisory creation and notification
- **Enhanced SARIF Integration**: Validated SARIF output with proper categorization for GitHub Security tab

#### Workflow Version Management (2025)

- **Pinned Action Versions**: All GitHub Actions use specific version tags for security and stability
- **TruffleHog v3.87.0**: Latest stable release for comprehensive secret scanning
- **Trivy v0.28.0**: Latest stable release for container vulnerability scanning
- **OpenSSF Scorecard v2.5.1**: Enhanced configuration with proper token authentication
- **golangci-lint**: Updated to latest version for improved Go code analysis
- **No Unstable Branches**: Eliminated use of `@master` and `@main` action references

#### Security Configuration Files

- `.golangci.yml`: Comprehensive Go linting with security rules
- `.yamllint.yml`: YAML validation standards
- `.github/dependabot.yml`: Automated dependency update configuration
- `.github/SECURITY_CHECKLIST.md`: 100+ point security release validation

### Container Security

- **Non-root Execution:** All containers run as UID 1001
- **Minimal Images:** Reduced attack surface
- **Static Binaries:** No dynamic dependencies
- **Network Policies:** Kubernetes-native isolation

### Data Security

- **Authentication:** LDAP integration
- **Authorization:** Group-based access control
- **Data Isolation:** Owner-based resource separation
- **Audit Logging:** Comprehensive operation logging

## Deployment Options

### Development

- **Local Kind Cluster:** Full stack deployment
- **Hot Reloading:** Fast iteration via `make setagaya`
- **Port Forwarding:** Direct access to services

### Production

- **Kubernetes Cluster:** Any CNCF-compliant distribution
- **Helm Charts:** Available in `helm_utils/`
- **High Availability:** Multi-replica deployments
- **Persistent Storage:** For test data and results

## Extension Points

### Adding New Schedulers

Implement `scheduler.EngineScheduler` interface:

```go
type EngineScheduler interface {
    Deploy(collection *model.Collection) error
    Trigger(collection *model.Collection) error
    Terminate(collection *model.Collection) error
    Purge(collection *model.Collection) error
}
```

### Adding Storage Backends

Implement `object_storage.Storage` interface:

```go
type Storage interface {
    Upload(bucket, key string, data []byte) error
    Download(bucket, key string) ([]byte, error)
    Delete(bucket, key string) error
}
```

### Adding Engine Types

Follow `setagaya/engines/jmeter/` structure:

- Agent sidecar pattern
- Metrics reporting endpoint
- Configuration file management
- Lifecycle management

## Migration and Upgrade

### Database Migrations

- **Automated:** Run on startup
- **Versioned:** Timestamp-based naming
- **Rollback:** Manual process via SQL scripts

### Container Updates

- **Rolling Updates:** Kubernetes-native
- **Zero Downtime:** Service mesh compatibility
- **Health Checks:** Kubernetes liveness/readiness probes

---

**Last Updated:** September 11, 2025 **Document Version:** 2.1 **Next Review:** Quarterly or on major releases

## Current RBAC Implementation Status

### ✅ Phase 1 Completed (September 2025)
- **OpenAPI 3.0 Specification**: Complete RBAC API specification (`docs/api/rbac-openapi.yaml`)
- **Database Schema**: Initial RBAC schema with multi-tenant support (`setagaya/db/2025091101_rbac_initial_schema.sql`)
- **Core Domain Models**: Comprehensive Go structures and interfaces (`setagaya/rbac/`)
- **Test Infrastructure**: TDD-first approach with **94.1% test coverage** exceeding 80% target
- **Configuration Framework**: RBAC configuration integrated into `config_tmpl.json`
- **Build Integration**: RBAC package successfully integrated with existing build system

### 🚧 Next Phases (Planned)
- **Phase 2**: RBAC Engine Development (3 weeks) - Authorization logic and database implementation
- **Phase 3**: Multi-Tenant Architecture (3 weeks) - Tenant management and data isolation  
- **Phase 4**: API Security Enhancement (2 weeks) - Endpoint protection and middleware
- **Phase 5**: Monitoring & Audit (2 weeks) - Compliance and security logging

### 📊 Test Coverage Achievement
- **RBAC Package**: 94.1% test coverage (Target: 80% minimum)
- **TDD Methodology**: Comprehensive unit tests for all domain models
- **API-First Design**: Complete OpenAPI specification before implementation
- **Make Targets**: Automated testing with `make test-coverage-rbac`
