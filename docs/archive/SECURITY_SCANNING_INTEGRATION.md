# Security Scanning Tools Integration

## Overview

Setagaya now includes comprehensive security scanning with three primary tools that provide detailed summaries in GitHub's Security tab:

1. **Grype** - Container vulnerability scanning
2. **OpenSSF Scorecard** - Security posture assessment
3. **anchore-sbom-scan** - Software Bill of Materials vulnerability analysis

## Tool Integration Status

### ✅ Grype Integration
- **Status**: Fully integrated and operational
- **Purpose**: Container vulnerability scanning with comprehensive coverage
- **Output**: SARIF format for GitHub Security tab
- **Category**: `grype-{image-name}` for organized results
- **Workflows**: Both `security-check.yml` and `security-monitoring.yml`

### ✅ OpenSSF Scorecard
- **Status**: Enhanced with detailed summaries
- **Purpose**: Security posture assessment and best practices evaluation
- **Output**: SARIF format with comprehensive metrics
- **Category**: `openssf-scorecard`
- **Workflow**: `security-monitoring.yml` (scheduled runs)

### ✅ anchore-sbom-scan
- **Status**: Enhanced with robust error handling and summaries
- **Purpose**: SBOM generation and vulnerability analysis
- **Output**: Enhanced SARIF with proper validation
- **Category**: `anchore-sbom-scan`
- **Workflow**: `security-monitoring.yml`

## GitHub Security Tab Organization

Security scanning results are now properly categorized in GitHub's Security tab:

```
Code scanning alerts
├── grype-setagaya-api
├── grype-setagaya-jmeter
├── grype-setagaya-storage
├── grype-setagaya-ingress
├── grype-setagaya-grafana
├── grype-monitoring
├── openssf-scorecard
├── anchore-sbom-scan
├── docker-setagaya-api (Trivy)
├── docker-setagaya-jmeter (Trivy)
└── ... (other Trivy categories)
```

## Summary Features

### Job Summaries
Each security tool now provides comprehensive GitHub Actions job summaries including:

- **Vulnerability counts** by severity level
- **Scan status** and success indicators
- **Action items** when issues are detected
- **Links** to detailed results and external dashboards
- **Troubleshooting information** for failed scans

### SARIF Validation
- Automatic SARIF file validation and enhancement
- Proper schema compliance for GitHub integration
- Enhanced error handling for malformed outputs
- Fallback to empty SARIF files when scans fail

## Workflow Triggers

### security-check.yml
- **Push events** to main branches
- **Pull requests** to main branches
- **Scheduled runs** (daily at 2 AM UTC)
- **Manual dispatch** with optional force scanning

### security-monitoring.yml
- **Scheduled runs** (weekly on Monday at 2 AM UTC)
- **Manual dispatch** with scan type selection
- **Conditional execution** based on scan type

## Configuration

### Grype Configuration
```yaml
uses: anchore/scan-action@v6
with:
  image: 'image-name:tag'
  output-format: sarif
  output-file: 'grype-results.sarif'
  severity-cutoff: medium
  fail-build: false
```

### OpenSSF Scorecard Configuration
```yaml
uses: ossf/scorecard-action@v2.4.0
with:
  results_file: scorecard-results.sarif
  results_format: sarif
  repo_token: ${{ secrets.GITHUB_TOKEN }}
  publish_results: true
```

### anchore-sbom-scan Configuration
```yaml
# SBOM Generation
uses: anchore/sbom-action@v0
with:
  path: ./
  format: spdx-json
  output-file: sbom.spdx.json

# Vulnerability Scanning
uses: anchore/scan-action@v6
with:
  sbom: sbom.spdx.json
  output-format: sarif
  output-file: sbom-scan-results.sarif
  severity-cutoff: high
  fail-build: false
```

## Troubleshooting

### Common Issues

1. **No Summary in GitHub Security Tab**
   - Check that SARIF files are properly formatted
   - Verify category names are unique and descriptive
   - Ensure SARIF uploads have proper conditions

2. **Failed SARIF Upload**
   - Review SARIF validation script output
   - Check for proper JSON structure
   - Verify artifact locations are properly set

3. **Missing Tool Results**
   - Check workflow conditions and triggers
   - Review tool-specific logs in GitHub Actions
   - Verify Docker images build successfully for container scanning

### Validation Script

Use the provided SARIF validation script:

```bash
# Validate and enhance SARIF file
.github/scripts/validate-sarif.sh input.sarif ToolName output.sarif true
```

## Monitoring and Maintenance

### Regular Tasks
- Review security scanning results weekly
- Update tool versions quarterly
- Validate SARIF output quality monthly
- Monitor GitHub Actions quota usage

### Performance Optimization
- Conditional scanning based on file changes
- Parallel execution of independent scans
- Proper caching for container builds
- Efficient SARIF processing

## Security Impact

This comprehensive security scanning integration provides:

- **Complete vulnerability coverage** across containers and dependencies
- **Automated security posture assessment** with industry best practices
- **Transparent reporting** in GitHub's Security tab
- **Actionable insights** through detailed summaries
- **Continuous monitoring** with scheduled scans

All three tools now provide meaningful summaries, resolving the "no summary" issue in GitHub's Security tab status reports.