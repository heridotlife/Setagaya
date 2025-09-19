# Setagaya Documentation Index

This directory contains comprehensive documentation for the Setagaya Load Testing Platform.

## 📚 Documentation Structure

### **Planning & Development**
- **[RBAC Executive Summary](RBAC_EXECUTIVE_SUMMARY.md)** - Executive overview of enterprise RBAC initiative
- **[RBAC Development Plan](RBAC_DEVELOPMENT_PLAN.md)** - Comprehensive development strategy for v3.0 RBAC
- **[RBAC Technical Specification](RBAC_TECHNICAL_SPECIFICATION.md)** - Detailed implementation guide for RBAC

### **API Documentation**
- **[OpenAPI Specification](api/openapi.yaml)** - REST API documentation (OpenAPI 3.0)

# Setagaya Documentation Index

This file is the canonical index for repository documentation. It is maintained as part of Phase 1 (audit & canonical index) of the documentation reorganization.

## Quick links

- Root README: [../README.md](../README.md)
- Technical Specifications: [../TECHNICAL_SPECS.md](../TECHNICAL_SPECS.md)
- API (OpenAPI): [api/openapi.yaml](api/openapi.yaml)
- Security: [../SECURITY.md](../SECURITY.md)
- Development guidelines (AI & coding): [../.github/instructions/copilot.instructions.md](../.github/instructions/copilot.instructions.md)

## Documentation Inventory (Phase 1 audit)

Below is a concise inventory of key documentation files and suggested category/status for Phase 1. This is not exhaustive — use it as the canonical starting point for the reorganization.

| File / Path | Suggested Category | Current status | Owner |
|---|---:|---|---|
| `RBAC_EXECUTIVE_SUMMARY.md` | guides / executive | stable | @team-rbac |
| `RBAC_DEVELOPMENT_PLAN.md` | planning | reviewed | @team-rbac |
| `RBAC_TECHNICAL_SPECIFICATION.md` | reference / design | draft | @team-rbac |
| `api/openapi.yaml` | api / reference | stable | @api-team |
| `TECHNICAL_SPECS.md` | reference / architecture | stable | @arch-team |
| `SECURITY.md` | security | stable | @security |
| `setagaya/JMETER_BUILD_OPTIONS.md` | guides / ops | reviewed | @engines-team |
| `.github/instructions/copilot.instructions.md` | contrib / developer-guides | stable | @dev-rel |
| `.github/SECURITY_CHECKLIST.md` | security / checklist | stable | @security |
| `docs/SUMMARY.md` | guides / book | draft | @doc-maintainers |
| `docs/src/introduction.md` | guides / intro | draft | @doc-maintainers |
| `DOCUMENATION.md` | reference / misc | draft | @doc-maintainers |
| `README.md` (repo root) | entry | stable | @maintainers |
| `CHANGELOG.md` | release | stable | @release |
| `wordlist.dic`, `cspell.json` | appendix / tools | stable | @doc-maintainers |
| `kubernetes/` (manifests) | ops / deployment | reviewed | @ops |
| `grafana/` (dashboards) | ops / monitoring | reviewed | @ops |

Notes:
- Status values: draft (needs work), reviewed (peer-reviewed), stable (production-ready).
- Owner values are placeholders — replace with actual GitHub usernames or team handles when available.

## Phase 1 tasks completed (this update)

- Inventory created and included above
- Canonical index updated (this file)
- Suggested categories/status assigned to top-level docs

## Immediate next steps (Phase 1 finishing tasks)

1. Add minimal front-matter to high-priority docs (title/description/kind/status/owner). See docs/templates for examples (will be created in Phase 3).
2. Run link and spell checks locally and fix broken links.
3. Add `docs/_redirects` or a simple migration map to avoid breaking external links while moving files.
4. Create per-category index pages: `docs/guides/README.md`, `docs/reference/README.md`, `docs/api/README.md`, `docs/ops/README.md`.

## Local checks (quick commands)

Run these locally before opening migration PRs to catch obvious problems (adapt to your environment):

```bash
# lint and format markdown (project has npm scripts)
npm run lint:md
npm run format

# lint YAML manifests
yamllint kubernetes/ || true

# spellcheck (cspell)
npm run lint:spell || npx cspell '**/*.md' --config cspell.json

# validate OpenAPI (if you have openapi-cli installed)
# npx @redocly/openapi-cli validate api/openapi.yaml || true
```

## Migration safety notes

- Update `.github/wordlist.txt` before introducing new domain-specific terms (repo policy requires this).
- Do not move `api/openapi.yaml` without first ensuring CI OpenAPI validation will run on the new path.
- When moving files, prefer incremental PRs (20-30 files per PR) and use link-check CI to catch regressions.

---

**Last Updated**: 2025-09-19
**Phase**: Phase 1 — audit & canonical index (in this branch)
