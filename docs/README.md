# Setagaya Documentation Index

This directory contains comprehensive documentation for the Setagaya Load Testing Platform.

## 📚 Documentation Structure

### **Planning & Development**
- **[RBAC Executive Summary](RBAC_EXECUTIVE_SUMMARY.md)** - Executive overview of enterprise RBAC initiative
- **[RBAC Development Plan](RBAC_DEVELOPMENT_PLAN.md)** - Comprehensive development strategy for v3.0 RBAC
- **[RBAC Technical Specification](RBAC_TECHNICAL_SPECIFICATION.md)** - Detailed implementation guide for RBAC

### **API Documentation**
- **[OpenAPI Specification](api/openapi.yaml)** - REST API documentation (OpenAPI 3.0)

### **Platform Documentation** (Root Level)
- **[Technical Specifications](../TECHNICAL_SPECS.md)** - Comprehensive technical documentation
- **[Security Policy](../SECURITY.md)** - Security measures and vulnerability disclosure
- **[JMeter Build Options](../setagaya/JMETER_BUILD_OPTIONS.md)** - JMeter version compatibility guide
- **[Development Guidelines](../.github/instructions/copilot.instructions.md)** - AI coding guidelines and patterns
- **[Security Checklist](../.github/SECURITY_CHECKLIST.md)** - Release security validation

## 🗺️ Documentation Roadmap

### **Current Focus (v2.0.0-rc.1)**
- ✅ Complete technical specifications
- ✅ Security automation documentation
- ✅ API documentation improvements
- ✅ Development workflow documentation

### **Next Phase (v3.0.0)**
- 🎯 **RBAC Documentation Suite** (completed)
  - Executive summary for stakeholders
  - Comprehensive development plan
  - Technical implementation specifications
- 📋 **User Documentation**
  - Administrator guides
  - End-user tutorials
  - API client examples
- 🔐 **Security Documentation**
  - Identity management guides
  - Compliance procedures
  - Audit trail documentation

### **Future Enhancements**
- **Interactive Documentation**: API playground and tutorials
- **Video Guides**: Setup and configuration walkthroughs
- **Best Practices**: Load testing methodology and patterns
- **Troubleshooting**: Common issues and solutions

## 📖 How to Use This Documentation

### **For Developers**
1. Start with [Technical Specifications](../TECHNICAL_SPECS.md) for architecture overview
2. Review [Development Guidelines](../.github/instructions/copilot.instructions.md) for coding standards
3. Use [API Documentation](api/openapi.yaml) for integration details
4. Follow [RBAC Technical Specification](RBAC_TECHNICAL_SPECIFICATION.md) for v3.0 development

### **For Project Managers**
1. Read [RBAC Executive Summary](RBAC_EXECUTIVE_SUMMARY.md) for initiative overview
2. Review [RBAC Development Plan](RBAC_DEVELOPMENT_PLAN.md) for timeline and milestones
3. Use [Security Policy](../SECURITY.md) for compliance understanding
4. Reference [Security Checklist](../.github/SECURITY_CHECKLIST.md) for release validation

### **For System Administrators**
1. Start with [Technical Specifications](../TECHNICAL_SPECS.md) for deployment details
2. Review [JMeter Build Options](../setagaya/JMETER_BUILD_OPTIONS.md) for engine setup
3. Use [Security Policy](../SECURITY.md) for security configuration
4. Follow [Development Guidelines](../.github/instructions/copilot.instructions.md) for maintenance

### **For Enterprise Customers**
1. Review [RBAC Executive Summary](RBAC_EXECUTIVE_SUMMARY.md) for enterprise features
2. Understand [Security Policy](../SECURITY.md) for compliance requirements
3. Use [API Documentation](api/openapi.yaml) for integration planning
4. Reference [RBAC Development Plan](RBAC_DEVELOPMENT_PLAN.md) for roadmap details

## 🔄 Documentation Maintenance

### **Update Process**
- Documentation is automatically validated via GitHub Actions
- Spell checking and link validation on every commit
- Technical accuracy reviews during feature development
- Regular updates to reflect current architecture

### **Contributing**
- Follow the documentation standards in [Development Guidelines](../.github/instructions/copilot.instructions.md)
- Update relevant documentation for any code changes
- Ensure OpenAPI specification stays current with API changes
- Add new technical terms to the spell check wordlist

### **Feedback**
- Documentation issues can be reported via GitHub Issues
- Improvement suggestions welcome via Pull Requests
- Regular documentation reviews with stakeholder feedback
- User experience improvements based on support queries

---

## 📚 Legacy Documentation Build

### **mdBook Setup** (for book-style documentation)
If you want to build the legacy mdBook documentation:

1. Install [mdBook](https://github.com/rust-lang/mdBook)
2. `cd docs && mdbook build`
3. `mdbook serve` for local development
4. `mdbook watch` for automatic rebuilds

### **GitHub Pages**
The documentation is automatically published to GitHub Pages via GitHub Actions. See [GitHub Pages Configuration](https://github.com/peaceiris/actions-mdbook) for setup details.

---

**Last Updated**: September 11, 2025
**Next Review**: Monthly during active development
