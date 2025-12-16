# Setagaya Documentation Index

Welcome to the Setagaya Load Testing Platform documentation. This index helps you find the right documentation for your needs.

## 📚 Core Documentation (Root Level)

### [📖 README.md](../README.md)
- **Purpose**: Project overview and quick start
- **Audience**: First-time users, general overview
- **Contents**: Features, architecture overview, installation, basic usage

### [🔧 Technical Specifications](../TECHNICAL_SPECS.md)
- **Purpose**: Comprehensive technical documentation
- **Audience**: Developers, system administrators, architects
- **Contents**: Detailed architecture, configuration, deployment, APIs

### [🔒 Security Documentation](../SECURITY.md)
- **Purpose**: Security policies and vulnerability disclosure
- **Audience**: Security teams, operators, researchers
- **Contents**: Vulnerability reporting, security measures, best practices

### [📋 Security Checklist](../.github/SECURITY_CHECKLIST.md)
- **Purpose**: Release security validation checklist
- **Audience**: Release managers, security officers
- **Contents**: 100+ security checkpoints for releases

### [📝 Changelog](../CHANGELOG.md)
- **Purpose**: Version history and release notes
- **Audience**: All users tracking changes
- **Contents**: Feature additions, bug fixes, breaking changes

## 📚 Documentation in This Directory

### **Planning & Development**
- **[RBAC Executive Summary](RBAC_EXECUTIVE_SUMMARY.md)** - Executive overview of enterprise RBAC initiative
- **[RBAC Development Plan](RBAC_DEVELOPMENT_PLAN.md)** - Comprehensive development strategy for v3.0 RBAC
- **[RBAC Technical Specification](RBAC_TECHNICAL_SPECIFICATION.md)** - Detailed implementation guide for RBAC

### **Best Practices & Guides**
- **[Best Practices](BEST_PRACTICES.md)** - CodeQL, Docker security, and workflow optimization patterns
- **[Documentation Links](DOCUMENTATION_LINKS.md)** - Configurable documentation URLs for deployment

### **API Documentation**
- **[OpenAPI Specification](api/openapi.yaml)** - REST API documentation (OpenAPI 3.0)

### **Component-Specific Documentation**
- **[JMeter Build Options](../setagaya/JMETER_BUILD_OPTIONS.md)** - JMeter version compatibility guide
- **[Development Guidelines](../.github/instructions/copilot.instructions.md)** - AI coding guidelines and patterns

## 🚀 Getting Started

### Quick Start Path
1. **Start Here**: [README.md](../README.md) - Overview and local setup
2. **Deep Dive**: [Technical Specifications](../TECHNICAL_SPECS.md) - Complete technical details
3. **JMeter Setup**: [JMeter Build Options](../setagaya/JMETER_BUILD_OPTIONS.md) - Engine configuration

### For Different Audiences

#### 👩‍💻 **Developers**
- [Development Guidelines](../.github/instructions/copilot.instructions.md) - AI coding guidelines and patterns
- [Technical Specifications](../TECHNICAL_SPECS.md) - Architecture and extension points
- [Best Practices](BEST_PRACTICES.md) - CodeQL, Docker, and workflow optimization
- [RBAC Technical Specification](RBAC_TECHNICAL_SPECIFICATION.md) - v3.0 RBAC implementation

#### 🏢 **Project Managers**
- [RBAC Executive Summary](RBAC_EXECUTIVE_SUMMARY.md) - Enterprise RBAC initiative overview
- [RBAC Development Plan](RBAC_DEVELOPMENT_PLAN.md) - Timeline and milestones
- [Security Policy](../SECURITY.md) - Compliance and security posture

#### 🔧 **System Administrators**
- [Technical Specifications](../TECHNICAL_SPECS.md) - Deployment and infrastructure
- [JMeter Build Options](../setagaya/JMETER_BUILD_OPTIONS.md) - Engine setup
- [Security Policy](../SECURITY.md) - Security configuration
- [Security Checklist](../.github/SECURITY_CHECKLIST.md) - Release validation

#### 🧪 **Test Engineers**
- [README.md](../README.md) - Platform capabilities and workflow
- [Technical Specifications](../TECHNICAL_SPECS.md) - Test lifecycle and monitoring
- [API Documentation](api/openapi.yaml) - Integration and automation

#### 🔒 **Security Teams**
- [Security Policy](../SECURITY.md) - Vulnerability disclosure and procedures
- [Security Checklist](../.github/SECURITY_CHECKLIST.md) - Release security validation
- [Best Practices](BEST_PRACTICES.md) - Security scanning and hardening

## 🔍 Finding Specific Information

### Architecture & Design
- **Project Structure**: [README.md](../README.md) → Core Components
- **Detailed Architecture**: [Technical Specs](../TECHNICAL_SPECS.md) → Architecture Overview
- **Domain Model**: [Technical Specs](../TECHNICAL_SPECS.md) → Domain Model

### Installation & Setup
- **Quick Setup**: [README.md](../README.md) → Quick Start
- **Local Development**: [README.md](../README.md) → Local Development Setup
- **Production Deployment**: [Technical Specs](../TECHNICAL_SPECS.md) → Deployment Options

### Configuration
- **Basic Config**: [README.md](../README.md) → Configuration
- **Detailed Config**: [Technical Specs](../TECHNICAL_SPECS.md) → Configuration System
- **Examples**: `setagaya/config_tmpl.json`

### JMeter & Engines
- **Overview**: [README.md](../README.md) → Container Images
- **Version Support**: [JMeter Build Options](../setagaya/JMETER_BUILD_OPTIONS.md)
- **Technical Details**: [Technical Specs](../TECHNICAL_SPECS.md) → JMeter Engine Compatibility

### Development
- **Getting Started**: [Development Guidelines](../.github/instructions/copilot.instructions.md)
- **Coding Patterns**: [Technical Specs](../TECHNICAL_SPECS.md) → Extension Points
- **Best Practices**: [Best Practices](BEST_PRACTICES.md)
- **Testing**: [Technical Specs](../TECHNICAL_SPECS.md) → Development Workflow

## 🆘 Common Questions

**Q: Which JMeter version should I use?**  
→ See [JMeter Build Options](../setagaya/JMETER_BUILD_OPTIONS.md)

**Q: How do I deploy to production?**  
→ See [Technical Specifications](../TECHNICAL_SPECS.md) → Deployment Options

**Q: How do I extend the platform?**  
→ See [Technical Specifications](../TECHNICAL_SPECS.md) → Extension Points

**Q: What are the security considerations?**  
→ See [Security Policy](../SECURITY.md) and [Technical Specs](../TECHNICAL_SPECS.md) → Security

**Q: How do I report a security vulnerability?**  
→ See [Security Policy](../SECURITY.md) → Reporting a Vulnerability

**Q: How do I set up monitoring?**  
→ See [Technical Specifications](../TECHNICAL_SPECS.md) → Metrics and Monitoring

**Q: What security automation is available?**  
→ See [Technical Specs](../TECHNICAL_SPECS.md) → Security Automation and [Security Checklist](../.github/SECURITY_CHECKLIST.md)

## 🔄 Documentation Maintenance

### Update Process
- Documentation is automatically validated via GitHub Actions
- Spell checking and link validation on every commit
- Technical accuracy reviews during feature development
- Regular updates to reflect current architecture

### Contributing
- Follow documentation standards in [Development Guidelines](../.github/instructions/copilot.instructions.md)
- Update relevant documentation for any code changes
- Ensure OpenAPI specification stays current with API changes
- Add new technical terms to `.github/wordlist.txt`

### Archived Documents
Historical summaries and deprecated documentation can be found in the [archive](archive/) directory.

---

**Last Updated**: January 2025  
**Next Review**: Monthly during active development

**Need help?** Start with the [README.md](../README.md) for overview, then dive into [Technical Specifications](../TECHNICAL_SPECS.md) for detailed information.

