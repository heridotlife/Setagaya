-- RBAC Database Schema for Setagaya v3.0
-- Phase 1: Core RBAC tables for multi-tenant role-based access control
-- Migration Version: 2025.09.11.001
-- Description: Initial RBAC schema deployment with Okta integration support

-- Drop tables if they exist (for development/testing)
-- DROP TABLE IF EXISTS rbac_audit_log;
-- DROP TABLE IF EXISTS rbac_permission_cache;
-- DROP TABLE IF EXISTS rbac_user_roles;
-- DROP TABLE IF EXISTS rbac_tenants;
-- DROP TABLE IF EXISTS rbac_roles;

-- ============================================================================
-- Core RBAC Tables
-- ============================================================================

-- Roles table with hierarchical support
CREATE TABLE rbac_roles (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL UNIQUE COMMENT 'Unique role name (e.g., tenant_admin, service_provider_admin)',
    display_name VARCHAR(255) NOT NULL COMMENT 'Human-readable role name',
    description TEXT COMMENT 'Detailed description of role capabilities',
    parent_role_id BIGINT NULL COMMENT 'Parent role for inheritance (future feature)',
    is_system_role BOOLEAN DEFAULT FALSE COMMENT 'True for built-in roles that cannot be deleted',
    is_tenant_scoped BOOLEAN DEFAULT TRUE COMMENT 'True if role operates within tenant scope',
    permissions JSON NOT NULL COMMENT 'JSON array of permission objects',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (parent_role_id) REFERENCES rbac_roles(id) ON DELETE SET NULL,
    INDEX idx_rbac_roles_name (name),
    INDEX idx_rbac_roles_parent (parent_role_id),
    INDEX idx_rbac_roles_system (is_system_role),
    INDEX idx_rbac_roles_tenant_scoped (is_tenant_scoped)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='RBAC roles with hierarchical support and permission definitions';

-- Tenants table for multi-tenancy
CREATE TABLE rbac_tenants (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL UNIQUE COMMENT 'Unique tenant identifier (e.g., acme-corp)',
    display_name VARCHAR(255) NOT NULL COMMENT 'Human-readable tenant name',
    description TEXT COMMENT 'Tenant description and notes',
    okta_group_prefix VARCHAR(100) NOT NULL UNIQUE COMMENT 'Okta group prefix (e.g., setagaya-acme-corp)',
    status ENUM('ACTIVE', 'SUSPENDED', 'DELETED') DEFAULT 'ACTIVE' COMMENT 'Tenant lifecycle status',
    quota_config JSON COMMENT 'Resource quotas and limits configuration',
    billing_config JSON COMMENT 'Billing and payment configuration',
    metadata JSON COMMENT 'Additional tenant-specific metadata',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_rbac_tenants_name (name),
    INDEX idx_rbac_tenants_status (status),
    INDEX idx_rbac_tenants_okta_prefix (okta_group_prefix)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Multi-tenant organizations with Okta integration';

-- User roles assignment with tenant scoping
CREATE TABLE rbac_user_roles (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id VARCHAR(255) NOT NULL COMMENT 'Okta User ID (email or UUID)',
    user_email VARCHAR(255) NOT NULL COMMENT 'User email address for display',
    role_id BIGINT NOT NULL COMMENT 'Reference to rbac_roles',
    tenant_id BIGINT NULL COMMENT 'NULL for global roles, specific tenant for scoped roles',
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When role was granted',
    granted_by VARCHAR(255) NOT NULL COMMENT 'Who granted this role (user ID)',
    expires_at TIMESTAMP NULL COMMENT 'NULL for permanent roles, future expiration date',
    is_active BOOLEAN DEFAULT TRUE COMMENT 'Active status for temporary suspension',
    
    FOREIGN KEY (role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES rbac_tenants(id) ON DELETE CASCADE,
    
    -- Ensure unique user-role-tenant combinations
    UNIQUE KEY unique_user_role_tenant (user_id, role_id, tenant_id),
    
    INDEX idx_rbac_user_roles_user (user_id),
    INDEX idx_rbac_user_roles_tenant (tenant_id),
    INDEX idx_rbac_user_roles_active (is_active),
    INDEX idx_rbac_user_roles_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='User role assignments with tenant scoping and expiration support';

-- Permission cache for performance optimization
CREATE TABLE rbac_permission_cache (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id VARCHAR(255) NOT NULL COMMENT 'Okta User ID',
    tenant_id BIGINT NULL COMMENT 'NULL for global permissions',
    resource_type VARCHAR(100) NOT NULL COMMENT 'Resource type (project, collection, etc.)',
    resource_id VARCHAR(255) NULL COMMENT 'Specific resource ID or NULL for type-level',
    permissions JSON NOT NULL COMMENT 'Computed permissions for this context',
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When permissions were computed',
    expires_at TIMESTAMP NOT NULL COMMENT 'Cache expiration time',
    
    -- Unique cache entries per user-tenant-resource context
    UNIQUE KEY unique_cache_entry (user_id, tenant_id, resource_type, resource_id),
    
    INDEX idx_rbac_cache_user (user_id),
    INDEX idx_rbac_cache_tenant (tenant_id),
    INDEX idx_rbac_cache_expires (expires_at),
    INDEX idx_rbac_cache_resource (resource_type, resource_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Permission cache for performance optimization with TTL support';

-- Comprehensive audit logging for compliance and security
CREATE TABLE rbac_audit_log (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id VARCHAR(255) NOT NULL COMMENT 'User who performed the action',
    user_email VARCHAR(255) NOT NULL COMMENT 'User email for display',
    session_id VARCHAR(255) COMMENT 'Session identifier for tracking',
    action VARCHAR(100) NOT NULL COMMENT 'Action performed (create_project, delete_tenant, etc.)',
    resource_type VARCHAR(50) NOT NULL COMMENT 'Type of resource affected',
    resource_id VARCHAR(255) COMMENT 'Specific resource identifier',
    tenant_id BIGINT NULL COMMENT 'Tenant context for the action',
    result ENUM('ALLOWED', 'DENIED') NOT NULL COMMENT 'Authorization result',
    reason TEXT COMMENT 'Reason for the decision or additional context',
    request_details JSON COMMENT 'Full request context and parameters',
    ip_address VARCHAR(45) COMMENT 'Client IP address (IPv4 or IPv6)',
    user_agent TEXT COMMENT 'Client user agent string',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When the action occurred',
    
    FOREIGN KEY (tenant_id) REFERENCES rbac_tenants(id) ON DELETE SET NULL,
    
    INDEX idx_rbac_audit_user (user_id),
    INDEX idx_rbac_audit_timestamp (timestamp),
    INDEX idx_rbac_audit_tenant (tenant_id),
    INDEX idx_rbac_audit_action (action),
    INDEX idx_rbac_audit_result (result),
    INDEX idx_rbac_audit_resource (resource_type, resource_id),
    INDEX idx_rbac_audit_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Immutable audit log for all authorization decisions and actions';

-- ============================================================================
-- Migration Support for Existing Tables
-- ============================================================================

-- Add tenant support to existing project table
ALTER TABLE project
ADD COLUMN tenant_id BIGINT NULL COMMENT 'Tenant ownership for multi-tenancy',
ADD COLUMN created_by VARCHAR(255) NULL COMMENT 'Okta User ID who created the project',
ADD COLUMN updated_by VARCHAR(255) NULL COMMENT 'Okta User ID who last updated the project',
ADD FOREIGN KEY (tenant_id) REFERENCES rbac_tenants(id) ON DELETE SET NULL,
ADD INDEX idx_project_tenant (tenant_id),
ADD INDEX idx_project_created_by (created_by);

-- Add tenant support to existing collection table
ALTER TABLE collection
ADD COLUMN tenant_id BIGINT NULL COMMENT 'Tenant ownership for multi-tenancy',
ADD COLUMN created_by VARCHAR(255) NULL COMMENT 'Okta User ID who created the collection',
ADD COLUMN updated_by VARCHAR(255) NULL COMMENT 'Okta User ID who last updated the collection',
ADD FOREIGN KEY (tenant_id) REFERENCES rbac_tenants(id) ON DELETE SET NULL,
ADD INDEX idx_collection_tenant (tenant_id),
ADD INDEX idx_collection_created_by (created_by);

-- Add tenant support to existing plan table
ALTER TABLE plan
ADD COLUMN tenant_id BIGINT NULL COMMENT 'Tenant ownership for multi-tenancy',
ADD COLUMN created_by VARCHAR(255) NULL COMMENT 'Okta User ID who created the plan',
ADD COLUMN updated_by VARCHAR(255) NULL COMMENT 'Okta User ID who last updated the plan',
ADD FOREIGN KEY (tenant_id) REFERENCES rbac_tenants(id) ON DELETE SET NULL,
ADD INDEX idx_plan_tenant (tenant_id),
ADD INDEX idx_plan_created_by (created_by);

-- ============================================================================
-- Default Data Insertion
-- ============================================================================

-- Insert default system roles
INSERT INTO rbac_roles (name, display_name, description, is_system_role, is_tenant_scoped, permissions) VALUES
('service_provider_admin', 'Service Provider Admin', 'Full platform administration with global access to all tenants and resources', TRUE, FALSE, '[]'),
('service_provider_support', 'Service Provider Support', 'Read-only access for customer support and troubleshooting across all tenants', TRUE, FALSE, '[]'),
('pjm_loadtest', 'Project Manager - Load Testing', 'Cross-tenant project management and coordination for load testing operations', TRUE, FALSE, '[]'),
('tenant_admin', 'Tenant Administrator', 'Full administrative access within assigned tenant(s)', TRUE, TRUE, '[]'),
('tenant_editor', 'Tenant Editor', 'Create and modify resources within assigned tenant(s)', TRUE, TRUE, '[]'),
('tenant_viewer', 'Tenant Viewer', 'Read-only access to resources within assigned tenant(s)', TRUE, TRUE, '[]');

-- Insert default tenant for migration of existing data
INSERT INTO rbac_tenants (name, display_name, description, okta_group_prefix, status, metadata) VALUES
('default', 'Default Tenant', 'Default tenant for existing data migration and single-tenant installations', 'setagaya-default', 'ACTIVE', '{"migration": true, "created_for": "data_migration"}');

-- Update existing projects to belong to default tenant
UPDATE project SET tenant_id = 1 WHERE tenant_id IS NULL;
UPDATE collection SET tenant_id = 1 WHERE tenant_id IS NULL;
UPDATE plan SET tenant_id = 1 WHERE tenant_id IS NULL;

-- ============================================================================
-- Database Constraints and Validation
-- ============================================================================

-- Add check constraints for data validation
ALTER TABLE rbac_tenants 
ADD CONSTRAINT chk_tenant_name_format 
CHECK (name REGEXP '^[a-z0-9-]+$' AND LENGTH(name) >= 3);

ALTER TABLE rbac_tenants
ADD CONSTRAINT chk_okta_group_prefix_format
CHECK (okta_group_prefix REGEXP '^setagaya-[a-z0-9-]+$');

-- Add check constraint for role names
ALTER TABLE rbac_roles
ADD CONSTRAINT chk_role_name_format
CHECK (name REGEXP '^[a-z_]+$' AND LENGTH(name) >= 3);

-- ============================================================================
-- Performance Optimization
-- ============================================================================

-- Composite indexes for common query patterns
CREATE INDEX idx_rbac_user_roles_user_tenant ON rbac_user_roles(user_id, tenant_id);
CREATE INDEX idx_rbac_audit_user_tenant_timestamp ON rbac_audit_log(user_id, tenant_id, timestamp);
CREATE INDEX idx_rbac_audit_tenant_timestamp ON rbac_audit_log(tenant_id, timestamp DESC);

-- ============================================================================
-- Comments and Documentation
-- ============================================================================

-- Add table comments for documentation
ALTER TABLE rbac_roles COMMENT = 'RBAC roles with hierarchical support and JSON permission definitions for flexible authorization';
ALTER TABLE rbac_tenants COMMENT = 'Multi-tenant organizations with Okta integration and resource quotas';
ALTER TABLE rbac_user_roles COMMENT = 'User role assignments with tenant scoping, expiration, and audit trail';
ALTER TABLE rbac_permission_cache COMMENT = 'Performance cache for computed permissions with TTL management';
ALTER TABLE rbac_audit_log COMMENT = 'Immutable audit trail for all authorization decisions and user actions';