"""
Entity Models for Access Control System
========================================

Implements comprehensive data models for both RBAC and ABAC systems:

RBAC Components:
- Users: Identity entities requesting access
- Roles: Named collections of permissions (e.g., Analyst, Admin)
- Permissions: Specific actions on resources (e.g., read:document)
- Role Hierarchy: Inheritance relationships between roles

ABAC Components:
- User Attributes: Properties like clearance level, department
- Resource Attributes: Classification, owner, sensitivity
- Policies: Rules evaluating attributes for access decisions

This design follows NIST RBAC and XACML ABAC standards commonly
used in defense and intelligence environments.
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean,
    ForeignKey, Text, Enum as SQLEnum
)
from sqlalchemy.orm import relationship
import enum

from .database import Base


class ClearanceLevel(enum.Enum):
    """
    Security clearance levels modeled after U.S. government classifications.
    Used for demonstrating hierarchical access control.
    """
    UNCLASSIFIED = 0
    CONFIDENTIAL = 1
    SECRET = 2
    TOP_SECRET = 3
    TOP_SECRET_SCI = 4  # Sensitive Compartmented Information


class AccessDecision(enum.Enum):
    """Possible outcomes of an access control decision."""
    PERMIT = "PERMIT"
    DENY = "DENY"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INDETERMINATE = "INDETERMINATE"


# ============================================================================
# RBAC Models
# ============================================================================

class User(Base):
    """
    User entity representing an identity in the system.

    In defense/intel contexts, users are typically authenticated via
    CAC (Common Access Card) or similar PKI credentials.
    """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True)
    full_name = Column(String(255))
    password_hash = Column(String(255))  # BCrypt hash
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    roles = relationship("UserRole", back_populates="user", cascade="all, delete-orphan")
    attributes = relationship("UserAttribute", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}')>"


class Role(Base):
    """
    Role entity representing a named collection of permissions.

    Examples in defense context:
    - Intelligence Analyst
    - System Administrator
    - Security Officer
    - Auditor
    """
    __tablename__ = 'roles'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    users = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")
    permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")

    # Role hierarchy - parent roles (roles this role inherits from)
    parent_roles = relationship(
        "RoleHierarchy",
        foreign_keys="RoleHierarchy.child_role_id",
        back_populates="child_role",
        cascade="all, delete-orphan"
    )

    # Role hierarchy - child roles (roles that inherit from this role)
    child_roles = relationship(
        "RoleHierarchy",
        foreign_keys="RoleHierarchy.parent_role_id",
        back_populates="parent_role",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Role(id={self.id}, name='{self.name}')>"


class Permission(Base):
    """
    Permission entity representing a specific action on a resource type.

    Format: action:resource_type (e.g., 'read:intelligence_report')

    Common actions in security contexts:
    - read, write, delete, approve, classify, declassify
    """
    __tablename__ = 'permissions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text)
    resource_type = Column(String(100))  # e.g., 'document', 'system', 'report'
    action = Column(String(50))  # e.g., 'read', 'write', 'approve'
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    roles = relationship("RolePermission", back_populates="permission", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Permission(id={self.id}, name='{self.name}')>"


class Resource(Base):
    """
    Resource entity representing protected assets in the system.

    Examples: Documents, Systems, Reports, Databases, Facilities
    """
    __tablename__ = 'resources'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    resource_type = Column(String(100), nullable=False)  # document, system, etc.
    description = Column(Text)
    owner_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    attributes = relationship("ResourceAttribute", back_populates="resource", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Resource(id={self.id}, name='{self.name}', type='{self.resource_type}')>"


# ============================================================================
# RBAC Junction Tables
# ============================================================================

class UserRole(Base):
    """
    Association between users and roles.

    Supports temporal constraints (valid_from, valid_until) for
    time-limited role assignments common in classified environments.
    """
    __tablename__ = 'user_roles'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)
    assigned_by = Column(Integer, ForeignKey('users.id'))
    assigned_at = Column(DateTime, default=datetime.utcnow)
    valid_from = Column(DateTime, default=datetime.utcnow)
    valid_until = Column(DateTime)  # NULL = no expiration

    # Relationships
    user = relationship("User", back_populates="roles", foreign_keys=[user_id])
    role = relationship("Role", back_populates="users")

    def __repr__(self):
        return f"<UserRole(user_id={self.user_id}, role_id={self.role_id})>"


class RolePermission(Base):
    """Association between roles and permissions."""
    __tablename__ = 'role_permissions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)
    permission_id = Column(Integer, ForeignKey('permissions.id'), nullable=False)
    granted_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    role = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")

    def __repr__(self):
        return f"<RolePermission(role_id={self.role_id}, permission_id={self.permission_id})>"


class RoleHierarchy(Base):
    """
    Role inheritance relationships.

    Enables role hierarchies like:
    - Senior Analyst inherits from Analyst
    - Admin inherits from all operational roles

    This reduces permission management overhead and ensures
    consistent access policies.
    """
    __tablename__ = 'role_hierarchy'

    id = Column(Integer, primary_key=True, autoincrement=True)
    parent_role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)
    child_role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    parent_role = relationship("Role", foreign_keys=[parent_role_id], back_populates="child_roles")
    child_role = relationship("Role", foreign_keys=[child_role_id], back_populates="parent_roles")

    def __repr__(self):
        return f"<RoleHierarchy(parent={self.parent_role_id}, child={self.child_role_id})>"


# ============================================================================
# ABAC Models
# ============================================================================

class UserAttribute(Base):
    """
    User attributes for ABAC policy evaluation.

    Common attributes in defense/intel:
    - clearance_level: Security clearance
    - department: Organizational unit
    - location: Physical/network location
    - citizenship: For ITAR/EAR compliance
    - polygraph_status: For certain accesses
    """
    __tablename__ = 'user_attributes'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    attribute_name = Column(String(100), nullable=False)
    attribute_value = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="attributes")

    def __repr__(self):
        return f"<UserAttribute(user_id={self.user_id}, {self.attribute_name}='{self.attribute_value}')>"


class ResourceAttribute(Base):
    """
    Resource attributes for ABAC policy evaluation.

    Common attributes:
    - classification: Security classification level
    - compartment: SCI compartments (e.g., TK, SI, HCS)
    - handling_caveats: NOFORN, REL TO, etc.
    - data_owner: Originating organization
    """
    __tablename__ = 'resource_attributes'

    id = Column(Integer, primary_key=True, autoincrement=True)
    resource_id = Column(Integer, ForeignKey('resources.id'), nullable=False)
    attribute_name = Column(String(100), nullable=False)
    attribute_value = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    resource = relationship("Resource", back_populates="attributes")

    def __repr__(self):
        return f"<ResourceAttribute(resource_id={self.resource_id}, {self.attribute_name}='{self.attribute_value}')>"


class ABACPolicy(Base):
    """
    ABAC Policy definition following XACML concepts.

    Policies define rules for access decisions based on:
    - Subject attributes (user properties)
    - Resource attributes (what's being accessed)
    - Action (what operation is requested)
    - Environment (contextual conditions)

    The policy_expression is a JSON-serialized rule that gets
    evaluated by the ABAC engine.
    """
    __tablename__ = 'abac_policies'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    policy_expression = Column(Text, nullable=False)  # JSON policy rule
    effect = Column(String(20), default="DENY")  # PERMIT or DENY
    priority = Column(Integer, default=0)  # Higher = evaluated first
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<ABACPolicy(id={self.id}, name='{self.name}', effect='{self.effect}')>"


# ============================================================================
# Audit Logging
# ============================================================================

class AuditLog(Base):
    """
    Comprehensive audit log for all access decisions.

    Critical for:
    - Security investigations
    - Compliance reporting
    - Insider threat detection
    - Access pattern analysis

    Follows NIST 800-53 AU (Audit and Accountability) controls.
    """
    __tablename__ = 'audit_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Who
    user_id = Column(Integer, ForeignKey('users.id'))
    username = Column(String(100))  # Denormalized for query performance

    # What
    action = Column(String(100), nullable=False)
    resource_id = Column(Integer, ForeignKey('resources.id'))
    resource_name = Column(String(255))  # Denormalized
    resource_type = Column(String(100))

    # Decision
    decision = Column(SQLEnum(AccessDecision), nullable=False)
    decision_reason = Column(Text)
    policy_applied = Column(String(100))  # Which policy made the decision

    # Context
    access_method = Column(String(50))  # RBAC, ABAC, or HYBRID
    client_ip = Column(String(45))  # IPv4 or IPv6
    session_id = Column(String(100))

    # Additional metadata
    request_details = Column(Text)  # JSON with full request context

    def __repr__(self):
        return f"<AuditLog(id={self.id}, user='{self.username}', action='{self.action}', decision={self.decision})>"
