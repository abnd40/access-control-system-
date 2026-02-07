"""
Demo Data Loader
================

Creates realistic sample data for demonstrating access control concepts.
Models a defense/intelligence environment with:

- Multiple clearance levels
- Department-based access
- Role hierarchies
- Classification-based resource protection

This data enables demonstration of both RBAC and ABAC decision-making.
"""

import json
from models.database import init_db, get_session
from models.entities import (
    User, Role, Permission, Resource,
    UserRole, RolePermission, RoleHierarchy,
    UserAttribute, ResourceAttribute, ABACPolicy
)


def load_demo_data():
    """
    Load comprehensive demo data for access control demonstration.

    Creates:
    - 6 users with different clearances and departments
    - 5 roles in a hierarchy
    - 15+ permissions
    - 5 classified resources
    - 4 ABAC policies
    """
    init_db()

    with get_session() as session:
        # Clear existing data (for idempotent loading)
        session.query(ABACPolicy).delete()
        session.query(ResourceAttribute).delete()
        session.query(UserAttribute).delete()
        session.query(RoleHierarchy).delete()
        session.query(RolePermission).delete()
        session.query(UserRole).delete()
        session.query(Resource).delete()
        session.query(Permission).delete()
        session.query(Role).delete()
        session.query(User).delete()
        session.commit()

        # ================================================================
        # Create Users
        # ================================================================
        users = [
            User(
                username="admin",
                full_name="System Administrator",
                email="admin@agency.gov",
                is_active=True
            ),
            User(
                username="analyst1",
                full_name="Jane Smith",
                email="jsmith@agency.gov",
                is_active=True
            ),
            User(
                username="analyst2",
                full_name="John Doe",
                email="jdoe@agency.gov",
                is_active=True
            ),
            User(
                username="senior_analyst",
                full_name="Sarah Johnson",
                email="sjohnson@agency.gov",
                is_active=True
            ),
            User(
                username="auditor",
                full_name="Michael Chen",
                email="mchen@agency.gov",
                is_active=True
            ),
            User(
                username="contractor",
                full_name="External Contractor",
                email="contractor@vendor.com",
                is_active=True
            )
        ]
        for user in users:
            session.add(user)
        session.flush()

        # ================================================================
        # Create Roles with Hierarchy
        # ================================================================
        roles = {
            'Viewer': Role(
                name="Viewer",
                description="Basic read-only access to unclassified materials"
            ),
            'Analyst': Role(
                name="Analyst",
                description="Intelligence analyst with read/write to reports"
            ),
            'Senior Analyst': Role(
                name="Senior Analyst",
                description="Senior analyst with approval authority"
            ),
            'Administrator': Role(
                name="Administrator",
                description="System administrator with full access"
            ),
            'Auditor': Role(
                name="Auditor",
                description="Security auditor with read-only access to all resources and logs"
            )
        }
        for role in roles.values():
            session.add(role)
        session.flush()

        # Create role hierarchy
        # Senior Analyst inherits from Analyst
        session.add(RoleHierarchy(
            parent_role_id=roles['Analyst'].id,
            child_role_id=roles['Senior Analyst'].id
        ))
        # Analyst inherits from Viewer
        session.add(RoleHierarchy(
            parent_role_id=roles['Viewer'].id,
            child_role_id=roles['Analyst'].id
        ))
        # Administrator inherits from Senior Analyst
        session.add(RoleHierarchy(
            parent_role_id=roles['Senior Analyst'].id,
            child_role_id=roles['Administrator'].id
        ))
        session.flush()

        # ================================================================
        # Create Permissions
        # ================================================================
        permissions = [
            # Document permissions
            Permission(name="read:document", action="read", resource_type="document",
                      description="Read documents"),
            Permission(name="write:document", action="write", resource_type="document",
                      description="Create and edit documents"),
            Permission(name="delete:document", action="delete", resource_type="document",
                      description="Delete documents"),
            Permission(name="classify:document", action="classify", resource_type="document",
                      description="Set document classification"),

            # Intelligence report permissions
            Permission(name="read:intel_report", action="read", resource_type="intel_report",
                      description="Read intelligence reports"),
            Permission(name="write:intel_report", action="write", resource_type="intel_report",
                      description="Create intelligence reports"),
            Permission(name="approve:intel_report", action="approve", resource_type="intel_report",
                      description="Approve intelligence reports for distribution"),

            # System permissions
            Permission(name="manage:users", action="manage", resource_type="users",
                      description="Create and manage user accounts"),
            Permission(name="manage:roles", action="manage", resource_type="roles",
                      description="Create and manage roles"),
            Permission(name="manage:policies", action="manage", resource_type="policies",
                      description="Create and manage ABAC policies"),

            # Audit permissions
            Permission(name="read:audit_logs", action="read", resource_type="audit_logs",
                      description="View audit logs"),
            Permission(name="export:audit_logs", action="export", resource_type="audit_logs",
                      description="Export audit logs"),

            # Wildcard admin permission
            Permission(name="admin:*", action="all", resource_type="all",
                      description="Full administrative access")
        ]
        for perm in permissions:
            session.add(perm)
        session.flush()

        # Create permission map for easy lookup
        perm_map = {p.name: p for p in permissions}

        # ================================================================
        # Assign Permissions to Roles
        # ================================================================
        role_permissions = {
            'Viewer': ['read:document'],
            'Analyst': ['read:intel_report', 'write:intel_report', 'write:document'],
            'Senior Analyst': ['approve:intel_report', 'classify:document'],
            'Administrator': ['admin:*', 'manage:users', 'manage:roles', 'manage:policies'],
            'Auditor': ['read:audit_logs', 'export:audit_logs', 'read:document', 'read:intel_report']
        }

        for role_name, perm_names in role_permissions.items():
            role = roles[role_name]
            for perm_name in perm_names:
                if perm_name in perm_map:
                    session.add(RolePermission(
                        role_id=role.id,
                        permission_id=perm_map[perm_name].id
                    ))
        session.flush()

        # ================================================================
        # Assign Roles to Users
        # ================================================================
        user_map = {u.username: u for u in users}

        user_roles = {
            'admin': ['Administrator'],
            'analyst1': ['Analyst'],
            'analyst2': ['Analyst'],
            'senior_analyst': ['Senior Analyst'],
            'auditor': ['Auditor'],
            'contractor': ['Viewer']
        }

        for username, role_names in user_roles.items():
            user = user_map[username]
            for role_name in role_names:
                session.add(UserRole(
                    user_id=user.id,
                    role_id=roles[role_name].id
                ))
        session.flush()

        # ================================================================
        # Set User Attributes (for ABAC)
        # ================================================================
        user_attributes = {
            'admin': {
                'clearance_level': 'TOP_SECRET_SCI',
                'department': 'IT_SECURITY',
                'citizenship': 'US',
                'location': 'HQ'
            },
            'analyst1': {
                'clearance_level': 'SECRET',
                'department': 'ANALYSIS',
                'citizenship': 'US',
                'location': 'HQ'
            },
            'analyst2': {
                'clearance_level': 'SECRET',
                'department': 'ANALYSIS',
                'citizenship': 'US',
                'location': 'FIELD_OFFICE'
            },
            'senior_analyst': {
                'clearance_level': 'TOP_SECRET',
                'department': 'ANALYSIS',
                'citizenship': 'US',
                'location': 'HQ'
            },
            'auditor': {
                'clearance_level': 'TOP_SECRET_SCI',
                'department': 'OVERSIGHT',
                'citizenship': 'US',
                'location': 'HQ'
            },
            'contractor': {
                'clearance_level': 'CONFIDENTIAL',
                'department': 'EXTERNAL',
                'citizenship': 'US',
                'location': 'REMOTE'
            }
        }

        for username, attrs in user_attributes.items():
            user = user_map[username]
            for attr_name, attr_value in attrs.items():
                session.add(UserAttribute(
                    user_id=user.id,
                    attribute_name=attr_name,
                    attribute_value=attr_value
                ))
        session.flush()

        # ================================================================
        # Create Resources
        # ================================================================
        resources = [
            Resource(
                name="DAILY_BRIEF_2024",
                resource_type="intel_report",
                description="Daily intelligence briefing - TOP SECRET"
            ),
            Resource(
                name="THREAT_ASSESSMENT_Q4",
                resource_type="intel_report",
                description="Quarterly threat assessment - SECRET"
            ),
            Resource(
                name="BUDGET_REPORT_2024",
                resource_type="document",
                description="Annual budget report - UNCLASSIFIED"
            ),
            Resource(
                name="SIGINT_COLLECTION_ALPHA",
                resource_type="intel_report",
                description="Signals intelligence collection - TOP SECRET/SCI"
            ),
            Resource(
                name="TRAINING_MANUAL",
                resource_type="document",
                description="Employee training manual - UNCLASSIFIED"
            )
        ]
        for res in resources:
            session.add(res)
        session.flush()

        resource_map = {r.name: r for r in resources}

        # ================================================================
        # Set Resource Attributes
        # ================================================================
        resource_attributes = {
            'DAILY_BRIEF_2024': {
                'classification': 'TOP_SECRET',
                'compartment': 'NONE',
                'handling_caveat': 'NOFORN',
                'owner_department': 'ANALYSIS'
            },
            'THREAT_ASSESSMENT_Q4': {
                'classification': 'SECRET',
                'compartment': 'NONE',
                'handling_caveat': 'REL_TO_FVEY',
                'owner_department': 'ANALYSIS'
            },
            'BUDGET_REPORT_2024': {
                'classification': 'UNCLASSIFIED',
                'compartment': 'NONE',
                'handling_caveat': 'NONE',
                'owner_department': 'FINANCE'
            },
            'SIGINT_COLLECTION_ALPHA': {
                'classification': 'TOP_SECRET_SCI',
                'compartment': 'SI',
                'handling_caveat': 'NOFORN',
                'owner_department': 'SIGINT'
            },
            'TRAINING_MANUAL': {
                'classification': 'UNCLASSIFIED',
                'compartment': 'NONE',
                'handling_caveat': 'NONE',
                'owner_department': 'HR'
            }
        }

        for res_name, attrs in resource_attributes.items():
            res = resource_map[res_name]
            for attr_name, attr_value in attrs.items():
                session.add(ResourceAttribute(
                    resource_id=res.id,
                    attribute_name=attr_name,
                    attribute_value=attr_value
                ))
        session.flush()

        # ================================================================
        # Create ABAC Policies
        # ================================================================
        policies = [
            ABACPolicy(
                name="clearance_enforcement",
                description="User clearance must meet or exceed resource classification",
                effect="PERMIT",
                priority=100,
                policy_expression=json.dumps({
                    "target": {
                        "actions": ["read", "write", "approve"]
                    },
                    "rules": [
                        {
                            "operator": "AND",
                            "conditions": [
                                {
                                    "subject.clearance_level": {"gte": "resource.classification"}
                                }
                            ]
                        }
                    ]
                })
            ),
            ABACPolicy(
                name="department_access",
                description="Users can only access resources from their department or shared resources",
                effect="PERMIT",
                priority=90,
                policy_expression=json.dumps({
                    "target": {
                        "resource_types": ["intel_report"]
                    },
                    "rules": [
                        {
                            "operator": "OR",
                            "conditions": [
                                {"subject.department": {"eq": "resource.owner_department"}},
                                {"subject.department": {"eq": "OVERSIGHT"}},
                                {"resource.owner_department": {"eq": "SHARED"}}
                            ]
                        }
                    ]
                })
            ),
            ABACPolicy(
                name="noforn_restriction",
                description="NOFORN documents require US citizenship",
                effect="PERMIT",
                priority=95,
                policy_expression=json.dumps({
                    "target": {
                        "actions": ["read", "write"]
                    },
                    "rules": [
                        {
                            "operator": "OR",
                            "conditions": [
                                {"resource.handling_caveat": {"neq": "NOFORN"}},
                                {"subject.citizenship": {"eq": "US"}}
                            ]
                        }
                    ]
                })
            ),
            ABACPolicy(
                name="hq_only_access",
                description="Certain resources only accessible from HQ location",
                effect="PERMIT",
                priority=80,
                policy_expression=json.dumps({
                    "target": {
                        "actions": ["read", "write", "approve"]
                    },
                    "rules": [
                        {
                            "operator": "OR",
                            "conditions": [
                                {"resource.classification": {"eq": "UNCLASSIFIED"}},
                                {"subject.location": {"in": ["HQ", "SCIF"]}}
                            ]
                        }
                    ]
                })
            )
        ]

        for policy in policies:
            session.add(policy)
        session.flush()

        print("Demo data loaded successfully!")
        print("\nCreated:")
        print(f"  - {len(users)} users")
        print(f"  - {len(roles)} roles (with hierarchy)")
        print(f"  - {len(permissions)} permissions")
        print(f"  - {len(resources)} resources")
        print(f"  - {len(policies)} ABAC policies")


if __name__ == "__main__":
    load_demo_data()
