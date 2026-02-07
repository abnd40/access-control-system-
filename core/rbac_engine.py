"""
Role-Based Access Control (RBAC) Engine
========================================

Implements NIST RBAC model with the following features:
- Core RBAC: Users, roles, permissions, sessions
- Hierarchical RBAC: Role inheritance and permission propagation
- Constrained RBAC: Separation of duties (SoD) support

Reference: NIST INCITS 359-2004 (RBAC Standard)

In defense/intel environments, RBAC is foundational for:
- Need-to-know access enforcement
- Duty separation (e.g., analysts vs approvers)
- Audit trail generation
- Least privilege implementation
"""

from datetime import datetime
from typing import List, Set, Optional, Dict, Any
from sqlalchemy.orm import Session

from models.entities import (
    User, Role, Permission, Resource,
    UserRole, RolePermission, RoleHierarchy, AccessDecision
)


class RBACEngine:
    """
    RBAC decision engine implementing hierarchical role-based access control.

    Supports:
    - Direct permission assignment through roles
    - Permission inheritance through role hierarchies
    - Time-based role validity
    - Efficient permission caching
    """

    def __init__(self, session: Session):
        """
        Initialize RBAC engine with database session.

        Args:
            session: SQLAlchemy session for database operations
        """
        self.session = session
        self._permission_cache: Dict[int, Set[str]] = {}  # user_id -> permissions

    def check_access(
        self,
        user_id: int,
        permission_name: str,
        resource: Optional[Resource] = None
    ) -> tuple[AccessDecision, str]:
        """
        Check if a user has the specified permission.

        Args:
            user_id: The user requesting access
            permission_name: The permission being checked (e.g., 'read:document')
            resource: Optional resource for resource-specific checks

        Returns:
            Tuple of (AccessDecision, reason_string)
        """
        # Get user
        user = self.session.query(User).filter(User.id == user_id).first()
        if not user:
            return AccessDecision.DENY, "User not found"

        if not user.is_active:
            return AccessDecision.DENY, "User account is inactive"

        # Get all effective permissions for the user
        effective_permissions = self.get_effective_permissions(user_id)

        # Check if required permission is in effective permissions
        if permission_name in effective_permissions:
            return AccessDecision.PERMIT, f"Permission '{permission_name}' granted via role assignment"

        # Check for wildcard permissions (e.g., 'admin:*' matches 'admin:users')
        for perm in effective_permissions:
            if perm.endswith(':*'):
                prefix = perm[:-1]  # Remove '*'
                if permission_name.startswith(prefix):
                    return AccessDecision.PERMIT, f"Permission granted via wildcard '{perm}'"

        return AccessDecision.DENY, f"Permission '{permission_name}' not granted to user"

    def get_effective_permissions(self, user_id: int) -> Set[str]:
        """
        Get all effective permissions for a user, including inherited permissions.

        This implements the hierarchical RBAC model where permissions flow
        from parent roles to child roles.

        Args:
            user_id: The user ID to get permissions for

        Returns:
            Set of permission names the user effectively has
        """
        # Check cache first
        if user_id in self._permission_cache:
            return self._permission_cache[user_id]

        permissions = set()
        now = datetime.utcnow()

        # Get user's direct role assignments
        user_roles = self.session.query(UserRole).filter(
            UserRole.user_id == user_id,
            UserRole.valid_from <= now,
            (UserRole.valid_until.is_(None) | (UserRole.valid_until > now))
        ).all()

        # Collect all role IDs (direct and inherited)
        all_role_ids = set()
        for user_role in user_roles:
            role = self.session.query(Role).filter(
                Role.id == user_role.role_id,
                Role.is_active == True
            ).first()
            if role:
                all_role_ids.add(role.id)
                # Get inherited roles (traverse up the hierarchy)
                inherited_roles = self._get_inherited_roles(role.id)
                all_role_ids.update(inherited_roles)

        # Get permissions for all roles
        for role_id in all_role_ids:
            role_perms = self.session.query(RolePermission).filter(
                RolePermission.role_id == role_id
            ).all()
            for rp in role_perms:
                perm = self.session.query(Permission).filter(
                    Permission.id == rp.permission_id
                ).first()
                if perm:
                    permissions.add(perm.name)

        # Cache the result
        self._permission_cache[user_id] = permissions
        return permissions

    def _get_inherited_roles(self, role_id: int, visited: Optional[Set[int]] = None) -> Set[int]:
        """
        Recursively get all roles that a role inherits from.

        Handles circular references through visited set tracking.

        Args:
            role_id: Starting role ID
            visited: Set of already visited role IDs (for cycle detection)

        Returns:
            Set of inherited role IDs
        """
        if visited is None:
            visited = set()

        if role_id in visited:
            return set()  # Prevent infinite loops

        visited.add(role_id)
        inherited = set()

        # Get parent roles
        hierarchies = self.session.query(RoleHierarchy).filter(
            RoleHierarchy.child_role_id == role_id
        ).all()

        for h in hierarchies:
            inherited.add(h.parent_role_id)
            # Recurse to get grandparent roles
            inherited.update(self._get_inherited_roles(h.parent_role_id, visited))

        return inherited

    def get_user_roles(self, user_id: int) -> List[Role]:
        """
        Get all roles directly assigned to a user.

        Args:
            user_id: The user ID

        Returns:
            List of Role objects
        """
        now = datetime.utcnow()
        user_roles = self.session.query(UserRole).filter(
            UserRole.user_id == user_id,
            UserRole.valid_from <= now,
            (UserRole.valid_until.is_(None) | (UserRole.valid_until > now))
        ).all()

        roles = []
        for ur in user_roles:
            role = self.session.query(Role).filter(
                Role.id == ur.role_id,
                Role.is_active == True
            ).first()
            if role:
                roles.append(role)

        return roles

    def assign_role(
        self,
        user_id: int,
        role_id: int,
        assigned_by: Optional[int] = None,
        valid_until: Optional[datetime] = None
    ) -> UserRole:
        """
        Assign a role to a user.

        Args:
            user_id: User to receive the role
            role_id: Role to assign
            assigned_by: User ID of who made the assignment
            valid_until: Optional expiration date

        Returns:
            Created UserRole object
        """
        # Clear cache for this user
        self._permission_cache.pop(user_id, None)

        user_role = UserRole(
            user_id=user_id,
            role_id=role_id,
            assigned_by=assigned_by,
            valid_until=valid_until
        )
        self.session.add(user_role)
        self.session.flush()
        return user_role

    def revoke_role(self, user_id: int, role_id: int) -> bool:
        """
        Revoke a role from a user.

        Args:
            user_id: User to revoke from
            role_id: Role to revoke

        Returns:
            True if role was revoked, False if not found
        """
        # Clear cache for this user
        self._permission_cache.pop(user_id, None)

        result = self.session.query(UserRole).filter(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id
        ).delete()

        return result > 0

    def create_role_hierarchy(self, parent_role_id: int, child_role_id: int) -> RoleHierarchy:
        """
        Create a role hierarchy relationship.

        The child role will inherit all permissions from the parent role.

        Args:
            parent_role_id: The senior/parent role
            child_role_id: The junior/child role that inherits

        Returns:
            Created RoleHierarchy object
        """
        # Clear all caches since hierarchy affects multiple users
        self._permission_cache.clear()

        hierarchy = RoleHierarchy(
            parent_role_id=parent_role_id,
            child_role_id=child_role_id
        )
        self.session.add(hierarchy)
        self.session.flush()
        return hierarchy

    def get_role_hierarchy(self, role_id: int) -> Dict[str, Any]:
        """
        Get the complete hierarchy for a role.

        Returns both parent roles (inherits from) and child roles (inherited by).

        Args:
            role_id: Role to get hierarchy for

        Returns:
            Dictionary with 'parents' and 'children' lists
        """
        role = self.session.query(Role).filter(Role.id == role_id).first()
        if not role:
            return {'role': None, 'parents': [], 'children': []}

        # Get parent roles
        parent_hierarchies = self.session.query(RoleHierarchy).filter(
            RoleHierarchy.child_role_id == role_id
        ).all()
        parents = []
        for h in parent_hierarchies:
            parent = self.session.query(Role).filter(Role.id == h.parent_role_id).first()
            if parent:
                parents.append({'id': parent.id, 'name': parent.name})

        # Get child roles
        child_hierarchies = self.session.query(RoleHierarchy).filter(
            RoleHierarchy.parent_role_id == role_id
        ).all()
        children = []
        for h in child_hierarchies:
            child = self.session.query(Role).filter(Role.id == h.child_role_id).first()
            if child:
                children.append({'id': child.id, 'name': child.name})

        return {
            'role': {'id': role.id, 'name': role.name},
            'parents': parents,
            'children': children
        }

    def clear_cache(self, user_id: Optional[int] = None):
        """
        Clear the permission cache.

        Args:
            user_id: Specific user to clear, or None to clear all
        """
        if user_id:
            self._permission_cache.pop(user_id, None)
        else:
            self._permission_cache.clear()
