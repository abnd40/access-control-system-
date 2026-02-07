"""
Hybrid Access Control Engine
============================

Combines RBAC and ABAC for comprehensive access control.

This hybrid approach is common in defense/intel environments where:
- RBAC provides efficient role-based permission management
- ABAC adds fine-grained, context-aware access decisions

The hybrid model supports:
- RBAC-first: Quick permit via roles, then ABAC validation
- ABAC-first: Attribute check, then role verification
- Parallel: Both must permit for access
- Override: ABAC can override RBAC decisions

This implementation uses an AND strategy by default:
- User must have RBAC permission AND pass ABAC policy
"""

from typing import Tuple, Optional, Dict, Any
from sqlalchemy.orm import Session

from models.entities import AccessDecision, User, Resource
from .rbac_engine import RBACEngine
from .abac_engine import ABACEngine
from .audit import AuditLogger


class HybridAccessControl:
    """
    Unified access control system combining RBAC and ABAC.

    Provides a single interface for access decisions while leveraging
    both role-based and attribute-based controls. All decisions are
    automatically logged for audit purposes.
    """

    # Combining strategies
    STRATEGY_RBAC_ONLY = 'rbac_only'
    STRATEGY_ABAC_ONLY = 'abac_only'
    STRATEGY_RBAC_AND_ABAC = 'rbac_and_abac'
    STRATEGY_RBAC_OR_ABAC = 'rbac_or_abac'
    STRATEGY_ABAC_OVERRIDE = 'abac_override'

    def __init__(self, session: Session, strategy: str = 'rbac_and_abac'):
        """
        Initialize hybrid access control.

        Args:
            session: SQLAlchemy session
            strategy: Combining strategy to use
        """
        self.session = session
        self.strategy = strategy
        self.rbac = RBACEngine(session)
        self.abac = ABACEngine(session)
        self.audit = AuditLogger(session)

    def check_access(
        self,
        user_id: int,
        permission: str,
        resource_id: Optional[int] = None,
        action: Optional[str] = None,
        environment: Optional[Dict[str, Any]] = None,
        client_ip: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> Tuple[AccessDecision, str]:
        """
        Check if access should be granted.

        This is the primary method for access control decisions.
        It combines RBAC and ABAC based on the configured strategy.

        Args:
            user_id: Requesting user
            permission: Required permission (for RBAC)
            resource_id: Target resource ID (for ABAC)
            action: Action being performed (defaults to permission if not provided)
            environment: Environmental context for ABAC
            client_ip: Client IP for audit logging
            session_id: Session ID for audit logging

        Returns:
            Tuple of (AccessDecision, reason)
        """
        # Get user info for logging
        user = self.session.query(User).filter(User.id == user_id).first()
        username = user.username if user else None

        # Get resource info for logging
        resource = None
        resource_name = None
        resource_type = None
        if resource_id:
            resource = self.session.query(Resource).filter(Resource.id == resource_id).first()
            if resource:
                resource_name = resource.name
                resource_type = resource.resource_type

        # Use permission as action if not specified
        if action is None:
            action = permission

        # Execute access check based on strategy
        decision, reason, policy_applied = self._evaluate(
            user_id, permission, resource_id, action, environment
        )

        # Log the decision
        self.audit.log_access_decision(
            user_id=user_id,
            username=username,
            action=action,
            resource_id=resource_id,
            resource_name=resource_name,
            resource_type=resource_type,
            decision=decision,
            decision_reason=reason,
            policy_applied=policy_applied,
            access_method=self.strategy.upper(),
            client_ip=client_ip,
            session_id=session_id,
            request_details={
                'permission': permission,
                'environment': environment
            }
        )

        return decision, reason

    def _evaluate(
        self,
        user_id: int,
        permission: str,
        resource_id: Optional[int],
        action: str,
        environment: Optional[Dict[str, Any]]
    ) -> Tuple[AccessDecision, str, Optional[str]]:
        """
        Internal evaluation method based on strategy.

        Args:
            user_id: Requesting user
            permission: Required permission
            resource_id: Target resource
            action: Action being performed
            environment: Environmental context

        Returns:
            Tuple of (decision, reason, policy_applied)
        """
        if self.strategy == self.STRATEGY_RBAC_ONLY:
            return self._evaluate_rbac_only(user_id, permission)

        elif self.strategy == self.STRATEGY_ABAC_ONLY:
            return self._evaluate_abac_only(user_id, resource_id, action, environment)

        elif self.strategy == self.STRATEGY_RBAC_AND_ABAC:
            return self._evaluate_rbac_and_abac(
                user_id, permission, resource_id, action, environment
            )

        elif self.strategy == self.STRATEGY_RBAC_OR_ABAC:
            return self._evaluate_rbac_or_abac(
                user_id, permission, resource_id, action, environment
            )

        elif self.strategy == self.STRATEGY_ABAC_OVERRIDE:
            return self._evaluate_abac_override(
                user_id, permission, resource_id, action, environment
            )

        else:
            return AccessDecision.DENY, f"Unknown strategy: {self.strategy}", None

    def _evaluate_rbac_only(
        self,
        user_id: int,
        permission: str
    ) -> Tuple[AccessDecision, str, Optional[str]]:
        """RBAC-only evaluation."""
        decision, reason = self.rbac.check_access(user_id, permission)
        return decision, reason, "RBAC"

    def _evaluate_abac_only(
        self,
        user_id: int,
        resource_id: Optional[int],
        action: str,
        environment: Optional[Dict[str, Any]]
    ) -> Tuple[AccessDecision, str, Optional[str]]:
        """ABAC-only evaluation."""
        if resource_id is None:
            return AccessDecision.DENY, "Resource ID required for ABAC", None

        return self.abac.check_access(user_id, resource_id, action, environment)

    def _evaluate_rbac_and_abac(
        self,
        user_id: int,
        permission: str,
        resource_id: Optional[int],
        action: str,
        environment: Optional[Dict[str, Any]]
    ) -> Tuple[AccessDecision, str, Optional[str]]:
        """
        AND strategy: Both RBAC and ABAC must permit.

        This is the most secure approach, requiring:
        1. User has the required role/permission (RBAC)
        2. User's attributes satisfy resource policies (ABAC)
        """
        # Check RBAC first
        rbac_decision, rbac_reason = self.rbac.check_access(user_id, permission)

        if rbac_decision != AccessDecision.PERMIT:
            return rbac_decision, f"RBAC denied: {rbac_reason}", "RBAC"

        # If no resource specified, RBAC permit is sufficient
        if resource_id is None:
            return AccessDecision.PERMIT, rbac_reason, "RBAC"

        # Check ABAC
        abac_decision, abac_reason, policy = self.abac.check_access(
            user_id, resource_id, action, environment
        )

        if abac_decision == AccessDecision.NOT_APPLICABLE:
            # No ABAC policy applies, RBAC permit stands
            return AccessDecision.PERMIT, f"RBAC: {rbac_reason} (no ABAC policy)", "RBAC"

        if abac_decision != AccessDecision.PERMIT:
            return abac_decision, f"ABAC denied: {abac_reason}", policy

        return AccessDecision.PERMIT, f"RBAC and ABAC permit", policy

    def _evaluate_rbac_or_abac(
        self,
        user_id: int,
        permission: str,
        resource_id: Optional[int],
        action: str,
        environment: Optional[Dict[str, Any]]
    ) -> Tuple[AccessDecision, str, Optional[str]]:
        """
        OR strategy: Either RBAC or ABAC permit is sufficient.

        More permissive approach allowing access if either system permits.
        """
        # Check RBAC
        rbac_decision, rbac_reason = self.rbac.check_access(user_id, permission)

        if rbac_decision == AccessDecision.PERMIT:
            return AccessDecision.PERMIT, f"RBAC permit: {rbac_reason}", "RBAC"

        # RBAC denied, check ABAC if resource specified
        if resource_id is not None:
            abac_decision, abac_reason, policy = self.abac.check_access(
                user_id, resource_id, action, environment
            )

            if abac_decision == AccessDecision.PERMIT:
                return AccessDecision.PERMIT, f"ABAC permit: {abac_reason}", policy

            return AccessDecision.DENY, f"Both RBAC and ABAC denied", policy

        return rbac_decision, rbac_reason, "RBAC"

    def _evaluate_abac_override(
        self,
        user_id: int,
        permission: str,
        resource_id: Optional[int],
        action: str,
        environment: Optional[Dict[str, Any]]
    ) -> Tuple[AccessDecision, str, Optional[str]]:
        """
        ABAC Override strategy: ABAC decisions override RBAC.

        Useful when ABAC policies need to enforce additional constraints
        or grant exceptions beyond RBAC permissions.
        """
        # If resource specified, ABAC takes precedence
        if resource_id is not None:
            abac_decision, abac_reason, policy = self.abac.check_access(
                user_id, resource_id, action, environment
            )

            if abac_decision != AccessDecision.NOT_APPLICABLE:
                return abac_decision, f"ABAC override: {abac_reason}", policy

        # Fall back to RBAC
        rbac_decision, rbac_reason = self.rbac.check_access(user_id, permission)
        return rbac_decision, f"RBAC (no ABAC override): {rbac_reason}", "RBAC"

    def set_strategy(self, strategy: str):
        """
        Change the combining strategy.

        Args:
            strategy: New strategy to use
        """
        valid_strategies = [
            self.STRATEGY_RBAC_ONLY,
            self.STRATEGY_ABAC_ONLY,
            self.STRATEGY_RBAC_AND_ABAC,
            self.STRATEGY_RBAC_OR_ABAC,
            self.STRATEGY_ABAC_OVERRIDE
        ]

        if strategy not in valid_strategies:
            raise ValueError(f"Invalid strategy. Must be one of: {valid_strategies}")

        self.strategy = strategy

    def get_user_permissions_summary(self, user_id: int) -> Dict[str, Any]:
        """
        Get a comprehensive summary of user's access capabilities.

        Useful for access reviews and compliance reporting.

        Args:
            user_id: User to analyze

        Returns:
            Dictionary with roles, permissions, and attributes
        """
        user = self.session.query(User).filter(User.id == user_id).first()
        if not user:
            return {'error': 'User not found'}

        # Get RBAC info
        roles = self.rbac.get_user_roles(user_id)
        permissions = self.rbac.get_effective_permissions(user_id)

        # Get ABAC attributes
        attributes = self.abac.get_user_attributes(user_id)

        return {
            'user': {
                'id': user.id,
                'username': user.username,
                'full_name': user.full_name,
                'is_active': user.is_active
            },
            'rbac': {
                'roles': [{'id': r.id, 'name': r.name} for r in roles],
                'effective_permissions': list(permissions)
            },
            'abac': {
                'attributes': attributes
            }
        }
