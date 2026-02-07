"""
Attribute-Based Access Control (ABAC) Engine
=============================================

Implements XACML-inspired ABAC model with the following components:

Policy Decision Point (PDP): Evaluates policies and returns decisions
Policy Information Point (PIP): Retrieves attribute values
Policy Administration Point (PAP): Manages policies (via CLI)

Key Concepts:
- Subject Attributes: Properties of the requester (clearance, department)
- Resource Attributes: Properties of the target (classification, owner)
- Action: The operation being performed
- Environment: Context (time, location, threat level)

Reference: NIST SP 800-162 (ABAC Guide)

This implementation supports:
- JSON-based policy expressions
- Multiple combining algorithms
- Attribute comparisons and ranges
- Policy priorities
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from models.entities import (
    User, Resource, UserAttribute, ResourceAttribute,
    ABACPolicy, AccessDecision
)


class PolicyEvaluationContext:
    """
    Context object containing all attributes for policy evaluation.

    Follows XACML terminology:
    - subject: The entity requesting access (user attributes)
    - resource: The entity being accessed (resource attributes)
    - action: The operation being performed
    - environment: Contextual conditions
    """

    def __init__(
        self,
        subject_attrs: Dict[str, Any],
        resource_attrs: Dict[str, Any],
        action: str,
        environment_attrs: Optional[Dict[str, Any]] = None
    ):
        self.subject = subject_attrs
        self.resource = resource_attrs
        self.action = action
        self.environment = environment_attrs or {}

    def get_attribute(self, category: str, name: str) -> Any:
        """
        Get an attribute value from the context.

        Args:
            category: One of 'subject', 'resource', 'action', 'environment'
            name: Attribute name

        Returns:
            Attribute value or None if not found
        """
        if category == 'subject':
            return self.subject.get(name)
        elif category == 'resource':
            return self.resource.get(name)
        elif category == 'action':
            return self.action if name == 'id' else None
        elif category == 'environment':
            return self.environment.get(name)
        return None


class ABACEngine:
    """
    ABAC Policy Decision Point (PDP) implementation.

    Evaluates access requests against defined policies using
    attribute-based rules. Supports complex policy expressions
    with AND/OR logic and various comparison operators.
    """

    # Clearance level hierarchy for comparisons
    CLEARANCE_LEVELS = {
        'UNCLASSIFIED': 0,
        'CONFIDENTIAL': 1,
        'SECRET': 2,
        'TOP_SECRET': 3,
        'TOP_SECRET_SCI': 4
    }

    def __init__(self, session: Session):
        """
        Initialize ABAC engine with database session.

        Args:
            session: SQLAlchemy session for database operations
        """
        self.session = session

    def check_access(
        self,
        user_id: int,
        resource_id: int,
        action: str,
        environment: Optional[Dict[str, Any]] = None
    ) -> Tuple[AccessDecision, str, Optional[str]]:
        """
        Evaluate access request against ABAC policies.

        Args:
            user_id: Requesting user
            resource_id: Target resource
            action: Requested operation
            environment: Optional environmental context

        Returns:
            Tuple of (decision, reason, policy_name)
        """
        # Build evaluation context
        context = self._build_context(user_id, resource_id, action, environment)
        if context is None:
            return AccessDecision.DENY, "Failed to build evaluation context", None

        # Get applicable policies, ordered by priority
        policies = self.session.query(ABACPolicy).filter(
            ABACPolicy.is_active == True
        ).order_by(ABACPolicy.priority.desc()).all()

        if not policies:
            return AccessDecision.NOT_APPLICABLE, "No policies defined", None

        # Evaluate each policy (first-applicable combining algorithm)
        for policy in policies:
            try:
                result = self._evaluate_policy(policy, context)
                if result is not None:  # Policy is applicable
                    decision = AccessDecision.PERMIT if result else AccessDecision.DENY
                    effect = policy.effect
                    reason = f"Policy '{policy.name}' evaluated to {effect}"
                    return decision, reason, policy.name
            except Exception as e:
                # Log error and continue to next policy
                continue

        return AccessDecision.NOT_APPLICABLE, "No applicable policy found", None

    def _build_context(
        self,
        user_id: int,
        resource_id: int,
        action: str,
        environment: Optional[Dict[str, Any]]
    ) -> Optional[PolicyEvaluationContext]:
        """
        Build evaluation context from user and resource attributes.

        Args:
            user_id: User ID
            resource_id: Resource ID
            action: Requested action
            environment: Environmental attributes

        Returns:
            PolicyEvaluationContext or None if entities not found
        """
        # Get user and their attributes
        user = self.session.query(User).filter(User.id == user_id).first()
        if not user:
            return None

        user_attrs = self.session.query(UserAttribute).filter(
            UserAttribute.user_id == user_id
        ).all()

        subject_attrs = {
            'id': user.id,
            'username': user.username,
            'is_active': user.is_active
        }
        for attr in user_attrs:
            subject_attrs[attr.attribute_name] = attr.attribute_value

        # Get resource and its attributes
        resource = self.session.query(Resource).filter(Resource.id == resource_id).first()
        if not resource:
            return None

        resource_attrs_list = self.session.query(ResourceAttribute).filter(
            ResourceAttribute.resource_id == resource_id
        ).all()

        resource_attrs = {
            'id': resource.id,
            'name': resource.name,
            'type': resource.resource_type,
            'owner_id': resource.owner_id
        }
        for attr in resource_attrs_list:
            resource_attrs[attr.attribute_name] = attr.attribute_value

        # Add default environment attributes
        env = environment or {}
        env.setdefault('current_time', datetime.utcnow().isoformat())
        env.setdefault('day_of_week', datetime.utcnow().strftime('%A'))

        return PolicyEvaluationContext(
            subject_attrs=subject_attrs,
            resource_attrs=resource_attrs,
            action=action,
            environment_attrs=env
        )

    def _evaluate_policy(
        self,
        policy: ABACPolicy,
        context: PolicyEvaluationContext
    ) -> Optional[bool]:
        """
        Evaluate a single policy against the context.

        Policy expression format (JSON):
        {
            "target": {
                "actions": ["read", "write"],  # Optional: applicable actions
                "resource_types": ["document"]  # Optional: applicable resource types
            },
            "rules": [
                {
                    "operator": "AND",  # AND, OR
                    "conditions": [
                        {
                            "subject.clearance_level": {"gte": "resource.classification"}
                        }
                    ]
                }
            ]
        }

        Args:
            policy: The policy to evaluate
            context: The evaluation context

        Returns:
            True if policy permits, False if denies, None if not applicable
        """
        try:
            expression = json.loads(policy.policy_expression)
        except json.JSONDecodeError:
            return None

        # Check if policy is applicable (target matching)
        target = expression.get('target', {})

        # Check action applicability
        if 'actions' in target:
            if context.action not in target['actions']:
                return None  # Policy not applicable to this action

        # Check resource type applicability
        if 'resource_types' in target:
            resource_type = context.get_attribute('resource', 'type')
            if resource_type not in target['resource_types']:
                return None  # Policy not applicable to this resource type

        # Evaluate rules
        rules = expression.get('rules', [])
        if not rules:
            return None

        for rule in rules:
            result = self._evaluate_rule(rule, context)
            if not result:
                # If any rule fails, policy evaluation fails
                return policy.effect == 'DENY'

        # All rules passed
        return policy.effect == 'PERMIT'

    def _evaluate_rule(
        self,
        rule: Dict[str, Any],
        context: PolicyEvaluationContext
    ) -> bool:
        """
        Evaluate a single rule within a policy.

        Args:
            rule: Rule definition with operator and conditions
            context: Evaluation context

        Returns:
            True if rule passes, False otherwise
        """
        operator = rule.get('operator', 'AND')
        conditions = rule.get('conditions', [])

        results = []
        for condition in conditions:
            result = self._evaluate_condition(condition, context)
            results.append(result)

        if operator == 'AND':
            return all(results)
        elif operator == 'OR':
            return any(results)
        else:
            return False

    def _evaluate_condition(
        self,
        condition: Dict[str, Any],
        context: PolicyEvaluationContext
    ) -> bool:
        """
        Evaluate a single condition.

        Condition format:
        {
            "subject.clearance_level": {"gte": "resource.classification"}
        }

        Supported operators:
        - eq: Equal
        - neq: Not equal
        - gt, gte: Greater than (or equal)
        - lt, lte: Less than (or equal)
        - in: Value in list
        - contains: List contains value
        - matches: Regex match

        Args:
            condition: Condition definition
            context: Evaluation context

        Returns:
            True if condition is satisfied
        """
        for attr_path, comparison in condition.items():
            # Get the left-side value
            left_value = self._resolve_attribute(attr_path, context)

            for op, right_side in comparison.items():
                # Resolve right side (could be a literal or attribute reference)
                if isinstance(right_side, str) and '.' in right_side:
                    right_value = self._resolve_attribute(right_side, context)
                else:
                    right_value = right_side

                # Perform comparison
                if not self._compare(left_value, op, right_value):
                    return False

        return True

    def _resolve_attribute(
        self,
        attr_path: str,
        context: PolicyEvaluationContext
    ) -> Any:
        """
        Resolve an attribute path to its value.

        Args:
            attr_path: Path like 'subject.clearance_level'
            context: Evaluation context

        Returns:
            Attribute value
        """
        parts = attr_path.split('.')
        if len(parts) != 2:
            return None

        category, name = parts
        return context.get_attribute(category, name)

    def _compare(self, left: Any, operator: str, right: Any) -> bool:
        """
        Perform comparison between values.

        Special handling for clearance levels to enable hierarchical comparison.

        Args:
            left: Left operand
            operator: Comparison operator
            right: Right operand

        Returns:
            Comparison result
        """
        # Handle None values
        if left is None or right is None:
            return operator == 'eq' and left == right

        # Special handling for clearance level comparisons
        if left in self.CLEARANCE_LEVELS:
            left = self.CLEARANCE_LEVELS[left]
        if right in self.CLEARANCE_LEVELS:
            right = self.CLEARANCE_LEVELS[right]

        # Perform comparison
        try:
            if operator == 'eq':
                return left == right
            elif operator == 'neq':
                return left != right
            elif operator == 'gt':
                return left > right
            elif operator == 'gte':
                return left >= right
            elif operator == 'lt':
                return left < right
            elif operator == 'lte':
                return left <= right
            elif operator == 'in':
                return left in right
            elif operator == 'contains':
                return right in left
            elif operator == 'matches':
                import re
                return bool(re.match(right, str(left)))
            else:
                return False
        except (TypeError, ValueError):
            return False

    def create_policy(
        self,
        name: str,
        description: str,
        policy_expression: Dict[str, Any],
        effect: str = 'PERMIT',
        priority: int = 0
    ) -> ABACPolicy:
        """
        Create a new ABAC policy.

        Args:
            name: Policy name
            description: Policy description
            policy_expression: Policy rules as dictionary
            effect: PERMIT or DENY
            priority: Higher priority evaluated first

        Returns:
            Created ABACPolicy object
        """
        policy = ABACPolicy(
            name=name,
            description=description,
            policy_expression=json.dumps(policy_expression),
            effect=effect,
            priority=priority
        )
        self.session.add(policy)
        self.session.flush()
        return policy

    def set_user_attribute(
        self,
        user_id: int,
        attribute_name: str,
        attribute_value: str
    ) -> UserAttribute:
        """
        Set or update a user attribute.

        Args:
            user_id: User ID
            attribute_name: Attribute name
            attribute_value: Attribute value

        Returns:
            Created or updated UserAttribute
        """
        # Check if attribute exists
        existing = self.session.query(UserAttribute).filter(
            UserAttribute.user_id == user_id,
            UserAttribute.attribute_name == attribute_name
        ).first()

        if existing:
            existing.attribute_value = attribute_value
            existing.updated_at = datetime.utcnow()
            return existing
        else:
            attr = UserAttribute(
                user_id=user_id,
                attribute_name=attribute_name,
                attribute_value=attribute_value
            )
            self.session.add(attr)
            self.session.flush()
            return attr

    def set_resource_attribute(
        self,
        resource_id: int,
        attribute_name: str,
        attribute_value: str
    ) -> ResourceAttribute:
        """
        Set or update a resource attribute.

        Args:
            resource_id: Resource ID
            attribute_name: Attribute name
            attribute_value: Attribute value

        Returns:
            Created or updated ResourceAttribute
        """
        # Check if attribute exists
        existing = self.session.query(ResourceAttribute).filter(
            ResourceAttribute.resource_id == resource_id,
            ResourceAttribute.attribute_name == attribute_name
        ).first()

        if existing:
            existing.attribute_value = attribute_value
            return existing
        else:
            attr = ResourceAttribute(
                resource_id=resource_id,
                attribute_name=attribute_name,
                attribute_value=attribute_value
            )
            self.session.add(attr)
            self.session.flush()
            return attr

    def get_user_attributes(self, user_id: int) -> Dict[str, str]:
        """
        Get all attributes for a user.

        Args:
            user_id: User ID

        Returns:
            Dictionary of attribute name to value
        """
        attrs = self.session.query(UserAttribute).filter(
            UserAttribute.user_id == user_id
        ).all()

        return {attr.attribute_name: attr.attribute_value for attr in attrs}

    def get_resource_attributes(self, resource_id: int) -> Dict[str, str]:
        """
        Get all attributes for a resource.

        Args:
            resource_id: Resource ID

        Returns:
            Dictionary of attribute name to value
        """
        attrs = self.session.query(ResourceAttribute).filter(
            ResourceAttribute.resource_id == resource_id
        ).all()

        return {attr.attribute_name: attr.attribute_value for attr in attrs}
