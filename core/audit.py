"""
Audit Logging Module
====================

Implements comprehensive audit logging for all access control decisions.
Critical for compliance with security frameworks:

- NIST 800-53 AU (Audit and Accountability)
- ICD 503 (Intelligence Community security)
- FISMA requirements
- SOX compliance (for financial systems)

Features:
- Immutable audit trail
- Detailed decision context
- Query and reporting capabilities
- Export functionality for SIEM integration
"""

import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from models.entities import AuditLog, AccessDecision, User, Resource


class AuditLogger:
    """
    Audit logging service for access control decisions.

    Provides:
    - Log creation for all access decisions
    - Query capabilities for security investigations
    - Export for external SIEM systems
    - Statistical analysis of access patterns
    """

    def __init__(self, session: Session):
        """
        Initialize audit logger with database session.

        Args:
            session: SQLAlchemy session for database operations
        """
        self.session = session

    def log_access_decision(
        self,
        user_id: Optional[int],
        username: Optional[str],
        action: str,
        resource_id: Optional[int],
        resource_name: Optional[str],
        resource_type: Optional[str],
        decision: AccessDecision,
        decision_reason: str,
        policy_applied: Optional[str] = None,
        access_method: str = 'HYBRID',
        client_ip: Optional[str] = None,
        session_id: Optional[str] = None,
        request_details: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        """
        Log an access control decision.

        Args:
            user_id: ID of requesting user
            username: Username (denormalized for query performance)
            action: Action being attempted
            resource_id: Target resource ID
            resource_name: Resource name (denormalized)
            resource_type: Type of resource
            decision: The access decision made
            decision_reason: Explanation for the decision
            policy_applied: Name of policy that made the decision
            access_method: RBAC, ABAC, or HYBRID
            client_ip: Client IP address
            session_id: Session identifier
            request_details: Additional context as dictionary

        Returns:
            Created AuditLog entry
        """
        log_entry = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            resource_id=resource_id,
            resource_name=resource_name,
            resource_type=resource_type,
            decision=decision,
            decision_reason=decision_reason,
            policy_applied=policy_applied,
            access_method=access_method,
            client_ip=client_ip,
            session_id=session_id,
            request_details=json.dumps(request_details) if request_details else None
        )

        self.session.add(log_entry)
        self.session.flush()
        return log_entry

    def get_logs(
        self,
        user_id: Optional[int] = None,
        resource_id: Optional[int] = None,
        action: Optional[str] = None,
        decision: Optional[AccessDecision] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditLog]:
        """
        Query audit logs with various filters.

        Args:
            user_id: Filter by user
            resource_id: Filter by resource
            action: Filter by action type
            decision: Filter by decision outcome
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum results to return
            offset: Pagination offset

        Returns:
            List of matching AuditLog entries
        """
        query = self.session.query(AuditLog)

        if user_id is not None:
            query = query.filter(AuditLog.user_id == user_id)
        if resource_id is not None:
            query = query.filter(AuditLog.resource_id == resource_id)
        if action is not None:
            query = query.filter(AuditLog.action == action)
        if decision is not None:
            query = query.filter(AuditLog.decision == decision)
        if start_time is not None:
            query = query.filter(AuditLog.timestamp >= start_time)
        if end_time is not None:
            query = query.filter(AuditLog.timestamp <= end_time)

        return query.order_by(desc(AuditLog.timestamp)).limit(limit).offset(offset).all()

    def get_recent_denials(self, hours: int = 24, limit: int = 50) -> List[AuditLog]:
        """
        Get recent access denials for security monitoring.

        Critical for detecting:
        - Unauthorized access attempts
        - Potential insider threats
        - Misconfigured permissions

        Args:
            hours: Look back period in hours
            limit: Maximum results

        Returns:
            List of DENY audit logs
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return self.session.query(AuditLog).filter(
            AuditLog.decision == AccessDecision.DENY,
            AuditLog.timestamp >= cutoff
        ).order_by(desc(AuditLog.timestamp)).limit(limit).all()

    def get_user_activity(
        self,
        user_id: int,
        hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get activity summary for a specific user.

        Useful for:
        - User behavior analytics
        - Insider threat detection
        - Access pattern analysis

        Args:
            user_id: User to analyze
            hours: Look back period

        Returns:
            Activity summary dictionary
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        logs = self.session.query(AuditLog).filter(
            AuditLog.user_id == user_id,
            AuditLog.timestamp >= cutoff
        ).all()

        # Aggregate statistics
        total_requests = len(logs)
        permits = sum(1 for l in logs if l.decision == AccessDecision.PERMIT)
        denials = sum(1 for l in logs if l.decision == AccessDecision.DENY)

        actions = {}
        resources = {}
        for log in logs:
            actions[log.action] = actions.get(log.action, 0) + 1
            if log.resource_name:
                resources[log.resource_name] = resources.get(log.resource_name, 0) + 1

        return {
            'user_id': user_id,
            'period_hours': hours,
            'total_requests': total_requests,
            'permits': permits,
            'denials': denials,
            'denial_rate': denials / total_requests if total_requests > 0 else 0,
            'actions': actions,
            'resources_accessed': resources,
            'first_activity': min(l.timestamp for l in logs).isoformat() if logs else None,
            'last_activity': max(l.timestamp for l in logs).isoformat() if logs else None
        }

    def get_resource_access_history(
        self,
        resource_id: int,
        hours: int = 168  # 1 week default
    ) -> Dict[str, Any]:
        """
        Get access history for a specific resource.

        Useful for:
        - Data access auditing
        - Compliance reporting
        - Identifying unusual access patterns

        Args:
            resource_id: Resource to analyze
            hours: Look back period

        Returns:
            Access history summary
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        logs = self.session.query(AuditLog).filter(
            AuditLog.resource_id == resource_id,
            AuditLog.timestamp >= cutoff
        ).all()

        users = {}
        actions = {}
        for log in logs:
            if log.username:
                users[log.username] = users.get(log.username, 0) + 1
            actions[log.action] = actions.get(log.action, 0) + 1

        return {
            'resource_id': resource_id,
            'period_hours': hours,
            'total_access_attempts': len(logs),
            'unique_users': len(users),
            'users': users,
            'actions': actions,
            'successful_accesses': sum(1 for l in logs if l.decision == AccessDecision.PERMIT),
            'denied_accesses': sum(1 for l in logs if l.decision == AccessDecision.DENY)
        }

    def export_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        format: str = 'json'
    ) -> str:
        """
        Export audit logs for external SIEM integration.

        Supports common formats for integration with:
        - Splunk
        - ELK Stack
        - Azure Sentinel
        - AWS CloudWatch

        Args:
            start_time: Export start time
            end_time: Export end time
            format: Output format ('json' or 'csv')

        Returns:
            Formatted log data as string
        """
        logs = self.get_logs(
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )

        if format == 'json':
            return json.dumps([
                {
                    'timestamp': log.timestamp.isoformat(),
                    'user_id': log.user_id,
                    'username': log.username,
                    'action': log.action,
                    'resource_id': log.resource_id,
                    'resource_name': log.resource_name,
                    'resource_type': log.resource_type,
                    'decision': log.decision.value,
                    'decision_reason': log.decision_reason,
                    'policy_applied': log.policy_applied,
                    'access_method': log.access_method,
                    'client_ip': log.client_ip,
                    'session_id': log.session_id
                }
                for log in logs
            ], indent=2)

        elif format == 'csv':
            lines = ['timestamp,user_id,username,action,resource_id,resource_name,decision,policy_applied']
            for log in logs:
                lines.append(
                    f'{log.timestamp.isoformat()},{log.user_id},{log.username},'
                    f'{log.action},{log.resource_id},{log.resource_name},'
                    f'{log.decision.value},{log.policy_applied}'
                )
            return '\n'.join(lines)

        else:
            raise ValueError(f"Unsupported format: {format}")

    def get_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get overall access control statistics.

        Provides high-level metrics for security dashboards.

        Args:
            hours: Analysis period

        Returns:
            Statistics dictionary
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        logs = self.session.query(AuditLog).filter(
            AuditLog.timestamp >= cutoff
        ).all()

        total = len(logs)
        permits = sum(1 for l in logs if l.decision == AccessDecision.PERMIT)
        denials = sum(1 for l in logs if l.decision == AccessDecision.DENY)

        by_method = {'RBAC': 0, 'ABAC': 0, 'HYBRID': 0}
        for log in logs:
            if log.access_method in by_method:
                by_method[log.access_method] += 1

        unique_users = len(set(l.user_id for l in logs if l.user_id))
        unique_resources = len(set(l.resource_id for l in logs if l.resource_id))

        return {
            'period_hours': hours,
            'total_decisions': total,
            'permits': permits,
            'denials': denials,
            'permit_rate': permits / total if total > 0 else 0,
            'denial_rate': denials / total if total > 0 else 0,
            'by_access_method': by_method,
            'unique_users': unique_users,
            'unique_resources': unique_resources
        }
