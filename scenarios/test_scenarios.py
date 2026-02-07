"""
Test Scenarios for Access Control Demonstration
================================================

Provides realistic test scenarios that demonstrate both RBAC and ABAC
access control decisions in a defense/intelligence context.

Scenarios:
1. Clearance Level - Tests classification-based access
2. Department Access - Tests organizational boundaries
3. Role Hierarchy - Tests permission inheritance
4. Combined RBAC+ABAC - Tests hybrid access decisions
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from models.database import get_session
from models.entities import User, Resource, AccessDecision
from core.hybrid_engine import HybridAccessControl

console = Console()


def run_scenarios(scenario_name: str = "all"):
    """
    Run access control test scenarios.

    Args:
        scenario_name: Which scenario to run (clearance, department, hierarchy, combined, all)
    """
    scenarios = {
        'clearance': run_clearance_scenario,
        'department': run_department_scenario,
        'hierarchy': run_hierarchy_scenario,
        'combined': run_combined_scenario
    }

    console.print(Panel(
        "[bold]Access Control Test Scenarios[/bold]\n\n"
        "These scenarios demonstrate real-world access control decisions\n"
        "using both RBAC (role-based) and ABAC (attribute-based) controls.",
        title="Test Suite",
        box=box.DOUBLE
    ))

    if scenario_name == "all":
        for name, func in scenarios.items():
            console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
            func()
    elif scenario_name in scenarios:
        scenarios[scenario_name]()
    else:
        console.print(f"[red]Unknown scenario: {scenario_name}[/red]")
        console.print(f"Available: {', '.join(scenarios.keys())}, all")


def run_clearance_scenario():
    """
    Scenario: Clearance Level Enforcement

    Tests that users can only access resources at or below their clearance level.
    Demonstrates the fundamental principle of security classification.
    """
    console.print(Panel(
        "[bold]Scenario: Clearance Level Enforcement[/bold]\n\n"
        "Tests that users can only access resources at or below their clearance level.\n"
        "This is a fundamental security control in classified environments.",
        title="Clearance Scenario",
        box=box.ROUNDED
    ))

    test_cases = [
        # (username, resource_name, permission, expected)
        ("analyst1", "THREAT_ASSESSMENT_Q4", "read:intel_report", True),    # SECRET user -> SECRET doc
        ("analyst1", "DAILY_BRIEF_2024", "read:intel_report", False),       # SECRET user -> TOP SECRET doc
        ("senior_analyst", "DAILY_BRIEF_2024", "read:intel_report", True),  # TS user -> TOP SECRET doc
        ("contractor", "SIGINT_COLLECTION_ALPHA", "read:intel_report", False),  # CONF user -> TS/SCI doc
        ("admin", "SIGINT_COLLECTION_ALPHA", "read:intel_report", True),    # TS/SCI user -> TS/SCI doc
    ]

    _run_test_cases(test_cases, "Clearance Level Tests")


def run_department_scenario():
    """
    Scenario: Department-Based Access Control

    Tests that users can primarily access resources from their own department,
    with exceptions for oversight roles.
    """
    console.print(Panel(
        "[bold]Scenario: Department-Based Access[/bold]\n\n"
        "Tests organizational boundaries - users primarily access their department's resources.\n"
        "Oversight roles (auditors) can access across departments for compliance.",
        title="Department Scenario",
        box=box.ROUNDED
    ))

    test_cases = [
        # ANALYSIS department users accessing ANALYSIS resources
        ("analyst1", "THREAT_ASSESSMENT_Q4", "read:intel_report", True),
        ("analyst2", "DAILY_BRIEF_2024", "read:intel_report", True),

        # Auditor (OVERSIGHT) can access across departments
        ("auditor", "THREAT_ASSESSMENT_Q4", "read:intel_report", True),
        ("auditor", "DAILY_BRIEF_2024", "read:intel_report", True),

        # Contractor (EXTERNAL) accessing internal resources
        ("contractor", "BUDGET_REPORT_2024", "read:document", True),  # Unclassified, accessible
    ]

    _run_test_cases(test_cases, "Department Access Tests")


def run_hierarchy_scenario():
    """
    Scenario: Role Hierarchy and Permission Inheritance

    Tests that permissions flow correctly through the role hierarchy.
    Senior roles inherit permissions from junior roles.
    """
    console.print(Panel(
        "[bold]Scenario: Role Hierarchy & Permission Inheritance[/bold]\n\n"
        "Tests permission inheritance through role hierarchy:\n"
        "  Viewer -> Analyst -> Senior Analyst -> Administrator\n\n"
        "Each level inherits all permissions from lower levels.",
        title="Hierarchy Scenario",
        box=box.ROUNDED
    ))

    test_cases = [
        # Viewer permissions
        ("contractor", "TRAINING_MANUAL", "read:document", True),

        # Analyst permissions (inherits Viewer)
        ("analyst1", "TRAINING_MANUAL", "read:document", True),      # Inherited from Viewer
        ("analyst1", "THREAT_ASSESSMENT_Q4", "write:intel_report", True),  # Direct permission

        # Senior Analyst permissions (inherits Analyst)
        ("senior_analyst", "TRAINING_MANUAL", "read:document", True),      # Inherited from Viewer
        ("senior_analyst", "THREAT_ASSESSMENT_Q4", "write:intel_report", True),  # Inherited from Analyst
        ("senior_analyst", "DAILY_BRIEF_2024", "approve:intel_report", True),  # Direct permission

        # Admin permissions (inherits all + admin:*)
        ("admin", "TRAINING_MANUAL", "read:document", True),
        ("admin", "THREAT_ASSESSMENT_Q4", "write:intel_report", True),
        ("admin", "DAILY_BRIEF_2024", "approve:intel_report", True),
    ]

    _run_test_cases(test_cases, "Role Hierarchy Tests", strategy="rbac_only")


def run_combined_scenario():
    """
    Scenario: Combined RBAC + ABAC Enforcement

    Tests the hybrid model where both role-based and attribute-based
    checks must pass for access to be granted.
    """
    console.print(Panel(
        "[bold]Scenario: Combined RBAC + ABAC (Hybrid Model)[/bold]\n\n"
        "Tests the most secure configuration where:\n"
        "  1. User must have required RBAC permission, AND\n"
        "  2. User's attributes must satisfy ABAC policies\n\n"
        "This is the recommended approach for high-security environments.",
        title="Combined Scenario",
        box=box.ROUNDED
    ))

    test_cases = [
        # Has RBAC permission AND sufficient clearance
        ("analyst1", "THREAT_ASSESSMENT_Q4", "read:intel_report", True),

        # Has RBAC permission but INSUFFICIENT clearance
        ("analyst1", "DAILY_BRIEF_2024", "read:intel_report", False),

        # Has sufficient clearance but NO RBAC permission
        ("auditor", "DAILY_BRIEF_2024", "write:intel_report", False),

        # Has RBAC permission AND clearance AND from correct department
        ("senior_analyst", "DAILY_BRIEF_2024", "approve:intel_report", True),

        # Admin has both RBAC (admin:*) and clearance
        ("admin", "SIGINT_COLLECTION_ALPHA", "read:intel_report", True),

        # Contractor: has Viewer role but low clearance
        ("contractor", "BUDGET_REPORT_2024", "read:document", True),   # UNCLASSIFIED - OK
        ("contractor", "THREAT_ASSESSMENT_Q4", "read:intel_report", False),  # No permission
    ]

    _run_test_cases(test_cases, "Combined RBAC+ABAC Tests", strategy="rbac_and_abac")


def _run_test_cases(test_cases, title, strategy="rbac_and_abac"):
    """
    Execute a list of test cases and display results.

    Args:
        test_cases: List of (username, resource_name, permission, expected_permit) tuples
        title: Title for the results table
        strategy: Access control strategy to use
    """
    table = Table(title=title, box=box.ROUNDED)
    table.add_column("User", style="cyan")
    table.add_column("Resource")
    table.add_column("Permission")
    table.add_column("Expected")
    table.add_column("Actual")
    table.add_column("Result")
    table.add_column("Reason")

    passed = 0
    failed = 0

    with get_session() as session:
        engine = HybridAccessControl(session, strategy=strategy)

        for username, resource_name, permission, expected in test_cases:
            # Get user and resource
            user = session.query(User).filter(User.username == username).first()
            resource = session.query(Resource).filter(Resource.name == resource_name).first()

            if not user or not resource:
                table.add_row(
                    username, resource_name, permission,
                    "?", "?", "[yellow]SKIP[/yellow]", "Entity not found"
                )
                continue

            # Test access
            decision, reason = engine.check_access(
                user_id=user.id,
                permission=permission,
                resource_id=resource.id,
                client_ip="127.0.0.1"
            )

            actual = decision == AccessDecision.PERMIT
            expected_str = "[green]PERMIT[/green]" if expected else "[red]DENY[/red]"
            actual_str = "[green]PERMIT[/green]" if actual else "[red]DENY[/red]"

            if actual == expected:
                result = "[green]PASS[/green]"
                passed += 1
            else:
                result = "[red]FAIL[/red]"
                failed += 1

            table.add_row(
                username,
                resource_name[:25],
                permission,
                expected_str,
                actual_str,
                result,
                reason[:35] + "..." if len(reason) > 35 else reason
            )

    console.print(table)
    console.print(f"\nResults: [green]{passed} passed[/green], [red]{failed} failed[/red]")


def run_interactive_demo():
    """
    Run an interactive demonstration of the access control system.

    Guides the user through various access scenarios with explanations.
    """
    console.print(Panel(
        "[bold]Interactive Access Control Demo[/bold]\n\n"
        "This demo will walk you through various access control scenarios,\n"
        "explaining the decision-making process at each step.",
        title="Interactive Demo",
        box=box.DOUBLE
    ))

    scenarios = [
        {
            "title": "Basic RBAC Check",
            "description": "An analyst tries to read an intelligence report",
            "user": "analyst1",
            "permission": "read:intel_report",
            "resource": "THREAT_ASSESSMENT_Q4"
        },
        {
            "title": "Insufficient Clearance",
            "description": "Same analyst tries to access a TOP SECRET document",
            "user": "analyst1",
            "permission": "read:intel_report",
            "resource": "DAILY_BRIEF_2024"
        },
        {
            "title": "Role Hierarchy in Action",
            "description": "Senior analyst approves a report (inherited + direct permissions)",
            "user": "senior_analyst",
            "permission": "approve:intel_report",
            "resource": "DAILY_BRIEF_2024"
        },
        {
            "title": "Administrative Access",
            "description": "Administrator accesses highly classified material",
            "user": "admin",
            "permission": "read:intel_report",
            "resource": "SIGINT_COLLECTION_ALPHA"
        }
    ]

    with get_session() as session:
        engine = HybridAccessControl(session, strategy="rbac_and_abac")

        for i, scenario in enumerate(scenarios, 1):
            console.print(f"\n[bold cyan]Demo {i}/{len(scenarios)}: {scenario['title']}[/bold cyan]")
            console.print(f"[dim]{scenario['description']}[/dim]\n")

            user = session.query(User).filter(User.username == scenario['user']).first()
            resource = session.query(Resource).filter(Resource.name == scenario['resource']).first()

            if user and resource:
                # Show user info
                console.print(f"  User: [cyan]{user.username}[/cyan] ({user.full_name})")

                # Show user attributes
                from core.abac_engine import ABACEngine
                abac = ABACEngine(session)
                attrs = abac.get_user_attributes(user.id)
                console.print(f"  Clearance: [yellow]{attrs.get('clearance_level', 'N/A')}[/yellow]")
                console.print(f"  Department: {attrs.get('department', 'N/A')}")

                # Show resource info
                console.print(f"\n  Resource: [green]{resource.name}[/green]")
                res_attrs = abac.get_resource_attributes(resource.id)
                console.print(f"  Classification: [yellow]{res_attrs.get('classification', 'N/A')}[/yellow]")

                console.print(f"\n  Permission Requested: [magenta]{scenario['permission']}[/magenta]")

                # Make decision
                decision, reason = engine.check_access(
                    user_id=user.id,
                    permission=scenario['permission'],
                    resource_id=resource.id,
                    client_ip="127.0.0.1"
                )

                if decision == AccessDecision.PERMIT:
                    console.print(f"\n  [bold green]ACCESS GRANTED[/bold green]")
                else:
                    console.print(f"\n  [bold red]ACCESS DENIED[/bold red]")
                console.print(f"  Reason: {reason}")

            console.print("\n" + "-" * 50)


if __name__ == "__main__":
    run_scenarios("all")
