"""
Access Control System - Interactive CLI
========================================

Professional command-line interface for managing and testing
access control policies. Demonstrates practical IAM operations.

Features:
- User, role, and permission management
- ABAC policy configuration
- Real-time access decision testing
- Audit log analysis

Built with Typer and Rich for a polished user experience.
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box
from typing import Optional
from datetime import datetime
import json

# Initialize CLI app and console
app = typer.Typer(
    name="access-control",
    help="Enterprise Access Control System - RBAC/ABAC Demo",
    add_completion=False
)

console = Console()

# Sub-commands
users_app = typer.Typer(help="Manage users")
roles_app = typer.Typer(help="Manage roles and permissions")
resources_app = typer.Typer(help="Manage resources")
policies_app = typer.Typer(help="Manage ABAC policies")
audit_app = typer.Typer(help="View audit logs")
test_app = typer.Typer(help="Test access decisions")

app.add_typer(users_app, name="users")
app.add_typer(roles_app, name="roles")
app.add_typer(resources_app, name="resources")
app.add_typer(policies_app, name="policies")
app.add_typer(audit_app, name="audit")
app.add_typer(test_app, name="test")


def get_session():
    """Get a database session."""
    from models.database import get_session
    return get_session()


def print_banner():
    """Display application banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║         ACCESS CONTROL SYSTEM DEMONSTRATION               ║
    ║                                                           ║
    ║   Role-Based (RBAC) + Attribute-Based (ABAC) Controls    ║
    ║           Enterprise Security Implementation              ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, style="bold blue"))


# ============================================================================
# Database Commands
# ============================================================================

@app.command()
def init():
    """Initialize the database with schema."""
    from models.database import init_db
    init_db()
    console.print("[green]Database initialized successfully![/green]")


@app.command()
def reset():
    """Reset database (WARNING: destroys all data)."""
    if typer.confirm("This will delete all data. Are you sure?"):
        from models.database import reset_db
        reset_db()
        console.print("[yellow]Database reset complete.[/yellow]")


@app.command()
def demo():
    """Load demo data for testing."""
    from scenarios import load_demo_data
    load_demo_data()
    console.print("[green]Demo data loaded successfully![/green]")
    console.print("\nTry these commands to explore:")
    console.print("  [cyan]python main.py users list[/cyan]")
    console.print("  [cyan]python main.py roles list[/cyan]")
    console.print("  [cyan]python main.py test access --user analyst1 --permission read:intel_report[/cyan]")


# ============================================================================
# User Commands
# ============================================================================

@users_app.command("list")
def list_users():
    """List all users in the system."""
    from models.entities import User

    with get_session() as session:
        users = session.query(User).all()

        table = Table(title="System Users", box=box.ROUNDED)
        table.add_column("ID", style="cyan", justify="right")
        table.add_column("Username", style="green")
        table.add_column("Full Name")
        table.add_column("Email")
        table.add_column("Status", justify="center")
        table.add_column("Created")

        for user in users:
            status = "[green]Active[/green]" if user.is_active else "[red]Inactive[/red]"
            table.add_row(
                str(user.id),
                user.username,
                user.full_name or "-",
                user.email or "-",
                status,
                user.created_at.strftime("%Y-%m-%d") if user.created_at else "-"
            )

        console.print(table)


@users_app.command("create")
def create_user(
    username: str = typer.Option(..., help="Username"),
    full_name: str = typer.Option(None, help="Full name"),
    email: str = typer.Option(None, help="Email address")
):
    """Create a new user."""
    from models.entities import User

    with get_session() as session:
        user = User(
            username=username,
            full_name=full_name,
            email=email
        )
        session.add(user)
        session.flush()
        console.print(f"[green]Created user: {username} (ID: {user.id})[/green]")


@users_app.command("show")
def show_user(username: str = typer.Argument(..., help="Username to show")):
    """Show detailed user information including roles and attributes."""
    from models.entities import User
    from core.hybrid_engine import HybridAccessControl

    with get_session() as session:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            console.print(f"[red]User '{username}' not found[/red]")
            return

        engine = HybridAccessControl(session)
        summary = engine.get_user_permissions_summary(user.id)

        # User info panel
        user_info = f"""
[bold]Username:[/bold] {summary['user']['username']}
[bold]Full Name:[/bold] {summary['user']['full_name'] or 'N/A'}
[bold]Status:[/bold] {'[green]Active[/green]' if summary['user']['is_active'] else '[red]Inactive[/red]'}
"""
        console.print(Panel(user_info, title="User Information", box=box.ROUNDED))

        # Roles
        if summary['rbac']['roles']:
            roles_tree = Tree("[bold]Assigned Roles[/bold]")
            for role in summary['rbac']['roles']:
                roles_tree.add(f"[cyan]{role['name']}[/cyan] (ID: {role['id']})")
            console.print(roles_tree)
        else:
            console.print("[yellow]No roles assigned[/yellow]")

        # Permissions
        if summary['rbac']['effective_permissions']:
            console.print("\n[bold]Effective Permissions:[/bold]")
            for perm in sorted(summary['rbac']['effective_permissions']):
                console.print(f"  [green]✓[/green] {perm}")
        else:
            console.print("[yellow]No permissions[/yellow]")

        # Attributes
        if summary['abac']['attributes']:
            console.print("\n[bold]User Attributes (ABAC):[/bold]")
            attrs_table = Table(box=box.SIMPLE)
            attrs_table.add_column("Attribute", style="cyan")
            attrs_table.add_column("Value", style="green")
            for name, value in summary['abac']['attributes'].items():
                attrs_table.add_row(name, value)
            console.print(attrs_table)


@users_app.command("set-attr")
def set_user_attribute(
    username: str = typer.Argument(..., help="Username"),
    attribute: str = typer.Option(..., "--attr", "-a", help="Attribute name"),
    value: str = typer.Option(..., "--value", "-v", help="Attribute value")
):
    """Set a user attribute for ABAC policies."""
    from models.entities import User
    from core.abac_engine import ABACEngine

    with get_session() as session:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            console.print(f"[red]User '{username}' not found[/red]")
            return

        engine = ABACEngine(session)
        engine.set_user_attribute(user.id, attribute, value)
        console.print(f"[green]Set {username}.{attribute} = {value}[/green]")


# ============================================================================
# Role Commands
# ============================================================================

@roles_app.command("list")
def list_roles():
    """List all roles and their permissions."""
    from models.entities import Role, RolePermission, Permission

    with get_session() as session:
        roles = session.query(Role).all()

        for role in roles:
            role_perms = session.query(RolePermission).filter(
                RolePermission.role_id == role.id
            ).all()

            perm_names = []
            for rp in role_perms:
                perm = session.query(Permission).filter(Permission.id == rp.permission_id).first()
                if perm:
                    perm_names.append(perm.name)

            tree = Tree(f"[bold cyan]{role.name}[/bold cyan] (ID: {role.id})")
            if role.description:
                tree.add(f"[dim]{role.description}[/dim]")
            if perm_names:
                perms_branch = tree.add("[green]Permissions[/green]")
                for perm in perm_names:
                    perms_branch.add(perm)
            else:
                tree.add("[yellow]No permissions[/yellow]")

            console.print(tree)
            console.print()


@roles_app.command("create")
def create_role(
    name: str = typer.Option(..., help="Role name"),
    description: str = typer.Option(None, help="Role description")
):
    """Create a new role."""
    from models.entities import Role

    with get_session() as session:
        role = Role(name=name, description=description)
        session.add(role)
        session.flush()
        console.print(f"[green]Created role: {name} (ID: {role.id})[/green]")


@roles_app.command("assign")
def assign_role(
    username: str = typer.Option(..., "--user", "-u", help="Username"),
    role_name: str = typer.Option(..., "--role", "-r", help="Role name")
):
    """Assign a role to a user."""
    from models.entities import User, Role
    from core.rbac_engine import RBACEngine

    with get_session() as session:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            console.print(f"[red]User '{username}' not found[/red]")
            return

        role = session.query(Role).filter(Role.name == role_name).first()
        if not role:
            console.print(f"[red]Role '{role_name}' not found[/red]")
            return

        engine = RBACEngine(session)
        engine.assign_role(user.id, role.id)
        console.print(f"[green]Assigned role '{role_name}' to user '{username}'[/green]")


@roles_app.command("hierarchy")
def show_hierarchy(role_name: str = typer.Argument(..., help="Role name")):
    """Show role hierarchy (parents and children)."""
    from models.entities import Role
    from core.rbac_engine import RBACEngine

    with get_session() as session:
        role = session.query(Role).filter(Role.name == role_name).first()
        if not role:
            console.print(f"[red]Role '{role_name}' not found[/red]")
            return

        engine = RBACEngine(session)
        hierarchy = engine.get_role_hierarchy(role.id)

        tree = Tree(f"[bold cyan]{role_name}[/bold cyan] Hierarchy")

        if hierarchy['parents']:
            parents = tree.add("[yellow]Inherits From (Parents)[/yellow]")
            for parent in hierarchy['parents']:
                parents.add(f"[green]{parent['name']}[/green]")
        else:
            tree.add("[dim]No parent roles[/dim]")

        if hierarchy['children']:
            children = tree.add("[yellow]Inherited By (Children)[/yellow]")
            for child in hierarchy['children']:
                children.add(f"[blue]{child['name']}[/blue]")
        else:
            tree.add("[dim]No child roles[/dim]")

        console.print(tree)


@roles_app.command("add-parent")
def add_role_parent(
    role_name: str = typer.Option(..., "--role", "-r", help="Child role"),
    parent_name: str = typer.Option(..., "--parent", "-p", help="Parent role to inherit from")
):
    """Create role hierarchy (child inherits from parent)."""
    from models.entities import Role
    from core.rbac_engine import RBACEngine

    with get_session() as session:
        role = session.query(Role).filter(Role.name == role_name).first()
        parent = session.query(Role).filter(Role.name == parent_name).first()

        if not role:
            console.print(f"[red]Role '{role_name}' not found[/red]")
            return
        if not parent:
            console.print(f"[red]Role '{parent_name}' not found[/red]")
            return

        engine = RBACEngine(session)
        engine.create_role_hierarchy(parent.id, role.id)
        console.print(f"[green]{role_name} now inherits from {parent_name}[/green]")


# ============================================================================
# Resource Commands
# ============================================================================

@resources_app.command("list")
def list_resources():
    """List all resources."""
    from models.entities import Resource

    with get_session() as session:
        resources = session.query(Resource).all()

        table = Table(title="Protected Resources", box=box.ROUNDED)
        table.add_column("ID", style="cyan", justify="right")
        table.add_column("Name", style="green")
        table.add_column("Type")
        table.add_column("Description")

        for res in resources:
            table.add_row(
                str(res.id),
                res.name,
                res.resource_type,
                (res.description or "-")[:50]
            )

        console.print(table)


@resources_app.command("create")
def create_resource(
    name: str = typer.Option(..., help="Resource name"),
    resource_type: str = typer.Option(..., "--type", "-t", help="Resource type"),
    description: str = typer.Option(None, help="Description")
):
    """Create a new resource."""
    from models.entities import Resource

    with get_session() as session:
        resource = Resource(
            name=name,
            resource_type=resource_type,
            description=description
        )
        session.add(resource)
        session.flush()
        console.print(f"[green]Created resource: {name} (ID: {resource.id})[/green]")


@resources_app.command("set-attr")
def set_resource_attribute(
    resource_name: str = typer.Argument(..., help="Resource name"),
    attribute: str = typer.Option(..., "--attr", "-a", help="Attribute name"),
    value: str = typer.Option(..., "--value", "-v", help="Attribute value")
):
    """Set a resource attribute for ABAC policies."""
    from models.entities import Resource
    from core.abac_engine import ABACEngine

    with get_session() as session:
        resource = session.query(Resource).filter(Resource.name == resource_name).first()
        if not resource:
            console.print(f"[red]Resource '{resource_name}' not found[/red]")
            return

        engine = ABACEngine(session)
        engine.set_resource_attribute(resource.id, attribute, value)
        console.print(f"[green]Set {resource_name}.{attribute} = {value}[/green]")


@resources_app.command("show")
def show_resource(name: str = typer.Argument(..., help="Resource name")):
    """Show resource details including attributes."""
    from models.entities import Resource
    from core.abac_engine import ABACEngine

    with get_session() as session:
        resource = session.query(Resource).filter(Resource.name == name).first()
        if not resource:
            console.print(f"[red]Resource '{name}' not found[/red]")
            return

        engine = ABACEngine(session)
        attrs = engine.get_resource_attributes(resource.id)

        info = f"""
[bold]Name:[/bold] {resource.name}
[bold]Type:[/bold] {resource.resource_type}
[bold]Description:[/bold] {resource.description or 'N/A'}
"""
        console.print(Panel(info, title="Resource Information", box=box.ROUNDED))

        if attrs:
            console.print("[bold]Resource Attributes:[/bold]")
            table = Table(box=box.SIMPLE)
            table.add_column("Attribute", style="cyan")
            table.add_column("Value", style="green")
            for attr_name, attr_value in attrs.items():
                table.add_row(attr_name, attr_value)
            console.print(table)


# ============================================================================
# Policy Commands
# ============================================================================

@policies_app.command("list")
def list_policies():
    """List all ABAC policies."""
    from models.entities import ABACPolicy

    with get_session() as session:
        policies = session.query(ABACPolicy).order_by(ABACPolicy.priority.desc()).all()

        table = Table(title="ABAC Policies", box=box.ROUNDED)
        table.add_column("ID", style="cyan", justify="right")
        table.add_column("Name", style="green")
        table.add_column("Effect")
        table.add_column("Priority", justify="right")
        table.add_column("Active", justify="center")
        table.add_column("Description")

        for policy in policies:
            effect_style = "green" if policy.effect == "PERMIT" else "red"
            active = "[green]Yes[/green]" if policy.is_active else "[red]No[/red]"
            table.add_row(
                str(policy.id),
                policy.name,
                f"[{effect_style}]{policy.effect}[/{effect_style}]",
                str(policy.priority),
                active,
                (policy.description or "-")[:40]
            )

        console.print(table)


@policies_app.command("show")
def show_policy(name: str = typer.Argument(..., help="Policy name")):
    """Show detailed policy information."""
    from models.entities import ABACPolicy

    with get_session() as session:
        policy = session.query(ABACPolicy).filter(ABACPolicy.name == name).first()
        if not policy:
            console.print(f"[red]Policy '{name}' not found[/red]")
            return

        expression = json.loads(policy.policy_expression)

        console.print(Panel(
            f"""
[bold]Name:[/bold] {policy.name}
[bold]Effect:[/bold] {policy.effect}
[bold]Priority:[/bold] {policy.priority}
[bold]Active:[/bold] {'Yes' if policy.is_active else 'No'}
[bold]Description:[/bold] {policy.description or 'N/A'}
""",
            title="Policy Details",
            box=box.ROUNDED
        ))

        console.print("\n[bold]Policy Expression:[/bold]")
        console.print_json(json.dumps(expression, indent=2))


# ============================================================================
# Test Commands
# ============================================================================

@test_app.command("access")
def test_access(
    username: str = typer.Option(..., "--user", "-u", help="Username"),
    permission: str = typer.Option(..., "--permission", "-p", help="Permission to test"),
    resource: str = typer.Option(None, "--resource", "-r", help="Resource name (for ABAC)"),
    strategy: str = typer.Option("rbac_and_abac", "--strategy", "-s",
                                  help="Strategy: rbac_only, abac_only, rbac_and_abac, rbac_or_abac")
):
    """Test an access decision."""
    from models.entities import User, Resource as ResourceModel
    from core.hybrid_engine import HybridAccessControl

    with get_session() as session:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            console.print(f"[red]User '{username}' not found[/red]")
            return

        resource_id = None
        if resource:
            res = session.query(ResourceModel).filter(ResourceModel.name == resource).first()
            if not res:
                console.print(f"[red]Resource '{resource}' not found[/red]")
                return
            resource_id = res.id

        engine = HybridAccessControl(session, strategy=strategy)
        decision, reason = engine.check_access(
            user_id=user.id,
            permission=permission,
            resource_id=resource_id,
            client_ip="127.0.0.1"
        )

        # Display result
        if decision.value == "PERMIT":
            console.print(Panel(
                f"[bold green]ACCESS GRANTED[/bold green]\n\n"
                f"User: {username}\n"
                f"Permission: {permission}\n"
                f"Resource: {resource or 'N/A'}\n"
                f"Strategy: {strategy}\n\n"
                f"Reason: {reason}",
                title="Access Decision",
                box=box.DOUBLE
            ))
        else:
            console.print(Panel(
                f"[bold red]ACCESS DENIED[/bold red]\n\n"
                f"User: {username}\n"
                f"Permission: {permission}\n"
                f"Resource: {resource or 'N/A'}\n"
                f"Strategy: {strategy}\n\n"
                f"Reason: {reason}",
                title="Access Decision",
                box=box.DOUBLE
            ))


@test_app.command("scenario")
def run_scenario(
    scenario_name: str = typer.Argument("all", help="Scenario to run: clearance, department, time, all")
):
    """Run predefined test scenarios."""
    from scenarios import run_scenarios
    run_scenarios(scenario_name)


# ============================================================================
# Audit Commands
# ============================================================================

@audit_app.command("logs")
def view_logs(
    limit: int = typer.Option(20, "--limit", "-l", help="Number of logs to show"),
    user: str = typer.Option(None, "--user", "-u", help="Filter by username"),
    decision: str = typer.Option(None, "--decision", "-d", help="Filter by decision (PERMIT/DENY)")
):
    """View audit logs."""
    from models.entities import AuditLog, User, AccessDecision as AD
    from core.audit import AuditLogger

    with get_session() as session:
        logger = AuditLogger(session)

        user_id = None
        if user:
            u = session.query(User).filter(User.username == user).first()
            if u:
                user_id = u.id

        dec = None
        if decision:
            dec = AD.PERMIT if decision.upper() == "PERMIT" else AD.DENY

        logs = logger.get_logs(user_id=user_id, decision=dec, limit=limit)

        table = Table(title="Audit Logs", box=box.ROUNDED)
        table.add_column("Time", style="dim")
        table.add_column("User", style="cyan")
        table.add_column("Action")
        table.add_column("Resource")
        table.add_column("Decision")
        table.add_column("Reason")

        for log in logs:
            dec_style = "green" if log.decision == AD.PERMIT else "red"
            table.add_row(
                log.timestamp.strftime("%H:%M:%S") if log.timestamp else "-",
                log.username or "-",
                log.action or "-",
                log.resource_name or "-",
                f"[{dec_style}]{log.decision.value}[/{dec_style}]",
                (log.decision_reason or "-")[:30]
            )

        console.print(table)


@audit_app.command("stats")
def audit_stats(hours: int = typer.Option(24, help="Analysis period in hours")):
    """Show access control statistics."""
    from core.audit import AuditLogger

    with get_session() as session:
        logger = AuditLogger(session)
        stats = logger.get_statistics(hours=hours)

        console.print(Panel(
            f"""
[bold]Period:[/bold] Last {stats['period_hours']} hours

[bold]Total Decisions:[/bold] {stats['total_decisions']}
[bold]Permits:[/bold] [green]{stats['permits']}[/green] ({stats['permit_rate']:.1%})
[bold]Denials:[/bold] [red]{stats['denials']}[/red] ({stats['denial_rate']:.1%})

[bold]Unique Users:[/bold] {stats['unique_users']}
[bold]Unique Resources:[/bold] {stats['unique_resources']}

[bold]By Access Method:[/bold]
  RBAC: {stats['by_access_method'].get('RBAC', 0)}
  ABAC: {stats['by_access_method'].get('ABAC', 0)}
  Hybrid: {stats['by_access_method'].get('HYBRID', 0)}
""",
            title="Access Control Statistics",
            box=box.ROUNDED
        ))


@audit_app.command("denials")
def recent_denials(hours: int = typer.Option(24, help="Look back period")):
    """Show recent access denials (security monitoring)."""
    from core.audit import AuditLogger
    from models.entities import AccessDecision as AD

    with get_session() as session:
        logger = AuditLogger(session)
        denials = logger.get_recent_denials(hours=hours)

        if not denials:
            console.print("[green]No access denials in the specified period.[/green]")
            return

        table = Table(title=f"Access Denials (Last {hours}h)", box=box.ROUNDED)
        table.add_column("Time", style="dim")
        table.add_column("User", style="cyan")
        table.add_column("Action", style="yellow")
        table.add_column("Resource")
        table.add_column("Reason")

        for log in denials:
            table.add_row(
                log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else "-",
                log.username or "-",
                log.action or "-",
                log.resource_name or "-",
                (log.decision_reason or "-")[:40]
            )

        console.print(table)


@audit_app.command("export")
def export_logs(
    output: str = typer.Option("audit_export.json", "--output", "-o", help="Output file"),
    format: str = typer.Option("json", "--format", "-f", help="Format: json or csv")
):
    """Export audit logs for SIEM integration."""
    from core.audit import AuditLogger

    with get_session() as session:
        logger = AuditLogger(session)
        data = logger.export_logs(format=format)

        with open(output, 'w') as f:
            f.write(data)

        console.print(f"[green]Exported audit logs to {output}[/green]")


# ============================================================================
# Main Entry Point
# ============================================================================

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    Access Control System - Enterprise IAM Demonstration

    This system demonstrates Role-Based (RBAC) and Attribute-Based (ABAC)
    access control patterns used in defense and intelligence environments.
    """
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("\nUse [cyan]--help[/cyan] to see available commands.\n")
        console.print("Quick Start:")
        console.print("  1. [cyan]python main.py init[/cyan]     - Initialize database")
        console.print("  2. [cyan]python main.py demo[/cyan]     - Load demo data")
        console.print("  3. [cyan]python main.py users list[/cyan] - View users")
        console.print("  4. [cyan]python main.py test access --user analyst1 --permission read:intel_report[/cyan]")
        console.print()


if __name__ == "__main__":
    app()
