# Access Control System

> Enterprise-grade Identity and Access Management (IAM) demonstration featuring Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) implementations commonly used in defense and intelligence environments.

## Overview

This project demonstrates a comprehensive access control system that combines two industry-standard access control models:

- **RBAC (Role-Based Access Control)**: Permission management through role assignments and hierarchies
- **ABAC (Attribute-Based Access Control)**: Fine-grained, policy-driven access decisions based on attributes

The system is designed to showcase understanding of IAM concepts critical to defense and intelligence operations, including security clearance enforcement, need-to-know principles, and comprehensive audit logging.

## Key Features

### Role-Based Access Control (RBAC)
- **User-Role Assignment**: Associate users with organizational roles
- **Role Hierarchy**: Senior roles inherit permissions from junior roles (e.g., Senior Analyst inherits from Analyst)
- **Permission Inheritance**: Automatic permission propagation through role hierarchies
- **Time-Based Validity**: Support for temporary role assignments with expiration

### Attribute-Based Access Control (ABAC)
- **User Attributes**: Clearance level, department, citizenship, location
- **Resource Attributes**: Classification, handling caveats, compartments
- **Policy Engine**: JSON-based policy expressions with AND/OR logic
- **Hierarchical Comparisons**: Automatic clearance level comparison (UNCLASSIFIED < CONFIDENTIAL < SECRET < TOP SECRET < TS/SCI)

### Hybrid Access Control
- Multiple combining strategies:
  - `rbac_only`: Role-based decisions only
  - `abac_only`: Attribute-based decisions only
  - `rbac_and_abac`: Both must permit (most secure)
  - `rbac_or_abac`: Either can permit
  - `abac_override`: ABAC decisions take precedence

### Audit Logging
- Complete audit trail of all access decisions
- Query capabilities for security investigations
- Export functionality for SIEM integration (JSON/CSV)
- Statistical analysis for security monitoring

## RBAC vs ABAC Comparison

| Aspect | RBAC | ABAC |
|--------|------|------|
| **Access Based On** | User's assigned roles | User/resource/environment attributes |
| **Granularity** | Coarse (role-level) | Fine-grained (attribute-level) |
| **Flexibility** | Requires role creation for new access patterns | Policies adapt to attribute changes |
| **Scalability** | Role explosion in complex environments | Scales well with policy-based approach |
| **Administration** | Simple role assignments | Complex policy management |
| **Audit** | Who has what role | Why access was granted/denied |
| **Best For** | Stable organizational structures | Dynamic, context-aware decisions |

### When to Use Each

**RBAC is ideal for:**
- Well-defined organizational hierarchies
- Relatively static permission requirements
- Simplified administration needs

**ABAC is ideal for:**
- Fine-grained access control requirements
- Dynamic environments with changing contexts
- Cross-organizational resource sharing
- Regulatory compliance (need-to-know enforcement)

**Hybrid (Recommended for Defense/Intel):**
- Use RBAC for broad permission categories
- Use ABAC for fine-grained, context-aware decisions
- Achieves both administrative simplicity and security depth

## Real-World Use Cases

### 1. Intelligence Community Access Control
```
User: Intelligence Analyst
Clearance: SECRET
Department: ANALYSIS
Accessing: Threat Assessment (SECRET, ANALYSIS dept)
Result: PERMIT - Clearance sufficient, same department
```

### 2. Cross-Department Access
```
User: Security Auditor
Clearance: TOP SECRET/SCI
Department: OVERSIGHT
Accessing: SIGINT Report (TOP SECRET/SCI, SIGINT dept)
Result: PERMIT - Oversight role has cross-department access
```

### 3. Insufficient Clearance
```
User: External Contractor
Clearance: CONFIDENTIAL
Accessing: Daily Brief (TOP SECRET)
Result: DENY - Clearance level insufficient
```

### 4. Location-Based Restriction
```
User: Field Analyst
Location: FIELD_OFFICE
Accessing: Classified Document (requires HQ access)
Result: DENY - Must access from HQ or SCIF
```

## Installation

### Prerequisites
- Python 3.9+
- pip (Python package manager)

### Setup

```bash
# Clone or navigate to the project directory
cd 09-access-control

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database and load demo data
python main.py init
python main.py demo
```

## Usage

### Quick Start

```bash
# View all commands
python main.py --help

# List all users
python main.py users list

# View user details with roles and attributes
python main.py users show analyst1

# List roles and permissions
python main.py roles list

# Test an access decision
python main.py test access --user analyst1 --permission read:intel_report --resource THREAT_ASSESSMENT_Q4

# Run test scenarios
python main.py test scenario all
```

### Managing Users

```bash
# Create a new user
python main.py users create --username newuser --full-name "New User" --email "new@agency.gov"

# Set user attributes for ABAC
python main.py users set-attr analyst1 --attr clearance_level --value TOP_SECRET
python main.py users set-attr analyst1 --attr department --value SIGINT
```

### Managing Roles

```bash
# Create a new role
python main.py roles create --name "Special Access" --description "Special program access"

# Assign role to user
python main.py roles assign --user analyst1 --role "Special Access"

# Create role hierarchy
python main.py roles add-parent --role "Senior Analyst" --parent "Analyst"

# View role hierarchy
python main.py roles hierarchy "Senior Analyst"
```

### Managing Resources

```bash
# Create a resource
python main.py resources create --name "PROJECT_ALPHA" --type intel_report

# Set resource attributes
python main.py resources set-attr PROJECT_ALPHA --attr classification --value TOP_SECRET
python main.py resources set-attr PROJECT_ALPHA --attr compartment --value SI

# View resource details
python main.py resources show PROJECT_ALPHA
```

### Testing Access Decisions

```bash
# Test with default strategy (RBAC + ABAC)
python main.py test access --user analyst1 --permission read:intel_report --resource DAILY_BRIEF_2024

# Test with specific strategy
python main.py test access --user analyst1 --permission read:intel_report --resource DAILY_BRIEF_2024 --strategy rbac_only

# Run all test scenarios
python main.py test scenario all

# Run specific scenario
python main.py test scenario clearance
```

### Viewing Audit Logs

```bash
# View recent audit logs
python main.py audit logs --limit 20

# Filter by user
python main.py audit logs --user analyst1

# Filter by decision
python main.py audit logs --decision DENY

# View access statistics
python main.py audit stats --hours 24

# View recent denials (security monitoring)
python main.py audit denials --hours 24

# Export logs for SIEM
python main.py audit export --output audit.json --format json
```

## Architecture

```
09-access-control/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── access_control.db       # SQLite database (created on init)
│
├── models/                 # Database models
│   ├── __init__.py
│   ├── database.py         # SQLAlchemy configuration
│   └── entities.py         # Entity definitions (User, Role, etc.)
│
├── core/                   # Access control engines
│   ├── __init__.py
│   ├── rbac_engine.py      # RBAC implementation
│   ├── abac_engine.py      # ABAC implementation
│   ├── hybrid_engine.py    # Combined RBAC+ABAC
│   └── audit.py            # Audit logging service
│
├── cli/                    # Command-line interface
│   ├── __init__.py
│   └── main.py             # Typer CLI application
│
└── scenarios/              # Demo data and test scenarios
    ├── __init__.py
    ├── demo_data.py        # Sample data loader
    └── test_scenarios.py   # Test scenario runner
```

## Technologies Used

| Technology | Purpose |
|------------|---------|
| **Python 3.9+** | Core programming language |
| **SQLAlchemy 2.0** | ORM for database operations |
| **SQLite** | Lightweight, portable database |
| **Typer** | CLI framework with type hints |
| **Rich** | Terminal formatting and tables |
| **bcrypt** | Password hashing (production-ready) |

## Security Considerations

This is a demonstration project. For production deployment, consider:

1. **Database**: Replace SQLite with PostgreSQL with encrypted connections
2. **Authentication**: Integrate with enterprise IdP (LDAP, SAML, OIDC)
3. **Secrets Management**: Use HashiCorp Vault or AWS Secrets Manager
4. **Audit Logs**: Stream to immutable storage (S3 with Object Lock)
5. **Network Security**: TLS everywhere, network segmentation
6. **Session Management**: Implement proper session tokens with expiration

## Compliance Alignment

This system demonstrates concepts from:

- **NIST SP 800-53**: Access Control (AC) family
- **NIST SP 800-162**: Guide to ABAC
- **NIST INCITS 359-2004**: RBAC Standard
- **ICD 503**: Intelligence Community security
- **FISMA**: Federal Information Security requirements

## Sample ABAC Policy

```json
{
  "name": "clearance_enforcement",
  "effect": "PERMIT",
  "priority": 100,
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
}
```

This policy permits access only when the user's clearance level is greater than or equal to the resource's classification level.

## Future Enhancements

- [ ] Web-based administration interface
- [ ] REST API for external integration
- [ ] OAuth 2.0 / OIDC authentication
- [ ] Real-time policy updates
- [ ] Machine learning for anomaly detection
- [ ] Multi-tenant support
- [ ] Policy simulation and impact analysis

## License

This project is created for educational and portfolio demonstration purposes.

---

*Developed as part of a cybersecurity portfolio demonstrating Identity and Access Management expertise for defense/intelligence sector opportunities.*
