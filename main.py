#!/usr/bin/env python3
"""
Access Control System - Main Entry Point
=========================================

Enterprise-grade Identity and Access Management (IAM) demonstration
featuring RBAC and ABAC access control models.

Usage:
    python main.py --help          # Show available commands
    python main.py init            # Initialize database
    python main.py demo            # Load demo data
    python main.py users list      # List users
    python main.py test access ... # Test access decisions

For defense/intelligence internship portfolio demonstration.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli.main import app

if __name__ == "__main__":
    app()
