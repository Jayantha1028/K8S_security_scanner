#!/usr/bin/env python3
"""
native_scanner/__main__.py
==========================
Module entry point. Allows executing via:
    python3 -m native_K8S_scanner <args>
"""

import sys
try:
    from .cli import main
except ImportError:
    from cli import main

if __name__ == "__main__":
    main()
