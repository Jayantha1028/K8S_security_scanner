#!/usr/bin/env python3
"""
setup.py for k8s-native-scanner
==============================
Independent packaging configuration for k8s-native-scanner.
"""

from setuptools import setup, find_packages
from pathlib import Path

ROOT = Path(__file__).parent

setup(
    name="k8s-native-scanner",
    version="1.0.0",
    description="Pure-Python Kubernetes Security Scanner, Attack Path DAG & Cloud-Native Security Engine",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").exists() else "",
    long_description_content_type="text/markdown",
    author="Kubernetes Native Security Team",
    python_requires=">=3.9",
    packages=find_packages(),
    py_modules=[
        "scanner",
        "attack_graph",
        "bundle",
        "cli",
        "compliance",
        "container",
        "cve",
        "declarative",
        "dashboard",
        "ebpf_probe",
        "remediate",
        "sarif",
        "taxonomy",
        "webhook",
    ],
    install_requires=[
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "coverage>=7.0"],
        "tls": ["cryptography>=3.4.0"],
    },
    entry_points={
        "console_scripts": [
            "k8s-native-scan = cli:main",
            "native-sec = cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
)
