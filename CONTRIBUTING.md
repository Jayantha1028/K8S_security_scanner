# Contributing to Kubernetes Native Security Scanner

Thank you for your interest in contributing to `k8s-native-scanner`! This document provides guidelines for development, testing, code style, and security practices.

---

## 1. Development Setup

The project requires Python 3.9+ and relies exclusively on standard library modules and `PyYAML`.

```bash
# Clone the repository
git clone https://github.com/Jayantha1028/K8S_security_scanner.git
cd K8S_security_scanner

# Create and activate a clean virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable development mode
pip install --upgrade pip
pip install -e .
pip install pyflakes pyyaml
```

---

## 2. Running Tests & Benchmarks

All contributions must pass the complete unit test suite without regressions:

```bash
# Run the entire test suite (220+ tests in < 3.0s)
python3 -m unittest discover tests -v

# Run performance micro-benchmarks
python3 cli.py benchmark --markdown
```

### Self-Dogfooding Security Verification
Before submitting a pull request, run the scanner on its own production deployment manifests:
```bash
# Verify turnkey operator compliance (must score >= 95.0)
python3 cli.py scan deploy/k8s/turnkey-operator.yaml --ci-check --min-score 95.0

# Verify multi-framework regulatory certification
python3 cli.py compliance deploy/k8s/turnkey-operator.yaml --framework all
```

---

## 3. Code Standards & Static Analysis

1. **Zero Unsafe Deserialization**:
   - Always use `yaml.safe_load` or `yaml.safe_load_all`. Never use `yaml.load`.
2. **Zero Undefined Names**:
   - Run `pyflakes` to verify that all referenced imports, variables, and modules are resolved:
     ```bash
     pyflakes . | grep -v "imported but unused"
     ```
3. **SSRF Guard**:
   - Any outbound HTTP connection must be validated through `validate_safe_url()` in `container.py`.
4. **Cryptographic Standards**:
   - Always use `secrets.token_bytes()` or `secrets.token_hex()` for secret generation.
   - Always use `hmac.compare_digest()` for constant-time comparisons.
   - Enforce explicit algorithm verification in JWT handlers (`HS256`).

---

## 4. Architecture Guidelines

The project maintains an intentional **two-tier architecture**:
- **Tier 1 (Core)**: Fast, single-binary capable, zero runtime dependencies outside PyYAML.
- **Tier 2 (Extensions)**: Optional enterprise and in-cluster orchestration features.

Refer to [`ARCHITECTURE.md`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/ARCHITECTURE.md) for module mappings and data flow specifications.

---

## 5. Security Vulnerability Disclosure

If you discover a security issue or potential vulnerability in `k8s-native-scanner`, please **do not open a public issue**. Instead, report it privately to the maintainers or platform security team via GitHub Security Advisories or by emailing `security@platform.enterprise.internal`.
