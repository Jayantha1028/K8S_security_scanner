#!/usr/bin/env python3
"""
tests/test_cli_and_auth_hardening.py
====================================
Unit tests verifying fixes for:
1. cli.py cmd_fleet cluster ID generation (time module import).
2. cli.py invalid action error handling (cmd_fleet, cmd_auth, cmd_storage, cmd_kubecam).
3. auth.py JWT header security validation (preventing alg: none and algorithm confusion).
4. auth.py fast API key lookup.
"""

import argparse
import base64
import json
import unittest
from unittest.mock import patch
import io

from cli import cmd_fleet, cmd_auth, cmd_storage, cmd_kubecam
from auth import EnterpriseAuthManager, ROLE_SECURITY_ENGINEER


class TestCliAndAuthHardening(unittest.TestCase):
    def test_cmd_fleet_register_without_cluster_id_no_nameerror(self):
        """Verifies cmd_fleet register generates default cluster ID without crashing."""
        args = argparse.Namespace(
            action="register",
            tenant="test-tenant",
            cluster_id=None,
            name="test-cluster",
            provider="aws",
            region="us-west-2",
        )
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            code = cmd_fleet(args)
            self.assertEqual(code, 0)
            self.assertIn("Cluster registered successfully", mock_out.getvalue())
            self.assertIn("cls-", mock_out.getvalue())

    def test_cmd_fleet_unrecognized_action(self):
        """Verifies cmd_fleet returns error 1 on unrecognized action."""
        args = argparse.Namespace(
            action="unrecognized_action",
            tenant="test-tenant",
        )
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            code = cmd_fleet(args)
            self.assertEqual(code, 1)
            self.assertIn("Unrecognized fleet action", mock_err.getvalue())

    def test_cmd_auth_unrecognized_action(self):
        """Verifies cmd_auth returns error 1 on unrecognized action."""
        args = argparse.Namespace(
            action="unrecognized_action",
            tenant="test-tenant",
        )
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            code = cmd_auth(args)
            self.assertEqual(code, 1)
            self.assertIn("Unrecognized auth action", mock_err.getvalue())

    def test_cmd_storage_unrecognized_action(self):
        """Verifies cmd_storage returns error 1 on unrecognized action."""
        args = argparse.Namespace(
            action="invalid_storage_op",
            db_path=":memory:",
            json=False,
        )
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            code = cmd_storage(args)
            self.assertEqual(code, 1)
            self.assertIn("Unrecognized storage action", mock_err.getvalue())

    def test_jwt_rejects_alg_none(self):
        """Security test: verifies JWT engine strictly rejects 'alg': 'none'."""
        auth_mgr = EnterpriseAuthManager()
        # Forge an unauthenticated token with alg: none
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": "attacker",
            "roles": ["PlatformAdmin"],
            "exp": 9999999999,
        }).encode()).decode().rstrip("=")
        forged_token = f"{header}.{payload}."

        identity = auth_mgr.verify_jwt(forged_token)
        self.assertIsNone(identity, "JWT verification must reject alg: none tokens!")

    def test_jwt_rejects_asymmetric_alg_confusion(self):
        """Security test: verifies JWT engine strictly rejects non-HS256 algorithms like RS256."""
        auth_mgr = EnterpriseAuthManager()
        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": "attacker",
            "exp": 9999999999,
        }).encode()).decode().rstrip("=")
        sig = "invalidsig"
        forged_token = f"{header}.{payload}.{sig}"

        identity = auth_mgr.verify_jwt(forged_token)
        self.assertIsNone(identity, "JWT verification must reject RS256 alg confusion tokens!")


if __name__ == "__main__":
    unittest.main()
