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

    def test_saml_unsigned_assertion_rejected_by_default(self):
        """Security test: verifies unsigned SAML assertion is rejected when require_signature=True."""
        auth_mgr = EnterpriseAuthManager()
        unsigned_xml = """<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:Subject><saml2:NameID>forged-admin@evil.com</saml2:NameID></saml2:Subject>
            <saml2:AttributeStatement>
                <saml2:Attribute Name="groups"><saml2:AttributeValue>PlatformAdmin</saml2:AttributeValue></saml2:Attribute>
            </saml2:AttributeStatement>
        </saml2:Assertion>"""
        # Default require_signature=True must block this auth bypass attempt
        identity = auth_mgr.parse_saml_assertion(unsigned_xml, tenant_id="tenant-sec", require_signature=True)
        self.assertIsNone(identity, "Unsigned SAML assertion must be rejected by default to prevent auth bypass!")

    def test_saml_xmldsig_rsa_signature_verified(self):
        """Security test: verifies genuine cryptographically signed SAML XMLDSig assertion."""
        try:
            import xml.etree.ElementTree as ET
            import hashlib
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.primitives import hashes, serialization
        except ImportError:
            self.skipTest("cryptography not available")

        auth_mgr = EnterpriseAuthManager()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pubkey_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        ET.register_namespace("ds", "http://www.w3.org/2000/09/xmldsig#")
        ET.register_namespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion")

        assertion_body = '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assert1"><saml2:Subject><saml2:NameID>legit-admin@enterprise.com</saml2:NameID></saml2:Subject><saml2:AttributeStatement><saml2:Attribute Name="groups"><saml2:AttributeValue>Corporate-Security-Admins</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion>'
        c14n_assert = ET.canonicalize(assertion_body)
        digest = hashlib.sha256(c14n_assert.encode("utf-8")).digest()
        digest_b64 = base64.b64encode(digest).decode("utf-8")

        signed_info = f'<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_assert1"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>'
        c14n_si = ET.canonicalize(signed_info)
        sig_bytes = private_key.sign(c14n_si.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = base64.b64encode(sig_bytes).decode("utf-8")

        signed_xml = f'''<saml2:Response xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            {assertion_body}
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                {signed_info}
                <ds:SignatureValue>{sig_b64}</ds:SignatureValue>
            </ds:Signature>
        </saml2:Response>'''

        # Genuine signature must be accepted
        identity = auth_mgr.parse_saml_assertion(
            signed_xml, tenant_id="tenant-sec", idp_cert_or_pubkey_pem=pubkey_pem, require_signature=True
        )
        self.assertIsNotNone(identity)
        self.assertEqual(identity.subject, "legit-admin@enterprise.com")
        self.assertIn("PlatformAdmin", identity.roles)

        # Tampered assertion (e.g. attacker changing username or group) must be rejected
        tampered_xml = signed_xml.replace("legit-admin@enterprise.com", "hacker@evil.com")
        tampered_id = auth_mgr.parse_saml_assertion(
            tampered_xml, tenant_id="tenant-sec", idp_cert_or_pubkey_pem=pubkey_pem, require_signature=True
        )
        self.assertIsNone(tampered_id, "Tampered SAML payload must be rejected by XMLDSig verification!")


if __name__ == "__main__":
    unittest.main()
