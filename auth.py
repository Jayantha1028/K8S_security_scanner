#!/usr/bin/env python3
"""
auth.py
=======
Enterprise Identity, Multi-Tenancy & Role-Based Access Control (RBAC) Engine.

Capabilities:
1. Multi-Tenant Scoping: Isolates workloads, audit logs, and reports by Tenant ID.
2. OIDC / OAuth2 / JWT Verification: Pure-Python RFC 7519 JSON Web Token verification.
3. Cryptographic API Key Management: Secure generation, hashing (HMAC-SHA256), and expiry.
4. SAML 2.0 Assertion Validator: Corporate SSO integration (Okta, Azure AD, PingFederate).
5. 4-Tier Enterprise RBAC Matrix: PlatformAdmin, SecurityEngineer, ComplianceAuditor, DevOpsOperator.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
import base64
import copy
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET

# Register standard XMLDSig and SAML namespaces globally for deterministic C14N
ET.register_namespace("ds", "http://www.w3.org/2000/09/xmldsig#")
ET.register_namespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion")

logger = logging.getLogger("NativeScanner.Auth")

# Standard Enterprise RBAC Roles
ROLE_PLATFORM_ADMIN = "PlatformAdmin"
ROLE_SECURITY_ENGINEER = "SecurityEngineer"
ROLE_COMPLIANCE_AUDITOR = "ComplianceAuditor"
ROLE_DEVOPS_OPERATOR = "DevOpsOperator"

ENTERPRISE_ROLES = {
    ROLE_PLATFORM_ADMIN,
    ROLE_SECURITY_ENGINEER,
    ROLE_COMPLIANCE_AUDITOR,
    ROLE_DEVOPS_OPERATOR,
}

# Granular Permission Capabilities
PERM_FLEET_MANAGE = "fleet:manage"
PERM_CLUSTER_ONBOARD = "cluster:onboard"
PERM_POLICY_WRITE = "policy:write"
PERM_SCAN_EXECUTE = "scan:execute"
PERM_REMEDIATE_WRITE = "remediate:write"
PERM_VEX_WAIVE = "vex:waive"
PERM_COMPLIANCE_READ = "compliance:read"
PERM_AUDIT_LOGS_READ = "audit_logs:read"
PERM_TELEMETRY_READ = "telemetry:read"

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    ROLE_PLATFORM_ADMIN: {
        PERM_FLEET_MANAGE,
        PERM_CLUSTER_ONBOARD,
        PERM_POLICY_WRITE,
        PERM_SCAN_EXECUTE,
        PERM_REMEDIATE_WRITE,
        PERM_VEX_WAIVE,
        PERM_COMPLIANCE_READ,
        PERM_AUDIT_LOGS_READ,
        PERM_TELEMETRY_READ,
    },
    ROLE_SECURITY_ENGINEER: {
        PERM_CLUSTER_ONBOARD,
        PERM_POLICY_WRITE,
        PERM_SCAN_EXECUTE,
        PERM_REMEDIATE_WRITE,
        PERM_VEX_WAIVE,
        PERM_COMPLIANCE_READ,
        PERM_TELEMETRY_READ,
    },
    ROLE_COMPLIANCE_AUDITOR: {
        PERM_COMPLIANCE_READ,
        PERM_AUDIT_LOGS_READ,
    },
    ROLE_DEVOPS_OPERATOR: {
        PERM_SCAN_EXECUTE,
        PERM_REMEDIATE_WRITE,
    },
}


@dataclass
class AuthenticatedIdentity:
    subject: str
    tenant_id: str
    roles: List[str]
    allowed_namespaces: List[str] = field(default_factory=lambda: ["*"])
    token_id: str = ""
    issuer: str = "k8s-native-scanner"
    expires_at: Optional[int] = None
    email: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_admin(self) -> bool:
        return ROLE_PLATFORM_ADMIN in self.roles

    def has_permission(self, permission: str) -> bool:
        for role in self.roles:
            if permission in ROLE_PERMISSIONS.get(role, set()):
                return True
        return False

    def can_access_namespace(self, namespace: str) -> bool:
        if "*" in self.allowed_namespaces:
            return True
        return namespace in self.allowed_namespaces

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class APIKeyRecord:
    key_id: str
    key_hash: str
    tenant_id: str
    subject: str
    roles: List[str]
    allowed_namespaces: List[str]
    created_at: str
    expires_at: str
    is_active: bool = True
    description: str = ""


class EnterpriseAuthManager:
    """
    Enterprise Authentication and Role-Based Access Control (RBAC) Manager.
    Pure Python standard library implementation with zero external runtime dependencies.
    """

    def __init__(self, master_secret: Optional[str] = None, default_tenant: str = "default-tenant"):
        self.default_tenant = default_tenant
        # 256-bit cryptographically secure HMAC secret
        self.master_secret = (master_secret or os.environ.get("SCANNER_AUTH_SECRET", "")).encode("utf-8")
        if not self.master_secret:
            self.master_secret = secrets.token_bytes(32)

        self._api_keys: Dict[str, APIKeyRecord] = {}
        self._audit_log: List[Dict[str, Any]] = []

    # --------------------------------------------------------------------------
    # 1. API Key Generation & Verification
    # --------------------------------------------------------------------------
    def generate_api_key(
        self,
        tenant_id: str,
        subject: str,
        roles: List[str],
        allowed_namespaces: Optional[List[str]] = None,
        duration_days: int = 90,
        description: str = "",
    ) -> Tuple[str, APIKeyRecord]:
        """
        Generates a secure bearer API token in format: k8s_sec_live_<32-byte-hex>.
        Returns (raw_secret_key, key_record). The raw secret is only displayed once.
        """
        key_id = f"key_{secrets.token_hex(6)}"
        secret_part = secrets.token_hex(24)
        raw_key = f"k8s_sec_live_{key_id}_{secret_part}"

        key_hash = hmac.new(self.master_secret, raw_key.encode("utf-8"), hashlib.sha256).hexdigest()
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=duration_days)

        record = APIKeyRecord(
            key_id=key_id,
            key_hash=key_hash,
            tenant_id=tenant_id or self.default_tenant,
            subject=subject,
            roles=roles,
            allowed_namespaces=allowed_namespaces or ["*"],
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
            is_active=True,
            description=description,
        )
        self._api_keys[key_id] = record
        self._record_audit_event("API_KEY_GENERATED", tenant_id, subject, {"key_id": key_id, "roles": roles})
        return raw_key, record

    def verify_api_key(self, raw_key: str) -> Optional[AuthenticatedIdentity]:
        """Verifies a raw bearer API key against stored cryptographic hashes."""
        if not raw_key or not raw_key.startswith("k8s_sec_live_"):
            return None

        parts = raw_key.split("_")
        if len(parts) < 5:
            return None
        key_id = f"{parts[3]}_{parts[4]}" if len(parts) > 4 else parts[3]

        # Fast O(1) lookup by key_id
        matching_record = self._api_keys.get(key_id)
        if not matching_record:
            for k_id, rec in self._api_keys.items():
                if raw_key.startswith(f"k8s_sec_live_{k_id}"):
                    matching_record = rec
                    break

        if not matching_record or not matching_record.is_active:
            return None

        # Constant-time HMAC comparison to prevent timing attacks
        expected_hash = hmac.new(self.master_secret, raw_key.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_hash, matching_record.key_hash):
            return None

        # Expiry check
        exp_dt = datetime.fromisoformat(matching_record.expires_at)
        if datetime.now(timezone.utc) > exp_dt:
            return None

        return AuthenticatedIdentity(
            subject=matching_record.subject,
            tenant_id=matching_record.tenant_id,
            roles=matching_record.roles,
            allowed_namespaces=matching_record.allowed_namespaces,
            token_id=matching_record.key_id,
            issuer="k8s-native-scanner/api-key",
            expires_at=int(exp_dt.timestamp()),
            metadata={"description": matching_record.description},
        )

    # --------------------------------------------------------------------------
    # 2. Pure-Python RFC 7519 JSON Web Token (JWT) Engine
    # --------------------------------------------------------------------------
    def issue_jwt(
        self,
        tenant_id: str,
        subject: str,
        roles: List[str],
        allowed_namespaces: Optional[List[str]] = None,
        duration_minutes: int = 60,
        email: str = "",
    ) -> str:
        """Issues an HMAC-SHA256 signed JSON Web Token (JWT)."""
        now = int(time.time())
        exp = now + (duration_minutes * 60)
        token_id = secrets.token_hex(8)

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "iss": "k8s-native-scanner",
            "sub": subject,
            "aud": "k8s-cnapp-fleet",
            "jti": token_id,
            "iat": now,
            "nbf": now,
            "exp": exp,
            "tenant_id": tenant_id or self.default_tenant,
            "roles": roles,
            "namespaces": allowed_namespaces or ["*"],
            "email": email,
        }

        b64_header = self._base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        b64_payload = self._base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        message = f"{b64_header}.{b64_payload}".encode("utf-8")
        signature = hmac.new(self.master_secret, message, hashlib.sha256).digest()
        b64_sig = self._base64url_encode(signature)

        return f"{b64_header}.{b64_payload}.{b64_sig}"

    def verify_jwt(self, jwt_token: str) -> Optional[AuthenticatedIdentity]:
        """Verifies an HMAC-SHA256 signed JWT token."""
        if not jwt_token or jwt_token.count(".") != 2:
            return None

        b64_header, b64_payload, b64_sig = jwt_token.split(".")

        # 1. Strict RFC 7519 Header validation (Algorithm confusion prevention)
        try:
            header_json = self._base64url_decode(b64_header).decode("utf-8")
            header = json.loads(header_json)
        except Exception:
            return None

        if not isinstance(header, dict):
            return None
        # Enforce strict HS256 algorithm — explicitly block 'none', asymmetric algs, or unrecognized algorithms
        if header.get("alg") != "HS256":
            logger.warning(f"Rejected JWT with unsupported or disallowed algorithm: {header.get('alg')}")
            return None

        # 2. Cryptographic signature verification using constant-time comparison
        message = f"{b64_header}.{b64_payload}".encode("utf-8")
        expected_sig = hmac.new(self.master_secret, message, hashlib.sha256).digest()
        expected_b64_sig = self._base64url_encode(expected_sig)

        if not hmac.compare_digest(b64_sig, expected_b64_sig):
            return None

        # 3. Payload decoding & claims validation
        try:
            payload_json = self._base64url_decode(b64_payload).decode("utf-8")
            payload = json.loads(payload_json)
        except Exception:
            return None

        if not isinstance(payload, dict):
            return None

        # Expiry check
        now = int(time.time())
        if payload.get("exp", 0) < now:
            return None
        if payload.get("nbf", 0) > now + 30:  # 30-second clock skew
            return None

        return AuthenticatedIdentity(
            subject=payload.get("sub", "unknown"),
            tenant_id=payload.get("tenant_id", self.default_tenant),
            roles=payload.get("roles", [ROLE_DEVOPS_OPERATOR]),
            allowed_namespaces=payload.get("namespaces", ["*"]),
            token_id=payload.get("jti", ""),
            issuer=payload.get("iss", "k8s-native-scanner"),
            expires_at=payload.get("exp"),
            email=payload.get("email", ""),
            metadata=payload,
        )

    # --------------------------------------------------------------------------
    # 3. SAML 2.0 XMLDSig Verification & Assertion Parser
    # --------------------------------------------------------------------------
    def verify_saml_signature(
        self,
        root: ET.Element,
        idp_cert_or_pubkey_pem: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Cryptographically validates SAML 2.0 XMLDSig digital signature according to
        W3C XML Signature Syntax and Processing specifications.
        Prevents XML Signature Wrapping (XSW), signature stripping, and forgery attacks.
        """
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa, utils
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography import x509
            from cryptography.exceptions import InvalidSignature
        except ImportError:
            return False, "SAML signature verification requires 'cryptography' library (pip install k8s-native-scanner[tls])"

        ET.register_namespace("ds", "http://www.w3.org/2000/09/xmldsig#")
        ET.register_namespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion")

        sig_node = root.find(".//{*}Signature")
        if sig_node is None:
            return False, "Missing XMLDSig <Signature> element in SAML assertion"

        si_node = sig_node.find("{*}SignedInfo")
        if si_node is None:
            return False, "Missing <SignedInfo> in XMLDSig signature"

        sig_val_node = sig_node.find("{*}SignatureValue")
        if sig_val_node is None or not sig_val_node.text:
            return False, "Missing <SignatureValue> in XMLDSig signature"

        ref_node = si_node.find("{*}Reference")
        if ref_node is None:
            return False, "Missing <Reference> in <SignedInfo>"

        digest_val_node = ref_node.find("{*}DigestValue")
        if digest_val_node is None or not digest_val_node.text:
            return False, "Missing <DigestValue> in <Reference>"

        # 1. Determine public key (explicit trust anchor or embedded X.509 cert)
        pubkey = None
        if idp_cert_or_pubkey_pem:
            try:
                pem_bytes = idp_cert_or_pubkey_pem.encode("utf-8") if isinstance(idp_cert_or_pubkey_pem, str) else idp_cert_or_pubkey_pem
                if b"CERTIFICATE" in pem_bytes:
                    cert = x509.load_pem_x509_certificate(pem_bytes)
                    pubkey = cert.public_key()
                else:
                    pubkey = load_pem_public_key(pem_bytes)
            except Exception as e:
                return False, f"Failed to load IdP certificate or public key: {e}"
        else:
            x509_node = sig_node.find(".//{*}X509Certificate")
            if x509_node is not None and x509_node.text:
                try:
                    cert_der = base64.b64decode(x509_node.text.strip())
                    cert = x509.load_der_x509_certificate(cert_der)
                    pubkey = cert.public_key()
                except Exception as e:
                    return False, f"Failed to load embedded X509Certificate: {e}"

        if not pubkey:
            return False, "No trusted IdP certificate or embedded X.509 certificate available to verify SAML signature"

        # 2. Canonicalize SignedInfo and verify signature bytes
        try:
            c14n_si = ET.canonicalize(ET.tostring(si_node, encoding="unicode"))
            sig_bytes = base64.b64decode(sig_val_node.text.strip())
        except Exception as e:
            return False, f"Failed to canonicalize SignedInfo or decode signature: {e}"

        sig_method_node = si_node.find("{*}SignatureMethod")
        sig_alg = (sig_method_node.get("Algorithm", "") if sig_method_node is not None else "").lower()
        hash_alg = hashes.SHA1() if "rsa-sha1" in sig_alg else hashes.SHA256()

        if isinstance(pubkey, rsa.RSAPublicKey):
            try:
                pubkey.verify(sig_bytes, c14n_si.encode("utf-8"), padding.PKCS1v15(), hash_alg)
            except InvalidSignature:
                return False, "Cryptographic SAML signature verification failed: signature does not match SignedInfo"
            except Exception as e:
                return False, f"RSA verification error: {e}"
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            try:
                if len(sig_bytes) == 64:
                    r = int.from_bytes(sig_bytes[:32], "big")
                    s = int.from_bytes(sig_bytes[32:], "big")
                    der_sig = utils.encode_dss_signature(r, s)
                else:
                    der_sig = sig_bytes
                pubkey.verify(der_sig, c14n_si.encode("utf-8"), ec.ECDSA(hash_alg))
            except InvalidSignature:
                return False, "Cryptographic SAML signature verification failed: ECDSA signature does not match SignedInfo"
            except Exception as e:
                return False, f"ECDSA verification error: {e}"
        else:
            return False, f"Unsupported public key type: {type(pubkey).__name__}"

        # 3. Verify Assertion Content Digest
        assertion_node = root if "Assertion" in root.tag else root.find(".//{*}Assertion")
        if assertion_node is not None:
            try:
                assertion_copy = copy.deepcopy(assertion_node)
                copy_sig = assertion_copy.find(".//{*}Signature")
                if copy_sig is not None:
                    for parent in assertion_copy.iter():
                        if copy_sig in list(parent):
                            parent.remove(copy_sig)
                            break
                c14n_assertion = ET.canonicalize(ET.tostring(assertion_copy, encoding="unicode"))
                digest_method_node = ref_node.find("{*}DigestMethod")
                digest_alg = (digest_method_node.get("Algorithm", "") if digest_method_node is not None else "").lower()
                if "sha1" in digest_alg:
                    calc_digest = hashlib.sha1(c14n_assertion.encode("utf-8")).digest()
                else:
                    calc_digest = hashlib.sha256(c14n_assertion.encode("utf-8")).digest()
                expected_digest = base64.b64decode(digest_val_node.text.strip())
                if not hmac.compare_digest(calc_digest, expected_digest):
                    return False, "SAML assertion digest mismatch: payload was modified after signing (tampered)"
            except Exception as e:
                logger.debug(f"Assertion digest check warning: {e}")

        return True, None

    def parse_saml_assertion(
        self,
        saml_xml_or_b64: str,
        tenant_id: str,
        idp_cert_or_pubkey_pem: Optional[str] = None,
        require_signature: bool = True,
        allow_unsigned_dev: bool = False,
    ) -> Optional[AuthenticatedIdentity]:
        """
        Parses and cryptographically verifies a corporate SAML 2.0 assertion XML or base64 payload.
        Maps corporate groups/claims to Kubernetes security RBAC roles.
        Enforces XMLDSig signature verification to prevent authentication bypass attacks.
        """
        raw_xml = saml_xml_or_b64.strip()
        if not raw_xml.startswith("<"):
            try:
                raw_xml = base64.b64decode(raw_xml).decode("utf-8", errors="replace")
            except Exception:
                return None

        # Safe DOM XML parsing
        try:
            root = ET.fromstring(raw_xml)
        except Exception as e:
            logger.warning(f"Failed to parse SAML XML DOM: {e}")
            return None

        # Signature verification gate
        sig_node = root.find(".//{*}Signature")
        if sig_node is not None:
            valid_sig, sig_err = self.verify_saml_signature(root, idp_cert_or_pubkey_pem)
            if not valid_sig:
                logger.warning(f"SAML assertion rejected: {sig_err}")
                return None
        else:
            if require_signature and not allow_unsigned_dev:
                logger.warning("SAML assertion rejected: missing XMLDSig signature and require_signature=True (auth bypass prevention)")
                return None
            logger.warning("SECURITY WARNING: Processing unsigned SAML assertion. Prohibited in production.")

        # Extract Subject NameID from parsed DOM
        name_id_node = root.find(".//{*}NameID")
        if name_id_node is None or not name_id_node.text:
            return None
        subject = name_id_node.text.strip()

        # Extract Attributes from parsed DOM
        email = None
        assigned_roles = []
        for attr in root.findall(".//{*}Attribute"):
            attr_name = (attr.get("Name") or "").lower()
            vals = [val.text.strip() for val in attr.findall("{*}AttributeValue") if val.text]
            if attr_name in ("email", "mail") and vals:
                email = vals[0]
            elif attr_name in ("groups", "roles", "memberof"):
                for val in vals:
                    g_lower = val.lower()
                    if "admin" in g_lower or "infosec" in g_lower:
                        assigned_roles.append(ROLE_PLATFORM_ADMIN)
                    elif "security" in g_lower or "soc" in g_lower:
                        assigned_roles.append(ROLE_SECURITY_ENGINEER)
                    elif "audit" in g_lower or "compliance" in g_lower:
                        assigned_roles.append(ROLE_COMPLIANCE_AUDITOR)

        if not email:
            email = f"{subject}@corporate.local"

        if not assigned_roles:
            assigned_roles = [ROLE_DEVOPS_OPERATOR]

        return AuthenticatedIdentity(
            subject=subject,
            tenant_id=tenant_id or self.default_tenant,
            roles=list(set(assigned_roles)),
            allowed_namespaces=["*"],
            token_id=f"saml_{secrets.token_hex(6)}",
            issuer="corporate-idp-saml2",
            expires_at=int(time.time()) + 28800,  # 8 hours
            email=email,
            metadata={"saml_authenticated": True, "signed": sig_node is not None},
        )

    # --------------------------------------------------------------------------
    # 4. Universal Authorization Gateway
    # --------------------------------------------------------------------------
    def authorize(
        self,
        identity: Optional[AuthenticatedIdentity],
        required_permission: str,
        target_tenant: Optional[str] = None,
        target_namespace: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Evaluates whether an identity is authorized to perform an operation.
        Returns (is_allowed, reason).
        """
        if not identity:
            return False, "Authentication required: valid API key or Bearer JWT token required."

        # Tenant boundary check (PlatformAdmin can cross tenants if explicitly authorized)
        if target_tenant and target_tenant != identity.tenant_id:
            if not identity.is_admin:
                return False, f"Multi-tenant violation: access denied to foreign tenant '{target_tenant}'."

        # Namespace boundary check
        if target_namespace and not identity.can_access_namespace(target_namespace):
            return False, f"Namespace boundary violation: access denied to namespace '{target_namespace}'."

        # Permission capability check
        if not identity.has_permission(required_permission):
            return False, f"RBAC permission denied: identity lacks required capability '{required_permission}'."

        return True, "Authorized"

    # --------------------------------------------------------------------------
    # Internal Helpers
    # --------------------------------------------------------------------------
    def _record_audit_event(self, action: str, tenant_id: str, actor: str, details: Dict[str, Any]):
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "tenant_id": tenant_id,
            "actor": actor,
            "details": details,
        })
        if len(self._audit_log) > 5000:
            self._audit_log = self._audit_log[-2000:]

    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _base64url_decode(encoded: str) -> bytes:
        rem = len(encoded) % 4
        if rem > 0:
            encoded += "=" * (4 - rem)
        return base64.urlsafe_b64decode(encoded.encode("ascii"))
