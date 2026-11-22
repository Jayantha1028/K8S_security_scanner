#!/usr/bin/env python3
"""
sigstore.py
===========
Cosign & Sigstore OCI Image Envelope & Cryptographic Signature Verifier.

Capabilities:
- Validates Cosign OCI signature payload envelopes (sha256-<hash>.sig)
- Parses and validates in-toto SLSA Provenance v0.2 / v1.0 Attestations (sha256-<hash>.att)
- Immutable OCI digest matching and workload annotation identity checking
- Cryptographic ECDSA (P-256) and RSA signature verification against public keys
  (requires Python 'cryptography' library)

Note on Offline & Air-Gapped Environments:
Full online Fulcio certificate authority validation and Rekor transparency log queries
require live network connectivity. In air-gapped or CI pipeline environments, this module
verifies offline Cosign envelopes, public key signatures, and cluster admission annotations.
"""

import base64
from dataclasses import asdict, dataclass, field
import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("NativeScanner.Sigstore")


@dataclass
class SignatureVerificationResult:
    image: str
    verified: bool
    digest: str
    signer_identity: Optional[str] = None
    issuer: Optional[str] = None
    has_slsa_provenance: bool = False
    slsa_build_type: Optional[str] = None
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SigstoreVerifier:
    """
    Validates container image signatures, SLSA provenance envelopes, and Cosign metadata.
    """

    @staticmethod
    def extract_image_digest(image_ref: str) -> Optional[str]:
        """Extracts sha256 digest from image@sha256:hash reference."""
        if "@sha256:" in image_ref:
            return image_ref.split("@sha256:")[-1].strip()
        return None

    @staticmethod
    def compute_cosign_sig_tag(digest: str) -> str:
        """Computes standard Cosign signature tag for a sha256 digest: sha256-<digest>.sig"""
        clean_digest = digest.replace("sha256:", "")
        return f"sha256-{clean_digest}.sig"

    @staticmethod
    def compute_cosign_att_tag(digest: str) -> str:
        """Computes standard Cosign attestation tag: sha256-<digest>.att"""
        clean_digest = digest.replace("sha256:", "")
        return f"sha256-{clean_digest}.att"

    def verify_cosign_payload(
        self,
        payload_bytes: bytes,
        expected_digest: str,
        expected_image: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validates Cosign JSON payload envelope matching standard Cosign schema:
        {
          "Critical": {
            "Identity": {"docker-reference": "..."},
            "Image": {"Docker-manifest-digest": "sha256:..."},
            "Type": "cosign container image signature"
          }
        }
        """
        try:
            data = json.loads(payload_bytes.decode("utf-8"))
        except Exception as e:
            return False, f"Failed to parse Cosign JSON payload: {str(e)}"

        critical = data.get("Critical", {})
        if not critical:
            return False, "Missing 'Critical' block in Cosign envelope"

        sig_type = critical.get("Type")
        if sig_type != "cosign container image signature":
            return False, f"Unexpected signature type: '{sig_type}'"

        signed_digest = critical.get("Image", {}).get("Docker-manifest-digest", "")
        clean_expected = expected_digest.replace("sha256:", "")
        clean_signed = signed_digest.replace("sha256:", "")

        if clean_signed != clean_expected:
            return False, f"Digest mismatch: signed '{signed_digest}' != expected '{expected_digest}'"

        if expected_image:
            signed_ref = critical.get("Identity", {}).get("docker-reference", "")
            # Verify repository base matches
            if signed_ref and expected_image.split(":")[0] not in signed_ref:
                return False, f"Repository reference mismatch: '{signed_ref}' != '{expected_image}'"

        return True, None

    def verify_cryptographic_signature(
        self,
        payload_bytes: bytes,
        signature: Union[str, bytes],
        public_key_pem: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Performs genuine cryptographic signature verification of payload bytes
        against an ECDSA or RSA public key in PEM format.
        Supports standard Cosign ECDSA P-256 (SHA-256) and RSA signatures.
        """
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography.exceptions import InvalidSignature
        except ImportError:
            return False, "Cryptographic signature verification requires 'cryptography' library (pip install k8s-native-scanner[tls])"

        # Decode signature if base64 string
        if isinstance(signature, str):
            try:
                sig_bytes = base64.b64decode(signature)
            except Exception as e:
                return False, f"Failed to base64-decode signature: {str(e)}"
        else:
            sig_bytes = signature

        try:
            pubkey = load_pem_public_key(public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem)
        except Exception as e:
            return False, f"Invalid public key PEM: {str(e)}"

        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            # Cosign generates either DER-encoded ECDSA signatures or raw (r || s, 64-bytes for P-256)
            if len(sig_bytes) == 64:
                r = int.from_bytes(sig_bytes[:32], "big")
                s = int.from_bytes(sig_bytes[32:], "big")
                der_sig = utils.encode_dss_signature(r, s)
            else:
                der_sig = sig_bytes

            try:
                pubkey.verify(der_sig, payload_bytes, ec.ECDSA(hashes.SHA256()))
                return True, None
            except InvalidSignature:
                return False, "ECDSA cryptographic signature verification failed: signature mismatch"
            except Exception as e:
                return False, f"ECDSA verification error: {str(e)}"

        elif isinstance(pubkey, rsa.RSAPublicKey):
            try:
                pubkey.verify(sig_bytes, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
                return True, None
            except InvalidSignature:
                try:
                    pubkey.verify(
                        sig_bytes,
                        payload_bytes,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256(),
                    )
                    return True, None
                except InvalidSignature:
                    return False, "RSA cryptographic signature verification failed: signature mismatch"
            except Exception as e:
                return False, f"RSA verification error: {str(e)}"

        return False, f"Unsupported public key type: {type(pubkey).__name__}"

    def verify_in_toto_attestation(
        self, attestation_payload: bytes, expected_digest: str
    ) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """
        Validates in-toto SLSA attestation predicate matching payload:
        {
          "_type": "https://in-toto.io/Statement/v0.1",
          "predicateType": "https://slsa.dev/provenance/v0.2",
          "subject": [{"name": "...", "digest": {"sha256": "..."}}],
          "predicate": {...}
        }
        """
        try:
            data = json.loads(attestation_payload.decode("utf-8"))
        except Exception as e:
            return False, {}, f"Invalid in-toto statement: {str(e)}"

        subjects = data.get("subject", [])
        if not subjects:
            return False, {}, "Missing 'subject' field in in-toto attestation"

        clean_expected = expected_digest.replace("sha256:", "")
        digest_matched = False
        for s in subjects:
            sub_digest = s.get("digest", {}).get("sha256", "")
            if sub_digest == clean_expected:
                digest_matched = True
                break

        if not digest_matched:
            return False, {}, f"No subject digest matched expected sha256:{clean_expected}"

        predicate_type = data.get("predicateType", "")
        predicate = data.get("predicate", {})
        is_slsa = "slsa.dev/provenance" in predicate_type

        details = {
            "statement_type": data.get("_type"),
            "predicate_type": predicate_type,
            "is_slsa": is_slsa,
            "builder_id": predicate.get("builder", {}).get("id") if isinstance(predicate, dict) else None,
            "build_type": predicate.get("buildType") if isinstance(predicate, dict) else None,
        }
        return True, details, None

    def verify_workload_image_signature(
        self,
        image_ref: str,
        annotations: Optional[Dict[str, str]] = None,
        mock_payload: Optional[bytes] = None,
        signature: Optional[Union[str, bytes]] = None,
        public_key_pem: Optional[str] = None,
    ) -> SignatureVerificationResult:
        """
        Performs holistic signature verification for a container image in a workload.
        Validates:
        1. Immutable sha256 digest reference (@sha256:...).
        2. Cryptographic signature check if signature & public_key_pem are supplied.
        3. Cosign envelope structure and digest alignment if payload is supplied.
        4. Admission controller verified annotations or Fulcio certificate identity.
        """
        ann = annotations or {}
        digest = self.extract_image_digest(image_ref)

        # 1. Check if pinned by immutable digest
        if not digest:
            return SignatureVerificationResult(
                image=image_ref,
                verified=False,
                digest="",
                error_message="Image reference lacks immutable sha256 digest pinning (@sha256:...)",
            )

        # 2. Cryptographic signature verification if public key & signature supplied
        if signature and public_key_pem:
            payload_to_verify = mock_payload or digest.encode("utf-8")
            valid_sig, sig_err = self.verify_cryptographic_signature(
                payload_to_verify, signature, public_key_pem
            )
            if not valid_sig:
                return SignatureVerificationResult(
                    image=image_ref,
                    verified=False,
                    digest=digest,
                    error_message=sig_err,
                )

            # If payload was supplied, also verify envelope structure
            if mock_payload:
                valid_env, env_err = self.verify_cosign_payload(mock_payload, digest, expected_image=image_ref)
                if not valid_env:
                    return SignatureVerificationResult(
                        image=image_ref,
                        verified=False,
                        digest=digest,
                        error_message=env_err,
                    )

            return SignatureVerificationResult(
                image=image_ref,
                verified=True,
                digest=digest,
                signer_identity="cosign-cryptographic-key",
                issuer="local-public-key",
                has_slsa_provenance=False,
                details={
                    "verification_type": "cryptographic_key",
                    "sig_tag": self.compute_cosign_sig_tag(digest),
                },
            )

        # 3. If payload provided without public key (e.g. offline envelope check)
        if mock_payload:
            valid, err = self.verify_cosign_payload(mock_payload, digest, expected_image=image_ref)
            if not valid:
                return SignatureVerificationResult(
                    image=image_ref,
                    verified=False,
                    digest=digest,
                    error_message=err,
                )
            cosign_identity = ann.get("cosign.sigstore.dev/certificate-identity") or ann.get("dev.cosignproject.cosign/subject")
            cosign_issuer = ann.get("cosign.sigstore.dev/certificate-oidc-issuer")
            return SignatureVerificationResult(
                image=image_ref,
                verified=True,
                digest=digest,
                signer_identity=cosign_identity or "cosign-envelope-valid",
                issuer=cosign_issuer or "cosign-envelope",
                has_slsa_provenance=False,
                details={
                    "verification_type": "cosign_envelope_match",
                    "sig_tag": self.compute_cosign_sig_tag(digest),
                },
            )

        # 4. Check for Cosign / Sigstore annotations in manifest (admission/CI attestation)
        cosign_identity = ann.get("cosign.sigstore.dev/certificate-identity") or ann.get("dev.cosignproject.cosign/subject")
        cosign_issuer = ann.get("cosign.sigstore.dev/certificate-oidc-issuer")
        is_verified_ann = (
            ann.get("cosign.sigstore.dev/verified") == "true"
            or ann.get("sigstore.dev/verified") == "true"
        )
        predicate_type = ann.get("cosign.sigstore.dev/predicate-type", "")
        has_slsa = "slsa.dev/provenance" in predicate_type or ann.get("slsa.dev/provenance") == "true"

        if cosign_identity or is_verified_ann:
            return SignatureVerificationResult(
                image=image_ref,
                verified=True,
                digest=digest,
                signer_identity=cosign_identity or "cosign-admission-verified",
                issuer=cosign_issuer or "cosign-admission-attestation",
                has_slsa_provenance=has_slsa,
                slsa_build_type=predicate_type if has_slsa else None,
                details={
                    "verification_type": "admission_annotation",
                    "sig_tag": self.compute_cosign_sig_tag(digest),
                    "att_tag": self.compute_cosign_att_tag(digest),
                },
            )

        # 5. Digest is pinned, but no signature envelope, key, or certificate identity was provided
        return SignatureVerificationResult(
            image=image_ref,
            verified=False,
            digest=digest,
            signer_identity=None,
            issuer=None,
            has_slsa_provenance=False,
            error_message="Image is pinned by digest, but lacks verified Cosign signature envelope or Fulcio certificate identity annotation",
            details={
                "digest_pinned": True,
                "sig_tag": self.compute_cosign_sig_tag(digest),
                "att_tag": self.compute_cosign_att_tag(digest),
            },
        )
