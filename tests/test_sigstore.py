#!/usr/bin/env python3
"""
tests/test_sigstore.py
======================
Unit tests for the Cosign & Sigstore OCI Image Verification Engine (sigstore.py).
"""

import json
import unittest

from sigstore import SigstoreVerifier, SignatureVerificationResult


class TestSigstoreVerifier(unittest.TestCase):
    def setUp(self):
        self.verifier = SigstoreVerifier()
        self.sample_digest = "b45c7e112d8a5629df4f7c8f9b9f7a7d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b"
        self.image_ref = f"ghcr.io/org/app@sha256:{self.sample_digest}"

    def test_extract_image_digest(self):
        digest = self.verifier.extract_image_digest(self.image_ref)
        self.assertEqual(digest, self.sample_digest)

        digest_none = self.verifier.extract_image_digest("nginx:latest")
        self.assertIsNone(digest_none)

    def test_compute_cosign_tags(self):
        sig_tag = self.verifier.compute_cosign_sig_tag(self.sample_digest)
        self.assertEqual(sig_tag, f"sha256-{self.sample_digest}.sig")

        att_tag = self.verifier.compute_cosign_att_tag(self.sample_digest)
        self.assertEqual(att_tag, f"sha256-{self.sample_digest}.att")

    def test_verify_cosign_payload_valid(self):
        payload = json.dumps({
            "Critical": {
                "Identity": {"docker-reference": "ghcr.io/org/app"},
                "Image": {"Docker-manifest-digest": f"sha256:{self.sample_digest}"},
                "Type": "cosign container image signature"
            }
        }).encode("utf-8")

        valid, err = self.verifier.verify_cosign_payload(payload, self.sample_digest, "ghcr.io/org/app")
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_verify_cosign_payload_mismatch(self):
        payload = json.dumps({
            "Critical": {
                "Identity": {"docker-reference": "ghcr.io/org/app"},
                "Image": {"Docker-manifest-digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
                "Type": "cosign container image signature"
            }
        }).encode("utf-8")

        valid, err = self.verifier.verify_cosign_payload(payload, self.sample_digest)
        self.assertFalse(valid)
        self.assertIn("Digest mismatch", err)

    def test_verify_in_toto_attestation_slsa(self):
        att_payload = json.dumps({
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "subject": [
                {
                    "name": "ghcr.io/org/app",
                    "digest": {"sha256": self.sample_digest}
                }
            ],
            "predicate": {
                "builder": {"id": "https://github.com/slsa-framework/slsa-github-generator"},
                "buildType": "https://github.com/slsa-framework/slsa-github-generator/delegator-generic@v1"
            }
        }).encode("utf-8")

        valid, details, err = self.verifier.verify_in_toto_attestation(att_payload, self.sample_digest)
        self.assertTrue(valid)
        self.assertTrue(details["is_slsa"])
        self.assertIsNone(err)

    def test_verify_workload_image_signature_with_annotations(self):
        res = self.verifier.verify_workload_image_signature(
            self.image_ref,
            annotations={
                "cosign.sigstore.dev/certificate-identity": "sec-team@corp.internal",
                "cosign.sigstore.dev/predicate-type": "https://slsa.dev/provenance/v0.2",
            }
        )
        self.assertTrue(res.verified)
        self.assertEqual(res.signer_identity, "sec-team@corp.internal")
        self.assertTrue(res.has_slsa_provenance)

    def test_unsigned_digest_pinned_image_is_not_verified(self):
        """CRITICAL: An image with a digest but NO signature or annotation must NOT be marked verified."""
        res = self.verifier.verify_workload_image_signature(self.image_ref)
        self.assertFalse(res.verified)
        self.assertIsNone(res.signer_identity)
        self.assertFalse(res.has_slsa_provenance)
        self.assertIn("lacks verified Cosign signature", res.error_message)

    def test_unverified_image_without_digest(self):
        res = self.verifier.verify_workload_image_signature("nginx:1.21")
        self.assertFalse(res.verified)
        self.assertIn("lacks immutable sha256 digest", res.error_message)

    def test_cryptographic_ecdsa_signature_verification(self):
        """Tests authentic ECDSA P-256 signature verification over payload."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes, serialization
        except ImportError:
            self.skipTest("cryptography not installed")

        # Generate test ECDSA key pair
        private_key = ec.generate_private_key(ec.SECP256R1())
        pubkey_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        payload = b'{"Critical":{"Identity":{"docker-reference":"test"},"Type":"cosign"}}'
        signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))

        # Verify valid signature
        valid, err = self.verifier.verify_cryptographic_signature(payload, signature, pubkey_pem)
        self.assertTrue(valid)
        self.assertIsNone(err)

        # Verify tampered payload fails
        tampered = b'{"Critical":{"Identity":{"docker-reference":"evil"},"Type":"cosign"}}'
        valid_tampered, err_tampered = self.verifier.verify_cryptographic_signature(tampered, signature, pubkey_pem)
        self.assertFalse(valid_tampered)
        self.assertIn("signature mismatch", err_tampered)


if __name__ == "__main__":
    unittest.main()
