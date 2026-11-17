"""
Unit Tests for CryptoEngine
Covers key generation, signing, verification, tamper detection, and error conditions.
"""

import io
import unittest

from core.crypto_engine import (
    CryptoEngine,
    HashAlgorithm,
    KeyAlgorithm,
    VerificationResult,
)


class TestCryptoEngine(unittest.TestCase):
    def setUp(self):
        self.doc_content = b"Official Contract: Party A agrees to deliver software to Party B."
        self.rsa_priv, self.rsa_pub = CryptoEngine.generate_key_pair(KeyAlgorithm.RSA_2048)
        self.ec_priv, self.ec_pub = CryptoEngine.generate_key_pair(KeyAlgorithm.ECDSA_SECP256R1)

    def test_rsa_keygen_and_fingerprint(self):
        self.assertIn(b"BEGIN PRIVATE KEY", self.rsa_priv)
        self.assertIn(b"BEGIN PUBLIC KEY", self.rsa_pub)
        fingerprint = CryptoEngine.get_public_key_fingerprint(self.rsa_pub)
        self.assertIsInstance(fingerprint, str)
        self.assertEqual(len(fingerprint.split(":")), 32)  # 32 bytes SHA-256

    def test_ecdsa_keygen_and_fingerprint(self):
        self.assertIn(b"BEGIN PRIVATE KEY", self.ec_priv)
        self.assertIn(b"BEGIN PUBLIC KEY", self.ec_pub)
        fingerprint = CryptoEngine.get_public_key_fingerprint(self.ec_pub)
        self.assertIsInstance(fingerprint, str)
        self.assertEqual(len(fingerprint.split(":")), 32)

    def test_hash_calculation(self):
        hex_digest, raw_bytes = CryptoEngine.compute_hash(self.doc_content, HashAlgorithm.SHA256)
        self.assertEqual(len(hex_digest), 64)
        self.assertEqual(len(raw_bytes), 32)

        # Stream testing
        stream = io.BytesIO(self.doc_content)
        stream_hex, _ = CryptoEngine.compute_hash(stream, HashAlgorithm.SHA256)
        self.assertEqual(hex_digest, stream_hex)

    def test_rsa_signing_and_verification_success(self):
        sign_res = CryptoEngine.sign(
            self.doc_content,
            self.rsa_priv,
            signer_identifier="Alice",
            document_name="contract.txt",
        )
        self.assertTrue(sign_res["signature_bytes"])
        self.assertTrue(sign_res["signature_base64"])
        self.assertEqual(sign_res["manifest"]["signer_identifier"], "Alice")

        verify_res = CryptoEngine.verify(
            self.doc_content,
            sign_res["signature_base64"],
            self.rsa_pub,
        )
        self.assertTrue(verify_res.is_valid)
        self.assertFalse(verify_res.tamper_detected)
        self.assertIn("VALID", verify_res.status_message)

    def test_ecdsa_signing_and_verification_success(self):
        sign_res = CryptoEngine.sign(
            self.doc_content,
            self.ec_priv,
            signer_identifier="Bob",
            document_name="agreement.txt",
        )
        verify_res = CryptoEngine.verify(
            self.doc_content,
            sign_res["signature_base64"],
            self.ec_pub,
        )
        self.assertTrue(verify_res.is_valid)
        self.assertFalse(verify_res.tamper_detected)

    def test_tamper_detection(self):
        sign_res = CryptoEngine.sign(self.doc_content, self.rsa_priv)
        tampered_content = b"Official Contract: Party A agrees to deliver MALWARE to Party B."

        verify_res = CryptoEngine.verify(
            tampered_content,
            sign_res["signature_base64"],
            self.rsa_pub,
        )
        self.assertFalse(verify_res.is_valid)
        self.assertTrue(verify_res.tamper_detected)
        self.assertIn("FAILED", verify_res.status_message)

    def test_wrong_public_key_rejection(self):
        sign_res = CryptoEngine.sign(self.doc_content, self.rsa_priv)
        _, another_pub = CryptoEngine.generate_key_pair(KeyAlgorithm.RSA_2048)

        verify_res = CryptoEngine.verify(
            self.doc_content,
            sign_res["signature_base64"],
            another_pub,
        )
        self.assertFalse(verify_res.is_valid)
        self.assertTrue(verify_res.tamper_detected)

    def test_corrupted_signature_rejection(self):
        sign_res = CryptoEngine.sign(self.doc_content, self.rsa_priv)
        # Flip characters in the base64 signature
        corrupted_sig = "A" * len(sign_res["signature_base64"])

        verify_res = CryptoEngine.verify(
            self.doc_content,
            corrupted_sig,
            self.rsa_pub,
        )
        self.assertFalse(verify_res.is_valid)

    def test_passphrase_protected_key(self):
        pwd = "SecretPassphrase123!"
        priv_enc, pub = CryptoEngine.generate_key_pair(KeyAlgorithm.RSA_2048, passphrase=pwd)
        self.assertIn(b"ENCRYPTED", priv_enc)

        sign_res = CryptoEngine.sign(self.doc_content, priv_enc, passphrase=pwd)
        verify_res = CryptoEngine.verify(self.doc_content, sign_res["signature_base64"], pub)
        self.assertTrue(verify_res.is_valid)

    def test_tamper_simulation_method(self):
        sign_res = CryptoEngine.sign(self.doc_content, self.rsa_priv)
        sim = CryptoEngine.simulate_tampering(
            self.doc_content,
            sign_res["signature_base64"],
            self.rsa_pub,
            tamper_position=5,
        )
        self.assertTrue(sim["original_verification"]["is_valid"])
        self.assertFalse(sim["tampered_verification"]["is_valid"])
        self.assertNotEqual(sim["original_hash"], sim["tampered_hash"])


if __name__ == "__main__":
    unittest.main()
