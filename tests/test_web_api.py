"""
Web API Endpoint Tests for Digital Signature System
"""

import io
import json
import unittest

from app import app
from core.crypto_engine import CryptoEngine, KeyAlgorithm


class TestWebAPI(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_index_route(self):
        response = self.app.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Digital Signature", response.data)

    def test_download_sample_route(self):
        response = self.app.get("/api/download-sample")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CONFIDENTIAL MUTUAL NON-DISCLOSURE", response.data)

    def test_keygen_api(self):
        res = self.app.post(
            "/api/keygen",
            data=json.dumps({"algorithm": "RSA-2048"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("BEGIN PRIVATE KEY", data["private_key"])
        self.assertIn("BEGIN PUBLIC KEY", data["public_key"])
        self.assertIn(":", data["fingerprint"])

    def test_sign_and_verify_api(self):
        # 1. Generate keys
        priv_pem, pub_pem = CryptoEngine.generate_key_pair(KeyAlgorithm.RSA_2048)

        # 2. Call /api/sign
        sign_res = self.app.post(
            "/api/sign",
            data={
                "document": (io.BytesIO(b"Hello Cryptographic World"), "hello.txt"),
                "private_key_text": priv_pem.decode("utf-8"),
                "signer_name": "Test Signer",
                "hash_algo": "SHA-256",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(sign_res.status_code, 200)
        sign_data = sign_res.get_json()
        self.assertTrue(sign_data["success"])
        sig_b64 = sign_data["signature_base64"]

        # 3. Call /api/verify with intact document
        verify_res = self.app.post(
            "/api/verify",
            data={
                "document": (io.BytesIO(b"Hello Cryptographic World"), "hello.txt"),
                "public_key_text": pub_pem.decode("utf-8"),
                "signature_text": sig_b64,
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(verify_res.status_code, 200)
        verify_data = verify_res.get_json()
        self.assertTrue(verify_data["success"])
        self.assertTrue(verify_data["verification"]["is_valid"])

        # 4. Call /api/verify with tampered document
        tampered_res = self.app.post(
            "/api/verify",
            data={
                "document": (io.BytesIO(b"Hello Cryptographic World TAMPERED"), "hello.txt"),
                "public_key_text": pub_pem.decode("utf-8"),
                "signature_text": sig_b64,
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(tampered_res.status_code, 200)
        tampered_data = tampered_res.get_json()
        self.assertFalse(tampered_data["verification"]["is_valid"])
        self.assertTrue(tampered_data["verification"]["tamper_detected"])

    def test_tamper_lab_api(self):
        priv_pem, pub_pem = CryptoEngine.generate_key_pair(KeyAlgorithm.RSA_2048)

        res = self.app.post(
            "/api/tamper-lab",
            data={
                "document": (io.BytesIO(b"Sample critical data bytes"), "critical.txt"),
                "private_key_text": priv_pem.decode("utf-8"),
                "public_key_text": pub_pem.decode("utf-8"),
                "tamper_position": "0",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        tr = data["tamper_result"]
        self.assertTrue(tr["original_verification"]["is_valid"])
        self.assertFalse(tr["tampered_verification"]["is_valid"])


if __name__ == "__main__":
    unittest.main()
