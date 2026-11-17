"""
Digital Signature and Document Verification System
Core Cryptographic Engine

Provides industry-standard asymmetric cryptographic operations:
- Key Pair Generation (RSA 2048/3072/4096-bit, ECDSA SECP256R1/SECP256K1/SECP384R1)
- Key Serialization / Deserialization (PEM PKCS#8, SPKI)
- Cryptographic Hashing (SHA-256, SHA-384, SHA-512)
- Digital Signature Generation (RSA-PSS / ECDSA)
- Signature Verification and Integrity Validation
- Tamper Detection and Verification Audit Manifests
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import io
from dataclasses import asdict, dataclass
from enum import Enum
from typing import BinaryIO, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils as asym_utils
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)


class KeyAlgorithm(str, Enum):
    RSA_2048 = "RSA-2048"
    RSA_3072 = "RSA-3072"
    RSA_4096 = "RSA-4096"
    ECDSA_SECP256R1 = "ECDSA-SECP256R1"
    ECDSA_SECP256K1 = "ECDSA-SECP256K1"
    ECDSA_SECP384R1 = "ECDSA-SECP384R1"


class HashAlgorithm(str, Enum):
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"


@dataclass
class VerificationResult:
    is_valid: bool
    document_hash: str
    hash_algorithm: str
    key_algorithm: str
    key_fingerprint: str
    signature_base64: str
    status_message: str
    verified_at: str
    tamper_detected: bool

    def to_dict(self) -> dict:
        return asdict(self)


class CryptoEngine:
    """Core cryptographic engine for signing and document verification."""

    CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks

    @staticmethod
    def _get_hash_instance(algo_name: Union[str, HashAlgorithm]) -> hashes.HashAlgorithm:
        """Map algorithm string to cryptography HashAlgorithm instance."""
        algo_str = str(algo_name).upper().replace("_", "-")
        if "384" in algo_str:
            return hashes.SHA384()
        elif "512" in algo_str:
            return hashes.SHA512()
        else:
            return hashes.SHA256()

    @classmethod
    def compute_hash(
        cls,
        data: Union[bytes, BinaryIO],
        algorithm: Union[str, HashAlgorithm] = HashAlgorithm.SHA256,
    ) -> Tuple[str, bytes]:
        """
        Compute cryptographic digest of data or file stream in a chunked, memory-safe manner.
        Returns:
            Tuple of (hex_digest, raw_bytes_digest)
        """
        hash_inst = cls._get_hash_instance(algorithm)
        hasher = hashes.Hash(hash_inst, backend=default_backend())

        if isinstance(data, (bytes, bytearray)):
            hasher.update(data)
        else:
            if hasattr(data, "seekable") and data.seekable():
                data.seek(0)
            while True:
                chunk = data.read(cls.CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
            if hasattr(data, "seekable") and data.seekable():
                data.seek(0)

        digest = hasher.finalize()
        return digest.hex(), digest

    @classmethod
    def generate_key_pair(
        cls,
        algorithm: Union[str, KeyAlgorithm] = KeyAlgorithm.RSA_2048,
        passphrase: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Generate asymmetric key pair and return (private_pem, public_pem) bytes.
        """
        algo_str = str(algorithm).upper()

        if "ECDSA" in algo_str or "EC" in algo_str:
            if "384" in algo_str:
                curve = ec.SECP384R1()
            elif "256K1" in algo_str:
                curve = ec.SECP256K1()
            else:
                curve = ec.SECP256R1()
            private_key = ec.generate_private_key(curve, backend=default_backend())
        else:
            if "4096" in algo_str:
                key_size = 4096
            elif "3072" in algo_str:
                key_size = 3072
            else:
                key_size = 2048
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend(),
            )

        # Encrypt private key if passphrase is provided
        if passphrase:
            encryption = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        else:
            encryption = serialization.NoEncryption()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return private_pem, public_pem

    @classmethod
    def load_private_key(
        cls,
        pem_data: Union[bytes, str],
        passphrase: Optional[str] = None,
    ) -> PrivateKeyTypes:
        """Load private key from PEM bytes or string with optional passphrase."""
        if isinstance(pem_data, str):
            pem_data = pem_data.encode("utf-8")

        pwd_bytes = passphrase.encode("utf-8") if passphrase else None
        return serialization.load_pem_private_key(
            pem_data,
            password=pwd_bytes,
            backend=default_backend(),
        )

    @classmethod
    def load_public_key(
        cls,
        pem_data: Union[bytes, str],
    ) -> PublicKeyTypes:
        """Load public key from PEM bytes or string."""
        if isinstance(pem_data, str):
            pem_data = pem_data.encode("utf-8")

        return serialization.load_pem_public_key(
            pem_data,
            backend=default_backend(),
        )

    @classmethod
    def get_public_key_fingerprint(cls, public_key_or_pem: Union[PublicKeyTypes, bytes, str]) -> str:
        """
        Compute a standard SHA-256 fingerprint for a public key (colon-delimited hex).
        Example: 3a:f1:89:...
        """
        if not isinstance(public_key_or_pem, (bytes, str)):
            pem = public_key_or_pem.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            pem = public_key_or_pem.encode("utf-8") if isinstance(public_key_or_pem, str) else public_key_or_pem

        raw_digest = hashlib.sha256(pem).digest()
        return ":".join(f"{b:02x}" for b in raw_digest)

    @classmethod
    def identify_key_algorithm(cls, key: Union[PrivateKeyTypes, PublicKeyTypes]) -> str:
        """Identify key type and parameter size."""
        if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            size = key.key_size
            return f"RSA-{size}"
        elif isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
            curve_name = key.curve.name.upper()
            return f"ECDSA-{curve_name}"
        return "UNKNOWN"

    @classmethod
    def sign(
        cls,
        document_data: Union[bytes, BinaryIO],
        private_key_pem: Union[bytes, str],
        passphrase: Optional[str] = None,
        hash_algo: Union[str, HashAlgorithm] = HashAlgorithm.SHA256,
        signer_identifier: Optional[str] = None,
        document_name: Optional[str] = None,
    ) -> dict:
        """
        Sign document data using private key with RSA-PSS or ECDSA.
        Returns a comprehensive dictionary containing:
        - raw signature bytes
        - signature base64
        - document hash
        - audit manifest (ready for JSON export)
        """
        private_key = cls.load_private_key(private_key_pem, passphrase=passphrase)
        hash_inst = cls._get_hash_instance(hash_algo)
        hash_hex, hash_bytes = cls.compute_hash(document_data, algorithm=hash_algo)

        # Signing logic based on key type
        if isinstance(private_key, rsa.RSAPrivateKey):
            # RSA-PSS with MGF1 (Probabilistic Signature Scheme - gold standard)
            signature = private_key.sign(
                hash_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hash_inst),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                asym_utils.Prehashed(hash_inst),
            )
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                hash_bytes,
                ec.ECDSA(asym_utils.Prehashed(hash_inst)),
            )
        else:
            raise ValueError(f"Unsupported key type: {type(private_key)}")

        sig_b64 = base64.b64encode(signature).decode("ascii")
        public_key = private_key.public_key()
        fingerprint = cls.get_public_key_fingerprint(public_key)
        key_algo = cls.identify_key_algorithm(private_key)

        manifest = {
            "version": "1.0",
            "document_name": document_name or "document",
            "document_hash": hash_hex,
            "hash_algorithm": str(hash_algo),
            "key_algorithm": key_algo,
            "signer_fingerprint": fingerprint,
            "signer_identifier": signer_identifier or "Anonymous Signer",
            "signed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "signature_base64": sig_b64,
        }

        return {
            "signature_bytes": signature,
            "signature_base64": sig_b64,
            "document_hash": hash_hex,
            "manifest": manifest,
            "key_fingerprint": fingerprint,
            "key_algorithm": key_algo,
        }

    @classmethod
    def verify(
        cls,
        document_data: Union[bytes, BinaryIO],
        signature: Union[bytes, str],
        public_key_pem: Union[bytes, str],
        hash_algo: Union[str, HashAlgorithm] = HashAlgorithm.SHA256,
    ) -> VerificationResult:
        """
        Verify digital signature against document and public key.
        Signature can be raw bytes or Base64 string.
        """
        # Convert base64 signature string to bytes if needed
        if isinstance(signature, str):
            try:
                sig_bytes = base64.b64decode(signature.strip())
            except Exception:
                sig_bytes = signature.encode("latin-1")
        else:
            sig_bytes = signature

        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

        try:
            public_key = cls.load_public_key(public_key_pem)
        except Exception as e:
            return VerificationResult(
                is_valid=False,
                document_hash="",
                hash_algorithm=str(hash_algo),
                key_algorithm="INVALID_KEY",
                key_fingerprint="",
                signature_base64=sig_b64,
                status_message=f"Invalid public key format: {str(e)}",
                verified_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                tamper_detected=False,
            )

        key_algo = cls.identify_key_algorithm(public_key)
        fingerprint = cls.get_public_key_fingerprint(public_key)
        hash_inst = cls._get_hash_instance(hash_algo)
        hash_hex, hash_bytes = cls.compute_hash(document_data, algorithm=hash_algo)

        # Verification
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    sig_bytes,
                    hash_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hash_inst),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    asym_utils.Prehashed(hash_inst),
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    sig_bytes,
                    hash_bytes,
                    ec.ECDSA(asym_utils.Prehashed(hash_inst)),
                )
            else:
                return VerificationResult(
                    is_valid=False,
                    document_hash=hash_hex,
                    hash_algorithm=str(hash_algo),
                    key_algorithm=key_algo,
                    key_fingerprint=fingerprint,
                    signature_base64=sig_b64,
                    status_message=f"Unsupported key algorithm: {type(public_key)}",
                    verified_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    tamper_detected=False,
                )

            return VerificationResult(
                is_valid=True,
                document_hash=hash_hex,
                hash_algorithm=str(hash_algo),
                key_algorithm=key_algo,
                key_fingerprint=fingerprint,
                signature_base64=sig_b64,
                status_message="Document signature is VALID. Cryptographic integrity and authenticity verified.",
                verified_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                tamper_detected=False,
            )

        except InvalidSignature:
            return VerificationResult(
                is_valid=False,
                document_hash=hash_hex,
                hash_algorithm=str(hash_algo),
                key_algorithm=key_algo,
                key_fingerprint=fingerprint,
                signature_base64=sig_b64,
                status_message="SIGNATURE VERIFICATION FAILED: The document has been tampered with, or the public key/signature does not match.",
                verified_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                tamper_detected=True,
            )
        except Exception as e:
            return VerificationResult(
                is_valid=False,
                document_hash=hash_hex,
                hash_algorithm=str(hash_algo),
                key_algorithm=key_algo,
                key_fingerprint=fingerprint,
                signature_base64=sig_b64,
                status_message=f"Verification error: {str(e)}",
                verified_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                tamper_detected=False,
            )

    @classmethod
    def simulate_tampering(
        cls,
        document_bytes: bytes,
        signature: Union[bytes, str],
        public_key_pem: Union[bytes, str],
        tamper_position: int = 0,
    ) -> dict:
        """
        Interactive demonstration: flips one byte of the document and attempts verification
        to demonstrate that any alteration completely destroys cryptographic verification.
        """
        if not document_bytes:
            document_bytes = b"Sample Document For Tampering Test"

        pos = min(tamper_position, len(document_bytes) - 1)
        original_byte = document_bytes[pos]
        # Invert the byte to ensure change
        tampered_byte = (original_byte ^ 0xFF)
        tampered_bytes = bytearray(document_bytes)
        tampered_bytes[pos] = tampered_byte

        original_hash, _ = cls.compute_hash(document_bytes)
        tampered_hash, _ = cls.compute_hash(bytes(tampered_bytes))

        # Verify original
        orig_res = cls.verify(document_bytes, signature, public_key_pem)
        # Verify tampered
        tampered_res = cls.verify(bytes(tampered_bytes), signature, public_key_pem)

        return {
            "original_hash": original_hash,
            "tampered_hash": tampered_hash,
            "tampered_byte_index": pos,
            "original_byte_val": original_byte,
            "tampered_byte_val": tampered_byte,
            "original_verification": orig_res.to_dict(),
            "tampered_verification": tampered_res.to_dict(),
        }
