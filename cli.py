#!/usr/bin/env python3
"""
Digital Signature and Document Verification System - Command Line Interface (CLI)

Supports:
- Key Generation (RSA / ECDSA)
- Document Hashing
- Digital Signing & Manifest Creation
- Signature Verification & Integrity Auditing
- Live Tamper Simulation Sandbox
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from core.crypto_engine import (
    CryptoEngine,
    HashAlgorithm,
    KeyAlgorithm,
    VerificationResult,
)


def print_banner():
    banner = r"""
╔═══════════════════════════════════════════════════════════════════════╗
║         DIGITAL SIGNATURE & DOCUMENT VERIFICATION SYSTEM              ║
║         Asymmetric Cryptography • RSA-PSS & ECDSA • SHA-256           ║
╚═══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def cmd_keygen(args):
    """Generate asymmetric key pairs (RSA or ECDSA)."""
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    priv_path = out_dir / (args.prefix + "_private.pem")
    pub_path = out_dir / (args.prefix + "_public.pem")

    algo = args.algo.upper()
    print(f"[*] Generating {algo} key pair...")

    priv_bytes, pub_bytes = CryptoEngine.generate_key_pair(
        algorithm=algo,
        passphrase=args.passphrase,
    )

    with open(priv_path, "wb") as f:
        f.write(priv_bytes)
    with open(pub_path, "wb") as f:
        f.write(pub_bytes)

    fingerprint = CryptoEngine.get_public_key_fingerprint(pub_bytes)

    print(f"[✓] Key pair successfully generated!")
    print(f"    Private Key:  {priv_path} {'(ENCRYPTED)' if args.passphrase else ''}")
    print(f"    Public Key:   {pub_path}")
    print(f"    Fingerprint:  {fingerprint}")


def cmd_hash(args):
    """Compute cryptographic hash of a document."""
    doc_path = Path(args.doc)
    if not doc_path.exists():
        print(f"[!] Error: File not found: {doc_path}", file=sys.stderr)
        sys.exit(1)

    with open(doc_path, "rb") as f:
        hex_digest, _ = CryptoEngine.compute_hash(f, algorithm=args.algo)

    print(f"[*] File:            {doc_path.name}")
    print(f"[*] Size:            {doc_path.stat().st_size:,} bytes")
    print(f"[*] Algorithm:       {args.algo.upper()}")
    print(f"[✓] Document Digest: {hex_digest}")


def cmd_sign(args):
    """Sign a document with a private key."""
    doc_path = Path(args.doc)
    key_path = Path(args.key)

    if not doc_path.exists():
        print(f"[!] Error: Document file not found: {doc_path}", file=sys.stderr)
        sys.exit(1)
    if not key_path.exists():
        print(f"[!] Error: Private key file not found: {key_path}", file=sys.stderr)
        sys.exit(1)

    with open(key_path, "rb") as f:
        priv_pem = f.read()

    print(f"[*] Reading and hashing '{doc_path.name}'...")
    with open(doc_path, "rb") as f:
        doc_bytes = f.read()

    try:
        sign_result = CryptoEngine.sign(
            document_data=doc_bytes,
            private_key_pem=priv_pem,
            passphrase=args.passphrase,
            hash_algo=args.algo,
            signer_identifier=args.signer,
            document_name=doc_path.name,
        )
    except Exception as e:
        print(f"[!] Signing failed: {e}", file=sys.stderr)
        sys.exit(1)

    sig_out = Path(args.out_sig) if args.out_sig else doc_path.with_suffix(doc_path.suffix + ".sig")
    with open(sig_out, "wb") as f:
        f.write(sign_result["signature_bytes"])

    manifest_out = Path(args.out_manifest) if args.out_manifest else doc_path.with_suffix(doc_path.suffix + ".manifest.json")
    with open(manifest_out, "w", encoding="utf-8") as f:
        json.dump(sign_result["manifest"], f, indent=2)

    print(f"[✓] Document successfully signed!")
    print(f"    Document:           {doc_path.name}")
    print(f"    SHA-256 Digest:     {sign_result['document_hash']}")
    print(f"    Key Algorithm:      {sign_result['key_algorithm']}")
    print(f"    Signer Fingerprint: {sign_result['key_fingerprint']}")
    print(f"    Raw Signature:      {sig_out}")
    print(f"    Audit Manifest:     {manifest_out}")


def cmd_verify(args):
    """Verify document signature against public key."""
    doc_path = Path(args.doc)
    key_path = Path(args.key)

    if not doc_path.exists():
        print(f"[!] Error: Document not found: {doc_path}", file=sys.stderr)
        sys.exit(1)
    if not key_path.exists():
        print(f"[!] Error: Public key not found: {key_path}", file=sys.stderr)
        sys.exit(1)

    # Signature can come from --sig file or --manifest file
    if args.manifest:
        man_path = Path(args.manifest)
        if not man_path.exists():
            print(f"[!] Error: Manifest not found: {man_path}", file=sys.stderr)
            sys.exit(1)
        with open(man_path, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)
        sig_data = manifest_data.get("signature_base64")
        if not sig_data:
            print(f"[!] Error: Manifest does not contain 'signature_base64'", file=sys.stderr)
            sys.exit(1)
    elif args.sig:
        sig_path = Path(args.sig)
        if not sig_path.exists():
            print(f"[!] Error: Signature file not found: {sig_path}", file=sys.stderr)
            sys.exit(1)
        with open(sig_path, "rb") as f:
            sig_data = f.read()
    else:
        print("[!] Error: Either --sig or --manifest must be provided.", file=sys.stderr)
        sys.exit(1)

    with open(key_path, "rb") as f:
        pub_pem = f.read()
    with open(doc_path, "rb") as f:
        doc_bytes = f.read()

    print(f"[*] Verifying signature for '{doc_path.name}'...")
    result: VerificationResult = CryptoEngine.verify(
        document_data=doc_bytes,
        signature=sig_data,
        public_key_pem=pub_pem,
        hash_algo=args.algo,
    )

    print("-" * 65)
    if result.is_valid:
        print(f"🟢 VERIFICATION SUCCESS: VALID SIGNATURE")
        print(f"   The document is authentic and has NOT been modified.")
    else:
        print(f"🔴 VERIFICATION FAILURE: INVALID SIGNATURE OR TAMPERED")
        print(f"   {result.status_message}")

    print("-" * 65)
    print(f"   Document Digest:    {result.document_hash}")
    print(f"   Key Algorithm:      {result.key_algorithm}")
    print(f"   Signer Fingerprint: {result.key_fingerprint}")
    print(f"   Audit Timestamp:    {result.verified_at}")
    print("-" * 65)

    if not result.is_valid:
        sys.exit(2)


def cmd_tamper_demo(args):
    """Demonstrate how tampering with a single byte invalidates the signature."""
    doc_path = Path(args.doc)
    key_path = Path(args.key)
    pub_path = Path(args.pubkey)

    if not doc_path.exists() or not key_path.exists() or not pub_path.exists():
        print("[!] Error: Ensure --doc, --key, and --pubkey exist.", file=sys.stderr)
        sys.exit(1)

    with open(doc_path, "rb") as f:
        original_doc = f.read()
    with open(key_path, "rb") as f:
        priv_pem = f.read()
    with open(pub_path, "rb") as f:
        pub_pem = f.read()

    print("[1] Signing original document...")
    sign_res = CryptoEngine.sign(original_doc, priv_pem)

    print("[2] Running live tamper simulation (altering byte at position 0)...")
    sim = CryptoEngine.simulate_tampering(
        original_doc,
        sign_res["signature_bytes"],
        pub_pem,
        tamper_position=0,
    )

    print("\n" + "=" * 65)
    print("TAMPER RESISTANCE DEMONSTRATION")
    print("=" * 65)
    print(f"Original Document Hash: {sim['original_hash']}")
    print(f"Original Verification:  VALID (Authentic: {sim['original_verification']['is_valid']})")
    print("-" * 65)
    print(f"Modified Byte Index:    {sim['tampered_byte_index']}")
    print(f"Byte Change:            {sim['original_byte_val']} -> {sim['tampered_byte_val']}")
    print(f"Tampered Document Hash: {sim['tampered_hash']}")
    print(f"Tampered Verification:  FAILED (Valid: {sim['tampered_verification']['is_valid']})")
    print("=" * 65)
    print("Result: Cryptographic signature mathematically guarantees integrity.\n")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Digital Signature and Document Verification System CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate RSA or ECDSA key pair")
    p_keygen.add_argument("--algo", default="RSA-2048", choices=["RSA-2048", "RSA-4096", "ECDSA-SECP256R1", "ECDSA-SECP256K1"])
    p_keygen.add_argument("--passphrase", help="Optional passphrase to encrypt private key")
    p_keygen.add_argument("--out-dir", default="./keys", help="Output directory for generated keys")
    p_keygen.add_argument("--prefix", default="key", help="Key file prefix")
    p_keygen.set_defaults(func=cmd_keygen)

    # hash
    p_hash = subparsers.add_parser("hash", help="Compute cryptographic hash of a file")
    p_hash.add_argument("--doc", required=True, help="Path to document file")
    p_hash.add_argument("--algo", default="SHA-256", choices=["SHA-256", "SHA-384", "SHA-512"])
    p_hash.set_defaults(func=cmd_hash)

    # sign
    p_sign = subparsers.add_parser("sign", help="Sign a document using a private key")
    p_sign.add_argument("--doc", required=True, help="Document file to sign")
    p_sign.add_argument("--key", required=True, help="Private key PEM file")
    p_sign.add_argument("--passphrase", help="Passphrase if private key is encrypted")
    p_sign.add_argument("--algo", default="SHA-256", choices=["SHA-256", "SHA-384", "SHA-512"])
    p_sign.add_argument("--signer", default="Document Signer", help="Signer name or identifier")
    p_sign.add_argument("--out-sig", help="Destination path for .sig raw binary signature")
    p_sign.add_argument("--out-manifest", help="Destination path for .manifest.json audit receipt")
    p_sign.set_defaults(func=cmd_sign)

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify a document's digital signature")
    p_verify.add_argument("--doc", required=True, help="Original or received document file")
    p_verify.add_argument("--key", required=True, help="Public key PEM file")
    p_verify.add_argument("--sig", help="Raw binary or base64 signature file")
    p_verify.add_argument("--manifest", help="Audit manifest JSON file")
    p_verify.add_argument("--algo", default="SHA-256", choices=["SHA-256", "SHA-384", "SHA-512"])
    p_verify.set_defaults(func=cmd_verify)

    # tamper-demo
    p_tamper = subparsers.add_parser("tamper-demo", help="Demonstrate live tamper rejection")
    p_tamper.add_argument("--doc", required=True, help="Path to document")
    p_tamper.add_argument("--key", required=True, help="Path to private key PEM")
    p_tamper.add_argument("--pubkey", required=True, help="Path to public key PEM")
    p_tamper.set_defaults(func=cmd_tamper_demo)

    parsed_args = parser.parse_args()
    parsed_args.func(parsed_args)


if __name__ == "__main__":
    main()
