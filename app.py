"""
Digital Signature and Document Verification System
Flask Web Application & REST API
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

from core.crypto_engine import (
    CryptoEngine,
    HashAlgorithm,
    KeyAlgorithm,
    VerificationResult,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32MB max file size

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_DOC_PATH = BASE_DIR / "sample_docs" / "sample_contract.txt"


@app.route("/")
def index():
    """Render the dashboard UI."""
    return render_template("index.html")


@app.route("/api/keygen", methods=["POST"])
def api_keygen():
    """
    Generate asymmetric key pair.
    Payload: { algorithm: "RSA-2048" | "ECDSA-SECP256R1" ..., passphrase: "optional" }
    """
    try:
        data = request.get_json(silent=True) or {}
        algo = data.get("algorithm", "RSA-2048")
        passphrase = data.get("passphrase") or None

        priv_bytes, pub_bytes = CryptoEngine.generate_key_pair(
            algorithm=algo,
            passphrase=passphrase,
        )
        fingerprint = CryptoEngine.get_public_key_fingerprint(pub_bytes)

        return jsonify({
            "success": True,
            "algorithm": algo,
            "private_key": priv_bytes.decode("utf-8"),
            "public_key": pub_bytes.decode("utf-8"),
            "fingerprint": fingerprint,
            "encrypted": bool(passphrase),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/hash", methods=["POST"])
def api_hash():
    """Compute cryptographic hash of uploaded file."""
    if "document" not in request.files:
        return jsonify({"success": False, "error": "No document provided"}), 400

    file = request.files["document"]
    algo = request.form.get("algorithm", "SHA-256")

    try:
        hex_digest, _ = CryptoEngine.compute_hash(file.stream, algorithm=algo)
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)

        return jsonify({
            "success": True,
            "filename": file.filename,
            "hash": hex_digest,
            "algorithm": algo,
            "size_bytes": size,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/sign", methods=["POST"])
def api_sign():
    """
    Sign uploaded document using provided private key.
    Accepts:
    - document (file)
    - private_key (file or text string)
    - passphrase (optional string)
    - signer_name (optional string)
    - hash_algo (optional string, default SHA-256)
    """
    if "document" not in request.files:
        return jsonify({"success": False, "error": "Document file is required"}), 400

    doc_file = request.files["document"]
    doc_bytes = doc_file.read()

    # Private key from file or form text
    if "private_key_file" in request.files and request.files["private_key_file"].filename:
        priv_pem = request.files["private_key_file"].read()
    elif "private_key_text" in request.form and request.form["private_key_text"].strip():
        priv_pem = request.form["private_key_text"].strip().encode("utf-8")
    else:
        return jsonify({"success": False, "error": "Private key is required (upload file or paste PEM)"}), 400

    passphrase = request.form.get("passphrase") or None
    signer_name = request.form.get("signer_name") or "Authorized Signer"
    hash_algo = request.form.get("hash_algo") or "SHA-256"

    try:
        sign_result = CryptoEngine.sign(
            document_data=doc_bytes,
            private_key_pem=priv_pem,
            passphrase=passphrase,
            hash_algo=hash_algo,
            signer_identifier=signer_name,
            document_name=doc_file.filename,
        )

        return jsonify({
            "success": True,
            "document_name": doc_file.filename,
            "document_hash": sign_result["document_hash"],
            "signature_base64": sign_result["signature_base64"],
            "key_fingerprint": sign_result["key_fingerprint"],
            "key_algorithm": sign_result["key_algorithm"],
            "manifest": sign_result["manifest"],
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Signing error: {str(e)}"}), 400


@app.route("/api/verify", methods=["POST"])
def api_verify():
    """
    Verify document integrity and authenticity.
    Accepts:
    - document (file)
    - public_key (file or form text)
    - signature (file, manifest JSON file, or text string)
    """
    if "document" not in request.files:
        return jsonify({"success": False, "error": "Document file is required"}), 400

    doc_file = request.files["document"]
    doc_bytes = doc_file.read()

    # Public key
    if "public_key_file" in request.files and request.files["public_key_file"].filename:
        pub_pem = request.files["public_key_file"].read()
    elif "public_key_text" in request.form and request.form["public_key_text"].strip():
        pub_pem = request.form["public_key_text"].strip().encode("utf-8")
    else:
        return jsonify({"success": False, "error": "Public key is required"}), 400

    # Signature or manifest
    sig_input = None
    if "manifest_file" in request.files and request.files["manifest_file"].filename:
        try:
            man = json.loads(request.files["manifest_file"].read().decode("utf-8"))
            sig_input = man.get("signature_base64")
        except Exception as e:
            return jsonify({"success": False, "error": f"Invalid manifest JSON: {str(e)}"}), 400
    elif "signature_file" in request.files and request.files["signature_file"].filename:
        sig_input = request.files["signature_file"].read()
    elif "signature_text" in request.form and request.form["signature_text"].strip():
        sig_input = request.form["signature_text"].strip()
        # Could be JSON manifest pasted into signature text
        if sig_input.startswith("{") and "signature_base64" in sig_input:
            try:
                parsed = json.loads(sig_input)
                sig_input = parsed.get("signature_base64", sig_input)
            except Exception:
                pass
    else:
        return jsonify({"success": False, "error": "Signature or audit manifest is required"}), 400

    hash_algo = request.form.get("hash_algo", "SHA-256")

    try:
        result: VerificationResult = CryptoEngine.verify(
            document_data=doc_bytes,
            signature=sig_input,
            public_key_pem=pub_pem,
            hash_algo=hash_algo,
        )

        return jsonify({
            "success": True,
            "verification": result.to_dict(),
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Verification error: {str(e)}"}), 400


@app.route("/api/tamper-lab", methods=["POST"])
def api_tamper_lab():
    """
    Demonstrate real-time tamper detection by modifying bytes and testing signature.
    """
    if "document" not in request.files:
        return jsonify({"success": False, "error": "Document file is required"}), 400

    doc_file = request.files["document"]
    doc_bytes = doc_file.read()

    # Private key for signing
    if "private_key_file" in request.files and request.files["private_key_file"].filename:
        priv_pem = request.files["private_key_file"].read()
    elif "private_key_text" in request.form and request.form["private_key_text"].strip():
        priv_pem = request.form["private_key_text"].strip().encode("utf-8")
    else:
        return jsonify({"success": False, "error": "Private key is required"}), 400

    # Public key
    if "public_key_file" in request.files and request.files["public_key_file"].filename:
        pub_pem = request.files["public_key_file"].read()
    elif "public_key_text" in request.form and request.form["public_key_text"].strip():
        pub_pem = request.form["public_key_text"].strip().encode("utf-8")
    else:
        try:
            priv_obj = CryptoEngine.load_private_key(priv_pem)
            pub_pem = priv_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception:
            return jsonify({"success": False, "error": "Public key required or private key invalid"}), 400

    tamper_pos = int(request.form.get("tamper_position", 0))

    try:
        sign_res = CryptoEngine.sign(doc_bytes, priv_pem)
        sim = CryptoEngine.simulate_tampering(
            doc_bytes,
            sign_res["signature_bytes"],
            pub_pem,
            tamper_position=tamper_pos,
        )
        return jsonify({"success": True, "tamper_result": sim})
    except Exception as e:
        return jsonify({"success": False, "error": f"Tamper lab error: {str(e)}"}), 400


@app.route("/api/download-sample", methods=["GET"])
def api_download_sample():
    """Provide downloadable sample contract."""
    if SAMPLE_DOC_PATH.exists():
        return send_file(SAMPLE_DOC_PATH, as_attachment=True, download_name="sample_contract.txt")
    return jsonify({"error": "Sample document not found"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Digital Signature & Verification Server on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
