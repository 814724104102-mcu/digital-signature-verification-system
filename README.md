# Digital Signature and Document Verification System

A secure, modern, full-featured cryptographic application for generating digital signatures, verifying document authenticity, and detecting unauthorized document tampering.

Implemented in Python utilizing standard public-key cryptography (RSA-PSS & ECDSA) and cryptographic hashing (SHA-256 / SHA-512).

---

## Key Features

- **Asymmetric Cryptography Core**:
  - RSA (2048-bit / 4096-bit) using PKCS#8 formatting and **PSS** (Probabilistic Signature Scheme) padding.
  - ECDSA with NIST P-256 (`secp256r1`) and Koblitz (`secp256k1`) curves.
  - Optional passphrase encryption for private keys using AES-256.
- **Integrity & Verification**:
  - Memory-safe chunked streaming SHA-256 / SHA-512 hashing (supports arbitrary file sizes).
  - Raw binary signature output (`.sig`) and Base64-encoded audit manifests (`.json`).
  - Key fingerprint generation (SHA-256 colon-delimited hex digest).
- **Interactive Web Interface**:
  - Key generation dashboard with 1-click PEM export and clipboard utilities.
  - Document signing workflow supporting drag-and-drop file uploads.
  - Verification certificate viewer with visual indicators (Authentic vs Tampered).
  - Live **Tamper Resistance Lab** demonstrating mathematical rejection upon single-byte modification.
  - In-session audit log table tracking verification history.
- **Command Line Utility (`cli.py`)**:
  - Headless terminal tool for automated scripting, CI/CD pipelines, and auditing.
- **Automated Test Suite**:
  - Comprehensive unit tests covering key generation, signing, verification, and tamper rejection.

---

## Architectural Workflow

```text
               +-----------------------------+
               |        Original File        |
               | (PDF, DOCX, TXT, Binaries)  |
               +--------------+--------------+
                              |
                              v
                      [ SHA-256 Digest ]
                              |
                              v
    +------------------+      |
    | Signer's Private |      |
    |    Key (PEM)     | ---->+---> [ RSA-PSS / ECDSA Sign ]
    +------------------+                 |
                                         v
                              +--------------------+
                              |  Digital Signature |
                              |  & Audit Manifest  |
                              +---------+----------+
                                        |
  [ Transmitted File ]                  |
           +                            |
  [ Signer's Public Key ]               |
           |                            |
           v                            v
    [ SHA-256 Digest ] <----+ [ Verify Signature ]
                            |
                   Does Hash Match?
                   /              \
               YES                 NO
               /                    \
     +-------------------+    +--------------------+
     | Document Authentic|    | Tampered / Invalid |
     |    & Untampered   |    |    Verification    |
     +-------------------+    +--------------------+
```

---

## Project Structure

```text
.
├── core/
│   ├── __init__.py
│   └── crypto_engine.py       # Core asymmetric cryptographic engine
├── static/
│   ├── css/
│   │   └── style.css          # Frontend styling
│   └── js/
│       └── app.js             # Client-side asynchronous interaction
├── templates/
│   └── index.html             # Web dashboard
├── sample_docs/
│   └── sample_contract.txt    # Sample document for verification testing
├── tests/
│   ├── __init__.py
│   ├── test_crypto.py         # Unit tests for cryptographic engine
│   └── test_web_api.py        # Web API integration tests
├── app.py                     # Flask web server and REST API
├── cli.py                     # Command-line interface
├── requirements.txt           # Project dependencies
├── .gitignore                 # Git ignore rules
├── LICENSE                    # MIT License
└── README.md                  # Project documentation
```

---

## Getting Started

### 1. Prerequisites & Installation

Clone the repository and install the required dependencies:

```bash
git clone https://github.com/814724104102-mcu/digital-signature-verification-system.git
cd digital-signature-verification-system

# Install dependencies
pip install -r requirements.txt
```

### 2. Running the Automated Tests

Run the test suite to ensure all cryptographic properties pass:

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

### 3. Launching the Web Interface

Start the local Flask application:

```bash
python3 app.py
```

Open `http://127.0.0.1:5000` in your web browser.

---

## Command Line Interface (CLI) Usage

The project includes an executable CLI (`cli.py`) for automated terminal operations.

### Generate Key Pair
```bash
python3 cli.py keygen --algo RSA-2048 --out-dir ./keys --prefix mykey
```

### Compute Document Digest
```bash
python3 cli.py hash --doc sample_docs/sample_contract.txt --algo SHA-256
```

### Sign a Document
```bash
python3 cli.py sign \
  --doc sample_docs/sample_contract.txt \
  --key keys/mykey_private.pem \
  --signer "Alice" \
  --out-sig contract.sig \
  --out-manifest contract.manifest.json
```

### Verify a Document
```bash
python3 cli.py verify \
  --doc sample_docs/sample_contract.txt \
  --key keys/mykey_public.pem \
  --manifest contract.manifest.json
```

### Run Live Tamper Demonstration
```bash
python3 cli.py tamper-demo \
  --doc sample_docs/sample_contract.txt \
  --key keys/mykey_private.pem \
  --pubkey keys/mykey_public.pem
```

---

## Cryptographic Design Details

- **RSA-PSS (Probabilistic Signature Scheme)**: Unlike legacy PKCS#1 v1.5 padding which is deterministic and vulnerable to padding oracle attacks, PSS incorporates a cryptographic salt and mask generation function (MGF1), providing provable security under the RSA assumption.
- **ECDSA (Elliptic Curve Digital Signature Algorithm)**: Offers equivalent security to 2048/3072-bit RSA with significantly smaller keys and lower computational overhead, utilizing SECP256R1 and SECP256K1 curves.
- **Avalanche Effect**: Modern cryptographic hash functions guarantee that modifying even a single character or byte produces an unpredictable, vastly different digest, making unauthorized document alterations immediately detectable.

---

## License

This project is open-source and released under the [MIT License](LICENSE).
