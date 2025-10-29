
# PQC JWT Python Library

A comprehensive Python library for generating, managing, signing, and verifying **Post-Quantum Cryptography (PQC) JSON Web Tokens (JWTs)**.  
Supports ML-DSA (Dilithium), Falcon, and SPHINCS+ digital signature algorithms via the `pqcrypto` package.

This library encapsulates key management and JWT logic, making it easy to integrate **quantum-resistant signatures** into your application's authentication flow.

---

## Features

- **Post-Quantum Ready:** Implements NIST-standardized ML-DSA, Falcon padded, and SPHINCS+ signature algorithms for quantum-safe JWTs.
- **Multiple Algorithm Support:** Handles multiple security levels and schemes:
  - ML-DSA-44 (Dilithium2)
  - ML-DSA-65 (Dilithium3)
  - ML-DSA-87 (Dilithium5)
  - Falcon-512, Falcon-1024
  - SPHINCS+ variants (SHA2-128f/s, SHA2-192f/s, SHA2-256f/s, SHAKE-128f/s, SHAKE-192f/s, SHAKE-256f/s)
- **Flexible Key Storage:** Save/load key pairs in formats:
  - `pem`: Base64 with generic PEM headers (BEGIN/END PRIVATE/PUBLIC KEY)
  - `pub`: Simple public key in hex
  - `bin`: Raw binary key bytes
- **Publisher/Consumer Roles:** 
  - **Publisher:** generates keys and signs JWTs  
  - **Consumer:** loads public keys and verifies JWTs
- **Standard JWT Claims Validation:** Automatically validates `exp`, `nbf`, and `iat` claims during decoding.

---

## Requirements

```bash
pip install pqcrypto
```

---

## API Reference

### JWTManager (Main Interface)

Handles initialization, key loading/generation, signing, and verification.

| Parameter   | Type | Default | Description |
|------------|------|---------|-------------|
| mode       | str  | "publisher" | Set `"publisher"` to sign or `"consumer"` to only verify |
| key_dir    | str  | "./keys" | Directory for storing keys |
| key_format | str  | "pem"   | Key storage format (`pem`, `pub`, `bin`) |
| algorithm  | str  | "ML-DSA-44" | PQC algorithm to use (any supported algorithm) |

#### Methods

| Method | Description |
|--------|-------------|
| `encode(payload, headers)` | Signs the payload using the private key and returns the JWT string |
| `decode(jwt, validate_claims=True)` | Verifies the JWT signature and validates claims. Returns `(headers, payload)` |
| `verify(jwt)` | Checks signature and claims validity. Returns `True` or `False` |
| `get_public_key(output_format="bytes")` | Returns public key in `bytes`, `hex`, or `pem` |
| `export_public_key(file_path, format_type=None)` | Saves the public key to a file |

---

### JWTKeyManager (Static Utilities)

Provides low-level key handling and utility methods.

| Method | Description |
|--------|-------------|
| `get_supported_algorithms()` | Returns a list of all supported PQC algorithms |
| `save_key(key, file_path, ...)` | Saves a key (bytes) in `pem`, `pub`, or `bin` format |
| `load_key(file_path, ...)` | Loads a key from file; auto-detects format if `"auto"` |
| `bytes_to_pem(key_bytes, ...)` | Converts raw key bytes into a PEM string |

---

## Example Usage

```python
import time
from pqjwt import create_publisher, create_consumer

# Publisher: generates keys if missing, signs JWTs
publisher = create_publisher(key_dir="./keys", algorithm="ML-DSA-65", key_format="pem")
payload = {"user_id": 123, "role": "admin", "exp": int(time.time()) + 3600}
jwt_token = publisher.encode(payload)
print("Generated JWT:", jwt_token)

# Consumer: loads only the public key, verifies JWT
consumer = create_consumer(key_dir="./keys", algorithm="ML-DSA-65", key_format="pem")
try:
    headers, claims = consumer.decode(jwt_token)
    print("JWT is valid!")
    print("Claims:", claims)
except ValueError as e:
    print("Verification failed:", e)
```

---

## Key File Naming Convention

Keys are stored in `key_dir` to prevent conflicts:

| Key Type     | File Path Example (ML-DSA-44, pem format) |
|-------------|-------------------------------------------|
| Public Key  | `ml-dsa-44_public.pem`                     |
| Private Key | `ml-dsa-44_private.pem`                    |

> Note: `.pub` extension may be used if `pub` format is selected.

---

## Security Notice

- **PEM Headers:** Keys are stored in Base64 between generic PEM headers. Full PKCS#8/SPKI compliance is not enforced (ASN.1 wrapping is needed for standard compliance).
- **Key Protection:** Private keys must be stored securely (e.g., `chmod 600`) and never exposed publicly.
- **Algorithm Safety:**  
  - ML-DSA: NIST standardized, no known attacks.  
  - Falcon Padded: Resists timing attacks.  
  - SPHINCS+: Conservative hash-based security, very large signatures, lattice-resistant.

---