
# PQC JWT Python Library

A comprehensive Python library for generating, managing, signing, and verifying Post-Quantum Cryptography (PQC) JSON Web Tokens (JWTs) using the ML-DSA (formerly Dilithium) digital signature algorithms.

This library encapsulates key management and JWT logic, making it easy to integrate quantum-resistant signatures into your application's authentication flow.

## Features

- **Post-Quantum Ready:** Implements the NIST-standardized ML-DSA (Dilithium) signature algorithm for quantum-safe JWTs, via the `pqcrypto` package.

- **Multiple Algorithm Support:** Seamlessly handles three security levels:
  - `ML-DSA-44` (Corresponds to Dilithium2)
  - `ML-DSA-65` (Corresponds to Dilithium3)
  - `ML-DSA-87` (Corresponds to Dilithium5)

- **Flexible Key Storage:** Supports saving and loading key pairs in three formats:
  - `pem`: Base64 encoded, utilizing generic PKCS#8/SPKI-like headers (BEGIN/END PRIVATE/PUBLIC KEY).
  - `pub`: Simple public key format (plaintext hex).
  - `bin`: Raw binary key bytes.

- **Publisher/Consumer Roles:** Dedicated modes for key generation/signing (Publisher) and public key loading/verification (Consumer).

- **Standard JWT Claims Validation:** Automatically validates `exp` (Expiration Time) and `nbf` (Not Before) claims during decoding.

## 🧩 Requirements

This library relies on the following external package for the core cryptographic functions:

```bash
pip install pqcrypto
```

## 📚 API Reference

The core functionality is provided by two classes: `JWTKeyManager` (static utility methods) and `JWTManager` (main JWT interface).

### 1. JWTManager (Main Interface)

This class handles initialization, key loading/generation, and the core encode/decode logic.

| Parameter     | Type   | Default       | Description                                                                 |
|---------------|--------|---------------|-----------------------------------------------------------------------------|
| mode          | str    | "publisher"   | Set to `"publisher"` (to sign/verify) or `"consumer"` (to only verify).    |
| key_dir       | str    | ./keys        | Directory for key storage.                                                  |
| key_format    | str    | "pem"         | Storage format: `"pem"`, `"pub"`, or `"bin"`.                              |
| algorithm     | str    | "ML-DSA-44"   | PQC algorithm to use (`ML-DSA-44`, `ML-DSA-65`, or `ML-DSA-87`).          |

#### Methods

| Method                          | Description |
|---------------------------------|------------|
| `encode(payload, headers)`       | Signs the payload using the private key and returns the full JWT string. |
| `decode(jwt, validate_claims=True)` | Verifies the JWT signature and validates claims (e.g., `exp`). Returns `(headers, payload)`. |
| `verify(jwt)`                    | Checks the signature and claims validity. Returns `True` or `False`. |
| `get_public_key(output_format)`  | Returns the public key in bytes, hex, or PEM string format. |
| `export_public_key(file_path, format_type)` | Saves the public key to a specified file path. |

#### Example

```python
import time
from jwt_library import JWTManager

# Publisher (Generates keys if they don't exist, and signs)
publisher = JWTManager(mode="publisher", algorithm="ML-DSA-65", key_format="pem")

# 1. Encode a JWT
payload = {"user_id": 123, "role": "admin", "exp": int(time.time()) + 3600}
jwt_token = publisher.encode(payload)
print("Generated JWT:", jwt_token)

# Consumer (Loads only the public key, and verifies)
consumer = JWTManager(mode="consumer", algorithm="ML-DSA-65", key_format="pem")

# 2. Decode and verify the JWT
try:
    headers, claims = consumer.decode(jwt_token)
    print("\nJWT is valid!")
    print("Claims:", claims)
except ValueError as e:
    print("\nVerification failed:", e)
```

### 2. JWTKeyManager (Static Utilities)

This class contains static methods for low-level key handling.

| Method                  | Description |
|-------------------------|------------|
| `get_supported_algorithms()` | Returns a list of supported ML-DSA algorithms. |
| `save_key(key, file_path, ...)` | Saves a raw key (bytes) to a file in the specified format (`pem`, `pub`, or `bin`). |
| `load_key(file_path, ...)` | Loads a key from a file, automatically detecting the format if specified as `"auto"`. |
| `bytes_to_pem(key_bytes, ...)` | Converts raw key bytes into a PEM-formatted string. |

## ⚙️ Key File Naming Convention

Keys are saved in the `key_dir` using the following convention to prevent conflicts:

| Key Type      | Example Format     | File Path (e.g., ML-DSA-44 in pem format) |
|---------------|-----------------|------------------------------------------|
| Public Key    | `[algorithm]_public.[format]` | `ml-dsa-44_public.pem` |
| Private Key   | `[algorithm]_private.[format]` | `ml-dsa-44_private.pem` |

> **Note on Public Key Naming:** While the pem format is used for storage, the file extension might be automatically set to `.pub` if you explicitly choose the `pub` format during initialization, following common conventions (e.g., SSH).

## ⚠️ Security Notice

- **PKCS#8/SPKI Compliance:** The library currently saves the raw key bytes encoded in Base64 between generic PEM headers (`BEGIN/END PRIVATE/PUBLIC KEY`). For full compliance with PKCS#8 (private) or SPKI (public), these key bytes should be wrapped in an ASN.1 structure including the algorithm OID. This implementation uses generic headers as a preparatory step towards standardization.

- **Key Protection:** Always ensure that your private key files (`ml-dsa-xx_private.pem` or `.bin`) are stored with strict access permissions (e.g., `chmod 600`) and are never exposed publicly.