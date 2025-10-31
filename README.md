# PQC JWT Python Library

A comprehensive Python library for generating, managing, signing, and verifying **Post-Quantum Cryptography (PQC) JSON Web Tokens (JWTs)**. Supports ML-DSA (Dilithium), Falcon, and SPHINCS+ digital signature algorithms via the `pqcrypto` package.

This library encapsulates key management and JWT logic, making it easy to integrate **quantum-resistant signatures** into your application's authentication flow.

---

## 🚀 Features

- **Post-Quantum Ready:** Implements NIST-standardized ML-DSA, Falcon padded, and SPHINCS+ signature algorithms for quantum-safe JWTs
- **Multiple Algorithm Support:** Handles multiple security levels and schemes:
  - **ML-DSA** (Dilithium): ML-DSA-44, ML-DSA-65, ML-DSA-87
  - **Falcon Padded**: Falcon-512, Falcon-1024  
  - **SPHINCS+**: Multiple variants with SHA2 and SHAKE hashing
- **Flexible Key Storage:** Save/load key pairs in multiple formats:
  - `pem`: Base64 with generic PEM headers
  - `pub`: Simple public key in hex format
  - `bin`: Raw binary key bytes
- **Publisher/Consumer Roles:** 
  - **Publisher**: Generates keys and signs JWTs  
  - **Consumer**: Loads public keys and verifies JWTs
- **Standard JWT Claims Validation:** Automatically validates `exp`, `nbf`, and `iat` claims
- **Comprehensive Error Handling:** Detailed exceptions for all error scenarios

---

## Requirements

- Python 3.7 or higher
- `pqcrypto` package

```bash
pip install pqcrypto
```

---

## Installation

### From PyPI
```bash
pip install pqjwt
```

### From Source
```bash
git clone https://github.com/your-username/pqjwt.git
cd pqjwt
pip install -e .
```

---

## Quick Start

### Basic Usage

```python
import time
from pqjwt import create_publisher, create_consumer

# Publisher: generates keys if missing, signs JWTs
publisher = create_publisher(
    key_dir="./keys", 
    algorithm="ML-DSA-44", 
    key_format="pem"
)

# Create JWT payload with standard claims
payload = {
    "user_id": 123, 
    "role": "admin", 
    "iat": int(time.time()),  # Issued at
    "exp": int(time.time()) + 3600  # Expires in 1 hour
}

# Sign and encode JWT
jwt_token = publisher.encode(payload)
print("Generated JWT:", jwt_token)

# Consumer: loads public key, verifies JWT
consumer = create_consumer(
    key_dir="./keys", 
    algorithm="ML-DSA-44", 
    key_format="pem"
)

try:
    headers, claims = consumer.decode(jwt_token)
    print("✅ JWT is valid!")
    print("Headers:", headers)
    print("Claims:", claims)
except Exception as e:
    print("❌ Verification failed:", e)
```

### Advanced Usage with Custom Headers

```python
from pqjwt import create_publisher

publisher = create_publisher(algorithm="Falcon-512")

# Custom JWT headers
custom_headers = {
    "alg": "Falcon512",
    "typ": "JWT", 
    "kid": "key-001"  # Key ID for key rotation
}

payload = {
    "sub": "user@example.com",
    "scope": "read write admin",
    "exp": int(time.time()) + 7200
}

jwt_token = publisher.encode(payload, headers=custom_headers)
print("JWT with custom headers:", jwt_token)
```

---

## Supported Algorithms

### ML-DSA (Dilithium) - NIST Standardized
| Algorithm | JWT Header | Security Level | Description |
|-----------|------------|----------------|-------------|
| `ML-DSA-44` | `Dilithium2` | Level 2 | Balanced security/performance |
| `ML-DSA-65` | `Dilithium3` | Level 3 | Higher security |
| `ML-DSA-87` | `Dilithium5` | Level 5 | Highest security |

### Falcon Padded - Timing Attack Resistant
| Algorithm | JWT Header | Security Level | Signature Size |
|-----------|------------|----------------|----------------|
| `Falcon-512` | `Falcon512` | Level 1 | ~690 bytes |
| `Falcon-1024` | `Falcon1024` | Level 5 | ~1330 bytes |

### SPHINCS+ - Hash-Based Security
| Algorithm | JWT Header | Security Level | Signature Size |
|-----------|------------|----------------|----------------|
| `SPHINCS+-SHA2-128f-simple` | `SphincsSha2128f` | Level 1 | ~17KB |
| `SPHINCS+-SHA2-128s-simple` | `SphincsSha2128s` | Level 1 | ~8KB |
| `SPHINCS+-SHA2-192f-simple` | `SphincsSha2192f` | Level 3 | ~35KB |
| `SPHINCS+-SHA2-192s-simple` | `SphincsSha2192s` | Level 3 | ~16KB |
| `SPHINCS+-SHA2-256f-simple` | `SphincsSha2256f` | Level 5 | ~49KB |
| `SPHINCS+-SHA2-256s-simple` | `SphincsSha2256s` | Level 5 | ~22KB |

*Plus SHAKE variants for all SPHINCS+ algorithms*

---

## Key Management

### Key Formats

#### PEM Format (Default)
```python
# Keys stored as:
# - ml-dsa-44_public.pem
# - ml-dsa-44_private.pem

publisher = create_publisher(
    key_dir="./keys",
    algorithm="ML-DSA-44", 
    key_format="pem"  # Default
)
```

Example PEM file:
```
-----BEGIN PUBLIC KEY-----
MOCK_BASE64_DATA_HERE
-----END PUBLIC KEY-----
```

#### PUB Format (Public Key Only)
```python
# Public key stored as:
# - ml-dsa-44_public.pub

publisher = create_publisher(
    key_dir="./keys",
    algorithm="ML-DSA-44",
    key_format="pub"
)
```

Example PUB file:
```
ML-DSA-44 PUBLIC KEY
a1b2c3d4e5f6... (hex encoded key)
```

#### BIN Format (Raw Binary)
```python
# Keys stored as raw binary:
# - ml-dsa-44_public.bin
# - ml-dsa-44_private.bin

publisher = create_publisher(
    key_dir="./keys",
    algorithm="ML-DSA-44",
    key_format="bin"
)
```

### Manual Key Management

```python
from pqjwt import JWTKeyManager

# Save keys manually
public_key = b"..."  # Raw public key bytes
JWTKeyManager.save_key(
    public_key, 
    "my_key.pem", 
    format_type="pem", 
    key_type="public",
    algorithm="ML-DSA-44"
)

# Load keys manually
loaded_key, algorithm = JWTKeyManager.load_key(
    "my_key.pem", 
    format_type="pem", 
    key_type="public"
)
```

---

## API Reference

### JWTManager Class

Main class for JWT operations.

#### Initialization
```python
JWTManager(
    mode="publisher",      # "publisher" or "consumer"
    key_dir="./keys",      # Directory for key storage
    key_format="pem",      # "pem", "pub", or "bin"
    algorithm="ML-DSA-44"  # Any supported algorithm
)
```

#### Methods

##### `encode(payload, headers=None)`
Signs a payload and returns JWT string.

```python
publisher = create_publisher()
jwt = publisher.encode(
    payload={"user": "123", "exp": ...},
    headers={"alg": "Dilithium2", "typ": "JWT"}
)
```

##### `decode(jwt, validate_claims=True, clock_skew=5)`
Verifies JWT and returns (headers, payload).

```python
consumer = create_consumer()
headers, payload = consumer.decode(
    jwt_token,
    validate_claims=True,  # Validate exp, nbf, iat
    clock_skew=5           # Allow 5 seconds clock difference
)
```

##### `verify(jwt)`
Quick verification without full decoding.

```python
is_valid = consumer.verify(jwt_token)
```

##### `get_public_key(output_format="bytes")`
Get public key in different formats.

```python
key_bytes = publisher.get_public_key("bytes")
key_hex = publisher.get_public_key("hex") 
key_pem = publisher.get_public_key("pem")
```

##### `export_public_key(file_path, format_type=None)`
Export public key to file.

```python
publisher.export_public_key("backup_key.pem", "pem")
```

### Factory Functions

#### `create_publisher(key_dir="./keys", key_format="pem", algorithm="ML-DSA-44")`
Creates a JWTManager instance in publisher mode.

#### `create_consumer(key_dir="./keys", key_format="pem", algorithm="ML-DSA-44")`
Creates a JWTManager instance in consumer mode.

### JWTKeyManager Class

Static utility methods for key management.

#### `get_supported_algorithms()`
Returns list of all supported algorithms.

```python
algorithms = JWTKeyManager.get_supported_algorithms()
print("Supported:", algorithms)
```

#### `get_jwt_header_name(algorithm)`
Maps algorithm name to JWT header.

```python
header = JWTKeyManager.get_jwt_header_name("ML-DSA-44")
print(header)  # "Dilithium2"
```

#### `get_algorithm_from_jwt_header(jwt_header)`
Maps JWT header back to algorithm name.

```python
algorithm = JWTKeyManager.get_algorithm_from_jwt_header("Dilithium2")
print(algorithm)  # "ML-DSA-44"
```

---

## Error Handling

The library provides detailed exceptions for all error scenarios:

```python
from pqjwt import (
    JWTExpiredError,
    JWTSignatureError, 
    JWTValidationError,
    AlgorithmNotSupportedError,
    CryptoKeyError
)

try:
    headers, payload = consumer.decode(jwt_token)
except JWTExpiredError as e:
    print("Token expired:", e)
except JWTSignatureError as e:
    print("Invalid signature:", e)
except JWTValidationError as e:
    print("Validation failed:", e)
except AlgorithmNotSupportedError as e:
    print("Algorithm not supported:", e)
```

### Available Exceptions

- **`JWTExpiredError`**: Token has expired
- **`JWTSignatureError`**: Signature verification failed
- **`JWTValidationError`**: General validation failure (malformed token, invalid claims)
- **`JWTDecodeError`**: Error decoding Base64 or JSON
- **`CryptoKeyError`**: Key-related errors (missing private key, etc.)
- **`AlgorithmNotSupportedError`**: Unsupported algorithm specified
- **`KeyFormatError`**: Invalid key format

---

## Security Considerations

### Algorithm Security
- **ML-DSA**: NIST Standardized (FIPS 204), no known practical attacks
- **Falcon Padded**: Mitigates timing attacks present in basic Falcon variants  
- **SPHINCS+**: Conservative hash-based security, very large signatures but resistant to lattice attacks

### Key Protection
- Store private keys securely with appropriate file permissions
- Never expose private keys in client applications
- Use different key directories for different environments

### Best Practices
```python
# Use appropriate security levels
production_algorithm = "ML-DSA-65"  # Level 3 security
testing_algorithm = "ML-DSA-44"     # Level 2 security

# Set reasonable expiration times
payload = {
    "exp": int(time.time()) + 3600,  # 1 hour for access tokens
    "iat": int(time.time())
}
```

---

## Testing

Run the test suite:

```bash
python -m pytest tests/ -v
```

Or run the test file directly:

```bash
python tests/test.py
```

---

## 📝 File Naming Convention

Keys are automatically named based on algorithm and format:

| Algorithm | Format | Public Key File | Private Key File |
|-----------|--------|-----------------|------------------|
| ML-DSA-44 | pem | `ml-dsa-44_public.pem` | `ml-dsa-44_private.pem` |
| Falcon-512 | pub | `falcon-512_public.pub` | `falcon-512_private.pem` |
| SPHINCS+-SHA2-128f-simple | bin | `sphincs+-sha2-128f-simple_public.bin` | `sphincs+-sha2-128f-simple_private.bin` |

> Note: Private keys are always stored in PEM format when using PUB format for public keys.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🆘 Troubleshooting

### Common Issues

**"Algorithm not supported" Error**
- Check algorithm name spelling
- Use `JWTKeyManager.get_supported_algorithms()` to see available options

**"Public key not found" Error**
- Ensure key files exist in the specified directory
- Check file naming convention matches algorithm

**Signature Verification Fails**
- Ensure same algorithm used for signing and verification
- Check clock skew for time-based claims

**Performance Issues with SPHINCS+**
- SPHINCS+ has large signature sizes, consider using ML-DSA or Falcon for high-throughput applications

---

## 📞 Support

For bugs and feature requests, please open an issue on GitHub.

For security vulnerabilities, please contact the maintainers directly.
```