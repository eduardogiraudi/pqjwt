# PQJWT - Post-Quantum JWT JavaScript Library

A comprehensive JavaScript/Node.js library for generating, managing, signing, and verifying **Post-Quantum Cryptography (PQC) JSON Web Tokens (JWTs)**. Supports ML-DSA (Dilithium) and SLH‑DSA (SPHINCS+) digital signature algorithms via the `@noble/post-quantum` package.

This library provides quantum-resistant JWT authentication with a simple, intuitive API, making it easy to secure your applications against future quantum computing threats.

---

## Features

* **🛡️ Post-Quantum Ready**: Implements NIST-standardized ML-DSA (Dilithium) and SPHINCS+ (SLH‑DSA) signature algorithms for quantum-safe JWTs.
* **🔐 Multiple Security Levels**: Supports ML-DSA-44/65/87 and 12 SPHINCS+ variants for different security/performance trade-offs.
* **📁 Flexible Key Storage**: Save/load key pairs in multiple formats:

  * `pem`: Base64 with PEM headers (raw bytes, not PKCS#8/SPKI)
  * `bin`: Raw binary key bytes
* **👥 Publisher/Consumer Roles**:

  * **Publisher**: Generates keys and signs JWTs
  * **Consumer**: Loads public keys and verifies JWTs
* **⏰ Standard JWT Claims**: Automatic validation of `exp`, `nbf`, and `iat` claims
* **🚨 Comprehensive Error Handling**: Detailed exceptions for all error scenarios
* **🌐 Universal Compatibility**: Works with Node.js, browsers, and other JavaScript environments

---

## Requirements

* Node.js 18.0 or higher
* Or any modern JavaScript environment with crypto support

---

## Installation

### npm

```bash
npm install pqjwt
```

### yarn

```bash
yarn add pqjwt
```

### pnpm

```bash
pnpm add pqjwt
```

---

## Quick Start

### Publisher Example

```javascript
import { createPublisher, createConsumer } from 'pqjwt';

// Publisher: generates keys if missing, signs JWTs
const publisher = createPublisher('./keys', 'pem', 'ML-DSA-65');

// JWT payload with standard claims
const payload = {
  userId: 123,
  role: 'admin',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour expiration
};

// Sign JWT
const jwtToken = publisher.encode(payload);
console.log('Generated JWT:', jwtToken);
```

### Consumer Example

```javascript
const consumer = createConsumer('./keys', 'pem', 'ML-DSA-65');

try {
  const { headers, payload: claims } = consumer.decode(jwtToken);
  console.log('✅ JWT is valid!');
  console.log('Headers:', headers);
  console.log('Claims:', claims);
} catch (error) {
  console.log('❌ Verification failed:', error.message);
}
```

### SPHINCS+ Example

```javascript
const sphincsPublisher = createPublisher('./keys', 'pem', 'SPHINCS+-SHAKE-256f');
const token = sphincsPublisher.encode({ user: 'alice', exp: Math.floor(Date.now()/1000)+3600 });
console.log('JWT SPHINCS+ token:', token);
```

---

## Supported Algorithms

### ML-DSA (Dilithium) - NIST Standardized

| Algorithm | JWT Header | Security Level | Description                   |
| --------- | ---------- | -------------- | ----------------------------- |
| ML-DSA-44 | Dilithium2 | Level 2        | Balanced security/performance |
| ML-DSA-65 | Dilithium3 | Level 3        | Higher security (Recommended) |
| ML-DSA-87 | Dilithium5 | Level 5        | Maximum security              |

### SLH‑DSA (SPHINCS+) Variants

| Algorithm           | JWT Header       | Description   |
| ------------------- | ---------------- | ------------- |
| SPHINCS+-SHA2-128f  | SphincsSha2128f  | Fast variant  |
| SPHINCS+-SHA2-128s  | SphincsSha2128s  | Small variant |
| SPHINCS+-SHA2-192f  | SphincsSha2192f  | Fast variant  |
| SPHINCS+-SHA2-192s  | SphincsSha2192s  | Small variant |
| SPHINCS+-SHA2-256f  | SphincsSha2256f  | Fast variant  |
| SPHINCS+-SHA2-256s  | SphincsSha2256s  | Small variant |
| SPHINCS+-SHAKE-128f | SphincsShake128f | Fast variant  |
| SPHINCS+-SHAKE-128s | SphincsShake128s | Small variant |
| SPHINCS+-SHAKE-192f | SphincsShake192f | Fast variant  |
| SPHINCS+-SHAKE-192s | SphincsShake192s | Small variant |
| SPHINCS+-SHAKE-256f | SphincsShake256f | Fast variant  |
| SPHINCS+-SHAKE-256s | SphincsShake256s | Small variant |

> **Future Support**: Falcon-512 and Falcon-1024 algorithms will be supported in future releases for additional post-quantum security options.

---

## Key Format Disclaimer
**Important Note on PEM Format**: Current PEM implementation uses generic headers (`BEGIN PUBLIC KEY`/`BEGIN PRIVATE KEY`) with base64-encoded raw key bytes. Full PKCS#8 (private keys) and SPKI (public keys) ASN.1 encoding is **not yet implemented**. This means:
- Generated PEM files are **not standards-compliant** with OpenSSL and other PKI tools
- Keys are stored in a **library-specific format** that only works with this library
- **Interoperability with external systems is limited**

### Manual Key Management

```javascript
import { JWTKeyManager } from 'pqjwt';

const key = JWTKeyManager.loadKey('my_key.pem', 'auto', 'public');
JWTKeyManager.saveKey(key, 'saved_key.pem', 'pem', 'public');
```

---

## Error Handling

Exceptions include:

* `JWTExpiredError` – Token expired
* `JWTSignatureError` – Signature verification failed
* `JWTValidationError` – Validation failure (malformed token, invalid claims)
* `JWTDecodeError` – Error decoding Base64/JSON
* `AlgorithmNotSupportedError` – Unsupported algorithm specified

```javascript
try {
  consumer.decode(token);
} catch (error) {
  if (error instanceof JWTExpiredError) console.log('Token expired');
}
```

---

## Security Considerations

* Use strong algorithms (`ML-DSA-65` or SPHINCS+ variants) for production
* Store private keys securely
* Set reasonable expiration times and validate claims
* Rotate keys when necessary

---

## Examples

### Express.js Middleware

```javascript
import express from 'express';
import { createConsumer } from 'pqjwt';

const consumer = createConsumer('./keys', 'pem', 'ML-DSA-65');
const app = express();

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  try {
    const { payload } = consumer.decode(token, true);
    req.user = payload;
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Access granted', user: req.user });
});
```

---

## File Naming Convention

Keys are automatically named based on algorithm and format:


| Algorithm           | Format  | Public Key                      | Private Key |                                  |       |
| ------------------- | ------- | ------------------------------- | ----------- | -------------------------------- | ----- |
| ML-DSA-44           | pem/bin | `ml_dsa_44_public.{pem          | bin}`       | `ml_dsa_44_private.{pem          | bin}` |
| ML-DSA-65           | pem/bin | `ml_dsa_65_public.{pem          | bin}`       | `ml_dsa_65_private.{pem          | bin}` |
| ML-DSA-87           | pem/bin | `ml_dsa_87_public.{pem          | bin}`       | `ml_dsa_87_private.{pem          | bin}` |
| SPHINCS+-SHA2-128f  | pem/bin | `sphincs_sha2_128f_public.{pem  | bin}`       | `sphincs_sha2_128f_private.{pem  | bin}` |
| SPHINCS+-SHA2-128s  | pem/bin | `sphincs_sha2_128s_public.{pem  | bin}`       | `sphincs_sha2_128s_private.{pem  | bin}` |
| SPHINCS+-SHA2-192f  | pem/bin | `sphincs_sha2_192f_public.{pem  | bin}`       | `sphincs_sha2_192f_private.{pem  | bin}` |
| SPHINCS+-SHA2-192s  | pem/bin | `sphincs_sha2_192s_public.{pem  | bin}`       | `sphincs_sha2_192s_private.{pem  | bin}` |
| SPHINCS+-SHA2-256f  | pem/bin | `sphincs_sha2_256f_public.{pem  | bin}`       | `sphincs_sha2_256f_private.{pem  | bin}` |
| SPHINCS+-SHA2-256s  | pem/bin | `sphincs_sha2_256s_public.{pem  | bin}`       | `sphincs_sha2_256s_private.{pem  | bin}` |
| SPHINCS+-SHAKE-128f | pem/bin | `sphincs_shake_128f_public.{pem | bin}`       | `sphincs_shake_128f_private.{pem | bin}` |
| SPHINCS+-SHAKE-128s | pem/bin | `sphincs_shake_128s_public.{pem | bin}`       | `sphincs_shake_128s_private.{pem | bin}` |
| SPHINCS+-SHAKE-192f | pem/bin | `sphincs_shake_192f_public.{pem | bin}`       | `sphincs_shake_192f_private.{pem | bin}` |
| SPHINCS+-SHAKE-192s | pem/bin | `sphincs_shake_192s_public.{pem | bin}`       | `sphincs_shake_192s_private.{pem | bin}` |
| SPHINCS+-SHAKE-256f | pem/bin | `sphincs_shake_256f_public.{pem | bin}`       | `sphincs_shake_256f_private.{pem | bin}` |
| SPHINCS+-SHAKE-256s | pem/bin | `sphincs_shake_256s_public.{pem | bin}`       | `sphincs_shake_256s_private.{pem | bin}` |

> **Note**: The `{pem|bin}` placeholder indicates that either PEM or binary format can be used depending on your configuration.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

MIT License - see [LICENSE](../LICENSE)

---

## Support

* **Issues**: Open an issue on GitHub
* **Security**: Contact maintainers directly for vulnerabilities
* **Questions**: Check issues or discussions

---

## Acknowledgments

Built with [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum), implementing ML-DSA (FIPS 204) and SPHINCS+ (SLH‑DSA) for post-quantum JWTs.

---

