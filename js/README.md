# PQJWT - Post-Quantum JWT JavaScript Library

A comprehensive JavaScript/Node.js library for generating, managing, signing, and verifying **Post-Quantum Cryptography (PQC) JSON Web Tokens (JWTs)**. Supports ML-DSA (Dilithium) digital signature algorithms via the `@noble/post-quantum` package.

This library provides quantum-resistant JWT authentication with a simple, intuitive API, making it easy to secure your applications against future quantum computing threats.

---

## Features

- **🛡️ Post-Quantum Ready**: Implements NIST-standardized ML-DSA (Dilithium) signature algorithms for quantum-safe JWTs
- **🔐 Multiple Security Levels**: Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 for different security requirements
- **📁 Flexible Key Storage**: Save/load key pairs in multiple formats:
  - `pem`: Base64 with PEM headers
  - `bin`: Raw binary key bytes
- **👥 Publisher/Consumer Roles**: 
  - **Publisher**: Generates keys and signs JWTs  
  - **Consumer**: Loads public keys and verifies JWTs
- **⏰ Standard JWT Claims**: Automatic validation of `exp`, `nbf`, and `iat` claims
- **🚨 Comprehensive Error Handling**: Detailed exceptions for all error scenarios
- **🌐 Universal Compatibility**: Works with Node.js, browsers, and other JavaScript environments

---

## Requirements

- Node.js 18.0 or higher
- Or any modern JavaScript environment with crypto support

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

### Basic Usage

```javascript
import { createPublisher, createConsumer } from 'pqjwt';

// Publisher: generates keys if missing, signs JWTs
const publisher = createPublisher(
  './keys',           // key directory
  'pem',              // key format
  'ML-DSA-65'         // algorithm
);

// Create JWT payload with standard claims
const payload = {
  userId: 123,
  role: 'admin',
  iat: Math.floor(Date.now() / 1000),        // Issued at
  exp: Math.floor(Date.now() / 1000) + 3600  // Expires in 1 hour
};

// Sign and encode JWT
const jwtToken = publisher.encode(payload);
console.log('Generated JWT:', jwtToken);

// Consumer: loads public key, verifies JWT
const consumer = createConsumer(
  './keys',
  'pem', 
  'ML-DSA-65'
);

try {
  const { headers, payload: claims } = consumer.decode(jwtToken);
  console.log('✅ JWT is valid!');
  console.log('Headers:', headers);
  console.log('Claims:', claims);
} catch (error) {
  console.log('❌ Verification failed:', error.message);
}
```

### Simplified API with PQJWT Class

```javascript
import { PQJWT } from 'pqjwt';

// Simple publisher setup
const publisher = new PQJWT({
  mode: 'publisher',
  keyDir: './keys',
  algorithm: 'ML-DSA-65'
});

const token = publisher.sign({
  sub: 'user123',
  scope: 'read write',
  exp: Math.floor(Date.now() / 1000) + 7200
});

console.log('JWT Token:', token);

// Simple consumer verification  
const consumer = new PQJWT({
  mode: 'consumer', 
  keyDir: './keys',
  algorithm: 'ML-DSA-65'
});

const isValid = consumer.isValid(token);
console.log('Token valid:', isValid);
```

### Advanced Usage with Custom Headers

```javascript
import { createPublisher } from 'pqjwt';

const publisher = createPublisher('./keys', 'pem', 'ML-DSA-65');

// Custom JWT headers
const customHeaders = {
  alg: 'Dilithium3',
  typ: 'JWT',
  kid: 'key-001'  // Key ID for key rotation
};

const payload = {
  sub: 'user@example.com',
  scope: 'read write admin',
  exp: Math.floor(Date.now() / 1000) + 7200
};

const jwtToken = publisher.encode(payload, customHeaders);
console.log('JWT with custom headers:', jwtToken);
```

---

## Supported Algorithms

### ML-DSA (Dilithium) - NIST Standardized
| Algorithm | JWT Header | Security Level | Description |
|-----------|------------|----------------|-------------|
| `ML-DSA-44` | `Dilithium2` | Level 2 | Balanced security/performance |
| `ML-DSA-65` | `Dilithium3` | Level 3 | Higher security (Recommended) |
| `ML-DSA-87` | `Dilithium5` | Level 5 | Maximum security |

> **Note**: Currently supports ML-DSA algorithms. Falcon and SPHINCS+ support is planned for future releases.

---

## Key Management

### Key Formats

#### PEM Format (Default)
```javascript
// Keys stored as:
// - ml_dsa_65_public.pem
// - ml_dsa_65_private.pem

const publisher = createPublisher(
  './keys',
  'pem',        // Default format
  'ML-DSA-65'
);
```

Example PEM file:
```
-----BEGIN PUBLIC KEY-----
MOCK_BASE64_DATA_HERE
-----END PUBLIC KEY-----
```

#### BIN Format (Raw Binary)
```javascript
// Keys stored as raw binary:
// - ml_dsa_65_public.bin  
// - ml_dsa_65_private.bin

const publisher = createPublisher(
  './keys',
  'bin',        // Binary format
  'ML-DSA-65'
);
```

### Manual Key Management

```javascript
import { JWTKeyManager } from 'pqjwt';

// Save keys manually
const publicKey = Buffer.from('...'); // Raw public key bytes
JWTKeyManager.saveKey(
  publicKey,
  'my_key.pem',
  'pem',
  'public',
  'ML-DSA-65'
);

// Load keys manually
const { key: loadedKey, algorithm } = JWTKeyManager.loadKey(
  'my_key.pem',
  'pem',
  'public'
);
```

---

## API Reference

### PQJWT Class

Simplified main class for common JWT operations.

#### Initialization
```javascript
new PQJWT({
  mode: 'publisher',      // 'publisher' or 'consumer'
  keyDir: './keys',       // Directory for key storage  
  algorithm: 'ML-DSA-65', // Cryptographic algorithm
  keyFormat: 'pem'        // 'pem' or 'bin'
})
```

#### Methods

##### `sign(payload, headers = null)`
Signs a payload and returns JWT string.

```javascript
const pqjwt = new PQJWT({ mode: 'publisher' });
const jwt = pqjwt.sign(
  { userId: '123', exp: ... },
  { alg: 'Dilithium3', typ: 'JWT' }
);
```

##### `verify(token, validateClaims = true)`
Verifies JWT and returns `{ headers, payload }`.

```javascript
const pqjwt = new PQJWT({ mode: 'consumer' });
const { headers, payload } = pqjwt.verify(
  jwtToken,
  true  // Validate exp, nbf, iat claims
);
```

##### `isValid(token)`
Quick verification without full decoding.

```javascript
const isValid = pqjwt.isValid(jwtToken);
```

##### `getPublicKey(format = 'pem')`
Get public key in different formats.

```javascript
const keyPem = pqjwt.getPublicKey('pem');
const keyHex = pqjwt.getPublicKey('hex');
const keyBytes = pqjwt.getPublicKey('bytes');
```

### JWTManager Class

Advanced class with full functionality.

#### Initialization
```javascript
new JWTManager(
  'publisher',     // Mode
  './keys',        // Key directory  
  'pem',           // Key format
  'ML-DSA-65'      // Algorithm
)
```

#### Methods

##### `encode(payload, headers = null)`
Signs payload and returns JWT string.

##### `decode(jwt, validateClaims = true)`
Verifies JWT and returns `{ headers, payload }`.

##### `verify(jwt)`
Quick verification returning boolean.

##### `getPublicKeyPem()`
Returns public key in PEM format.

##### `getSecretKeyPem()`
Returns secret key in PEM format (publisher only).

### Factory Functions

#### `createPublisher(keyDir = './keys', keyFormat = 'pem', algorithm = 'ML-DSA-65')`
Creates a JWTManager instance in publisher mode.

#### `createConsumer(keyDir = './keys', keyFormat = 'pem', algorithm = 'ML-DSA-65')`  
Creates a JWTManager instance in consumer mode.

#### `createPQJWT(options = {})`
Creates a PQJWT instance with simplified API.

### JWTKeyManager Class

Static utility methods for key management.

#### `getSupportedAlgorithms()`
Returns list of all supported algorithms.

```javascript
import { JWTKeyManager } from 'pqjwt';

const algorithms = JWTKeyManager.getSupportedAlgorithms();
console.log('Supported algorithms:', algorithms);
// ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']
```

#### `getJwtHeaderName(algorithm)`
Maps algorithm name to JWT header.

```javascript
const header = JWTKeyManager.getJwtHeaderName('ML-DSA-65');
console.log(header); // 'Dilithium3'
```

#### `getAlgorithmFromJwtHeader(jwtHeader)`
Maps JWT header back to algorithm name.

```javascript
const algorithm = JWTKeyManager.getAlgorithmFromJwtHeader('Dilithium3');
console.log(algorithm); // 'ML-DSA-65'
```

---

## Error Handling

The library provides detailed exceptions for all error scenarios:

```javascript
import {
  JWTExpiredError,
  JWTSignatureError,
  JWTValidationError, 
  AlgorithmNotSupportedError,
  JWTDecodeError
} from 'pqjwt';

try {
  const { headers, payload } = consumer.decode(jwtToken);
} catch (error) {
  if (error instanceof JWTExpiredError) {
    console.log('Token expired:', error.message);
  } else if (error instanceof JWTSignatureError) {
    console.log('Invalid signature:', error.message);
  } else if (error instanceof JWTValidationError) {
    console.log('Validation failed:', error.message);
  } else if (error instanceof AlgorithmNotSupportedError) {
    console.log('Algorithm not supported:', error.message);
  } else if (error instanceof JWTDecodeError) {
    console.log('Decode error:', error.message);
  }
}
```

### Available Exceptions

- **`JWTExpiredError`**: Token has expired
- **`JWTSignatureError`**: Signature verification failed  
- **`JWTValidationError`**: General validation failure (malformed token, invalid claims)
- **`JWTDecodeError`**: Error decoding Base64 or JSON
- **`AlgorithmNotSupportedError`**: Unsupported algorithm specified
- **`CryptoKeyError`**: Key-related errors (missing private key, etc.)
- **`KeyFormatError`**: Invalid key format

---

## Security Considerations

### Algorithm Security
- **ML-DSA**: NIST Standardized (FIPS 204), no known practical attacks
- Uses auditable `@noble/post-quantum` implementation
- Constant-time operations where possible

### Key Protection
- Store private keys securely with appropriate file permissions
- Never expose private keys in client applications
- Use different key directories for different environments
- Consider key rotation policies for long-term security

### Best Practices

```javascript
// Use appropriate security levels
const productionAlgorithm = 'ML-DSA-65';  // Level 3 security
const testingAlgorithm = 'ML-DSA-44';     // Level 2 security

// Set reasonable expiration times
const payload = {
  userId: 123,
  exp: Math.floor(Date.now() / 1000) + 3600,  // 1 hour for access tokens
  iat: Math.floor(Date.now() / 1000)
};

// Validate critical claims
try {
  const result = consumer.decode(token, true); // Enable claim validation
} catch (error) {
  // Handle validation errors appropriately
}
```

### Key Format Notes
The PEM format uses standard headers with base64-encoded raw key bytes. For maximum interoperability in production systems, consider implementing full PKCS#8 (private keys) and SPKI (public keys) encoding.

---

## Examples

### Express.js Middleware

```javascript
import express from 'express';
import { createConsumer } from 'pqjwt';

const app = express();
const consumer = createConsumer('./keys', 'pem', 'ML-DSA-65');

// JWT authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const { payload } = consumer.decode(token, true);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// Protected route
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ 
    message: 'Access granted',
    user: req.user 
  });
});
```

### Key Rotation Example

```javascript
import { JWTKeyManager } from 'pqjwt';

// Check available algorithms
const algorithms = JWTKeyManager.getSupportedAlgorithms();
console.log('Available algorithms:', algorithms);

// Migrate to stronger algorithm over time
const getCurrentAlgorithm = () => {
  // Logic to determine current algorithm based on timeline
  return 'ML-DSA-65'; // Current standard
};

const publisher = createPublisher('./keys', 'pem', getCurrentAlgorithm());
```

---

## Testing

Run the test suite:

```bash
# Run all tests
npm test

# Run unit tests only  
npm run test:unit

# Run tests in watch mode
npm run test:watch
```

Run the examples:

```bash
npm run examples
```

---

## File Naming Convention

Keys are automatically named based on algorithm and format:

| Algorithm | Format | Public Key File | Private Key File |
|-----------|--------|-----------------|------------------|
| ML-DSA-44 | pem | `ml_dsa_44_public.pem` | `ml_dsa_44_private.pem` |
| ML-DSA-65 | bin | `ml_dsa_65_public.bin` | `ml_dsa_65_private.bin` |

> Note: Algorithm names are converted to lowercase with underscores for file naming.

---

## Contributing


1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

---

## Support

- **Issues**: For bugs and feature requests, please open an issue on GitHub
- **Security**: For security vulnerabilities, please contact the maintainers directly
- **Questions**: For usage questions, check existing issues or start a discussion

---


## Acknowledgments

Built with [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) - a secure, auditable implementation of post-quantum cryptography in JavaScript.

Implements ML-DSA (FIPS 204) standard for digital signatures.