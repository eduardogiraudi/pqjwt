/**
 * PQJWT - Post-Quantum JSON Web Tokens
 * 
 * A secure JWT implementation using post-quantum cryptographic algorithms
 * including ML-DSA (Dilithium), Falcon, and SPHINCS+.
 * 
 * @module pqjwt
 */

export { JWTManager, JWTKeyManager, createPublisher, createConsumer } from './jwt-manager.js';
export { 
    AlgorithmNotSupportedError,
    KeyFormatError, 
    CryptoKeyError,
    JWTValidationError,
    JWTExpiredError,
    JWTSignatureError,
    JWTDecodeError
} from './errors.js';

// Re-export noble algorithms for advanced usage
export { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

// Version
export const version = '1.0.0';

/**
 * Main PQJWT class - simplified API for common use cases
 */
export class PQJWT {
    /**
     * Create a new PQJWT instance
     * @param {Object} options - Configuration options
     * @param {string} options.mode - 'publisher' or 'consumer'
     * @param {string} options.keyDir - Directory for keys
     * @param {string} options.algorithm - Cryptographic algorithm
     * @param {string} options.keyFormat - Key format ('pem', 'bin')
     */
    constructor(options = {}) {
        const {
            mode = 'publisher',
            keyDir = './keys',
            algorithm = 'ML-DSA-65', 
            keyFormat = 'pem'
        } = options;

        this.manager = new JWTManager(mode, keyDir, keyFormat, algorithm);
    }

    /**
     * Create a JWT token
     * @param {Object} payload - Token payload
     * @param {Object} headers - Additional headers
     * @returns {string} JWT token
     */
    sign(payload, headers = null) {
        return this.manager.encode(payload, headers);
    }

    /**
     * Verify and decode a JWT token
     * @param {string} token - JWT token to verify
     * @param {boolean} validateClaims - Whether to validate claims (exp, nbf, iat)
     * @returns {Object} Decoded token { headers, payload }
     */
    verify(token, validateClaims = true) {
        return this.manager.decode(token, validateClaims);
    }

    /**
     * Quick verification without decoding
     * @param {string} token - JWT token to verify
     * @returns {boolean} True if token is valid
     */
    isValid(token) {
        return this.manager.verify(token);
    }

    /**
     * Get public key in specified format
     * @param {string} format - Output format ('pem', 'hex', 'bytes')
     * @returns {string|Buffer} Public key
     */
    getPublicKey(format = 'pem') {
        if (format === 'pem') {
            return this.manager.getPublicKeyPem();
        } else if (format === 'hex') {
            return this.manager.publicKey.toString('hex');
        }
        return this.manager.publicKey;
    }
}

/**
 * Factory function for creating PQJWT instances
 * @param {Object} options - Configuration options
 * @returns {PQJWT} PQJWT instance
 */
export function createPQJWT(options = {}) {
    return new PQJWT(options);
}

/**
 * Create a publisher instance (for signing tokens)
 * @param {string} keyDir - Key directory
 * @param {string} algorithm - Algorithm to use
 * @returns {PQJWT} Publisher instance
 */
export function createPublisherSimple(keyDir = './keys', algorithm = 'ML-DSA-65') {
    return new PQJWT({ mode: 'publisher', keyDir, algorithm });
}

/**
 * Create a consumer instance (for verifying tokens)
 * @param {string} keyDir - Key directory
 * @param {string} algorithm - Algorithm to use  
 * @returns {PQJWT} Consumer instance
 */
export function createConsumerSimple(keyDir = './keys', algorithm = 'ML-DSA-65') {
    return new PQJWT({ mode: 'consumer', keyDir, algorithm });
}

// Default export
export default PQJWT;