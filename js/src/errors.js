/**
 * Base error class for PQJWT
 */
export class PQJWTError extends Error {
    constructor(message) {
        super(message);
        this.name = this.constructor.name;
    }
}

/**
 * Algorithm not supported error
 */
export class AlgorithmNotSupportedError extends PQJWTError {
    constructor(algorithm, supportedAlgorithms) {
        super(`Algorithm '${algorithm}' not supported. Supported algorithms: ${supportedAlgorithms.join(', ')}`);
        this.algorithm = algorithm;
        this.supportedAlgorithms = supportedAlgorithms;
    }
}

/**
 * Key format error
 */
export class KeyFormatError extends PQJWTError {
    constructor(message, formatType) {
        super(message);
        this.formatType = formatType;
    }
}

/**
 * Cryptographic key error
 */
export class CryptoKeyError extends PQJWTError {
    constructor(message, keyType) {
        super(message);
        this.keyType = keyType;
    }
}

/**
 * JWT validation error
 */
export class JWTValidationError extends PQJWTError {
    constructor(message, claim = null) {
        super(message);
        this.claim = claim;
    }
}

/**
 * JWT expired error
 */
export class JWTExpiredError extends JWTValidationError {
    constructor(expTime, currentTime) {
        super(`JWT expired at ${new Date(expTime * 1000).toISOString()}. Current time: ${new Date(currentTime * 1000).toISOString()}`);
        this.expTime = expTime;
        this.currentTime = currentTime;
    }
}

/**
 * JWT signature error
 */
export class JWTSignatureError extends JWTValidationError {
    constructor(algorithm) {
        super(`Invalid JWT signature for algorithm: ${algorithm}`);
        this.algorithm = algorithm;
    }
}

/**
 * JWT decode error
 */
export class JWTDecodeError extends PQJWTError {
    constructor(message) {
        super(`JWT decode error: ${message}`);
    }
}

/**
 * Key not found error
 */
export class KeyNotFoundError extends PQJWTError {
    constructor(keyPath, keyType) {
        super(`${keyType} key not found at: ${keyPath}`);
        this.keyPath = keyPath;
        this.keyType = keyType;
    }
}