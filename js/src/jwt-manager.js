import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'fs';
import { 
    AlgorithmNotSupportedError,
    JWTValidationError,
    JWTExpiredError,
    JWTSignatureError,
    JWTDecodeError
} from './errors.js';

class JWTKeyManager {
    static ALGORITHMS = {
        "ML-DSA-44": {
            instance: ml_dsa44,
            jwt_header: "Dilithium2"
        },
        "ML-DSA-65": {
            instance: ml_dsa65,
            jwt_header: "Dilithium3"
        },
        "ML-DSA-87": {
            instance: ml_dsa87,
            jwt_header: "Dilithium5"
        }
    };

    static getSupportedAlgorithms() {
        return Object.keys(this.ALGORITHMS);
    }

    static getJwtHeaderName(algorithm) {
        if (!this.ALGORITHMS[algorithm]) {
            throw new AlgorithmNotSupportedError(algorithm, this.getSupportedAlgorithms());
        }
        return this.ALGORITHMS[algorithm].jwt_header;
    }

    static getAlgorithmFromJwtHeader(jwtHeader) {
        for (const [alg, params] of Object.entries(this.ALGORITHMS)) {
            if (params.jwt_header === jwtHeader) {
                return alg;
            }
        }
        throw new AlgorithmNotSupportedError(jwtHeader, this.getSupportedAlgorithms());
    }

    static saveKey(key, filePath, formatType = "pem", keyType = "public") {
        if (formatType === "pem") {
            const pemHeader = keyType === "private" ? 
                "-----BEGIN PRIVATE KEY-----" : "-----BEGIN PUBLIC KEY-----";
            const pemFooter = keyType === "private" ? 
                "-----END PRIVATE KEY-----" : "-----END PUBLIC KEY-----";
            
            const keyB64 = Buffer.from(key).toString('base64');
            const pemContent = `${pemHeader}\n${keyB64}\n${pemFooter}`;
            writeFileSync(filePath, pemContent);
        } else if (formatType === "bin") {
            writeFileSync(filePath, key);
        } else {
            throw new Error(`Unsupported format: ${formatType}`);
        }
    }

    static loadKey(filePath, formatType = "auto", keyType = "public") {
        if (formatType === "auto") {
            formatType = filePath.endsWith('.pem') ? "pem" : "bin";
        }

        if (formatType === "pem") {
            const content = readFileSync(filePath, 'utf8');
            const lines = content.trim().split('\n');
            
            if (lines.length < 3) {
                throw new Error("Invalid PEM format");
            }

            const base64Data = lines.slice(1, -1).join('');
            return Buffer.from(base64Data, 'base64');
        } else {
            return readFileSync(filePath);
        }
    }
}

class JWTManager {
    constructor(mode = "publisher", keyDir = "./keys", keyFormat = "pem", algorithm = "ML-DSA-44") {
        this.mode = mode;
        this.keyDir = keyDir;
        this.keyFormat = keyFormat;
        this.algorithm = algorithm;
        this.publicKey = null;
        this.secretKey = null;

        if (!JWTKeyManager.ALGORITHMS[algorithm]) {
            throw new AlgorithmNotSupportedError(algorithm, JWTKeyManager.getSupportedAlgorithms());
        }

        this.algorithmInstance = JWTKeyManager.ALGORITHMS[algorithm].instance;

        if (!existsSync(keyDir)) {
            mkdirSync(keyDir, { recursive: true });
        }

        this._loadOrGenerateKeys();
    }

    _getKeyPaths() {
        const baseName = this.algorithm.toLowerCase().replace('-', '_');
        const publicKeyPath = `${this.keyDir}/${baseName}_public.${this.keyFormat}`;
        const secretKeyPath = this.mode === "publisher" ? 
            `${this.keyDir}/${baseName}_private.${this.keyFormat}` : null;

        return { publicKeyPath, secretKeyPath };
    }

    _loadOrGenerateKeys() {
        const { publicKeyPath, secretKeyPath } = this._getKeyPaths();

        if (this.mode === "publisher") {
            if (existsSync(publicKeyPath) && existsSync(secretKeyPath)) {
                this.publicKey = JWTKeyManager.loadKey(publicKeyPath, this.keyFormat, "public");
                this.secretKey = JWTKeyManager.loadKey(secretKeyPath, this.keyFormat, "private");
                console.log(`✓ Keys for ${this.algorithm} loaded from ${this.keyDir}`);
            } else {
                // Generate new keys using noble
                const keyPair = this.algorithmInstance.keygen();
                
                // Convert Uint8Array to Buffer
                this.publicKey = Buffer.from(keyPair.publicKey);
                this.secretKey = Buffer.from(keyPair.secretKey);

                JWTKeyManager.saveKey(this.publicKey, publicKeyPath, this.keyFormat, "public");
                JWTKeyManager.saveKey(this.secretKey, secretKeyPath, this.keyFormat, "private");
                
                console.log(`✓ New keys for ${this.algorithm} generated and saved in ${this.keyDir}`);
            }
        } else {
            if (existsSync(publicKeyPath)) {
                this.publicKey = JWTKeyManager.loadKey(publicKeyPath, this.keyFormat, "public");
                console.log(`✓ Public key for ${this.algorithm} loaded from ${publicKeyPath}`);
            } else {
                throw new Error(`✗ Public key not found at ${publicKeyPath}`);
            }
        }
    }

    _base64urlEncode(data) {
        return Buffer.from(data).toString('base64url');
    }

    _base64urlDecode(data) {
        return Buffer.from(data, 'base64url');
    }

    encode(payload, headers = null) {
        if (this.mode !== "publisher") {
            throw new Error("Only publishers can sign JWT");
        }

        const jwtHeaderName = JWTKeyManager.getJwtHeaderName(this.algorithm);
        const defaultHeaders = {
            "alg": jwtHeaderName,
            "typ": "JWT"
        };

        const finalHeaders = headers ? { ...defaultHeaders, ...headers } : defaultHeaders;

        const headerEncoded = this._base64urlEncode(JSON.stringify(finalHeaders));
        const payloadEncoded = this._base64urlEncode(JSON.stringify(payload));
        const messageToSign = `${headerEncoded}.${payloadEncoded}`;

        // Sign with noble - convert Buffer to Uint8Array for noble
        const messageUint8 = new Uint8Array(Buffer.from(messageToSign));
        const secretKeyUint8 = new Uint8Array(this.secretKey);
        const signature = this.algorithmInstance.sign(messageUint8, secretKeyUint8);
        
        const signatureEncoded = this._base64urlEncode(signature);

        return `${headerEncoded}.${payloadEncoded}.${signatureEncoded}`;
    }

    decode(jwt, validateClaims = true) {
        const parts = jwt.split('.');
        if (parts.length !== 3) {
            throw new JWTValidationError("Invalid JWT format: wrong number of parts");
        }

        const [headerEncoded, payloadEncoded, signatureEncoded] = parts;

        try {
            const headerJson = this._base64urlDecode(headerEncoded).toString();
            const payloadJson = this._base64urlDecode(payloadEncoded).toString();
            const signature = this._base64urlDecode(signatureEncoded);

            const headers = JSON.parse(headerJson);
            const payload = JSON.parse(payloadJson);

            // Validate claims if requested
            if (validateClaims) {
                const now = Math.floor(Date.now() / 1000);

                if (payload.exp) {
                    if (now >= payload.exp) {
                        throw new JWTExpiredError(payload.exp, now);
                    }
                }

                if (payload.nbf && now < payload.nbf) {
                    throw new JWTValidationError(`JWT not yet valid. Current time: ${now}, Not before: ${payload.nbf}`);
                }
            }

            // Get algorithm from JWT header
            const jwtAlg = headers.alg;
            const expectedAlgorithm = JWTKeyManager.getAlgorithmFromJwtHeader(jwtAlg);

            // Verify signature using noble
            const messageToVerify = `${headerEncoded}.${payloadEncoded}`;
            const messageUint8 = new Uint8Array(Buffer.from(messageToVerify));
            const publicKeyUint8 = new Uint8Array(this.publicKey);
            const signatureUint8 = new Uint8Array(signature);
            
            const isValid = this.algorithmInstance.verify(signatureUint8, messageUint8, publicKeyUint8);

            if (!isValid) {
                throw new JWTSignatureError(expectedAlgorithm);
            }

            return { headers, payload };

        } catch (error) {
            // Gestione specifica degli errori di parsing JSON
            if (error instanceof SyntaxError && error.message.includes('JSON')) {
                throw new JWTDecodeError(`Invalid JSON in JWT: ${error.message}`);
            }
            
            if (error instanceof JWTValidationError || 
                error instanceof JWTExpiredError || 
                error instanceof JWTSignatureError ||
                error instanceof JWTDecodeError) {
                throw error;
            }
            
            throw new JWTDecodeError(error.message);
        }
    }

    verify(jwt) {
        try {
            this.decode(jwt, false);
            return true;
        } catch {
            return false;
        }
    }

    getPublicKeyPem() {
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        const keyB64 = this.publicKey.toString('base64');
        return `${pemHeader}\n${keyB64}\n${pemFooter}`;
    }

    getSecretKeyPem() {
        if (this.mode !== "publisher") {
            throw new Error("Only publishers can access secret key");
        }
        const pemHeader = "-----BEGIN PRIVATE KEY-----";
        const pemFooter = "-----END PRIVATE KEY-----";
        const keyB64 = this.secretKey.toString('base64');
        return `${pemHeader}\n${keyB64}\n${pemFooter}`;
    }
}

// Factory functions
export function createPublisher(keyDir = "./keys", keyFormat = "pem", algorithm = "ML-DSA-65") {
    return new JWTManager("publisher", keyDir, keyFormat, algorithm);
}

export function createConsumer(keyDir = "./keys", keyFormat = "pem", algorithm = "ML-DSA-65") {
    return new JWTManager("consumer", keyDir, keyFormat, algorithm);
}

export { JWTManager, JWTKeyManager };