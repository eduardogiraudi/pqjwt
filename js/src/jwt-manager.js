import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128f, slh_dsa_sha2_128s, slh_dsa_sha2_192f, slh_dsa_sha2_192s, slh_dsa_sha2_256f, slh_dsa_sha2_256s, slh_dsa_shake_128f, slh_dsa_shake_128s, slh_dsa_shake_192f, slh_dsa_shake_192s, slh_dsa_shake_256f, slh_dsa_shake_256s } from '@noble/post-quantum/slh-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

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
        },
        "SPHINCS+-SHA2-128f": {
            instance: slh_dsa_sha2_128f,
            jwt_header: "SphincsSha2128f"
        },
        "SPHINCS+-SHA2-128s": {
            instance: slh_dsa_sha2_128s,
            jwt_header: "SphincsSha2128s"
        },
        "SPHINCS+-SHA2-192f": {
            instance: slh_dsa_sha2_192f,
            jwt_header: "SphincsSha2192f"
        },
        "SPHINCS+-SHA2-192s": {
            instance: slh_dsa_sha2_192s,
            jwt_header: "SphincsSha2192s"
        },
        "SPHINCS+-SHA2-256f": {
            instance: slh_dsa_sha2_256f,
            jwt_header: "SphincsSha2256f"
        },
        "SPHINCS+-SHA2-256s": {
            instance: slh_dsa_sha2_256s,
            jwt_header: "SphincsSha2256s"
        },
        "SPHINCS+-SHAKE-128f": {
            instance: slh_dsa_shake_128f,
            jwt_header: "SphincsShake128f"
        },
        "SPHINCS+-SHAKE-128s": {
            instance: slh_dsa_shake_128s,
            jwt_header: "SphincsShake128s"
        },
        "SPHINCS+-SHAKE-192f": {
            instance: slh_dsa_shake_192f,
            jwt_header: "SphincsShake192f"
        },
        "SPHINCS+-SHAKE-192s": {
            instance: slh_dsa_shake_192s,
            jwt_header: "SphincsShake192s"
        },
        "SPHINCS+-SHAKE-256f": {
            instance: slh_dsa_shake_256f,
            jwt_header: "SphincsShake256f"
        },
        "SPHINCS+-SHAKE-256s": {
            instance: slh_dsa_shake_256s,
            jwt_header: "SphincsShake256s"
        }
    };

    static SUPPORTED_FORMATS = ["pem", "pub", "bin"];

    static getSupportedAlgorithms() {
        return Object.keys(this.ALGORITHMS);
    }

    static getJwtHeaderName(algorithm) {
        if (!this.ALGORITHMS[algorithm]) {
            throw new Error(`Algorithm ${algorithm} not supported`);
        }
        return this.ALGORITHMS[algorithm].jwt_header;
    }

    static getAlgorithmFromJwtHeader(jwtHeader) {
        for (const [alg, params] of Object.entries(this.ALGORITHMS)) {
            if (params.jwt_header === jwtHeader) {
                return alg;
            }
        }
        throw new Error(`JWT header ${jwtHeader} not supported`);
    }

    static async generateKeyPair(algorithm, seed = null) {
        if (!this.ALGORITHMS[algorithm]) {
            throw new Error(`Algorithm ${algorithm} not supported`);
        }
        
        const algInstance = this.ALGORITHMS[algorithm].instance;
        if (seed) {
            return algInstance.keygen(seed);
        }
        return algInstance.keygen();
    }

    static async sign(message, secretKey, algorithm) {
        if (!this.ALGORITHMS[algorithm]) {
            throw new Error(`Algorithm ${algorithm} not supported`);
        }
        
        const algInstance = this.ALGORITHMS[algorithm].instance;
        return algInstance.sign(message, secretKey);
    }

    static async verify(signature, message, publicKey, algorithm) {
        if (!this.ALGORITHMS[algorithm]) {
            throw new Error(`Algorithm ${algorithm} not supported`);
        }
        
        const algInstance = this.ALGORITHMS[algorithm].instance;
        return algInstance.verify(signature, message, publicKey);
    }

    static base64urlEncode(data) {
        return btoa(String.fromCharCode(...new Uint8Array(data)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    static base64urlDecode(data) {
        data = data.replace(/-/g, '+').replace(/_/g, '/');
        while (data.length % 4) {
            data += '=';
        }
        return new Uint8Array([...atob(data)].map(c => c.charCodeAt(0)));
    }
}

class JWTManager {
    constructor(mode = "publisher", keyDir = "./keys", keyFormat = "pem", algorithm = "ML-DSA-65") {
        this.mode = mode;
        this.keyDir = keyDir;
        this.keyFormat = keyFormat;
        this.algorithm = algorithm;
        this.publicKey = null;
        this.secretKey = null;

        if (!JWTKeyManager.ALGORITHMS[algorithm]) {
            throw new Error(`Algorithm ${algorithm} not supported`);
        }
    }

    async initialize() {
        // In browser environment, we can't write to filesystem
        // So we'll use localStorage or keep keys in memory
        await this._loadOrGenerateKeys();
    }

    async _loadOrGenerateKeys() {
        const storageKey = `jwt_keys_${this.algorithm}`;
        
        if (this.mode === "publisher") {
            const stored = localStorage.getItem(storageKey);
            if (stored) {
                const keys = JSON.parse(stored);
                this.publicKey = this._stringToUint8Array(keys.publicKey);
                this.secretKey = this._stringToUint8Array(keys.secretKey);
                console.log(`Keys for ${this.algorithm} loaded from storage`);
            } else {
                // Generate new keys
                const keys = await JWTKeyManager.generateKeyPair(this.algorithm);
                this.publicKey = keys.publicKey;
                this.secretKey = keys.secretKey;
                
                // Store in localStorage
                localStorage.setItem(storageKey, JSON.stringify({
                    publicKey: this._uint8ArrayToString(this.publicKey),
                    secretKey: this._uint8ArrayToString(this.secretKey)
                }));
                console.log(`Keys for ${this.algorithm} generated and stored`);
            }
        } else if (this.mode === "consumer") {
            const stored = localStorage.getItem(storageKey);
            if (stored) {
                const keys = JSON.parse(stored);
                this.publicKey = this._stringToUint8Array(keys.publicKey);
                console.log(`Public key for ${this.algorithm} loaded from storage`);
            } else {
                throw new Error(`Public key for ${this.algorithm} not found in storage`);
            }
        }
    }

    async encode(payload, headers = null) {
        if (this.mode !== "publisher") {
            throw new Error("Only publishers can sign a JWT");
        }
        if (!this.secretKey) {
            throw new Error("Private key not available for signing");
        }

        const jwtHeaderName = JWTKeyManager.getJwtHeaderName(this.algorithm);
        const defaultHeaders = {
            alg: jwtHeaderName,
            typ: "JWT"
        };

        const mergedHeaders = headers ? { ...defaultHeaders, ...headers } : defaultHeaders;

        const headerEncoded = JWTKeyManager.base64urlEncode(
            new TextEncoder().encode(JSON.stringify(mergedHeaders))
        );
        
        const payloadEncoded = JWTKeyManager.base64urlEncode(
            new TextEncoder().encode(JSON.stringify(payload))
        );
        
        const messageToSign = new TextEncoder().encode(`${headerEncoded}.${payloadEncoded}`);
        
        const signature = await JWTKeyManager.sign(messageToSign, this.secretKey, this.algorithm);
        const signatureEncoded = JWTKeyManager.base64urlEncode(signature);

        return `${headerEncoded}.${payloadEncoded}.${signatureEncoded}`;
    }

    async decode(jwt, validateClaims = true, clockSkew = 5) {
        try {
            const parts = jwt.split('.');
            if (parts.length !== 3) {
                throw new Error("Malformed JWT: wrong number of parts");
            }

            const [headerEncoded, payloadEncoded, signatureEncoded] = parts;
            
            const headerJson = new TextDecoder().decode(JWTKeyManager.base64urlDecode(headerEncoded));
            const payloadJson = new TextDecoder().decode(JWTKeyManager.base64urlDecode(payloadEncoded));
            
            const headers = JSON.parse(headerJson);
            const payload = JSON.parse(payloadJson);
            
            const signature = JWTKeyManager.base64urlDecode(signatureEncoded);

            if (validateClaims) {
                const now = Math.floor(Date.now() / 1000);
                
                if (payload.exp && now >= payload.exp) {
                    throw new Error("JWT expired");
                }
                
                if (payload.nbf && now + clockSkew < payload.nbf) {
                    throw new Error("JWT not yet valid");
                }
                
                if (payload.iat && payload.iat > now) {
                    throw new Error("JWT issued in future");
                }
            }

            const jwtAlg = headers.alg;
            const expectedAlgorithm = JWTKeyManager.getAlgorithmFromJwtHeader(jwtAlg);
            
            if (expectedAlgorithm !== this.algorithm) {
                console.warn(`JWT algorithm (${expectedAlgorithm}) differs from manager's (${this.algorithm})`);
            }

            const messageToVerify = new TextEncoder().encode(`${headerEncoded}.${payloadEncoded}`);
            const isValid = await JWTKeyManager.verify(signature, messageToVerify, this.publicKey, expectedAlgorithm);

            if (!isValid) {
                throw new Error("Invalid signature");
            }

            return { headers, payload };
            
        } catch (error) {
            throw new Error(`JWT validation failed: ${error.message}`);
        }
    }

    async verify(jwt) {
        try {
            await this.decode(jwt, false);
            return true;
        } catch {
            return false;
    }

    getPublicKey(outputFormat = "string") {
        if (outputFormat === "string") {
            return this._uint8ArrayToString(this.publicKey);
        } else if (outputFormat === "hex") {
            return Array.from(this.publicKey).map(b => b.toString(16).padStart(2, '0')).join('');
        } else {
            throw new Error(`Unsupported output format: ${outputFormat}`);
        }
    }

    _uint8ArrayToString(uint8Array) {
        return Array.from(uint8Array).map(b => String.fromCharCode(b)).join('');
    }

    _stringToUint8Array(string) {
        return new Uint8Array([...string].map(c => c.charCodeAt(0)));
    }
}

// Factory functions
async function createPublisher(keyDir = "./keys", keyFormat = "pem", algorithm = "ML-DSA-65") {
    const manager = new JWTManager("publisher", keyDir, keyFormat, algorithm);
    await manager.initialize();
    return manager;
}

async function createConsumer(keyDir = "./keys", keyFormat = "pem", algorithm = "ML-DSA-65") {
    const manager = new JWTManager("consumer", keyDir, keyFormat, algorithm);
    await manager.initialize();
    return manager;
}

// Export for use in modules
export { JWTKeyManager, JWTManager, createPublisher, createConsumer };