import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'fs';
import {
    AlgorithmNotSupportedError,
    JWTValidationError,
    JWTExpiredError,
    JWTSignatureError,
    JWTDecodeError
} from './errors.js';
import {
    createMLDSA44,
    createMLDSA65,
    createMLDSA87,
    createSlhDsaSha2128f,
    createSlhDsaSha2128s,
    createSlhDsaSha2192f,
    createSlhDsaSha2192s,
    createSlhDsaSha2256f,
    createSlhDsaSha2256s,
    createSlhDsaShake128f,
    createSlhDsaShake128s,
    createSlhDsaShake192f,
    createSlhDsaShake192s,
    createSlhDsaShake256f,
    createSlhDsaShake256s,
    createFalcon512,
    createFalcon1024,
    createFalconPadded512,
    createFalconPadded1024,
} from '@oqs/liboqs-js/sig'; 
import asn from 'asn1.js';

const AlgorithmIdentifier = asn.define('AlgorithmIdentifier', function() {
    this.seq().obj(this.key('id').objid());
});

const SubjectPublicKeyInfo = asn.define('SubjectPublicKeyInfo', function() {
    this.seq().obj(
        this.key('algorithm').use(AlgorithmIdentifier),
        this.key('subjectPublicKey').bitstr()
    );
});

const OneAsymmetricKey = asn.define('OneAsymmetricKey', function() {
    this.seq().obj(
        this.key('version').int(),
        this.key('algorithm').use(AlgorithmIdentifier),
        this.key('privateKey').octstr()
    );
});

const OIDS = {
  'ML-DSA-44':  [2, 16, 840, 1, 101, 3, 4, 3, 17],
  'ML-DSA-65':  [2, 16, 840, 1, 101, 3, 4, 3, 18],
  'ML-DSA-87':  [2, 16, 840, 1, 101, 3, 4, 3, 19],
  'FN-DSA-512':  [1, 3, 9999, 3, 6],
  'FN-DSA-1024': [1, 3, 9999, 3, 7],
  'SLH-DSA-SHA2-128s': [2, 16, 840, 1, 101, 3, 4, 3, 20],
  'SLH-DSA-SHA2-128f': [2, 16, 840, 1, 101, 3, 4, 3, 21],
  'SLH-DSA-SHA2-192s': [2, 16, 840, 1, 101, 3, 4, 3, 22],
  'SLH-DSA-SHA2-192f': [2, 16, 840, 1, 101, 3, 4, 3, 23],
  'SLH-DSA-SHA2-256s': [2, 16, 840, 1, 101, 3, 4, 3, 24],
  'SLH-DSA-SHA2-256f': [2, 16, 840, 1, 101, 3, 4, 3, 25],
  'SLH-DSA-SHAKE-128s': [2, 16, 840, 1, 101, 3, 4, 3, 26],
  'SLH-DSA-SHAKE-128f': [2, 16, 840, 1, 101, 3, 4, 3, 27],
  'SLH-DSA-SHAKE-192s': [2, 16, 840, 1, 101, 3, 4, 3, 28],
  'SLH-DSA-SHAKE-192f': [2, 16, 840, 1, 101, 3, 4, 3, 29],
  'SLH-DSA-SHAKE-256s': [2, 16, 840, 1, 101, 3, 4, 3, 30],
  'SLH-DSA-SHAKE-256f': [2, 16, 840, 1, 101, 3, 4, 3, 31]
};


const ALGORITHM_REGISTRY = {
    //mldsa
    "ML-DSA-44": { factory: createMLDSA44,  jwt_header: "ML-DSA-44",  instance: null },
    "ML-DSA-65": { factory: createMLDSA65,  jwt_header: "ML-DSA-65",  instance: null },
    "ML-DSA-87": { factory: createMLDSA87,  jwt_header: "ML-DSA-87",  instance: null },

    //slhdsasha 
    "SLH-DSA-SHA2-128f": { factory: createSlhDsaSha2128f, jwt_header: "SLH-DSA-SHA2-128f", instance: null },
    "SLH-DSA-SHA2-128s": { factory: createSlhDsaSha2128s, jwt_header: "SLH-DSA-SHA2-128s", instance: null },
    "SLH-DSA-SHA2-192f": { factory: createSlhDsaSha2192f, jwt_header: "SLH-DSA-SHA2-192f", instance: null },
    "SLH-DSA-SHA2-192s": { factory: createSlhDsaSha2192s, jwt_header: "SLH-DSA-SHA2-192s", instance: null },
    "SLH-DSA-SHA2-256f": { factory: createSlhDsaSha2256f, jwt_header: "SLH-DSA-SHA2-256f", instance: null },
    "SLH-DSA-SHA2-256s": { factory: createSlhDsaSha2256s, jwt_header: "SLH-DSA-SHA2-256s", instance: null },

    // slhdsashake
    "SLH-DSA-SHAKE-128f": { factory: createSlhDsaShake128f, jwt_header: "SLH-DSA-SHAKE-128f", instance: null },
    "SLH-DSA-SHAKE-128s": { factory: createSlhDsaShake128s, jwt_header: "SLH-DSA-SHAKE-128s", instance: null },
    "SLH-DSA-SHAKE-192f": { factory: createSlhDsaShake192f, jwt_header: "SLH-DSA-SHAKE-192f", instance: null },
    "SLH-DSA-SHAKE-192s": { factory: createSlhDsaShake192s, jwt_header: "SLH-DSA-SHAKE-192s", instance: null },
    "SLH-DSA-SHAKE-256f": { factory: createSlhDsaShake256f, jwt_header: "SLH-DSA-SHAKE-256f", instance: null },
    "SLH-DSA-SHAKE-256s": { factory: createSlhDsaShake256s, jwt_header: "SLH-DSA-SHAKE-256s", instance: null },

    // falcon
    //"Falcon-512":         { factory: createFalcon512,        jwt_header: "Falcon512",        instance: null },
    //"Falcon-1024":        { factory: createFalcon1024,       jwt_header: "Falcon1024",       instance: null },
    "FN-DSA-512":  { factory: createFalconPadded512,  jwt_header: "FN-DSA-512",  instance: null },
    "FN-DSA-1024": { factory: createFalconPadded1024, jwt_header: "FN-DSA-1024", instance: null },
};

//JWTKeyManager

class JWTKeyManager {
    /**
     * @param {string} algorithm
     */
    static async init(algorithm) {
        const entry = ALGORITHM_REGISTRY[algorithm];
        if (!entry) throw new AlgorithmNotSupportedError(algorithm, this.getSupportedAlgorithms());
        if (!entry.instance) {
            entry.instance = await entry.factory();
        }
    }


    static destroyAll() {
        for (const entry of Object.values(ALGORITHM_REGISTRY)) {
            if (entry.instance) {
                try { entry.instance.destroy(); } catch { /*  */ }
                entry.instance = null;
            }
        }
    }

    static getSupportedAlgorithms() {
        return Object.keys(ALGORITHM_REGISTRY);
    }

    static getJwtHeaderName(algorithm) {
        const entry = ALGORITHM_REGISTRY[algorithm];
        if (!entry) throw new AlgorithmNotSupportedError(algorithm, this.getSupportedAlgorithms());
        return entry.jwt_header;
    }

    static getAlgorithmFromJwtHeader(jwtHeader) {
        for (const [alg, entry] of Object.entries(ALGORITHM_REGISTRY)) {
            if (entry.jwt_header === jwtHeader) return alg;
        }
        throw new AlgorithmNotSupportedError(jwtHeader, this.getSupportedAlgorithms());
    }

    static getInstance(algorithm) {
        const entry = ALGORITHM_REGISTRY[algorithm];
        if (!entry?.instance) {
            throw new Error(`Wasm instance ${algorithm} not loaded. Use createPublisher() or createConsumer().`);
        }
        return entry.instance;
    }

    static saveKey(key, filePath, formatType = "pem", keyType = "public", algorithm = "ML-DSA-65") {
        let finalBuffer = Buffer.from(key);
    
        if (formatType === "pem") {
            const oid = OIDS[algorithm];
            if (!oid) throw new Error(`OID not found for the algorithm: ${algorithm}`);
    
            if (keyType === "public") {
                finalBuffer = SubjectPublicKeyInfo.encode({
                    algorithm: { id: oid },
                    subjectPublicKey: { unused: 0, data: finalBuffer }
                }, 'der');
            } else {
                finalBuffer = OneAsymmetricKey.encode({
                    version: 0,
                    algorithm: { id: oid },
                    privateKey: finalBuffer
                }, 'der');
            }
    
            const label = keyType === "private" ? "PRIVATE KEY" : "PUBLIC KEY";
            const base64 = finalBuffer.toString('base64');
            const lines = base64.match(/.{1,64}/g).join('\n');
            const pem = `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
            writeFileSync(filePath, pem);
        } else {
            writeFileSync(filePath, finalBuffer);
        }
    }

    static loadKey(filePath, formatType = "auto") {
        if (formatType === "auto") formatType = filePath.endsWith('.pem') ? "pem" : "bin";
        
        const rawData = readFileSync(filePath);
        if (formatType === "bin") return rawData;
    
        const pemString = rawData.toString('utf8');
        const base64 = pemString.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, '');
        const derBuffer = Buffer.from(base64, 'base64');
    
        try {
            if (pemString.includes("PUBLIC KEY")) {
                const decoded = SubjectPublicKeyInfo.decode(derBuffer, 'der');
                return Buffer.from(decoded.subjectPublicKey.data);
            } 
            else {
                const decoded = OneAsymmetricKey.decode(derBuffer, 'der');
                return Buffer.from(decoded.privateKey);
            }
        } catch (e) {
            console.warn("ASN.1 decode failed, returning raw base64 content", e.message);
            return derBuffer;
        }
    }
}



class JWTManager {
    constructor(mode = "publisher", keyDir = "./keys", keyFormat = "pem", algorithm = "ML-DSA-65") {
        this.mode      = mode;
        this.keyDir    = keyDir;
        this.keyFormat = keyFormat;
        this.algorithm = algorithm;
        this.publicKey = null;
        this.secretKey = null;

        if (!ALGORITHM_REGISTRY[algorithm]) {
            throw new AlgorithmNotSupportedError(algorithm, JWTKeyManager.getSupportedAlgorithms());
        }
        if (!existsSync(keyDir)) mkdirSync(keyDir, { recursive: true });
    }

    _getKeyPaths() {
        const base = this.algorithm.toLowerCase().replace(/[^a-z0-9]+/g, '_');
        return {
            publicKeyPath: `${this.keyDir}/${base}_public.${this.keyFormat}`,
            secretKeyPath: `${this.keyDir}/${base}_private.${this.keyFormat}`,
        };
    }

    _loadOrGenerateKeys() {
        const { publicKeyPath, secretKeyPath } = this._getKeyPaths();
        const instance = JWTKeyManager.getInstance(this.algorithm); 

        if (this.mode === "publisher") {
            if (existsSync(publicKeyPath) && existsSync(secretKeyPath)) {
                this.publicKey = JWTKeyManager.loadKey(publicKeyPath, this.keyFormat);
                this.secretKey = JWTKeyManager.loadKey(secretKeyPath, this.keyFormat);
                console.log(`${this.algorithm} keys loaded from ${this.keyDir}`);
            } else {
                const { publicKey, secretKey } = instance.generateKeyPair();
                this.publicKey = Buffer.from(publicKey);
                this.secretKey = Buffer.from(secretKey);
                JWTKeyManager.saveKey(this.publicKey, publicKeyPath, this.keyFormat, "public", this.algorithm);
                JWTKeyManager.saveKey(this.secretKey, secretKeyPath, this.keyFormat, "private", this.algorithm);
                console.log(`New ${this.algorithm} keys generated and saved in ${this.keyDir}`);
            }
        } else {
            if (!existsSync(publicKeyPath)) {
                throw new Error(`Public key not found in ${publicKeyPath}`);
            }
            this.publicKey = JWTKeyManager.loadKey(publicKeyPath, this.keyFormat);
            console.log(`${this.algorithm} public key loaded from ${publicKeyPath}`);
        }
    }

    _base64urlEncode(data) { return Buffer.from(data).toString('base64url'); }
    _base64urlDecode(data) { return Buffer.from(data, 'base64url'); }

    encode(payload, headers = null) {
        if (this.mode !== "publisher") throw new Error("Only publishers can sign JWT");

        const jwtHeaderName = JWTKeyManager.getJwtHeaderName(this.algorithm);
        const finalHeaders  = { alg: jwtHeaderName, typ: "JWT", ...(headers ?? {}) };

        const headerEncoded  = this._base64urlEncode(JSON.stringify(finalHeaders));
        const payloadEncoded = this._base64urlEncode(JSON.stringify(payload));
        const messageToSign  = `${headerEncoded}.${payloadEncoded}`;

        const instance  = JWTKeyManager.getInstance(this.algorithm);
        const signature = instance.sign(
            new Uint8Array(Buffer.from(messageToSign)),
            new Uint8Array(this.secretKey),
        );

        return `${headerEncoded}.${payloadEncoded}.${this._base64urlEncode(signature)}`;
    }

    decode(jwt, validateClaims = true) {
        const parts = jwt.split('.');
        if (parts.length !== 3) {
            throw new JWTValidationError("Invalid JWT format: wrong number of parts");
        }

        const [headerEncoded, payloadEncoded, signatureEncoded] = parts;

        try {
            const headers   = JSON.parse(this._base64urlDecode(headerEncoded).toString());
            const payload   = JSON.parse(this._base64urlDecode(payloadEncoded).toString());
            const signature = this._base64urlDecode(signatureEncoded);

            if (validateClaims) {
                const now = Math.floor(Date.now() / 1000);
                if (payload.exp && now >= payload.exp) throw new JWTExpiredError(payload.exp, now);
                if (payload.nbf && now < payload.nbf)  throw new JWTValidationError(`JWT not yet valid. Current time: ${now}, Not before: ${payload.nbf}`);
            }

            const headerAlg = JWTKeyManager.getAlgorithmFromJwtHeader(headers.alg);
            if (headerAlg !== this.algorithm) {
                throw new JWTValidationError(
                    `Algorithm mismatch: Server requires ${this.algorithm}, but JWT header specifies ${headerAlg}`
                );
            }

            const instance = JWTKeyManager.getInstance(this.algorithm);
            const isValid  = instance.verify(
                new Uint8Array(Buffer.from(`${headerEncoded}.${payloadEncoded}`)),
                new Uint8Array(signature),
                new Uint8Array(this.publicKey),
            );

            if (!isValid) throw new JWTSignatureError(this.algorithm);

            return { headers, payload };

        } catch (error) {
            if (error instanceof SyntaxError && error.message.includes('JSON')) {
                throw new JWTDecodeError(`Invalid JSON in JWT: ${error.message}`);
            }
            if (
                error instanceof JWTValidationError ||
                error instanceof JWTExpiredError    ||
                error instanceof JWTSignatureError  ||
                error instanceof JWTDecodeError
            ) throw error;

            throw new JWTDecodeError(error.message);
        }
    }

    verify(jwt) {
        try { this.decode(jwt, false); return true; }
        catch { return false; }
    }

    getPublicKeyPem() {
        return `-----BEGIN PUBLIC KEY-----\n${this.publicKey.toString('base64')}\n-----END PUBLIC KEY-----`;
    }

    getSecretKeyPem() {
        if (this.mode !== "publisher") throw new Error("Only publishers can access secret key");
        return `-----BEGIN PRIVATE KEY-----\n${this.secretKey.toString('base64')}\n-----END PRIVATE KEY-----`;
    }
}



/**
 * @param {string} [keyDir="./keys"]
 * @param {"pem"|"bin"} [keyFormat="pem"]
 * @param {string} [algorithm="ML-DSA-65"]
 * @returns {Promise<JWTManager>}
 *
 * @example
 * const pub = await createPublisher("./keys", "pem", "Falcon-512");
 * const token = pub.encode({ sub: "123", exp: ... });
 */
export async function createPublisher(keyDir = "./keys", keyFormat = "pem", algorithm = "ML-DSA-65") {
    await JWTKeyManager.init(algorithm);
    const mgr = new JWTManager("publisher", keyDir, keyFormat, algorithm);
    mgr._loadOrGenerateKeys();
    return mgr;
}

/**
 * @param {string} [keyDir="./keys"]
 * @param {"pem"|"bin"} [keyFormat="pem"]
 * @param {string} [algorithm="ML-DSA-65"]
 * @returns {Promise<JWTManager>}
 *
 * @example
 * const consumer = await createConsumer("./keys", "pem", "Falcon-512");
 * const { headers, payload } = consumer.decode(token);
 */
export async function createConsumer(keyDir = "./keys", keyFormat = "pem", algorithm = "ML-DSA-65") {
    await JWTKeyManager.init(algorithm);
    const mgr = new JWTManager("consumer", keyDir, keyFormat, algorithm);
    mgr._loadOrGenerateKeys();
    return mgr;
}

export { JWTManager, JWTKeyManager };