import { describe, it, before, after } from 'node:test';
import { strict as assert } from 'node:assert';
import { JWTManager } from '../../src/jwt-manager.js';
import { 
    AlgorithmNotSupportedError, 
    JWTValidationError,
    JWTExpiredError,
    JWTSignatureError,
    JWTDecodeError
} from '../../src/errors.js';
import { rm } from 'fs/promises';

describe('JWTManager', () => {
    const testKeyDir = './test-keys-temp';
    
    before(async () => {
        // Clean up before tests
        try {
            await rm(testKeyDir, { recursive: true, force: true });
        } catch (error) {
            // Ignore if directory doesn't exist
        }
    });

    after(async () => {
        // Clean up after tests
        try {
            await rm(testKeyDir, { recursive: true, force: true });
        } catch (error) {
            // Ignore errors
        }
    });

    it('should create publisher with ML-DSA-65', async () => {
        const publisher = new JWTManager('publisher', testKeyDir, 'pem', 'ML-DSA-65');
        assert.ok(publisher.publicKey);
        assert.ok(publisher.secretKey);
    });

    it('should create consumer with existing keys', async () => {
        // First create publisher to generate keys
        const publisher = new JWTManager('publisher', testKeyDir, 'pem', 'ML-DSA-65');
        
        // Then create consumer with same keys
        const consumer = new JWTManager('consumer', testKeyDir, 'pem', 'ML-DSA-65');
        assert.ok(consumer.publicKey);
        assert.ok(!consumer.secretKey); // Consumer shouldn't have secret key
    });

    it('should sign and verify JWT', async () => {
        const publisher = new JWTManager('publisher', testKeyDir, 'pem', 'ML-DSA-65');
        const consumer = new JWTManager('consumer', testKeyDir, 'pem', 'ML-DSA-65');

        const payload = { sub: 'test', iat: Math.floor(Date.now() / 1000) };
        const jwt = publisher.encode(payload);
        
        const isValid = consumer.verify(jwt);
        assert.equal(isValid, true);

        const { headers, payload: decoded } = consumer.decode(jwt);
        assert.equal(decoded.sub, 'test');
    });

    it('should throw error for unsupported algorithm', async () => {
        assert.throws(() => {
            new JWTManager('publisher', testKeyDir, 'pem', 'UNSUPPORTED-ALG');
        }, AlgorithmNotSupportedError);
    });

    it('should validate expiration', async () => {
        const publisher = new JWTManager('publisher', testKeyDir, 'pem', 'ML-DSA-65');
        
        const payload = { 
            sub: 'test', 
            exp: Math.floor(Date.now() / 1000) - 3600 // Expired 1 hour ago
        };
        
        const jwt = publisher.encode(payload);
        const consumer = new JWTManager('consumer', testKeyDir, 'pem', 'ML-DSA-65');

        assert.throws(() => {
            consumer.decode(jwt, true);
        }, JWTExpiredError);
    });

    it('should handle invalid JWT format - wrong number of parts', async () => {
        const consumer = new JWTManager('consumer', testKeyDir, 'pem', 'ML-DSA-65');
        
        // JWT con numero di parti sbagliato (2 parti invece di 3)
        assert.throws(() => {
            consumer.decode('part1.part2');
        }, JWTValidationError);
    });

    it('should handle invalid signature', async () => {
        const publisher = new JWTManager('publisher', testKeyDir, 'pem', 'ML-DSA-65');
        const consumer = new JWTManager('consumer', testKeyDir, 'pem', 'ML-DSA-65');

        const payload = { sub: 'test' };
        const jwt = publisher.encode(payload);
        
        // Modify the signature to make it invalid
        const parts = jwt.split('.');
        parts[2] = parts[2].slice(0, -10) + 'invalid'; // Corrupt signature
        
        const invalidJwt = parts.join('.');
        
        assert.throws(() => {
            consumer.decode(invalidJwt);
        }, JWTSignatureError);
    });

    it('should handle malformed JSON in JWT', async () => {
        const consumer = new JWTManager('consumer', testKeyDir, 'pem', 'ML-DSA-65');
        
        // Create a JWT with invalid JSON in payload - usa base64url valido ma JSON invalido
        const header = Buffer.from(JSON.stringify({ alg: "Dilithium3", typ: "JWT" })).toString('base64url');
        const invalidPayload = Buffer.from("invalid-json{not:valid}").toString('base64url');
        const malformedJwt = `${header}.${invalidPayload}.signaturepart`;
        
        assert.throws(() => {
            consumer.decode(malformedJwt);
        }, JWTDecodeError);
    });

    it('should handle not-before claim', async () => {
        const publisher = new JWTManager('publisher', testKeyDir, 'pem', 'ML-DSA-65');
        
        const payload = { 
            sub: 'test', 
            nbf: Math.floor(Date.now() / 1000) + 3600 // Not valid for 1 hour
        };
        
        const jwt = publisher.encode(payload);
        const consumer = new JWTManager('consumer', testKeyDir, 'pem', 'ML-DSA-65');

        assert.throws(() => {
            consumer.decode(jwt, true);
        }, JWTValidationError);
    });

    it('should handle invalid base64 in JWT', async () => {
        const consumer = new JWTManager('consumer', testKeyDir, 'pem', 'ML-DSA-65');
        
        // JWT con base64 invalido
        const invalidBase64Jwt = 'invalid.base64!.signature';
        
        assert.throws(() => {
            consumer.decode(invalidBase64Jwt);
        }, JWTDecodeError);
    });

    it('should handle empty JWT', async () => {
        const consumer = new JWTManager('consumer', testKeyDir, 'pem', 'ML-DSA-65');
        
        assert.throws(() => {
            consumer.decode('');
        }, JWTValidationError);
    });

    it('should handle JWT with only one part', async () => {
        const consumer = new JWTManager('consumer', testKeyDir, 'pem', 'ML-DSA-65');
        
        assert.throws(() => {
            consumer.decode('onlyonepart');
        }, JWTValidationError);
    });
});