import { describe, it, before, after } from 'node:test';
import { strict as assert } from 'node:assert';
import { createPublisher, createConsumer } from '../../src/jwt-manager.js'; 
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
        try {
            await rm(testKeyDir, { recursive: true, force: true });
        } catch (error) {}
    });

    after(async () => {
        try {
            await rm(testKeyDir, { recursive: true, force: true });
        } catch (error) {}
    });

    it('should create publisher with ML-DSA-65', async () => {
        const publisher = await createPublisher(testKeyDir, 'pem', 'ML-DSA-65');
        assert.ok(publisher.publicKey);
        assert.ok(publisher.secretKey);
    });

    it('should create consumer with existing keys', async () => {
        await createPublisher(testKeyDir, 'pem', 'ML-DSA-65');
        
        // Poi crea il consumer
        const consumer = await createConsumer(testKeyDir, 'pem', 'ML-DSA-65');
        assert.ok(consumer.publicKey);
        assert.ok(!consumer.secretKey); 
    });

    it('should sign and verify JWT', async () => {
        const publisher = await createPublisher(testKeyDir, 'pem', 'ML-DSA-65');
        const consumer = await createConsumer(testKeyDir, 'pem', 'ML-DSA-65');

        const payload = { sub: 'test', iat: Math.floor(Date.now() / 1000) };
        const jwt = publisher.encode(payload);
        
        const isValid = consumer.verify(jwt);
        assert.equal(isValid, true);

        const { payload: decoded } = consumer.decode(jwt);
        assert.equal(decoded.sub, 'test');
    });

    it('should throw error for unsupported algorithm', async () => {
        await assert.rejects(async () => {
            await createPublisher(testKeyDir, 'pem', 'UNSUPPORTED-ALG');
        }, AlgorithmNotSupportedError);
    });

    it('should validate expiration', async () => {
        const publisher = await createPublisher(testKeyDir, 'pem', 'ML-DSA-65');
        const consumer = await createConsumer(testKeyDir, 'pem', 'ML-DSA-65');
        
        const payload = { 
            sub: 'test', 
            exp: Math.floor(Date.now() / 1000) - 3600 
        };
        
        const jwt = publisher.encode(payload);

        assert.throws(() => {
            consumer.decode(jwt, true);
        }, JWTExpiredError);
    });

    it('should handle invalid JWT format - wrong number of parts', async () => {
        const consumer = await createConsumer(testKeyDir, 'pem', 'ML-DSA-65');
        assert.throws(() => {
            consumer.decode('part1.part2');
        }, JWTValidationError);
    });

    it('should handle invalid signature', async () => {
            const publisher = await createPublisher(testKeyDir, 'pem', 'ML-DSA-65');
            const consumer = await createConsumer(testKeyDir, 'pem', 'ML-DSA-65');
    
            const jwt = publisher.encode({ sub: 'test' });
            const parts = jwt.split('.');
            

            const signature = parts[2];
            const corruptedSignature = 'X' + signature.substring(1); 
            
            const invalidJwt = `${parts[0]}.${parts[1]}.${corruptedSignature}`;
            
            assert.throws(() => {
                consumer.decode(invalidJwt);
            }, JWTSignatureError);
        });

    it('should handle malformed JSON in JWT', async () => {
        const consumer = await createConsumer(testKeyDir, 'pem', 'ML-DSA-65');
        const header = Buffer.from(JSON.stringify({ alg: "ML-DSA-65", typ: "JWT" })).toString('base64url');
        const invalidPayload = Buffer.from("invalid-json{not:valid}").toString('base64url');
        const malformedJwt = `${header}.${invalidPayload}.signaturepart`;
        
        assert.throws(() => {
            consumer.decode(malformedJwt);
        }, JWTDecodeError);
    });

    it('should handle not-before claim', async () => {
        const publisher = await createPublisher(testKeyDir, 'pem', 'ML-DSA-65');
        const consumer = await createConsumer(testKeyDir, 'pem', 'ML-DSA-65');
        
        const payload = { 
            sub: 'test', 
            nbf: Math.floor(Date.now() / 1000) + 3600 
        };
        
        const jwt = publisher.encode(payload);

        assert.throws(() => {
            consumer.decode(jwt, true);
        }, JWTValidationError);
    });

    it('should handle invalid base64 in JWT', async () => {
        const consumer = await createConsumer(testKeyDir, 'pem', 'ML-DSA-65');
        assert.throws(() => {
            consumer.decode('invalid.base64!.signature');
        }, JWTDecodeError);
    });
});