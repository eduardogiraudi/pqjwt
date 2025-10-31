import { createPQJWT, createPublisherSimple, createConsumerSimple } from '../src/index.js';

// Example 1: Simple usage with PQJWT class
console.log('=== Example 1: Basic PQJWT Usage ===');

const pqjwt = createPQJWT({
    mode: 'publisher',
    keyDir: './example-keys',
    algorithm: 'ML-DSA-65'
});

// Sign a token
const token = pqjwt.sign({
    userId: '12345',
    username: 'alice',
    role: 'admin',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
});

console.log('Token:', token.substring(0, 50) + '...');

// Verify the token
const isValid = pqjwt.isValid(token);
console.log('Token valid:', isValid);

// Example 2: Publisher/Consumer pattern
console.log('\n=== Example 2: Publisher/Consumer Pattern ===');

const publisher = createPublisherSimple('./example-keys', 'ML-DSA-65');
const consumer = createConsumerSimple('./example-keys', 'ML-DSA-65');

// Publisher creates token
const userToken = publisher.sign({
    userId: '67890',
    email: 'user@example.com',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 7200 // 2 hours
});

console.log('User token created');

// Consumer verifies token
try {
    const { headers, payload } = consumer.verify(userToken);
    console.log('Token verified successfully!');
    console.log('User ID:', payload.userId);
    console.log('Email:', payload.email);
} catch (error) {
    console.error('Token verification failed:', error.message);
}

// Example 3: Get public key for sharing
console.log('\n=== Example 3: Public Key Export ===');

const publicKeyPem = publisher.getPublicKey('pem');
console.log('Public Key (PEM):');
console.log(publicKeyPem.substring(0, 100) + '...');

console.log('\n✅ All examples completed successfully!');