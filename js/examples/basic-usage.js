import { createPublisher, createConsumer } from '../src/jwt-manager.js';
import { JWTKeyManager } from '../src/jwt-manager.js';

(async () => {
  try {

    
    const algorithm = 'FN-DSA-512';
    const keyDir = './example-keys';

    //pub init
    const publisher = await createPublisher(keyDir, 'pem', algorithm);
    
    // consumer init
    const consumer = await createConsumer(keyDir, 'pem', algorithm);
    
    // Sign a token
    const token = publisher.encode({
        userId: '12345',
        username: 'alice',
        role: 'admin',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
    });
    
    console.log('Token created successfully:', token);
    
    //  Verify the token
    const isValid = consumer.verify(token);
    console.log('Token valid:', isValid);
    
    // Decode and check payload
    try {
        const { headers, payload } = consumer.decode(token);
        console.log('Token verified successfully!');
        console.log('User ID:', payload.userId);
        console.log('Used algorithm (Header):', headers.alg);
    } catch (error) {
        console.error('Token verification failed:', error.message);
    }

    // Public Key Export
    console.log('\n=== Example 2: Public Key Export ===');
    const publicKeyPem = publisher.getPublicKeyPem();
    console.log('Public Key (PEM):');
    console.log(publicKeyPem.substring(0, 60) + '...');

    // Cleanup (free wasm mem)
    JWTKeyManager.destroyAll();
    
    console.log('\n✅ All examples completed successfully!');

  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  }
})();