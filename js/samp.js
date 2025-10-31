import {createPublisher, createConsumer} 
async function example() {
    // Create a publisher
    const publisher = await createPublisher("./keys", "pem", "ML-DSA-65");
    
    // Create a JWT
    const payload = { 
        sub: "user123", 
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600 
    };
    
    const jwt = await publisher.encode(payload);
    console.log("JWT:", jwt);
    
    // Verify the JWT
    const consumer = await createConsumer("./keys", "pem", "ML-DSA-65");
    const isValid = await consumer.verify(jwt);
    console.log("JWT valid:", isValid);
    
    if (isValid) {
        const decoded = await consumer.decode(jwt);
        console.log("Decoded JWT:", decoded);
    }
}

await example();