const { Client, Databases } = require('node-appwrite');
const crypto = require('crypto');

module.exports = async ({ req, res, log, error }) => {
    // Check required environment variables
    const webhookSecret = process.env.NRFCLOUD_WEBHOOK_SECRET;
    const databaseId = process.env.DATABASE_ID;
    const collectionId = process.env.COLLECTION_ID;

    if (!webhookSecret || !databaseId || !collectionId) {
        error('Missing required environment variables (NRFCLOUD_WEBHOOK_SECRET, DATABASE_ID, or COLLECTION_ID).');
        return res.send('Internal Server Error', 500);
    }
    
    // 1. Basic Request Validation
    if (req.method !== 'POST') {
        return res.send('Method Not Allowed', 405);
    }
    
    // --- 2. nRF Cloud Signature Verification (Security) ---
    const nrfSignature = req.headers['x-nrfcloud-signature'];
    
    if (!nrfSignature) {
        error('Missing X-NRFCLOUD-SIGNATURE header. Rejecting request.');
        return res.send('Unauthorized: Missing signature', 401);
    }
    
    // nRF Cloud sends the HMAC-SHA256 signature calculated over the raw request body.
    const hmac = crypto.createHmac('sha256', webhookSecret);
    hmac.update(req.body);
    const calculatedSignature = hmac.digest('hex');
    
    if (calculatedSignature !== nrfSignature) {
        error(`Signature mismatch. Calculated: ${calculatedSignature}, Received: ${nrfSignature}`);
        return res.send('Unauthorized: Invalid signature', 401);
    }
    log('Signature verified successfully.');

    // --- 3. Payload Parsing and Verification Check ---
    let payload;
    try {
        payload = JSON.parse(req.body);
    } catch (e) {
        error(`Invalid JSON payload: ${e.message}`);
        return res.send('Invalid JSON', 400);
    }

    // Handle initial verification request
    if (payload.event === 'verification') {
        log(`Received verification request with token: ${payload.token}. Please confirm in nRF Cloud portal.`);
        // Respond with OK to acknowledge receipt.
        return res.send('Verification request acknowledged', 200);
    }

    // --- 4. Appwrite Database Storage ---
    if (Array.isArray(payload.messages) && payload.messages.length > 0) {
        log(`Processing ${payload.messages.length} messages.`);
        
        // Initialize Appwrite Client using environment variables
        const client = new Client()
            .setEndpoint(process.env.APPWRITE_ENDPOINT)
            .setProject(process.env.APPWRITE_PROJECT_ID)
            .setKey(process.env.APPWRITE_API_KEY); 
        
        const databases = new Databases(client);

        for (const message of payload.messages) {
            try {
                const deviceId = message.device_id;
                const messageType = message.appId;
                const timestamp = message.ts; // ISO 8601 timestamp
                const payloadData = message.payload; 

                // Store the data in the Appwrite Database
                await databases.createDocument(
                    databaseId,
                    collectionId,
                    'unique()', // Let Appwrite generate a unique ID
                    {
                        deviceId: deviceId,
                        appId: messageType,
                        timestamp: timestamp,
                        // Store the payload data as a string or JSON object depending on your collection attribute
                        payload: JSON.stringify(payloadData), 
                    }
                );
                log(`Successfully stored message from device: ${deviceId}`);

            } catch (e) {
                error(`Database error for message from ${message.device_id || 'unknown'}: ${e.message}`);
                // Continue processing other messages even if one fails
            }
        }
    } else {
        log('Payload contains no messages or is of an unexpected format.');
    }

    // Always respond with 200 OK to confirm successful receipt
    return res.send('Webhook processing complete', 200);
};