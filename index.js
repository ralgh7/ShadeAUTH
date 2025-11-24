const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const crypto = require('crypto'); // For generating secure tokens
const rateLimit = require('express-rate-limit'); // For security

const app = express();
const PORT = process.env.PORT || 3000;

// --- Your KeyAuth Credentials from Render Environment Variables ---
const KEYAUTH_APP_NAME = process.env.KEYAUTH_APP_NAME;
const KEYAUTH_OWNER_ID = process.env.KEYAUTH_OWNER_ID;
const KEYAUTH_APP_SECRET = process.env.KEYAUTH_APP_SECRET;

// --- === NEW: DEFINE YOUR SECRET DATA HERE === ---
// Load these from environment variables for best security
// This is the key your C++ loader uses to decrypt your C# mod.
const DECRYPTION_KEY = process.env.DECRYPTION_KEY || "your-super-secret-key-12345";
// This is the URL where your WinForm app will download the Loader.dll
const LOADER_URL = process.env.LOADER_URL || "https://shadeauth.onrender.com/Loader.dll";
// --- === END OF NEW DATA === ---

// --- Session Management ---
const activeSessions = new Map();
const SESSION_TIMEOUT_MS = 2 * 60 * 1000; 

// --- Rate Limiter ---
const verifyLimiter = rateLimit({
	windowMs: 60 * 1000, // 1 minute
	max: 10, 
	message: { status: 'error', message: 'Too many login attempts. Please try again in a minute.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Middleware
app.use(cors());
app.use(express.json());

// --- /verify Endpoint (Rate Limited) ---
app.post('/verify', verifyLimiter, async (req, res) => {
    const { key } = req.body;

    if (!key) {
        return res.status(400).json({ status: 'error', message: 'No key provided.' });
    }

    try {
        // Step 1: Initialize a session with KeyAuth
        const initParams = new URLSearchParams();
        initParams.append('type', 'init');
        initParams.append('name', KEYAUTH_APP_NAME);
        initParams.append('ownerid', KEYAUTH_OWNER_ID);
        const initResponse = await fetch('https://keyauth.win/api/1.1/', { method: 'POST', body: initParams });
        const initJson = await initResponse.json();
        if (!initJson.success) {
            console.log(`KeyAuth INIT FAILED: ${initJson.message}`);
            return res.status(500).json({ status: 'error', message: 'Auth server init failed.' });
        }
        const sessionId = initJson.sessionid;

        // Step 2: Validate the license key
        const licenseParams = new URLSearchParams();
        licenseParams.append('type', 'license');
        licenseParams.append('key', key.trim());
        licenseParams.append('sessionid', sessionId);
        licenseParams.append('name', KEYAUTH_APP_NAME);
        licenseParams.append('ownerid', KEYAUTH_OWNER_ID);
        licenseParams.append('secret', KEYAUTH_APP_SECRET);
        const licenseResponse = await fetch('https://keyauth.win/api/1.1/', { method: 'POST', body: licenseParams });
        const responseText = await licenseResponse.text();
        
        let licenseJson;
        try {
            licenseJson = JSON.parse(responseText);
        } catch (e) {
            console.log(`KeyAuth verification failed with a non-JSON response: ${responseText}`);
            return res.status(401).json({ status: 'error', message: responseText });
        }


        if (licenseJson.success) {
            console.log(`KeyAuth SUCCESS for key: ${key}`);
            let expiryTimestamp = null;
            if (licenseJson.info && licenseJson.info.subscriptions && licenseJson.info.subscriptions.length > 0) {
                expiryTimestamp = licenseJson.info.subscriptions[0].expiry;
            }

            // --- Generate and store a secure session token ---
            const sessionToken = crypto.randomBytes(32).toString('hex');

            activeSessions.set(sessionToken, {
                key: key,
                expiry: expiryTimestamp,
                lastHeartbeat: Date.now()
            });

            console.log(`Issued session token: ${sessionToken.substring(0, 8)}...`);

            // --- === NEW: RETURN ALL DATA TO THE CLIENT === ---
            return res.status(200).json({
                status: 'success',
                message: 'Key is valid.',
                expiry: expiryTimestamp,
                token: sessionToken,
                decryptionKey: DECRYPTION_KEY, // <-- Send the dynamic key
                loaderUrl: LOADER_URL          // <-- Send the download URL
            });
            // --- === END OF CHANGE === ---

        } else {
            console.log(`KeyAuth FAILURE for key: ${key} - Reason: ${licenseJson.message}`);
            return res.status(401).json({ status: 'error', message: licenseJson.message });
        }

    } catch (error) {
        console.error('Error processing KeyAuth verification:', error);
        return res.status(500).json({ status: 'error', message: 'Server error while verifying key.' });
    }
});

// --- /heartbeat Endpoint ---
app.post('/heartbeat', (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ status: 'error', message: 'No token.' });
    }

    if (activeSessions.has(token)) {
        // Valid token. Update its last heartbeat time.
        const session = activeSessions.get(token);
        session.lastHeartbeat = Date.now();
        activeSessions.set(token, session);
        
        return res.status(200).json({ status: 'ok' });
    } else {
        // Invalid or expired token. Tell the mod to eject.
        return res.status(401).json({ status: 'error', message: 'Invalid or expired session.' });
    }
});

// --- Session Cleanup ---
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [token, session] of activeSessions.entries()) {
        if (now - session.lastHeartbeat > SESSION_TIMEOUT_MS) {
            activeSessions.delete(token);
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`Cleaned up ${cleaned} expired sessions.`);
    }
}, 30 * 1000); // Run every 30 seconds

app.listen(PORT, () => {
    console.log(`KeyAuth proxy server running on port ${PORT}`);
});
