const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const crypto = require('crypto'); // For generating secure tokens
const rateLimit = require('express-rate-limit'); // For security
const path = require('path'); // <-- We still need this

const app = express();
const PORT = process.env.PORT || 3000;

// --- Your KeyAuth Credentials from Render Environment Variables ---
const KEYAUTH_APP_NAME = process.env.KEYAUTH_APP_NAME;
const KEYAUTH_OWNER_ID = process.env.KEYAUTH_OWNER_ID;
const KEYAUTH_APP_SECRET = process.env.KEYAUTH_APP_SECRET;

// --- === NEW: DEFINE YOUR SECRET DATA HERE === ---
const DECRYPTION_KEY = process.env.DECRYPTION_KEY || "your-super-secret-key-12345";
// --- NEW: This is the *path* to the file, not the URL ---
const LOADER_FILE_NAME = "Loader.dll";
const LOADER_FILE_PATH = path.join(__dirname, LOADER_FILE_NAME); // Assumes Loader.dll is in the same folder as server.js
// --- === END OF NEW DATA === ---

// --- Session Management ---
const activeSessions = new Map();
const SESSION_TIMEOUT_MS = 2 * 60 * 1000; 
// --- NEW: Map to store one-time download tokens ---
const downloadTokens = new Map();
const DOWNLOAD_TOKEN_TIMEOUT_MS = 60 * 1000; // 1 minute

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

// --- REMOVED ---
// We no longer want a public static folder
// app.use(express.static(path.join(__dirname, 'public')));
// ---

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
            
            // --- NEW: Generate a one-time download token ---
            const downloadToken = crypto.randomBytes(32).toString('hex');
            downloadTokens.set(downloadToken, {
                timestamp: Date.now()
            });
            // Construct the full URL to send to the client
            const fullLoaderUrl = `https://shadeauth.onrender.com/download/${downloadToken}`;

            // --- === RETURN ALL DATA TO THE CLIENT === ---
            return res.status(200).json({
                status: 'success',
                message: 'Key is valid.',
                expiry: expiryTimestamp,
                token: sessionToken,
                decryptionKey: DECRYPTION_KEY, // <-- Send the dynamic key
                loaderUrl: fullLoaderUrl        // <-- Send the NEW one-time URL
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

// --- NEW: SECURE DOWNLOAD ENDPOINT ---
app.get('/download/:token', (req, res) => {
    const { token } = req.params;

    if (!token) {
        return res.status(400).json({ status: 'error', message: 'No token provided.' });
    }

    // Check if the one-time token is valid
    if (downloadTokens.has(token)) {
        const tokenData = downloadTokens.get(token);
        
        // --- ONE-TIME-USE: Delete the token immediately ---
        downloadTokens.delete(token); 

        // Optional: Check if token is expired (e.g., 1 minute)
        if (Date.now() - tokenData.timestamp > DOWNLOAD_TOKEN_TIMEOUT_MS) {
            console.log("Download token expired.");
            return res.status(401).json({ status: 'error', message: 'Download link expired.' });
        }

        // Token is valid, send the file
        console.log("Valid download token presented. Sending file...");
        res.download(LOADER_FILE_PATH, LOADER_FILE_NAME, (err) => {
            if (err) {
                console.error(`File send error: ${err.message}`);
                // res.status(500).json({ status: 'error', message: 'Error sending file.' });
            }
        });

    } else {
        // Token is invalid or has already been used
        console.log("Invalid or used download token.");
        return res.status(404).json({ status: 'error', message: 'Invalid download link.' });
    }
});
// --- END OF NEW ENDPOINT ---

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
        
        // --- NEW ENTANGLEMENT (This is for Phase 4) ---
        const oneTimeData = crypto.randomBytes(8).toString('hex');

        return res.status(200).json({ 
            status: 'ok', 
            oneTimeData: oneTimeData // <-- Send new data
        });

    } else {
        // Invalid or expired token. Tell the mod to eject.
        return res.status(401).json({ status: 'error', message: 'Invalid or expired session.' });
    }
});

// --- Session Cleanup ---
setInterval(() => {
    const now = Date.now();
    let cleanedSessions = 0;
    for (const [token, session] of activeSessions.entries()) {
        if (now - session.lastHeartbeat > SESSION_TIMEOUT_MS) {
            activeSessions.delete(token);
            cleanedSessions++;
        }
    }
    if (cleanedSessions > 0) {
        console.log(`Cleaned up ${cleanedSessions} expired sessions.`);
    }

    // --- NEW: Clean up expired download tokens ---
    let cleanedDownloads = 0;
    for (const [token, data] of downloadTokens.entries()) {
        if (now - data.timestamp > DOWNLOAD_TOKEN_TIMEOUT_MS) {
            downloadTokens.delete(token);
            cleanedDownloads++;
        }
    }
    if (cleanedDownloads > 0) {
        console.log(`Cleaned up ${cleanedDownloads} expired download tokens.`);
    }

}, 30 * 1000); // Run every 30 seconds

app.listen(PORT, () => {
    console.log(`KeyAuth proxy server running on port ${PORT}`);
});
