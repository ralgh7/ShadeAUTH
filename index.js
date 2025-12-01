const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const crypto = require('crypto'); // For generating secure tokens
const rateLimit = require('express-rate-limit'); // For security
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Your KeyAuth Credentials from Render Environment Variables ---
const KEYAUTH_APP_NAME = process.env.KEYAUTH_APP_NAME;
const KEYAUTH_OWNER_ID = process.env.KEYAUTH_OWNER_ID;
const KEYAUTH_APP_SECRET = process.env.KEYAUTH_APP_SECRET;

// --- === SECURITY CONFIGURATION === ---
// IMPORTANT: This should be the PARTIAL key. 
// If your C++ Salt is "SHADE_V1", and you want the full key to be "MYKEYSHADE_V1",
// then this variable should just be "MYKEY".
const DECRYPTION_KEY = process.env.DECRYPTION_KEY || "PARTIAL_KEY_HERE";

// This is the actual file on the server disk. 
// Ensure your VMProtected DLL is renamed to 'Loader.dll' and uploaded to the root folder.
const LOADER_FILE_NAME = "Loader.dll"; 
const LOADER_FILE_PATH = path.join(__dirname, LOADER_FILE_NAME); 
// --- === END CONFIG === ---

// --- Session Management ---
const activeSessions = new Map();
const SESSION_TIMEOUT_MS = 2 * 60 * 1000; 
// Map to store one-time download tokens
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
        
        // Handle non-JSON responses gracefully
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
            
            // --- Generate a one-time download token ---
            const downloadToken = crypto.randomBytes(32).toString('hex');
            downloadTokens.set(downloadToken, {
                timestamp: Date.now()
            });
            
            // Construct the one-time URL
            const fullLoaderUrl = `https://shadeauth.onrender.com/download/${downloadToken}`;

            return res.status(200).json({
                status: 'success',
                message: 'Key is valid.',
                expiry: expiryTimestamp,
                token: sessionToken,
                decryptionKey: DECRYPTION_KEY, // Sending PARTIAL key
                loaderUrl: fullLoaderUrl        // Sending One-Time URL
            });

        } else {
            console.log(`KeyAuth FAILURE for key: ${key} - Reason: ${licenseJson.message}`);
            return res.status(401).json({ status: 'error', message: licenseJson.message });
        }

    } catch (error) {
        console.error('Error processing KeyAuth verification:', error);
        return res.status(500).json({ status: 'error', message: 'Server error while verifying key.' });
    }
});

// --- SECURE DOWNLOAD ENDPOINT ---
app.get('/download/:token', (req, res) => {
    const { token } = req.params;

    if (!token) {
        return res.status(400).json({ status: 'error', message: 'No token provided.' });
    }

    if (downloadTokens.has(token)) {
        const tokenData = downloadTokens.get(token);
        
        // --- ONE-TIME-USE: Delete immediately ---
        downloadTokens.delete(token); 

        // Check expiry (1 minute)
        if (Date.now() - tokenData.timestamp > DOWNLOAD_TOKEN_TIMEOUT_MS) {
            return res.status(401).json({ status: 'error', message: 'Download link expired.' });
        }

        // Send the VMProtected DLL
        res.download(LOADER_FILE_PATH, "audio_driver.dll", (err) => {
            if (err) {
                console.error(`File send error: ${err.message}`);
            }
        });

    } else {
        return res.status(404).json({ status: 'error', message: 'Invalid or used download link.' });
    }
});

// --- /heartbeat Endpoint ---
app.post('/heartbeat', (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ status: 'error', message: 'No token.' });
    }

    if (activeSessions.has(token)) {
        // Update last heartbeat
        const session = activeSessions.get(token);
        session.lastHeartbeat = Date.now();
        activeSessions.set(token, session);
        
        // --- NEW SECURITY LOGIC: Time-Based Trap ---
        const currentMinute = new Date().getUTCMinutes();

        // --- LOGGING ADDED HERE ---
        console.log(`[Heartbeat] Token: ${token.substring(0, 6)}... | Sending UTC Minute: ${currentMinute}`);

        return res.status(200).json({ 
            status: 'ok', 
            magic: currentMinute 
        });

    } else {
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
    
    // Clean up expired download tokens
    for (const [token, data] of downloadTokens.entries()) {
        if (now - data.timestamp > DOWNLOAD_TOKEN_TIMEOUT_MS) {
            downloadTokens.delete(token);
        }
    }
}, 30 * 1000);

app.listen(PORT, () => {
    console.log(`KeyAuth proxy server running on port ${PORT}`);
});
