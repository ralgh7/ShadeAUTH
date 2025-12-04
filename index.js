const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const crypto = require('crypto'); 
const rateLimit = require('express-rate-limit'); 
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Your KeyAuth Credentials ---
const KEYAUTH_APP_NAME = process.env.KEYAUTH_APP_NAME;
const KEYAUTH_OWNER_ID = process.env.KEYAUTH_OWNER_ID;
const KEYAUTH_APP_SECRET = process.env.KEYAUTH_APP_SECRET;

// --- Security Config ---
const DECRYPTION_KEY = process.env.DECRYPTION_KEY || "PARTIAL_KEY_HERE";
const LOADER_FILE_NAME = "Loader.dll"; 
const LOADER_FILE_PATH = path.join(__dirname, LOADER_FILE_NAME); 

// --- Server Side Variables (SSV) ---
const SSV_CONFIG = {
    v1: 1.0,   // Speed
    v2: 1.0,   // Velmax
    v3: 2.75,  // Menu Dist
    v4: 1.0    // Pull
};

// --- State ---
const activeSessions = new Map();
const SESSION_TIMEOUT_MS = 2 * 60 * 1000; 
const downloadTokens = new Map();
const DOWNLOAD_TOKEN_TIMEOUT_MS = 60 * 1000; 

// --- Rate Limiting ---
const verifyLimiter = rateLimit({
    windowMs: 60 * 1000, 
    max: 10, 
    message: { status: 'error', message: 'Too many login attempts.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// --- Middleware ---
app.use(cors());
app.set('trust proxy', 1);
app.use(express.json());
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        console.error('Bad JSON Received:', err.message);
        return res.status(400).send({ status: 'error', message: 'Invalid JSON' });
    }
    next();
});

// --- === ENCRYPTION HELPER === ---
function xorEncrypt(text, key) {
    if (!key) return text;
    let result = [];
    for (let i = 0; i < text.length; i++) {
        result.push(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return Buffer.from(result).toString('base64');
}

// --- /verify Endpoint ---
app.post('/verify', verifyLimiter, async (req, res) => {
    const { key } = req.body;

    if (!key) return res.status(400).json({ status: 'error', message: 'No key provided.' });

    try {
        // 1. Init
        const initParams = new URLSearchParams();
        initParams.append('type', 'init');
        initParams.append('name', KEYAUTH_APP_NAME);
        initParams.append('ownerid', KEYAUTH_OWNER_ID);
        const initResponse = await fetch('https://keyauth.win/api/1.1/', { method: 'POST', body: initParams });
        const initJson = await initResponse.json();
        
        if (!initJson.success) return res.status(500).json({ status: 'error', message: 'Auth server init failed.' });
        
        // 2. Verify
        const sessionId = initJson.sessionid;
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
        try { licenseJson = JSON.parse(responseText); } catch (e) { return res.status(401).json({ status: 'error', message: responseText }); }

        if (licenseJson.success) {
            console.log(`KeyAuth SUCCESS for key: ${key}`);
            let expiryTimestamp = null;
            if (licenseJson.info && licenseJson.info.subscriptions && licenseJson.info.subscriptions.length > 0) {
                expiryTimestamp = licenseJson.info.subscriptions[0].expiry;
            }

            // Generate Session Token
            const sessionToken = crypto.randomBytes(32).toString('hex');
            activeSessions.set(sessionToken, {
                key: key,
                expiry: expiryTimestamp,
                lastHeartbeat: Date.now()
            });
            
            // Generate One-Time Download Token
            const downloadToken = crypto.randomBytes(32).toString('hex');
            downloadTokens.set(downloadToken, { timestamp: Date.now() });
            const fullLoaderUrl = `https://shadeauth.onrender.com/download/${downloadToken}`;

            // Return Plain JSON for Initial Handshake (Reliability)
            return res.status(200).json({
                status: 'success',
                message: 'Key is valid.',
                expiry: expiryTimestamp,
                token: sessionToken,
                decryptionKey: DECRYPTION_KEY,
                loaderUrl: fullLoaderUrl,
                magic: new Date().getUTCMinutes(),
                v1: SSV_CONFIG.v1,
                v2: SSV_CONFIG.v2,
                v3: SSV_CONFIG.v3,
                v4: SSV_CONFIG.v4
            });

        } else {
            return res.status(401).json({ status: 'error', message: licenseJson.message });
        }

    } catch (error) {
        console.error('Error processing KeyAuth verification:', error);
        return res.status(500).json({ status: 'error', message: 'Server error.' });
    }
});

// --- /download Endpoint ---
app.get('/download/:token', (req, res) => {
    const { token } = req.params;
    if (!token) return res.status(400).json({ status: 'error', message: 'No token.' });

    if (downloadTokens.has(token)) {
        const tokenData = downloadTokens.get(token);
        downloadTokens.delete(token); // One-time use

        if (Date.now() - tokenData.timestamp > DOWNLOAD_TOKEN_TIMEOUT_MS) {
            return res.status(401).json({ status: 'error', message: 'Expired.' });
        }

        res.download(LOADER_FILE_PATH, "audio_driver.dll", (err) => {
            if (err) console.error(`File send error: ${err.message}`);
        });
    } else {
        return res.status(404).json({ status: 'error', message: 'Invalid link.' });
    }
});

// --- /heartbeat Endpoint (ENCRYPTED) ---
app.post('/heartbeat', (req, res) => {
    const { token } = req.body;

    if (!token || !activeSessions.has(token)) {
        // Return Plain JSON on error so client knows what happened
        return res.status(401).json({ status: 'error', message: 'Invalid session.' });
    }

    const session = activeSessions.get(token);
    session.lastHeartbeat = Date.now();
    activeSessions.set(token, session);
    
    const payload = { 
        status: 'ok', 
        magic: new Date().getUTCMinutes(),
        v1: SSV_CONFIG.v1,
        v2: SSV_CONFIG.v2,
        v3: SSV_CONFIG.v3,
        v4: SSV_CONFIG.v4
    };

    // Encrypt response using the Session Token as the Key
    const jsonString = JSON.stringify(payload);
    const encryptedString = xorEncrypt(jsonString, token);

    // Send RAW STRING (Base64)
    return res.send(encryptedString); 
});

// --- Cleanup Interval ---
setInterval(() => {
    const now = Date.now();
    for (const [token, session] of activeSessions.entries()) {
        if (now - session.lastHeartbeat > SESSION_TIMEOUT_MS) activeSessions.delete(token);
    }
    for (const [token, data] of downloadTokens.entries()) {
        if (now - data.timestamp > DOWNLOAD_TOKEN_TIMEOUT_MS) downloadTokens.delete(token);
    }
}, 30 * 1000);

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
