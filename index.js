const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Your KeyAuth Credentials from Render Environment Variables ---
const KEYAUTH_APP_NAME = process.env.KEYAUTH_APP_NAME;
const KEYAUTH_OWNER_ID = process.env.KEYAUTH_OWNER_ID;
const KEYAUTH_APP_SECRET = process.env.KEYAUTH_APP_SECRET;


// Middleware
app.use(cors());
app.use(express.json());

// The verification endpoint
app.post('/verify', async (req, res) => {
    const { key } = req.body;

    if (!key) {
        return res.status(400).json({ status: 'error', message: 'No key provided.' });
    }

    try {
        // Step 1: Initialize a session with KeyAuth to get a session ID.
        const initParams = new URLSearchParams();
        initParams.append('type', 'init');
        initParams.append('name', KEYAUTH_APP_NAME);
        initParams.append('ownerid', KEYAUTH_OWNER_ID);

        const initResponse = await fetch('https://keyauth.win/api/1.1/', {
            method: 'POST',
            body: initParams
        });
        const initJson = await initResponse.json();

        if (!initJson.success) {
            console.log(`KeyAuth INIT FAILED: ${initJson.message}`);
            return res.status(500).json({ status: 'error', message: 'Authentication server failed to initialize.' });
        }

        const sessionId = initJson.sessionid;

        // Step 2: Use the new session ID to validate the user's license key.
        const licenseParams = new URLSearchParams();
        licenseParams.append('type', 'license');
        licenseParams.append('key', key.trim());
        licenseParams.append('sessionid', sessionId);
        licenseParams.append('name', KEYAUTH_APP_NAME);
        licenseParams.append('ownerid', KEYAUTH_OWNER_ID);
        licenseParams.append('secret', KEYAUTH_APP_SECRET);

        const licenseResponse = await fetch(
            'https://keyauth.win/api/1.1/',
            {
                method: 'POST',
                body: licenseParams
            }
        );

        const licenseJson = await licenseResponse.json();

        if (licenseJson.success) {
            console.log(`KeyAuth SUCCESS for key: ${key}`);

            let expiryTimestamp = null;

            // --- FIX: Use the correct path to get the expiry timestamp ---
            // Safely check that 'info' and 'subscriptions' exist and the array is not empty.
            if (licenseJson.info && licenseJson.info.subscriptions && licenseJson.info.subscriptions.length > 0) {
                expiryTimestamp = licenseJson.info.subscriptions[0].expiry;
            }

            return res.status(200).json({
                status: 'success',
                message: 'Key is valid.',
                expiry: expiryTimestamp 
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

app.listen(PORT, () => {
    console.log(`KeyAuth proxy server running on port ${PORT}`);
});
