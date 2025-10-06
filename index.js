const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// --- IMPORTANT: Your KeyAuth Credentials ---
// For the best security, set these as Environment Variables on Render.
const KEYAUTH_APP_NAME = process.env.KEYAUTH_APP_NAME || "YOUR_APP_NAME_HERE";
const KEYAUTH_OWNER_ID = process.env.KEYAUTH_OWNER_ID || "YOUR_OWNER_ID_HERE";
const KEYAUTH_APP_SECRET = process.env.KEYAUTH_APP_SECRET || "YOUR_APP_SECRET_HERE";


// Middleware
app.use(cors());
app.use(express.json());

// The verification endpoint
app.post('/verify', async (req, res) => {
    const { key } = req.body;

    if (!key) {
        return res.status(400).json({ status: 'error', message: 'No key provided.' });
    }

    // Prepare data to be sent to the KeyAuth API
    // Using URLSearchParams automatically formats it correctly
    const params = new URLSearchParams();
    params.append('type', 'license');
    params.append('key', key.trim());
    params.append('name', KEYAUTH_APP_NAME);
    params.append('ownerid', KEYAUTH_OWNER_ID);
    params.append('secret', KEYAUTH_APP_SECRET);

    try {
        const apiResponse = await fetch(
            'https://keyauth.win/api/1.1/', 
            {
                method: 'POST',
                body: params
            }
        );

        const responseJson = await apiResponse.json();

        // Check the 'success' field from KeyAuth's response
        if (responseJson.success) {
            console.log(`KeyAuth SUCCESS for key: ${key}`);
            return res.status(200).json({ status: 'success', message: responseJson.message });
        } else {
            // Key is invalid, expired, etc.
            console.log(`KeyAuth FAILURE for key: ${key} - Reason: ${responseJson.message}`);
            return res.status(401).json({ status: 'error', message: responseJson.message });
        }

    } catch (error) {
        console.error('Error contacting KeyAuth API:', error);
        return res.status(500).json({ status: 'error', message: 'Server error while verifying key.' });
    }
});

app.listen(PORT, () => {
    console.log(`KeyAuth proxy server running on port ${PORT}`);
});

