const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// IMPORTANT: In a real app, these would come from a secure database!
const VALID_KEYS = ['KEY-1234-ABCD', 'TEST-KEY-001', 'SHADE-MOD-XYZ'];

// Middleware
app.use(cors()); // Allows requests from any origin
app.use(express.json()); // Allows us to read JSON from the request body

// The verification endpoint
app.post('/verify', (req, res) => {
    const { key } = req.body;

    if (!key) {
        return res.status(400).json({ status: 'error', message: 'No key provided.' });
    }

    if (VALID_KEYS.includes(key.trim())) {
        console.log(`Successfully validated key: ${key}`);
        return res.status(200).json({ status: 'success', message: 'Key is valid.' });
    } else {
        console.log(`Failed validation for key: ${key}`);
        return res.status(401).json({ status: 'error', message: 'Invalid key.' });
    }
});

app.listen(PORT, () => {
    console.log(`Auth server running on port ${PORT}`);
});
