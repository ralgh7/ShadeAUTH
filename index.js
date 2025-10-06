const express = require('express');
const cors = require('cors');
const { Pool } = require('pg'); // Import the pg library

const app = express();
const PORT = process.env.PORT || 3000;

// --- Database Connection ---
// The app will get the connection string from an environment variable on Render.
// This is more secure than pasting the URL directly in the code.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for Render's database connections
  }
});

// --- One-time script to create the database table ---
// We'll run this automatically when the server starts if the table doesn't exist.
const initializeDatabase = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS auth_keys (
        id SERIAL PRIMARY KEY,
        key_value TEXT NOT NULL UNIQUE,
        activation_date TIMESTAMP,
        duration_days INTEGER NOT NULL
      );
    `);
    console.log('Database table "auth_keys" is ready.');
  } catch (err) {
    console.error('Error initializing database table:', err);
  } finally {
    client.release();
  }
};


// Middleware
app.use(cors());
app.use(express.json());

// --- The New Verification Endpoint ---
app.post('/verify', async (req, res) => {
    const { key } = req.body;

    if (!key) {
        return res.status(400).json({ status: 'error', message: 'No key provided.' });
    }

    try {
        const client = await pool.connect();
        const result = await client.query('SELECT * FROM auth_keys WHERE key_value = $1', [key.trim()]);
        
        if (result.rows.length === 0) {
            console.log(`Failed validation: Key not found - ${key}`);
            client.release();
            return res.status(401).json({ status: 'error', message: 'Invalid key.' });
        }

        const keyData = result.rows[0];

        // --- Timer Logic ---
        if (keyData.activation_date) {
            // Key has already been activated, check if it's expired.
            const activationDate = new Date(keyData.activation_date);
            const expirationDate = new Date(activationDate);
            expirationDate.setDate(activationDate.getDate() + keyData.duration_days);

            if (new Date() > expirationDate) {
                console.log(`Failed validation: Key has expired - ${key}`);
                client.release();
                return res.status(401).json({ status: 'error', message: 'This key has expired.' });
            }
        } else {
            // This is the FIRST time the key is being used. Activate it now.
            console.log(`First use for key: ${key}. Activating timer.`);
            const updateQuery = 'UPDATE auth_keys SET activation_date = NOW() WHERE id = $1';
            await client.query(updateQuery, [keyData.id]);
        }

        console.log(`Successfully validated key: ${key}`);
        client.release();
        return res.status(200).json({ status: 'success', message: 'Key is valid.' });

    } catch (err) {
        console.error('Database query error', err.stack);
        return res.status(500).json({ status: 'error', message: 'Server error during verification.' });
    }
});

// Start the server after ensuring the database is ready
app.listen(PORT, async () => {
    await initializeDatabase();
    console.log(`Auth server running on port ${PORT}`);
});
