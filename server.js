const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express(); // Declare app before using it

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

const secretKey = crypto.randomBytes(32).toString('hex'); // Generates a 64-character hex string
console.log(secretKey);

app.use(cors());
app.use(bodyParser.json());

// Database connection setup
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'secret_messages'
});

// Connect to the database
db.connect(err => {
    if (err) {
        console.error('Database connection failed: ' + err.stack);
        return;
    }
    console.log('Connected to the database.');
});

// Middleware for token authentication
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ status: 'error', message: 'Access denied' });

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.status(403).json({ status: 'error', message: 'Invalid token' });

        req.user = user;
        next();
    });
}

// Registration Route
app.post('/register', (req, res) => {
    const { name, surname, email, password } = req.body;

    // Hash the password before saving to the database
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.status(500).json({ status: 'error', message: 'Password hashing failed' });
        }

        const sql = 'INSERT INTO users (name, surname, email, password) VALUES (?, ?, ?, ?)';
        db.query(sql, [name, surname, email, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ status: 'error', message: 'Email already registered' });
                }
                return res.status(500).json({ status: 'error', message: 'Database error' });
            }
            res.json({ status: 'success', message: 'User registered successfully' });
        });
    });
});

// Login Route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', message: 'Database error: ' + err.message });
        }

        if (results.length === 0) {
            return res.status(401).json({ status: 'error', message: 'User not found' });
        }

        const user = results[0];

        // Compare the provided password with the stored hashed password
        bcrypt.compare(password, user.password, (err, match) => {
            if (err) {
                return res.status(500).json({ status: 'error', message: 'Password comparison error: ' + err.message });
            }

            if (!match) {
                return res.status(401).json({ status: 'error', message: 'Incorrect password' });
            }

            // Generate a JWT token
            const token = jwt.sign({ id: user.id, name: user.name, surname: user.surname, email: user.email }, secretKey, { expiresIn: '1h' });
            res.json({ status: 'success', token, userId: user.id, name: user.name }); // Send userId and name along with the token
        });
    });
});


// Send Message Route (Now Public)
app.post('/send', (req, res) => {
    const { message, recipientUserId } = req.body;

    // Store the encrypted message in the user_messages table
    const sql = 'INSERT INTO messages (encrypted_message, user_id) VALUES (?, ?)';
    db.query(sql, [message, recipientUserId], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', message: 'Database error: ' + err.message });
        }
        res.json({ status: 'success', message: 'Message sent successfully!' });
    });
});


// Fetch Messages Route (Protected)
app.get('/messages', authenticateToken, (req, res) => {
    const sql = 'SELECT * FROM messages WHERE user_id = ?';
    db.query(sql, [req.user.id], (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', message: 'Database error' });
        }

        res.json({ status: 'success', messages: results });
    });
});

// Start the server
app.listen(3000, () => {
    console.log("Server started on port 3000");
});
