const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Initialize SQLite database
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database');
        // Create users table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
            profile_info TEXT
        )`, (err) => {
            if (err) {
                console.error('Error creating table:', err.message);
            } else {
                console.log('Users table created/verified');
                // Insert default admin user (VULNERABLE: plain text password)
                db.run(`INSERT OR IGNORE INTO users (username, email, password, profile_info) 
                        VALUES ('admin', 'admin@test.com', 'password123', 'Administrator account')`, (err) => {
                    if (err) {
                        console.error('Error inserting admin user:', err.message);
                    } else {
                        console.log('Default admin user ready');
                    }
                });
            }
        });
    }
});

// Routes

// Home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// VULNERABLE LOGIN ENDPOINT - SQL Injection vulnerability
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // Ensure we always return JSON
    res.setHeader('Content-Type', 'application/json');
    
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required' });
    }
    
    // VULNERABILITY: Direct string concatenation allows SQL injection
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    console.log('Executing query:', query); // For debugging
    
    db.get(query, (err, row) => {
        if (err) {
            console.error('Database error:', err.message);
            return res.status(500).json({ success: false, error: 'Database error', details: err.message });
        }
        
        if (row) {
            // VULNERABILITY: Returning sensitive data
            res.json({ 
                success: true, 
                message: 'Login successful', 
                user: {
                    id: row.id,
                    username: row.username,
                    email: row.email,
                    password: row.password, // VULNERABILITY: Exposing password
                    profile_info: row.profile_info
                }
            });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    });
});

// VULNERABLE SIGNUP ENDPOINT - No input validation
app.post('/api/signup', (req, res) => {
    const { username, email, password, profile_info } = req.body;
    
    // Ensure we always return JSON
    res.setHeader('Content-Type', 'application/json');
    
    if (!username || !email || !password) {
        return res.status(400).json({ success: false, message: 'Username, email, and password required' });
    }
    
    // VULNERABILITY: No input validation or sanitization
    // VULNERABILITY: Plain text password storage
    // Basic escaping to prevent SQL breaking (but still vulnerable to injection)
    const escapedUsername = username.replace(/'/g, "''");
    const escapedEmail = email.replace(/'/g, "''");
    const escapedPassword = password.replace(/'/g, "''");
    const escapedProfileInfo = (profile_info || '').replace(/'/g, "''");
    
    const query = `INSERT INTO users (username, email, password, profile_info) 
                   VALUES ('${escapedUsername}', '${escapedEmail}', '${escapedPassword}', '${escapedProfileInfo}')`;
    
    console.log('Executing signup query:', query);
    
    db.run(query, function(err) {
        if (err) {
            console.error('Signup error:', err.message);
            return res.status(400).json({ success: false, error: 'Signup failed', details: err.message });
        }
        
        res.json({ 
            success: true, 
            message: 'User created successfully',
            userId: this.lastID 
        });
    });
});

// VULNERABLE PROFILE ENDPOINT - XSS vulnerability
app.get('/api/profile/:username', (req, res) => {
    const { username } = req.params;
    
    // VULNERABILITY: SQL injection in URL parameter
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    
    db.get(query, (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (row) {
            // VULNERABILITY: Returning unsanitized data that could contain XSS
            res.json({
                username: row.username,
                email: row.email,
                profile_info: row.profile_info, // This will be displayed without sanitization
                created_at: 'N/A'
            });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    });
});

// VULNERABLE UPDATE PROFILE ENDPOINT
app.post('/api/update-profile', (req, res) => {
    const { username, email, profile_info } = req.body;
    
    // VULNERABILITY: No authentication check
    // VULNERABILITY: SQL injection
    const query = `UPDATE users SET email = '${email}', profile_info = '${profile_info}' 
                   WHERE username = '${username}'`;
    
    db.run(query, function(err) {
        if (err) {
            return res.status(500).json({ error: 'Update failed', details: err.message });
        }
        
        res.json({ success: true, message: 'Profile updated successfully' });
    });
});

// VULNERABLE ADMIN ENDPOINT - No authentication
app.get('/api/admin/users', (req, res) => {
    // VULNERABILITY: No authentication or authorization check
    db.all('SELECT * FROM users', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        // VULNERABILITY: Exposing all user data including passwords
        res.json({ users: rows });
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚨 VULNERABLE User Management System running on http://localhost:${PORT}`);
    console.log('⚠️  WARNING: This application contains intentional security vulnerabilities for educational purposes!');
    console.log('🔍 Test with: OWASP ZAP, SQL injection, XSS attacks');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down server...');
    db.close((err) => {
        if (err) {
            console.error(err.message);
        } else {
            console.log('Database connection closed.');
        }
        process.exit(0);
    });
});
