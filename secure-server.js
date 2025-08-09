const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const winston = require('winston');

const app = express();
const PORT = 3001; // Different port for secure version
const JWT_SECRET = 'your-secret-key-change-in-production';

// Set up Winston logging
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline scripts
            styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
})); // Secure HTTP headers with CSP configuration
app.use(cors({
    origin: ['http://localhost:3001'], // Restrict CORS to specific origin
    credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public-secure')));

// Rate limiting middleware (basic implementation)
const requestCounts = new Map();
const rateLimit = (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    const windowSize = 60000; // 1 minute
    const maxRequests = 100; // Max 100 requests per minute
    
    if (!requestCounts.has(ip)) {
        requestCounts.set(ip, []);
    }
    
    const requests = requestCounts.get(ip);
    const validRequests = requests.filter(time => now - time < windowSize);
    
    if (validRequests.length >= maxRequests) {
        logger.warn(`Rate limit exceeded for IP: ${ip}`);
        return res.status(429).json({ error: 'Too many requests' });
    }
    
    validRequests.push(now);
    requestCounts.set(ip, validRequests);
    next();
};

app.use(rateLimit);

// Initialize SQLite database with better structure
const db = new sqlite3.Database('./secure_users.db', (err) => {
    if (err) {
        logger.error('Error opening database:', err.message);
    } else {
        logger.info('Connected to secure SQLite database');
        // Create users table with better structure
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            profile_info TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            failed_login_attempts INTEGER DEFAULT 0,
            account_locked BOOLEAN DEFAULT 0
        )`, (err) => {
            if (err) {
                logger.error('Error creating table:', err.message);
            } else {
                logger.info('Secure users table created/verified');
                // Create secure admin user
                createDefaultAdmin();
            }
        });
    }
});

// Create default admin user with hashed password
async function createDefaultAdmin() {
    try {
        const hashedPassword = await bcrypt.hash('SecureAdmin123!', 12);
        db.run(`INSERT OR IGNORE INTO users (username, email, password_hash, profile_info) 
                VALUES (?, ?, ?, ?)`, 
                ['admin', 'admin@secure.com', hashedPassword, 'Secure Administrator account'],
                (err) => {
                    if (err) {
                        logger.error('Error creating admin user:', err.message);
                    } else {
                        logger.info('Secure admin user ready');
                    }
                });
    } catch (error) {
        logger.error('Error hashing admin password:', error);
    }
}

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
        logger.warn('Access attempt without token');
        return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            logger.warn('Invalid token access attempt');
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Input validation and sanitization middleware
const validateAndSanitize = {
    login: (req, res, next) => {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        if (!validator.isLength(username, { min: 3, max: 50 })) {
            return res.status(400).json({ error: 'Username must be 3-50 characters' });
        }
        
        if (!validator.isLength(password, { min: 8, max: 128 })) {
            return res.status(400).json({ error: 'Password must be 8-128 characters' });
        }
        
        // Sanitize inputs
        req.body.username = validator.escape(username.trim());
        req.body.password = password; // Don't escape password
        
        next();
    },
    
    signup: (req, res, next) => {
        const { username, email, password, profile_info } = req.body;
        
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password required' });
        }
        
        // Validate email
        if (!validator.isEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        // Validate username
        if (!validator.isLength(username, { min: 3, max: 50 }) || 
            !validator.isAlphanumeric(username)) {
            return res.status(400).json({ error: 'Username must be 3-50 alphanumeric characters' });
        }
        
        // Validate password strength
        if (!validator.isStrongPassword(password, {
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
        })) {
            return res.status(400).json({ 
                error: 'Password must be at least 8 characters with uppercase, lowercase, number, and symbol' 
            });
        }
        
        // Sanitize inputs
        req.body.username = validator.escape(username.trim());
        req.body.email = validator.normalizeEmail(email);
        req.body.profile_info = profile_info ? validator.escape(profile_info.trim()) : '';
        
        next();
    }
};

// Routes

// Home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public-secure', 'index.html'));
});

// SECURE LOGIN ENDPOINT
app.post('/api/login', validateAndSanitize.login, async (req, res) => {
    const { username, password } = req.body;
    
    try {
        logger.info(`Login attempt for user: ${username}`);
        
        // Use parameterized query to prevent SQL injection
        db.get('SELECT * FROM users WHERE username = ? AND account_locked = 0', [username], 
               async (err, user) => {
            if (err) {
                logger.error('Database error during login:', err.message);
                return res.status(500).json({ error: 'Internal server error' });
            }
            
            if (!user) {
                logger.warn(`Login failed - user not found: ${username}`);
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Check if account is locked due to too many failed attempts
            if (user.failed_login_attempts >= 5) {
                logger.warn(`Login blocked - too many failed attempts: ${username}`);
                return res.status(423).json({ error: 'Account locked due to too many failed attempts' });
            }
            
            // Verify password
            const passwordMatch = await bcrypt.compare(password, user.password_hash);
            
            if (!passwordMatch) {
                // Increment failed login attempts
                db.run('UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?', 
                       [user.id]);
                logger.warn(`Login failed - invalid password: ${username}`);
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Reset failed attempts and update last login
            db.run('UPDATE users SET failed_login_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?', 
                   [user.id]);
            
            // Generate JWT token
            const token = jwt.sign(
                { 
                    id: user.id, 
                    username: user.username,
                    email: user.email 
                }, 
                JWT_SECRET, 
                { expiresIn: '1h' }
            );
            
            logger.info(`Successful login: ${username}`);
            
            // Return secure response (no password exposure)
            res.json({
                success: true,
                message: 'Login successful',
                token: token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    profile_info: user.profile_info
                }
            });
        });
    } catch (error) {
        logger.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// SECURE SIGNUP ENDPOINT
app.post('/api/signup', validateAndSanitize.signup, async (req, res) => {
    const { username, email, password, profile_info } = req.body;
    
    try {
        logger.info(`Signup attempt for user: ${username}`);
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Use parameterized query to prevent SQL injection
        db.run('INSERT INTO users (username, email, password_hash, profile_info) VALUES (?, ?, ?, ?)',
               [username, email, hashedPassword, profile_info],
               function(err) {
                   if (err) {
                       if (err.code === 'SQLITE_CONSTRAINT') {
                           logger.warn(`Signup failed - user exists: ${username}`);
                           return res.status(400).json({ error: 'Username or email already exists' });
                       }
                       logger.error('Signup error:', err.message);
                       return res.status(500).json({ error: 'Internal server error' });
                   }
                   
                   logger.info(`User created successfully: ${username}`);
                   res.json({
                       success: true,
                       message: 'User created successfully',
                       userId: this.lastID
                   });
               });
    } catch (error) {
        logger.error('Signup error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// SECURE PROFILE ENDPOINT - Requires authentication
app.get('/api/profile/:username', authenticateToken, (req, res) => {
    const { username } = req.params;
    
    // Validate username parameter
    if (!validator.isAlphanumeric(username) || !validator.isLength(username, { min: 1, max: 50 })) {
        return res.status(400).json({ error: 'Invalid username parameter' });
    }
    
    logger.info(`Profile request for: ${username} by user: ${req.user.username}`);
    
    // Use parameterized query
    db.get('SELECT username, email, profile_info, created_at FROM users WHERE username = ?', 
           [username], (err, row) => {
        if (err) {
            logger.error('Profile fetch error:', err.message);
            return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (row) {
            // Return sanitized profile data (no sensitive information)
            res.json({
                username: row.username,
                email: row.email,
                profile_info: row.profile_info, // This is already escaped during input
                created_at: row.created_at
            });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    });
});

// SECURE ADMIN ENDPOINT - Requires authentication and admin role
app.get('/api/admin/users', authenticateToken, (req, res) => {
    // Check if user is admin
    if (req.user.username !== 'admin') {
        logger.warn(`Unauthorized admin access attempt by: ${req.user.username}`);
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    logger.info(`Admin users list accessed by: ${req.user.username}`);
    
    // Return limited user data (no passwords)
    db.all('SELECT id, username, email, created_at, last_login, failed_login_attempts FROM users', 
           (err, rows) => {
        if (err) {
            logger.error('Admin users fetch error:', err.message);
            return res.status(500).json({ error: 'Internal server error' });
        }
        
        res.json({ users: rows });
    });
});

// SECURE UPDATE PROFILE ENDPOINT
app.post('/api/update-profile', authenticateToken, validateAndSanitize.signup, (req, res) => {
    const { email, profile_info } = req.body;
    const userId = req.user.id;
    
    logger.info(`Profile update for user ID: ${userId}`);
    
    // Use parameterized query
    db.run('UPDATE users SET email = ?, profile_info = ? WHERE id = ?',
           [email, profile_info, userId],
           function(err) {
               if (err) {
                   logger.error('Profile update error:', err.message);
                   return res.status(500).json({ error: 'Internal server error' });
               }
               
               logger.info(`Profile updated for user ID: ${userId}`);
               res.json({ success: true, message: 'Profile updated successfully' });
           });
});

// Logout endpoint (client-side token removal, but we can log it)
app.post('/api/logout', authenticateToken, (req, res) => {
    logger.info(`User logged out: ${req.user.username}`);
    res.json({ success: true, message: 'Logged out successfully' });
});

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    logger.warn(`404 request: ${req.method} ${req.originalUrl}`);
    res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
    logger.info(`🔒 SECURE User Management System running on http://localhost:${PORT}`);
    logger.info('✅ Security measures implemented: Input validation, password hashing, JWT auth, logging');
    console.log(`🔒 SECURE User Management System running on http://localhost:${PORT}`);
    console.log('✅ Security measures implemented: Input validation, password hashing, JWT auth, logging');
});

// Graceful shutdown
process.on('SIGINT', () => {
    logger.info('Shutting down secure server...');
    console.log('\nShutting down secure server...');
    db.close((err) => {
        if (err) {
            logger.error('Database close error:', err.message);
        } else {
            logger.info('Database connection closed.');
        }
        process.exit(0);
    });
});
