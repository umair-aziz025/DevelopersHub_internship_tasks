// Week 5: Ethical Hacking & Advanced Security Server
// Enhanced security with CSRF protection and advanced input validation

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const winston = require('winston');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3002;

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'secure_jwt_secret_key_week5_ethical_hacking';

// Security logging configuration
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'week5-security.log' }),
        new winston.transports.File({ filename: 'week5-security-alerts.log', level: 'warn' }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

// Advanced input validation system
const inputValidator = {
    // SQL injection patterns
    sqlPatterns: [
        /(\%27)|(')|(\\x27)|(\-\-)|(\%23)|(#)/i,
        /((\%3D)|(=))[^\n]*((\%27)|(')|(\\x27)|((\%3B)|(;)))/i,
        /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
        /((\%27)|(\'))union/i,
        /union\s+select/i,
        /select.*from/i,
        /insert\s+into/i,
        /delete\s+from/i,
        /update.*set/i,
        /drop\s+table/i,
        /create\s+table/i,
        /exec(\s|\+)+(s|x)p\w+/i,
        /waitfor\s+delay/i,
        /sleep\s*\(/i,
        /benchmark\s*\(/i,
        /pg_sleep\s*\(/i
    ],
    
    // XSS patterns
    xssPatterns: [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
        /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
        /<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi,
        /javascript:/gi,
        /vbscript:/gi,
        /onload\s*=/gi,
        /onerror\s*=/gi,
        /onclick\s*=/gi,
        /onmouseover\s*=/gi,
        /onmouseout\s*=/gi,
        /onfocus\s*=/gi,
        /onblur\s*=/gi
    ],
    
    // Command injection patterns
    commandPatterns: [
        /(\||&|;|\$|\?|<|>|\(|\)|`|\\)/,
        /(nc|netcat|telnet|wget|curl|ping|nslookup|dig)/i,
        /(chmod|chown|rm|mv|cp|mkdir|rmdir)/i,
        /(cat|head|tail|grep|awk|sed)/i
    ],
    
    // LDAP injection patterns
    ldapPatterns: [
        /(\*|\(|\)|&|\||!)/,
        /\x00/,
        /(objectClass|cn|uid|sn|ou)/i
    ],
    
    // Validate against SQL injection
    validateSQL: function(input) {
        if (!input || typeof input !== 'string') return false;
        return !this.sqlPatterns.some(pattern => pattern.test(input));
    },
    
    // Validate against XSS
    validateXSS: function(input) {
        if (!input || typeof input !== 'string') return false;
        return !this.xssPatterns.some(pattern => pattern.test(input));
    },
    
    // Validate against command injection
    validateCommand: function(input) {
        if (!input || typeof input !== 'string') return false;
        return !this.commandPatterns.some(pattern => pattern.test(input));
    },
    
    // Validate against LDAP injection
    validateLDAP: function(input) {
        if (!input || typeof input !== 'string') return false;
        return !this.ldapPatterns.some(pattern => pattern.test(input));
    },
    
    // Comprehensive validation
    validateInput: function(input, type = 'general') {
        const validations = {
            general: () => this.validateSQL(input) && this.validateXSS(input) && this.validateCommand(input),
            username: () => /^[a-zA-Z0-9_]{3,50}$/.test(input) && this.validateSQL(input),
            email: () => validator.isEmail(input) && this.validateXSS(input),
            password: () => input.length >= 8 && input.length <= 128,
            alphanumeric: () => /^[a-zA-Z0-9]+$/.test(input),
            numeric: () => /^[0-9]+$/.test(input),
            url: () => validator.isURL(input) && this.validateXSS(input),
            json: () => {
                try {
                    JSON.parse(input);
                    return this.validateXSS(input) && this.validateSQL(input);
                } catch {
                    return false;
                }
            }
        };
        
        return validations[type] ? validations[type]() : validations.general();
    },
    
    // Sanitize input
    sanitizeInput: function(input) {
        if (!input || typeof input !== 'string') return '';
        
        return input
            .replace(/[<>]/g, '') // Remove angle brackets
            .replace(/['"]/g, '') // Remove quotes
            .replace(/[;]/g, '') // Remove semicolons
            .replace(/[--]/g, '') // Remove SQL comments
            .replace(/[\/\*]/g, '') // Remove comment markers
            .replace(/[&|`$]/g, '') // Remove command injection chars
            .trim()
            .substring(0, 1000); // Limit length
    }
};

// Simple CSRF protection implementation (since csurf is deprecated)
const csrfProtection = {
    tokens: new Map(),
    
    // Generate CSRF token
    generateToken: () => {
        return crypto.randomBytes(32).toString('hex');
    },
    
    // Store token with expiration
    storeToken: function(sessionId, token) {
        this.tokens.set(sessionId, {
            token: token,
            expires: Date.now() + (1000 * 60 * 30) // 30 minutes
        });
    },
    
    // Validate token
    validateToken: function(sessionId, providedToken) {
        const stored = this.tokens.get(sessionId);
        if (!stored) return false;
        
        // Check expiration
        if (Date.now() > stored.expires) {
            this.tokens.delete(sessionId);
            return false;
        }
        
        return stored.token === providedToken;
    },
    
    // Clean expired tokens
    cleanExpiredTokens: function() {
        const now = Date.now();
        for (const [sessionId, data] of this.tokens.entries()) {
            if (now > data.expires) {
                this.tokens.delete(sessionId);
            }
        }
    }
};

// Clean expired CSRF tokens every 10 minutes
setInterval(() => csrfProtection.cleanExpiredTokens(), 10 * 60 * 1000);

// Security alert system
function sendSecurityAlert(alertData) {
    logger.warn('🚨 Security Alert', alertData);
    
    // In production, this would send to SIEM, security team, etc.
    console.log(`🚨 SECURITY ALERT: ${alertData.type} from ${alertData.ip}`);
}

// Advanced input validation middleware
const advancedInputValidation = (req, res, next) => {
    const validateObject = (obj, path = '') => {
        for (const [key, value] of Object.entries(obj)) {
            const currentPath = path ? `${path}.${key}` : key;
            
            if (typeof value === 'string') {
                if (!inputValidator.validateInput(value)) {
                    logger.warn(`Malicious input detected at ${currentPath}: ${value.substring(0, 100)}`);
                    sendSecurityAlert({
                        type: 'MALICIOUS_INPUT',
                        field: currentPath,
                        value: value.substring(0, 100),
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date().toISOString()
                    });
                    return res.status(400).json({ 
                        error: `Invalid input detected in field: ${currentPath}`,
                        code: 'VALIDATION_ERROR'
                    });
                }
            } else if (typeof value === 'object' && value !== null) {
                const result = validateObject(value, currentPath);
                if (result) return result;
            }
        }
    };
    
    // Validate request body
    if (req.body && typeof req.body === 'object') {
        const validationResult = validateObject(req.body);
        if (validationResult) return validationResult;
    }
    
    // Validate query parameters
    if (req.query && typeof req.query === 'object') {
        const validationResult = validateObject(req.query, 'query');
        if (validationResult) return validationResult;
    }
    
    next();
};

// CSRF protection middleware
const csrfProtectionMiddleware = (req, res, next) => {
    // Skip CSRF for GET, HEAD, OPTIONS
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }
    
    const sessionId = req.cookies.sessionId || req.ip;
    const providedToken = req.body._csrf || 
                         req.query._csrf || 
                         req.headers['csrf-token'] ||
                         req.headers['xsrf-token'] ||
                         req.headers['x-csrf-token'] ||
                         req.headers['x-xsrf-token'];
    
    if (!csrfProtection.validateToken(sessionId, providedToken)) {
        logger.warn('CSRF token validation failed', {
            sessionId: sessionId,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            method: req.method,
            url: req.url
        });
        
        sendSecurityAlert({
            type: 'CSRF_ATTACK',
            sessionId: sessionId,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            timestamp: new Date().toISOString()
        });
        
        return res.status(403).json({ 
            error: 'CSRF token validation failed',
            code: 'CSRF_ERROR'
        });
    }
    
    next();
};

// Enhanced referrer check
const referrerCheck = (req, res, next) => {
    const referrer = req.get('Referrer') || req.get('Referer');
    const allowedOrigins = [
        'http://localhost:3002',
        'https://localhost:3002',
        'http://127.0.0.1:3002'
    ];
    
    // For state-changing operations
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        if (referrer && !allowedOrigins.some(origin => referrer.startsWith(origin))) {
            logger.warn(`Suspicious referrer detected: ${referrer}`);
            sendSecurityAlert({
                type: 'SUSPICIOUS_REFERRER',
                referrer: referrer,
                ip: req.ip,
                timestamp: new Date().toISOString()
            });
            return res.status(403).json({ 
                error: 'Invalid referrer',
                code: 'REFERRER_ERROR'
            });
        }
    }
    
    next();
};

// Advanced Rate Limiting
const createAdvancedRateLimiter = (windowMs, max, message, skipSuccessfulRequests = false) => {
    return rateLimit({
        windowMs: windowMs,
        max: max,
        message: { error: message, code: 'RATE_LIMIT_EXCEEDED' },
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: skipSuccessfulRequests,
        handler: (req, res, next, options) => {
            logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
            sendSecurityAlert({
                type: 'RATE_LIMIT_EXCEEDED',
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                endpoint: req.path,
                timestamp: new Date().toISOString()
            });
            res.status(options.statusCode).json(options.message);
        }
    });
};

// Rate limiters
const generalLimiter = createAdvancedRateLimiter(15 * 60 * 1000, 100, 'Too many requests');
const authLimiter = createAdvancedRateLimiter(15 * 60 * 1000, 5, 'Too many authentication attempts');
const apiLimiter = createAdvancedRateLimiter(15 * 60 * 1000, 50, 'API rate limit exceeded');

// Slow down middleware
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 50, // Allow 50 requests per windowMs without delay
    delayMs: () => 500, // Add 500ms delay for each request after delayAfter
    maxDelayMs: 20000, // Maximum delay of 20 seconds
});

// Database setup
const db = new sqlite3.Database(':memory:', (err) => {
    if (err) {
        logger.error('Error connecting to database:', err);
    } else {
        logger.info('Connected to Week 5 SQLite database for ethical hacking testing');
    }
});

// Enhanced security middleware setup
app.use(cookieParser());
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: true,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

app.use(cors({
    origin: ['http://localhost:3002', 'http://127.0.0.1:3002'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'CSRF-Token']
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Apply rate limiting
app.use(generalLimiter);
app.use(speedLimiter);

// Apply security middleware
app.use(advancedInputValidation);
app.use(referrerCheck);

// Database schema
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        profile_info TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        login_attempts INTEGER DEFAULT 0,
        locked_until DATETIME,
        is_admin BOOLEAN DEFAULT 0
    )`);
    
    // Create admin user for testing
    const adminPassword = 'SecureAdmin123!';
    bcrypt.hash(adminPassword, 12, (err, hash) => {
        if (err) {
            logger.error('Error hashing admin password:', err);
            return;
        }
        
        db.run(`INSERT OR REPLACE INTO users (username, email, password_hash, profile_info, is_admin) 
                VALUES (?, ?, ?, ?, ?)`,
            ['admin', 'admin@week5test.com', hash, 'Week 5 Admin User for Ethical Hacking Tests', 1],
            function(err) {
                if (err) {
                    logger.error('Error creating admin user:', err);
                } else {
                    logger.info('Week 5 admin user ready for ethical hacking tests');
                }
            }
        );
    });
    
    logger.info('Week 5 database tables created/verified');
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required', code: 'AUTH_REQUIRED' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            logger.warn('Invalid token attempt', { ip: req.ip, token: token.substring(0, 20) });
            return res.status(403).json({ error: 'Invalid or expired token', code: 'TOKEN_INVALID' });
        }
        req.user = user;
        next();
    });
};

// CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
    const sessionId = req.cookies.sessionId || req.ip;
    const token = csrfProtection.generateToken();
    
    csrfProtection.storeToken(sessionId, token);
    
    // Set session cookie if not exists
    if (!req.cookies.sessionId) {
        res.cookie('sessionId', sessionId, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 30 * 60 * 1000 // 30 minutes
        });
    }
    
    res.json({ 
        csrfToken: token,
        message: 'CSRF token generated successfully',
        sessionId: sessionId
    });
});

// Week 5 Testing Endpoints
app.get('/api/week5/status', (req, res) => {
    res.json({
        message: 'Week 5 Ethical Hacking Server Active',
        security_features: [
            'Advanced Input Validation',
            'CSRF Protection',
            'SQL Injection Prevention',
            'XSS Protection',
            'Command Injection Prevention',
            'Rate Limiting',
            'Security Headers',
            'Referrer Validation',
            'Enhanced Logging'
        ],
        testing_endpoints: [
            '/api/csrf-token - Get CSRF token',
            '/api/login - Authentication (vulnerable in Week 1)',
            '/api/secure-login - Secure authentication',
            '/api/signup - Registration',
            '/api/profile - User profile',
            '/api/admin/users - Admin panel'
        ],
        ethical_hacking_tools: [
            'SQLMap integration ready',
            'Burp Suite testing endpoints',
            'OWASP ZAP compatible',
            'Custom vulnerability scanner ready'
        ]
    });
});

// Vulnerable login endpoint (for ethical hacking testing)
app.post('/api/login', authLimiter, (req, res) => {
    const { username, password } = req.body;
    
    logger.info('Login attempt (vulnerable endpoint)', { username, ip: req.ip });
    
    // INTENTIONALLY VULNERABLE - for ethical hacking demonstration
    // This simulates the Week 1 vulnerable endpoint for testing
    const query = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${password}'`;
    
    logger.warn('VULNERABLE QUERY EXECUTED (Week 5 Testing)', { query: query.substring(0, 100) });
    
    db.get(query, (err, user) => {
        if (err) {
            logger.error('Database error in vulnerable endpoint:', err);
            return res.status(500).json({ error: 'Server error' });
        }
        
        if (user) {
            const token = jwt.sign(
                { id: user.id, username: user.username },
                JWT_SECRET,
                { expiresIn: '1h' }
            );
            
            res.json({
                message: 'Login successful (vulnerable endpoint)',
                token: token,
                user: { id: user.id, username: user.username, email: user.email }
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// Secure login endpoint
app.post('/api/secure-login', authLimiter, csrfProtectionMiddleware, (req, res) => {
    const { username, password } = req.body;
    
    // Validate inputs
    if (!inputValidator.validateInput(username, 'username')) {
        return res.status(400).json({ error: 'Invalid username format', code: 'VALIDATION_ERROR' });
    }
    
    if (!inputValidator.validateInput(password, 'password')) {
        return res.status(400).json({ error: 'Invalid password format', code: 'VALIDATION_ERROR' });
    }
    
    logger.info('Secure login attempt', { username, ip: req.ip });
    
    // Use parameterized query (secure)
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            logger.error('Database error in secure login:', err);
            return res.status(500).json({ error: 'Server error', code: 'SERVER_ERROR' });
        }
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials', code: 'AUTH_FAILED' });
        }
        
        // Check if account is locked
        if (user.locked_until && new Date(user.locked_until) > new Date()) {
            return res.status(423).json({ 
                error: 'Account temporarily locked due to multiple failed attempts',
                code: 'ACCOUNT_LOCKED'
            });
        }
        
        bcrypt.compare(password, user.password_hash, (err, isValid) => {
            if (err) {
                logger.error('Error comparing passwords:', err);
                return res.status(500).json({ error: 'Server error', code: 'SERVER_ERROR' });
            }
            
            if (isValid) {
                // Reset login attempts
                db.run('UPDATE users SET login_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
                
                const token = jwt.sign(
                    { id: user.id, username: user.username, isAdmin: user.is_admin },
                    JWT_SECRET,
                    { expiresIn: '1h' }
                );
                
                logger.info('Successful secure login', { username, ip: req.ip });
                
                res.json({
                    message: 'Login successful',
                    token: token,
                    user: { 
                        id: user.id, 
                        username: user.username, 
                        email: user.email,
                        isAdmin: user.is_admin 
                    }
                });
            } else {
                // Increment login attempts
                const newAttempts = (user.login_attempts || 0) + 1;
                const lockUntil = newAttempts >= 5 ? new Date(Date.now() + 30 * 60 * 1000) : null; // 30 min lock
                
                db.run('UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?', 
                    [newAttempts, lockUntil, user.id]);
                
                logger.warn('Failed login attempt', { 
                    username, 
                    ip: req.ip, 
                    attempts: newAttempts,
                    locked: !!lockUntil 
                });
                
                sendSecurityAlert({
                    type: 'FAILED_LOGIN',
                    username: username,
                    ip: req.ip,
                    attempts: newAttempts,
                    timestamp: new Date().toISOString()
                });
                
                res.status(401).json({ 
                    error: 'Invalid credentials',
                    code: 'AUTH_FAILED',
                    remainingAttempts: Math.max(0, 5 - newAttempts)
                });
            }
        });
    });
});

// User registration
app.post('/api/signup', apiLimiter, csrfProtectionMiddleware, (req, res) => {
    const { username, email, password, profile_info } = req.body;
    
    // Enhanced validation
    if (!inputValidator.validateInput(username, 'username')) {
        return res.status(400).json({ error: 'Invalid username format', code: 'VALIDATION_ERROR' });
    }
    
    if (!inputValidator.validateInput(email, 'email')) {
        return res.status(400).json({ error: 'Invalid email format', code: 'VALIDATION_ERROR' });
    }
    
    if (!inputValidator.validateInput(password, 'password')) {
        return res.status(400).json({ error: 'Password must be 8-128 characters', code: 'VALIDATION_ERROR' });
    }
    
    if (profile_info && !inputValidator.validateInput(profile_info)) {
        return res.status(400).json({ error: 'Invalid profile information', code: 'VALIDATION_ERROR' });
    }
    
    // Check password strength
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({ 
            error: 'Password must contain uppercase, lowercase, number, and special character',
            code: 'WEAK_PASSWORD'
        });
    }
    
    logger.info('User registration attempt', { username, email, ip: req.ip });
    
    bcrypt.hash(password, 12, (err, hash) => {
        if (err) {
            logger.error('Error hashing password:', err);
            return res.status(500).json({ error: 'Server error', code: 'SERVER_ERROR' });
        }
        
        const sanitizedProfile = inputValidator.sanitizeInput(profile_info || '');
        
        db.run(`INSERT INTO users (username, email, password_hash, profile_info) VALUES (?, ?, ?, ?)`,
            [username, email, hash, sanitizedProfile],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint')) {
                        return res.status(409).json({ 
                            error: 'Username or email already exists',
                            code: 'DUPLICATE_USER'
                        });
                    }
                    logger.error('Error creating user:', err);
                    return res.status(500).json({ error: 'Server error', code: 'SERVER_ERROR' });
                }
                
                logger.info('User registered successfully', { username, email, ip: req.ip });
                res.status(201).json({ 
                    message: 'User created successfully',
                    userId: this.lastID 
                });
            }
        );
    });
});

// User profile endpoint
app.get('/api/profile', authenticateToken, (req, res) => {
    db.get('SELECT id, username, email, profile_info, created_at, last_login FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            if (err) {
                logger.error('Error fetching user profile:', err);
                return res.status(500).json({ error: 'Server error', code: 'SERVER_ERROR' });
            }
            
            if (!user) {
                return res.status(404).json({ error: 'User not found', code: 'USER_NOT_FOUND' });
            }
            
            res.json(user);
        }
    );
});

// Update profile endpoint
app.post('/api/update-profile', authenticateToken, csrfProtectionMiddleware, (req, res) => {
    const { email, profile_info } = req.body;
    
    // Validate inputs
    if (email && !inputValidator.validateInput(email, 'email')) {
        return res.status(400).json({ error: 'Invalid email format', code: 'VALIDATION_ERROR' });
    }
    
    if (profile_info && !inputValidator.validateInput(profile_info)) {
        return res.status(400).json({ error: 'Invalid profile information', code: 'VALIDATION_ERROR' });
    }
    
    const sanitizedProfile = inputValidator.sanitizeInput(profile_info || '');
    
    db.run('UPDATE users SET email = ?, profile_info = ? WHERE id = ?',
        [email, sanitizedProfile, req.user.id],
        function(err) {
            if (err) {
                logger.error('Error updating profile:', err);
                return res.status(500).json({ error: 'Server error', code: 'SERVER_ERROR' });
            }
            
            logger.info('Profile updated', { userId: req.user.id, ip: req.ip });
            res.json({ message: 'Profile updated successfully' });
        }
    );
});

// Admin endpoints
app.get('/api/admin/users', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin access required', code: 'ADMIN_REQUIRED' });
    }
    
    db.all('SELECT id, username, email, created_at, last_login, login_attempts FROM users',
        (err, users) => {
            if (err) {
                logger.error('Error fetching users (admin):', err);
                return res.status(500).json({ error: 'Server error', code: 'SERVER_ERROR' });
            }
            
            res.json({ users });
        }
    );
});

// Security testing endpoints
app.get('/api/test/xss', (req, res) => {
    const userInput = req.query.input || '';
    
    // Vulnerable response (for testing)
    res.send(`<h1>XSS Test Result</h1><p>Your input: ${userInput}</p>`);
});

app.get('/api/test/sql-injection', (req, res) => {
    const userId = req.query.id || '1';
    
    // Vulnerable query (for testing)
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    
    db.get(query, (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error', query: query });
        }
        
        res.json({ user: user, query: query });
    });
});

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        week: 5,
        timestamp: new Date().toISOString(),
        security_level: 'ethical_hacking_ready'
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        code: 'INTERNAL_ERROR'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Endpoint not found',
        code: 'NOT_FOUND',
        availableEndpoints: [
            'GET /api/week5/status',
            'GET /api/csrf-token',
            'POST /api/login (vulnerable)',
            'POST /api/secure-login',
            'POST /api/signup',
            'GET /api/profile',
            'POST /api/update-profile',
            'GET /api/admin/users',
            'GET /health'
        ]
    });
});

// Graceful shutdown
process.on('SIGINT', () => {
    logger.info('Shutting down Week 5 ethical hacking server...');
    console.log('\nShutting down Week 5 ethical hacking server...');
    
    db.close((err) => {
        if (err) {
            logger.error('Error closing database:', err);
        } else {
            logger.info('Database connection closed.');
        }
        process.exit(0);
    });
});

app.listen(PORT, () => {
    logger.info(`🔒 WEEK 5 Ethical Hacking Server running on http://localhost:${PORT}`);
    logger.info(`✅ Security Features: Advanced validation, CSRF protection, ethical hacking endpoints`);
    
    console.log(`🔒 WEEK 5 Ethical Hacking Server running on http://localhost:${PORT}`);
    console.log(`✅ Features: Ethical hacking testing, advanced security validation, CSRF protection`);
    console.log(`🧪 Testing Endpoints: /api/week5/status, /api/csrf-token, /api/login (vulnerable), /api/secure-login`);
    console.log(`📊 Security Level: Professional ethical hacking validation ready`);
});
