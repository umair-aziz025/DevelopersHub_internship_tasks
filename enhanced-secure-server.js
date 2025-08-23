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
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');

const app = express();
const PORT = 3001; // Enhanced secure version
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Enhanced Winston logging with security focus
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ''}`;
        })
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        }),
        new winston.transports.File({ 
            filename: 'security.log',
            format: winston.format.json()
        }),
        new winston.transports.File({ 
            filename: 'security-alerts.log',
            level: 'warn',
            format: winston.format.json()
        })
    ]
});

// Week 4: Advanced Security Monitoring System
const securityMonitor = {
    failedAttempts: new Map(),
    suspiciousIPs: new Set(),
    blockedIPs: new Map(),
    alertThresholds: {
        maxFailedLogins: 3,
        timeWindow: 300000, // 5 minutes
        lockoutDuration: 3600000, // 1 hour
        maxRequestsPerMinute: 100
    }
};

// Week 4: Real-time threat detection
const detectIntrusion = (req, ip, username) => {
    const key = `${ip}:${username}`;
    const attempts = securityMonitor.failedAttempts.get(key) || [];
    const now = Date.now();
    
    // Clean old attempts
    const recentAttempts = attempts.filter(time => now - time < securityMonitor.alertThresholds.timeWindow);
    
    if (recentAttempts.length >= securityMonitor.alertThresholds.maxFailedLogins) {
        // ALERT: Potential brute force attack
        logger.error('🚨 SECURITY ALERT: Brute force attack detected', {
            type: 'BRUTE_FORCE',
            ip: ip,
            username: username,
            attempts: recentAttempts.length,
            timestamp: new Date().toISOString(),
            severity: 'HIGH',
            action: 'IP_BLOCKED'
        });
        
        securityMonitor.suspiciousIPs.add(ip);
        securityMonitor.blockedIPs.set(ip, now + securityMonitor.alertThresholds.lockoutDuration);
        
        sendSecurityAlert({
            type: 'BRUTE_FORCE',
            ip: ip,
            username: username,
            attempts: recentAttempts.length,
            timestamp: new Date().toISOString()
        });
        
        return true; // Intrusion detected
    }
    
    recentAttempts.push(now);
    securityMonitor.failedAttempts.set(key, recentAttempts);
    return false;
};

// Week 4: Security Alert System
const sendSecurityAlert = (alertData) => {
    const alert = {
        ...alertData,
        severity: getSeverityLevel(alertData.type),
        action: getRecommendedAction(alertData.type),
        server: 'enhanced-secure-server',
        version: '4.0.0'
    };
    
    // Log to security file
    logger.error(`SECURITY ALERT: ${JSON.stringify(alert)}`);
    
    // Console notification
    console.log(`🚨 SECURITY ALERT: ${alert.type} detected from ${alert.ip}`);
    
    // In production: Send email, SMS, or webhook notification
    // emailService.sendAlert(alert);
    // slackService.postAlert(alert);
    // webhookService.triggerAlert(alert);
};

const getSeverityLevel = (type) => {
    const severityMap = {
        'BRUTE_FORCE': 'HIGH',
        'SQL_INJECTION': 'CRITICAL',
        'XSS_ATTEMPT': 'MEDIUM',
        'RATE_LIMIT_EXCEEDED': 'MEDIUM',
        'SUSPICIOUS_REQUEST': 'LOW',
        'TOKEN_TAMPERING': 'HIGH',
        'CORS_VIOLATION': 'MEDIUM'
    };
    return severityMap[type] || 'UNKNOWN';
};

const getRecommendedAction = (type) => {
    const actionMap = {
        'BRUTE_FORCE': 'BLOCK_IP',
        'SQL_INJECTION': 'BLOCK_REQUEST',
        'XSS_ATTEMPT': 'SANITIZE_INPUT',
        'RATE_LIMIT_EXCEEDED': 'THROTTLE_REQUESTS',
        'TOKEN_TAMPERING': 'REVOKE_TOKEN'
    };
    return actionMap[type] || 'MONITOR';
};

// Week 4: IP Blocking Middleware
const checkBlockedIP = (req, res, next) => {
    const ip = req.ip;
    const blockedUntil = securityMonitor.blockedIPs.get(ip);
    
    if (blockedUntil && Date.now() < blockedUntil) {
        logger.warn(`Blocked IP attempted access: ${ip}`);
        return res.status(403).json({ 
            error: 'IP temporarily blocked due to suspicious activity',
            unblockTime: new Date(blockedUntil).toISOString()
        });
    }
    
    // Clean expired blocks
    if (blockedUntil && Date.now() >= blockedUntil) {
        securityMonitor.blockedIPs.delete(ip);
        logger.info(`IP unblocked: ${ip}`);
    }
    
    next();
};

// Week 4: Advanced Rate Limiting
const createRateLimiter = (windowMs, max, message, skipSuccessfulRequests = false) => {
    return rateLimit({
        windowMs: windowMs,
        max: max,
        message: { error: message },
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: skipSuccessfulRequests,
        keyGenerator: (req) => {
            return req.ip; // Use IP as key
        },
        handler: (req, res) => {
            const ip = req.ip;
            logger.warn(`Rate limit exceeded for IP: ${ip} on endpoint: ${req.path}`);
            
            securityMonitor.suspiciousIPs.add(ip);
            
            sendSecurityAlert({
                type: 'RATE_LIMIT_EXCEEDED',
                ip: ip,
                endpoint: req.path,
                timestamp: new Date().toISOString()
            });
            
            res.status(429).json({ 
                error: message,
                retryAfter: Math.round(windowMs / 1000),
                endpoint: req.path
            });
        }
    });
};

// Week 4: Tiered Rate Limiting Strategy
const generalLimiter = createRateLimiter(15 * 60 * 1000, 100, 'Too many requests, please try again later');
const authLimiter = createRateLimiter(15 * 60 * 1000, 5, 'Too many authentication attempts, please try again later');
const apiLimiter = createRateLimiter(15 * 60 * 1000, 50, 'API rate limit exceeded');
const adminLimiter = createRateLimiter(15 * 60 * 1000, 10, 'Admin endpoint rate limit exceeded');

// Week 4: Progressive Speed Limiting
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 5, // Allow 5 requests per windowMs without delay
    delayMs: 500, // Add 500ms delay per request after delayAfter
    maxDelayMs: 20000, // Max delay of 20 seconds
    skip: (req) => {
        // Skip delay for successful requests
        return req.method === 'GET' && req.path === '/';
    }
});

// Week 4: API Key Authentication System
const apiKeys = new Map([
    ['dev-key-123', { name: 'Development', permissions: ['read'], rateLimit: 50 }],
    ['admin-key-456', { name: 'Admin', permissions: ['read', 'write', 'admin'], rateLimit: 100 }],
    ['prod-key-789', { name: 'Production', permissions: ['read', 'write'], rateLimit: 200 }]
]);

const validateApiKey = (requiredPermission = 'read') => {
    return (req, res, next) => {
        const apiKey = req.headers['x-api-key'];
        
        if (!apiKey) {
            logger.warn(`API access attempt without key from IP: ${req.ip}`);
            return res.status(401).json({ error: 'API key required' });
        }
        
        const keyData = apiKeys.get(apiKey);
        if (!keyData) {
            logger.warn(`Invalid API key attempt from IP: ${req.ip}: ${apiKey.substring(0, 8)}...`);
            sendSecurityAlert({
                type: 'INVALID_API_KEY',
                ip: req.ip,
                keyAttempt: apiKey.substring(0, 8) + '...',
                timestamp: new Date().toISOString()
            });
            return res.status(401).json({ error: 'Invalid API key' });
        }
        
        if (!keyData.permissions.includes(requiredPermission)) {
            logger.warn(`Insufficient API permissions for key: ${keyData.name}`);
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        
        req.apiKey = keyData;
        logger.info(`API access granted for: ${keyData.name}`);
        next();
    };
};

// Week 4: Advanced CORS Configuration
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'https://yourdomain.com',
            'https://api.yourdomain.com',
            'http://localhost:3001', // Development
            'http://localhost:3000'  // Testing
        ];
        
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            logger.warn(`CORS blocked request from origin: ${origin}`);
            sendSecurityAlert({
                type: 'CORS_VIOLATION',
                origin: origin,
                timestamp: new Date().toISOString()
            });
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Origin',
        'X-Requested-With',
        'Content-Type',
        'Accept',
        'Authorization',
        'X-API-Key'
    ],
    exposedHeaders: ['X-Total-Count', 'X-Rate-Limit-Remaining'],
    maxAge: 86400 // 24 hours
};

// Week 4: Advanced Security Headers with Helmet
const helmetConfig = {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                "'unsafe-inline'", // Only for development
                "https://cdn.jsdelivr.net",
                "https://cdnjs.cloudflare.com"
            ],
            styleSrc: [
                "'self'",
                "'unsafe-inline'",
                "https://fonts.googleapis.com",
                "https://cdn.jsdelivr.net"
            ],
            fontSrc: [
                "'self'",
                "https://fonts.gstatic.com",
                "data:"
            ],
            imgSrc: [
                "'self'",
                "data:",
                "https:"
            ],
            connectSrc: [
                "'self'",
                "https://api.yourdomain.com"
            ],
            mediaSrc: ["'self'"],
            objectSrc: ["'none'"],
            childSrc: ["'none'"],
            frameSrc: ["'none'"],
            workerSrc: ["'self'"],
            manifestSrc: ["'self'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"],
            upgradeInsecureRequests: []
        },
        reportOnly: false
    },
    crossOriginEmbedderPolicy: { policy: "require-corp" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-site" },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
    },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: false,
    referrerPolicy: { policy: "no-referrer" },
    xssFilter: true
};

// Week 4: HTTPS Enforcement
const enforceHTTPS = (req, res, next) => {
    if (process.env.NODE_ENV === 'production' && req.header('x-forwarded-proto') !== 'https') {
        logger.warn(`HTTP request redirected to HTTPS: ${req.url}`);
        return res.redirect(`https://${req.header('host')}${req.url}`);
    }
    next();
};

// Apply middleware in order
app.use(enforceHTTPS);
app.use(checkBlockedIP); // Check blocked IPs first
app.use(helmet(helmetConfig));
app.use(cors(corsOptions));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public-secure')));

// Apply rate limiting
app.use('/api/', generalLimiter);
app.use('/api/', speedLimiter);

// Week 4: Additional Security Headers
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 
        'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()');
    
    // Add security headers for API responses
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    next();
});

// Initialize SQLite database
const db = new sqlite3.Database('./secure_users.db', (err) => {
    if (err) {
        logger.error('Error opening database:', err.message);
    } else {
        logger.info('Connected to secure SQLite database');
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
                createDefaultAdmin();
            }
        });
    }
});

// Create default admin user
async function createDefaultAdmin() {
    try {
        const hashedPassword = await bcrypt.hash('SecureAdmin123!', 12);
        db.run(`INSERT OR IGNORE INTO users (username, email, password_hash, profile_info) 
                VALUES (?, ?, ?, ?)`, 
                ['admin', 'admin@secure.com', hashedPassword, 'Enhanced Secure Administrator'],
                (err) => {
                    if (err) {
                        logger.error('Error creating admin user:', err.message);
                    } else {
                        logger.info('Enhanced secure admin user ready');
                    }
                });
    } catch (error) {
        logger.error('Error hashing admin password:', error);
    }
}

// Week 4: Enhanced JWT Authentication
const enhancedJWTAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        logger.warn(`Unauthorized API access attempt from IP: ${req.ip}`);
        return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            logger.warn(`Invalid token access attempt from IP: ${req.ip}`);
            
            if (err.name === 'JsonWebTokenError') {
                sendSecurityAlert({
                    type: 'TOKEN_TAMPERING',
                    ip: req.ip,
                    error: err.message,
                    timestamp: new Date().toISOString()
                });
            }
            
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        
        // Check token freshness
        const tokenAge = Date.now() - (user.iat * 1000);
        if (tokenAge > 3600000) { // 1 hour
            logger.warn(`Expired token usage attempt from user: ${user.username}`);
            return res.status(403).json({ error: 'Token expired, please login again' });
        }
        
        req.user = user;
        next();
    });
};

// Input validation middleware (from previous weeks)
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
        
        req.body.username = validator.escape(username.trim());
        req.body.password = password;
        
        next();
    },
    
    signup: (req, res, next) => {
        const { username, email, password, profile_info } = req.body;
        
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password required' });
        }
        
        if (!validator.isEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        if (!validator.isLength(username, { min: 3, max: 50 }) || 
            !validator.isAlphanumeric(username)) {
            return res.status(400).json({ error: 'Username must be 3-50 alphanumeric characters' });
        }
        
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
        
        req.body.username = validator.escape(username.trim());
        req.body.email = validator.normalizeEmail(email);
        req.body.profile_info = profile_info ? validator.escape(profile_info.trim()) : '';
        
        next();
    }
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public-secure', 'index.html'));
});

// Week 4: Enhanced Login with Intrusion Detection
app.post('/api/login', authLimiter, validateAndSanitize.login, async (req, res) => {
    const { username, password } = req.body;
    const ip = req.ip;
    
    try {
        logger.info(`Login attempt for user: ${username} from IP: ${ip}`);
        
        // Check for intrusion attempts
        if (detectIntrusion(req, ip, username)) {
            return res.status(423).json({ 
                error: 'Too many failed attempts. IP temporarily blocked.',
                retryAfter: new Date(Date.now() + securityMonitor.alertThresholds.lockoutDuration).toISOString()
            });
        }
        
        db.get('SELECT * FROM users WHERE username = ? AND account_locked = 0', [username], 
               async (err, user) => {
            if (err) {
                logger.error('Database error during login:', err.message);
                return res.status(500).json({ error: 'Internal server error' });
            }
            
            if (!user) {
                logger.warn(`Login failed - user not found: ${username} from IP: ${ip}`);
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            if (user.failed_login_attempts >= 5) {
                logger.warn(`Login blocked - too many failed attempts: ${username}`);
                return res.status(423).json({ error: 'Account locked due to too many failed attempts' });
            }
            
            const passwordMatch = await bcrypt.compare(password, user.password_hash);
            
            if (!passwordMatch) {
                db.run('UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?', [user.id]);
                logger.warn(`Login failed - invalid password: ${username} from IP: ${ip}`);
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Reset failed attempts and update last login
            db.run('UPDATE users SET failed_login_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
            
            // Generate JWT token
            const token = jwt.sign(
                { 
                    id: user.id, 
                    username: user.username,
                    email: user.email,
                    iat: Math.floor(Date.now() / 1000)
                }, 
                JWT_SECRET, 
                { expiresIn: '1h' }
            );
            
            logger.info(`Successful login: ${username} from IP: ${ip}`);
            
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

// Enhanced Signup (same as before but with additional logging)
app.post('/api/signup', authLimiter, validateAndSanitize.signup, async (req, res) => {
    const { username, email, password, profile_info } = req.body;
    
    try {
        logger.info(`Signup attempt for user: ${username} from IP: ${req.ip}`);
        
        const hashedPassword = await bcrypt.hash(password, 12);
        
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

// Week 4: API-protected Profile endpoint
app.get('/api/profile/:username', apiLimiter, enhancedJWTAuth, (req, res) => {
    const { username } = req.params;
    
    if (!validator.isAlphanumeric(username) || !validator.isLength(username, { min: 1, max: 50 })) {
        return res.status(400).json({ error: 'Invalid username parameter' });
    }
    
    logger.info(`Profile request for: ${username} by user: ${req.user.username} from IP: ${req.ip}`);
    
    db.get('SELECT username, email, profile_info, created_at FROM users WHERE username = ?', 
           [username], (err, row) => {
        if (err) {
            logger.error('Profile fetch error:', err.message);
            return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (row) {
            res.json({
                username: row.username,
                email: row.email,
                profile_info: row.profile_info,
                created_at: row.created_at
            });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    });
});

// Week 4: Enhanced Admin endpoint with API key option
app.get('/api/admin/users', adminLimiter, (req, res, next) => {
    // Try API key first, then JWT
    if (req.headers['x-api-key']) {
        return validateApiKey('admin')(req, res, next);
    } else {
        return enhancedJWTAuth(req, res, next);
    }
}, (req, res) => {
    // Check permissions
    if (req.apiKey) {
        // API key access
        if (!req.apiKey.permissions.includes('admin')) {
            return res.status(403).json({ error: 'Admin API key required' });
        }
        logger.info(`Admin users list accessed via API key: ${req.apiKey.name}`);
    } else {
        // JWT access
        if (req.user.username !== 'admin') {
            logger.warn(`Unauthorized admin access attempt by: ${req.user.username}`);
            return res.status(403).json({ error: 'Admin access required' });
        }
        logger.info(`Admin users list accessed by: ${req.user.username}`);
    }
    
    db.all('SELECT id, username, email, created_at, last_login, failed_login_attempts FROM users', 
           (err, rows) => {
        if (err) {
            logger.error('Admin users fetch error:', err.message);
            return res.status(500).json({ error: 'Internal server error' });
        }
        
        res.json({ 
            users: rows,
            totalCount: rows.length,
            accessedBy: req.apiKey ? req.apiKey.name : req.user.username
        });
    });
});

// Week 4: Security status endpoint
app.get('/api/security/status', apiLimiter, validateApiKey('read'), (req, res) => {
    const stats = {
        server: 'enhanced-secure-server',
        version: '4.0.0',
        uptime: process.uptime(),
        security: {
            blockedIPs: securityMonitor.blockedIPs.size,
            suspiciousIPs: securityMonitor.suspiciousIPs.size,
            activeAlerts: securityMonitor.failedAttempts.size,
            rateLimit: {
                general: '100 requests/15min',
                auth: '5 requests/15min',
                api: '50 requests/15min',
                admin: '10 requests/15min'
            },
            features: [
                'Advanced Rate Limiting',
                'Intrusion Detection',
                'API Key Authentication',
                'Enhanced JWT Security',
                'CORS Protection',
                'CSP Headers',
                'HTTPS Enforcement'
            ]
        },
        timestamp: new Date().toISOString()
    };
    
    logger.info(`Security status accessed by API key: ${req.apiKey.name}`);
    res.json(stats);
});

// Logout endpoint
app.post('/api/logout', enhancedJWTAuth, (req, res) => {
    logger.info(`User logged out: ${req.user.username} from IP: ${req.ip}`);
    res.json({ success: true, message: 'Logged out successfully' });
});

// Week 4: Enhanced Error handling
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', {
        error: err.message,
        stack: err.stack,
        ip: req.ip,
        method: req.method,
        path: req.path
    });
    
    if (err.message.includes('CORS')) {
        return res.status(403).json({ error: 'CORS policy violation' });
    }
    
    res.status(500).json({ error: 'Internal server error' });
});

// Week 4: Enhanced 404 handler
app.use('*', (req, res) => {
    logger.warn(`404 request: ${req.method} ${req.originalUrl} from IP: ${req.ip}`);
    res.status(404).json({ 
        error: 'Endpoint not found',
        method: req.method,
        path: req.originalUrl
    });
});

// Start enhanced secure server
app.listen(PORT, () => {
    logger.info(`🔒 ENHANCED SECURE User Management System running on http://localhost:${PORT}`);
    logger.info('✅ Week 4 Security Features: Advanced threat detection, API security, enhanced headers');
    console.log(`🔒 ENHANCED SECURE User Management System running on http://localhost:${PORT}`);
    console.log('✅ Week 4 Features: Intrusion detection, API keys, advanced rate limiting, security monitoring');
});

// Graceful shutdown
process.on('SIGINT', () => {
    logger.info('Shutting down enhanced secure server...');
    console.log('\nShutting down enhanced secure server...');
    db.close((err) => {
        if (err) {
            logger.error('Database close error:', err.message);
        } else {
            logger.info('Database connection closed.');
        }
        process.exit(0);
    });
});

// Export for testing
module.exports = app;
