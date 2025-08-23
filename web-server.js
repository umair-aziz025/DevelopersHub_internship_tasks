// Simple Static Web Server for the Web Interface
const express = require('express');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 8080;

// Enable CORS for all origins (for development)
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'CSRF-Token']
}));

// Serve static files from current directory
app.use(express.static(path.join(__dirname)));

// Serve the web interface at root
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'web-interface.html'));
});

// Health check
app.get('/status', (req, res) => {
    res.json({
        message: 'Web Interface Server Running',
        timestamp: new Date().toISOString(),
        port: PORT
    });
});

app.listen(PORT, () => {
    console.log(`🌐 Web Interface Server running on http://localhost:${PORT}`);
    console.log(`📱 Access your web app at: http://localhost:${PORT}`);
    console.log(`🔧 Serving files from: ${__dirname}`);
});

module.exports = app;
