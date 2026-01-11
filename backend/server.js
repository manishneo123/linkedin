// Load environment variables FIRST - before any other code
require('dotenv').config({ path: require('path').join(__dirname, '.env') });

// Debug: Log if .env is being loaded (only in development)
if (process.env.NODE_ENV !== 'production') {
    console.log('🔍 Environment check:');
    console.log('  DB_HOST:', process.env.DB_HOST ? '✓ Set' : '✗ Missing');
    console.log('  DB_USER:', process.env.DB_USER ? '✓ Set' : '✗ Missing');
    console.log('  DB_NAME:', process.env.DB_NAME ? '✓ Set' : '✗ Missing');
    console.log('  .env file path:', require('path').join(__dirname, '.env'));
}

const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

// Validate required environment variables
const requiredEnvVars = [
    'STRIPE_SECRET_KEY',
    'STRIPE_WEBHOOK_SECRET',
    'OPENAI_API_KEY',
    'DB_HOST',
    'DB_USER',
    //'DB_PASSWORD',
    'DB_NAME',
    'BACKEND_URL'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
    console.error('❌ Missing required environment variables:');
    missingVars.forEach(varName => console.error(`   - ${varName}`));
    console.error('\nPlease create a .env file in the backend directory with all required variables.');
    console.error('Example .env file location:', path.join(__dirname, '.env'));
    console.error('\nYou can copy .env.example to .env and fill in the values.');
    
    // Check if .env file exists
    const fs = require('fs');
    const envPath = path.join(__dirname, '.env');
    if (!fs.existsSync(envPath)) {
        console.error(`\n⚠️  .env file not found at: ${envPath}`);
        console.error('   Creating a template .env file...');
        // Don't exit in development - allow defaults
        if (process.env.NODE_ENV === 'production') {
            process.exit(1);
        } else {
            console.warn('   Continuing with defaults (development mode only)');
        }
    } else {
        console.error(`\n⚠️  .env file exists at: ${envPath}`);
        console.error('   But some required variables are missing or empty.');
        if (process.env.NODE_ENV === 'production') {
            process.exit(1);
        }
    }
}

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const OpenAI = require('openai');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const multer = require('multer');
const mammoth = require('mammoth');
const pdfParse = require('pdf-parse');
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType } = require('docx');
const PDFDocument = require('pdfkit');

const app = express();
const PORT = process.env.PORT || 3000;

// Security: Rate limiting configuration
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100; // 100 requests per window

// Middleware
// CORS configuration - restrict to extension origin if provided
const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests) if API key is provided
        if (!origin && process.env.ALLOW_NO_ORIGIN === 'true') {
            return callback(null, true);
        }
        // Allow Chrome extension origins
        if (origin && (origin.startsWith('chrome-extension://') || origin === process.env.FRONTEND_URL)) {
            callback(null, true);
        } else if (process.env.NODE_ENV === 'development') {
            // In development, allow all origins
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Configure multer for file uploads (memory storage for CV files)
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    },
    fileFilter: (req, file, cb) => {
        // Accept text, DOCX, DOC, and PDF files
        const allowedMimes = [
            'text/plain',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/msword',
            'application/pdf'
        ];
        const allowedExtensions = ['.txt', '.docx', '.doc', '.pdf'];
        
        const fileExtension = path.extname(file.originalname).toLowerCase();
        const isValidMime = allowedMimes.includes(file.mimetype);
        const isValidExtension = allowedExtensions.includes(fileExtension);
        
        if (isValidMime || isValidExtension) {
            cb(null, true);
        } else {
            cb(new Error(`Invalid file type. Allowed: ${allowedExtensions.join(', ')}`), false);
        }
    }
});

// MySQL Database Connection Pool
// Use defaults if env vars are not set (for development)
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'linkedin_sales_copilot',
    waitForConnections: true,
    connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT) || 10,
    queueLimit: parseInt(process.env.DB_QUEUE_LIMIT) || 0
};

// Log database config (without password) for debugging
if (process.env.NODE_ENV !== 'production') {
    console.log('📊 Database Configuration:');
    console.log('  Host:', dbConfig.host);
    console.log('  Port:', dbConfig.port);
    console.log('  User:', dbConfig.user);
    console.log('  Database:', dbConfig.database);
    console.log('  Password:', dbConfig.password ? '***' : '(empty)');
}

const pool = mysql.createPool(dbConfig);

// Test database connection on startup
pool.getConnection()
    .then(connection => {
        console.log('✓ Database connection successful');
        connection.release();
    })
    .catch(err => {
        console.error('✗ Database connection failed:', err.message);
        console.error('  Please check your .env file and ensure:');
        console.error('    - DB_HOST is set correctly');
        console.error('    - DB_USER is set correctly');
        console.error('    - DB_PASSWORD is set (can be empty for local MySQL)');
        console.error('    - DB_NAME is set correctly');
        console.error('    - MySQL server is running');
    });

// Credit configuration
const CREDIT_CONFIG = {
    FREE_TOKENS: parseInt(process.env.FREE_TOKENS) || 10000,
    TOKEN_COST_PER_1M: {
        input: parseFloat(process.env.TOKEN_COST_PER_1M_INPUT) || 0.15,
        output: parseFloat(process.env.TOKEN_COST_PER_1M_OUTPUT) || 0.60
    }
};

// Pricing packages - can be overridden via environment variables
// Format: PRICING_PACKAGES_JSON (optional, if not provided, uses defaults below)
let PRICING_PACKAGES;
if (process.env.PRICING_PACKAGES_JSON) {
    try {
        PRICING_PACKAGES = JSON.parse(process.env.PRICING_PACKAGES_JSON);
    } catch (e) {
        console.warn('Invalid PRICING_PACKAGES_JSON, using defaults');
        PRICING_PACKAGES = null;
    }
}

if (!PRICING_PACKAGES) {
    PRICING_PACKAGES = [
        { 
            id: 0, 
            name: process.env.PKG_0_NAME || 'Starter', 
            tokens: parseInt(process.env.PKG_0_TOKENS) || 100000, 
            price_usd: parseFloat(process.env.PKG_0_PRICE_USD) || 9.99,
            price_inr: parseFloat(process.env.PKG_0_PRICE_INR) || 799
        },
        { 
            id: 1, 
            name: process.env.PKG_1_NAME || 'Professional', 
            tokens: parseInt(process.env.PKG_1_TOKENS) || 500000, 
            price_usd: parseFloat(process.env.PKG_1_PRICE_USD) || 39.99,
            price_inr: parseFloat(process.env.PKG_1_PRICE_INR) || 3199
        },
        { 
            id: 2, 
            name: process.env.PKG_2_NAME || 'Enterprise', 
            tokens: parseInt(process.env.PKG_2_TOKENS) || 2000000, 
            price_usd: parseFloat(process.env.PKG_2_PRICE_USD) || 149.99,
            price_inr: parseFloat(process.env.PKG_2_PRICE_INR) || 11999
        }
    ];
}

// Generate API key
function generateApiKey() {
    const prefix = 'lsc_'; // LinkedIn Sales Copilot prefix
    const randomPart = crypto.randomBytes(32).toString('hex');
    return `${prefix}${randomPart}`;
}

// Initialize user with free tokens and generate API key if needed
async function initializeUser(userId, userData = {}) {
    try {
        const connection = await pool.getConnection();
        
        // Check if user exists
        const [existing] = await connection.query(
            'SELECT * FROM users WHERE user_id = ?',
            [userId]
        );
        
        if (existing.length === 0) {
            // Generate API key for new user
            const apiKey = generateApiKey();
            // Create new user with free tokens and API key
            await connection.query(
                'INSERT INTO users (user_id, balance, used, name, linkedin_profile_url, api_key, api_key_created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())',
                [
                    userId, 
                    CREDIT_CONFIG.FREE_TOKENS, 
                    0,
                    userData.name || null,
                    userData.linkedinProfileUrl || null,
                    apiKey
                ]
            );
        } else if (userData.name || userData.linkedinProfileUrl) {
            // Update user profile data if provided
            await connection.query(
                'UPDATE users SET name = COALESCE(?, name), linkedin_profile_url = COALESCE(?, linkedin_profile_url) WHERE user_id = ?',
                [userData.name || null, userData.linkedinProfileUrl || null, userId]
            );
        }
        
        // Get user data
        const [users] = await connection.query(
            'SELECT * FROM users WHERE user_id = ?',
            [userId]
        );
        
        connection.release();
        
        if (users.length === 0) {
            throw new Error('Failed to initialize user');
        }
        
        return {
            userId: users[0].user_id,
            balance: users[0].balance,
            used: users[0].used,
            name: users[0].name,
            linkedinProfileUrl: users[0].linkedin_profile_url,
            createdAt: users[0].created_at
        };
    } catch (error) {
        console.error('Error initializing user:', error);
        throw error;
    }
}

// Get or generate API key for user
async function getOrGenerateApiKey(userId) {
    try {
        const connection = await pool.getConnection();
        const [users] = await connection.query(
            'SELECT api_key FROM users WHERE user_id = ?',
            [userId]
        );
        
        if (users.length === 0) {
            connection.release();
            throw new Error('User not found');
        }
        
        let apiKey = users[0].api_key;
        
        // Generate API key if user doesn't have one
        if (!apiKey) {
            apiKey = generateApiKey();
            await connection.query(
                'UPDATE users SET api_key = ?, api_key_created_at = NOW() WHERE user_id = ?',
                [apiKey, userId]
            );
        }
        
        connection.release();
        return apiKey;
    } catch (error) {
        console.error('Error getting API key:', error);
        throw error;
    }
}

// Validate API key middleware
async function validateApiKey(req, res, next) {
    try {
        const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
        
        if (!apiKey) {
            return res.status(401).json({ error: 'API key is required. Please provide x-api-key header or Authorization Bearer token.' });
        }
        
        const connection = await pool.getConnection();
        const [users] = await connection.query(
            'SELECT user_id, api_key FROM users WHERE api_key = ?',
            [apiKey]
        );
        
        if (users.length === 0) {
            connection.release();
            return res.status(401).json({ error: 'Invalid API key' });
        }
        
        // Update last API call timestamp
        await connection.query(
            'UPDATE users SET last_api_call_at = NOW() WHERE user_id = ?',
            [users[0].user_id]
        );
        
        // Attach user info to request
        req.userId = users[0].user_id;
        req.apiKey = apiKey;
        
        connection.release();
        next();
    } catch (error) {
        console.error('Error validating API key:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

// Rate limiting middleware
async function rateLimitMiddleware(req, res, next) {
    try {
        const apiKey = req.apiKey;
        const endpoint = req.path;
        const now = new Date();
        const windowStart = new Date(now.getTime() - RATE_LIMIT_WINDOW_MS);
        
        const connection = await pool.getConnection();
        
        // Clean up old rate limit records
        await connection.query(
            'DELETE FROM api_rate_limits WHERE window_start < ?',
            [windowStart]
        );
        
        // Get current rate limit for this API key and endpoint
        const [limits] = await connection.query(
            'SELECT request_count FROM api_rate_limits WHERE api_key = ? AND endpoint = ? AND window_start >= ?',
            [apiKey, endpoint, windowStart]
        );
        
        if (limits.length > 0) {
            const currentCount = limits[0].request_count;
            if (currentCount >= RATE_LIMIT_MAX_REQUESTS) {
                connection.release();
                return res.status(429).json({ 
                    error: 'Rate limit exceeded',
                    message: `Too many requests. Maximum ${RATE_LIMIT_MAX_REQUESTS} requests per ${RATE_LIMIT_WINDOW_MS / 1000} seconds.`,
                    retryAfter: Math.ceil((RATE_LIMIT_WINDOW_MS - (now.getTime() - new Date(limits[0].window_start).getTime())) / 1000)
                });
            }
            
            // Increment request count
            await connection.query(
                'UPDATE api_rate_limits SET request_count = request_count + 1 WHERE api_key = ? AND endpoint = ? AND window_start >= ?',
                [apiKey, endpoint, windowStart]
            );
        } else {
            // Create new rate limit record
            await connection.query(
                'INSERT INTO api_rate_limits (api_key, endpoint, request_count, window_start) VALUES (?, ?, 1, ?)',
                [apiKey, endpoint, now]
            );
        }
        
        connection.release();
        next();
    } catch (error) {
        console.error('Error in rate limiting:', error);
        // Don't block request on rate limit error, just log it
        next();
    }
}

// Stripe webhook route must use raw body - define BEFORE json parser
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const userId = session.metadata.userId;
        const tokens = parseInt(session.metadata.tokens);
        const packageId = parseInt(session.metadata.packageId);

        if (userId && tokens) {
            const connection = await pool.getConnection();
            
            try {
                await connection.beginTransaction();
                
                // Initialize user if doesn't exist
                await initializeUser(userId);
                
                // Get package details
                const pkg = PRICING_PACKAGES[packageId] || { name: 'Unknown', price_usd: 0, price_inr: 0 };
                const currency = session.metadata.currency || session.currency || 'usd';
                const price = currency === 'inr' ? (pkg.price_inr || 0) : (pkg.price_usd || 0);
                
                // Retrieve payment intent details if available
                let paymentIntentId = null;
                let paymentMethod = null;
                let customerEmail = session.customer_email || session.customer_details?.email || null;
                
                if (session.payment_intent) {
                    try {
                        const paymentIntent = await stripe.paymentIntents.retrieve(session.payment_intent);
                        paymentIntentId = paymentIntent.id;
                        paymentMethod = paymentIntent.payment_method_types?.[0] || null;
                    } catch (err) {
                        console.error('Error retrieving payment intent:', err);
                    }
                }
                
                // Add credits to user balance
                await connection.query(
                    'UPDATE users SET balance = balance + ? WHERE user_id = ?',
                    [tokens, userId]
                );
                
                // Store payment transaction
                const paymentId = uuidv4();
                await connection.query(
                    `INSERT INTO payment_transactions (
                        payment_id, user_id, stripe_session_id, stripe_payment_intent_id,
                        package_id, package_name, tokens_purchased, amount_paid, currency,
                        payment_status, payment_method, customer_email
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        paymentId,
                        userId,
                        session.id,
                        paymentIntentId,
                        packageId,
                        pkg.name,
                        tokens,
                        price,
                        currency,
                        session.payment_status || 'paid',
                        paymentMethod,
                        customerEmail
                    ]
                );
                
                await connection.commit();
                connection.release();

                console.log(`Payment processed: ${tokens} tokens added for user ${userId}, payment ID: ${paymentId}`);
            } catch (error) {
                await connection.rollback();
                connection.release();
                console.error('Error processing payment:', error);
            }
        }
    }

    res.json({ received: true });
});

// JSON parser for all other routes (must come AFTER webhook route)
app.use(express.json({ limit: '10mb' })); // Increase limit for large GPT requests

// Initialize database tables
async function initializeDatabase() {
    try {
        const connection = await pool.getConnection();
        
        // Create users table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                user_id VARCHAR(255) PRIMARY KEY,
                balance INT NOT NULL DEFAULT 10000,
                used INT NOT NULL DEFAULT 0,
                name VARCHAR(255),
                linkedin_profile_url VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_created_at (created_at),
                INDEX idx_linkedin_profile_url (linkedin_profile_url)
            )
        `);
        
        // Create prospects table (for tracking analyzed prospects)
        await connection.query(`
            CREATE TABLE IF NOT EXISTS prospects (
                prospect_id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                linkedin_profile_url VARCHAR(500) NOT NULL,
                name VARCHAR(255),
                headline VARCHAR(500),
                company VARCHAR(255),
                location VARCHAR(255),
                analysis_status VARCHAR(50) DEFAULT 'pending',
                analyzed_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_linkedin_profile_url (linkedin_profile_url),
                INDEX idx_analysis_status (analysis_status),
                INDEX idx_created_at (created_at),
                UNIQUE KEY unique_user_prospect (user_id, linkedin_profile_url)
            )
        `);
        
        // Create transactions table (for credit usage)
        await connection.query(`
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                prospect_id VARCHAR(255),
                process_type VARCHAR(100) NOT NULL,
                process_description VARCHAR(500),
                tokens_used INT NOT NULL,
                input_tokens INT NOT NULL,
                output_tokens INT NOT NULL,
                cost DECIMAL(10, 6) NOT NULL,
                model VARCHAR(100),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                FOREIGN KEY (prospect_id) REFERENCES prospects(prospect_id) ON DELETE SET NULL,
                INDEX idx_user_id (user_id),
                INDEX idx_prospect_id (prospect_id),
                INDEX idx_process_type (process_type),
                INDEX idx_timestamp (timestamp),
                INDEX idx_model (model)
            )
        `);
        
        // Create payment_transactions table (for Stripe payments)
        await connection.query(`
            CREATE TABLE IF NOT EXISTS payment_transactions (
                payment_id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                stripe_session_id VARCHAR(255) NOT NULL,
                stripe_payment_intent_id VARCHAR(255),
                package_id INT NOT NULL,
                package_name VARCHAR(100) NOT NULL,
                tokens_purchased INT NOT NULL,
                amount_paid DECIMAL(10, 2) NOT NULL,
                currency VARCHAR(10) NOT NULL DEFAULT 'usd',
                payment_status VARCHAR(50) NOT NULL,
                payment_method VARCHAR(50),
                customer_email VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_stripe_session_id (stripe_session_id),
                INDEX idx_payment_status (payment_status),
                INDEX idx_created_at (created_at)
            )
        `);
        
        // Create content_analyses table (for storing content inspiration analyses)
        await connection.query(`
            CREATE TABLE IF NOT EXISTS content_analyses (
                analysis_id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                profile_url VARCHAR(500) NOT NULL,
                profile_name VARCHAR(255),
                analysis_type VARCHAR(50) DEFAULT 'content_inspiration',
                analysis_data JSON NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_profile_url (profile_url),
                INDEX idx_analysis_type (analysis_type),
                INDEX idx_created_at (created_at)
            )
        `);
        
        // Create generated_content table (for storing AI-generated LinkedIn content)
        await connection.query(`
            CREATE TABLE IF NOT EXISTS generated_content (
                content_id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                content_type VARCHAR(50) NOT NULL,
                topic VARCHAR(500),
                tone VARCHAR(50),
                content TEXT NOT NULL,
                title VARCHAR(500),
                strategy TEXT,
                tips JSON,
                hashtags JSON,
                metadata JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_content_type (content_type),
                INDEX idx_created_at (created_at)
            )
        `);
        
        // Create job_analyses table (for storing LinkedIn job posting analyses)
        await connection.query(`
            CREATE TABLE IF NOT EXISTS job_analyses (
                job_analysis_id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                job_url VARCHAR(500) NOT NULL,
                job_title VARCHAR(500),
                company_name VARCHAR(255),
                location VARCHAR(255),
                employment_type VARCHAR(100),
                seniority_level VARCHAR(100),
                job_function VARCHAR(255),
                industries JSON,
                description TEXT,
                requirements TEXT,
                responsibilities TEXT,
                skills_required JSON,
                qualifications JSON,
                benefits JSON,
                salary_range VARCHAR(255),
                posted_date VARCHAR(100),
                applicants_count VARCHAR(100),
                raw_data JSON,
                analyzed_data JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_job_url (job_url),
                INDEX idx_company_name (company_name),
                INDEX idx_job_title (job_title),
                INDEX idx_created_at (created_at),
                UNIQUE KEY unique_user_job (user_id, job_url)
            )
        `);
        
        connection.release();
        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Database initialization error:', error);
        throw error;
    }
}

// Initialize database on startup
initializeDatabase().catch(console.error);

// Create or get prospect
async function createOrGetProspect(userId, prospectData) {
    try {
        const connection = await pool.getConnection();
        
        const prospectId = uuidv4();
        const linkedinUrl = prospectData.linkedinProfileUrl || prospectData.linkedin_profile_url || '';
        
        if (!linkedinUrl) {
            connection.release();
            throw new Error('LinkedIn profile URL is required');
        }
        
        // Check if prospect already exists for this user
        const [existing] = await connection.query(
            'SELECT prospect_id FROM prospects WHERE user_id = ? AND linkedin_profile_url = ?',
            [userId, linkedinUrl]
        );
        
        if (existing.length > 0) {
            // Update existing prospect
            await connection.query(
                `UPDATE prospects 
                 SET name = ?, headline = ?, company = ?, location = ?, 
                     analysis_status = 'analyzing', updated_at = CURRENT_TIMESTAMP
                 WHERE prospect_id = ?`,
                [
                    prospectData.name || null,
                    prospectData.headline || null,
                    prospectData.company || null,
                    prospectData.location || null,
                    existing[0].prospect_id
                ]
            );
            connection.release();
            return existing[0].prospect_id;
        }
        
        // Create new prospect
        await connection.query(
            `INSERT INTO prospects (
                prospect_id, user_id, linkedin_profile_url, name, headline, 
                company, location, analysis_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'analyzing')`,
            [
                prospectId,
                userId,
                linkedinUrl,
                prospectData.name || null,
                prospectData.headline || null,
                prospectData.company || null,
                prospectData.location || null
            ]
        );
        
        connection.release();
        return prospectId;
    } catch (error) {
        console.error('Error creating prospect:', error);
        throw error;
    }
}

// Update prospect analysis status
async function updateProspectStatus(prospectId, status = 'completed') {
    try {
        const connection = await pool.getConnection();
        await connection.query(
            `UPDATE prospects 
             SET analysis_status = ?, analyzed_at = CURRENT_TIMESTAMP 
             WHERE prospect_id = ?`,
            [status, prospectId]
        );
        connection.release();
    } catch (error) {
        console.error('Error updating prospect status:', error);
    }
}

// Calculate token cost
function calculateCost(inputTokens, outputTokens) {
    const inputCost = (inputTokens / 1000000) * CREDIT_CONFIG.TOKEN_COST_PER_1M.input;
    const outputCost = (outputTokens / 1000000) * CREDIT_CONFIG.TOKEN_COST_PER_1M.output;
    return inputCost + outputCost;
}

// Convert cost to tokens (reverse calculation)
function costToTokens(cost) {
    // Approximate: average of input/output rates
    const avgRate = (CREDIT_CONFIG.TOKEN_COST_PER_1M.input + CREDIT_CONFIG.TOKEN_COST_PER_1M.output) / 2;
    return Math.floor((cost / avgRate) * 1000000);
}

// Public endpoint to get or generate API key (requires user-id for initial setup)
app.post('/api/auth/generate-key', async (req, res) => {
    try {
        const userId = req.headers['x-user-id'] || req.body.userId || uuidv4();
        
        if (!userId) {
            return res.status(400).json({ error: 'User ID is required' });
        }
        
        // Initialize user if needed
        await initializeUser(userId);
        
        // Get or generate API key
        const apiKey = await getOrGenerateApiKey(userId);
        
        res.json({ 
            success: true,
            apiKey: apiKey,
            message: 'API key generated successfully. Store this securely - it will not be shown again.'
        });
    } catch (error) {
        console.error('Error generating API key:', error);
        res.status(500).json({ error: 'Failed to generate API key' });
    }
});

// Get user credits (protected)
app.get('/api/credits', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        const user = await initializeUser(userId);
        
        res.json({
            balance: user.balance,
            used: user.used,
            remaining: user.balance - user.used,
            name: user.name,
            linkedinProfileUrl: user.linkedinProfileUrl
        });
    } catch (error) {
        console.error('Error getting credits:', error);
        res.status(500).json({ error: 'Failed to get credits' });
    }
});

// Get pricing packages (public endpoint, but rate limited)
app.get('/api/packages', (req, res) => {
    res.json({ packages: PRICING_PACKAGES });
});

// Update user profile (protected)
app.post('/api/user/profile', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        
        const { name, linkedinProfileUrl } = req.body;
        await initializeUser(userId, { name, linkedinProfileUrl });
        
        res.json({ success: true, message: 'Profile updated' });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Create prospect (protected)
app.post('/api/prospects', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        
        const prospectData = req.body;
        const prospectId = await createOrGetProspect(userId, prospectData);
        
        res.json({ success: true, prospectId });
    } catch (error) {
        console.error('Error creating prospect:', error);
        res.status(500).json({ error: 'Failed to create prospect: ' + error.message });
    }
});

// Update prospect status (protected)
app.put('/api/prospects/:prospectId/status', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const { prospectId } = req.params;
        const { status } = req.body;
        await updateProspectStatus(prospectId, status);
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating prospect status:', error);
        res.status(500).json({ error: 'Failed to update prospect status' });
    }
});

// Save analysis results (protected)
app.post('/api/analyses', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        
        const {
            prospectId,
            sellerGoal,
            sellerOffer,
            sellerIcp,
            sellerProof,
            sellerRiskLevel,
            sellerOfferType,
            analysisData
        } = req.body;
        
        if (!analysisData) {
            return res.status(400).json({ error: 'Analysis data is required' });
        }
        
        const connection = await pool.getConnection();
        try {
            const analysisId = uuidv4();
            
            await connection.query(
                `INSERT INTO analyses (
                    analysis_id, user_id, prospect_id,
                    seller_goal, seller_offer, seller_icp, seller_proof,
                    seller_risk_level, seller_offer_type, analysis_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    analysisId,
                    userId,
                    prospectId || null,
                    sellerGoal || null,
                    sellerOffer || null,
                    sellerIcp || null,
                    sellerProof || null,
                    sellerRiskLevel || null,
                    sellerOfferType || null,
                    JSON.stringify(analysisData)
                ]
            );
            
            connection.release();
            res.json({ success: true, analysisId });
        } catch (dbError) {
            connection.release();
            throw dbError;
        }
    } catch (error) {
        console.error('Error saving analysis:', error);
        res.status(500).json({ error: 'Failed to save analysis: ' + error.message });
    }
});

// Get analyses for a user (protected)
app.get('/api/analyses', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        
        const { prospectId, limit = 50, offset = 0 } = req.query;
        
        const connection = await pool.getConnection();
        try {
            let query = 'SELECT * FROM analyses WHERE user_id = ?';
            const params = [userId];
            
            if (prospectId) {
                query += ' AND prospect_id = ?';
                params.push(prospectId);
            }
            
            query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
            params.push(parseInt(limit), parseInt(offset));
            
            const [analyses] = await connection.query(query, params);
            
            // Parse JSON data for each analysis
            const parsedAnalyses = analyses.map(analysis => ({
                ...analysis,
                analysisData: JSON.parse(analysis.analysis_data)
            }));
            
            connection.release();
            res.json({ success: true, analyses: parsedAnalyses });
        } catch (dbError) {
            connection.release();
            throw dbError;
        }
    } catch (error) {
        console.error('Error fetching analyses:', error);
        res.status(500).json({ error: 'Failed to fetch analyses: ' + error.message });
    }
});

// OpenAI Proxy - handles GPT calls with credit tracking (protected)
app.post('/api/openai-proxy', validateApiKey, rateLimitMiddleware, async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        await connection.beginTransaction();
        
        const userId = req.userId;

        const user = await initializeUser(userId);
        
        // Check if body is parsed
        if (!req.body) {
            await connection.rollback();
            connection.release();
            return res.status(400).json({ error: 'Request body is missing or not parsed' });
        }
        
        const { request } = req.body;
        
        if (!request) {
            await connection.rollback();
            connection.release();
            return res.status(400).json({ error: 'Request object is missing in body' });
        }

        // Estimate tokens (rough approximation)
        const promptText = request.messages?.map(m => m.content).join(' ') || '';
        const estimatedInputTokens = Math.ceil(promptText.length / 4); // ~4 chars per token
        const estimatedOutputTokens = 500; // Buffer for response

        // Check if user has enough credits
        const estimatedCost = calculateCost(estimatedInputTokens, estimatedOutputTokens);
        const estimatedTokensNeeded = Math.ceil(estimatedCost * 1000000 / CREDIT_CONFIG.TOKEN_COST_PER_1M.input);

        if (user.balance - user.used < estimatedTokensNeeded) {
            await connection.rollback();
            connection.release();
            return res.status(402).json({
                error: 'INSUFFICIENT_CREDITS. You have ' + (user.balance - user.used) + ' credits left. You need ' + estimatedTokensNeeded + ' credits.',
                remaining: user.balance - user.used,
                needed: estimatedTokensNeeded
            });
        }

        // Make OpenAI API call
        const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
        const completion = await openai.chat.completions.create(request);

        // Calculate actual tokens used
        const actualInputTokens = completion.usage?.prompt_tokens || estimatedInputTokens;
        const actualOutputTokens = completion.usage?.completion_tokens || estimatedOutputTokens;
        const actualCost = calculateCost(actualInputTokens, actualOutputTokens);
        const tokensUsed = Math.ceil(actualCost * 1000000 / CREDIT_CONFIG.TOKEN_COST_PER_1M.input);

        // Deduct credits in database
        await connection.query(
            'UPDATE users SET used = used + ? WHERE user_id = ?',
            [tokensUsed, userId]
        );

        // Record transaction
        const transactionId = uuidv4();
        const processType = req.body.processType || 'gpt_api_call';
        const processDescription = req.body.processDescription || `GPT API call using ${request.model}`;
        const prospectId = req.body.prospectId || null;
        
        await connection.query(
            `INSERT INTO transactions (
                transaction_id, user_id, prospect_id, process_type, process_description,
                tokens_used, input_tokens, output_tokens, cost, model
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                transactionId, 
                userId, 
                prospectId,
                processType,
                processDescription,
                tokensUsed, 
                actualInputTokens, 
                actualOutputTokens, 
                actualCost, 
                request.model
            ]
        );

        // Get updated user balance
        const [updatedUser] = await connection.query(
            'SELECT balance, used FROM users WHERE user_id = ?',
            [userId]
        );

        await connection.commit();
        connection.release();

        res.json({
            response: {
                id: completion.id,
                object: completion.object,
                created: completion.created,
                model: completion.model,
                choices: completion.choices,
                usage: completion.usage
            },
            creditsUsed: tokensUsed,
            remaining: updatedUser[0].balance - updatedUser[0].used
        });
    } catch (error) {
        await connection.rollback();
        connection.release();
        console.error('OpenAI Proxy Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Content Analyses endpoints
app.post('/api/content-analyses', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        const {
            profileUrl,
            profileName,
            analysisType,
            analysisData
        } = req.body;
        
        if (!analysisData || !profileUrl) {
            return res.status(400).json({ error: 'Analysis data and profile URL are required' });
        }
        
        const connection = await pool.getConnection();
        try {
            // Check if analysis already exists for this user and profile URL
            const [existing] = await connection.query(
                `SELECT analysis_id FROM content_analyses 
                WHERE user_id = ? AND profile_url = ? 
                LIMIT 1`,
                [userId, profileUrl]
            );
            
            let analysisId;
            if (existing && existing.length > 0) {
                // Update existing analysis
                analysisId = existing[0].analysis_id;
                await connection.query(
                    `UPDATE content_analyses 
                    SET profile_name = ?, 
                        analysis_type = ?, 
                        analysis_data = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE analysis_id = ?`,
                    [
                        profileName || null,
                        analysisType || 'content_inspiration',
                        JSON.stringify(analysisData),
                        analysisId
                    ]
                );
            } else {
                // Create new analysis
                analysisId = uuidv4();
                await connection.query(
                    `INSERT INTO content_analyses (
                        analysis_id, user_id, profile_url, profile_name, analysis_type, analysis_data
                    ) VALUES (?, ?, ?, ?, ?, ?)`,
                    [
                        analysisId,
                        userId,
                        profileUrl,
                        profileName || null,
                        analysisType || 'content_inspiration',
                        JSON.stringify(analysisData)
                    ]
                );
            }
            
            res.json({ 
                success: true,
                analysisId: analysisId,
                updated: existing && existing.length > 0
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Content Analysis Save Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/content-analyses', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        const { limit = 50, offset = 0 } = req.query;
        
        const connection = await pool.getConnection();
        try {
            const [analyses] = await connection.query(
                `SELECT 
                    analysis_id, profile_url, profile_name, analysis_type, 
                    analysis_data, created_at
                FROM content_analyses 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT ? OFFSET ?`,
                [userId, parseInt(limit), parseInt(offset)]
            );
            
            // Parse JSON data
            const parsedAnalyses = analyses.map(a => ({
                ...a,
                analysis_data: typeof a.analysis_data === 'string' 
                    ? JSON.parse(a.analysis_data) 
                    : a.analysis_data
            }));
            
            res.json({ 
                success: true,
                analyses: parsedAnalyses 
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Content Analysis Get Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/content-analyses/:analysisId', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        const { analysisId } = req.params;
        
        const connection = await pool.getConnection();
        try {
            const [result] = await connection.query(
                'DELETE FROM content_analyses WHERE analysis_id = ? AND user_id = ?',
                [analysisId, userId]
            );
            
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Analysis not found or access denied' });
            }
            
            res.json({ 
                success: true,
                message: 'Analysis deleted successfully' 
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Content Analysis Delete Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Job Analyses endpoints
app.post('/api/job-analyses', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        const {
            jobUrl,
            jobTitle,
            companyName,
            location,
            employmentType,
            seniorityLevel,
            jobFunction,
            industries,
            description,
            requirements,
            responsibilities,
            skillsRequired,
            qualifications,
            benefits,
            salaryRange,
            postedDate,
            applicantsCount,
            rawData,
            analyzedData
        } = req.body;
        
        if (!jobUrl) {
            return res.status(400).json({ error: 'Job URL is required' });
        }
        
        const connection = await pool.getConnection();
        try {
            // Check if job analysis already exists for this user and job URL
            const [existing] = await connection.query(
                `SELECT job_analysis_id FROM job_analyses 
                WHERE user_id = ? AND job_url = ? 
                LIMIT 1`,
                [userId, jobUrl]
            );
            
            let jobAnalysisId;
            if (existing && existing.length > 0) {
                // Update existing analysis
                jobAnalysisId = existing[0].job_analysis_id;
                await connection.query(
                    `UPDATE job_analyses 
                    SET job_title = ?, 
                        company_name = ?,
                        location = ?,
                        employment_type = ?,
                        seniority_level = ?,
                        job_function = ?,
                        industries = ?,
                        description = ?,
                        requirements = ?,
                        responsibilities = ?,
                        skills_required = ?,
                        qualifications = ?,
                        benefits = ?,
                        salary_range = ?,
                        posted_date = ?,
                        applicants_count = ?,
                        raw_data = ?,
                        analyzed_data = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE job_analysis_id = ?`,
                    [
                        jobTitle || null,
                        companyName || null,
                        location || null,
                        employmentType || null,
                        seniorityLevel || null,
                        jobFunction || null,
                        industries ? JSON.stringify(industries) : null,
                        description || null,
                        requirements || null,
                        responsibilities || null,
                        skillsRequired ? JSON.stringify(skillsRequired) : null,
                        qualifications ? JSON.stringify(qualifications) : null,
                        benefits ? JSON.stringify(benefits) : null,
                        salaryRange || null,
                        postedDate || null,
                        applicantsCount || null,
                        rawData ? JSON.stringify(rawData) : null,
                        analyzedData ? JSON.stringify(analyzedData) : null,
                        jobAnalysisId
                    ]
                );
            } else {
                // Create new analysis
                jobAnalysisId = uuidv4();
                await connection.query(
                    `INSERT INTO job_analyses (
                        job_analysis_id, user_id, job_url, job_title, company_name, location,
                        employment_type, seniority_level, job_function, industries, description,
                        requirements, responsibilities, skills_required, qualifications, benefits,
                        salary_range, posted_date, applicants_count, raw_data, analyzed_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        jobAnalysisId,
                        userId,
                        jobUrl,
                        jobTitle || null,
                        companyName || null,
                        location || null,
                        employmentType || null,
                        seniorityLevel || null,
                        jobFunction || null,
                        industries ? JSON.stringify(industries) : null,
                        description || null,
                        requirements || null,
                        responsibilities || null,
                        skillsRequired ? JSON.stringify(skillsRequired) : null,
                        qualifications ? JSON.stringify(qualifications) : null,
                        benefits ? JSON.stringify(benefits) : null,
                        salaryRange || null,
                        postedDate || null,
                        applicantsCount || null,
                        rawData ? JSON.stringify(rawData) : null,
                        analyzedData ? JSON.stringify(analyzedData) : null
                    ]
                );
            }
            
            res.json({ 
                success: true,
                jobAnalysisId: jobAnalysisId,
                updated: existing && existing.length > 0
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Job Analysis Save Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/job-analyses', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        const { limit = 50, offset = 0, jobUrl } = req.query;
        
        const connection = await pool.getConnection();
        try {
            let query = `SELECT 
                job_analysis_id, job_url, job_title, company_name, location,
                employment_type, seniority_level, job_function, industries,
                description, requirements, responsibilities, skills_required,
                qualifications, benefits, salary_range, posted_date, applicants_count,
                raw_data, analyzed_data, created_at, updated_at
            FROM job_analyses 
            WHERE user_id = ?`;
            const params = [userId];
            
            if (jobUrl) {
                query += ' AND job_url = ?';
                params.push(jobUrl);
            }
            
            query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
            params.push(parseInt(limit), parseInt(offset));
            
            const [analyses] = await connection.query(query, params);
            
            // Parse JSON fields
            const parsedAnalyses = analyses.map(a => ({
                ...a,
                industries: a.industries ? (typeof a.industries === 'string' ? JSON.parse(a.industries) : a.industries) : null,
                skills_required: a.skills_required ? (typeof a.skills_required === 'string' ? JSON.parse(a.skills_required) : a.skills_required) : null,
                qualifications: a.qualifications ? (typeof a.qualifications === 'string' ? JSON.parse(a.qualifications) : a.qualifications) : null,
                benefits: a.benefits ? (typeof a.benefits === 'string' ? JSON.parse(a.benefits) : a.benefits) : null,
                raw_data: a.raw_data ? (typeof a.raw_data === 'string' ? JSON.parse(a.raw_data) : a.raw_data) : null,
                analyzed_data: a.analyzed_data ? (typeof a.analyzed_data === 'string' ? JSON.parse(a.analyzed_data) : a.analyzed_data) : null
            }));
            
            res.json({ 
                success: true,
                analyses: parsedAnalyses 
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Job Analysis Get Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/job-analyses/:jobAnalysisId', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        const { jobAnalysisId } = req.params;
        
        const connection = await pool.getConnection();
        try {
            const [result] = await connection.query(
                'DELETE FROM job_analyses WHERE job_analysis_id = ? AND user_id = ?',
                [jobAnalysisId, userId]
            );
            
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Job analysis not found or access denied' });
            }
            
            res.json({ 
                success: true,
                message: 'Job analysis deleted successfully' 
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Job Analysis Delete Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// CV File Processing endpoint
app.post('/api/process-cv-file', validateApiKey, rateLimitMiddleware, upload.single('cvFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        const file = req.file;
        const fileName = file.originalname;
        const fileExtension = path.extname(fileName).toLowerCase();
        let extractedText = '';
        
        try {
            // Process based on file type
            if (fileExtension === '.txt' || file.mimetype === 'text/plain') {
                // Plain text file
                extractedText = file.buffer.toString('utf-8');
            } else if (fileExtension === '.docx' || 
                      file.mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
                // DOCX file using mammoth
                const result = await mammoth.extractRawText({ buffer: file.buffer });
                extractedText = result.value;
                
                // Log warnings if any
                if (result.messages && result.messages.length > 0) {
                    const warnings = result.messages.filter(m => m.type === 'warning');
                    if (warnings.length > 0) {
                        console.log(`[CV Processing] DOCX warnings for ${fileName}:`, warnings.map(w => w.message));
                    }
                }
            } else if (fileExtension === '.doc' || file.mimetype === 'application/msword') {
                // DOC file (older format) - mammoth can handle some DOCX-like files
                // Note: True .doc files (binary format) may not work perfectly
                try {
                    const result = await mammoth.extractRawText({ buffer: file.buffer });
                    extractedText = result.value;
                } catch (docError) {
                    return res.status(400).json({ 
                        error: 'DOC file format not fully supported. Please convert to DOCX or TXT format.',
                        details: docError.message 
                    });
                }
            } else if (fileExtension === '.pdf' || file.mimetype === 'application/pdf') {
                // PDF file using pdf-parse
                try {
                    const pdfData = await pdfParse(file.buffer);
                    extractedText = pdfData.text;
                    
                    // Log PDF metadata
                    if (pdfData.info) {
                        console.log(`[CV Processing] PDF metadata for ${fileName}:`, {
                            title: pdfData.info.Title,
                            author: pdfData.info.Author,
                            pages: pdfData.numpages
                        });
                    }
                } catch (pdfError) {
                    return res.status(400).json({ 
                        error: 'Failed to parse PDF file. Please ensure it is a valid PDF with extractable text.',
                        details: pdfError.message 
                    });
                }
            } else {
                return res.status(400).json({ 
                    error: `Unsupported file format: ${fileExtension}. Supported formats: TXT, DOCX, DOC, PDF` 
                });
            }
            
            // Clean up extracted text
            extractedText = extractedText.replace(/\n{3,}/g, '\n\n').trim();
            
            if (!extractedText || extractedText.length < 10) {
                return res.status(400).json({ 
                    error: 'File appears to be empty or could not extract meaningful text. Please ensure the file contains readable text.' 
                });
            }
            
            // Structure CV using GPT (optional, but recommended for better suggestions)
            let structuredCv = null;
            try {
                structuredCv = await structureCvWithGpt(extractedText, req.userId);
                console.log('[CV Processing] ✓ CV structured into JSON object');
            } catch (gptError) {
                console.warn('[CV Processing] GPT structuring failed, returning raw text:', gptError.message);
                // Continue with raw text if structuring fails
            }
            
            res.json({
                success: true,
                fileName: fileName,
                fileType: fileExtension,
                content: extractedText,
                structured: structuredCv, // Include structured CV object
                characterCount: extractedText.length,
                wordCount: extractedText.trim().split(/\s+/).filter(w => w.length > 0).length
            });
            
        } catch (processingError) {
            console.error('[CV Processing] Error processing file:', processingError);
            res.status(500).json({ 
                error: 'Failed to process file',
                details: processingError.message 
            });
        }
        
    } catch (error) {
        console.error('CV File Processing Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Generate Formatted CV endpoint (PDF or DOCX) with GPT structuring
app.post('/api/generate-cv-file', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const { cvContent, structuredCv, useStructuredCv, format, jobTitle, fileName, useGptFormatting = true, aiEdits = [] } = req.body;
        
        // Prefer structured CV if provided
        let finalStructuredCv = null;
        if (useStructuredCv && structuredCv) {
            finalStructuredCv = structuredCv;
            console.log('[CV Generation] Using provided structured CV');
        } else if (cvContent && cvContent.trim()) {
            // Fallback to structuring from content if no structured CV provided
            if (useGptFormatting && cvContent.length < 50000) {
                try {
                    finalStructuredCv = await structureCvWithGpt(cvContent, req.userId);
                    console.log('[CV Generation] ✓ CV structured with GPT from content');
                } catch (gptError) {
                    console.warn('[CV Generation] GPT structuring failed:', gptError.message);
                }
            }
        } else if (!structuredCv) {
            return res.status(400).json({ error: 'CV content or structured CV is required' });
        }
        
        if (!format || !['pdf', 'docx'].includes(format.toLowerCase())) {
            return res.status(400).json({ error: 'Format must be either "pdf" or "docx"' });
        }
        
        const safeJobTitle = (jobTitle || 'job').replace(/[^a-z0-9]/gi, '_').substring(0, 50);
        const timestamp = Date.now();
        const defaultFileName = fileName || `optimized_cv_${safeJobTitle}_${timestamp}`;
        
        try {
            // Use provided structured CV (preferred) or structure from content if needed
            const structuredCv = finalStructuredCv;
            const cvContentForFallback = cvContent || '';
            
            if (format.toLowerCase() === 'docx') {
                // Generate DOCX file
                const doc = new Document({
                    sections: [{
                        properties: {},
                        children: structuredCv 
                            ? formatStructuredCvForDocx(structuredCv, aiEdits)
                            : formatCvContentForDocx(cvContentForFallback, aiEdits)
                    }]
                });
                
                // Generate buffer
                const buffer = await Packer.toBuffer(doc);
                
                res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
                res.setHeader('Content-Disposition', `attachment; filename="${defaultFileName}.docx"`);
                res.send(buffer);
                
            } else if (format.toLowerCase() === 'pdf') {
                // Generate PDF file
                const doc = new PDFDocument({
                    margin: 50,
                    size: 'LETTER'
                });
                
                // Set response headers
                res.setHeader('Content-Type', 'application/pdf');
                res.setHeader('Content-Disposition', `attachment; filename="${defaultFileName}.pdf"`);
                
                // Pipe PDF to response
                doc.pipe(res);
                
                // Format and add CV content
                if (structuredCv) {
                    formatStructuredCvForPdf(doc, structuredCv, aiEdits);
                } else {
                    formatCvContentForPdf(doc, cvContentForFallback, aiEdits);
                }
                
                // Finalize PDF
                doc.end();
            }
            
        } catch (generationError) {
            console.error('[CV Generation] Error generating file:', generationError);
            res.status(500).json({ 
                error: 'Failed to generate CV file',
                details: generationError.message 
            });
        }
        
    } catch (error) {
        console.error('CV Generation Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Helper function to structure CV using GPT
async function structureCvWithGpt(cvContent, userId) {
    const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    
    const prompt = `You are an expert CV/resume parser. Parse the following CV content and structure it into a well-organized JSON format.

CV CONTENT:
${cvContent}

Extract and organize the CV into the following structure:
{
  "personalInfo": {
    "name": "Full Name",
    "email": "email@example.com",
    "phone": "phone number",
    "location": "City, State/Country",
    "linkedin": "LinkedIn URL",
    "website": "Personal website"
  },
  "summary": "Professional summary or objective",
  "experience": [
    {
      "title": "Job Title",
      "company": "Company Name",
      "location": "City, State",
      "startDate": "MM/YYYY or YYYY",
      "endDate": "MM/YYYY, YYYY, or 'Present'",
      "description": "Brief description",
      "achievements": ["achievement 1", "achievement 2", ...]
    }
  ],
  "education": [
    {
      "degree": "Degree Name",
      "school": "School/University Name",
      "location": "City, State",
      "graduationDate": "YYYY",
      "gpa": "GPA if mentioned",
      "honors": "Honors if any"
    }
  ],
  "skills": {
    "technical": ["skill1", "skill2", ...],
    "soft": ["skill1", "skill2", ...],
    "languages": ["language1", "language2", ...]
  },
  "projects": [
    {
      "name": "Project Name",
      "description": "Project description",
      "technologies": ["tech1", "tech2"],
      "url": "Project URL if available"
    }
  ],
  "certifications": [
    {
      "name": "Certification Name",
      "issuer": "Issuing Organization",
      "date": "Date",
      "expiryDate": "Expiry if applicable"
    }
  ],
  "awards": ["Award 1", "Award 2", ...],
  "additionalSections": {
    "sectionName": "content or array of items"
  }
}

Return ONLY valid JSON. If a section is not present in the CV, use null or empty array/object.`;

    try {
        const completion = await openai.chat.completions.create({
            model: 'gpt-4o-mini',
            messages: [
                { role: 'system', content: 'You are an expert CV/resume parser. Always respond with valid JSON only.' },
                { role: 'user', content: prompt }
            ],
            temperature: 0.3,
            max_tokens: 3000,
            response_format: { type: 'json_object' }
        });
        
        const responseText = completion.choices[0].message.content;
        const structured = JSON.parse(responseText);
        
        return structured;
    } catch (error) {
        console.error('[CV Structuring] GPT error:', error);
        throw error;
    }
}

// Helper function to format structured CV data for DOCX
function formatStructuredCvForDocx(structuredCv) {
    const children = [];
    
    // Personal Info Header
    if (structuredCv.personalInfo) {
        const info = structuredCv.personalInfo;
        const nameParts = [];
        if (info.name) nameParts.push(new TextRun({ text: info.name, bold: true, size: 32 }));
        
        const contactInfo = [];
        if (info.email) contactInfo.push(info.email);
        if (info.phone) contactInfo.push(info.phone);
        if (info.location) contactInfo.push(info.location);
        if (info.linkedin) contactInfo.push(info.linkedin);
        
        children.push(new Paragraph({
            children: nameParts,
            alignment: AlignmentType.CENTER,
            spacing: { after: 100 }
        }));
        
        if (contactInfo.length > 0) {
            children.push(new Paragraph({
                text: contactInfo.join(' | '),
                alignment: AlignmentType.CENTER,
                spacing: { after: 240 }
            }));
        }
    }
    
    // Summary
    if (structuredCv.summary) {
        children.push(new Paragraph({
            text: 'PROFESSIONAL SUMMARY',
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 240, after: 120 },
            border: {
                bottom: { color: "4472C4", size: 6, space: 1, value: "single" }
            }
        }));
        children.push(new Paragraph({
            text: structuredCv.summary,
            spacing: { after: 240 }
        }));
    }
    
    // Experience
    if (structuredCv.experience && structuredCv.experience.length > 0) {
        children.push(new Paragraph({
            text: 'PROFESSIONAL EXPERIENCE',
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 240, after: 180 },
            border: {
                bottom: { color: "4472C4", size: 6, space: 1, value: "single" }
            }
        }));
        
        structuredCv.experience.forEach(exp => {
            const titleParts = [new TextRun({ text: exp.title || '', bold: true, size: 24 })];
            if (exp.company) {
                titleParts.push(new TextRun({ text: ` | ${exp.company}`, size: 24 }));
            }
            if (exp.location) {
                titleParts.push(new TextRun({ text: ` | ${exp.location}`, italics: true, size: 22 }));
            }
            if (exp.startDate || exp.endDate) {
                const dateRange = `${exp.startDate || ''} - ${exp.endDate || 'Present'}`;
                titleParts.push(new TextRun({ text: ` | ${dateRange}`, size: 22 }));
            }
            
            children.push(new Paragraph({
                children: titleParts,
                spacing: { after: 100 }
            }));
            
            if (exp.description) {
                children.push(new Paragraph({
                    text: exp.description,
                    spacing: { after: 80 }
                }));
            }
            
            if (exp.achievements && exp.achievements.length > 0) {
                exp.achievements.forEach(achievement => {
                    children.push(new Paragraph({
                        text: achievement,
                        bullet: { level: 0 },
                        spacing: { after: 80 },
                        indent: { left: 360 }
                    }));
                });
            }
            
            children.push(new Paragraph({ text: '', spacing: { after: 120 } }));
        });
    }
    
    // Education
    if (structuredCv.education && structuredCv.education.length > 0) {
        children.push(new Paragraph({
            text: 'EDUCATION',
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 240, after: 180 },
            border: {
                bottom: { color: "4472C4", size: 6, space: 1, value: "single" }
            }
        }));
        
        structuredCv.education.forEach(edu => {
            const eduParts = [new TextRun({ text: edu.degree || '', bold: true, size: 24 })];
            if (edu.school) {
                eduParts.push(new TextRun({ text: ` | ${edu.school}`, size: 24 }));
            }
            if (edu.location) {
                eduParts.push(new TextRun({ text: ` | ${edu.location}`, italics: true, size: 22 }));
            }
            if (edu.graduationDate) {
                eduParts.push(new TextRun({ text: ` | ${edu.graduationDate}`, size: 22 }));
            }
            
            children.push(new Paragraph({
                children: eduParts,
                spacing: { after: 100 }
            }));
            
            if (edu.gpa || edu.honors) {
                const details = [];
                if (edu.gpa) details.push(`GPA: ${edu.gpa}`);
                if (edu.honors) details.push(edu.honors);
                children.push(new Paragraph({
                    text: details.join(' | '),
                    spacing: { after: 120 }
                }));
            }
        });
    }
    
    // Skills
    if (structuredCv.skills) {
        const skillSections = [];
        if (structuredCv.skills.technical && structuredCv.skills.technical.length > 0) {
            skillSections.push(`Technical: ${structuredCv.skills.technical.join(', ')}`);
        }
        if (structuredCv.skills.soft && structuredCv.skills.soft.length > 0) {
            skillSections.push(`Soft Skills: ${structuredCv.skills.soft.join(', ')}`);
        }
        if (structuredCv.skills.languages && structuredCv.skills.languages.length > 0) {
            skillSections.push(`Languages: ${structuredCv.skills.languages.join(', ')}`);
        }
        
        if (skillSections.length > 0) {
            children.push(new Paragraph({
                text: 'SKILLS',
                heading: HeadingLevel.HEADING_2,
                spacing: { before: 240, after: 120 },
                border: {
                    bottom: { color: "4472C4", size: 6, space: 1, value: "single" }
                }
            }));
            
            skillSections.forEach(section => {
                children.push(new Paragraph({
                    text: section,
                    spacing: { after: 80 }
                }));
            });
        }
    }
    
    // Projects
    if (structuredCv.projects && structuredCv.projects.length > 0) {
        children.push(new Paragraph({
            text: 'PROJECTS',
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 240, after: 180 },
            border: {
                bottom: { color: "4472C4", size: 6, space: 1, value: "single" }
            }
        }));
        
        structuredCv.projects.forEach(project => {
            const projParts = [new TextRun({ text: project.name || '', bold: true, size: 24 })];
            if (project.technologies && project.technologies.length > 0) {
                projParts.push(new TextRun({ text: ` | ${project.technologies.join(', ')}`, size: 22 }));
            }
            
            children.push(new Paragraph({
                children: projParts,
                spacing: { after: 80 }
            }));
            
            if (project.description) {
                children.push(new Paragraph({
                    text: project.description,
                    spacing: { after: 120 }
                }));
            }
        });
    }
    
    // Certifications
    if (structuredCv.certifications && structuredCv.certifications.length > 0) {
        children.push(new Paragraph({
            text: 'CERTIFICATIONS',
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 240, after: 120 },
            border: {
                bottom: { color: "4472C4", size: 6, space: 1, value: "single" }
            }
        }));
        
        structuredCv.certifications.forEach(cert => {
            const certText = `${cert.name}${cert.issuer ? ` | ${cert.issuer}` : ''}${cert.date ? ` | ${cert.date}` : ''}`;
            children.push(new Paragraph({
                text: certText,
                spacing: { after: 80 }
            }));
        });
    }
    
    return children.length > 0 ? children : [new Paragraph({ text: 'CV content' })];
}

// Helper function to check if text position is in AI edit range
function isAiEdit(position, aiEdits) {
    if (!aiEdits || aiEdits.length === 0) return false;
    return aiEdits.some(edit => position >= edit.start && position <= edit.end);
}

// Helper function to format CV content for DOCX with better structure
function formatCvContentForDocx(cvContent, aiEdits = []) {
    // Preserve ALL lines including empty ones for proper spacing
    const lines = cvContent.split('\n');
    const children = [];
    
    let currentSection = null;
    let inExperienceBlock = false;
    let experienceItems = [];
    
    // Calculate character positions for AI edit detection
    let charPosition = 0;
    
    // Parse CV into structured sections
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i]; // Preserve original
        const trimmedLine = line.trim();
        const nextLine = i < lines.length - 1 ? lines[i + 1].trim() : '';
        const lineStartPos = charPosition;
        const lineEndPos = charPosition + line.length;
        
        // Handle empty lines - preserve as spacing
        if (trimmedLine.length === 0) {
            if (i > 0 && i < lines.length - 1 && children.length > 0) {
                children.push(new Paragraph({ text: '', spacing: { after: 100 } }));
            }
            charPosition = lineEndPos + 1;
            continue;
        }
        
        // Detect section headers (use trimmed line for detection)
        const isSectionHeader = (
            trimmedLine === trimmedLine.toUpperCase() && trimmedLine.length < 50 && trimmedLine.length > 2 ||
            trimmedLine.endsWith(':') && trimmedLine.length < 50 ||
            /^(PROFESSIONAL|EXPERIENCE|WORK|EDUCATION|SKILLS|SUMMARY|OBJECTIVE|CONTACT|PROJECTS|CERTIFICATIONS|AWARDS|LANGUAGES|TECHNICAL|SUGGESTED)/i.test(trimmedLine)
        );
        
        // Check if this line is part of an AI edit
        const isAiEdited = isAiEdit(lineStartPos, aiEdits) || isAiEdit(lineEndPos, aiEdits);
        
        if (isSectionHeader) {
            // Close any open experience block
            if (inExperienceBlock && experienceItems.length > 0) {
                children.push(...experienceItems);
                experienceItems = [];
                inExperienceBlock = false;
            }
            
            // Add spacing before new section
            if (children.length > 0) {
                children.push(new Paragraph({ text: '' }));
            }
            
            // Add section header with better styling
            const headerText = trimmedLine.replace(':', '').trim();
            children.push(new Paragraph({
                text: headerText,
                heading: HeadingLevel.HEADING_2,
                spacing: { before: 240, after: 180 },
                border: {
                    bottom: {
                        color: "4472C4",
                        size: 6,
                        space: 1,
                        value: "single"
                    }
                }
            }));
            
            currentSection = line;
        } else {
            // Detect job entries (pattern: Job Title | Company | Date or similar)
            const isJobEntry = /^[A-Z][^|]+(\s*\|\s*[^|]+)+/.test(line) || 
                             (/^[A-Z][^•]+$/.test(line) && line.length < 100 && nextLine && /^\d{4}|\w+\s+\d{4}/.test(nextLine));
            
            // Detect dates (for experience/education entries)
            const hasDate = /\d{4}|\w+\s+\d{4}|Present|Current/i.test(line);
            
            // Check if it's a bullet point
            const isBullet = /^[-•*]\s/.test(line) || /^\d+\.\s/.test(line);
            const cleanLine = line.replace(/^[-•*]\s/, '').replace(/^\d+\.\s/, '');
            
            if (isJobEntry || (hasDate && !isBullet)) {
                // Job title or position entry - make it bold
                children.push(new Paragraph({
                    children: [
                        new TextRun({
                            text: cleanLine,
                            bold: true,
                            size: 24 // 12pt
                        })
                    ],
                    spacing: { after: 120 }
                }));
            } else if (isBullet) {
                // Bullet point with proper formatting
                children.push(new Paragraph({
                    text: cleanLine,
                    bullet: {
                        level: 0
                    },
                    spacing: { after: 100 },
                    indent: { left: 360 } // 0.25 inch indent
                }));
            } else {
                // Regular text - check if it's a company name or location
                const isCompanyOrLocation = line.length < 80 && (
                    /^(at|@)/i.test(line) ||
                    /^[A-Z][a-z]+\s+(Inc|LLC|Ltd|Corp|Company)/i.test(line) ||
                    /,\s*[A-Z]{2}\s+\d{5}/.test(line) // Location pattern
                );
                
                if (isCompanyOrLocation) {
                    // Company or location - italic
                    children.push(new Paragraph({
                        children: [
                            new TextRun({
                                text: cleanLine,
                                italics: true,
                                size: 22 // 11pt
                            })
                        ],
                        spacing: { after: 100 }
                    }));
            } else {
                // Regular paragraph - highlight if AI-edited
                if (isAiEdited) {
                    children.push(new Paragraph({
                        children: [
                            new TextRun({
                                text: cleanLine,
                                highlight: "yellow",
                                italics: true
                            })
                        ],
                        spacing: { after: 100 }
                    }));
                } else {
                    children.push(new Paragraph({
                        text: cleanLine,
                        spacing: { after: 100 }
                    }));
                }
            }
        }
        
        // Update character position (add 1 for newline)
        charPosition = lineEndPos + 1;
    }
    
    // Close any remaining experience block
    if (experienceItems.length > 0) {
        children.push(...experienceItems);
    }
    
    return children.length > 0 ? children : [new Paragraph({ text: cvContent })];
    }

}

// Helper function to format structured CV data for PDF
function formatStructuredCvForPdf(doc, structuredCv, aiEdits = []) {
    // Header with name
    if (structuredCv.personalInfo && structuredCv.personalInfo.name) {
        doc.fontSize(24)
           .font('Helvetica-Bold')
           .fillColor('#0a66c2')
           .text(structuredCv.personalInfo.name, { align: 'center' })
           .fillColor('black')
           .moveDown(0.3);
        
        // Contact info
        const contactInfo = [];
        if (structuredCv.personalInfo.email) contactInfo.push(structuredCv.personalInfo.email);
        if (structuredCv.personalInfo.phone) contactInfo.push(structuredCv.personalInfo.phone);
        if (structuredCv.personalInfo.location) contactInfo.push(structuredCv.personalInfo.location);
        if (structuredCv.personalInfo.linkedin) contactInfo.push(structuredCv.personalInfo.linkedin);
        
        if (contactInfo.length > 0) {
            doc.fontSize(10)
               .font('Helvetica')
               .text(contactInfo.join(' | '), { align: 'center' })
               .moveDown(0.5);
        }
        
        // Decorative line
        doc.moveTo(50, doc.y)
           .lineTo(550, doc.y)
           .strokeColor('#0a66c2')
           .lineWidth(2)
           .stroke()
           .moveDown(1);
    }
    
    // Summary
    if (structuredCv.summary) {
        doc.fontSize(14)
           .font('Helvetica-Bold')
           .fillColor('#0a66c2')
           .text('PROFESSIONAL SUMMARY', 60, doc.y, { width: 480 })
           .fillColor('black')
           .moveDown(0.5);
        
        doc.fontSize(11)
           .font('Helvetica')
           .text(structuredCv.summary, { width: 500 })
           .moveDown(1);
    }
    
    // Experience
    if (structuredCv.experience && structuredCv.experience.length > 0) {
        // Section header
        const headerY = doc.y;
        doc.rect(50, headerY - 5, 500, 25)
           .fillColor('#e8f0fe')
           .fill()
           .fillColor('black');
        
        doc.fontSize(14)
           .font('Helvetica-Bold')
           .fillColor('#0a66c2')
           .text('PROFESSIONAL EXPERIENCE', 60, headerY, { width: 480 })
           .fillColor('black')
           .moveDown(0.8);
        
        structuredCv.experience.forEach(exp => {
            // Job title and company
            const titleLine = `${exp.title || ''}${exp.company ? ` | ${exp.company}` : ''}${exp.location ? ` | ${exp.location}` : ''}`;
            doc.fontSize(13)
               .font('Helvetica-Bold')
               .text(titleLine, { width: 500 })
               .moveDown(0.2);
            
            // Date range
            if (exp.startDate || exp.endDate) {
                const dateRange = `${exp.startDate || ''} - ${exp.endDate || 'Present'}`;
                doc.fontSize(10)
                   .font('Helvetica-Oblique')
                   .text(dateRange)
                   .moveDown(0.3);
            }
            
            // Description
            if (exp.description) {
                doc.fontSize(11)
                   .font('Helvetica')
                   .text(exp.description, { width: 500 })
                   .moveDown(0.3);
            }
            
            // Achievements
            if (exp.achievements && exp.achievements.length > 0) {
                exp.achievements.forEach(achievement => {
                    doc.fontSize(11)
                       .font('Helvetica')
                       .text('•', 60)
                       .text(achievement, 75, doc.y - 11, { width: 470 })
                       .moveDown(0.4);
                });
            }
            
            doc.moveDown(0.5);
        });
    }
    
    // Education
    if (structuredCv.education && structuredCv.education.length > 0) {
        const headerY = doc.y;
        doc.rect(50, headerY - 5, 500, 25)
           .fillColor('#e8f0fe')
           .fill()
           .fillColor('black');
        
        doc.fontSize(14)
           .font('Helvetica-Bold')
           .fillColor('#0a66c2')
           .text('EDUCATION', 60, headerY, { width: 480 })
           .fillColor('black')
           .moveDown(0.8);
        
        structuredCv.education.forEach(edu => {
            const eduLine = `${edu.degree || ''}${edu.school ? ` | ${edu.school}` : ''}${edu.location ? ` | ${edu.location}` : ''}${edu.graduationDate ? ` | ${edu.graduationDate}` : ''}`;
            doc.fontSize(12)
               .font('Helvetica-Bold')
               .text(eduLine, { width: 500 })
               .moveDown(0.2);
            
            if (edu.gpa || edu.honors) {
                const details = [];
                if (edu.gpa) details.push(`GPA: ${edu.gpa}`);
                if (edu.honors) details.push(edu.honors);
                doc.fontSize(10)
                   .font('Helvetica')
                   .text(details.join(' | '))
                   .moveDown(0.5);
            }
        });
    }
    
    // Skills
    if (structuredCv.skills) {
        const headerY = doc.y;
        doc.rect(50, headerY - 5, 500, 25)
           .fillColor('#e8f0fe')
           .fill()
           .fillColor('black');
        
        doc.fontSize(14)
           .font('Helvetica-Bold')
           .fillColor('#0a66c2')
           .text('SKILLS', 60, headerY, { width: 480 })
           .fillColor('black')
           .moveDown(0.8);
        
        const skillLines = [];
        if (structuredCv.skills.technical && structuredCv.skills.technical.length > 0) {
            skillLines.push(`Technical: ${structuredCv.skills.technical.join(', ')}`);
        }
        if (structuredCv.skills.soft && structuredCv.skills.soft.length > 0) {
            skillLines.push(`Soft Skills: ${structuredCv.skills.soft.join(', ')}`);
        }
        if (structuredCv.skills.languages && structuredCv.skills.languages.length > 0) {
            skillLines.push(`Languages: ${structuredCv.skills.languages.join(', ')}`);
        }
        
        skillLines.forEach(line => {
            doc.fontSize(11)
               .font('Helvetica')
               .text(line, { width: 500 })
               .moveDown(0.4);
        });
    }
    
    // Projects
    if (structuredCv.projects && structuredCv.projects.length > 0) {
        const headerY = doc.y;
        doc.rect(50, headerY - 5, 500, 25)
           .fillColor('#e8f0fe')
           .fill()
           .fillColor('black');
        
        doc.fontSize(14)
           .font('Helvetica-Bold')
           .fillColor('#0a66c2')
           .text('PROJECTS', 60, headerY, { width: 480 })
           .fillColor('black')
           .moveDown(0.8);
        
        structuredCv.projects.forEach(project => {
            const projLine = `${project.name || ''}${project.technologies && project.technologies.length > 0 ? ` | ${project.technologies.join(', ')}` : ''}`;
            doc.fontSize(12)
               .font('Helvetica-Bold')
               .text(projLine, { width: 500 })
               .moveDown(0.2);
            
            if (project.description) {
                doc.fontSize(11)
                   .font('Helvetica')
                   .text(project.description, { width: 500 })
                   .moveDown(0.5);
            }
        });
    }
    
    // Certifications
    if (structuredCv.certifications && structuredCv.certifications.length > 0) {
        const headerY = doc.y;
        doc.rect(50, headerY - 5, 500, 25)
           .fillColor('#e8f0fe')
           .fill()
           .fillColor('black');
        
        doc.fontSize(14)
           .font('Helvetica-Bold')
           .fillColor('#0a66c2')
           .text('CERTIFICATIONS', 60, headerY, { width: 480 })
           .fillColor('black')
           .moveDown(0.8);
        
        structuredCv.certifications.forEach(cert => {
            const certText = `${cert.name}${cert.issuer ? ` | ${cert.issuer}` : ''}${cert.date ? ` | ${cert.date}` : ''}`;
            doc.fontSize(11)
               .font('Helvetica')
               .text(certText, { width: 500 })
               .moveDown(0.4);
        });
    }
}

// Helper function to format CV content for PDF with better structure
function formatCvContentForPdf(doc, cvContent, aiEdits = []) {
    // Preserve all lines, including empty ones that might be intentional spacing
    const lines = cvContent.split('\n');
    
    // Add professional header with line
    doc.fontSize(24)
       .font('Helvetica-Bold')
       .fillColor('#0a66c2') // LinkedIn blue
       .text('CURRICULUM VITAE', { align: 'center' })
       .fillColor('black')
       .moveDown(0.5);
    
    // Add decorative line
    doc.moveTo(50, doc.y)
       .lineTo(550, doc.y)
       .strokeColor('#0a66c2')
       .lineWidth(2)
       .stroke()
       .moveDown(1);
    
    let currentSection = null;
    let charPosition = 0;
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i]; // Preserve original
        const trimmedLine = line.trim();
        const nextLine = i < lines.length - 1 ? lines[i + 1].trim() : '';
        const lineStartPos = charPosition;
        const lineEndPos = charPosition + line.length;
        
        // Handle empty lines - preserve as spacing
        if (trimmedLine.length === 0) {
            if (i > 0 && i < lines.length - 1) {
                doc.moveDown(0.3);
            }
            charPosition = lineEndPos + 1;
            continue;
        }
        
        // Detect section headers (use trimmed line)
        const isSectionHeader = (
            trimmedLine === trimmedLine.toUpperCase() && trimmedLine.length < 50 && trimmedLine.length > 2 ||
            trimmedLine.endsWith(':') && trimmedLine.length < 50 ||
            /^(PROFESSIONAL|EXPERIENCE|WORK|EDUCATION|SKILLS|SUMMARY|OBJECTIVE|CONTACT|PROJECTS|CERTIFICATIONS|AWARDS|LANGUAGES|TECHNICAL|SUGGESTED)/i.test(trimmedLine)
        );
        
        // Check if this line is part of an AI edit
        const isAiEdited = isAiEdit(lineStartPos, aiEdits) || isAiEdit(lineEndPos, aiEdits);
        
        if (isSectionHeader) {
            // Add spacing before new section
            if (currentSection !== null) {
                doc.moveDown(1);
            }
            
            // Section header with background color
            const headerText = trimmedLine.replace(':', '').trim();
            const headerY = doc.y;
            
            // Draw background rectangle for section header
            doc.rect(50, headerY - 5, 500, 25)
               .fillColor('#e8f0fe')
               .fill()
               .fillColor('black');
            
            // Section header text
            doc.fontSize(14)
               .font('Helvetica-Bold')
               .fillColor(isAiEdited ? '#ffc107' : '#0a66c2')
               .text(headerText + (isAiEdited ? ' [AI]' : ''), 60, headerY, { width: 480 })
               .fillColor('black')
               .moveDown(0.8);
            
            currentSection = line;
        } else {
            // Detect job entries (use trimmed line)
            const isJobEntry = /^[A-Z][^|]+(\s*\|\s*[^|]+)+/.test(trimmedLine) || 
                             (/^[A-Z][^•]+$/.test(trimmedLine) && trimmedLine.length < 100 && nextLine && /^\d{4}|\w+\s+\d{4}/.test(nextLine));
            
            // Detect dates (use trimmed line)
            const hasDate = /\d{4}|\w+\s+\d{4}|Present|Current/i.test(trimmedLine);
            
            // Check if it's a bullet point (use trimmed line)
            const isBullet = /^[-•*]\s/.test(trimmedLine) || /^\d+\.\s/.test(trimmedLine);
            const cleanLine = trimmedLine.replace(/^[-•*]\s/, '').replace(/^\d+\.\s/, '');
            
            if (isJobEntry || (hasDate && !isBullet && trimmedLine.length < 100)) {
                // Job title or position - bold and slightly larger
                doc.fontSize(13)
                   .font('Helvetica-Bold')
                   .text(cleanLine, { continued: false })
                   .moveDown(0.3);
            } else if (isBullet) {
                // Bullet point with proper indentation
                doc.fontSize(11)
                   .font('Helvetica')
                   .text('•', 60)
                   .text(cleanLine, 75, doc.y - 11, { width: 470 })
                   .moveDown(0.4);
            } else {
                // Check if it's a company name or location
                const isCompanyOrLocation = trimmedLine.length < 80 && (
                    /^(at|@)/i.test(trimmedLine) ||
                    /^[A-Z][a-z]+\s+(Inc|LLC|Ltd|Corp|Company)/i.test(trimmedLine) ||
                    /,\s*[A-Z]{2}\s+\d{5}/.test(trimmedLine)
                );
                
                if (isCompanyOrLocation) {
                    // Company or location - italic
                    doc.fontSize(11)
                       .font('Helvetica-Oblique')
                       .text(cleanLine)
                       .moveDown(0.3);
                } else {
                    // Regular text - highlight if AI-edited
                    doc.fontSize(11)
                       .font(isAiEdited ? 'Helvetica-Oblique' : 'Helvetica')
                       .fillColor(isAiEdited ? '#ffc107' : 'black');
                    
                    if (isAiEdited) {
                        // Draw highlight background
                        const textY = doc.y;
                        doc.save();
                        doc.rect(50, textY - 2, 500, 13)
                           .fillColor('#fff3cd')
                           .fill();
                        doc.restore();
                    }
                    
                    doc.text(cleanLine, { align: 'left', width: 500 })
                       .fillColor('black')
                       .moveDown(0.4);
                }
            }
        }
        
        // Update character position (add 1 for newline)
        charPosition = lineEndPos + 1;
    }
}

// Generated Content endpoints
app.post('/api/generated-content', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        const {
            contentType,
            topic,
            tone,
            content,
            title,
            strategy,
            tips,
            hashtags,
            metadata
        } = req.body;
        
        if (!content || !contentType) {
            return res.status(400).json({ error: 'Content and content type are required' });
        }
        
        const connection = await pool.getConnection();
        try {
            const contentId = uuidv4();
            
            await connection.query(
                `INSERT INTO generated_content (
                    content_id, user_id, content_type, topic, tone, content, title, strategy, tips, hashtags, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    contentId,
                    userId,
                    contentType,
                    topic || null,
                    tone || null,
                    content,
                    title || null,
                    strategy || null,
                    tips ? JSON.stringify(tips) : null,
                    hashtags ? JSON.stringify(hashtags) : null,
                    metadata ? JSON.stringify(metadata) : null
                ]
            );
            
            res.json({ 
                success: true,
                contentId: contentId 
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Generated Content Save Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Create Stripe checkout session
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const { packageId, userId, currency = 'usd' } = req.body;

        if (!userId) {
            return res.status(400).json({ error: 'User ID required' });
        }

        const pkg = PRICING_PACKAGES[packageId];
        if (!pkg) {
            return res.status(400).json({ error: 'Invalid package' });
        }

        // Validate currency
        if (currency !== 'usd' && currency !== 'inr') {
            return res.status(400).json({ error: 'Invalid currency. Supported: usd, inr' });
        }

        // Get price based on currency
        const price = currency === 'inr' ? pkg.price_inr : pkg.price_usd;
        const currencySymbol = currency === 'inr' ? '₹' : '$';

        // Use backend URL for success/cancel redirects (Chrome extension URLs don't work for Stripe redirects)
        const backendUrl = process.env.BACKEND_URL;
        // Remove chrome-extension:// protocol if present
        const baseUrl = backendUrl.startsWith('chrome-extension://') 
            ? process.env.BACKEND_URL
            : backendUrl;
        
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: currency,
                        product_data: {
                            name: `${pkg.name} Package`,
                            description: `${pkg.tokens.toLocaleString()} tokens`
                        },
                        unit_amount: Math.round(price * (currency === 'inr' ? 100 : 100)) // Convert to smallest currency unit (paise for INR, cents for USD)
                    },
                    quantity: 1
                }
            ],
            mode: 'payment',
            success_url: `${baseUrl}/success?session_id={CHECKOUT_SESSION_ID}&user_id=${userId}&package_id=${packageId}`,
            cancel_url: `${baseUrl}/cancel?user_id=${userId}`,
            metadata: {
                userId,
                packageId: packageId.toString(),
                tokens: pkg.tokens.toString(),
                currency: currency
            }
        });

        res.json({ url: session.url, sessionId: session.id });
    } catch (error) {
        console.error('Stripe Checkout Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Note: Webhook handler is defined earlier (before express.json()) to receive raw body

// Success page (for redirect after payment)
app.get('/success', (req, res) => {
    const { session_id, user_id, package_id } = req.query;
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Payment Successful</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }
                .container {
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    text-align: center;
                    max-width: 500px;
                }
                h1 { color: #4caf50; margin: 0 0 20px 0; }
                p { color: #666; margin: 10px 0; }
                .close-btn {
                    background: #667eea;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 16px;
                    margin-top: 20px;
                }
                .close-btn:hover {
                    background: #5568d3;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>✓ Payment Successful!</h1>
                <p>Your credits have been added to your account.</p>
                <p>You can close this window and return to the extension.</p>
                <button class="close-btn" onclick="window.close()">Close Window</button>
                <script>
                    // Try to notify the extension if it's listening
                    if (window.opener) {
                        try {
                            window.opener.postMessage({
                                type: 'PAYMENT_SUCCESS',
                                sessionId: '${session_id || ''}',
                                userId: '${user_id || ''}',
                                packageId: '${package_id || ''}'
                            }, '*');
                        } catch(e) {
                            console.log('Could not notify extension:', e);
                        }
                    }
                </script>
            </div>
        </body>
        </html>
    `);
});

// Cancel page
app.get('/cancel', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Payment Cancelled</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                }
                .container {
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    text-align: center;
                    max-width: 500px;
                }
                h1 { color: #f5576c; margin: 0 0 20px 0; }
                p { color: #666; margin: 10px 0; }
                .close-btn {
                    background: #f5576c;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 16px;
                    margin-top: 20px;
                }
                .close-btn:hover {
                    background: #e0455a;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Payment Cancelled</h1>
                <p>Your payment was cancelled. No charges were made.</p>
                <button class="close-btn" onclick="window.close()">Close Window</button>
            </div>
        </body>
        </html>
    `);
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Free tokens per user: ${CREDIT_CONFIG.FREE_TOKENS}`);
});

