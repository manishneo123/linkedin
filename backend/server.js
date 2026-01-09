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

