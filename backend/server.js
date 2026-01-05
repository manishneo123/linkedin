require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
// Use test/sandbox keys for Stripe (change to live keys in production)
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_51LKhEWSIyr7jGq28mBLChX4Q1xcDmffIvHcJXu5ePL6smTIkRUv9wl7hfVbRXnGDPMLmAWTJHcAldbIOVMB4OpgG00IqgNyH1P');
const OpenAI = require('openai');
const mysql = require('mysql2/promise');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());

// MySQL Database Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'linkedin_sales_copilot',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Credit configuration
const CREDIT_CONFIG = {
    FREE_TOKENS: parseInt(process.env.FREE_TOKENS) || 10000,
    TOKEN_COST_PER_1M: {
        input: parseFloat(process.env.TOKEN_COST_PER_1M_INPUT) || 0.15,
        output: parseFloat(process.env.TOKEN_COST_PER_1M_OUTPUT) || 0.60
    }
};

// Pricing packages with USD and INR prices
// Note: INR prices are approximate conversions, adjust based on current exchange rates
const PRICING_PACKAGES = [
    { 
        id: 0, 
        name: 'Starter', 
        tokens: 100000, 
        price_usd: 9.99,
        price_inr: 799  // Approximate: $9.99 * 80 INR/USD
    },
    { 
        id: 1, 
        name: 'Professional', 
        tokens: 500000, 
        price_usd: 39.99,
        price_inr: 3199  // Approximate: $39.99 * 80 INR/USD
    },
    { 
        id: 2, 
        name: 'Enterprise', 
        tokens: 2000000, 
        price_usd: 149.99,
        price_inr: 11999  // Approximate: $149.99 * 80 INR/USD
    }
];

// Initialize user with free tokens
async function initializeUser(userId, userData = {}) {
    try {
        const connection = await pool.getConnection();
        
        // Check if user exists
        const [existing] = await connection.query(
            'SELECT * FROM users WHERE user_id = ?',
            [userId]
        );
        
        if (existing.length === 0) {
            // Create new user with free tokens
            await connection.query(
                'INSERT INTO users (user_id, balance, used, name, linkedin_profile_url) VALUES (?, ?, ?, ?, ?)',
                [
                    userId, 
                    CREDIT_CONFIG.FREE_TOKENS, 
                    0,
                    userData.name || null,
                    userData.linkedinProfileUrl || null
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

// Stripe webhook route must use raw body - define BEFORE json parser
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        // Use test webhook secret for sandbox mode (change to production secret in production)
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || 'whsec_pMPFucMifGYVmyOcuKZCiaKQph3Of3i2');
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

// Get user credits
app.get('/api/credits', async (req, res) => {
    try {
        const userId = req.headers['x-user-id'] || uuidv4();
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

// Get pricing packages
app.get('/api/packages', (req, res) => {
    res.json({ packages: PRICING_PACKAGES });
});

// Update user profile
app.post('/api/user/profile', async (req, res) => {
    try {
        const userId = req.headers['x-user-id'];
        if (!userId) {
            return res.status(400).json({ error: 'User ID required' });
        }
        
        const { name, linkedinProfileUrl } = req.body;
        await initializeUser(userId, { name, linkedinProfileUrl });
        
        res.json({ success: true, message: 'Profile updated' });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Create prospect
app.post('/api/prospects', async (req, res) => {
    try {
        const userId = req.headers['x-user-id'];
        if (!userId) {
            return res.status(400).json({ error: 'User ID required' });
        }
        
        const prospectData = req.body;
        const prospectId = await createOrGetProspect(userId, prospectData);
        
        res.json({ success: true, prospectId });
    } catch (error) {
        console.error('Error creating prospect:', error);
        res.status(500).json({ error: 'Failed to create prospect: ' + error.message });
    }
});

// Update prospect status
app.put('/api/prospects/:prospectId/status', async (req, res) => {
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

// Save analysis results
app.post('/api/analyses', async (req, res) => {
    try {
        const userId = req.headers['x-user-id'];
        if (!userId) {
            return res.status(400).json({ error: 'User ID required' });
        }
        
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

// Get analyses for a user
app.get('/api/analyses', async (req, res) => {
    try {
        const userId = req.headers['x-user-id'];
        if (!userId) {
            return res.status(400).json({ error: 'User ID required' });
        }
        
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

// OpenAI Proxy - handles GPT calls with credit tracking
app.post('/api/openai-proxy', async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        await connection.beginTransaction();
        
        const userId = req.headers['x-user-id'];
        if (!userId) {
            await connection.rollback();
            connection.release();
            return res.status(400).json({ error: 'User ID required' });
        }

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
        const backendUrl = process.env.BACKEND_URL || req.headers.origin || 'http://localhost:3000';
        // Remove chrome-extension:// protocol if present
        const baseUrl = backendUrl.startsWith('chrome-extension://') 
            ? (process.env.BACKEND_URL || 'http://localhost:3000')
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

