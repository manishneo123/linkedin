# LinkedIn Sales Copilot - Revenue Model Implementation

## Overview

This extension now supports two payment modes:
1. **Own API Key Mode** (Backward Compatible): Users can use their own OpenAI API key
2. **Backend Credits Mode**: Users purchase credits and use the backend API proxy

## Backend Setup

### Prerequisites
- Node.js (v14 or higher)
- Stripe account with API keys
- OpenAI API key (for backend credit-based calls)

### Installation

1. Navigate to the backend directory:
```bash
cd backend
```

2. Install dependencies:
```bash
npm install
```

3. Create `.env` file:
```bash
cp .env.example .env
```

4. Configure `.env`:
```env
PORT=3000
NODE_ENV=development

# Stripe Configuration
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
STRIPE_PUBLISHABLE_KEY=pk_test_your_stripe_publishable_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

# OpenAI Configuration (for credit-based calls)
OPENAI_API_KEY=sk-your-openai-api-key

# Credit Configuration
FREE_TOKENS=10000
TOKEN_COST_PER_1M_INPUT=0.15
TOKEN_COST_PER_1M_OUTPUT=0.60
```

5. Start the server:
```bash
npm start
# or for development with auto-reload
npm run dev
```

### Stripe Webhook Setup

For production, you need to set up Stripe webhooks to handle payment completion:

1. Install Stripe CLI: https://stripe.com/docs/stripe-cli
2. Forward webhooks to local server (development):
```bash
stripe listen --forward-to localhost:3000/api/webhook
```

3. In production, configure the webhook endpoint in your Stripe dashboard:
   - URL: `https://your-domain.com/api/webhook`
   - Events: `checkout.session.completed`

## Frontend Configuration

### Backend URL

Update the `BACKEND_URL` in `popup/popup.js`:
```javascript
const BACKEND_URL = 'http://localhost:3000'; // Change to your production URL
```

For production, update to your actual backend URL:
```javascript
const BACKEND_URL = 'https://your-backend-domain.com';
```

## Usage

### For Users

1. **Using Own API Key** (Default):
   - Go to Settings tab
   - Uncheck "Use Backend Credits"
   - Enter your OpenAI API key
   - The extension works as before

2. **Using Backend Credits**:
   - Go to Settings tab
   - Check "Use Backend Credits"
   - View your remaining credits
   - Click "Buy Credits" to purchase more
   - Credits are automatically deducted when using GPT features

### Credit System

- **Free Tokens**: Each new user gets 10,000 free tokens
- **Token Costs**: Based on OpenAI pricing for gpt-4o-mini:
  - Input: $0.15 per 1M tokens
  - Output: $0.60 per 1M tokens
- **Pricing Packages**:
  - Starter: 100,000 tokens - $9.99
  - Professional: 500,000 tokens - $39.99
  - Enterprise: 2,000,000 tokens - $149.99

## API Endpoints

### `GET /api/credits`
Get user's credit balance
- Headers: `x-user-id: <user_id>`
- Response: `{ balance, used, remaining }`

### `GET /api/packages`
Get available pricing packages
- Response: `{ packages: [...] }`

### `POST /api/openai-proxy`
Proxy OpenAI API calls with credit tracking
- Headers: `x-user-id: <user_id>`, `Content-Type: application/json`
- Body: `{ request: <openai_request>, userId: <user_id> }`
- Response: `{ response: <openai_response>, creditsUsed, remaining }`

### `POST /api/create-checkout-session`
Create Stripe checkout session
- Body: `{ packageId: <number>, userId: <string> }`
- Response: `{ url: <checkout_url>, sessionId: <session_id> }`

### `POST /api/webhook`
Stripe webhook handler (for payment completion)

## Backward Compatibility

The extension maintains full backward compatibility:
- If "Use Backend Credits" is unchecked, it works exactly as before with user's own API key
- All existing functionality remains unchanged
- Users can switch between modes at any time

## Production Deployment

1. Deploy backend to a hosting service (Heroku, AWS, etc.)
2. Update `BACKEND_URL` in `popup/popup.js` to production URL
3. Configure environment variables in production
4. Set up Stripe webhook endpoint in Stripe dashboard
5. Test payment flow end-to-end

