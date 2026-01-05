# LinkedIn Sales Copilot Backend

Backend API server for the LinkedIn Sales Copilot Chrome Extension.

## Prerequisites

- Node.js (v14 or higher)
- MySQL (v5.7 or higher, or MariaDB 10.3+)

## Setup

1. Install dependencies:
```bash
npm install
```

2. Set up MySQL database:
```bash
# Create database and tables
mysql -u root -p < database.sql

# Or manually:
mysql -u root -p
CREATE DATABASE linkedin_sales_copilot;
USE linkedin_sales_copilot;
SOURCE database.sql;
```

3. Create `.env` file from `.env.example`:
```bash
cp .env.example .env
```

4. Configure your environment variables:
- `STRIPE_SECRET_KEY`: Your Stripe secret key
- `STRIPE_PUBLISHABLE_KEY`: Your Stripe publishable key
- `STRIPE_WEBHOOK_SECRET`: Your Stripe webhook secret
- `OPENAI_API_KEY`: Your OpenAI API key (for credit-based calls)
- `FREE_TOKENS`: Initial free tokens per user (default: 10000)
- `DB_HOST`: MySQL host (default: localhost)
- `DB_PORT`: MySQL port (default: 3306)
- `DB_USER`: MySQL username
- `DB_PASSWORD`: MySQL password
- `DB_NAME`: Database name (default: linkedin_sales_copilot)

5. Run the server:
```bash
npm start
# or for development
npm run dev
```

## API Endpoints

- `GET /api/credits` - Get user's credit balance
- `GET /api/packages` - Get pricing packages
- `POST /api/openai-proxy` - Proxy OpenAI API calls with credit tracking
- `POST /api/create-checkout-session` - Create Stripe checkout session
- `POST /api/webhook` - Stripe webhook handler

## Stripe Webhook Setup

1. Install Stripe CLI: https://stripe.com/docs/stripe-cli
2. Forward webhooks to local server:
```bash
stripe listen --forward-to localhost:3000/api/webhook
```

