# LinkedIn Sales Copilot – Backend

Backend API server for **[AI Copilot for LinkedIn](https://chromewebstore.google.com/detail/ai-copilot-for-linkedin/khgklonoehpkpklolblfabajepgpgbic?hl=en&authuser=0)**, the Chrome extension for sales outreach, warm intros from connections, content creation, comment suggestions, and job applications on LinkedIn.

---

## What this project is

This repo is the **backend** for the AI Copilot for LinkedIn ecosystem:

- **Chrome extension (frontend):** [AI Copilot for LinkedIn – Chrome Web Store](https://chromewebstore.google.com/detail/ai-copilot-for-linkedin/khgklonoehpkpklolblfabajepgpgbic?hl=en&authuser=0) — install the extension from here.
- **Chrome extension source code:** [linkedin-chrome-plugin](https://github.com/YOUR_ORG/linkedin-chrome-plugin) — open-source repo for the extension (popup, content scripts, UI).

The extension can run **without this backend** if users supply their own OpenAI API key. When the backend is used, it provides:

- **Credits and billing** — Free tokens for new users, purchase additional credits, Stripe payments.
- **API proxy** — OpenAI requests go through this server; credits are deducted per use.
- **Persistence** — Store analyses (prospects, content, job analyses, post-comment suggestions) and user/transaction data in MySQL.

**Relevant details:**

- **Stack:** Node.js, Express, MySQL, Stripe, OpenAI.
- **Auth:** API key per user (generated via extension); requests use `x-api-key` (or similar).
- **Main capabilities:** Auth/key generation, credits balance, OpenAI proxy with credit tracking, Stripe checkout and webhooks, prospect/analysis/content/job and post-comment-suggestion storage and retrieval.

---

## Chrome Web Store & extension repo

| | Link |
|--|------|
| **Install extension** | [Chrome Web Store – AI Copilot for LinkedIn](https://chromewebstore.google.com/detail/ai-copilot-for-linkedin/khgklonoehpkpklolblfabajepgpgbic?hl=en&authuser=0) |
| **Extension source (GitHub)** | [linkedin-chrome-plugin](https://github.com/YOUR_ORG/linkedin-chrome-plugin) |

Replace `YOUR_ORG` with your GitHub org or username.

---

## Prerequisites

- Node.js (v14 or higher)
- MySQL (v5.7 or higher, or MariaDB 10.3+)
- (Optional) Stripe account for payments
- OpenAI API key (for credit-based AI calls)

---

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
- `STRIPE_WEBHOOK_SECRET`: Your Stripe webhook secret
- `OPENAI_API_KEY`: Your OpenAI API key (for credit-based calls)
- `FREE_TOKENS`: Initial free tokens per user (default: 10000)
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`: MySQL connection
- `BACKEND_URL`: Public URL of this backend (for CORS / extension config)

5. Run the server:
```bash
npm start
# or for development
npm run dev
```

---

## API endpoints (overview)

- **Auth / credits:** `GET /api/credits`, `POST /api/auth/generate-key`
- **OpenAI proxy:** `POST /api/openai-proxy` — proxy OpenAI with credit tracking
- **Post comment suggestion:** `POST /api/post-comment-suggestion` — multi-post analysis and suggested comments
- **Connections (warm intro list):** `POST /api/connections-extract` — extract connection entries from listing page text via AI (when DOM scraping fails); `POST /api/connections-score` — score a list of connections (name, headline, location, url) against seller profile and return Buyer/Influencer/Evangelist with relevance scores
- **Prospects / analyses:** `POST /api/prospects`, `POST /api/analyses`, etc.
- **Content / job:** `POST /api/content-analyses`, `POST /api/job-analyses`, and related GET endpoints
- **Payments:** `GET /api/packages`, `POST /api/create-checkout-session`, `POST /api/webhook` (Stripe)

See `server.js` and the [linkedin-chrome-plugin](https://github.com/YOUR_ORG/linkedin-chrome-plugin) repo for full request/response shapes.

---

## Stripe webhook setup

1. Install [Stripe CLI](https://stripe.com/docs/stripe-cli).
2. Forward webhooks to your local server:
```bash
stripe listen --forward-to localhost:3000/api/webhook
```
3. In production, set the webhook URL in the Stripe dashboard (e.g. `https://your-domain.com/api/webhook`, event: `checkout.session.completed`).

---

## Extension configuration

In the **Chrome extension** ([source](https://github.com/YOUR_ORG/linkedin-chrome-plugin)), set `BACKEND_URL` in `popup/popup.js` to this backend’s URL (e.g. `http://localhost:3000` or your production URL). Users can also skip the backend and use **Settings → Use Backend Credits off** and their own OpenAI API key.

---

## Related docs

- **Revenue model (credits, Stripe, API key vs backend):** [README_BACKEND.md](../README_BACKEND.md) in the repo root.
- **Payments / Stripe:** [README_PAYMENTS.md](./README_PAYMENTS.md) in this directory (if present).
