# AI Copilot for LinkedIn – Backend & API

This repository is the **backend** for [**AI Copilot for LinkedIn**](https://chromewebstore.google.com/detail/ai-copilot-for-linkedin/khgklonoehpkpklolblfabajepgpgbic?hl=en&authuser=0): the Chrome extension that adds AI-powered sales outreach, warm intros from connections, content creation, comment suggestions, and job-application tools on LinkedIn.

---

## What’s in this repo

- **Backend API** (Node.js, Express, MySQL) used when extension users choose “Use Backend Credits”: auth, credits, OpenAI proxy, Stripe payments, and storage for prospects, analyses, content, job data, and post-comment suggestions.
- The extension can also run **without this backend** by using a personal OpenAI API key (see the [Chrome extension repo](https://github.com/manishneo123/linkedin-chrome-plugin)).

---

## Links

| | URL |
|--|-----|
| **Install the extension** | [Chrome Web Store – AI Copilot for LinkedIn](https://chromewebstore.google.com/detail/ai-copilot-for-linkedin/khgklonoehpkpklolblfabajepgpgbic?hl=en&authuser=0) |
| **Chrome extension source** | [linkedin-chrome-plugin](https://github.com/YOUR_ORG/linkedin-chrome-plugin) |

Replace `YOUR_ORG` with your GitHub org or username.

---

## Backend setup and docs

- **[backend/README.md](backend/README.md)** — Project overview, what the backend does, Chrome Web Store and extension repo links, prerequisites, setup, API overview, Stripe webhook, extension config.
- **[README_BACKEND.md](README_BACKEND.md)** — Revenue model: own API key vs backend credits, Stripe, pricing, API endpoints, production deployment.

Quick start:

```bash
cd backend
npm install
# Configure .env (see backend/README.md)
mysql -u root -p < database.sql
npm start
```

---

## License

See the repository license. Use of the extension and backend is subject to OpenAI’s and LinkedIn’s terms of use.
