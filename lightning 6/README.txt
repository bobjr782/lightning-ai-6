lightning on Cloudflare Pages
=============================
Folder layout
  public/                 the site (index.html, _headers, _redirects, _routes.json, LICENSES.txt)
  functions/api/chat.js   secure chat proxy: OpenRouter, Groq, Google Gemini (keys stay on the server)
  functions/api/image.js  image generation (Workers AI, Hugging Face, Together, Pollinations)
  functions/api/config.js tells the app what the server can do
  functions/api/publish.js, artifacts.js, functions/a/[id].js   Publish artifact + Online artifacts
  LICENSES.txt            license + third-party notices

Deploy
  1. Put this folder in a GitHub repo.
  2. Cloudflare dashboard > Workers & Pages > Create > Pages > Connect to Git.
     Framework preset: None.  Build command: (empty).  Build output directory: public
     The "functions" folder is picked up automatically.
  3. Project > Settings > Variables and Secrets (Production): add as SECRETS
        OPENROUTER_API_KEY, GROQ_API_KEY, GOOGLE_API_KEY   (add any you have; one is enough)
     Optional: HF_TOKEN, TOGETHER_API_KEY, RATE_LIMIT_PER_MIN
  4. Project > Settings > Bindings:
        KV namespace  -> variable name  ARTIFACTS   (needed for Publish artifact / Online artifacts)
        Workers AI    -> variable name  AI          (optional: free, fast image generation)
  5. Redeploy (Deployments > Retry) so the new settings apply.

Google Gemini as a backup
  Get a free key at https://aistudio.google.com/apikey and add it as GOOGLE_API_KEY (or let each
  visitor use "Sign in with Google" in the sidebar). When OpenRouter or Groq answers "rate
  limited", lightning now switches to the next provider automatically: OpenRouter -> Groq -> Google.

Notes
  - Everyone shares your server keys, so keep RATE_LIMIT_PER_MIN modest. The built-in limiter is
    per server instance; for a hard cap add a Cloudflare Rate Limiting rule on /api/*.
  - Chats, projects and images are saved in each visitor's own browser, not on the server.
  - Published artifacts live in Workers KV. KV is eventually consistent, so a new artifact can take
    up to a minute to appear on the Online artifacts page for visitors in other regions.
  - Anyone can publish, so review the Online artifacts page now and then. Published pages run in a
    locked-down sandbox and cannot read your site's data.
  - Local testing: npx wrangler pages dev public --kv ARTIFACTS   (copy .dev.vars.example to .dev.vars)
