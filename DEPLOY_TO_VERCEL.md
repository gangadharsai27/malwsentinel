# Deploying MalwSentinel to Vercel

Your project is completely configured and ready for 1-click deployment on **Vercel**!

---

## Project Structure on Vercel

```
csproject/
├── api/
│   └── index.py            # Vercel Serverless Function entrypoint (ASGI)
├── public/
│   ├── index.html          # Global Edge CDN Dashboard UI
│   └── static/
│       ├── style.css       # Glassmorphic Cyber CSS
│       └── app.js          # Interactive JavaScript client
├── server.py               # Starlette backend routes (/api/*)
├── llm_engine.py           # Multi-AI Agent Engine (Kimi, GLM, DeepSeek, Gemini)
├── malware_triage_agent.py # Static analysis tools & containment policy hook
├── vercel.json             # Vercel routing configuration
├── .vercelignore           # Prevents uploading venv, cache, and private keys
└── requirements.txt        # Python dependencies automatically installed by Vercel
```

---

## Option 1: Deploy via GitHub (Recommended & Easiest)

1. **Initialize Git & Push to GitHub**:
   ```bash
   git init
   git add .
   git commit -m "MalwSentinel initial commit ready for Vercel"
   git branch -M main
   git remote add origin https://github.com/<YOUR_USERNAME>/<YOUR_REPO_NAME>.git
   git push -u origin main
   ```

2. **Import into Vercel**:
   - Go to **[https://vercel.com](https://vercel.com)** and log in.
   - Click **"Add New..."** -> **"Project"**.
   - Select your GitHub repository.
   - Leave the **Framework Preset** as *Other* (Vercel automatically detects `vercel.json` and Python).

3. **Configure Environment Variables in Vercel**:
   In the **Environment Variables** section on Vercel, add your API keys:
   - `GEMINI_API_KEY`: *(Optional - for Google Gemini)*
   - `DEEPSEEK_API_KEY`: *(Optional - for DeepSeek)*
   - `TOKENRA_API_KEY`: *(Optional - for Tokenra / Ox Alpha)*

4. **Click "Deploy"**:
   - Vercel will install `requirements.txt`, bundle static assets to its Edge CDN, and deploy your live URL (e.g. `https://your-project.vercel.app`)!

---

## Option 2: Deploy via Vercel CLI

1. **Install Vercel CLI** (if you have Node.js):
   ```bash
   npm install -g vercel
   ```

2. **Deploy directly from terminal**:
   ```bash
   vercel
   ```
   Follow the interactive prompts:
   - *Set up and deploy?* -> `Y`
   - *Which scope?* -> select your account
   - *Link to existing project?* -> `N`
   - *Project name?* -> `malwsentinel`
   - *Directory?* -> `./`
   - *Want to modify settings?* -> `N`

3. **Production Deployment**:
   ```bash
   vercel --prod
   ```

---

## Serverless Considerations Handled

- **Read-Only Filesystem**: Vercel Serverless Functions have a read-only filesystem except for `/tmp`. The backend has been configured to store uploads and temporary files in `/tmp/uploads`.
- **Zero-Latency Static Assets**: All HTML, CSS, and JS files are served directly by Vercel's Global Edge CDN from the `public/` directory without spinning up Python functions for static assets.
- **Dynamic AI Model Selection**: Users can still switch models (**Kimi**, **GLM**, **DeepSeek**, **Gemini**) directly inside the live web UI on Vercel without redeploying.
