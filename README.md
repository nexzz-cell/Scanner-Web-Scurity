# Security and Finding Loopholes — Netlify Edition

## Deploy
1. Extract this ZIP or push its contents to a GitHub repository.
2. In Netlify, choose **Add new site → Import an existing project** and connect the repository.
3. Build settings:
   - Build command: leave empty
   - Publish directory: `public`
   - Functions directory: `netlify/functions`
4. Deploy. Netlify reads `netlify.toml` automatically.
5. Open your deployed site and test only a domain you own or are authorized to assess.

You can also use Netlify CLI locally:
- Install Node.js 18+
- `npm install -g netlify-cli`
- From this folder run `netlify dev`

## Included
- Cyber-neobrutalism responsive frontend
- Netlify Function backend (`/.netlify/functions/scan`)
- Same-origin crawler (up to 12 pages)
- HTTPS and common security-header checks
- Cookie Secure / HttpOnly / SameSite review (where headers expose cookies)
- URL parameter and HTML form inventory
- Manual-review IDOR parameter hints
- Console, summary, findings, JSON export

## Safety and limitations
The function sends GET requests only, stays on the same origin, blocks private/non-public IP addresses, does not follow cross-origin redirects, and never submits forms. It does not brute-force credentials, bypass authentication, inject exploit payloads, or modify server data. IDOR-like parameter names are review hints, not vulnerability confirmation.

This is a serverless passive checker, not a full commercial DAST scanner. Netlify function execution limits and target website behavior can limit crawl depth. For production use, add user authentication, per-user rate limits, logging, and an explicit allowlist of authorized domains before exposing it publicly.
