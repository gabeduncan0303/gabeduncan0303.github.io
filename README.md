# Private Gallery (GitHub Pages frontend + Cloudflare Worker backend)

This repo is split into:
- `frontend/` static site (deploy to GitHub Pages)
- `worker/` Cloudflare Worker API (auth + uploads + private media)

## 1) Deploy backend (Cloudflare)
1. Install Wrangler: `npm i -g wrangler`
2. In `worker/`:
   - Create D1: `wrangler d1 create private_gallery`
   - Create R2: `wrangler r2 bucket create private-gallery-media`
   - Put the D1 `database_id` into `worker/wrangler.toml`
   - Set `FRONTEND_ORIGIN` to your GitHub Pages origin
   - Apply schema: `wrangler d1 execute private_gallery --file=./schema.sql`
   - Deploy: `wrangler deploy`
3. Note your API base URL:
   `https://private-gallery-api.<your-subdomain>.workers.dev`

## 2) Deploy frontend (GitHub Pages)
1. Edit `frontend/config.js` and set:
   `API_BASE` to your Worker URL
2. Push to a GitHub repo.
3. Enable Pages:
   - Settings -> Pages -> Deploy from branch
   - Select the branch and set the folder to `/frontend`

## Notes
- No localStorage/cookies are used.
- After a page refresh, users must log in again (token is kept only in memory).
- Media is private: all downloads require a valid Bearer token and ownership check.
