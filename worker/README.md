# Private Gallery API (Cloudflare Workers + D1 + R2)

This worker provides:
- Register/Login (username+password only)
- Upload image/video
- List media
- Download media (authorized)
- Delete media

Auth tokens are returned to the frontend and must be sent as:
`Authorization: Bearer <token>`

No cookies required. No localStorage required (frontend keeps token only in memory).

## Prereqs
- Cloudflare account
- Wrangler installed: `npm i -g wrangler`

## Setup
1) Create D1 + R2
- `wrangler d1 create private_gallery`
- `wrangler r2 bucket create private-gallery-media`

2) Put the D1 database_id into `wrangler.toml`.

3) Apply schema:
- `wrangler d1 execute private_gallery --file=./schema.sql`

4) Set FRONTEND_ORIGIN in `wrangler.toml` to your GitHub Pages origin.

5) Deploy:
- `wrangler deploy`

Your API base will be something like:
`https://private-gallery-api.<your-subdomain>.workers.dev`

## Endpoints
- POST /api/register {username,password}
- POST /api/login {username,password} -> {token, username}
- POST /api/logout (Bearer token)
- GET  /api/media (Bearer token)
- POST /api/media (Bearer token, multipart field "file")
- GET  /api/media/:id/file (Bearer token)
- DELETE /api/media/:id (Bearer token)
