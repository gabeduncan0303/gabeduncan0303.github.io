# Private Gallery (GitHub Pages + Supabase)

This is a static React site designed to be hosted on GitHub Pages. It uses Supabase for:
- User accounts (Auth)
- Private media storage (Storage bucket)
- Media metadata (Postgres table with RLS)

## 1) Create Supabase project
Create a project in Supabase, then copy:
- Project URL
- Anon public key

## 2) Create a private Storage bucket
Name it `private-media` (or any name you set in `VITE_SUPABASE_BUCKET`).
Set bucket visibility to **private**.

## 3) Create the `media` table
Run this in Supabase SQL editor:

```sql
create table if not exists public.media (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  storage_path text not null,
  mime_type text not null,
  original_name text not null,
  size_bytes bigint not null,
  created_at timestamptz not null default now()
);

alter table public.media enable row level security;

create policy "media_select_own"
on public.media for select
using (auth.uid() = owner_id);

create policy "media_insert_own"
on public.media for insert
with check (auth.uid() = owner_id);

create policy "media_delete_own"
on public.media for delete
using (auth.uid() = owner_id);
```

## 4) Storage policies (bucket: private-media)
Storage uses `storage.objects`. Create policies so users can manage files under their own folder: `${userId}/...`

```sql
create policy "storage_read_own"
on storage.objects for select
using (
  bucket_id = 'private-media'
  and (auth.uid()::text = (storage.foldername(name))[1])
);

create policy "storage_insert_own"
on storage.objects for insert
with check (
  bucket_id = 'private-media'
  and (auth.uid()::text = (storage.foldername(name))[1])
);

create policy "storage_delete_own"
on storage.objects for delete
using (
  bucket_id = 'private-media'
  and (auth.uid()::text = (storage.foldername(name))[1])
);
```

If your bucket name is different, replace `'private-media'`.

## 5) Configure environment variables
Create `.env` in the project root:

```
VITE_SUPABASE_URL=...
VITE_SUPABASE_ANON_KEY=...
VITE_SUPABASE_BUCKET=private-media
```

## 6) Run locally
```bash
npm install
npm run dev
```

## 7) Deploy to GitHub Pages
Two common approaches:

### A) Deploy from your machine
1. Install dependencies
2. Run:
```bash
npm run deploy
```
This pushes `dist/` to a `gh-pages` branch.

In your repo settings:
- Pages source: `gh-pages` branch / root

### B) GitHub Actions (recommended)
Use a workflow that runs `npm ci && npm run build` and publishes `dist`.
If you want that, tell me and I’ll provide the workflow file.

## Notes
- This app uses a HashRouter so deep links work on GitHub Pages.
- Media is served via short-lived signed URLs.
