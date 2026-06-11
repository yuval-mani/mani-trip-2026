# Mani Trip — NYC 2026 (private)

Private family trip page, gated by a **server-side** shared password (PHP).

## Why this changed

The original `index.html` had a client-side "gate" with the password (`MANI2026`)
written into the page. That gave no real protection — anyone could view source,
run `sessionStorage.setItem('mani_auth','ok')`, or just delete the overlay, because
the private content was already shipped to the browser.

This version never sends the private page until the server verifies the password.

## Layout

```
public/index.php        ← the only web-facing file: login + server-side auth
private/content.php      ← the real page; refuses direct access (guard + outside web root)
private/config.php       ← password resolution + throttle settings
private/.env.example     ← copy to .env, or use RunCloud env vars instead
index.html               ← ORIGINAL reference only. Do NOT deploy to the web root.
```

## RunCloud deployment

1. **Push these files** to the web app (Git deployment or SFTP).
2. **Set the Public Path** of the web app to `public`.
   RunCloud → Web Application → Settings → *Public Path* = `public`.
   This keeps `private/` unreachable over HTTP.
3. **Set the password.** Either:
   - *Preferred (hash):* generate a hash and add it as a RunCloud **Environment Variable**
     named `MANI_PW_HASH`:
     ```
     php -r "echo password_hash('YOUR_PASSWORD', PASSWORD_DEFAULT), PHP_EOL;"
     ```
   - *Or via .env:* `cp private/.env.example private/.env` and fill `MANI_PW_HASH`
     (or the simpler `MANI_PW=...` plaintext).
   - *Simplest:* set env var `MANI_PW=YOUR_PASSWORD` in RunCloud.
   Env variables win over `.env`.
4. **Make sure `private/` is writable** by the PHP-FPM user (it writes `.throttle.json`).
   RunCloud apps run as the app's system user by default, so this is usually fine.

> If `index.html` ever sits inside the public path, the old insecure page is reachable
> at `/index.html`. Keep it out of `public/` (it currently lives in the repo root, which
> is *not* the public path when Public Path = `public`).

## Notes

- Session cookie is HttpOnly + SameSite=Lax, and `Secure` when served over HTTPS.
- Brute-force throttle: 8 attempts per IP per 10 min (tune in `private/config.php`).
- Logout: `/?logout=1`.
- To change the password later, just update `MANI_PW_HASH` / `MANI_PW` — no code edits.
