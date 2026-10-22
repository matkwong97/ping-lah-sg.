# Ping Lah! SG v5 — Cloudflare Pages + D1 (NO R2)

## Deployment from zero
1. Create a **new GitHub repository**, e.g. `ping-lah-sg`, and upload all files and directories from this ZIP at repository root. Do not upload only `public`.
2. Cloudflare Dashboard → Storage & databases → D1 SQL Database → Create database `ping-lah-db`. Open SQL Console and execute the **entire `schema.sql`** file.
3. Cloudflare → Workers & Pages → Create → **Pages** → Connect to Git → choose repository. Framework preset `None`, build command blank, output directory `public`, production branch `main`. Deploy.
4. In the Pages project → Settings → Bindings → Add **D1 database** binding: variable `DB`, database `ping-lah-db`. No R2 binding is needed. Redeploy from Deployments or push a new commit.
5. Visit the Pages URL using HTTPS. Register account A, copy the recovery code somewhere safe. In a separate browser/device register B. Share codes, add friends, test pager and voice both ways.
6. On iPhone, use Safari → Share → Add to Home Screen for the installable app experience. Allow microphone permission when prompted.

## How it works
- Friendships, account tokens, recovery hashes, pager messages and small voice files are stored in D1.
- Voice recordings have a 12-second maximum in the UI and a strict 380KB upload limit. The voice bytes are base64 encoded in D1 (larger storage overhead than R2). Voice messages expire after 24 hours; pages after 7 days. Expired data is filtered immediately and cleaned when the inbox endpoint is requested.
- One-time recovery code is shown after registration; recovery rotates token and recovery code. **Without the recovery code, clearing browser data loses the account.** No email login or password reset exists.
- Basic D1-backed rate limiting: registration and recovery per IP, message/upload per account. Not a substitute for Cloudflare WAF and abuse controls.
- The retro pager has hardware controls, a green LCD, and categorized outgoing pages.

## Honest limitations
- **Background push notifications are not yet implemented.** A service worker is registered for future support, but the app currently polls every 15 seconds while open. Do not claim background push is working. Real push needs VAPID credentials, subscription management and a push delivery implementation.
- D1 voice blobs are a low-setup-cost solution for light testing only. D1 storage and write limits apply, and base64 increases size about 33%. For scale, switch to R2.
- Physical deletion occurs on inbox activity, not precisely at the expiry moment. For a firm 24-hour data deletion guarantee, add a scheduled cleanup Worker.
- Audio support depends on MediaRecorder and browser codecs. Test with iOS Safari, Chrome and Android; recordings might be shorter than the cap when the compressed size limit is reached.
- No end-to-end encryption, verified identity, moderation or account abuse reports. Do not position this as a secure/private messenger.
V5 - deployment test 
© Matthew Kwong 2026.
