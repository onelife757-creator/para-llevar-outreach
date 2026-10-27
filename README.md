# PARA LLEVAR AI Outreach

Black-and-white editorial CRM for PARA LLEVAR, hosted on a separate Cloudflare Pages project.

## Sales catalog
- PARA LLEVAR magazine: $14 wholesale, $26 retail
- Check Please: $12 wholesale, $24 retail
- Advertising: full page $800, two full-page ads $1,600, two-page spread $2,000
- Additional placement: contributor thank-you $200, editor's-letter integration $400

## Secure Cloudflare setup — required before use

A new backend is committed at `functions/api/[[path]].js`. The existing Pages deployment needs a **separate** Cloudflare D1 database binding and setup secret:

1. In **Para Llevar's Cloudflare account**, go to **Storage & databases → D1 SQL Database → Create database**. Name it `para-llevar-outreach-db`.
2. Go to **Workers & Pages → para-llevar-outreach → Settings → Bindings**. Add a **D1 database** binding with variable name **`PL_DB`** and select the new database. Apply it to production.
3. Under **Settings → Variables and Secrets**, add a secret named **`PL_SETUP_KEY`**. Use a unique long random password, not a team PIN.
4. Redeploy the latest `main` commit, because bindings usually require deployment to become active.
5. Open `https://para-llevar-outreach.pages.dev`. Enter the owner's name, a 4–8 digit PIN, and the setup key **once**. Subsequent visits use name/PIN. Never share the setup key with callers.
6. Sign in as the owner. Open Team and create individual caller accounts.

D1 tables are created automatically when the first API request runs. `schema.sql` is provided for documentation / manual initialization; running the SQL manually is optional. Do not create a second database in the Creative Strategies account.

**Security:** Sessions use an HTTP-only Secure SameSite cookie, PINs are PBKDF2 hashed, and all lead read/write operations check role and assignment. Callers only see their assigned leads. Do not share passwords or enter secret values into chat.

## Included now
- Dashboard and distinct Wholesale / Advertising / Retail queues
- Shared D1 lead storage, owner/caller login and owner-only team creation
- Assignment isolation for staff, server audit events
- Editable sales email templates
- Manual send logging and three-day follow-up due dates

## Not yet built
- Live email delivery, Gmail reply sync, AI prospecting, automatic follow-up sends
- Production-grade authentication hardening: rate-limiting for PIN attempts, PIN rotation, account lockout and staff revocation UI
- Thorough end-to-end testing and verified production security review

**Manual send means recordkeeping only.** It never sends an email. Until rate-limiting and production tests are completed, restrict access to trusted staff and avoid storing sensitive customer details.

## Current project
GitHub: `onelife757-creator/para-llevar-outreach`
Cloudflare: `https://para-llevar-outreach.pages.dev`
