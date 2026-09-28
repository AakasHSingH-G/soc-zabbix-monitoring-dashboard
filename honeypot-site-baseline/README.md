# Northstar Relay Honeypot Site

A self-contained static decoy website designed to resemble a realistic, full-size
internal e-commerce and operations environment — 24 catalog products across 4
categories, plus a 9-page internal operations workspace (users, orders,
invoices, employees, vendors, support tickets, settings). It has **no backend, no database, and
makes no outbound network calls** — every "vulnerability" below is cosmetic
bait meant to hold an attacker's attention and generate rich access-log /
IDS/IPS signal on the honeypot listener that serves this directory, without
exposing anything real.

Serve this directory as-is from your existing Honey Port / decoy web root. It
does not need, and must not be given, any real database, real credentials, or
outbound connectivity.

## Pages

- `index.html` — Storefront with catalog, search, category filters, client-side cart.
- `product.html?id=N` — Product detail page. `id` is an unvalidated, sequential
  integer (1-6) and the page renders "internal" fields (cost, supplier,
  internal note) next to the public ones — bait for parameter tampering / IDOR
  probing and automated scanners that enumerate `id`.
- `payment.html` — Simulated checkout: QR wallet switching, order summary, fake
  card form. Nothing is transmitted; card fields are never read into any
  network request.
- `admin-login.html` — Fake staff login.
  - A small set of legacy-looking default credentials (see `decoy-files/`,
    `.env`, `config.php.bak`) "succeed" and forward to `dashboard.html` — bait
    for credential-stuffing / default-password attempts.
  - Input that looks like a SQL injection payload (`'`, `--`, `OR 1=1`, `UNION
    SELECT`, …) trips a fake backend error message referencing a fictitious
    `relay_auth.accounts` table — bait for automated SQLi scanners, with zero
    real query execution behind it.
- `dashboard.html` — Fake internal ops dashboard (metrics, incidents, audit feed).
- `dashboard-users.html` — Fake user roster. Accepts `?user_id=N` as a direct
  link and echoes back whichever id was requested — IDOR bait.
- `dashboard-orders.html` — Fake order list. Accepts `?order_id=...` the same way.
- `dashboard-invoices.html` — Fake finance invoices (customer + supplier). Accepts `?invoice_id=...`.
- `dashboard-employees.html` — Fake employee directory with extensions and access levels.
  Accepts `?emp_id=N`.
- `dashboard-vendors.html` — Fake vendor/procurement portal, including a table of
  unmasked "supplier API keys" (`decoy-key-...`, non-functional) — high-value bait
  for anyone scraping the dashboard for credentials.
- `dashboard-tickets.html` — Fake customer support ticket queue. Accepts `?ticket_id=...`.
- `dashboard-settings.html` — Fake system settings page: unmasked integration secrets
  (event collector, Telegram bot, payment relay, GeoIP, backup storage — all
  `decoy-...` placeholders), a list of default admin usernames, and build/deploy
  metadata. This is the single richest bait page in the site.
- `admin/` — Empty bait directory that redirects to the login page (probed by
  most admin-panel scanners).
- `api/products.json`, `api/users.json`, `api/orders.json`, `api/employees.json`,
  `api/invoices.json`, `api/vendors.json`, `api/tickets.json` — Static JSON that
  mirrors what a real internal API would return, for tools that enumerate
  `/api/*` paths.

## Bait / recon files

These exist purely to be *found and downloaded* by scanners and manual
testers; none contain real secrets or connect to anything:

- `.env`, `config.php.bak`, `decoy-files/.env`, `decoy-files/config.php` —
  synthetic environment/config files with placeholder, non-functional values.
- `dashboard-settings.html` and `dashboard-vendors.html` — unmasked API keys /
  integration secrets rendered directly on the page (all `decoy-...` placeholders).
- `backup.sql` — synthetic SQL export with fabricated rows only.
- `.git/config`, `.git/HEAD` — minimal fake git metadata (no working tree, no
  real history) for tools that probe `/.git/config`.
- `robots.txt` — deliberately `Disallow`s the bait paths above, which in
  practice advertises them to anything that reads `robots.txt` looking for
  "protected" areas.
- `sitemap.xml` — lists every page above, including the bait ones, for
  crawlers and scanners that pull the sitemap instead of link-following.

## Supporting files

- `style.css` — Shared responsive styles for every page.
- `decoy-files/` — Additional harmless synthetic files (`.env`, `config.php`,
  deployment notes).

## Local preview

```sh
cd honeypot-site
python3 -m http.server 8765
```

Open `http://localhost:8765/`.

## Behavior / safety notes

- Fully static: no server-side code, no database, no session validation.
  "Successful" admin login and all dashboard pages are reachable directly by
  URL with no real access control — this is intentional decoy behavior, not a
  real authorization bypass on a real system.
- Cart state lives only in browser `localStorage`.
- No page makes a request to any third-party or external host. All `fetch`-able
  resources (`api/*.json`) are same-origin static files.
- All names, emails, credentials, tokens, and financial data are fabricated.
  Nothing here is a real account, a real payment path, or real PII.
- Per the isolation spec this site was built against, this directory should be
  served only from the isolated decoy module/port, and any interaction with it
  should flow into the existing security pipeline via the `decoy-event-adapter`
  — this static site itself has no knowledge of, and makes no calls to, that
  pipeline; log/event capture happens at the web-server/listener layer in
  front of it.
