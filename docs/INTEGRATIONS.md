# Paystack, WhatsApp Cloud API and email configuration

All credentials are environment secrets (`.env`, mode 600). They are never shown in the UI or logs.
Without configuration, CyberWatch reports the channel as **unconfigured** — it never pretends a message
was sent or a payment succeeded.

## Paystack

1. Create the business in the Paystack dashboard; use **test** keys in staging.
2. Set `CW_PAYSTACK_SECRET_KEY=sk_test_...` (staging) or `sk_live_...` (production only).
3. Webhook URL: `https://<your-host>/api/v1/webhooks/paystack`. Paystack signs requests with
   HMAC-SHA512 of the raw body using the secret key (`x-paystack-signature`); invalid signatures get 401.
4. Callback: checkout returns customers to `/app/<tenant>/billing?reference=...`; the page asks the API to
   verify the transaction. **Entitlements change only after server-side verification**
   (`GET /transaction/verify/:reference`) with matching reference, amount and currency.

Flow implemented: plan selection → server-side price from `plans` → `POST /transaction/initialize` →
hosted checkout → verify (callback and/or `charge.success` webhook, deduplicated) → subscription activated →
reusable authorization stored encrypted → renewal by the platform with
`POST /transaction/charge_authorization` (re-verified) → on failure: grace period
(`CW_GRACE_PERIOD_DAYS`), one retry per day, owner/billing emails → expiry restricts service but keeps data.

**Verify against current Paystack documentation before going live** (the build environment could not
open Paystack's docs): endpoint paths above, `charge.success` payload fields used (`id`, `reference`),
and the `authorization.reusable` flag. Paystack's own subscription product is not used, so Paystack does
not retry failed renewals for us — CyberWatch handles retries and reminders.

Refunds and disputes: payments can be marked `reversed/refunded` through the database by a billing
administrator today; an in-app refund workflow is not yet implemented (BUILD_STATUS.md).

Reconciliation: Admin → Payments shows verification state; "Re-verify" re-queries Paystack.

## WhatsApp Business Platform (Cloud API)

1. In Meta Business Manager create a WhatsApp Business Account, add and verify the sender phone number,
   and generate a **system-user permanent access token** with `whatsapp_business_messaging`.
2. Set `CW_WHATSAPP_PHONE_NUMBER_ID`, `CW_WHATSAPP_ACCESS_TOKEN`, optionally `CW_WHATSAPP_API_VERSION`.
3. Create and get approval for these message templates (category *Utility*, language `en`):
   - `cyberwatch_incident_alert` — body with 4 parameters: `{{1}}` severity, `{{2}}` title,
     `{{3}}` website, `{{4}}` incident reference. Example: *"CyberWatch {{1}} alert: {{2}} on {{3}} ({{4}}). Sign in to review."*
   - `cyberwatch_test_message` — no parameters.
4. Messages are sent with `POST https://graph.facebook.com/<version>/<phone_number_id>/messages`
   (`type: template`). Recipients must have opted in (consent is recorded per recipient/user).
   Business-initiated messages outside the 24-hour window must use approved templates — CyberWatch
   only sends templates.
5. Delivery receipts via the Meta webhook are not yet processed (status = accepted by API).

Failures: HTTP 429/5xx retry with backoff (max 5 attempts); 4xx are permanent; optional email fallback.

## Email (SMTP)

Settings: `CW_SMTP_HOST`, `CW_SMTP_PORT`, `CW_SMTP_USERNAME`, `CW_SMTP_PASSWORD`, `CW_SMTP_STARTTLS` and `CW_EMAIL_FROM`.
- **Port 587** uses STARTTLS.
- **Port 465** uses implicit TLS automatically.
- Any provider with authenticated SMTP works (Zoho Mail, Microsoft 365, Amazon SES, Postmark and others).

On a server, set everything with the guided script. It asks for the values, hides the password, keeps a backup of
`.env`, restarts the API and the notification worker, and sends a test email:
```bash
sudo bash /opt/cyberwatch/deploy/scripts/configure-email.sh
```
At any time afterwards:
- `docker compose exec api python -m app.cli send-test-email you@example.com` sends one message and explains any failure.
- `deploy/scripts/healthcheck.sh` shows an `email` line (configured, plus 24-hour sent/failed counts).

### Zoho Mail (company domain)
1. Create a mailbox for system mail, e.g. `alerts@yourdomain`. Zoho only relays mail *from* the signed-in mailbox or
   its aliases, so `CW_EMAIL_FROM` uses the same address. The script does this automatically.
2. If the mailbox uses two-factor sign-in, create an **application-specific password**:
   Zoho Accounts → Security → App Passwords.
3. Make sure SMTP access is allowed for the mailbox (Zoho Mail → Settings → Mail Accounts → IMAP/POP/SMTP).
4. Choose the server for your Zoho data centre, which matches your MX records:
   - `mx.zoho.com` → `smtppro.zoho.com`
   - `mx.zoho.eu` → `smtppro.zoho.eu`
   - `mx.zoho.in` → `smtppro.zoho.in`
5. Run `configure-email.sh` and accept the defaults (`smtppro.zoho.com`, port 587).

### Deliverability (keep alerts out of spam)
- **SPF:** the TXT record on the root domain must include Zoho, e.g. `v=spf1 include:zoho.com ~all`.
  If it already lists other senders (the web host's IP, other services), add `include:zoho.com` to it rather
  than replacing it.
- **DKIM:** in Zoho Mail Admin → Domains → *your domain* → Email Configuration → DKIM, add a selector (e.g. `zmail`).
  Publish the TXT record Zoho shows (`zmail._domainkey`), then click **Verify**. A `default._domainkey` record created by
  cPanel does not sign Zoho's mail.
- **DMARC:** start with `v=DMARC1; p=none; rua=mailto:you@yourdomain`. Once SPF and DKIM pass, move to
  `p=quarantine`.
- Every message carries `Date` and `Message-ID` headers, which receiving servers expect.

Also use **Notifications → Send test** in the customer portal to confirm delivery to a recipient; the result
appears in Delivery history.
