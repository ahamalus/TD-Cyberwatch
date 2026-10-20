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

Set `CW_SMTP_HOST`, `CW_SMTP_PORT` (587), `CW_SMTP_USERNAME`, `CW_SMTP_PASSWORD`, `CW_SMTP_STARTTLS=true`,
`CW_EMAIL_FROM`. Any transactional provider with SMTP (e.g. a Nigerian-hosted mail server, Amazon SES,
Postmark, Mailgun) works. Publish SPF, DKIM and DMARC for the sender domain. Use **Notifications → Send
test** to confirm delivery; the result appears in Delivery history.
