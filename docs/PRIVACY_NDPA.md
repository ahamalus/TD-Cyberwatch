# NDPA compliance record (Nigeria Data Protection Act 2023)

**Status:** working document for Trust Data management and your legal adviser. It is not legal advice. The
public notice is at `/privacy` (`frontend/src/pages/public/Privacy.tsx`). Keep both in step.

## Roles
- **Controller:** Trust Data Compliance Ltd, for user accounts, billing, alerts and the audit trail.
- **Processor:** Trust Data, on customers' instructions, for website files and hosting metadata. Customer
  contracts should include data-processing terms (NDPA s.29): instructions, confidentiality, security,
  sub-processors, assistance with rights requests, breach notice, and deletion or return at the end.

## To confirm or complete (management)
- [ ] **NDPC registration:** decide whether Trust Data is a *data controller or processor of major
  importance* (NDPC thresholds) and, if so, register with the NDPC and pay the fee.
- [ ] **Data Protection Officer:** designate a DPO (NDPA s.32), publish their contact, and replace the
  generic contact address on `/privacy` if needed.
- [ ] **Registered address:** add the company's registered address to `/privacy`.
- [ ] **Customer terms:** add the data-processing terms to customer contracts and terms of service.
- [ ] **Provider terms:** check each sub-processor's data-processing terms and transfer safeguards
  (Cloudflare, Zoho, Paystack, Meta), and where Zoho stores your organisation's mail.
- [ ] **Annual audit:** if the NDPC requires it for your category, arrange the annual compliance audit
  through a licensed DPCO.
- [ ] **DPIA:** do a data protection impact assessment for the monitoring service. It reads customers'
  website files, which can contain personal data. Mitigations already in place are listed under Security
  below.

## Records of processing
| Activity | Data subjects | Personal data | Purpose | Lawful basis | Retention | Recipients |
|---|---|---|---|---|---|---|
| User accounts | Customer staff, Trust Data staff | Name, email, phone (optional), organisation, role, preferences | Provide the service | Contract | While the account is active; anonymised on request | Zoho (email) |
| Sign-in security | Users | IP address, browser, time, outcome; sessions | Security, fraud prevention | Legitimate interest | 365 days (`CW_LOGIN_HISTORY_DAYS`); ended sessions 30 days | none |
| Audit trail | Users, staff | User id, actions, IP, browser | Accountability, investigations | Legal obligation / legitimate interest | Long-term (append-only); random id only after anonymisation | none |
| Alerts | Users and alert recipients | Email, WhatsApp number, alert content | Security notifications | Contract; consent for WhatsApp | Plan retention (≥30 days) | Zoho, Meta (WhatsApp) |
| Billing | Payers | Name, email, amounts, Paystack references, card brand and last 4 digits | Payments, refunds, tax | Contract; legal obligation | As tax law requires | Paystack |
| Website monitoring (as processor) | People whose data is in customers' website files | File paths, hashes, sizes; excerpts of code matching a malware rule (≤160 characters) | Integrity and malware monitoring | Customer instructions | Plan retention; deleted with the website | none (ClamAV runs locally) |
| Support | Customer staff | Ticket messages | Support | Contract | While the account is active | none |
| Backups | All of the above | Encrypted database and storage | Recovery | Legitimate interest | 30 days on the server, 60 days off-site | none (encrypted; key held off-server) |

## Data-subject requests
- **Access and portability:** users download their own data under Account security → *Download my data*
  (JSON; audited as `user.data_exported`).
- **Correction:** users edit their profile themselves; staff can correct other data.
- **Erasure:** after verifying the request, run
  `docker compose exec api python -m app.cli anonymise-user EMAIL "request reference"`. This de-identifies
  the account and removes sign-in history, sessions and alert recipients. It refuses if the person is the
  only owner of an organisation that has other members, and is audited as `user.anonymised`. Audit and
  billing records are kept with the random id only.
- **Timeline:** respond within 30 days. Record each request (date, identity check, outcome) in the support
  system.

## Security measures (NDPA s.39)
- **Encryption:** TLS in transit; hosting credentials encrypted (AES-GCM) with keys outside the database;
  backups encrypted with age, and the private key is kept off-server.
- **Tenant isolation:** row-level security enforced through a restricted database login (see SECURITY.md).
- **Staff access:** MFA is mandatory for staff and can be required for customer organisations; staff
  access to customer data only through time-limited grants the customer approves, all audited.
- **Audit trail:** tamper-evident hash chain with off-server anchors.
- **Website content:** read-only access to customer hosting; only fingerprints are stored, plus short
  evidence excerpts.

## Breach response
1. **Within 72 hours** of becoming aware of a breach likely to risk individuals' rights: notify the NDPC
   (NDPA s.40), with the nature of the breach, the categories and numbers affected, likely consequences, the
   measures taken, and the DPO contact.
2. **Without undue delay:** inform affected individuals where the risk is high. Customers (as controllers)
   are informed so they can meet their own duties.
3. **Evidence:** the audit trail, incident evidence and backups support the investigation. Keep a breach
   register.
