# Salesforce — scanner setup

How to create the credentials and environment variables for scanning Salesforce
(`OBJECT_TYPE=SALESFORCE`). The scanner authenticates through a **Connected App** with the
OAuth 2.0 **client-credentials flow**, running as a dedicated read-only **integration user** —
the model Proofpoint/Normalyze documents for DSPM.

## 1. Create the integration user and permission set

1. **Permission set** — *Setup → Users → Permission Sets → New* (e.g. `DSPM Scanner`).
   In the permission set enable:
   - *System Permissions*: **API Enabled**, **Api Only User** (blocks UI login), **View All Data**
     (this also enables its five dependent view permissions)
   - *System Permissions (Content section)*: **Query All Files** — required to see files beyond
     the integration user's own
2. **Integration user** — *Setup → Users → New User*. License: Salesforce (or Integration).
   Assign the permission set (*Permission Set Assignments → Edit Assignments*).

## 2. Create the Connected App

1. *Setup → App Manager → New Connected App*:
   - **Enable OAuth Settings** ✓
   - **Callback URL**: `https://login.salesforce.com/services/oauth2/callback` (required field;
     unused by the client-credentials flow)
   - **Selected OAuth Scopes**: *Manage user data via APIs (api)*
   - **Enable Client Credentials Flow** ✓
2. Save, then *Manage Consumer Details* (email verification) → copy the **Consumer Key** and
   **Consumer Secret**.
3. **Set the run-as user** — *App Manager → your app → Manage → Edit Policies*:
   under *Client Credentials Flow*, set **Run As** = the integration user from section 1.
   Under *OAuth Policies*, set *Permitted Users* to "Admin approved users are pre-authorized"
   and add the permission set to the app's *Manage Profiles / Permission Sets* if prompted.
4. **My Domain** — *Setup → My Domain*: the domain name is the `acme` in
   `https://acme.my.salesforce.com`. The token endpoint the scanner calls is
   `https://<domain>.my.salesforce.com/services/oauth2/token`.

## 3. Environment variables

| Variable | Required | Value |
|---|---|---|
| `OBJECT_TYPE` | yes | `SALESFORCE` (alias: `SFDC`) |
| `OBJECT_NAME` | yes | My Domain name (`acme`) or the full instance URL; `SF_DOMAIN` overrides it |
| `SF_CONSUMER_KEY` | yes | Connected App Consumer Key |
| `SF_CONSUMER_SECRET` | yes | Connected App Consumer Secret |
| `SF_OBJECTS` | no | Pin the sObjects to scan (`Contact,Lead,...`); empty = every queryable business object that holds records |
| `SF_INCLUDE_FILES` | no | `true` (default): also scan files attached to records (latest `ContentVersion` + `Attachment` bodies) |
| `SF_API_VERSION` | no | Default `v62.0` |

### Example `.env`

```bash
OBJECT_TYPE=SALESFORCE
OBJECT_NAME=acme                     # from https://acme.my.salesforce.com
SF_CONSUMER_KEY=<consumer-key>
SF_CONSUMER_SECRET=<consumer-secret>
# SF_OBJECTS=Contact,Lead,Case       # optional: pin the objects
# SF_INCLUDE_FILES=true

# leave CSPM_URL unset to keep findings local (output/findings/)
```

Run:

```bash
python -m src.dspm_scanner_worker_handler
```

What gets scanned: every queryable business object holding records (system shapes like
`*Share`/`*History`/`*Feed`/`*ChangeEvent` and `Apex*`/`Datacloud*` are excluded, empty objects
are skipped via `limits/recordCount`), text-typed fields only, up to `SAMPLE_LIMIT` records per
object — plus attached files through the same parsers as S3 objects. Incremental scans filter on
`SystemModstamp` when a `last_scan_time` is supplied (master-mode payloads).

## 4. Troubleshooting

| Error | Meaning | Fix |
|---|---|---|
| `invalid_client` on the token call | Wrong consumer key/secret | Re-copy from *Manage Consumer Details* (the secret is masked by default) |
| `invalid_grant` / `no client credentials user enabled` | Client Credentials Flow not enabled, or no Run As user | Section 2.1 checkbox + 2.3 Run As policy |
| Objects scanned but `Files/...` units error with 403 | Integration user lacks **Query All Files** | Section 1.1 — add it to the permission set |
| Far fewer objects than expected | `limits/recordCount` filtered empty objects (normal), or `SF_OBJECTS` is set | Unset `SF_OBJECTS`, check the log line "Salesforce objects selected for scan" |
| Rows missing from a scanned object | Field-level security / sharing hides them from the run-as user | "View All Data" covers most cases; check FLS on the object's fields |

> **Secret hygiene**: rotate the consumer secret from *Manage Consumer Details* if it may have
> leaked; keep the integration user API-only; never commit `.env`.
