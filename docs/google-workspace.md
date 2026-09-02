# Google Workspace (Drive) — scanner setup

How to create the credentials and environment variables for scanning Google Drive
(`OBJECT_TYPE=GOOGLE_WORKSPACE`). The scanner authenticates as a GCP **service account**,
authorized read-only via **domain-wide delegation** — the model the DSPM vendors document.

## 1. Create the service account and key

1. **Pick or create a GCP project** — [console.cloud.google.com](https://console.cloud.google.com)
   → project selector → *New project*. Any project works; it does **not** need to be in the same
   organization as your Workspace domain.
2. **Create the service account** — *IAM & Admin → Service Accounts → Create service account*.
   Name it for its job (e.g. `dspm-drive-scanner`). Skip both "grant access" screens — Drive
   scanning needs **no IAM roles**; access comes from Workspace, not GCP IAM.
3. **Create the JSON key** — open the service account → *Keys → Add key → Create new key → JSON*.
   The file downloads once and cannot be re-fetched. Store it outside the repo:

   ```bash
   mkdir -p ~/keys && mv ~/Downloads/<project>-*.json ~/keys/gws-scanner.json
   chmod 600 ~/keys/gws-scanner.json
   ```

   Copy the whole file, never paste-and-retype — a stray space inside `private_key` breaks PEM parsing.
4. **Enable the Google Drive API** — *APIs & Services → Library → Google Drive API → Enable*,
   in the key's project. Without this every call fails (including shared drives) with
   `403 ... Drive API has not been used in project ...`. Propagation takes a few minutes.

## 2. Grant access — pick one route

**A. My Drive scanning (domain-wide delegation, needs a Workspace super admin)**
[admin.google.com](https://admin.google.com) → *Security → Access and data control → API controls
→ Domain-wide delegation → Add new*:

- **Client ID**: the numeric `client_id` from the key JSON (not the email)
- **OAuth scopes**: `https://www.googleapis.com/auth/drive.readonly`

Scopes are **exact-match**: if the client ID is already delegated for other scopes, edit that
entry and *add* the Drive scope — otherwise Drive still fails with `unauthorized_client`.

**B. Shared-drive scanning (no admin console needed)**
Add the service account's **email** (`client_email` in the key) as a **Viewer** on the shared
drive (*Manage members*), or share a folder with it. The drive id is the `0A…` part of its URL.

## 3. Environment variables

| Variable | Required | Value |
|---|---|---|
| `OBJECT_TYPE` | yes | `GOOGLE_WORKSPACE` (aliases: `GDRIVE`, `GOOGLE_DRIVE`, `GOOGLEWORKSPACE`) |
| `OBJECT_NAME` | yes | What to scan: a user email (route A — their My Drive) or a shared-drive id (route B) |
| `GOOGLE_SA_KEY_FILE` | yes* | Path to the key JSON (\* or set `GOOGLE_APPLICATION_CREDENTIALS`; Application Default Credentials are used when neither is set) |
| `GOOGLE_IMPERSONATE_USER` | no | Pins the impersonated user explicitly (overrides `OBJECT_NAME`) |
| `GOOGLE_DRIVE_ID` | no | Pins the shared drive explicitly (overrides `OBJECT_NAME`) |

`OBJECT_NAME` containing `@` is treated as a user, anything else as a shared-drive id.

### Example `.env`

```bash
OBJECT_TYPE=GOOGLE_WORKSPACE
GOOGLE_SA_KEY_FILE=/home/you/keys/gws-scanner.json
OBJECT_NAME=user@example.com      # route A: that user's My Drive
# OBJECT_NAME=0AbCdEfGhIjKlMnOp   # route B: a shared drive

# leave CSPM_URL unset to keep findings local (output/findings/)
```

Run:

```bash
python -m src.dspm_scanner_worker_handler
```

## 4. Troubleshooting

| Error | Meaning | Fix |
|---|---|---|
| `unauthorized_client: Client is unauthorized to retrieve access tokens...` | Delegation missing for this client ID *with this scope* | Section 2A — add `drive.readonly` to the client's scope list; allow a few minutes |
| `403 ... Drive API has not been used in project ... or it is disabled` | Drive API disabled in the key's project | Section 1.4 — the error contains the exact enable link |
| `invalid_grant: Invalid JWT` | Clock skew, or a mangled `private_key` | Sync the clock; re-download the key rather than editing it |
| Listing succeeds but returns no files | Route B: the account isn't a member of that shared drive | Check *Manage members* for the `client_email`; confirm the drive id |
| `exportSizeLimitExceeded` | Google-native file over the 10 MB export cap | Recorded per file in the findings' `errors`; the scan continues |

> **Key hygiene**: the JSON key is a bearer credential. Keep it out of repos and chats,
> `chmod 600`, rotate it if it may have leaked (add the new key, then delete the old one), and
> keep the delegation scope list at exactly `drive.readonly`.
