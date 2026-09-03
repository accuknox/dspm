"""
GoogleDriveScanner: Google Workspace (Drive) connector.

How the DSPM vendors do it (research, Sept 2026):
- Proofpoint (Normalyze) documents the auth model precisely: a GCP service
  account authorized via domain-wide delegation in the Google Admin console,
  with the single OAuth scope https://www.googleapis.com/auth/drive.readonly
  so the scanner cannot modify data by construction.
- Nightfall scopes Drive scanning by drive type (My Drive vs shared drives),
  users/groups and file filters, and runs historical scans by enumerating
  files through the Drive API.
- Varonis and Cyera treat Drive as a first-class data store: files are
  fetched and classified with exactly the same engine as bucket objects
  (Cyera's coverage list is "Drive, Gmail, Meet recordings").

This connector follows that consensus: enumerate with files.list, export
Google-native formats (Docs -> .docx, Sheets -> .xlsx - the CSV export is
first-sheet-only, xlsx keeps every sheet - Slides -> .txt), download
everything else with alt=media, and hand the local file to the shared
parsers (src/scanners/files), exactly like the S3 connector. One Drive file
is one unit; workbooks and archives fan out per sheet / member inside the
parsers.

Auth: a service-account key file (target/sa_key_file, or the standard
GOOGLE_APPLICATION_CREDENTIALS), optionally impersonating a Workspace user
(target/impersonate_user, requires domain-wide delegation) to see that
user's My Drive, or pinned to one shared drive (target/drive_id). Without a
key file, Application Default Credentials are used.
"""
import os
import shutil
import tempfile
from typing import Any, Dict, Iterator, List, Optional, Tuple

# Conditional imports for soft failures, like pymongo in the Mongo connector
try:
    import google.auth
    from google.auth.transport.requests import AuthorizedSession
    from google.oauth2 import service_account
except ImportError:
    google = None
    AuthorizedSession = None
    service_account = None

from src.scanners.base import BaseScanner
from src.utils.logger import get_logger

logger = get_logger(__name__)

DRIVE_API = "https://www.googleapis.com/drive/v3"
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.readonly"  # read-only by construction

GOOGLE_MIME_PREFIX = "application/vnd.google-apps."
FOLDER_MIME = "application/vnd.google-apps.folder"
SHORTCUT_MIME = "application/vnd.google-apps.shortcut"

# Google-native formats -> (export MIME type, local extension the parsers dispatch on).
# Sheets exports as xlsx because text/csv is first-sheet-only (Drive API export reference).
EXPORT_FORMATS = {
    "application/vnd.google-apps.document": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx",
    ),
    "application/vnd.google-apps.spreadsheet": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx",
    ),
    "application/vnd.google-apps.presentation": ("text/plain", ".txt"),
}

MAX_FILE_BYTES = 100 * 1024 * 1024  # same guard as the S3 connector
PAGE_SIZE = 1000
LIST_FIELDS = "nextPageToken, files(id, name, mimeType, size, modifiedTime)"


def _error_reason(resp: Any) -> str:
    """Google's structured error reason + message, e.g. 'exportSizeLimitExceeded: This file is too large...'."""
    try:
        err = resp.json().get("error", {})
        errors = err.get("errors") or []
        reason = errors[0].get("reason") if errors else None
        message = err.get("message", "")
        return f"({reason}: {message})" if reason else f"({message})" if message else ""
    except Exception:
        text = (getattr(resp, "text", "") or "").strip()
        return f"({text[:150]})" if text else ""


def _safe_name(name: str, forced_ext: Optional[str]) -> str:
    """A path-traversal-safe local filename with the extension the parsers need."""
    base = os.path.basename(str(name).replace("\\", "/")) or "file"
    if forced_ext:
        root, _ = os.path.splitext(base)
        return (root or "file") + forced_ext
    return base


class GoogleDriveScanner(BaseScanner):
    """
    Scans Google Drive (My Drives via impersonation, or a shared drive) for
    sensitive data. Downloads/exports each file to temporary disk - never
    into memory - and classifies every unit the shared file parsers yield.
    """

    def __init__(self, engine, config: Dict[str, Any] = None, client=None):
        super().__init__(engine, config, client)
        # client, when injected, is an authorized requests-like session (tests)
        self.stats = {"files_scanned": 0, "errors": 0}

    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        return self.collect(target)

    def iter_scan(self, target: Dict[str, Any]) -> Iterator[Tuple[str, str, List[Dict[str, Any]]]]:
        """
        Scans one Drive file at a time, yielding (resource_id, file_name,
        findings) as each file finishes, so callers can checkpoint per file.

        Target structure:
        {
            "impersonate_user": "user@example.com",  # optional: that user's My Drive (domain-wide delegation)
            "drive_id": "0AbCd...",                  # optional: one shared drive instead
            "folder_id": "1XyZ...",                  # optional: restrict to a folder
            "sa_key_file": "/path/key.json",         # optional: service-account key (default GOOGLE_APPLICATION_CREDENTIALS)
            "max_files": 500,                        # optional cap on files per run
            "last_scan_time": "2026-08-01T00:00:00Z" # optional: only files modified since (incremental)
        }
        """
        session = self.client or self._build_session(target)
        if session is None:
            return
        scope = target.get("drive_id") or target.get("impersonate_user") or "my-drive"
        logger.info(f"Starting Google Drive scan for gdrive://{scope}")
        listed = 0
        try:
            for meta in self._list_files(session, target):
                listed += 1
                yield from self._scan_file(session, meta, scope, listed)
        except Exception as e:
            self.record_error(f"connect: {str(e)[:200]}")
            logger.error(f"Error scanning Google Drive ({scope}): {str(e)}")
        logger.info(
            f"Finished Google Drive scan for gdrive://{scope}: {listed} file(s) listed, "
            f"{self.stats['files_scanned']} scanned, {self.stats['errors']} error(s)",
        )

    # ------------------------------------------------------------------ auth
    def _build_session(self, target: Dict[str, Any]):
        if AuthorizedSession is None:
            self.record_error("connect: google-auth is not installed")
            logger.warning("google-auth is not installed. Skipping Google Drive scan.")
            return None
        key_file = (
            target.get("sa_key_file")
            or self.config.get("sa_key_file")
            or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        )
        subject = target.get("impersonate_user")
        try:
            if key_file:
                creds = service_account.Credentials.from_service_account_file(key_file, scopes=[DRIVE_SCOPE])
            else:
                creds, _project = google.auth.default(scopes=[DRIVE_SCOPE])
            if subject and hasattr(creds, "with_subject"):
                # Domain-wide delegation: act as this Workspace user (their My Drive)
                creds = creds.with_subject(subject)
            return AuthorizedSession(creds)
        except Exception as e:
            self.record_error(f"connect: {str(e)[:200]}")
            logger.error(f"Failed to build Google Drive credentials: {str(e)}")
            return None

    # ------------------------------------------------------------------ enumeration
    def _list_files(self, session, target: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
        clauses = ["trashed = false"]
        if target.get("folder_id"):
            clauses.append(f"'{target['folder_id']}' in parents")
        last_scan = target.get("last_scan_time") or self.config.get("last_scan_time")
        if last_scan:
            clauses.append(f"modifiedTime > '{last_scan}'")  # incremental, like S3 last_modified

        params: Dict[str, Any] = {
            "q": " and ".join(clauses),
            "pageSize": PAGE_SIZE,
            "fields": LIST_FIELDS,
            "supportsAllDrives": "true",
            "includeItemsFromAllDrives": "true",
        }
        if target.get("drive_id"):
            params["corpora"] = "drive"
            params["driveId"] = target["drive_id"]
        else:
            params["corpora"] = "user"

        max_files = target.get("max_files")
        listed = 0
        while True:
            resp = session.get(f"{DRIVE_API}/files", params=params, timeout=60)
            if resp.status_code >= 300:
                raise RuntimeError(f"files.list HTTP {resp.status_code}: {resp.text[:200]}")
            data = resp.json()
            for meta in data.get("files", []):
                yield meta
                listed += 1
                if max_files and listed >= max_files:
                    logger.info(f"Stopping Drive listing at max_files={max_files}")
                    return
            token = data.get("nextPageToken")
            if not token:
                return
            params["pageToken"] = token

    # ------------------------------------------------------------------ per file
    def _scan_file(
        self, session, meta: Dict[str, Any], scope: str, index: int = 0,
    ) -> Iterator[Tuple[str, str, List[Dict[str, Any]]]]:
        file_id = meta.get("id", "")
        name = meta.get("name") or file_id
        mime = meta.get("mimeType", "")
        size = int(meta.get("size") or 0)  # Google-native files carry no size

        if mime in (FOLDER_MIME, SHORTCUT_MIME):
            return
        if mime.startswith(GOOGLE_MIME_PREFIX) and mime not in EXPORT_FORMATS:
            logger.info(f"Skipping non-exportable Google file {name} ({mime})")
            return
        if size > self.config.get("max_file_bytes", MAX_FILE_BYTES):
            logger.info(f"Skipping file {name} with size {size}")
            return

        resource_id = f"gdrive://{scope}/{file_id}/{name}"
        exported = mime in EXPORT_FORMATS
        logger.info(
            f"[{index}] Scanning Drive file '{name}' "
            f"({'export ' + mime.rsplit('.', 1)[-1] if exported else mime or 'binary'}"
            f"{'' if exported else f', {size} bytes'})",
        )
        temp_dir = tempfile.mkdtemp()
        try:
            if mime in EXPORT_FORMATS:
                export_mime, ext = EXPORT_FORMATS[mime]
                local_path = os.path.join(temp_dir, _safe_name(name, ext))
                resp = session.get(
                    f"{DRIVE_API}/files/{file_id}/export",
                    params={"mimeType": export_mime}, timeout=120,
                )
            else:
                local_path = os.path.join(temp_dir, _safe_name(name, None))
                resp = session.get(
                    f"{DRIVE_API}/files/{file_id}",
                    params={"alt": "media", "supportsAllDrives": "true"}, timeout=300,
                )
            if resp.status_code >= 300:
                # Surface Google's reason: export 403s are usually exportSizeLimitExceeded
                # (the 10 MB export cap on Docs/Sheets/Slides) rather than a permission gap.
                reason = _error_reason(resp)
                self.record_error(f"{resource_id}: HTTP {resp.status_code} {reason}")
                logger.error(f"Failed to fetch {resource_id}: HTTP {resp.status_code} {reason}")
                return
            with open(local_path, "wb") as fh:
                fh.write(resp.content)

            findings = self.scan_local_file(local_path, resource_id)
            self.stats["files_scanned"] += 1
            if findings:
                logger.info(f"[{index}] '{name}': {len(findings)} finding(s)")
            yield resource_id, name, findings
        except Exception as e:
            self.record_error(f"{resource_id}: {str(e)[:200]}")
            logger.error(f"Error scanning Drive file {resource_id}: {str(e)}")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
