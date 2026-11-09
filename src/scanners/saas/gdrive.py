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

Oversized native files: files.export is capped at 10 MB by Google
(exportSizeLimitExceeded) and the cap cannot be raised. Two fallbacks, in
order: (1) the editors' own export endpoint
(docs.google.com/<kind>/d/<id>/export?format=...), which the same
drive.readonly token is accepted on, is not subject to the Drive API cap and
yields the identical docx/xlsx/txt - verified live on a 16 MB Sheet in Oct
2026; (2) the editor APIs - Sheets values.get in row chunks (rebuilt as a
local .xlsx so sheet names and row numbers stay identical), Docs
documents.get and Slides presentations.get (text only) - which have no cap
either but must be enabled in the service account's GCP project.

Auth: a service-account key file (target/sa_key_file, or the standard
GOOGLE_APPLICATION_CREDENTIALS), optionally impersonating a Workspace user
(target/impersonate_user, requires domain-wide delegation) to see that
user's My Drive, or pinned to one shared drive (target/drive_id). Without a
key file, Application Default Credentials are used.
"""
import os
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import quote

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
SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"
DOCS_API = "https://docs.googleapis.com/v1/documents"
SLIDES_API = "https://slides.googleapis.com/v1/presentations"
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
EXPORT_SIZE_LIMIT_REASON = "exportSizeLimitExceeded"  # Drive's fixed 10 MB files.export cap
# Editor export endpoint for oversized files: Google MIME -> (URL kind, format, expected content-type marker)
EDITOR_EXPORT = {
    "application/vnd.google-apps.document": ("document", "docx", "wordprocessingml"),
    "application/vnd.google-apps.spreadsheet": ("spreadsheets", "xlsx", "spreadsheetml"),
    "application/vnd.google-apps.presentation": ("presentation", "txt", "text/plain"),
}
SHEETS_ROW_CHUNK = 10_000  # rows per values.get call when rebuilding an oversized spreadsheet
XLSX_TITLE_BAD_CHARS = set("[]:*?/\\")
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


def _xlsx_sheet_title(title: str, taken: set) -> str:
    """Excel's sheet-name rules (31 chars, no []:*?/\\, unique) applied to a Google sheet title."""
    cleaned = "".join("_" if ch in XLSX_TITLE_BAD_CHARS else ch for ch in str(title)).strip("'") or "Sheet"
    candidate = cleaned[:31]
    n = 1
    while candidate in taken:
        n += 1
        suffix = f"~{n}"
        candidate = cleaned[: 31 - len(suffix)] + suffix
    taken.add(candidate)
    return candidate


def _docs_text(elements: Any, out: List[str]) -> None:
    """Flattens Docs API structural elements (paragraphs, tables, TOC) into text lines."""
    for element in elements or []:
        if "paragraph" in element:
            out.append(
                "".join(
                    run.get("textRun", {}).get("content", "") for run in element["paragraph"].get("elements", [])
                ),
            )
        elif "table" in element:
            for row in element["table"].get("tableRows", []):
                for cell in row.get("tableCells", []):
                    _docs_text(cell.get("content"), out)
        elif "tableOfContents" in element:
            _docs_text(element["tableOfContents"].get("content"), out)


def _slides_text(page_elements: Any, out: List[str]) -> None:
    """Flattens Slides API page elements (shapes, tables, groups) into text lines."""
    def runs(text: Dict[str, Any]) -> str:
        return "".join(te.get("textRun", {}).get("content", "") for te in text.get("textElements", []))

    for element in page_elements or []:
        if "shape" in element:
            out.append(runs(element["shape"].get("text", {})))
        elif "table" in element:
            for row in element["table"].get("tableRows", []):
                for cell in row.get("tableCells", []):
                    out.append(runs(cell.get("text", {})))
        elif "elementGroup" in element:
            _slides_text(element["elementGroup"].get("children"), out)


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
        temp_dir = self.workdir(resource_id)
        try:
            if exported:
                export_mime, ext = EXPORT_FORMATS[mime]
                local_path = os.path.join(temp_dir, _safe_name(name, ext))
                resp = session.get(
                    f"{DRIVE_API}/files/{file_id}/export",
                    params={"mimeType": export_mime}, timeout=120,
                )
                if resp.status_code == 403 and EXPORT_SIZE_LIMIT_REASON in _error_reason(resp):
                    # Google's 10 MB export cap cannot be raised: rebuild the file from the
                    # editor API (Sheets/Docs/Slides), which has no cap and takes the same scope.
                    logger.info(f"[{index}] '{name}' exceeds the 10 MB export cap; using the editor export / editor API fallback")
                    local_path = self._fetch_oversized_native(session, file_id, mime, name, temp_dir)
                    resp = None
            else:
                local_path = os.path.join(temp_dir, _safe_name(name, None))
                resp = session.get(
                    f"{DRIVE_API}/files/{file_id}",
                    params={"alt": "media", "supportsAllDrives": "true"}, timeout=300,
                )
            if resp is not None:
                if resp.status_code >= 300:
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
            self.discard_workdir(temp_dir)

    # ------------------------------------------------------------------ oversized native files
    def _fetch_oversized_native(self, session, file_id: str, mime: str, name: str, temp_dir: str) -> str:
        """
        Materialises a Google-native file that files.export refused with
        exportSizeLimitExceeded, using the matching editor API. Returns the
        local path; raises RuntimeError with Google's reason on API errors.
        """
        direct = self._fetch_via_editor_export(session, file_id, mime, name, temp_dir)
        if direct:
            return direct
        if mime == "application/vnd.google-apps.spreadsheet":
            return self._fetch_spreadsheet_via_sheets_api(session, file_id, name, temp_dir)
        if mime == "application/vnd.google-apps.document":
            doc = self._editor_api_json(session, f"{DOCS_API}/{file_id}", {}, "Docs")
            lines: List[str] = []
            _docs_text(doc.get("body", {}).get("content"), lines)
            for section in ("headers", "footers", "footnotes"):
                for part in (doc.get(section) or {}).values():
                    _docs_text(part.get("content"), lines)
            return self._write_text(temp_dir, name, lines)
        if mime == "application/vnd.google-apps.presentation":
            deck = self._editor_api_json(
                session, f"{SLIDES_API}/{file_id}",
                {"fields": "slides(pageElements,slideProperties.notesPage.pageElements)"}, "Slides",
            )
            lines = []
            for slide in deck.get("slides", []):
                _slides_text(slide.get("pageElements"), lines)
                _slides_text(slide.get("slideProperties", {}).get("notesPage", {}).get("pageElements"), lines)
            return self._write_text(temp_dir, name, lines)
        raise RuntimeError(f"no oversized-file fallback for {mime}")

    def _fetch_via_editor_export(self, session, file_id: str, mime: str, name: str, temp_dir: str) -> Optional[str]:
        """
        First fallback: the editors' export endpoint (what "File > Download"
        uses), which takes the same OAuth token, needs no extra API enabled
        and has no 10 MB cap. Returns None when it does not deliver the
        expected format (sign-in page, error), so the caller moves on to the
        editor API.
        """
        kind, fmt, marker = EDITOR_EXPORT[mime]
        try:
            resp = session.get(f"https://docs.google.com/{kind}/d/{file_id}/export", params={"format": fmt}, timeout=600)
        except Exception as e:
            logger.info(f"Editor export of {file_id} failed ({str(e)[:120]}); trying the editor API")
            return None
        content_type = (getattr(resp, "headers", None) or {}).get("content-type", "") or ""
        if resp.status_code != 200 or marker not in content_type:
            logger.info(
                f"Editor export of {file_id} returned HTTP {resp.status_code} ({content_type or 'no content-type'}); "
                "trying the editor API",
            )
            return None
        local_path = os.path.join(temp_dir, _safe_name(name, "." + fmt))
        with open(local_path, "wb") as fh:
            fh.write(resp.content)
        return local_path

    def _fetch_spreadsheet_via_sheets_api(self, session, file_id: str, name: str, temp_dir: str) -> str:
        """
        Rebuilds the workbook as a local .xlsx from Sheets values.get, one
        values call per SHEETS_ROW_CHUNK rows, so the xlsx parser yields the
        same '[sheet]' units and 'Row N' locations as a regular export would.
        values.get trims trailing empty rows per call; blank rows are written
        back only when data follows them, so row numbers stay exact without
        materialising a sheet's empty tail.
        """
        from openpyxl import Workbook  # local import keeps the module import-light

        meta = self._editor_api_json(
            session, f"{SHEETS_API}/{file_id}",
            {"fields": "sheets.properties(title,sheetType,gridProperties(rowCount))"}, "Sheets",
        )
        workbook = Workbook(write_only=True)
        taken: set = set()
        chunk = int(self.config.get("sheets_row_chunk", SHEETS_ROW_CHUNK))
        for sheet in meta.get("sheets", []):
            props = sheet.get("properties", {})
            if props.get("sheetType", "GRID") != "GRID":
                continue  # chart-only sheets hold no cells
            title = props.get("title", "Sheet")
            row_count = int((props.get("gridProperties") or {}).get("rowCount") or 0)
            worksheet = workbook.create_sheet(title=_xlsx_sheet_title(title, taken))
            quoted = "'" + title.replace("'", "''") + "'"
            pending_blank = 0
            start = 1
            while start <= row_count:
                end = min(start + chunk - 1, row_count)
                data = self._editor_api_json(
                    session, f"{SHEETS_API}/{file_id}/values/{quote(f'{quoted}!{start}:{end}', safe='')}",
                    {"majorDimension": "ROWS", "valueRenderOption": "FORMATTED_VALUE"}, "Sheets",
                )
                rows = data.get("values") or []
                if rows:
                    for _ in range(pending_blank):
                        worksheet.append([])
                    for row in rows:
                        worksheet.append(["" if v is None else str(v) for v in row])
                    pending_blank = (end - start + 1) - len(rows)
                else:
                    pending_blank += end - start + 1
                start = end + 1
        if not taken:
            workbook.create_sheet(title="Sheet1")
        local_path = os.path.join(temp_dir, _safe_name(name, ".xlsx"))
        workbook.save(local_path)
        return local_path

    @staticmethod
    def _editor_api_json(session, url: str, params: Dict[str, Any], api: str) -> Dict[str, Any]:
        resp = session.get(url, params=params, timeout=120)
        if resp.status_code >= 300:
            reason = _error_reason(resp)
            hint = ""
            if "accessNotConfigured" in reason or "SERVICE_DISABLED" in reason or "has not been used" in reason:
                hint = f" - enable the Google {api} API in the service account's GCP project"
            raise RuntimeError(f"{api} API HTTP {resp.status_code} {reason}{hint}")
        return resp.json() or {}

    @staticmethod
    def _write_text(temp_dir: str, name: str, lines: List[str]) -> str:
        local_path = os.path.join(temp_dir, _safe_name(name, ".txt"))
        with open(local_path, "w", encoding="utf-8") as fh:
            fh.write("".join(line if line.endswith("\n") else line + "\n" for line in lines))
        return local_path
