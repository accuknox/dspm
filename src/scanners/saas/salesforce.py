"""
SalesforceScanner: Salesforce connector.

How the DSPM vendors do it (research, Sept 2026):
- Proofpoint (Normalyze) documents the auth model precisely: a Connected App
  with the OAuth 2.0 client-credentials flow, run as a dedicated integration
  user holding a permission set with "API Enabled", "Api Only User",
  "View All Data" and "Query All Files".
- Nightfall scans standard and custom objects field by field (Accounts,
  Contacts, Leads, Cases, Attachments, ...), with per-object field selection.
- Varonis scans records AND the files attached to them ("the only product
  that can look inside files attached to objects") - so this connector scans
  ContentVersion / Attachment bodies too, by default.
- singer-io's tap-salesforce documents why Share/History/Feed/ChangeEvent
  and Datacloud* objects are not usefully queryable; they are excluded.

Records are columnar: one sObject is one unit (like a table), fields are
columns, so the whole pipeline (column verdicts, siblings, exclusivity)
applies unchanged. Files are downloaded to temporary disk and go through
the shared parsers, one unit per file.
"""
import os
import shutil
import tempfile
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit

try:
    import requests
except ImportError:
    requests = None

from src.pipeline.records import COLUMNAR, Cell, Record
from src.scanners.base import BaseScanner
from src.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_API_VERSION = "v62.0"

# Field types worth scanning; numbers, booleans, dates and references carry
# no free text (national ids stored in number fields are exceedingly rare in
# Salesforce, whose standard PII fields are all strings).
TEXT_FIELD_TYPES = {
    "string", "textarea", "email", "phone", "url",
    "picklist", "multipicklist", "combobox", "encryptedstring",
}

# System-object shapes that hold engine internals, not customer data
EXCLUDED_SUFFIXES = ("Share", "History", "Feed", "ChangeEvent", "Tag")
EXCLUDED_PREFIXES = ("Apex", "Aura", "Datacloud", "Setup")
EXCLUDED_OBJECTS = {
    "LoginHistory", "LoginIp", "AuthSession", "OauthToken", "Vote", "OutgoingEmail",
}
# Bodies are scanned through the files path below, not as records
FILE_OBJECTS = {"ContentVersion", "ContentDocument", "ContentDocumentLink", "Attachment"}

MAX_FILE_BYTES = 100 * 1024 * 1024  # same guard as the S3 / Drive connectors
RECORD_COUNT_BATCH = 100  # limits/recordCount accepts up to 100 object names per call


def _excluded(name: str) -> bool:
    return (
        name in EXCLUDED_OBJECTS
        or name in FILE_OBJECTS
        or name.endswith(EXCLUDED_SUFFIXES)
        or name.startswith(EXCLUDED_PREFIXES)
    )


class SalesforceScanner(BaseScanner):
    """
    Scans Salesforce sObjects (records field by field, like tables) and the
    files attached to them (ContentVersion / Attachment bodies through the
    shared file parsers).
    """

    def __init__(self, engine, config: Dict[str, Any] = None, client=None):
        super().__init__(engine, config, client)
        # client, when injected, is an authorized requests-like session (tests)
        self.stats = {"objects_scanned": 0, "records_scanned": 0, "files_scanned": 0, "errors": 0}

    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        return self.collect(target)

    def iter_scan(self, target: Dict[str, Any]) -> Iterator[Tuple[str, str, List[Dict[str, Any]]]]:
        """
        Scans one sObject at a time, yielding (resource_id, object_name,
        findings) as each finishes; attached files follow, one unit per file.

        Target structure:
        {
            "domain": "acme",                       # My Domain name, or a full https://... instance URL
            "consumer_key": "3MVG9...",             # Connected App, OAuth client-credentials flow
            "consumer_secret": "...",
            "access_token": "00D...",               # alternative: a ready token (+ instance_url)
            "instance_url": "https://acme.my.salesforce.com",
            "api_version": "v62.0",                 # optional
            "objects": ["Contact", "Lead"],         # optional: pin the objects; default = all queryable
                                                    # business objects that hold at least one record
            "include_files": true,                  # optional: also scan ContentVersion/Attachment bodies (default true)
            "sample_limit": 10000,                  # optional: records per object / files per source
            "last_scan_time": "2026-08-01T00:00:00Z"  # optional: SystemModstamp incremental filter
        }
        """
        session, instance, version = self._connect(target)
        if session is None:
            return
        host = urlsplit(instance).hostname or instance or "salesforce"
        base = f"{instance}/services/data/{version}"
        logger.info(f"Starting Salesforce scan for salesforce://{host} ({version})")

        try:
            objects = self._select_objects(session, base, target)
        except Exception as e:
            self.record_error(f"connect: {str(e)[:200]}")
            logger.error(f"Failed to enumerate Salesforce objects: {str(e)}")
            return

        for name in objects:
            findings = self._scan_object(session, base, instance, host, name, target)
            if findings is None:
                continue  # describe/query failed; error already recorded
            yield f"salesforce://{host}/{name}", name, self.dedup_findings(findings)

        include_files = target.get("include_files")
        if include_files is None:
            include_files = self.config.get("include_files", True)
        if include_files:
            yield from self._scan_files(session, base, host, target)

    # ------------------------------------------------------------------ auth
    def _connect(self, target: Dict[str, Any]):
        version = target.get("api_version") or self.config.get("sf_api_version") or DEFAULT_API_VERSION
        if self.client is not None:
            return self.client, (target.get("instance_url") or "").rstrip("/"), version

        if requests is None:
            self.record_error("connect: requests is not installed")
            return None, None, version

        domain = target.get("domain") or ""
        if domain.startswith("http"):
            base = domain.rstrip("/")
        elif domain:
            base = f"https://{domain}.my.salesforce.com"
        else:
            base = (target.get("instance_url") or "").rstrip("/")

        session = requests.Session()
        try:
            if target.get("access_token"):
                token, instance = target["access_token"], base
            else:
                # Connected App client-credentials flow (Normalyze/Proofpoint model):
                # the token is issued on behalf of the app's "Run As" integration user
                resp = session.post(
                    f"{base}/services/oauth2/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": target.get("consumer_key"),
                        "client_secret": target.get("consumer_secret"),
                    },
                    timeout=self.config.get("connect_timeout", 10),
                )
                if resp.status_code >= 300:
                    raise RuntimeError(f"token HTTP {resp.status_code}: {resp.text[:200]}")
                data = resp.json()
                token = data["access_token"]
                instance = (data.get("instance_url") or base).rstrip("/")
            session.headers["Authorization"] = f"Bearer {token}"
            return session, instance, version
        except Exception as e:
            self.record_error(f"connect: {str(e)[:200]}")
            logger.error(f"Failed to authenticate to Salesforce ({base}): {str(e)}")
            return None, None, version

    # ------------------------------------------------------------------ helpers
    def _get(self, session, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        resp = session.get(url, params=params, timeout=60)
        if resp.status_code >= 300:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    # ------------------------------------------------------------------ enumeration
    def _select_objects(self, session, base: str, target: Dict[str, Any]) -> List[str]:
        if target.get("objects"):
            return list(target["objects"])

        described = self._get(session, f"{base}/sobjects").get("sobjects", [])
        names = [s["name"] for s in described if s.get("queryable") and not _excluded(s["name"])]

        # Skip empty objects via limits/recordCount (approximate, 100 names per
        # call); orgs expose hundreds of queryable objects with zero rows.
        try:
            non_empty = set()
            for i in range(0, len(names), RECORD_COUNT_BATCH):
                chunk = names[i:i + RECORD_COUNT_BATCH]
                data = self._get(
                    session, f"{base}/limits/recordCount", params={"sObjects": ",".join(chunk)},
                )
                for row in data.get("sObjects", []):
                    if row.get("count"):
                        non_empty.add(row.get("name"))
            names = [n for n in names if n in non_empty]
        except Exception as e:
            logger.info(f"recordCount unavailable ({str(e)[:100]}); scanning all queryable objects")

        logger.info(f"Salesforce objects selected for scan: {len(names)}")
        return names

    # ------------------------------------------------------------------ records
    def _scan_object(
        self, session, base: str, instance: str, host: str, name: str, target: Dict[str, Any],
    ) -> Optional[List[Dict[str, Any]]]:
        resource_id = f"salesforce://{host}/{name}"
        try:
            desc = self._get(session, f"{base}/sobjects/{name}/describe")
        except Exception as e:
            self.record_error(f"{resource_id}: describe: {str(e)[:200]}")
            logger.error(f"Failed to describe {name}: {str(e)}")
            return None

        fields = [f["name"] for f in desc.get("fields", []) if f.get("type") in TEXT_FIELD_TYPES]
        if not fields:
            return []
        field_names = set(f["name"] for f in desc.get("fields", []))

        sample_limit = target.get("sample_limit", 10000)
        soql = f"SELECT Id, {', '.join(fields)} FROM {name}"  # noqa: S608 - names come from describe
        last_scan = target.get("last_scan_time") or self.config.get("last_scan_time")
        if last_scan and "SystemModstamp" in field_names:
            soql += f" WHERE SystemModstamp > {last_scan}"  # SOQL datetime literals are unquoted
        soql += f" LIMIT {int(sample_limit)}"
        if self.config.get("log_queries"):
            logger.info(f"Executing SOQL on {name}: {soql}")

        def records() -> Iterator[Record]:
            url: Optional[str] = f"{base}/query"
            params: Optional[Dict[str, Any]] = {"q": soql}
            count = 0
            try:
                while url:
                    data = self._get(session, url, params)
                    params = None
                    for rec in data.get("records", []):
                        rid = rec.get("Id", "")
                        cells = [
                            Cell(
                                value=str(value), field=field,
                                location=f"Object '{name}', Record {rid}, Field '{field}'",
                            )
                            for field, value in rec.items()
                            if field not in ("attributes", "Id") and value not in (None, "")
                        ]
                        yield Record(cells, shape=COLUMNAR)
                        count += 1
                    next_url = data.get("nextRecordsUrl")
                    url = f"{instance}{next_url}" if next_url and not data.get("done") else None
            finally:
                self.stats["records_scanned"] += count

        errors_before = self.stats["errors"]
        findings = self.classify(
            resource_id, records(),
            location_fn=lambda field, n: f"Object '{name}', Field '{field}' ({n} matches)",
            unit_name=name,
        )
        if self.stats["errors"] == errors_before:
            self.stats["objects_scanned"] += 1
        return findings

    # ------------------------------------------------------------------ files
    def _scan_files(
        self, session, base: str, host: str, target: Dict[str, Any],
    ) -> Iterator[Tuple[str, str, List[Dict[str, Any]]]]:
        """
        Files attached to records (the Varonis differentiator): the latest
        version of every File (ContentVersion) and every classic Attachment,
        downloaded and scanned through the shared parsers. Requires the
        "Query All Files" permission to see files beyond the run-as user's.
        """
        sample_limit = int(target.get("sample_limit", 10000))
        sources = (
            (
                "ContentVersion",
                f"SELECT Id, Title, FileExtension, ContentSize FROM ContentVersion WHERE IsLatest = true LIMIT {sample_limit}",  # noqa: E501
                "VersionData",
                lambda r: f"{r.get('Title') or r.get('Id')}.{r.get('FileExtension')}" if r.get("FileExtension") else (r.get("Title") or r.get("Id", "file")),
                lambda r: int(r.get("ContentSize") or 0),
            ),
            (
                "Attachment",
                f"SELECT Id, Name, BodyLength FROM Attachment LIMIT {sample_limit}",
                "Body",
                lambda r: r.get("Name") or r.get("Id", "file"),
                lambda r: int(r.get("BodyLength") or 0),
            ),
        )
        for obj, soql, blob_field, name_of, size_of in sources:
            try:
                if self.config.get("log_queries"):
                    logger.info(f"Executing SOQL on {obj}: {soql}")
                data = self._get(session, f"{base}/query", params={"q": soql})
            except Exception as e:
                self.record_error(f"salesforce://{host}/{obj}: {str(e)[:200]}")
                logger.error(f"Failed to list {obj}: {str(e)}")
                continue

            for rec in data.get("records", []):
                file_id = rec.get("Id", "")
                file_name = name_of(rec)
                size = size_of(rec)
                if size > self.config.get("max_file_bytes", MAX_FILE_BYTES):
                    logger.info(f"Skipping {obj} {file_name} with size {size}")
                    continue

                resource_id = f"salesforce://{host}/{obj}/{file_id}/{file_name}"
                temp_dir = tempfile.mkdtemp()
                try:
                    resp = session.get(f"{base}/sobjects/{obj}/{file_id}/{blob_field}", timeout=300)
                    if resp.status_code >= 300:
                        self.record_error(f"{resource_id}: HTTP {resp.status_code}")
                        continue
                    local_path = os.path.join(temp_dir, os.path.basename(str(file_name).replace("\\", "/")) or "file")
                    with open(local_path, "wb") as fh:
                        fh.write(resp.content)
                    findings = self.scan_local_file(local_path, resource_id)
                    self.stats["files_scanned"] += 1
                    yield resource_id, f"Files/{file_name}", findings
                except Exception as e:
                    self.record_error(f"{resource_id}: {str(e)[:200]}")
                    logger.error(f"Error scanning Salesforce file {resource_id}: {str(e)}")
                finally:
                    shutil.rmtree(temp_dir, ignore_errors=True)
