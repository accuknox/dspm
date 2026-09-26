"""
AzureBlobScanner: Azure Blob Storage and ADLS Gen2 through the Blob API.

The object-store counterpart of the S3 connector: list a container, download
each blob to temporary disk (never into memory), hand it to the shared file
parsers (src/scanners/files) and classify every unit they yield. ADLS Gen2
accounts (hierarchical namespace) answer the same Blob API; their directory
placeholders are skipped by metadata.

Skipped, counted in stats["objects_skipped"] and logged with the reason: empty
blobs and directory placeholders, archive-tier blobs (they need rehydration
before they can be read), page blobs (disk images), soft-deleted blobs, blobs
over max_file_bytes (100 MB) and blobs unchanged since last_scan_time.

Resource id: the blob URL, https://<account>.blob.core.windows.net/<container>/<name>,
never carrying a SAS token. KEEP_SCANNED_FILES mirrors it as azblob/<account>/<container>/<name>.
A blob that cannot be downloaded is recorded in stats["error_details"] and not yielded,
so it never looks clean in the findings.
"""
import os
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional, Tuple

from src.scanners.azure.common import (
    account_url, blob_service_client, parse_timestamp, redact, setting, strip_query,
)
from src.scanners.base import MAX_FILE_BYTES, BaseScanner
from src.utils.azure import AzureConfigError
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AzureBlobScanner(BaseScanner):
    """Scans the blobs of one container (or one blob) for sensitive data."""

    def __init__(self, engine, config: Dict[str, Any] = None, client=None):
        super().__init__(engine, config, client)
        # client, when injected, is a BlobServiceClient (tests)
        self.stats = {"objects_scanned": 0, "objects_skipped": 0, "errors": 0}

    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        return self.collect(target)

    def iter_scan(self, target: Dict[str, Any]) -> Iterator[Tuple[str, str, List[Dict[str, Any]]]]:
        """
        Scans one container blob by blob, yielding (resource_id, blob_name, findings)
        as each blob finishes, so callers can checkpoint per blob.

        Target structure:
        {
            "account": "mystorageacct",             # or its https:// URL; default AZURE_STORAGE_ACCOUNT
            "container": "uploads",                 # required
            "prefix": "exports/2026/",              # optional, restrict to a virtual directory
            "blob": "exports/2026/a.csv",           # optional, scan this one blob only
            "version_id": "...", "snapshot": "...", # optional, with "blob"
            "last_scan_time": "2026-08-01T00:00:00Z",  # optional, skip blobs not modified since
            "max_blobs": 500,                       # optional cap on blobs listed per run
            "endpoint_suffix": "core.windows.net",  # optional, sovereign clouds
            "connection_string" | "sas_token" | "account_key"  # optional credential overrides (see common.py)
        }
        """
        container_name = target.get("container")
        if not container_name:
            raise AzureConfigError("target['container'] is required (a container name, or account/container)")

        service = self.client
        owns_client = service is None
        try:
            if owns_client:
                service = blob_service_client(target, self.config)
            base_url = f"{self._service_url(service, target)}/{container_name}"
            container = service.get_container_client(container_name)
            logger.info(f"Starting Azure Blob scan for {base_url}")

            if target.get("blob"):
                yield from self._scan_blob(container, base_url, target["blob"], target)
                return

            last_scan = parse_timestamp(target.get("last_scan_time") or self.config.get("last_scan_time"))
            max_bytes = int(target.get("max_file_bytes") or self.config.get("max_file_bytes") or MAX_FILE_BYTES)
            max_blobs = int(target.get("max_blobs") or 0)
            listed = 0
            for props in container.list_blobs(name_starts_with=target.get("prefix") or None, include=["metadata"]):
                listed += 1
                name = getattr(props, "name", None) or str(props)
                reason = self._skip_reason(props, last_scan, max_bytes)
                if reason:
                    self.stats["objects_skipped"] += 1
                    logger.info(f"Skipping blob {name}: {reason}")
                else:
                    yield from self._scan_blob(container, base_url, name, target)
                if max_blobs and listed >= max_blobs:
                    logger.info(f"Stopping container listing at max_blobs={max_blobs}")
                    break
            logger.info(
                f"Finished Azure Blob scan for {base_url}: {listed} blob(s) listed, "
                f"{self.stats['objects_scanned']} scanned, {self.stats['objects_skipped']} skipped, "
                f"{self.stats['errors']} error(s)",
            )
        except Exception as e:
            self.record_error(f"connect: {redact(e)[:200]}")
            logger.error(f"Error scanning container '{container_name}': {redact(e)}")
        finally:
            if owns_client and service is not None:
                try:
                    service.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------ helpers
    def _service_url(self, service: Any, target: Dict[str, Any]) -> str:
        """The account's blob endpoint without credentials; injected clients may not know theirs."""
        url = getattr(service, "url", None)
        if isinstance(url, str) and "://" in url:
            return strip_query(url)
        return account_url(
            setting(target, self.config, "account", "AZURE_STORAGE_ACCOUNT"),
            setting(target, self.config, "endpoint_suffix", "AZURE_STORAGE_ENDPOINT_SUFFIX"),
        )

    def _skip_reason(self, props: Any, last_scan: Optional[datetime], max_bytes: int) -> Optional[str]:
        metadata = getattr(props, "metadata", None) or {}
        if str(metadata.get("hdi_isfolder", "")).lower() == "true":
            return "directory placeholder"
        if getattr(props, "deleted", False) is True:
            return "soft-deleted"
        if "page" in str(getattr(props, "blob_type", "") or "").lower():
            return "page blob (disk image)"
        if str(getattr(props, "blob_tier", "") or "").lower() == "archive" or getattr(props, "archive_status", None):
            return "archive tier, rehydration required"
        size = getattr(props, "size", None) or 0
        if size <= 0:
            return "empty"
        if size > max_bytes:
            return f"size {size} exceeds {max_bytes}"
        modified = parse_timestamp(getattr(props, "last_modified", None))
        if last_scan and modified and modified <= last_scan:
            return f"not modified since {last_scan.isoformat()}"
        return None

    def _scan_blob(
        self, container: Any, base_url: str, name: str, target: Dict[str, Any],
    ) -> Iterator[Tuple[str, str, List[Dict[str, Any]]]]:
        resource_id = f"{base_url}/{name}"
        logger.info(f"Scanning blob {resource_id}")
        temp_dir = self.workdir(resource_id)
        local_path = os.path.join(temp_dir, os.path.basename(str(name).replace("\\", "/")) or "blob.bin")
        try:
            single = target.get("blob") == name
            if single and target.get("snapshot"):
                blob = container.get_blob_client(name, snapshot=target["snapshot"])
            else:
                blob = container.get_blob_client(name)
            download_args: Dict[str, Any] = {"max_concurrency": int(self.config.get("download_concurrency", 2))}
            if single and target.get("version_id"):
                download_args["version_id"] = target["version_id"]
            with open(local_path, "wb") as fh:
                blob.download_blob(**download_args).readinto(fh)

            findings = self.scan_local_file(local_path, resource_id)
            self.stats["objects_scanned"] += 1
            if findings:
                logger.info(f"'{name}': {len(findings)} finding(s)")
            yield resource_id, name, findings
        except Exception as e:
            self.record_error(f"{resource_id}: {redact(e)[:200]}")
            logger.error(f"Error scanning blob {resource_id}: {redact(e)}")
        finally:
            self.discard_workdir(temp_dir)
