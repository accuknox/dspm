import os
from typing import Any, Dict, Iterator, List, Tuple

import boto3

from src.scanners.base import MAX_FILE_BYTES, BaseScanner
from src.utils.logger import get_logger

logger = get_logger(__name__)


class S3Scanner(BaseScanner):
    """
    Scans S3 objects for sensitive data: downloads the object to temporary
    disk (never into memory), hands it to the shared file parsers
    (src/scanners/files) and classifies every unit they yield. An object store
    connector for another provider only needs a different listing and download
    step (see src/scanners/azure/blob.py).
    """

    def __init__(self, engine, config: Dict[str, Any] = None, client=None):
        super().__init__(engine, config, client)
        # Same shape as the DB scanners' stats so callers can surface failures uniformly
        self.stats = {"objects_scanned": 0, "objects_skipped": 0, "errors": 0}

    def iter_scan(self, target: Dict[str, Any]) -> Iterator[Tuple[str, str, List[Dict[str, Any]]]]:
        """
        Scans a bucket object by object, yielding (resource_id, key, findings) as
        each object finishes - the object-store counterpart of the database
        connectors' per-relation loop, so callers can checkpoint. Empty objects
        (folder markers) and objects over max_file_bytes (100 MB) are skipped and
        counted in stats["objects_skipped"]. A target with "key" scans that one object.

        Target structure:
        {
            "bucket": "my-bucket",
            "prefix": "exports/2026/",   # optional, restrict to a key prefix
            "key": "path/to/object.csv"  # optional, one object (see scan())
        }
        """
        bucket = target["bucket"]
        if target.get("key"):
            yield f"arn:aws:s3:::{bucket}/{target['key']}", target["key"], self.scan(target)
            return

        if self.client is None:
            self.client = boto3.client("s3")  # one client for the whole bucket, reused by scan()
        max_bytes = int(self.config.get("max_file_bytes") or MAX_FILE_BYTES)
        params = {"Bucket": bucket}
        if target.get("prefix"):
            params["Prefix"] = target["prefix"]

        for page in self.client.get_paginator("list_objects_v2").paginate(**params):
            for obj in page.get("Contents", []):
                key = obj.get("Key")
                size = obj.get("Size") or 0
                if not key or size <= 0 or size > max_bytes:
                    self.stats["objects_skipped"] += 1
                    logger.info(f"Skipping object {key} with size {size}")
                    continue
                object_target = {
                    "bucket": bucket,
                    "key": key,
                    "version_id": obj.get("VersionId"),
                    "last_modified": obj.get("LastModified"),
                }
                yield f"arn:aws:s3:::{bucket}/{key}", key, self.scan(object_target)

    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Target structure:
        {
            "bucket": "my-bucket",
            "key": "path/to/object.csv",
            "version_id": "optional-version",
            "last_modified": "optional-timestamp"
        }
        """
        bucket = target["bucket"]
        key = target["key"]
        version_id = target.get("version_id")

        resource_id = f"arn:aws:s3:::{bucket}/{key}"
        logger.info(f"Starting S3 scan for {resource_id}")

        s3_client = self.client or boto3.client("s3")

        # Incremental check if configuration specifies last scan time
        if "last_scan_time" in self.config and target.get("last_modified"):
            last_scan = self.config["last_scan_time"]
            if target["last_modified"] <= last_scan:
                logger.info(
                    f"Skipping S3 scan for {resource_id} (not modified since {last_scan})",
                )
                return []

        # Download to a temporary directory (kept under config['keep_files_dir'] when set)
        temp_dir = self.workdir(resource_id)
        temp_file_path = os.path.join(temp_dir, os.path.basename(key) or "object.tmp")

        try:
            if version_id:
                s3_client.download_file(
                    bucket,
                    key,
                    temp_file_path,
                    ExtraArgs={"VersionId": version_id},
                )
            else:
                s3_client.download_file(bucket, key, temp_file_path)

            findings = self.scan_local_file(temp_file_path, resource_id)
            self.stats["objects_scanned"] += 1
            return findings

        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Error scanning S3 object {resource_id}: {str(e)}")
            return []
        finally:
            self.discard_workdir(temp_dir)

    def list_all_files(self, bucket: str):
        paginator = self.client.get_paginator("list_objects_v2")

        files = []

        for page in paginator.paginate(Bucket=bucket):
            files.extend(page.get("Contents", []))

        return files
