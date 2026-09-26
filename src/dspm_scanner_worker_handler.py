import json
import sys
import time
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import boto3
import requests

import settings
from src.engine.confidence import max_tier
from src.engine.detector import DetectionEngine
from src.scanners.aws.ddb import DynamoDBScanner
from src.scanners.aws.s3 import S3Scanner
from src.scanners.azure.blob import AzureBlobScanner
from src.scanners.azure.cosmos import CosmosNoSQLScanner
from src.scanners.db.mongo import MongoScanner
from src.scanners.db.sql import SQLScanner
from src.scanners.saas.gdrive import GoogleDriveScanner
from src.scanners.saas.salesforce import SalesforceScanner
from src.utils.logger import get_logger

logger = get_logger("handler")

BASE_DIR = Path(__file__).resolve().parent.parent

# Overridable so containers can point at a writable volume (OpenShift runs as a
# random non-root UID). Directories are created lazily inside the handler, never
# at import time.
OUTPUT_DIR = Path(settings.OUTPUT_DIR) if settings.OUTPUT_DIR else BASE_DIR / "output"
FINDINGS_DIR = OUTPUT_DIR / "findings"

# OBJECT_TYPE values accepted for S3 buckets
S3_OBJECT_TYPES = {"S3", "S3BUCKET"}

# OBJECT_TYPE values accepted for Azure Blob Storage / ADLS Gen2 containers
AZURE_BLOB_OBJECT_TYPES = {"AZURE_BLOB", "AZURE_BLOB_STORAGE", "AZUREBLOB", "BLOB", "ADLS", "ADLS_GEN2", "AZURE_STORAGE"}

# OBJECT_TYPE values -> canonical engine name for database scans. The Azure-managed engines
# (Azure Database for PostgreSQL / MySQL Flexible Server, Azure SQL, Cosmos DB for MongoDB) are
# ordinary wire-protocol databases to the scanner, so they alias the existing connectors.
DB_OBJECT_TYPES = {
    "MONGO": "mongo",
    "MONGODB": "mongo",
    "DOCUMENTDB": "mongo",
    "POSTGRES": "postgres",
    "POSTGRESQL": "postgres",
    "MYSQL": "mysql",
    "MARIADB": "mariadb",
    "MSSQL": "mssql",
    "SQLSERVER": "mssql",
    "AZURE_POSTGRES": "postgres",
    "AZURE_POSTGRESQL": "postgres",
    "AZURE_MYSQL": "mysql",
    "AZURE_SQL": "mssql",
    "AZURE_MSSQL": "mssql",
    "AZURE_SQL_DATABASE": "mssql",
    "COSMOS_MONGO": "mongo",
    "COSMOSDB_MONGO": "mongo",
    "AZURE_COSMOS_MONGO": "mongo",
}

# OBJECT_TYPE values accepted for Cosmos DB for NoSQL databases
COSMOS_OBJECT_TYPES = {"COSMOS_NOSQL", "COSMOSDB_NOSQL", "COSMOS", "COSMOSDB", "AZURE_COSMOS", "AZURE_COSMOS_NOSQL"}

# OBJECT_TYPE values -> canonical connector for SaaS scans
SAAS_OBJECT_TYPES = {
    "GDRIVE": "gdrive",
    "GOOGLEDRIVE": "gdrive",
    "GOOGLE_DRIVE": "gdrive",
    "GOOGLEWORKSPACE": "gdrive",
    "GOOGLE_WORKSPACE": "gdrive",
    "SALESFORCE": "salesforce",
    "SFDC": "salesforce",
}

UPLOAD_RETRIES = 3
MAX_WORKERS = 2  # objects scanned in parallel when several are configured


def club_findings(raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Club raw findings by detector name and type/category for a file.
    Output schema:
    [
        {
            "name": "Email",
            "type": "PII",
            "confidence": "very_likely",      # highest tier among the clubbed findings
            "finding_values": {
                "[EMAIL_ADDRESS]": "location"
            },
            "total_count": "n"
        }
    ]
    """
    if not raw_findings:
        return []

    grouped: Dict[tuple, Dict[str, Any]] = {}

    for f in raw_findings:
        name = f.get("detector", "Unknown")
        category = f.get("category", "General")
        val = str(f.get("value", ""))
        location = f.get("location", "")

        key = (name, category)
        if key not in grouped:
            grouped[key] = {
                "name": name,
                "type": category,
                "confidence": None,
                "finding_values": {},
                "total_count": 0,
            }
        grouped[key]["confidence"] = max_tier([grouped[key]["confidence"], f.get("confidence")])

        # Aggregated column findings stand for many rows/documents (see src/pipeline/classifier.py)
        grouped[key]["total_count"] += f.get("occurrences", 1)

        # If the same value is found in multiple locations, record them
        if val in grouped[key]["finding_values"]:
            existing_loc = grouped[key]["finding_values"][val]
            if isinstance(existing_loc, list):
                if location not in existing_loc:
                    existing_loc.append(location)
            elif existing_loc != location:
                grouped[key]["finding_values"][val] = [existing_loc, location]
        else:
            grouped[key]["finding_values"][val] = location

    return list(grouped.values())


def post_findings_to_api(api_url: str, zip_path: Path) -> bool:
    """
    HTTP POST request to upload the findings archive to the Artifact API / CSPM Backend.
    Matches:
    curl --location '<CSPM_URL>/api/v1/artifact/?data_type=DSPM&save_to_s3=false&label_id=test' \
         --header 'Authorization: Bearer <ARTIFACT_TOKEN>' \
         --form 'file=@<findings.zip>'
    Retries with backoff; returns True on success.
    """
    if not api_url:
        return False

    if not zip_path.exists():
        logger.error(f"Findings zip file {zip_path} does not exist for upload.")
        return False

    # URL ensuring clean trailing slash before query params
    url = f"{api_url.rstrip('/')}/api/v1/artifact/"
    params = {
        "data_type": "DSPM",
        "save_to_s3": "false",
        "label_id": settings.LABEL_ID or "test",
    }
    headers = {}
    if settings.ARTIFACT_TOKEN:
        headers["Authorization"] = f"Bearer {settings.ARTIFACT_TOKEN}"

    for attempt in range(1, UPLOAD_RETRIES + 1):
        try:
            logger.info(
                f"Sending {zip_path.name} to CSPM Backend: {url} with params {params} "
                f"(attempt {attempt}/{UPLOAD_RETRIES})",
            )
            with open(zip_path, "rb") as zip_file:
                resp = requests.post(
                    url=url,
                    params=params,
                    headers=headers,
                    files={"file": (zip_path.name, zip_file, "application/zip")},
                    timeout=60,
                )

            logger.info(f"Upload response status for {zip_path.name}: {resp.status_code}")
            logger.info(f"Upload response body for {zip_path.name}: {resp.text}")
            if resp.status_code < 300:
                return True
        except Exception as e:
            logger.error(f"Failed to post findings to Artifact API: {str(e)}")

        if attempt < UPLOAD_RETRIES:
            time.sleep(2 * attempt)

    return False


def scan_config() -> Dict[str, Any]:
    """Engine + pipeline configuration from settings (see .env.example)."""
    config = {
        "enabled_regions": settings.ENABLED_REGIONS,
        "log_queries": settings.LOG_QUERIES,
        "entropy_report_uncorroborated": settings.REPORT_TOKEN_LIKE_VALUES,
        "min_confidence": settings.MIN_CONFIDENCE,
        "report_private_ips": settings.REPORT_PRIVATE_IPS,
        "disabled_detectors": list(settings.DISABLED_DETECTORS),
        "allow_list": list(settings.ALLOW_LIST),
        "allow_regex": list(settings.ALLOW_REGEX),
        "aggregation_threshold": settings.AGGREGATION_THRESHOLD,
        "sample_strategy": settings.SAMPLE_STRATEGY,
        "adaptive_sampling": settings.ADAPTIVE_SAMPLING,
        "ner": settings.NER_ENABLED,
    }
    if settings.COLUMN_RATIO is not None:
        config["column_ratio"] = settings.COLUMN_RATIO
    if settings.MIN_COUNT is not None:
        config["min_count"] = settings.MIN_COUNT
    if settings.KEEP_SCANNED_FILES:
        # Every file a connector downloads or exports stays under <OUTPUT_DIR>/scanned (BaseScanner.workdir)
        config["keep_files_dir"] = str(OUTPUT_DIR / "scanned")
    return config


# ---------------------------------------------------------------------------- target helpers
def is_azure_type(normalized_type: str) -> bool:
    return (
        normalized_type in AZURE_BLOB_OBJECT_TYPES
        or normalized_type in COSMOS_OBJECT_TYPES
        or normalized_type.startswith(("AZURE_", "COSMOS"))
    )


def account_id_for(normalized_type: str) -> Optional[str]:
    """The cloud account the findings are attributed to: the Azure subscription for Azure targets, else the AWS account."""
    return settings.AZURE_SUBSCRIPTION_ID if is_azure_type(normalized_type) else settings.AWS_ACCOUNT_ID


def split_azure_target(name: str) -> Tuple[Optional[str], str]:
    """
    An Azure Blob target name -> (account, container). Accepted forms: 'container' (the
    account comes from AZURE_STORAGE_ACCOUNT), 'account/container', or a container URL
    such as https://acct.blob.core.windows.net/container (also Azurite's
    http://127.0.0.1:10000/devstoreaccount1/container).
    """
    if "://" in name:
        parts = urlsplit(name)
        segments = [s for s in parts.path.split("/") if s]
        if ".blob." not in (parts.hostname or "") and len(segments) >= 2:
            return f"{parts.scheme}://{parts.netloc}/{segments[0]}", segments[1]
        return f"{parts.scheme}://{parts.netloc}", segments[0] if segments else ""
    if "/" in name:
        account, container = name.split("/", 1)
        return account or settings.AZURE_STORAGE_ACCOUNT, container.strip("/")
    return settings.AZURE_STORAGE_ACCOUNT, name


# ---------------------------------------------------------------------------- findings file helpers
def _checkpoint(final_json: Dict[str, Any], findings_file: Path) -> None:
    """Rewrites the findings JSON so a run stopped midway leaves a readable partial file."""
    with findings_file.open("w") as f:
        json.dump(final_json, f, indent=4, default=str)


def _record_unit(final_json: Dict[str, Any], findings_file: Path, unit_name: str, findings: List[Dict[str, Any]]) -> None:
    """One entry per scanned unit (table, collection, container, Drive file...), clean ones included with []."""
    final_json["findings"][unit_name] = club_findings(findings)
    final_json["files_scanned"] += 1
    _checkpoint(final_json, findings_file)


def record_object_findings(
    final_json: Dict[str, Any], findings_file: Path, object_key: str, base_resource_id: str,
    raw_findings: List[Dict[str, Any]],
) -> None:
    """
    One entry per parser unit of an object-store object: a workbook yields one entry per
    sheet ("report.xlsx [Employees]", the sheet suffix the parsers append to the object's
    resource id), everything else one entry per object; clean objects are recorded with [].
    Shared by the S3 and Azure Blob loops.
    """
    entries: Dict[str, List[Dict[str, Any]]] = {}
    for finding in raw_findings:
        resource_id = str(finding.get("resource_id", ""))
        suffix = resource_id[len(base_resource_id):] if base_resource_id and resource_id.startswith(base_resource_id) else ""
        entry = f"{object_key}{suffix}" if suffix.startswith(" [") and suffix.endswith("]") else object_key
        entries.setdefault(entry, []).append(finding)
    if not entries:
        entries[object_key] = []
    for entry, entry_findings in entries.items():
        final_json["findings"][entry] = club_findings(entry_findings)
    final_json["files_scanned"] += 1
    _checkpoint(final_json, findings_file)


def _scan_errors(scanner: Any, label: str) -> Optional[str]:
    """The error summary line for a finished scanner, naming the failed units when it recorded them."""
    count = scanner.stats.get("errors", 0)
    if not count:
        return None
    details = scanner.stats.get("error_details") or []
    suffix = ": " + "; ".join(details[:10]) if details else ", see logs"
    return f"{count} error(s) during {label} scan{suffix}"


def process_bucket(bucket_name: str, object_type: str = "s3", object_region: str = None) -> Dict[str, Any]:
    """
    Process scan for a single target: an S3 bucket, an Azure Blob container, a database
    (including Cosmos DB) or a SaaS tenant.
    """
    logger.info(f"Starting scan for object: {bucket_name} (type: {object_type})")

    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)

    errors = []
    config = scan_config()
    if config.get("keep_files_dir"):
        logger.warning(
            f"KEEP_SCANNED_FILES is on: every scanned file is kept under {config['keep_files_dir']} (local testing only)",
        )

    scan_date = datetime.today().date()
    start_time = datetime.now()

    engine = DetectionEngine(config=config)
    findings_file = FINDINGS_DIR / f"{bucket_name.replace('/', '_')}-{scan_date}.json"

    normalized_type = str(object_type or "").upper()

    final_json = {
        "scan_time": start_time,
        "files_scanned": 0,
        "object_type": object_type,
        "object_name": bucket_name,
        "account_id": account_id_for(normalized_type),
        "time_taken": None,
        "findings": {},
    }

    if normalized_type in S3_OBJECT_TYPES or normalized_type in AZURE_BLOB_OBJECT_TYPES:
        label = "S3" if normalized_type in S3_OBJECT_TYPES else "Azure Blob"
        try:
            if normalized_type in S3_OBJECT_TYPES:
                logger.info(f"Creating S3 Client instance for {bucket_name}")
                # Static keys if provided; falls back to instance profile / IRSA when unset
                client_kwargs = {
                    "aws_secret_access_key": settings.AWS_SECRET_ACCESS_KEY,
                    "aws_access_key_id": settings.AWS_ACCESS_KEY_ID,
                    "service_name": "s3",
                }
                if object_region:
                    client_kwargs["region_name"] = object_region

                s3_client = boto3.client(**client_kwargs)
                store_scanner = S3Scanner(engine, config, s3_client)
                target = {"bucket": bucket_name}
            else:
                account, container = split_azure_target(bucket_name)
                logger.info(f"Creating Azure Blob scanner instance for {account}/{container}")
                # Credentials: the identity chain unless a connection string / SAS / key is configured
                target = {
                    "account": account,
                    "container": container,
                    "endpoint_suffix": settings.AZURE_STORAGE_ENDPOINT_SUFFIX,
                    "connection_string": settings.AZURE_STORAGE_CONNECTION_STRING,
                    "sas_token": settings.AZURE_STORAGE_SAS_TOKEN,
                    "account_key": settings.AZURE_STORAGE_ACCOUNT_KEY,
                }
                store_scanner = AzureBlobScanner(engine, config)

            # One entry per object (per sheet for workbooks), clean ones included, checkpointed after each
            for resource_id, object_key, raw_findings in store_scanner.iter_scan(target):
                record_object_findings(final_json, findings_file, object_key, resource_id, raw_findings)

            error = _scan_errors(store_scanner, label)
            if error:
                errors.append(error)
                logger.error(error)
        except Exception as e:
            errors.append(f"{label} scan failed: {str(e)}")
            logger.error(errors[-1])

    elif normalized_type in DB_OBJECT_TYPES:
        engine_name = DB_OBJECT_TYPES[normalized_type]
        try:
            logger.info(f"Creating {engine_name} scanner instance for {bucket_name}")
            target = {
                "engine": engine_name,
                "host": settings.DB_HOST,
                "port": settings.DB_PORT,
                "username": settings.DB_USERNAME,
                "password": settings.DB_PASSWORD,
                "database": bucket_name,
                "sample_limit": settings.SAMPLE_LIMIT,
            }
            if settings.DB_AUTH and settings.DB_AUTH != "password":
                target["auth"] = settings.DB_AUTH  # azure_entra: the scanner identity's token is the password

            # DB_URI-only setups: derive the host so findings carry the real
            # resource id instead of 'localhost'
            if settings.DB_URI and not target["host"]:
                try:
                    target["host"] = urlsplit(settings.DB_URI).hostname
                except ValueError:
                    pass

            if engine_name == "mongo":
                if settings.DB_URI:
                    target["uri"] = settings.DB_URI
                db_scanner = MongoScanner(engine, config)
            else:
                if settings.DB_URI:
                    target["connection_string"] = settings.DB_URI
                db_scanner = SQLScanner(engine, config)

            # A table/collection is the database counterpart of an S3 object: one entry
            # per relation (schema-qualified) or collection, clean ones included, checkpointed
            # after each just like the per-object loop above
            for _resource_id, relation_name, relation_findings in db_scanner.iter_scan(target):
                _record_unit(final_json, findings_file, relation_name, relation_findings)

            # Name the relations that were not scanned so the gap is visible in the findings file
            error = _scan_errors(db_scanner, engine_name)
            if error:
                errors.append(error)
                logger.error(error)
        except Exception as e:
            errors.append(f"{engine_name} scan failed: {str(e)}")
            logger.error(errors[-1])

    elif normalized_type in COSMOS_OBJECT_TYPES:
        try:
            logger.info(f"Creating Cosmos DB scanner instance for {bucket_name}")
            target = {
                "endpoint": settings.AZURE_COSMOS_ENDPOINT,
                "key": settings.AZURE_COSMOS_KEY,
                "database": bucket_name,
                "sample_limit": settings.SAMPLE_LIMIT,
            }
            cosmos_scanner = CosmosNoSQLScanner(engine, config)

            # One entry per container, clean ones included, checkpointed after each
            for _resource_id, container_name, container_findings in cosmos_scanner.iter_scan(target):
                _record_unit(final_json, findings_file, container_name, container_findings)

            error = _scan_errors(cosmos_scanner, "Cosmos DB")
            if error:
                errors.append(error)
                logger.error(error)
        except Exception as e:
            errors.append(f"Cosmos DB scan failed: {str(e)}")
            logger.error(errors[-1])

    elif normalized_type in SAAS_OBJECT_TYPES:
        connector = SAAS_OBJECT_TYPES[normalized_type]
        try:
            logger.info(f"Creating {connector} scanner instance for {bucket_name}")
            if connector == "gdrive":
                target = {
                    "sa_key_file": settings.GOOGLE_SA_KEY_FILE,
                    "impersonate_user": settings.GOOGLE_IMPERSONATE_USER,
                    "drive_id": settings.GOOGLE_DRIVE_ID,
                    "sample_limit": settings.SAMPLE_LIMIT,
                }
                # OBJECT_NAME names the drive when the GOOGLE_* vars are unset:
                # a user email (My Drive via domain-wide delegation) or a shared-drive id
                if not target["impersonate_user"] and not target["drive_id"]:
                    if "@" in bucket_name:
                        target["impersonate_user"] = bucket_name
                    else:
                        target["drive_id"] = bucket_name
                saas_scanner = GoogleDriveScanner(engine, config)
            else:
                target = {
                    "domain": settings.SF_DOMAIN or bucket_name,
                    "consumer_key": settings.SF_CONSUMER_KEY,
                    "consumer_secret": settings.SF_CONSUMER_SECRET,
                    "api_version": settings.SF_API_VERSION,
                    "objects": settings.SF_OBJECTS or None,
                    "include_files": settings.SF_INCLUDE_FILES,
                    "sample_limit": settings.SAMPLE_LIMIT,
                }
                saas_scanner = SalesforceScanner(engine, config)

            # One entry per Drive file / sObject / attached file, clean ones included,
            # checkpointed after each just like the object-store and DB loops above
            for _resource_id, unit_name, unit_findings in saas_scanner.iter_scan(target):
                _record_unit(final_json, findings_file, unit_name, unit_findings)

            error = _scan_errors(saas_scanner, connector)
            if error:
                errors.append(error)
                logger.error(error)
        except Exception as e:
            errors.append(f"{connector} scan failed: {str(e)}")
            logger.error(errors[-1])

    else:
        errors.append(f"Unsupported object type '{object_type}' for {bucket_name}")
        logger.error(errors[-1])

    end_time = datetime.now()
    final_json["time_taken"] = str(end_time - start_time)
    final_json["errors"] = errors

    _checkpoint(final_json, findings_file)

    logger.info(f"Time taken for scanning {bucket_name}: {end_time - start_time}")

    # Zip findings file
    logger.info(f"Zipping findings for {bucket_name} before sending to Artifact API")
    zip_file = findings_file.with_suffix(".zip")

    with zipfile.ZipFile(
        zip_file,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zipf:
        if findings_file.exists():
            zipf.write(findings_file, arcname=findings_file.name)

    # Post results to the Artifact API if configured
    api_url = settings.CSPM_URL
    if api_url:
        if not post_findings_to_api(api_url, zip_file):
            errors.append("findings upload to CSPM Backend failed")
            logger.error(f"Upload failed for {bucket_name}; findings kept locally at {findings_file}")
    else:
        logger.warning(f"CSPM_URL is not configured; findings kept locally at {findings_file}")

    # The JSON stays in FINDINGS_DIR as the local record; the archive is only the upload vehicle
    try:
        if zip_file.exists():
            zip_file.unlink(missing_ok=True)
            logger.info(f"Successfully removed ZIP file after upload attempt: {zip_file}")
    except Exception as e:
        logger.error(f"Failed to remove ZIP file {zip_file}: {str(e)}")

    return {
        "object_name": bucket_name,
        "object_type": object_type,
        "status": "success" if not errors else "error",
        "files_scanned": final_json["files_scanned"],
        "errors": errors,
    }


def parse_objects_to_scan() -> Dict[str, str]:
    """
    Parse the target objects and their types from environment variables.
    Supports JSON formats in OBJECTS_TO_SCAN, or fallback to OBJECT_NAME and OBJECT_TYPE.
    Example: {"bucket1": "s3", "bucket2": "s3"}
    """
    raw_env = settings.OBJECTS_TO_SCAN
    if not raw_env:
        raw_env = settings.OBJECT_NAME

    if raw_env:
        try:
            parsed = json.loads(raw_env)
            if isinstance(parsed, dict):
                return parsed
            elif isinstance(parsed, list):
                return {item: settings.OBJECT_TYPE or "s3" for item in parsed}
        except (json.JSONDecodeError, TypeError):
            pass

    # Fallback to single object if configured
    if settings.OBJECT_NAME:
        return {settings.OBJECT_NAME: settings.OBJECT_TYPE or "s3"}

    return {}


def lambda_handler(event: Dict[str, Any] = None, context: Any = None) -> Dict[str, Any]:
    """
    Handler entry point: scans every configured object, MAX_WORKERS at a time.
    """
    objects_dict = parse_objects_to_scan()
    if not objects_dict:
        logger.warning("No objects found to scan.")
        return {
            "statusCode": 200,
            "body": json.dumps({
                "status": "success",
                "message": "No objects to scan",
                "results": [],
            }),
        }

    # The Artifact API attributes object-store findings to a cloud account: the AWS account for S3
    # buckets, the Azure subscription for Blob containers. Database targets don't need one.
    s3_targets = [name for name, obj_type in objects_dict.items() if str(obj_type).upper() in S3_OBJECT_TYPES]
    if s3_targets and not settings.AWS_ACCOUNT_ID:
        logger.error("AWS Account ID is not configured. Please configure it in settings.py")
        return {
            "statusCode": 400,
            "body": json.dumps({
                "status": "failed",
                "error": "AWS Account ID is not configured. Please configure it in settings.py",
            }),
        }
    blob_targets = [name for name, obj_type in objects_dict.items() if str(obj_type).upper() in AZURE_BLOB_OBJECT_TYPES]
    if blob_targets and not settings.AZURE_SUBSCRIPTION_ID:
        logger.error("AZURE_SUBSCRIPTION_ID is not configured; it is required for Azure Blob targets")
        return {
            "statusCode": 400,
            "body": json.dumps({
                "status": "failed",
                "error": "AZURE_SUBSCRIPTION_ID is not configured; it is required for Azure Blob targets",
            }),
        }

    logger.info(f"Target objects to scan: {objects_dict}")
    results = []

    # If only 1 object, process directly without spawning process pool overhead
    if len(objects_dict) == 1:
        obj_name, obj_type = next(iter(objects_dict.items()))
        results.append(process_bucket(obj_name, obj_type, settings.OBJECT_REGION))
    else:
        # Multiprocessing: process MAX_WORKERS objects at a time
        logger.info(f"Launching multiprocessing pool with max_workers={MAX_WORKERS}")
        with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(process_bucket, obj_name, obj_type, settings.OBJECT_REGION): obj_name
                for obj_name, obj_type in objects_dict.items()
            }
            for future in as_completed(futures):
                obj_name = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    logger.error(f"Scanning {obj_name} generated an exception: {exc}")
                    results.append({
                        "object_name": obj_name,
                        "status": "failed",
                        "error": str(exc),
                    })

    failed = [r for r in results if r.get("status") != "success"]
    return {
        "statusCode": 200 if not failed else 500,
        "body": json.dumps({
            "status": "success" if not failed else "error",
            "results": results,
        }),
    }


# Run-once mode when executed directly (python -m src.dspm_scanner_worker_handler,
# as the container CMD does). Importing the module never starts a scan: the Lambda
# runtime imports it under its real module name, so __name__ is never "__main__".
if __name__ == "__main__":
    result = lambda_handler(None, None)
    sys.exit(0 if result.get("statusCode") == 200 else 1)
