import re
import time
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import quote_plus

# Conditional import for soft failures
try:
    from pymongo import MongoClient
    from pymongo.errors import OperationFailure
except ImportError:
    MongoClient = None
    OperationFailure = None

from src.pipeline.records import Record, document_record
from src.scanners.base import BaseScanner
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Databases that hold engine internals rather than user data
SYSTEM_DATABASES = {"admin", "local", "config"}

# Cosmos DB for MongoDB answers "request rate too large" with this code (HTTP 429 underneath) and
# a RetryAfterMs hint; the head strategy resumes the read from the last document seen
THROTTLED_CODE = 16500
THROTTLE_RETRIES = 8
_RETRY_AFTER_MS = re.compile(r"RetryAfterMs=(\d+)")


class MongoScanner(BaseScanner):
    """
    Scans MongoDB (and API-compatible stores like DocumentDB and Cosmos DB for
    MongoDB) for sensitive data.
    Discovers databases and collections dynamically, then streams documents as
    Records (one Cell per scalar leaf, dotted field paths as context) into the
    classification pipeline.
    """

    def __init__(self, engine, config: Dict[str, Any] = None, client=None):
        super().__init__(engine, config, client)
        self.stats = {"collections_scanned": 0, "documents_scanned": 0, "errors": 0}

    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scans every collection and returns all findings.
        See iter_scan for the target structure and per-collection results.
        """
        findings = []
        for _resource_id, _collection_name, collection_findings in self.iter_scan(target):
            findings.extend(collection_findings)
        return findings

    def iter_scan(self, target: Dict[str, Any]) -> Iterator[Tuple[str, str, List[Dict[str, Any]]]]:
        """
        Scans one collection at a time, yielding
        (resource_id, collection_name, findings) as each collection finishes —
        the database counterpart of scanning an S3 bucket object by object.
        collection_name is relative to the target: 'users' when the target pins
        a database, 'appdb.users' otherwise. Every visited collection is
        yielded, with an empty list when it is clean, and findings are
        deduplicated per collection.

        Target structure:
        {
            "uri": "mongodb://user:pass@host:27017/?authSource=admin", # optional, overrides the fields below # pragma: allowlist secret
            "host": "mongo.internal.example.com",
            "port": 27017,
            "username": "scanner",
            "password": "dbpassword", # pragma: allowlist secret
            "database": "appdb",           # optional, all non-system databases if omitted
            "collection": "users",         # optional, all collections if omitted
            "incremental_field": "updated_at",        # optional field for incremental scans
            "last_scan_time": "2026-08-01T00:00:00",  # optional, used with incremental_field
            "sample_limit": 10000,         # optional, max documents per collection
            "sample_strategy": "head"      # optional: "head" (first documents) or "random" ($sample)
        }
        """
        host = target.get("host") or "localhost"
        client = self.client
        owns_client = client is None

        if owns_client:
            if not MongoClient:
                self.stats["errors"] += 1
                logger.warning("pymongo is not installed. Skipping MongoDB scan.")
                return
            uri = target.get("uri") or self._build_uri(target)
            try:
                client = MongoClient(uri, serverSelectionTimeoutMS=self.config.get("connect_timeout", 10) * 1000)
            except Exception as e:
                self.stats["errors"] += 1
                logger.error(f"Failed to connect to MongoDB at {host}: {str(e)}")
                return

        logger.info(f"Starting MongoDB scan for mongodb://{host}")
        pinned_db = target.get("database")
        try:
            if pinned_db:
                db_names = [pinned_db]
            else:
                db_names = [d for d in client.list_database_names() if d not in SYSTEM_DATABASES]

            for db_name in db_names:
                db = client[db_name]
                try:
                    if target.get("collection"):
                        coll_names = [target["collection"]]
                    else:
                        coll_names = [c for c in db.list_collection_names() if not c.startswith("system.")]
                except Exception as e:
                    self.stats["errors"] += 1
                    logger.error(f"Failed to list collections for database '{db_name}': {str(e)}")
                    continue

                for coll_name in coll_names:
                    collection_findings = self._scan_collection(db, db_name, coll_name, target, host)
                    yield (
                        self._collection_resource_id(host, db_name, coll_name),
                        coll_name if pinned_db else f"{db_name}.{coll_name}",
                        self.dedup_findings(collection_findings),
                    )

        except Exception as e:
            self.stats["errors"] += 1
            self.stats.setdefault("error_details", []).append(f"connect: {str(e)[:200]}")
            logger.error(f"Error scanning MongoDB at {host}: {str(e)}")
        finally:
            if owns_client:
                try:
                    client.close()
                except Exception:
                    pass

    def _throttle_wait(self, error: Exception, retries: int) -> Optional[float]:
        """Seconds to wait before resuming after a Cosmos DB throttle; None for any other error or when retries are spent."""
        if OperationFailure is None or not isinstance(error, OperationFailure):
            return None
        if getattr(error, "code", None) != THROTTLED_CODE or retries >= THROTTLE_RETRIES:
            return None
        match = _RETRY_AFTER_MS.search(str(error))
        if match:
            return max(int(match.group(1)) / 1000.0, 0.1)
        return float(min(2 ** retries, 30))

    def _collection_resource_id(self, host: str, db_name: str, coll_name: str) -> str:
        return f"mongodb://{host}/{db_name}/{coll_name}"

    def _build_uri(self, target: Dict[str, Any]) -> str:
        host = target.get("host") or "localhost"
        port = target.get("port") or 27017
        username = target.get("username")
        password = target.get("password")
        auth = ""
        if username:
            auth = quote_plus(str(username))
            if password:
                auth += f":{quote_plus(str(password))}"
            auth += "@"
        uri = f"mongodb://{auth}{host}:{port}/"
        # A replica set reached through a port-forward / SSH tunnel advertises
        # cluster-internal member hostnames that do not resolve here; talk to
        # the one address we were given instead of discovering the topology.
        direct = target.get("direct_connection", self.config.get("direct_connection"))
        if direct is None:
            direct = str(host).lower() in ("localhost", "127.0.0.1", "::1")
        if direct:
            uri += "?directConnection=true"
        return uri

    def _scan_collection(
        self, db: Any, db_name: str, coll_name: str,
        target: Dict[str, Any], host: str,
    ) -> List[Dict[str, Any]]:
        resource_id = self._collection_resource_id(host, db_name, coll_name)
        logger.info(f"Scanning collection {db_name}.{coll_name}")

        # Incremental scanning: only documents changed since the last scan
        query = {}
        inc_field = target.get("incremental_field")
        last_scan_time = target.get("last_scan_time")
        if inc_field and last_scan_time:
            # BSON comparisons are type-bracketed: an ISO string never matches a
            # Date field, so parse strings into datetimes (raw value kept if unparseable)
            if isinstance(last_scan_time, str):
                try:
                    last_scan_time = datetime.fromisoformat(last_scan_time.replace("Z", "+00:00"))
                except ValueError:
                    pass
            query = {inc_field: {"$gt": last_scan_time}}

        sample_limit = target.get("sample_limit", 10000)
        batch_size = self.config.get("chunk_size", 1000)
        strategy = str(target.get("sample_strategy") or self.config.get("sample_strategy") or "head").lower()

        if self.config.get("log_queries"):
            if strategy == "random":
                logger.info(f"Executing aggregate on {db_name}.{coll_name}: $match {query} -> $sample {{size: {sample_limit}}}")
            else:
                logger.info(
                    f"Executing query on {db_name}.{coll_name}: "
                    f"find({query}, batch_size={batch_size}).limit({sample_limit})",
                )

        def cursor_from(skip: int):
            if strategy == "random":
                # $sample is a random draw over the whole collection (Wiz-style statistical sampling)
                pipeline = ([{"$match": query}] if query else []) + [{"$sample": {"size": sample_limit}}]
                return db[coll_name].aggregate(pipeline, batchSize=batch_size)
            cursor = db[coll_name].find(query, batch_size=batch_size)
            if skip:
                cursor = cursor.skip(skip)
            return cursor.limit(max(sample_limit - skip, 0) if sample_limit else 0)

        def documents() -> Iterator[Record]:
            doc_count = 0
            retries = 0
            try:
                while True:
                    if sample_limit and doc_count >= sample_limit:
                        return
                    try:
                        for doc_idx, doc in enumerate(cursor_from(doc_count), start=doc_count):
                            doc_id = doc.get("_id", f"index {doc_idx}") if isinstance(doc, dict) else f"index {doc_idx}"
                            # The dotted field path is context for the engine (headers.authorization,
                            # request.body, labels...), never part of the scanned text
                            yield document_record(
                                doc,
                                lambda path, d=doc_id: (
                                    f"Database '{db_name}', Collection '{coll_name}', Document _id={d}, Field '{path}'"
                                ),
                            )
                            doc_count += 1
                        return
                    except Exception as e:
                        wait = self._throttle_wait(e, retries)
                        if wait is None or strategy == "random":
                            raise
                        retries += 1
                        logger.warning(
                            f"Cosmos DB throttled {db_name}.{coll_name} (code {THROTTLED_CODE}); "
                            f"retry {retries}/{THROTTLE_RETRIES} in {wait:.1f}s from document {doc_count}",
                        )
                        time.sleep(wait)
            finally:
                self.stats["documents_scanned"] += doc_count

        errors_before = self.stats["errors"]
        findings = self.classify(
            resource_id, documents(),
            location_fn=lambda field, n: f"Database '{db_name}', Collection '{coll_name}', Field '{field}' ({n} matches)",
            unit_name=coll_name,
        )
        if self.stats["errors"] == errors_before:
            self.stats["collections_scanned"] += 1
        return findings
