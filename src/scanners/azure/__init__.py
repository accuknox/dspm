"""
Azure connectors: Blob Storage / ADLS Gen2 (src/scanners/azure/blob.py) and Cosmos DB
for NoSQL (src/scanners/azure/cosmos.py). Azure Database for PostgreSQL / MySQL, Azure
SQL and Cosmos DB for MongoDB are ordinary wire-protocol databases to the scanner and
use src/scanners/db through the worker's OBJECT_TYPE aliases.
"""
from src.scanners.azure.blob import AzureBlobScanner
from src.scanners.azure.cosmos import CosmosNoSQLScanner

__all__ = ["AzureBlobScanner", "CosmosNoSQLScanner"]
