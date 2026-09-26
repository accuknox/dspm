"""
Master (Lambda) handler routing for the Azure scan types, secret resolution through
Azure Key Vault, and the identity helpers. Scanners and HTTP are patched; nothing
talks to Azure.
"""
import json
import os
from unittest.mock import MagicMock, patch

import src.dspm_scanner_master_handler as master
from src.utils import azure as azure_utils


def _routed(scan_type, target, scanner_attr):
    scanner = MagicMock()
    scanner.scan.return_value = [{"detector": "Email"}]
    with patch.object(master, "DetectionEngine"), patch.object(master, scanner_attr, return_value=scanner):
        findings = master.process_single_event({"scan_type": scan_type, "target": dict(target), "config": {}})
    return findings, scanner


def test_master_routes_azure_scan_types():
    findings, scanner = _routed("azure_blob", {"account": "acct", "container": "uploads", "blob": "a.csv"}, "AzureBlobScanner")
    assert findings == [{"detector": "Email"}] and scanner.scan.call_args.args[0]["container"] == "uploads"
    _, scanner = _routed("cosmos", {"account": "acct", "database": "appdb"}, "CosmosNoSQLScanner")
    assert scanner.scan.call_args.args[0]["database"] == "appdb"
    _, scanner = _routed("azure_postgres", {"host": "h.postgres.database.azure.com", "database": "appdb"}, "SQLScanner")
    assert scanner.scan.call_args.args[0]["engine"] == "postgres"
    _, scanner = _routed("azure_sql", {"host": "h.database.windows.net", "database": "appdb"}, "SQLScanner")
    assert scanner.scan.call_args.args[0]["engine"] == "mssql"
    _, scanner = _routed("cosmos_mongo", {"uri": "mongodb://acct:key@acct.mongo.cosmos.azure.com:10255/?ssl=true"}, "MongoScanner")
    assert scanner.scan.call_args.args[0]["uri"].startswith("mongodb://")


def test_master_resolves_secrets_from_key_vault_or_secrets_manager():
    vault_uri = "https://dspm-kv.vault.azure.net/secrets/appdb"
    with patch.object(master, "get_keyvault_secret", return_value={"username": "u", "password": "p"}) as kv, \
            patch.object(master, "get_secret") as sm:
        target = master.resolve_db_credentials({"password_secret": vault_uri, "host": "h"})
    assert (target["username"], target["password"], target["host"]) == ("u", "p", "h")
    kv.assert_called_once_with(vault_uri)
    sm.assert_not_called()

    with patch.object(master, "get_keyvault_secret") as kv, \
            patch.object(master, "get_secret", return_value={"key": "cosmos-key"}) as sm:
        target = master.resolve_db_credentials({"password_secret": "arn:aws:secretsmanager:us-east-1:123:secret:cosmos"})
    assert target["key"] == "cosmos-key"
    kv.assert_not_called()
    sm.assert_called_once()


def test_keyvault_secret_is_read_with_the_scanner_identity():
    assert azure_utils.is_keyvault_uri("https://dspm-kv.vault.azure.net/secrets/appdb/abc123")
    assert azure_utils.is_keyvault_uri("https://kv.vault.usgovcloudapi.net/secrets/x")
    assert not azure_utils.is_keyvault_uri("arn:aws:secretsmanager:us-east-1:123:secret:x")
    assert not azure_utils.is_keyvault_uri("https://kv.vault.azure.net/keys/x")
    assert not azure_utils.is_keyvault_uri(None)

    credential = MagicMock()
    credential.get_token.return_value.token = "jwt"
    response = MagicMock(status_code=200)
    response.json.return_value = {"value": json.dumps({"username": "u", "password": "p"})}
    with patch.object(azure_utils, "default_credential", return_value=credential), \
            patch.object(azure_utils.requests, "get", return_value=response) as get:
        assert azure_utils.get_keyvault_secret("https://dspm-kv.vault.azure.net/secrets/appdb") == {"username": "u", "password": "p"}
    assert credential.get_token.call_args.args == ("https://vault.azure.net/.default",)
    assert get.call_args.args == ("https://dspm-kv.vault.azure.net/secrets/appdb",)
    assert get.call_args.kwargs["params"] == {"api-version": "7.4"}
    assert get.call_args.kwargs["headers"] == {"Authorization": "Bearer jwt"}

    # a plain-string secret is the password; failures give {} like Secrets Manager
    response.json.return_value = {"value": "s3cret"}
    with patch.object(azure_utils, "default_credential", return_value=credential), \
            patch.object(azure_utils.requests, "get", return_value=response):
        assert azure_utils.get_keyvault_secret("https://dspm-kv.vault.azure.net/secrets/appdb") == {"password": "s3cret"}
    with patch.object(azure_utils, "default_credential", return_value=credential), \
            patch.object(azure_utils.requests, "get", return_value=MagicMock(status_code=403)):
        assert azure_utils.get_keyvault_secret("https://dspm-kv.vault.azure.net/secrets/appdb") == {}


def test_default_credential_is_headless_and_selects_user_assigned_identities():
    with patch.object(azure_utils, "DefaultAzureCredential") as cred_cls, \
            patch.dict(os.environ, {"AZURE_CLIENT_ID": "mi-client"}, clear=False):
        os.environ.pop("AZURE_CLIENT_SECRET", None)
        os.environ.pop("AZURE_FEDERATED_TOKEN_FILE", None)
        azure_utils.default_credential()
    assert cred_cls.call_args.kwargs == {
        "exclude_interactive_browser_credential": True,
        "exclude_shared_token_cache_credential": True,
        "managed_identity_client_id": "mi-client",
    }
    # a service principal (client id + secret) is not a managed identity
    with patch.object(azure_utils, "DefaultAzureCredential") as cred_cls, \
            patch.dict(os.environ, {"AZURE_CLIENT_ID": "sp", "AZURE_CLIENT_SECRET": "s"}, clear=False):
        azure_utils.default_credential()
    assert "managed_identity_client_id" not in cred_cls.call_args.kwargs


def test_entra_token_becomes_the_password_of_every_connection():
    from sqlalchemy import create_engine

    from src.scanners.db.sql import SQLScanner

    credential = MagicMock()
    credential.get_token.return_value.token = "entra-jwt"
    provide_token = SQLScanner(MagicMock())._use_entra_tokens(create_engine("sqlite://"))
    cparams = {"user": "dspm-scanner-vm"}
    with patch.object(azure_utils, "default_credential", return_value=credential):
        provide_token(None, None, [], cparams)
    assert cparams["password"] == "entra-jwt"
    assert credential.get_token.call_args.args == ("https://ossrdbms-aad.database.windows.net/.default",)
