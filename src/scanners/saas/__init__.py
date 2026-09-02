"""
SaaS connectors (Google Workspace Drive, Salesforce).

Like every connector, they only enumerate units and stream Records/TextBlobs
or downloaded files into the shared pipeline (src/scanners/base.py); all
classification logic lives in src/pipeline and src/engine.
"""
