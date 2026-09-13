DSPM architecture: current implementation and proposed extensions.

![Project DSPM architecture](architecture.png)

Download the [PNG diagram](architecture.png) or [editable SVG](architecture.svg). The detailed Mermaid source and code map follow below.

Blue components are implemented in this repository. Grey components are external systems. Orange components and dotted connections represent proposed work. Arrows show logical data flow; `UnitClassifier` calls `DetectionEngine` for each cell or text blob during execution.

The current accuracy priority is reducing false alarms. Identity context is scoped to the same row or containing object, with array members kept separate. Weak numeric candidates require stronger evidence before promotion.

```mermaid
flowchart TB
    sources["DATA SOURCES<br/>AWS: S3, DynamoDB, RDS / Aurora<br/>Databases: PostgreSQL, MySQL / MariaDB, MSSQL, MongoDB / DocumentDB<br/>SaaS: Google Drive, Salesforce"]

    subgraph scanner["CURRENT SCANNER — IMPLEMENTED"]
        direction TB
        entry["SCAN ENTRY POINTS<br/>Worker: configured targets and scheduled runs<br/>Master: invocation, SQS, S3 events, DynamoDB Streams"]
        connectors["CONNECTOR ADAPTERS<br/>Authenticate, enumerate resources, read selected data"]
        extraction["EXTRACTION AND SAMPLING<br/>Database rows and nested documents<br/>CSV, Excel, Parquet, JSON, XML, PDF, Office, images / OCR, archives"]
        records["NORMALIZED INPUT<br/>Record / Cell / TextBlob<br/>Resource, field path, source location"]
        engine["DETECTION ENGINE<br/>Patterns, regional IDs and checksum validation<br/>PII, financial data, healthcare, credentials and entropy checks<br/>Optional spaCy NER; base64 and JWT inspection"]
        classifier["UNIT CLASSIFIER<br/>Field policies, allow lists and scoped identity context<br/>Stronger evidence for weak numeric candidates<br/>Cell-based column density and overlap handling<br/>Confidence tiers, count rules and aggregation"]
        findings["PIPELINE FINDINGS<br/>Detector, category, severity, value and location<br/>Confidence, evidence, value hash and column statistics"]
        delivery["RESULT DELIVERY<br/>Worker: grouped local JSON and optional ZIP upload<br/>Master: response and optional JSON upload"]

        entry --> connectors --> extraction --> records --> engine
        engine -->|"possible-and-above candidates"| classifier
        classifier --> findings --> delivery
    end

    sources -->|"content read by adapters"| connectors
    backend["EXTERNAL CSPM BACKEND<br/>Receives findings when configured"]
    delivery -->|"optional API upload"| backend

    tests["OFFLINE QUALITY CHECKS — IMPLEMENTED<br/>Detector and pipeline regression tests<br/>Fully labelled synthetic cases; precision / recall / F1"]
    tests -->|"validates"| engine
    tests -->|"validates"| classifier

    subgraph proposed["PROPOSED DSPM CAPABILITIES"]
        direction TB
        coverage["SCAN COVERAGE REGISTRY<br/>Complete, sampled, partial, skipped or failed<br/>Rows / bytes examined; parser and model availability"]
        semantic["SELECTIVE SEMANTIC CLASSIFICATION<br/>Document meaning and proprietary data<br/>Bounded private inference with supporting evidence"]
        access["ACCESS AND EXPOSURE COLLECTORS<br/>IAM policies, database grants, SaaS sharing<br/>Existing CSPM / CIEM context where available"]
        riskGraph["DATA AND IDENTITY RISK GRAPH<br/>Sensitive resources, effective access and exposure<br/>Business impact and risk prioritization"]
        actions["PRODUCT AND REMEDIATION<br/>Inventory, ownership and explanations<br/>Prioritized alerts and remediation workflows"]
        review["REVIEW AND CALIBRATION<br/>Reviewed findings and representative held-out data<br/>Versioned policies and quality thresholds"]
    end

    extraction -.->|"inspection coverage"| coverage
    records -.->|"selected content and metadata"| semantic
    semantic -.->|"semantic evidence"| classifier
    sources -.->|"permissions and sharing metadata"| access
    backend -.->|"available posture context"| access
    findings -.->|"versioned findings and evidence"| riskGraph
    coverage -.-> riskGraph
    access -.-> riskGraph
    riskGraph -.-> actions
    actions -.->|"review decisions"| review
    review -.->|"labelled evaluation cases"| tests

    classDef implemented fill:#eaf3ff,stroke:#2563eb,color:#102a43,stroke-width:1.5px;
    classDef external fill:#f1f5f9,stroke:#64748b,color:#243447;
    classDef planned fill:#fff7e6,stroke:#d97706,color:#713f12,stroke-width:1.5px,stroke-dasharray:6 4;
    class entry,connectors,extraction,records,engine,classifier,findings,delivery,tests implemented;
    class sources,backend external;
    class coverage,semantic,access,riskGraph,actions,review planned;
    style scanner fill:#f8fbff,stroke:#93b4e5,color:#102a43;
    style proposed fill:#fffcf5,stroke:#e7b668,color:#713f12,stroke-dasharray:6 4;
```

The current engine follows these boundaries in code:

| Component | Implementation |
|---|---|
| Scan entry points | [Worker](../src/dspm_scanner_worker_handler.py), [master handler](../src/dspm_scanner_master_handler.py) |
| Connector contract | [BaseScanner](../src/scanners/base.py) and adapters under `src/scanners/` |
| Parsing and normalized input | [File parsers](../src/scanners/files/parsers.py), [Record / Cell / TextBlob](../src/pipeline/records.py) |
| Candidate detection | [DetectionEngine](../src/engine/detector.py), [layers](../src/engine/layers.py), [recognizers](../src/engine/recognizers/) |
| Context and statistical classification | [UnitClassifier](../src/pipeline/classifier.py), [column profiles](../src/pipeline/columns.py), [sampling](../src/pipeline/sampling.py) |
| Accuracy checks | [Test runner](../run_tests.py), [labelled-case evaluator](../scripts/evaluate_accuracy.py) |

DynamoDB scans are currently exposed through the master handler. The worker groups results before export and currently omits pipeline evidence and column statistics from that grouped output. Preserving those fields requires the proposed versioned findings contract. Coverage and risk nodes describe future components; the current sampling stop rule does not establish that unread data is clean.

The proposed components and their priorities are explained in the [competitive assessment](dspm-competitive-assessment.md).
