# Supported File Extensions

## 1. Dedicated / Explicitly Supported File Extensions

| Category                | Extensions                                       | Format Description          | Processing Engine / Library                 |
| ----------------------- | ------------------------------------------------ | --------------------------- | ------------------------------------------- |
| **Columnar / Tabular**  | `.csv`, `.tsv`                                   | Comma-/Tab-Separated Values | `pandas` (streamed in chunks of 5,000 rows) |
|                         | `.parquet`                                       | Apache Parquet              | `fastparquet` / `pandas`                    |
|                         | `.xls`, `.xlsx`                                  | Microsoft Excel Sheets      | `pandas.ExcelFile` (parsed per sheet)       |
| **Structured / Record** | `.json`                                          | JSON Objects & Arrays       | `ijson` (streaming parser)                  |
|                         | `.jsonl`, `.ndjson`                              | JSON Lines / NDJSON         | Streaming line parser                       |
|                         | `.xml`                                           | XML Documents               | `lxml.etree` (streamed `iterparse`)         |
| **Documents**           | `.pdf`                                           | Adobe PDF Documents         | `pypdf` (page-by-page text extraction)      |
|                         | `.doc`, `.docx`                                  | Microsoft Word Documents    | `python-docx` (paragraph extraction)        |
| **Images (OCR)**        | `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.tiff` | Image Files                 | `Pillow` + `pytesseract` OCR                |
| **Archives**            | `.zip`, `.tar`, `.gz`, `.tgz`, `.bz2`            | Archive Files (recursive)   | `zipfile`, `tarfile`, `gzip`, `bz2`         |

---

## 2. General / Plain Text Support (Fallback)

Any file extension **not listed in the dedicated parsers** is processed as **plain text**.

The system scans UTF-8 text in blocks of **1,000 lines**, while maintaining **exact line and column tracking**.

### Plain Text / Documents

* `.txt`
* `.md`
* `.rst`
* `.rtf`
* `.log`

### Configuration & Infrastructure

* `.yaml`
* `.yml`
* `.env`
* `.ini`
* `.conf`
* `.toml`
* `.tf`
* `.hcl`
* `.properties`

### Source Code / Scripts

* `.py`
* `.js`
* `.ts`
* `.sql`
* `.sh`
* `.ps1`
* `.html`
* `.css`
* `.c`
* `.cpp`
* `.java`
* `.go`
* `.rb`
* *etc.*

### Fallback Processing Behavior

> **Any unsupported or unrecognized file extension is treated as UTF-8 plain text and processed using block-based scanning with exact line/column tracking.**
