"""
Per-detector reporting policy - the declarative half of a detector.

The recognizers and layers decide *whether a value matches*; a DetectorPolicy
decides *how a match may be reported*. Every vendor engine we studied separates
the two:

  * Amazon Macie managed data identifiers are a pattern, optional validation and
    a keyword requirement: SSNs, bank account numbers, passports, birth dates and
    AWS secret keys need a keyword within 30 characters - or in the column name /
    any element of the JSON path - while self-describing formats need nothing and
    credit cards exist in a keyword and a no-keyword variant. Custom identifiers
    add ignore words and occurrence thresholds ("if an object contains fewer
    occurrences than the lowest threshold, Macie doesn't create a finding").
  * Microsoft Purview: primary element + supporting elements within a proximity
    window; "use high confidence patterns with low counts, say five to 10, and
    low confidence patterns with higher counts, say 20 or more".
  * Nightfall: minimum confidence and minimum number of findings per detector
    ("how many findings must appear within the same message or file").
  * Orca: "a single, random nine-digit number in a file is unlikely to be a real
    Social Security number versus a file containing many"; thresholds on count
    and density; column-name allow and deny lists.
  * Sentra: "if 50% of values are valid credit card numbers, the whole column is
    labelled as such"; related columns (expiry, CVV) raise certainty.
  * Google SDP: exclusion rules (dictionary, regex, exclude-if-other-infoType,
    exclude-by-hotword which "allows you to exclude an entire column").

Fields
    context             "required": a hit whose evidence has neither validation nor
                                    context is capped at `possible` - it can only be
                                    reported through column density or a minimum count
                        "boost":    context raises the tier, its absence does not veto
                        "none":     self-identifying value, reported at any count
    column_ratio        share of a column's sampled non-empty values that must match
                        before the column is classified as this detector (Sentra: 0.5)
    column_min_matches  distinct matching values needed before a column verdict
    column_requires_validation  classify a column on the share of *validated* values, not raw
                        pattern matches. For a weak single-check-digit ID matched on a bare
                        digit run (NHS/UTR mod-11), the pattern matches every N-digit number,
                        so a phone column is 100% "matches" but only ~9% validate - counting
                        validated values keeps the column below threshold.
    column_classify     False for detectors whose column verdict is meaningless
                        (a column of random-looking strings is not a column of secrets)
    min_count           distinct `possible`-tier hits in one unit (or in one column that
                        did not reach column_ratio) that promote them to `likely`
    count_promotion     False for shapes that match ordinary words or random strings
                        (SWIFT/BIC, opaque tokens): many of them in one file is what any
                        file looks like, not evidence
    identity            the detector is an identity signal (name, e-mail, phone, address,
                        birth date) for record-level corroboration
    identity_corroboration
                        a `possible` hit is promoted one tier when the same record carries
                        two or more identity signals (Purview: SSN with Name / DateOfBirth
                        in proximity; Cyera's "identifiability")
    negative_fields     regex over the tokenised field name that vetoes the detector
                        (DLP negative keywords; Google exclude-by-hotword on a header)
    siblings            regex over the tokenised names of the *other* columns of the unit:
                        a match raises the detector's column one tier (Sentra: an expiry
                        and a CVV column next to a card column)

Policies are looked up by detector name, falling back to the finding's
category; new detectors need no entry unless they deviate from their
category's defaults.
"""
import re
from dataclasses import dataclass, replace
from typing import Any, Dict, Optional

CONTEXT_REQUIRED = "required"
CONTEXT_BOOST = "boost"
CONTEXT_NONE = "none"

# Column names that corroborate a neighbouring identifier column
_IDENTITY_SIBLINGS = (
    r"\b(?:date of birth|dob|birth ?date|birthday|first ?name|last ?name|full ?name|surname|given ?name|"
    r"family ?name|gender|sex|nationality|passport|marital|ssn|national ?id|aadhaar|pan|tax ?id)\b"
)
_CARD_SIBLINGS = r"\b(?:cvv|cvc|cvv2|cvc2|csc|expir\w*|exp ?(?:month|year|date|mm|yy)|valid ?(?:thru|till|until)|card ?holder|cardholder|card ?type|card ?brand|issuer|pan)\b"
_BANK_SIBLINGS = r"\b(?:routing|aba|ifsc|swift|bic|sort ?code|iban|bank ?(?:name|code|branch)|branch|beneficiary|account ?holder|micr)\b"
_HEALTH_SIBLINGS = r"\b(?:patient|diagnosis|icd|procedure|provider|npi|member ?id|insurance|policy|prescription|rx|claim)\b"

# Field names whose numeric values are never personal or financial identifiers
_TECHNICAL_NUMBER_FIELDS = (
    r"\b(?:hash|digest|checksum|crc|txn|transaction|trace|span|request|order|invoice|tracking|"
    r"imei|imsi|serial|barcode|ean|upc|isbn|asin|sku|lat|lng|latitude|longitude|epoch|timestamp|"
    r"pid|port|version|build|revision|counter|seq|sequence|offset|size|bytes|count|amount|total|"
    r"price|balance|score|rating|percent|duration)\b"
)


@dataclass(frozen=True)
class DetectorPolicy:
    context: str = CONTEXT_BOOST
    column_ratio: float = 0.5
    column_min_matches: int = 3
    column_classify: bool = True
    column_requires_validation: bool = False
    min_count: int = 10
    count_promotion: bool = True
    identity: bool = False
    identity_corroboration: bool = False
    negative_fields: Optional[str] = None
    siblings: Optional[str] = None

    def __post_init__(self):
        if self.context not in (CONTEXT_REQUIRED, CONTEXT_BOOST, CONTEXT_NONE):
            raise ValueError(f"unknown context policy {self.context!r}")
        object.__setattr__(self, "_negative_re", re.compile(self.negative_fields) if self.negative_fields else None)
        object.__setattr__(self, "_siblings_re", re.compile(self.siblings) if self.siblings else None)

    def vetoed_by_field(self, field_tokens: str) -> bool:
        """field_tokens: the tokenised field name joined by spaces (see rules.tokenize_field_name)."""
        return bool(field_tokens) and self._negative_re is not None and self._negative_re.search(field_tokens) is not None

    def has_sibling(self, field_tokens: str) -> bool:
        """True when another column's tokenised name corroborates this detector."""
        return bool(field_tokens) and self._siblings_re is not None and self._siblings_re.search(field_tokens) is not None


CATEGORY_DEFAULTS: Dict[str, DetectorPolicy] = {
    # keyword assignments, vendor formats and credential-named fields are self-describing
    "Credentials and Secrets": DetectorPolicy(context=CONTEXT_BOOST, min_count=3),
    "Entropy-Based Secret Detection": DetectorPolicy(context=CONTEXT_REQUIRED, column_classify=False, count_promotion=False),
    "PII": DetectorPolicy(context=CONTEXT_BOOST, identity=True),
    "Financial Data": DetectorPolicy(context=CONTEXT_REQUIRED, identity_corroboration=True, negative_fields=_TECHNICAL_NUMBER_FIELDS, siblings=_BANK_SIBLINGS),
    # count_promotion is off: these are matched on bare digit runs with a single check digit
    # (NHS mod-11, national-ID mod-10/11), which ~1-in-10 random numbers pass, so an absolute
    # count of matches is chance-dominated in any numeric column (a column of phone numbers
    # yields ~10 "valid" NHS numbers). Genuine columns are still promoted by column density
    # (>=50% of the column), siblings and record-level identity corroboration - not by count.
    "Regional Compliance": DetectorPolicy(context=CONTEXT_REQUIRED, identity_corroboration=True, negative_fields=_TECHNICAL_NUMBER_FIELDS, siblings=_IDENTITY_SIBLINGS, count_promotion=False),
    "Healthcare Data (PHI)": DetectorPolicy(context=CONTEXT_REQUIRED, identity_corroboration=True, negative_fields=_TECHNICAL_NUMBER_FIELDS, siblings=_HEALTH_SIBLINGS, count_promotion=False),
    "Technical Identifier": DetectorPolicy(context=CONTEXT_REQUIRED, identity=False, count_promotion=False),
}

POLICIES: Dict[str, DetectorPolicy] = {
    # --- PII: self-validating shapes are reported alone, weak ones need a hint
    "Email": DetectorPolicy(context=CONTEXT_NONE, identity=True),
    "Phone Number": DetectorPolicy(context=CONTEXT_BOOST, identity=True, negative_fields=_TECHNICAL_NUMBER_FIELDS),
    "PII.PersonName": DetectorPolicy(context=CONTEXT_BOOST, identity=True),
    "Address": DetectorPolicy(context=CONTEXT_BOOST, identity=True),
    "Date of Birth": DetectorPolicy(context=CONTEXT_REQUIRED, identity=True),
    "PII.IPAddress": DetectorPolicy(context=CONTEXT_BOOST, identity=False),
    "MAC_ADDRESS": DetectorPolicy(context=CONTEXT_BOOST, identity=False),
    "CA_POSTAL_CODE": DetectorPolicy(context=CONTEXT_REQUIRED, identity=False, column_ratio=0.8),
    "UK_POSTCODE": DetectorPolicy(context=CONTEXT_REQUIRED, identity=False, column_ratio=0.8),
    "DE_PLZ": DetectorPolicy(context=CONTEXT_REQUIRED, identity=False, column_ratio=0.8),
    # --- weak single-check-digit IDs matched on a bare digit run: their pattern matches every
    # 10-digit number, so classify the column on validated density (a phone column pattern-matches
    # 100% but only ~9% pass the mod-11 check). Regression: r@accuknox.com Drive scan reported
    # phone columns as UK_NHS / GB_UTR.
    "UK_NHS": DetectorPolicy(context=CONTEXT_REQUIRED, identity_corroboration=True, negative_fields=_TECHNICAL_NUMBER_FIELDS, siblings=_HEALTH_SIBLINGS, count_promotion=False, column_requires_validation=True),
    "GB_UTR": DetectorPolicy(context=CONTEXT_REQUIRED, identity_corroboration=True, negative_fields=_TECHNICAL_NUMBER_FIELDS, siblings=_IDENTITY_SIBLINGS, count_promotion=False, column_requires_validation=True),
    # --- Financial
    "Credit Card": DetectorPolicy(context=CONTEXT_REQUIRED, identity_corroboration=True, negative_fields=_TECHNICAL_NUMBER_FIELDS, siblings=_CARD_SIBLINGS),
    "IBAN": DetectorPolicy(context=CONTEXT_NONE, identity_corroboration=True, siblings=_BANK_SIBLINGS),
    "SWIFT/BIC": DetectorPolicy(context=CONTEXT_REQUIRED, column_ratio=0.8, count_promotion=False, siblings=_BANK_SIBLINGS),
    "Bank Account": DetectorPolicy(context=CONTEXT_REQUIRED, identity_corroboration=True, negative_fields=_TECHNICAL_NUMBER_FIELDS, siblings=_BANK_SIBLINGS),
    "ABA_ROUTING_NUMBER": DetectorPolicy(context=CONTEXT_REQUIRED, column_ratio=0.8, negative_fields=_TECHNICAL_NUMBER_FIELDS, siblings=_BANK_SIBLINGS),
    # --- Credentials: keyword assignments and vendor formats need nothing else
    "Private Key Header": DetectorPolicy(context=CONTEXT_NONE),
    "JWT Token": DetectorPolicy(context=CONTEXT_NONE),
    "AWS Access Key": DetectorPolicy(context=CONTEXT_NONE),
    "AWS Secret Access Key": DetectorPolicy(context=CONTEXT_REQUIRED, min_count=3),
    "Credentials in URL": DetectorPolicy(context=CONTEXT_NONE),
    "Basic Auth Credentials": DetectorPolicy(context=CONTEXT_NONE),
    "Secret.PasswordHash": DetectorPolicy(context=CONTEXT_NONE),
    "Encrypted Secret": DetectorPolicy(context=CONTEXT_NONE),
    "Password Pattern": DetectorPolicy(context=CONTEXT_BOOST, min_count=3),
    "API Key": DetectorPolicy(context=CONTEXT_BOOST, min_count=3),
    "Bearer Token": DetectorPolicy(context=CONTEXT_BOOST, min_count=3),
    "OAuth Token": DetectorPolicy(context=CONTEXT_BOOST, min_count=3),
    "High Entropy Secret": DetectorPolicy(context=CONTEXT_REQUIRED, column_classify=False, count_promotion=False),
    "Secret.TokenLikeValue": DetectorPolicy(context=CONTEXT_REQUIRED, column_classify=True, count_promotion=False),
    # --- Healthcare
    "Healthcare Data Detection": DetectorPolicy(context=CONTEXT_NONE, identity=False),
    # --- generic device / document / location identifiers (src/engine/recognizers/identifiers.py)
    "IMEI": DetectorPolicy(context=CONTEXT_REQUIRED, identity=False, negative_fields=_TECHNICAL_NUMBER_FIELDS),
    "ICCID": DetectorPolicy(context=CONTEXT_REQUIRED, identity=False, negative_fields=_TECHNICAL_NUMBER_FIELDS),
    "VIN": DetectorPolicy(context=CONTEXT_REQUIRED, identity=False, count_promotion=False),
    "GEO_COORDINATES": DetectorPolicy(context=CONTEXT_REQUIRED, identity=False),
    "PASSPORT_MRZ": DetectorPolicy(context=CONTEXT_NONE, identity_corroboration=False),
    "IN_IFSC": DetectorPolicy(context=CONTEXT_REQUIRED, column_ratio=0.8, count_promotion=False),
    "AU_BSB": DetectorPolicy(context=CONTEXT_REQUIRED, column_ratio=0.8, count_promotion=False),
    "GB_SORT_CODE": DetectorPolicy(context=CONTEXT_REQUIRED, column_ratio=0.8, count_promotion=False),
    "IN_UPI_ID": DetectorPolicy(context=CONTEXT_BOOST, identity=True),
    "US_EIN": DetectorPolicy(context=CONTEXT_REQUIRED, identity_corroboration=False, negative_fields=_TECHNICAL_NUMBER_FIELDS),
    "BR_CNPJ": DetectorPolicy(context=CONTEXT_REQUIRED, identity_corroboration=False),
}


def policy_for(detector: str, category: Optional[str] = None) -> DetectorPolicy:
    policy = POLICIES.get(detector)
    if policy is not None:
        return policy
    return CATEGORY_DEFAULTS.get(category or "", DetectorPolicy())


def register(detector: str, **overrides: Any) -> DetectorPolicy:
    """Adds or adjusts a detector's policy (deployment tuning, tests)."""
    base = POLICIES.get(detector, DetectorPolicy())
    policy = replace(base, **overrides)
    POLICIES[detector] = policy
    return policy
