"""
Column profiles and column verdicts.

Structured stores are classified per column, not per cell: Google Sensitive
Data Protection profiles a column into a predicted infoType from sampled rows,
Sentra labels a column when 50% of its values validate, Orca thresholds on
count and density, presidio-structured picks the most common entity across
sampled cells. A ColumnProfile accumulates one (column, detector) pair while
records stream through the classifier; column_verdict() turns it into a
classification when the density and distinct-value requirements are met.
"""
import hashlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from src.engine.confidence import TIERS, promote, rank
from src.engine.policy import DetectorPolicy

MAX_DISTINCT_TRACKED = 2000


@dataclass(frozen=True)
class MatchSource:
    """Source coordinates and confidence before record/column promotion."""

    cell_id: int
    start: int
    end: int
    independent: bool
    encoded: bool

    def overlaps(self, other: "MatchSource") -> bool:
        # Encoded findings use their container's coordinates, not the decoded
        # value's coordinates. A shared container does not imply a collision.
        if self.cell_id != other.cell_id or self.encoded or other.encoded:
            return False
        overlap = min(self.end, other.end) - max(self.start, other.start)
        return overlap > 0 and overlap / max(1, self.end - self.start) >= 0.8


@dataclass
class ColumnProfile:
    column: str
    detector: str
    category: str
    severity: str
    items: List[Dict[str, Any]] = field(default_factory=list)
    tiers: Counter = field(default_factory=Counter)
    distinct: Set[str] = field(default_factory=set)
    distinct_overflow: int = 0
    hinted: bool = False
    sources: List[MatchSource] = field(default_factory=list)
    sources_by_cell: Dict[int, List[MatchSource]] = field(default_factory=dict)
    cell_tiers: Dict[int, str] = field(default_factory=dict)
    validated_cells: Set[int] = field(default_factory=set)

    def add(
        self, candidate: Dict[str, Any], formatted: Dict[str, Any],
        cell_id: int, independent: bool,
    ) -> None:
        self.items.append(formatted)
        source = MatchSource(cell_id, candidate["start"], candidate["end"], independent, bool(candidate.get("encoded")))
        self.sources.append(source)
        self.sources_by_cell.setdefault(cell_id, []).append(source)
        # A cell can contain many matches. Density, validation and the majority
        # tier each get one vote per cell, while items retain every occurrence.
        previous = self.cell_tiers.get(cell_id)
        tier = candidate["confidence"]
        if previous is None or rank(tier) > rank(previous):
            if previous is not None:
                self.tiers[previous] -= 1
            self.cell_tiers[cell_id] = tier
            self.tiers[tier] += 1
        if candidate.get("field_hint") or "field" in candidate.get("evidence", ()):
            self.hinted = True
        evidence = candidate.get("evidence", ())
        if candidate.get("validated") or "checksum" in evidence or "format" in evidence or any(str(e).startswith("key:") for e in evidence):
            self.validated_cells.add(cell_id)
        digest = hashlib.sha1(str(candidate.get("value", "")).encode("utf-8", errors="ignore")).hexdigest()[:16]
        if digest in self.distinct:
            return
        if len(self.distinct) < MAX_DISTINCT_TRACKED:
            self.distinct.add(digest)
        else:
            self.distinct_overflow += 1

    @property
    def matches(self) -> int:
        """Matching cells, not matching spans (always <= sampled cells)."""
        return len(self.cell_tiers)

    @property
    def validated(self) -> int:
        return len(self.validated_cells)

    @property
    def distinct_count(self) -> int:
        return len(self.distinct) + self.distinct_overflow

    def majority_tier(self) -> str:
        """Highest tier reached by at least half of the matching cells."""
        total = self.matches
        cumulative = 0
        for tier in reversed(TIERS):
            cumulative += self.tiers.get(tier, 0)
            if cumulative * 2 >= total:
                return tier
        return TIERS[0]


@dataclass(frozen=True)
class ColumnVerdict:
    tier: str
    ratio: float
    sampled: int
    matches: int
    distinct: int


def column_verdict(
    profile: ColumnProfile, sampled: int, policy: DetectorPolicy,
    ratio_threshold: Optional[float] = None, min_matches: Optional[int] = None,
) -> Optional[ColumnVerdict]:
    """
    Classifies the column when enough distinct values match and the match share
    of the sampled non-empty values reaches the policy's column_ratio. The
    column tier is one step above the majority cell tier: statistical evidence
    is the corroboration a single cell lacked (Sentra, Orca), capped at
    very_likely.
    """
    if not policy.column_classify or sampled <= 0:
        return None
    threshold = policy.column_ratio if ratio_threshold is None else ratio_threshold
    needed = policy.column_min_matches if min_matches is None else min_matches
    if profile.matches < needed or profile.distinct_count < needed:
        return None
    # For a weak single-check-digit ID whose pattern matches any N-digit number, only the
    # validated share is meaningful: a phone column pattern-matches 100% but ~9% validate.
    numerator = profile.validated if policy.column_requires_validation else profile.matches
    ratio = numerator / sampled
    if ratio < threshold:
        return None
    tier = promote(profile.majority_tier())
    if rank(tier) < rank(profile.majority_tier()):
        tier = profile.majority_tier()
    return ColumnVerdict(tier=tier, ratio=ratio, sampled=sampled, matches=profile.matches, distinct=profile.distinct_count)
