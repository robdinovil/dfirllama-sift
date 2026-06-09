"""
ConfidenceScorer — per-finding confidence and false-positive risk scoring.

Each threat hunt hit is scored on:
  - Base confidence from evidence volume (count of matching rows)
  - FP risk adjustment per MITRE technique (some techniques have high FP in normal environments)
  - Corroboration boost when the same indicator appears across multiple tables

Output risk labels:
  CONFIRMED  ≥ 0.80 — high confidence, low FP risk
  LIKELY     ≥ 0.60 — corroborated or high-volume hit
  POSSIBLE   ≥ 0.40 — single hit or medium FP risk
  WEAK       < 0.40 — insufficient evidence
"""

from dataclasses import dataclass, field


@dataclass
class FindingScore:
    rule_id:      str
    confidence:   float       # 0.0–1.0
    fp_risk:      str         # low / medium / high
    corroborated: bool
    notes:        list[str] = field(default_factory=list)

    @property
    def risk_label(self) -> str:
        if self.confidence >= 0.80:
            return "CONFIRMED"
        if self.confidence >= 0.60:
            return "LIKELY"
        if self.confidence >= 0.40:
            return "POSSIBLE"
        return "WEAK"


# FP risk baseline per MITRE technique
_FP_RISK: dict[str, str] = {
    "T1003":     "low",    # credential dumping tool names are highly specific
    "T1003.001": "low",    # LSASS memory dump — very specific pattern
    "T1055":     "low",    # process injection via lsass — high specificity
    "T1059.001": "medium", # encoded PS — also used by legitimate admin scripts
    "T1105":     "medium", # certutil for download — has legitimate uses
    "T1036":     "medium", # masquerading — devs in AppData are common
    "T1053.005": "medium", # scheduled task — many apps create tasks
    "T1547.001": "high",   # registry run keys — very common in legitimate software
    "T1071.001": "medium", # C2 over HTTP/S — overlaps with legitimate traffic
    "T1049":     "medium", # non-standard port — dev tools also use these
    "T1110":     "low",    # brute force COUNT > 5 — very clear signal
    "T1078":     "medium", # external logon — could be VPN
    "T1218":     "low",    # LOLBin execution — rarely legitimate in production
}

_FP_DELTA: dict[str, float] = {
    "low":    +0.10,
    "medium":  0.00,
    "high":   -0.15,
}

_FP_NOTE: dict[str, str] = {
    "low":  "low FP risk — highly specific indicator",
    "high": "high FP risk — common in legitimate software",
}


def score_finding(rule_id: str, count: int,
                  corroborated: bool = False) -> FindingScore:
    """
    Score a single threat hunt finding.

    Args:
        rule_id:      MITRE technique ID (e.g. "T1003")
        count:        number of rows matching the rule
        corroborated: True if the indicator appears in more than one table
    """
    notes: list[str] = []
    fp_risk = _FP_RISK.get(rule_id, "medium")

    if count == 0:
        return FindingScore(rule_id=rule_id, confidence=0.0,
                            fp_risk=fp_risk, corroborated=False,
                            notes=["no hits — rule skipped"])
    elif count == 1:
        confidence = 0.40
        notes.append("single hit — low evidence volume")
    elif count <= 3:
        confidence = 0.60
        notes.append(f"{count} hits")
    elif count <= 10:
        confidence = 0.75
    else:
        confidence = 0.85
        notes.append(f"{count} hits — high volume")

    confidence += _FP_DELTA[fp_risk]
    if fp_risk in _FP_NOTE:
        notes.append(_FP_NOTE[fp_risk])

    if corroborated:
        confidence = min(1.0, confidence + 0.15)
        notes.append("cross-table corroboration")

    confidence = round(max(0.0, min(1.0, confidence)), 2)
    return FindingScore(
        rule_id=rule_id, confidence=confidence,
        fp_risk=fp_risk, corroborated=corroborated, notes=notes
    )


def enrich_hits(hits: list[dict]) -> list[dict]:
    """
    Attach a FindingScore to each hit returned by threat_hunt().

    Input hit keys: rule_id, severity, name, table, rows, count
    Output adds: "score" key with a FindingScore instance
    """
    tables_hit = {h["table"] for h in hits}
    enriched   = []
    for hit in hits:
        corroborated = len(tables_hit) > 1
        s            = score_finding(hit["rule_id"], hit["count"], corroborated)
        enriched.append({**hit, "score": s})
    return enriched
