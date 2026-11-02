"""Result containers shared by every analyzer."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    category: str               # header, auth, ip, domain, body, url, attachment, report, ...
    title: str
    points: int = 0
    evidence: str = ""
    hard_verdict: str | None = None   # MALICIOUS / SIMULATION / UNANALYZABLE overrides the score
    tags: list[str] = field(default_factory=list)


@dataclass
class CaseResult:
    case_id: str
    source: str = ""
    reported_by: str = ""
    reported_at: str = ""
    analyzed_at: str = ""
    message_sha256: str = ""
    original: dict[str, Any] = field(default_factory=dict)
    auth: dict[str, Any] = field(default_factory=dict)
    hops: list[dict[str, Any]] = field(default_factory=list)
    originating_ip: dict[str, Any] = field(default_factory=dict)
    sender_domains: list[dict[str, Any]] = field(default_factory=list)
    body: dict[str, Any] = field(default_factory=dict)
    urls: list[dict[str, Any]] = field(default_factory=list)
    attachments: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    verdict: str = "UNKNOWN"
    score: int = 0
    confidence: str = ""
    recommended_actions: list[str] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duplicate_of: str = ""

    def add(self, category: str, title: str, points: int = 0, evidence: str = "",
            hard_verdict: str | None = None, tags: list[str] | None = None) -> None:
        self.findings.append(Finding(category, title, points, evidence, hard_verdict, list(tags or [])))

    @property
    def tags(self) -> set[str]:
        return {t for f in self.findings for t in f.tags}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CaseResult":
        data = dict(data)
        data["findings"] = [Finding(**f) for f in data.get("findings", [])]
        known = cls.__dataclass_fields__
        return cls(**{k: v for k, v in data.items() if k in known})
