from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, field_validator

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_CONFIDENCES = {"certain", "firm", "tentative"}


class VulnerabilityRecord(BaseModel):
    """Normalized internal vulnerability representation shared across all adapters."""

    name: str
    location: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    cvss_version: float = 3.1
    severity: Optional[str] = None
    description: Optional[str] = None
    solution: Optional[str] = None
    category: Optional[str] = None
    cves: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    owasp_ids: list[str] = Field(default_factory=list)
    confidence: Optional[str] = None
    first_found_at: Optional[datetime] = None
    last_found_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    vendor_risk_score: Optional[float] = None
    asset_uid: Optional[str] = None
    listing_uid: Optional[str] = None
    source: str

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: object) -> Optional[str]:
        if v is None:
            return None
        normalized = str(v).lower().strip()
        return normalized if normalized in VALID_SEVERITIES else None

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(cls, v: object) -> Optional[str]:
        if v is None:
            return None
        normalized = str(v).lower().strip()
        return normalized if normalized in VALID_CONFIDENCES else None

    def to_synack(self) -> dict:
        """Serialize to Synack API payload dict (camelCase, omitting None/empty)."""
        payload: dict = {
            "name": self.name,
            "location": self.location,
            "cvssScore": self.cvss_score,
            "cvssVersion": self.cvss_version,
            "lastFoundAt": self.last_found_at.isoformat(),
            "source": self.source,
        }
        if self.description:
            payload["description"] = self.description
        if self.solution:
            payload["solution"] = self.solution
        if self.category:
            payload["category"] = self.category
        if self.severity:
            payload["severity"] = self.severity
        if self.confidence:
            payload["confidence"] = self.confidence
        if self.cves:
            payload["cves"] = self.cves
        if self.cwes:
            payload["cwes"] = self.cwes
        if self.owasp_ids:
            payload["owaspIds"] = self.owasp_ids
        if self.first_found_at:
            payload["firstFoundAt"] = self.first_found_at.isoformat()
        if self.vendor_risk_score is not None:
            payload["vendorRiskScore"] = self.vendor_risk_score
        if self.asset_uid:
            payload["assetUid"] = self.asset_uid
        if self.listing_uid:
            payload["listingUid"] = self.listing_uid
        return payload
