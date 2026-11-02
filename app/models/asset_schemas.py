"""Strict, bounded input contracts for private inventory workflows."""

from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Status = Literal["open", "in_progress", "remediated", "not_affected", "accepted_risk"]
Exposure = Literal["internet", "internal", "unknown"]
Tag = Annotated[str, Field(min_length=1, max_length=32)]


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("*", mode="before")
    @classmethod
    def strip_text(cls, value):
        return value.strip() if isinstance(value, str) else value


class AssetCreate(InputModel):
    external_id: str = Field(min_length=1, max_length=100, pattern=r"^[\w.@:/-]+$")
    name: str = Field(min_length=1, max_length=200)
    environment: str = Field("development", min_length=1, max_length=40)
    owner_team: str = Field("", max_length=100)
    criticality: int = Field(2, ge=1, le=4, strict=True)
    exposure: Exposure = "unknown"
    tags: list[Tag] = Field(default_factory=list, max_length=10)

    @field_validator("external_id", "environment", mode="before")
    @classmethod
    def normalize(cls, value):
        return value.strip().casefold() if isinstance(value, str) else value

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_tags(cls, value):
        if isinstance(value, list):
            return sorted(set(v.strip().casefold() for v in value if isinstance(v, str))) if all(isinstance(v, str) for v in value) else value
        return value


class VersionRequest(InputModel):
    expected_version: int = Field(ge=1, strict=True)


class AssetPatch(VersionRequest):
    external_id: str | None = None
    name: str | None = None
    environment: str | None = None
    owner_team: str | None = None
    criticality: int | None = Field(None, ge=1, le=4, strict=True)
    exposure: Exposure | None = None
    tags: list[Tag] | None = None

    @model_validator(mode="after")
    def no_null(self):
        if any(getattr(self, key) is None for key in self.model_fields_set):
            raise ValueError("Asset fields cannot be null.")
        return self


class ArchiveRequest(VersionRequest):
    archived: bool = True


class SoftwareCreate(InputModel):
    vendor: str = Field(min_length=1, max_length=100)
    product: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)
    cpe: str | None = Field(None, max_length=256, pattern=r"^cpe:2\.3:[aho]:")
    source: str = Field("manual", min_length=1, max_length=100)
    observed_at: datetime | None = None

    @field_validator("observed_at")
    @classmethod
    def aware_time(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("observed_at must include a UTC offset.")
        return value.astimezone(timezone.utc) if value else value


class SoftwarePatch(VersionRequest):
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    source: str | None = None
    observed_at: datetime | None = None


class AssessmentCreate(InputModel):
    cve_id: str = Field(min_length=13, max_length=32, pattern=r"^CVE-\d{4}-\d{4,}$")
    software_id: int | None = Field(None, ge=1, strict=True)
    source: str = Field("manual", min_length=1, max_length=100)
    confidence: Literal["confirmed", "suspected"] = "suspected"
    evidence_note: str = Field(min_length=1, max_length=4000)
    status: Status = "open"
    reason: str = Field("", max_length=4000)
    accepted_risk_expires_at: datetime | None = None

    @field_validator("cve_id", mode="before")
    @classmethod
    def uppercase_cve(cls, value):
        return value.strip().upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_disposition(self):
        if self.status in ("remediated", "not_affected", "accepted_risk") and not self.reason:
            raise ValueError("This assessment state requires a reason.")
        expiry = self.accepted_risk_expires_at
        if expiry and expiry.tzinfo is None:
            raise ValueError("Risk acceptance expiry must include a UTC offset.")
        if self.status == "accepted_risk" and (not expiry or expiry <= datetime.now(timezone.utc)):
            raise ValueError("Risk acceptance requires a future expiry.")
        if self.status != "accepted_risk" and expiry is not None:
            raise ValueError("Risk expiry is only valid for accepted_risk.")
        if expiry is not None:
            self.accepted_risk_expires_at = expiry.astimezone(timezone.utc)
        return self


class AssessmentPatch(VersionRequest):
    software_id: int | None = None
    source: str | None = None
    confidence: Literal["confirmed", "suspected"] | None = None
    evidence_note: str | None = None
    status: Status | None = None
    reason: str | None = None
    accepted_risk_expires_at: datetime | None = None


class ImportPreviewRequest(InputModel):
    csv_content: str = Field(min_length=1, max_length=1048576)


class ImportCommitRequest(InputModel):
    preview_token: str = Field(min_length=32, max_length=100)


# Output contracts intentionally do not include credentials or transport metadata.
class AssetRecord(BaseModel):
    id: int
    external_id: str
    name: str
    environment: str
    owner_team: str
    criticality: int
    exposure: Exposure
    tags: list[str]
    is_archived: int
    row_version: int
    created_by_user_id: int | None
    created_by_token_id: int | None
    created_by: str
    updated_by: str
    created_at: str
    updated_at: str


class AssetPage(BaseModel):
    items: list[AssetRecord]
    total: int
    limit: int
    offset: int


class SoftwareRecord(BaseModel):
    id: int
    asset_id: int
    vendor: str
    product: str
    version: str
    cpe: str | None
    source: str
    observed_at: str
    row_version: int
    created_by: str
    updated_by: str
    created_at: str
    updated_at: str


class SoftwarePage(BaseModel):
    items: list[SoftwareRecord]
    total: int
    limit: int
    offset: int


class AssessmentRecord(BaseModel):
    id: int
    asset_id: int
    cve_id: str
    software_id: int | None
    source: str
    confidence: Literal["confirmed", "suspected"]
    evidence_note: str
    status: Status
    reason: str
    accepted_risk_expires_at: str | None
    row_version: int
    created_by: str
    updated_by: str
    created_at: str
    updated_at: str


class PriorityRecord(AssessmentRecord):
    availability: str | None = None
    asset_name: str
    external_id: str
    environment: str
    owner_team: str
    criticality: int
    exposure: Exposure
    is_archived: int
    formula_version: Literal["v1"]
    score: float | None
    known_subtotal: float
    inputs: dict
    components: dict[str, float | None]
    missing_inputs: list[str]
    freshness_warnings: list[str]
    intelligence: dict
    urgent_kev: bool
    risk_acceptance_expired: bool
    effective_status: Status
    actionable: bool


class PriorityPage(BaseModel):
    items: list[PriorityRecord]
    total: int
    limit: int
    offset: int
    formula_version: Literal["v1"]
