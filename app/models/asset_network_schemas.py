"""Bounded network configuration. No command lines or credentials accepted."""
from typing import Literal
from pydantic import BaseModel, Field, StrictInt, field_validator, model_validator
from app.models.asset_schemas import InputModel, AssetCreate


class MonitorSettings(InputModel):
    expected_version: int = Field(ge=0, strict=True)
    target: str = Field(min_length=1, max_length=253)
    method: Literal['https', 'http', 'icmp', 'tcp'] = 'https'
    port: int | None = Field(None, ge=1, le=65535, strict=True)
    http_method: Literal['HEAD', 'GET'] = 'HEAD'
    path: str = Field('/', min_length=1, max_length=256)
    expected_codes: list[StrictInt] = Field(default_factory=lambda: list(range(200, 400)), min_length=1, max_length=500)
    enabled: bool = False
    authorized: bool = False
    scheduled: bool = False
    interval_seconds: int = Field(900, ge=1, le=31536000, strict=True)
    timeout_seconds: int = Field(3, ge=1, le=5, strict=True)
    failure_threshold: int = Field(3, ge=1, le=5, strict=True)

    @model_validator(mode='after')
    def validate_options(self):
        if self.enabled and not self.authorized:
            raise ValueError('Explicit authorization is required before enabling network traffic.')
        if not self.path.startswith('/') or self.path.startswith('//') or any(ord(c) < 33 for c in self.path) or any(c in self.path for c in ('\\', '#', '?')):
            raise ValueError('Use a relative health path without query, fragment or control characters.')
        if any(isinstance(code, bool) or not 100 <= code <= 599 for code in self.expected_codes):
            raise ValueError('Expected HTTP codes must be 100–599.')
        if self.method == 'icmp' and self.port is not None:
            raise ValueError('ICMP has no port.')
        if self.method == 'tcp' and self.port is None:
            raise ValueError('TCP requires one port.')
        return self


class DiscoverySettings(InputModel):
    expected_version: int = Field(0, ge=0, strict=True)
    name: str = Field(min_length=1, max_length=100)
    networks: list[str] = Field(min_length=1, max_length=16)
    exclusions: list[str] = Field(default_factory=list, max_length=100)
    ports: list[StrictInt] = Field(default_factory=lambda: [80, 443], min_length=1, max_length=5)
    resolve_names: bool = False
    forward_confirm: bool = False
    enabled: bool = False
    authorized: bool = False
    scheduled: bool = False
    interval_seconds: int = Field(86400, ge=1, le=31536000, strict=True)
    first_run_at: float | None = Field(None, ge=0, le=253402300799, allow_inf_nan=False)
    timeout_seconds: int = Field(3, ge=1, le=5, strict=True)
    allow_partial: bool = False

    @field_validator('networks', 'exclusions')
    @classmethod
    def bounded_networks(cls, values):
        if any(len(value) > 64 for value in values):
            raise ValueError('Network entry too long.')
        return values

    @model_validator(mode='after')
    def validate_options(self):
        if self.enabled and not self.authorized:
            raise ValueError('Explicit authorization is required before enabling discovery.')
        if any(isinstance(port, bool) or not 1 <= port <= 65535 for port in self.ports):
            raise ValueError('Use at most five individual ports, not ranges.')
        self.ports = sorted(set(self.ports))
        return self


class CheckRequest(InputModel):
    expected_generation: int = Field(ge=1, strict=True)
    idempotency_key: str = Field(min_length=8, max_length=100, pattern=r'^[a-zA-Z0-9_-]+$')


class ReviewRequest(InputModel):
    expected_version: int = Field(ge=1, strict=True)
    ignored: bool
    reopen_import: bool = False


class DiscoveryImportRow(InputModel):
    candidate_id: int = Field(ge=1, strict=True)
    observation_id: int = Field(ge=1, strict=True)
    action: Literal['create', 'link'] = 'create'
    asset: AssetCreate | None = None
    asset_id: int | None = Field(None, ge=1, strict=True)
    expected_version: int | None = Field(None, ge=1, strict=True)

    @model_validator(mode='after')
    def complete_action(self):
        if self.action == 'create' and (self.asset is None or self.asset_id is not None or self.expected_version is not None):
            raise ValueError('Create requires asset fields only.')
        if self.action == 'link' and (self.asset_id is None or self.expected_version is None or self.asset is not None):
            raise ValueError('Link requires an existing asset ID/version only.')
        return self


class DiscoveryImportRequest(InputModel):
    items: list[DiscoveryImportRow] = Field(min_length=1, max_length=100)


class NetworkJobResponse(BaseModel):
    id: int
    kind: Literal['monitor', 'discovery']
    asset_id: int | None
    profile_id: int | None
    generation: int
    source: Literal['manual', 'scheduled']
    status: Literal['queued', 'running', 'completed', 'partial', 'cancelled', 'error']
    due_at: float
    available_at: float
    started_at: float | None
    completed_at: float | None
    created_at: float
    processed: int
    responding: int
    skipped_periods: int
    result: dict


class NetworkJobPage(BaseModel):
    items: list[NetworkJobResponse]
    total: int
    limit: int
    offset: int


class MonitoringResponse(BaseModel):
    config: dict | None
    state: dict
    job: NetworkJobResponse | None
    addresses: list[dict]
