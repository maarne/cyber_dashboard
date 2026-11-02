"""Bounded, strict contracts; evidence is captured server-side, never uploaded."""
from typing import Literal
from pydantic import BaseModel, Field, model_validator
from app.models.asset_schemas import InputModel, VersionRequest

Severity = Literal['low', 'medium', 'high', 'critical']
Conclusion = Literal['malicious', 'benign', 'security_test', 'inconclusive']


class InvestigationRequest(InputModel):
    indicator: str = Field(min_length=1, max_length=2048)
    local_only: bool = True


class CaseCreate(InputModel):
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field('', max_length=4000)
    severity: Severity = 'medium'
    assignee_user_id: int | None = Field(None, ge=1, strict=True)
    initial_note: str = Field('', max_length=8000)
    snapshot_id: int | None = Field(None, ge=1, strict=True)


class CasePatch(VersionRequest):
    title: str | None = Field(None, min_length=1, max_length=200)
    summary: str | None = Field(None, max_length=4000)
    severity: Severity | None = None
    assignee_user_id: int | None = Field(None, ge=1, strict=True)

    @model_validator(mode='after')
    def valid_patch(self):
        fields = self.model_fields_set - {'expected_version'}
        if not fields or any(getattr(self, k) is None for k in fields - {'assignee_user_id'}):
            raise ValueError('Supply non-null changes; only assignee can be cleared.')
        return self


class CaseTransition(VersionRequest):
    status: Literal['open', 'in_progress', 'closed']
    reason: str = Field(min_length=1, max_length=8000)
    conclusion: Conclusion | None = None

    @model_validator(mode='after')
    def valid_conclusion(self):
        if (self.status == 'closed') != (self.conclusion is not None):
            raise ValueError('A conclusion is required only when closing.')
        return self


class CaseNote(VersionRequest):
    body: str = Field(min_length=1, max_length=8000)
    supersedes_note_id: int | None = Field(None, ge=1, strict=True)


class CaseEvidence(VersionRequest):
    snapshot_id: int = Field(ge=1, strict=True)


class CaseReference(VersionRequest):
    kind: Literal['asset', 'cve', 'actor', 'rule']
    target_id: str = Field(min_length=1, max_length=100)


class CaseArchive(VersionRequest):
    archived: bool
    reason: str = Field(min_length=1, max_length=2000)


class CaseRecord(BaseModel):
    id: int
    reference: str
    title: str
    summary: str
    severity: Severity
    status: Literal['open', 'in_progress', 'closed']
    assignee_user_id: int | None
    assignee_name: str | None
    actor_user_id: int | None
    actor_token_id: int | None
    actor_name: str
    conclusion: Conclusion | None
    closure_reason: str | None
    closed_at: str | None
    is_archived: bool
    row_version: int
    created_at: str
    updated_at: str


class CasePage(BaseModel):
    items: list[CaseRecord]
    next_before_id: int | None
    limits: dict


class SnapshotRecord(BaseModel):
    id: int
    indicator: str
    indicator_type: str
    actor_user_id: int | None
    actor_token_id: int | None
    actor_name: str
    captured_at: str
    schema_version: int
    sha256: str
    integrity_valid: bool
    warning: str | None
    evidence: dict | None


class InvestigationResponse(BaseModel):
    snapshot: SnapshotRecord
    history_id: int
    matching_cases: list[CaseRecord]


class CaseMutationResponse(BaseModel):
    case: CaseRecord
    note_id: int | None = None
    attached: bool | None = None
    added: bool | None = None


class CaseCollection(BaseModel):
    items: list[dict]
    next_before_id: int | None
