"""Complete, bounded snapshots. Source bytes are preserved, never stripped."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class RuleSnapshot(BaseModel):
    model_config = ConfigDict(extra='forbid')
    title: str = Field(min_length=1, max_length=300)
    rule_type: Literal['Sigma', 'SIGMA', 'YARA'] = 'Sigma'
    severity: Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFORMATIONAL'] = 'HIGH'
    mitre_ttp: str = Field('', max_length=200)
    target_cve: str = Field('', max_length=100)
    description: str = Field('', max_length=4000)
    code_content: str = Field(min_length=1, max_length=204800)
    target_siem: str = Field('Generic', max_length=200)
    deployment_guide: str = Field('', max_length=16000)

    @model_validator(mode='after')
    def bounded(self):
        if not self.title.strip() or not self.code_content.strip():
            raise ValueError('Title and source cannot be blank.')
        if len(self.code_content.encode()) > 204800:
            raise ValueError('Source must be at most 200 KiB UTF-8.')
        self.rule_type = 'Sigma' if self.rule_type.upper() == 'SIGMA' else 'YARA'
        return self


class RevisionRequest(RuleSnapshot):
    expected_version: int = Field(ge=1, strict=True)
    expected_parent_revision_id: int = Field(ge=1, strict=True)


class RuleAction(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    expected_version: int = Field(ge=1, strict=True)
    reason: str = Field('', max_length=2000)


class RuleReview(RuleAction):
    decision: Literal['approved', 'rejected']
    reason: str = Field(min_length=1, max_length=2000)


class RuleRollback(RuleAction):
    source_revision_id: int = Field(ge=1, strict=True)
    reason: str = Field(min_length=1, max_length=2000)


class RuleArchive(RuleAction):
    archived: bool
    reason: str = Field(min_length=1, max_length=2000)


class RevisionRecord(BaseModel):
    id: int
    rule_id: int
    revision_number: int
    parent_revision_id: int | None
    author_user_id: int | None
    author_token_id: int | None
    author_name: str
    state: str
    created_at: str
    sha256: str
    integrity_valid: bool
    snapshot: dict
    validation: dict | None
    reviews: list[dict]


class WorkingRule(BaseModel):
    id: int
    row_version: int
    is_archived: bool
    published_revision_id: int | None
    working_revision_id: int
    working: RevisionRecord


class RulePage(BaseModel):
    items: list[dict]
    next_before_id: int | None
