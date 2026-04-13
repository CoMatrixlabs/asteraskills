"""
SQLAlchemy ORM models for the compliance framework knowledge base.
Postgres is the authoritative relational store; Qdrant handles semantic search.
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, String, Text, Integer, Float, Boolean, DateTime, ForeignKey,
    UniqueConstraint, Index, ARRAY, Enum as SAEnum
)
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid
import enum


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ControlType(str, enum.Enum):
    preventive = "preventive"
    detective = "detective"
    corrective = "corrective"
    compensating = "compensating"
    deterrent = "deterrent"


class MappingType(str, enum.Enum):
    equivalent = "equivalent"
    related = "related"
    partial = "partial"


class IngestionStatus(str, enum.Enum):
    pending = "pending"
    processing = "processing"
    complete = "complete"
    failed = "failed"


class GapType(str, enum.Enum):
    missing = "missing"           # no policy coverage at all
    partial = "partial"           # some coverage but below threshold
    adequate = "adequate"         # above similarity threshold


# ---------------------------------------------------------------------------
# Core Framework Tables
# ---------------------------------------------------------------------------

class Framework(Base):
    __tablename__ = "frameworks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. "cis_v8_1"
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    source_url: Mapped[Optional[str]] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    requirements: Mapped[List["Requirement"]] = relationship(back_populates="framework")
    risks: Mapped[List["Risk"]] = relationship(back_populates="framework")
    controls: Mapped[List["Control"]] = relationship(back_populates="framework")
    scenarios: Mapped[List["Scenario"]] = relationship(back_populates="framework")

    def __repr__(self) -> str:
        return f"<Framework {self.id} ({self.name} {self.version})>"


class Requirement(Base):
    __tablename__ = "requirements"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)  # e.g. "hipaa_164.308(a)(1)(i)"
    framework_id: Mapped[str] = mapped_column(String(64), ForeignKey("frameworks.id"), nullable=False)
    requirement_code: Mapped[str] = mapped_column(String(128), nullable=False)  # raw code from source
    name: Mapped[Optional[str]] = mapped_column(String(512))
    description: Mapped[Optional[str]] = mapped_column(Text)
    domain: Mapped[Optional[str]] = mapped_column(String(256))
    # HIPAA: "required" | "addressable" | None
    compliance_type: Mapped[Optional[str]] = mapped_column(String(64))
    parent_requirement_id: Mapped[Optional[str]] = mapped_column(
        String(128), ForeignKey("requirements.id"), nullable=True
    )
    # Qdrant vector ID for fast bridge back to semantic search
    qdrant_vector_id: Mapped[Optional[str]] = mapped_column(String(128))
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, default=dict)

    # Relationships
    framework: Mapped["Framework"] = relationship(back_populates="requirements")
    children: Mapped[List["Requirement"]] = relationship(
        "Requirement", back_populates="parent", foreign_keys=[parent_requirement_id]
    )
    parent: Mapped[Optional["Requirement"]] = relationship(
        "Requirement", back_populates="children", remote_side=[id]
    )
    requirement_controls: Mapped[List["RequirementControl"]] = relationship(back_populates="requirement")

    __table_args__ = (
        UniqueConstraint("framework_id", "requirement_code", name="uq_requirement_framework_code"),
        Index("ix_requirements_framework_id", "framework_id"),
    )


class Risk(Base):
    __tablename__ = "risks"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)   # e.g. "CIS-RISK-001"
    framework_id: Mapped[str] = mapped_column(String(64), ForeignKey("frameworks.id"), nullable=False)
    risk_code: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    asset: Mapped[Optional[str]] = mapped_column(String(256))
    trigger: Mapped[Optional[str]] = mapped_column(String(256))
    loss_outcomes: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    likelihood: Mapped[Optional[float]] = mapped_column(Float)
    impact: Mapped[Optional[float]] = mapped_column(Float)
    qdrant_vector_id: Mapped[Optional[str]] = mapped_column(String(128))
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, default=dict)

    # Relationships
    framework: Mapped["Framework"] = relationship(back_populates="risks")
    risk_controls: Mapped[List["RiskControl"]] = relationship(back_populates="risk")
    test_cases: Mapped[List["TestCase"]] = relationship(back_populates="risk")

    __table_args__ = (
        UniqueConstraint("framework_id", "risk_code", name="uq_risk_framework_code"),
        Index("ix_risks_framework_id", "framework_id"),
    )


class Control(Base):
    __tablename__ = "controls"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)   # e.g. "cis_v8_1_VPM-2"
    framework_id: Mapped[str] = mapped_column(String(64), ForeignKey("frameworks.id"), nullable=False)
    control_code: Mapped[str] = mapped_column(String(128), nullable=False)  # e.g. "VPM-2"
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    domain: Mapped[Optional[str]] = mapped_column(String(256))
    control_type: Mapped[Optional[str]] = mapped_column(String(64))  # preventive / detective / etc.
    # CIS-specific: which CIS safeguard this maps to (e.g. "CIS-7")
    cis_control_id: Mapped[Optional[str]] = mapped_column(String(64))
    qdrant_vector_id: Mapped[Optional[str]] = mapped_column(String(128))
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, default=dict)

    # Relationships
    framework: Mapped["Framework"] = relationship(back_populates="controls")
    risk_controls: Mapped[List["RiskControl"]] = relationship(back_populates="control")
    requirement_controls: Mapped[List["RequirementControl"]] = relationship(back_populates="control")
    scenario_controls: Mapped[List["ScenarioControl"]] = relationship(back_populates="control")
    source_mappings: Mapped[List["CrossFrameworkMapping"]] = relationship(
        "CrossFrameworkMapping", foreign_keys="CrossFrameworkMapping.source_control_id",
        back_populates="source_control"
    )
    target_mappings: Mapped[List["CrossFrameworkMapping"]] = relationship(
        "CrossFrameworkMapping", foreign_keys="CrossFrameworkMapping.target_control_id",
        back_populates="target_control"
    )

    __table_args__ = (
        UniqueConstraint("framework_id", "control_code", name="uq_control_framework_code"),
        Index("ix_controls_framework_id", "framework_id"),
    )


class TestCase(Base):
    __tablename__ = "test_cases"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)   # e.g. "CIS-RISK-001-TEST-01"
    risk_id: Mapped[Optional[str]] = mapped_column(String(128), ForeignKey("risks.id"), nullable=True)
    control_id: Mapped[Optional[str]] = mapped_column(String(128), ForeignKey("controls.id"), nullable=True)
    framework_id: Mapped[str] = mapped_column(String(64), ForeignKey("frameworks.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    test_type: Mapped[Optional[str]] = mapped_column(String(128))
    objective: Mapped[Optional[str]] = mapped_column(Text)
    test_steps: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    expected_result: Mapped[Optional[str]] = mapped_column(Text)
    evidence_required: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    success_criteria: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    qdrant_vector_id: Mapped[Optional[str]] = mapped_column(String(128))
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, default=dict)

    # Relationships
    risk: Mapped[Optional["Risk"]] = relationship(back_populates="test_cases")
    framework: Mapped["Framework"] = relationship()

    __table_args__ = (
        Index("ix_test_cases_risk_id", "risk_id"),
        Index("ix_test_cases_control_id", "control_id"),
        Index("ix_test_cases_framework_id", "framework_id"),
    )


class Scenario(Base):
    __tablename__ = "scenarios"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)   # e.g. "CIS-RISK-001"
    framework_id: Mapped[str] = mapped_column(String(64), ForeignKey("frameworks.id"), nullable=False)
    scenario_code: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    asset: Mapped[Optional[str]] = mapped_column(String(256))
    trigger: Mapped[Optional[str]] = mapped_column(String(256))
    loss_outcomes: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    severity: Mapped[Optional[str]] = mapped_column(String(64))
    qdrant_vector_id: Mapped[Optional[str]] = mapped_column(String(128))
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, default=dict)

    # Relationships
    framework: Mapped["Framework"] = relationship(back_populates="scenarios")
    scenario_controls: Mapped[List["ScenarioControl"]] = relationship(back_populates="scenario")

    __table_args__ = (
        UniqueConstraint("framework_id", "scenario_code", name="uq_scenario_framework_code"),
        Index("ix_scenarios_framework_id", "framework_id"),
    )


# ---------------------------------------------------------------------------
# Bridge / Association Tables
# ---------------------------------------------------------------------------

class RiskControl(Base):
    """Many-to-many: which controls mitigate which risks."""
    __tablename__ = "risk_controls"

    risk_id: Mapped[str] = mapped_column(String(128), ForeignKey("risks.id"), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(128), ForeignKey("controls.id"), primary_key=True)
    mitigation_strength: Mapped[Optional[str]] = mapped_column(String(64))  # strong / moderate / weak

    risk: Mapped["Risk"] = relationship(back_populates="risk_controls")
    control: Mapped["Control"] = relationship(back_populates="risk_controls")


class RequirementControl(Base):
    """Many-to-many: which controls satisfy which requirements."""
    __tablename__ = "requirement_controls"

    requirement_id: Mapped[str] = mapped_column(String(128), ForeignKey("requirements.id"), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(128), ForeignKey("controls.id"), primary_key=True)

    requirement: Mapped["Requirement"] = relationship(back_populates="requirement_controls")
    control: Mapped["Control"] = relationship(back_populates="requirement_controls")


class ScenarioControl(Base):
    """Many-to-many: which controls are relevant to which scenarios."""
    __tablename__ = "scenario_controls"

    scenario_id: Mapped[str] = mapped_column(String(128), ForeignKey("scenarios.id"), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(128), ForeignKey("controls.id"), primary_key=True)

    scenario: Mapped["Scenario"] = relationship(back_populates="scenario_controls")
    control: Mapped["Control"] = relationship(back_populates="scenario_controls")


# ---------------------------------------------------------------------------
# Cross-Framework Mapping
# ---------------------------------------------------------------------------

class CrossFrameworkMapping(Base):
    """
    Explicit linkages between controls across frameworks.
    Populated during ingestion from inline YAML cross-references
    and can be enriched later by the mapping agent.
    """
    __tablename__ = "cross_framework_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_framework_id: Mapped[str] = mapped_column(String(64), ForeignKey("frameworks.id"), nullable=False)
    source_control_id: Mapped[str] = mapped_column(String(128), ForeignKey("controls.id"), nullable=False)
    target_framework_id: Mapped[str] = mapped_column(String(64), ForeignKey("frameworks.id"), nullable=False)
    # target_control_id is nullable: we may know the target framework ref code before the control is ingested
    target_control_id: Mapped[Optional[str]] = mapped_column(String(128), ForeignKey("controls.id"), nullable=True)
    # Raw code from source YAML (e.g. "CC 2.1") for deferred resolution
    target_raw_code: Mapped[Optional[str]] = mapped_column(String(256))
    mapping_type: Mapped[str] = mapped_column(String(32), default="related")
    confidence_score: Mapped[Optional[float]] = mapped_column(Float)
    source: Mapped[str] = mapped_column(String(64), default="yaml_inline")  # yaml_inline | agent_generated

    source_control: Mapped["Control"] = relationship(
        "Control", foreign_keys=[source_control_id], back_populates="source_mappings"
    )
    target_control: Mapped[Optional["Control"]] = relationship(
        "Control", foreign_keys=[target_control_id], back_populates="target_mappings"
    )

    __table_args__ = (
        Index("ix_cfm_source_framework", "source_framework_id"),
        Index("ix_cfm_target_framework", "target_framework_id"),
        Index("ix_cfm_source_control", "source_control_id"),
    )


# ---------------------------------------------------------------------------
# User Session & Document Tables
# ---------------------------------------------------------------------------

class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Array of framework IDs in scope for this session
    framework_scope: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    intent_classification: Mapped[Optional[str]] = mapped_column(String(256))
    clarification_state: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict)

    documents: Mapped[List["UploadedDocument"]] = relationship(back_populates="session")
    gap_results: Mapped[List["GapAnalysisResult"]] = relationship(back_populates="session")


class UploadedDocument(Base):
    __tablename__ = "uploaded_documents"

    id: Mapped[str] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    session_id: Mapped[Optional[str]] = mapped_column(String(128), ForeignKey("user_sessions.id"), nullable=True)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)  # upload | url
    format: Mapped[str] = mapped_column(String(32), nullable=False)       # pdf | docx | markdown | url
    # Frameworks this document claims to address
    framework_scope: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    ingestion_status: Mapped[str] = mapped_column(String(32), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    session: Mapped[Optional["UserSession"]] = relationship(back_populates="documents")
    chunks: Mapped[List["DocumentChunk"]] = relationship(back_populates="document")


class DocumentChunk(Base):
    __tablename__ = "document_chunks"

    id: Mapped[str] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    document_id: Mapped[str] = mapped_column(String(128), ForeignKey("uploaded_documents.id"), nullable=False)
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    section_heading: Mapped[Optional[str]] = mapped_column(String(512))
    page_number: Mapped[Optional[int]] = mapped_column(Integer)
    text_preview: Mapped[Optional[str]] = mapped_column(String(256))  # first 200 chars
    # Bridge back to Qdrant user_policies collection
    qdrant_vector_id: Mapped[Optional[str]] = mapped_column(String(128))

    document: Mapped["UploadedDocument"] = relationship(back_populates="chunks")
    gap_results: Mapped[List["GapAnalysisResult"]] = relationship(back_populates="matched_chunk")

    __table_args__ = (
        Index("ix_doc_chunks_document_id", "document_id"),
    )


class GapAnalysisResult(Base):
    __tablename__ = "gap_analysis_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(128), ForeignKey("user_sessions.id"), nullable=False)
    document_id: Mapped[str] = mapped_column(String(128), ForeignKey("uploaded_documents.id"), nullable=False)
    framework_id: Mapped[str] = mapped_column(String(64), ForeignKey("frameworks.id"), nullable=False)
    requirement_id: Mapped[Optional[str]] = mapped_column(String(128), ForeignKey("requirements.id"), nullable=True)
    control_id: Mapped[Optional[str]] = mapped_column(String(128), ForeignKey("controls.id"), nullable=True)
    gap_type: Mapped[str] = mapped_column(String(32), nullable=False)  # missing | partial | adequate
    similarity_score: Mapped[Optional[float]] = mapped_column(Float)
    matched_chunk_id: Mapped[Optional[str]] = mapped_column(
        String(128), ForeignKey("document_chunks.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    session: Mapped["UserSession"] = relationship(back_populates="gap_results")
    matched_chunk: Mapped[Optional["DocumentChunk"]] = relationship(back_populates="gap_results")

    __table_args__ = (
        Index("ix_gap_session_framework", "session_id", "framework_id"),
    )
