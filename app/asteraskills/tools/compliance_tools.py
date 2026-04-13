"""
Compliance and framework tools.
These tools query framework controls, CIS benchmarks, and perform gap analysis.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field
from sqlalchemy import text, select
from sqlalchemy.orm import Session

from asteraskills.tools.base import ToolResult, SecurityTool
from asteraskills.storage.sqlalchemy_session import get_session, get_security_intel_session
from asteraskills.ingestion.models import Framework, Control

logger = logging.getLogger(__name__)


# ============================================================================
# Framework Control Search Tool
# ============================================================================

class FrameworkControlInput(BaseModel):
    """Input schema for framework control search tool."""
    framework_id: Optional[str] = Field(default=None, description="Framework ID (e.g., cis_v8_1, nist_csf_2_0)")
    control_code: Optional[str] = Field(default=None, description="Control code (e.g., VPM-2)")
    query: Optional[str] = Field(default=None, description="Search query for control name or description")
    domain: Optional[str] = Field(default=None, description="Domain filter")


class FrameworkControlTool(SecurityTool):
    """Search framework controls from the compliance database."""
    
    @property
    def tool_name(self) -> str:
        return "framework_control_search"
    
    def cache_key(self, **kwargs) -> str:
        framework_id = kwargs.get("framework_id", "")
        control_code = kwargs.get("control_code", "")
        query = kwargs.get("query", "")
        return f"framework_control:{framework_id}:{control_code}:{query}"
    
    def execute(
        self,
        framework_id: Optional[str] = None,
        control_code: Optional[str] = None,
        query: Optional[str] = None,
        domain: Optional[str] = None
    ) -> ToolResult:
        """Execute framework control search."""
        try:
            # Framework controls use the default database (not security intel specific)
            with get_session() as session:
                stmt = select(
                    Control.id,
                    Control.framework_id,
                    Control.control_code,
                    Control.name,
                    Control.description,
                    Control.domain,
                    Control.control_type,
                    Framework.name.label("framework_name")
                ).join(Framework, Control.framework_id == Framework.id)
                
                if framework_id:
                    stmt = stmt.where(Control.framework_id == framework_id)
                
                if control_code:
                    stmt = stmt.where(Control.control_code == control_code)
                
                if query:
                    stmt = stmt.where(
                        (Control.name.ilike(f"%{query}%")) |
                        (Control.description.ilike(f"%{query}%"))
                    )
                
                if domain:
                    stmt = stmt.where(Control.domain == domain)
                
                stmt = stmt.order_by(Control.framework_id, Control.control_code)
                
                result = session.execute(stmt)
                rows = result.fetchall()
                
                if not rows:
                    return ToolResult(
                        success=True,
                        data={"controls": [], "message": "No controls found"},
                        source="postgres_framework_control",
                        timestamp=datetime.utcnow().isoformat()
                    )
                
                controls = []
                for row in rows:
                    controls.append({
                        "control_id": row[0],
                        "framework_id": row[1],
                        "framework_name": row[7],
                        "control_code": row[2],
                        "name": row[3],
                        "description": row[4],
                        "domain": row[5],
                        "control_type": row[6],
                    })
                
                return ToolResult(
                    success=True,
                    data={"controls": controls},
                    source="postgres_framework_control",
                    timestamp=datetime.utcnow().isoformat()
                )
        except Exception as e:
            logger.error(f"Error in framework control search: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="postgres_framework_control",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e)
            )


def create_framework_control_tool() -> StructuredTool:
    """Create LangChain tool for framework control search."""
    tool_instance = FrameworkControlTool()
    
    def _execute(
        framework_id: Optional[str] = None,
        control_code: Optional[str] = None,
        query: Optional[str] = None,
        domain: Optional[str] = None
    ) -> Dict[str, Any]:
        result = tool_instance.execute(framework_id, control_code, query, domain)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="framework_control_search",
        description="Search framework controls (CIS, NIST, HIPAA, etc.) from the compliance database. Can filter by framework, control code, domain, or search by name/description.",
        args_schema=FrameworkControlInput,
    )


# ============================================================================
# CIS Benchmark Lookup Tool
# ============================================================================

class CISBenchmarkInput(BaseModel):
    """Input schema for CIS benchmark lookup tool."""
    benchmark_id: Optional[str] = Field(default=None, description="Benchmark ID (e.g., CIS_Ubuntu_Linux_22.04)")
    rule_number: Optional[str] = Field(default=None, description="Rule number (e.g., 1.1.1.1)")
    attack_technique: Optional[str] = Field(default=None, description="ATT&CK technique ID to find related rules")


class CISBenchmarkTool(SecurityTool):
    """Lookup CIS benchmark rules and their mappings."""
    
    @property
    def tool_name(self) -> str:
        return "cis_benchmark_lookup"
    
    def cache_key(self, **kwargs) -> str:
        benchmark_id = kwargs.get("benchmark_id", "")
        rule_number = kwargs.get("rule_number", "")
        attack_technique = kwargs.get("attack_technique", "")
        return f"cis_benchmark:{benchmark_id}:{rule_number}:{attack_technique}"
    
    def execute(
        self,
        benchmark_id: Optional[str] = None,
        rule_number: Optional[str] = None,
        attack_technique: Optional[str] = None
    ) -> ToolResult:
        """Execute CIS benchmark lookup."""
        try:
            with get_security_intel_session("compliance") as session:
                try:
                    base_query = """
                        SELECT 
                            benchmark_id,
                            rule_number,
                            title,
                            description,
                            rationale,
                            remediation,
                            audit_procedure,
                            level,
                            profile,
                            control_id,
                            attack_techniques
                        FROM cis_benchmark_rules
                        WHERE 1=1
                    """
                    params = {}
                    
                    if benchmark_id:
                        base_query += " AND benchmark_id = :benchmark_id"
                        params["benchmark_id"] = benchmark_id
                    
                    if rule_number:
                        base_query += " AND rule_number = :rule_number"
                        params["rule_number"] = rule_number
                    
                    if attack_technique:
                        base_query += " AND :attack_technique = ANY(attack_techniques)"
                        params["attack_technique"] = attack_technique
                    
                    base_query += " ORDER BY benchmark_id, rule_number"
                    
                    stmt = text(base_query)
                    result = session.execute(stmt, params)
                    rows = result.fetchall()
                    
                    if not rows:
                        return ToolResult(
                            success=True,
                            data={"rules": [], "message": "No CIS benchmark rules found"},
                            source="postgres_cis_benchmark",
                            timestamp=datetime.utcnow().isoformat()
                        )
                    
                    rules = []
                    for row in rows:
                        rules.append({
                            "benchmark_id": row[0],
                            "rule_number": row[1],
                            "title": row[2],
                            "description": row[3],
                            "rationale": row[4],
                            "remediation": row[5],
                            "audit_procedure": row[6],
                            "level": row[7],
                            "profile": row[8],
                            "control_id": row[9],
                            "attack_techniques": list(row[10]) if row[10] else [],
                        })
                    
                    return ToolResult(
                        success=True,
                        data={"rules": rules},
                        source="postgres_cis_benchmark",
                        timestamp=datetime.utcnow().isoformat()
                    )
                except Exception as e:
                    if "does not exist" in str(e) or "relation" in str(e).lower():
                        logger.warning(f"cis_benchmark_rules table does not exist: {e}")
                        return ToolResult(
                            success=True,
                            data={"rules": [], "message": "CIS benchmark table not yet populated"},
                            source="postgres_cis_benchmark",
                            timestamp=datetime.utcnow().isoformat()
                        )
                    raise
        except Exception as e:
            logger.error(f"Error in CIS benchmark lookup: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="postgres_cis_benchmark",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e)
            )


def create_cis_benchmark_tool() -> StructuredTool:
    """Create LangChain tool for CIS benchmark lookup."""
    tool_instance = CISBenchmarkTool()
    
    def _execute(
        benchmark_id: Optional[str] = None,
        rule_number: Optional[str] = None,
        attack_technique: Optional[str] = None
    ) -> Dict[str, Any]:
        result = tool_instance.execute(benchmark_id, rule_number, attack_technique)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="cis_benchmark_lookup",
        description="Lookup CIS benchmark rules and their mappings to controls and ATT&CK techniques. Can filter by benchmark, rule number, or ATT&CK technique.",
        args_schema=CISBenchmarkInput,
    )


# ============================================================================
# Gap Analysis Tool (Stub - Complex tool requiring multiple data sources)
# ============================================================================

class GapAnalysisInput(BaseModel):
    """Input schema for gap analysis tool."""
    framework_id: str = Field(description="Framework ID to analyze")
    attack_techniques: Optional[List[str]] = Field(default=None, description="ATT&CK techniques to check coverage for")


class GapAnalysisTool(SecurityTool):
    """Perform gap analysis between frameworks and ATT&CK coverage."""
    
    @property
    def tool_name(self) -> str:
        return "gap_analysis"
    
    def cache_key(self, **kwargs) -> str:
        framework_id = kwargs.get("framework_id", "")
        attack_techniques = kwargs.get("attack_techniques", [])
        return f"gap_analysis:{framework_id}:{':'.join(attack_techniques) if attack_techniques else 'all'}"
    
    def execute(self, framework_id: str, attack_techniques: Optional[List[str]] = None) -> ToolResult:
        """Execute gap analysis."""
        # This is a complex tool that would require:
        # 1. Query attack_technique_control_mapping for the framework
        # 2. Compare against all known ATT&CK techniques
        # 3. Identify gaps
        # 4. Calculate coverage percentages
        
        # For now, return a stub response
        return ToolResult(
            success=True,
            data={
                "framework_id": framework_id,
                "message": "Gap analysis tool - implementation in progress",
                "note": "This tool requires comprehensive ATT&CK technique mapping data"
            },
            source="postgres_gap_analysis",
            timestamp=datetime.utcnow().isoformat()
        )


def create_gap_analysis_tool() -> StructuredTool:
    """Create LangChain tool for gap analysis."""
    tool_instance = GapAnalysisTool()
    
    def _execute(framework_id: str, attack_techniques: Optional[List[str]] = None) -> Dict[str, Any]:
        result = tool_instance.execute(framework_id, attack_techniques)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="gap_analysis",
        description="Perform gap analysis to identify missing controls or ATT&CK technique coverage gaps in a framework. Returns coverage statistics and recommendations.",
        args_schema=GapAnalysisInput,
    )
