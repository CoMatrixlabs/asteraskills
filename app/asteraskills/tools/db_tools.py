"""
Postgres database-based security intelligence tools.
These tools query custom Postgres tables for mappings and intelligence.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from asteraskills.tools.base import ToolResult, SecurityTool
from asteraskills.storage.sqlalchemy_session import get_session, get_security_intel_session

logger = logging.getLogger(__name__)


# ============================================================================
# CVE to ATT&CK Technique Mapping Tool
# ============================================================================

class CVEtoATTACKInput(BaseModel):
    """Input schema for CVE to ATT&CK mapping tool."""
    cve_id: str = Field(description="CVE identifier (e.g., CVE-2024-1234)")


class CVEtoATTACKMapperTool(SecurityTool):
    """Map CVE to MITRE ATT&CK techniques via Postgres mapping table."""
    
    @property
    def tool_name(self) -> str:
        return "cve_to_attack_mapper"
    
    def cache_key(self, **kwargs) -> str:
        cve_id = kwargs.get("cve_id", "")
        return f"cve_attack:{cve_id}"
    
    def execute(self, cve_id: str) -> ToolResult:
        """Execute CVE to ATT&CK mapping lookup."""
        try:
            with get_security_intel_session("cve_attack") as session:
                # Query cve_attack_mapping table
                # Note: This assumes the table exists. If not, return empty result.
                try:
                    stmt = text("""
                        SELECT 
                            attack_technique_id,
                            attack_tactic,
                            mapping_source,
                            confidence_score,
                            notes
                        FROM cve_attack_mapping
                        WHERE cve_id = :cve_id
                        ORDER BY confidence_score DESC
                    """)
                    
                    result = session.execute(stmt, {"cve_id": cve_id})
                    rows = result.fetchall()
                    
                    if not rows:
                        return ToolResult(
                            success=True,
                            data={
                                "cve_id": cve_id,
                                "attack_techniques": [],
                                "message": "No ATT&CK mappings found for this CVE"
                            },
                            source="postgres_attack_mapping",
                            timestamp=datetime.utcnow().isoformat()
                        )
                    
                    techniques = []
                    for row in rows:
                        techniques.append({
                            "technique_id": row[0],
                            "tactic": row[1],
                            "mapping_source": row[2],
                            "confidence_score": float(row[3]) if row[3] else None,
                            "notes": row[4],
                        })
                    
                    return ToolResult(
                        success=True,
                        data={
                            "cve_id": cve_id,
                            "attack_techniques": techniques
                        },
                        source="postgres_attack_mapping",
                        timestamp=datetime.utcnow().isoformat()
                    )
                except Exception as e:
                    # Table might not exist yet
                    if "does not exist" in str(e) or "relation" in str(e).lower():
                        logger.warning(f"cve_attack_mapping table does not exist: {e}")
                        return ToolResult(
                            success=True,
                            data={
                                "cve_id": cve_id,
                                "attack_techniques": [],
                                "message": "ATT&CK mapping table not yet populated"
                            },
                            source="postgres_attack_mapping",
                            timestamp=datetime.utcnow().isoformat()
                        )
                    raise
        except Exception as e:
            logger.error(f"Error in CVE to ATT&CK mapping: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="postgres_attack_mapping",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e)
            )


def create_cve_to_attack_tool() -> StructuredTool:
    """Create LangChain tool for CVE to ATT&CK mapping."""
    tool_instance = CVEtoATTACKMapperTool()
    
    def _execute(cve_id: str) -> Dict[str, Any]:
        result = tool_instance.execute(cve_id)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="cve_to_attack_mapper",
        description="Map a CVE to MITRE ATT&CK techniques. Returns associated attack techniques, tactics, and confidence scores from the mapping database.",
        args_schema=CVEtoATTACKInput,
    )


# ============================================================================
# ATT&CK Technique to Control Mapping Tool
# ============================================================================

class ATTACKtoControlInput(BaseModel):
    """Input schema for ATT&CK to Control mapping tool."""
    technique_id: str = Field(description="ATT&CK technique ID (e.g., T1003.001)")
    framework_ids: Optional[List[str]] = Field(default=None, description="Optional list of framework IDs to filter by")


class ATTACKtoControlMapperTool(SecurityTool):
    """Map ATT&CK technique to framework controls via Postgres mapping table."""
    
    @property
    def tool_name(self) -> str:
        return "attack_to_control_mapper"
    
    def cache_key(self, **kwargs) -> str:
        technique_id = kwargs.get("technique_id", "")
        framework_ids = kwargs.get("framework_ids", [])
        return f"attack_control:{technique_id}:{':'.join(framework_ids) if framework_ids else 'all'}"
    
    def execute(self, technique_id: str, framework_ids: Optional[List[str]] = None) -> ToolResult:
        """Execute ATT&CK to Control mapping lookup."""
        try:
            with get_security_intel_session("cve_attack") as session:
                try:
                    # Query attack_technique_control_mapping table
                    # Join with controls and frameworks tables
                    base_query = """
                        SELECT 
                            atcm.attack_technique_id,
                            c.id as control_id,
                            c.name as control_name,
                            c.description as control_description,
                            f.id as framework_id,
                            f.name as framework_name,
                            atcm.mitigation_effectiveness,
                            atcm.confidence_score,
                            atcm.notes
                        FROM attack_technique_control_mapping atcm
                        JOIN controls c ON atcm.control_id = c.id
                        JOIN frameworks f ON c.framework_id = f.id
                        WHERE atcm.attack_technique_id = :technique_id
                    """
                    
                    params = {"technique_id": technique_id}
                    
                    if framework_ids:
                        placeholders = ",".join([f":framework_{i}" for i in range(len(framework_ids))])
                        base_query += f" AND f.id IN ({placeholders})"
                        for i, fw_id in enumerate(framework_ids):
                            params[f"framework_{i}"] = fw_id
                    
                    base_query += " ORDER BY atcm.confidence_score DESC, atcm.mitigation_effectiveness DESC"
                    
                    stmt = text(base_query)
                    result = session.execute(stmt, params)
                    rows = result.fetchall()
                    
                    if not rows:
                        return ToolResult(
                            success=True,
                            data={
                                "technique_id": technique_id,
                                "controls": [],
                                "message": "No control mappings found for this ATT&CK technique"
                            },
                            source="postgres_attack_control_mapping",
                            timestamp=datetime.utcnow().isoformat()
                        )
                    
                    controls = []
                    for row in rows:
                        controls.append({
                            "control_id": row[1],
                            "control_name": row[2],
                            "control_description": row[3],
                            "framework_id": row[4],
                            "framework_name": row[5],
                            "mitigation_effectiveness": row[6],
                            "confidence_score": float(row[7]) if row[7] else None,
                            "notes": row[8],
                        })
                    
                    return ToolResult(
                        success=True,
                        data={
                            "technique_id": technique_id,
                            "controls": controls
                        },
                        source="postgres_attack_control_mapping",
                        timestamp=datetime.utcnow().isoformat()
                    )
                except Exception as e:
                    # Table might not exist yet
                    if "does not exist" in str(e) or "relation" in str(e).lower():
                        logger.warning(f"attack_technique_control_mapping table does not exist: {e}")
                        return ToolResult(
                            success=True,
                            data={
                                "technique_id": technique_id,
                                "controls": [],
                                "message": "ATT&CK to control mapping table not yet populated"
                            },
                            source="postgres_attack_control_mapping",
                            timestamp=datetime.utcnow().isoformat()
                        )
                    raise
        except Exception as e:
            logger.error(f"Error in ATT&CK to Control mapping: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="postgres_attack_control_mapping",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e)
            )


def create_attack_to_control_tool() -> StructuredTool:
    """Create LangChain tool for ATT&CK to Control mapping."""
    tool_instance = ATTACKtoControlMapperTool()
    
    def _execute(technique_id: str, framework_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        result = tool_instance.execute(technique_id, framework_ids)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="attack_to_control_mapper",
        description="Map a MITRE ATT&CK technique to framework controls (CIS, NIST, HIPAA, etc.). Returns controls that mitigate the technique, their effectiveness, and confidence scores.",
        args_schema=ATTACKtoControlInput,
    )


# ============================================================================
# CPE Resolver Tool
# ============================================================================

class CPEResolverInput(BaseModel):
    """Input schema for CPE resolver tool."""
    vendor: Optional[str] = Field(default=None, description="Vendor name (e.g., apache)")
    product: Optional[str] = Field(default=None, description="Product name (e.g., log4j)")
    version: Optional[str] = Field(default=None, description="Version (e.g., 2.14.1)")
    cpe_uri: Optional[str] = Field(default=None, description="Full CPE URI (e.g., cpe:2.3:a:apache:log4j:2.14.1)")


class CPEResolverTool(SecurityTool):
    """Resolve CPE (Common Platform Enumeration) to find affected CVEs."""
    
    @property
    def tool_name(self) -> str:
        return "cpe_resolver"
    
    def cache_key(self, **kwargs) -> str:
        cpe_uri = kwargs.get("cpe_uri", "")
        vendor = kwargs.get("vendor", "")
        product = kwargs.get("product", "")
        version = kwargs.get("version", "")
        return f"cpe_resolver:{cpe_uri or f'{vendor}:{product}:{version}'}"
    
    def execute(
        self,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
        cpe_uri: Optional[str] = None
    ) -> ToolResult:
        """Execute CPE resolution."""
        try:
            with get_security_intel_session("cpe") as session:
                try:
                    if cpe_uri:
                        # Direct CPE URI lookup
                        stmt = text("""
                            SELECT 
                                cve_id,
                                version_start,
                                version_end,
                                version_start_including,
                                version_end_including
                            FROM cve_cpe_affected
                            WHERE cpe_uri = :cpe_uri
                            ORDER BY cve_id
                        """)
                        result = session.execute(stmt, {"cpe_uri": cpe_uri})
                    elif vendor and product:
                        # Search by vendor/product/version
                        query = """
                            SELECT DISTINCT
                                cca.cve_id,
                                cca.version_start,
                                cca.version_end,
                                cca.version_start_including,
                                cca.version_end_including,
                                cd.cpe_uri,
                                cd.cpe_title
                            FROM cve_cpe_affected cca
                            JOIN cpe_dictionary cd ON cca.cpe_uri = cd.cpe_uri
                            WHERE cd.vendor = :vendor AND cd.product = :product
                        """
                        params = {"vendor": vendor, "product": product}
                        
                        if version:
                            query += " AND cd.version = :version"
                            params["version"] = version
                        
                        query += " ORDER BY cca.cve_id"
                        stmt = text(query)
                        result = session.execute(stmt, params)
                    else:
                        return ToolResult(
                            success=False,
                            data=None,
                            source="postgres_cpe_resolver",
                            timestamp=datetime.utcnow().isoformat(),
                            error_message="Must provide either cpe_uri or both vendor and product"
                        )
                    
                    rows = result.fetchall()
                    
                    if not rows:
                        return ToolResult(
                            success=True,
                            data={
                                "cves": [],
                                "message": "No CVEs found for the specified CPE"
                            },
                            source="postgres_cpe_resolver",
                            timestamp=datetime.utcnow().isoformat()
                        )
                    
                    cves = []
                    for row in rows:
                        cve_data = {
                            "cve_id": row[0],
                            "version_start": row[1],
                            "version_end": row[2],
                            "version_start_including": row[3] if len(row) > 3 else None,
                            "version_end_including": row[4] if len(row) > 4 else None,
                        }
                        if len(row) > 5:
                            cve_data["cpe_uri"] = row[5]
                            cve_data["cpe_title"] = row[6]
                        cves.append(cve_data)
                    
                    return ToolResult(
                        success=True,
                        data={"cves": cves},
                        source="postgres_cpe_resolver",
                        timestamp=datetime.utcnow().isoformat()
                    )
                except Exception as e:
                    # Table might not exist yet
                    if "does not exist" in str(e) or "relation" in str(e).lower():
                        logger.warning(f"CPE tables do not exist: {e}")
                        return ToolResult(
                            success=True,
                            data={
                                "cves": [],
                                "message": "CPE dictionary tables not yet populated"
                            },
                            source="postgres_cpe_resolver",
                            timestamp=datetime.utcnow().isoformat()
                        )
                    raise
        except Exception as e:
            logger.error(f"Error in CPE resolver: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="postgres_cpe_resolver",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e)
            )


def create_cpe_resolver_tool() -> StructuredTool:
    """Create LangChain tool for CPE resolution."""
    tool_instance = CPEResolverTool()
    
    def _execute(
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
        cpe_uri: Optional[str] = None
    ) -> Dict[str, Any]:
        result = tool_instance.execute(vendor, product, version, cpe_uri)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="cpe_resolver",
        description="Resolve CPE (Common Platform Enumeration) to find affected CVEs. Can search by vendor/product/version or by full CPE URI. Returns list of CVEs affecting the specified software.",
        args_schema=CPEResolverInput,
    )
