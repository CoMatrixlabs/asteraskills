"""
API-based security intelligence tools.
These tools fetch data from external APIs (NVD, EPSS, CISA KEV, etc.).
"""

import os
import logging
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.tools.base import ToolResult, SecurityTool

logger = logging.getLogger(__name__)


# ============================================================================
# NVD CVE API Tool
# ============================================================================

class CVEIntelligenceInput(BaseModel):
    """Input schema for CVE intelligence tool."""
    cve_id: str = Field(description="CVE identifier (e.g., CVE-2024-1234)")
    force_refresh: bool = Field(default=False, description="Force refresh even if cached")


class CVEIntelligenceTool(SecurityTool):
    """
    Fetch comprehensive CVE intelligence from multiple sources.
    
    Combines data from:
    - NVD API for CVE details
    - EPSS API for exploit prediction
    - CISA KEV for active exploitation status
    """
    
    def __init__(self):
        from asteraskills.config.settings import get_settings

        self.nvd_api_key = get_settings().NVD_API_KEY or os.getenv("NVD_API_KEY")  # Optional, increases rate limit
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.epss_base_url = "https://api.first.org/data/v1/epss"
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self._kev_cache: Optional[Dict[str, Any]] = None
        self._kev_cache_time: Optional[datetime] = None
    
    @property
    def tool_name(self) -> str:
        return "cve_intelligence"
    
    def cache_key(self, **kwargs) -> str:
        cve_id = kwargs.get("cve_id", "")
        return f"cve_intelligence:{cve_id}"
    
    def _fetch_nvd(self, cve_id: str) -> Dict[str, Any]:
        """Fetch CVE details from NVD API."""
        try:
            headers = {}
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key
            
            params = {"cveId": cve_id}
            response = requests.get(
                self.nvd_base_url,
                headers=headers,
                params=params,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            if not data.get("vulnerabilities"):
                return {"error": f"No NVD data found for {cve_id}"}
            
            vuln = data["vulnerabilities"][0]["cve"]
            
            # Extract CVSS scores
            cvss_v3 = None
            cvss_v2 = None
            if "metrics" in vuln:
                if "cvssMetricV31" in vuln["metrics"]:
                    cvss_v3 = vuln["metrics"]["cvssMetricV31"][0]["cvssData"]
                elif "cvssMetricV30" in vuln["metrics"]:
                    cvss_v3 = vuln["metrics"]["cvssMetricV30"][0]["cvssData"]
                if "cvssMetricV2" in vuln["metrics"]:
                    cvss_v2 = vuln["metrics"]["cvssMetricV2"][0]["cvssData"]
            
            return {
                "cve_id": cve_id,
                "description": vuln.get("descriptions", [{}])[0].get("value", ""),
                "published_date": vuln.get("published"),
                "last_modified": vuln.get("lastModified"),
                "cvss_v3": cvss_v3,
                "cvss_v2": cvss_v2,
                "cwe_ids": [weak["value"] for weak in vuln.get("weaknesses", [])],
                "references": [ref.get("url") for ref in vuln.get("references", [])],
            }
        except Exception as e:
            logger.error(f"Error fetching NVD data for {cve_id}: {e}")
            return {"error": str(e)}
    
    def _fetch_epss(self, cve_id: str) -> Dict[str, Any]:
        """Fetch EPSS score from FIRST API."""
        try:
            params = {"cve": cve_id}
            response = requests.get(
                self.epss_base_url,
                params=params,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            if not data.get("data"):
                return {"epss": None, "percentile": None}
            
            epss_data = data["data"][0]
            return {
                "epss": float(epss_data.get("epss", 0)),
                "percentile": float(epss_data.get("percentile", 0)),
                "date": epss_data.get("date"),
            }
        except Exception as e:
            logger.error(f"Error fetching EPSS data for {cve_id}: {e}")
            return {"epss": None, "error": str(e)}
    
    def _check_cisa_kev(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Check if CVE is in CISA KEV (Known Exploited Vulnerabilities)."""
        try:
            # Cache KEV data for 24 hours
            if (self._kev_cache is None or 
                self._kev_cache_time is None or 
                datetime.now() - self._kev_cache_time > timedelta(hours=24)):
                
                response = requests.get(self.kev_url, timeout=10)
                response.raise_for_status()
                self._kev_cache = response.json()
                self._kev_cache_time = datetime.now()
            
            # Search for CVE in KEV
            for vuln in self._kev_cache.get("vulnerabilities", []):
                if vuln.get("cveID") == cve_id:
                    return {
                        "cve_id": cve_id,
                        "vendor_project": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                        "vulnerability_name": vuln.get("vulnerabilityName"),
                        "date_added": vuln.get("dateAdded"),
                        "required_action": vuln.get("requiredAction"),
                        "due_date": vuln.get("dueDate"),
                    }
            
            return None
        except Exception as e:
            logger.error(f"Error checking CISA KEV for {cve_id}: {e}")
            return None
    
    def execute(self, cve_id: str, force_refresh: bool = False) -> ToolResult:
        """Execute CVE intelligence gathering."""
        try:
            # Fetch from APIs
            nvd_data = self._fetch_nvd(cve_id)
            epss_data = self._fetch_epss(cve_id)
            kev_data = self._check_cisa_kev(cve_id)
            
            # Synthesize result
            result = {
                "cve_id": cve_id,
                "nvd": nvd_data,
                "epss_score": epss_data.get("epss"),
                "epss_percentile": epss_data.get("percentile"),
                "actively_exploited": kev_data is not None,
                "kev_details": kev_data,
            }
            
            return ToolResult(
                success=True,
                data=result,
                source="aggregated",
                timestamp=datetime.utcnow().isoformat(),
                cache_hit=False
            )
        except Exception as e:
            logger.error(f"Error in CVE intelligence tool: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="cve_intelligence",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e)
            )


def create_cve_intelligence_tool() -> StructuredTool:
    """Create LangChain tool for CVE intelligence."""
    tool_instance = CVEIntelligenceTool()
    
    def _execute(cve_id: str, force_refresh: bool = False) -> Dict[str, Any]:
        result = tool_instance.execute(cve_id, force_refresh)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="cve_intelligence",
        description="Fetch comprehensive CVE intelligence including NVD details, EPSS exploit prediction scores, and CISA KEV active exploitation status. Use this to get detailed information about a specific CVE.",
        args_schema=CVEIntelligenceInput,
    )


# ============================================================================
# EPSS Lookup Tool
# ============================================================================

class EPSSLookupInput(BaseModel):
    """Input schema for EPSS lookup tool."""
    cve_id: str = Field(description="CVE identifier (e.g., CVE-2024-1234)")


class EPSSLookupTool(SecurityTool):
    """Query FIRST EPSS for exploit prediction scoring."""
    
    def __init__(self):
        self.base_url = "https://api.first.org/data/v1/epss"
    
    @property
    def tool_name(self) -> str:
        return "epss_lookup"
    
    def cache_key(self, **kwargs) -> str:
        cve_id = kwargs.get("cve_id", "")
        return f"epss:{cve_id}"
    
    def execute(self, cve_id: str) -> ToolResult:
        """Execute EPSS lookup."""
        try:
            params = {"cve": cve_id}
            response = requests.get(self.base_url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if not data.get("data"):
                return ToolResult(
                    success=False,
                    data=None,
                    source="epss_api",
                    timestamp=datetime.utcnow().isoformat(),
                    error_message=f"No EPSS score for {cve_id}"
                )
            
            epss_data = data["data"][0]
            result = {
                "cve": epss_data.get("cve"),
                "epss": float(epss_data.get("epss", 0)),
                "percentile": float(epss_data.get("percentile", 0)),
                "date": epss_data.get("date"),
            }
            
            return ToolResult(
                success=True,
                data=result,
                source="epss_api",
                timestamp=epss_data.get("date", datetime.utcnow().isoformat())
            )
        except Exception as e:
            logger.error(f"Error in EPSS lookup: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="epss_api",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e)
            )


def create_epss_lookup_tool() -> StructuredTool:
    """Create LangChain tool for EPSS lookup."""
    tool_instance = EPSSLookupTool()
    
    def _execute(cve_id: str) -> Dict[str, Any]:
        result = tool_instance.execute(cve_id)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="epss_lookup",
        description="Query FIRST EPSS (Exploit Prediction Scoring System) for exploit prediction scores. Returns a score from 0-1 indicating likelihood of exploitation and percentile ranking.",
        args_schema=EPSSLookupInput,
    )


# ============================================================================
# CISA KEV Check Tool
# ============================================================================

class CISAKEVInput(BaseModel):
    """Input schema for CISA KEV check tool."""
    cve_id: str = Field(description="CVE identifier to check against CISA KEV")


class CISAKEVTool(SecurityTool):
    """Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog."""
    
    def __init__(self):
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self._cache: Optional[Dict[str, Any]] = None
        self._cache_time: Optional[datetime] = None
    
    @property
    def tool_name(self) -> str:
        return "cisa_kev_check"
    
    def cache_key(self, **kwargs) -> str:
        cve_id = kwargs.get("cve_id", "")
        return f"cisa_kev:{cve_id}"
    
    def execute(self, cve_id: str) -> ToolResult:
        """Execute CISA KEV check."""
        try:
            # Cache KEV data for 24 hours
            if (self._cache is None or 
                self._cache_time is None or 
                datetime.now() - self._cache_time > timedelta(hours=24)):
                
                response = requests.get(self.kev_url, timeout=10)
                response.raise_for_status()
                self._cache = response.json()
                self._cache_time = datetime.now()
            
            # Search for CVE
            for vuln in self._cache.get("vulnerabilities", []):
                if vuln.get("cveID") == cve_id:
                    return ToolResult(
                        success=True,
                        data={
                            "cve_id": cve_id,
                            "in_kev": True,
                            "vendor_project": vuln.get("vendorProject"),
                            "product": vuln.get("product"),
                            "vulnerability_name": vuln.get("vulnerabilityName"),
                            "date_added": vuln.get("dateAdded"),
                            "required_action": vuln.get("requiredAction"),
                            "due_date": vuln.get("dueDate"),
                        },
                        source="cisa_kev",
                        timestamp=datetime.utcnow().isoformat()
                    )
            
            return ToolResult(
                success=True,
                data={"cve_id": cve_id, "in_kev": False},
                source="cisa_kev",
                timestamp=datetime.utcnow().isoformat()
            )
        except Exception as e:
            logger.error(f"Error in CISA KEV check: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="cisa_kev",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e)
            )


def create_cisa_kev_tool() -> StructuredTool:
    """Create LangChain tool for CISA KEV check."""
    tool_instance = CISAKEVTool()
    
    def _execute(cve_id: str) -> Dict[str, Any]:
        result = tool_instance.execute(cve_id)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="cisa_kev_check",
        description="Check if a CVE is listed in CISA's Known Exploited Vulnerabilities (KEV) catalog. CVEs in KEV are actively being exploited and require immediate action.",
        args_schema=CISAKEVInput,
    )


# ============================================================================
# GitHub Advisory Search Tool
# ============================================================================

class GitHubAdvisoryInput(BaseModel):
    """Input schema for GitHub Advisory search tool."""
    query: str = Field(description="Search query (CVE ID, package name, or vulnerability description)")
    ecosystem: Optional[str] = Field(default=None, description="Package ecosystem (npm, pypi, maven, nuget, rubygems)")


class GitHubAdvisoryTool(SecurityTool):
    """Search GitHub Advisory Database for OSS package vulnerabilities."""
    
    def __init__(self):
        self.base_url = "https://api.github.com/advisories"
        self.token = os.getenv("GITHUB_TOKEN")  # Optional, increases rate limit
    
    @property
    def tool_name(self) -> str:
        return "github_advisory_search"
    
    def cache_key(self, **kwargs) -> str:
        query = kwargs.get("query", "")
        ecosystem = kwargs.get("ecosystem", "")
        return f"github_advisory:{query}:{ecosystem}"
    
    def execute(self, query: str, ecosystem: Optional[str] = None) -> ToolResult:
        """Execute GitHub Advisory search."""
        try:
            headers = {"Accept": "application/vnd.github+json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            
            params = {"q": query}
            if ecosystem:
                params["ecosystem"] = ecosystem
            
            # GitHub Advisory API uses GraphQL, but we'll use the REST API for advisories
            # Note: GitHub's REST API for advisories is limited, this is a simplified version
            response = requests.get(
                f"{self.base_url}",
                headers=headers,
                params=params,
                timeout=10
            )
            
            # GitHub Advisory API might require GraphQL - this is a placeholder
            # In production, you'd use the GraphQL API or search via GitHub's search API
            if response.status_code == 404:
                # Fallback: use GitHub's search API
                search_url = "https://api.github.com/search/code"
                params = {"q": f"{query} language:yaml path:advisories"}
                response = requests.get(search_url, headers=headers, params=params, timeout=10)
            
            response.raise_for_status()
            data = response.json()
            
            return ToolResult(
                success=True,
                data=data,
                source="github_advisory_api",
                timestamp=datetime.utcnow().isoformat()
            )
        except Exception as e:
            logger.error(f"Error in GitHub Advisory search: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="github_advisory_api",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e)
            )


def create_github_advisory_tool() -> StructuredTool:
    """Create LangChain tool for GitHub Advisory search."""
    tool_instance = GitHubAdvisoryTool()
    
    def _execute(query: str, ecosystem: Optional[str] = None) -> Dict[str, Any]:
        result = tool_instance.execute(query, ecosystem)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="github_advisory_search",
        description="Search GitHub Advisory Database for open-source package vulnerabilities. Supports npm, PyPI, Maven, NuGet, and RubyGems ecosystems.",
        args_schema=GitHubAdvisoryInput,
    )


# ============================================================================
# CPE Lookup Tool
# ============================================================================

class CPELookupInput(BaseModel):
    """Input schema for CPE lookup tool."""
    product_name: Optional[str] = Field(default=None, description="Product name to search for (e.g., 'log4j', 'apache', 'nginx')")
    vendor: Optional[str] = Field(default=None, description="Vendor name (e.g., 'apache', 'microsoft')")
    product: Optional[str] = Field(default=None, description="Exact product name")
    version: Optional[str] = Field(default=None, description="Specific version to lookup")
    limit: int = Field(default=20, description="Maximum number of results to return")


class CPELookupTool(SecurityTool):
    """
    Lookup CPE (Common Platform Enumeration) entries for software/products.
    
    This tool searches the CPE dictionary to find software products,
    their vendors, versions, and CPE URIs. Useful for discovering
    how software is identified in vulnerability databases.
    """
    
    def __init__(self):
        from asteraskills.config.settings import get_settings

        self.nvd_api_key = get_settings().NVD_API_KEY or os.getenv("NVD_API_KEY")  # Optional, increases rate limit
        self.nvd_cpe_base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    
    @property
    def tool_name(self) -> str:
        return "cpe_lookup"
    
    def cache_key(self, **kwargs) -> str:
        product_name = kwargs.get("product_name", "")
        vendor = kwargs.get("vendor", "")
        product = kwargs.get("product", "")
        version = kwargs.get("version", "")
        return f"cpe_lookup:{product_name}:{vendor}:{product}:{version}"
    
    def _search_postgres(self, product_name: Optional[str] = None, vendor: Optional[str] = None,
                        product: Optional[str] = None, version: Optional[str] = None,
                        limit: int = 20) -> Optional[Dict[str, Any]]:
        """Search CPE dictionary in Postgres."""
        try:
            from asteraskills.storage.sqlalchemy_session import get_security_intel_session
            from sqlalchemy import text
            
            with get_security_intel_session("cpe") as session:
                try:
                    base_query = """
                        SELECT 
                            cpe_uri,
                            vendor,
                            product,
                            version,
                            cpe_title,
                            deprecated
                        FROM cpe_dictionary
                        WHERE 1=1
                    """
                    params = {}
                    
                    if product_name:
                        # Search in product name or title
                        base_query += """
                            AND (
                                product ILIKE :product_name 
                                OR cpe_title ILIKE :product_name
                                OR vendor ILIKE :product_name
                            )
                        """
                        params["product_name"] = f"%{product_name}%"
                    
                    if vendor:
                        base_query += " AND vendor ILIKE :vendor"
                        params["vendor"] = f"%{vendor}%"
                    
                    if product:
                        base_query += " AND product ILIKE :product"
                        params["product"] = f"%{product}%"
                    
                    if version:
                        base_query += " AND version = :version"
                        params["version"] = version
                    
                    base_query += " ORDER BY vendor, product, version LIMIT :limit"
                    params["limit"] = limit
                    
                    stmt = text(base_query)
                    result = session.execute(stmt, params)
                    rows = result.fetchall()
                    
                    if rows:
                        cpes = []
                        for row in rows:
                            cpes.append({
                                "cpe_uri": row[0],
                                "vendor": row[1],
                                "product": row[2],
                                "version": row[3],
                                "cpe_title": row[4],
                                "deprecated": row[5],
                            })
                        return {"cpes": cpes, "source": "postgres"}
                except Exception as e:
                    if "does not exist" in str(e) or "relation" in str(e).lower():
                        logger.debug(f"CPE dictionary table not available: {e}")
                        return None
                    raise
        except Exception as e:
            logger.debug(f"Postgres CPE lookup failed: {e}")
            return None
        
        return None
    
    def _search_nvd_api(self, product_name: Optional[str] = None, vendor: Optional[str] = None,
                       product: Optional[str] = None, limit: int = 20) -> Optional[Dict[str, Any]]:
        """Search NVD CPE API."""
        try:
            headers = {"Content-Type": "application/json"}
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key
            
            # Build search criteria for NVD CPE API v2.0
            # NVD CPE API uses keyword search or matchString
            criteria = {}
            if vendor and product:
                # Exact match string format: cpe:2.3:a:vendor:product:*
                match_string = f"cpe:2.3:a:{vendor}:{product}:*"
                criteria["matchString"] = match_string
            elif product_name:
                # Keyword search
                criteria["keywordSearch"] = product_name
            elif vendor:
                criteria["matchString"] = f"cpe:2.3:a:{vendor}:*:*"
            elif product:
                criteria["matchString"] = f"cpe:2.3:a:*:{product}:*"
            else:
                return None
            
            params = {
                "resultsPerPage": min(limit, 50),  # NVD API max is 50
                "startIndex": 0,
            }
            
            # NVD CPE API v2.0 uses POST with criteria in body
            response = requests.post(
                self.nvd_cpe_base_url,
                headers=headers,
                json=criteria,
                params=params,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            cpes = []
            # NVD CPE API v2.0 response structure
            for item in data.get("products", []):
                cpe_data = item.get("cpe", {})
                titles = cpe_data.get("titles", [])
                cpe_name = cpe_data.get("cpeName", "")
                
                # Parse CPE URI to extract components
                parts = cpe_name.split(":") if cpe_name else []
                vendor_part = parts[3] if len(parts) > 3 else ""
                product_part = parts[4] if len(parts) > 4 else ""
                version_part = parts[5] if len(parts) > 5 else ""
                
                cpes.append({
                    "cpe_uri": cpe_name,
                    "vendor": vendor_part,
                    "product": product_part,
                    "version": version_part if version_part != "*" else None,
                    "cpe_title": titles[0].get("title", "") if titles else "",
                    "deprecated": cpe_data.get("deprecated", False),
                })
            
            return {
                "cpes": cpes,
                "source": "nvd_api",
                "total_results": data.get("totalResults", len(cpes))
            }
        except Exception as e:
            logger.debug(f"NVD CPE API lookup failed: {e}")
            return None
    
    def execute(
        self,
        product_name: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
        limit: int = 20
    ) -> ToolResult:
        """Execute CPE lookup."""
        try:
            # Try Postgres first (faster, local)
            result = self._search_postgres(product_name, vendor, product, version, limit)
            
            # Fallback to NVD API if Postgres doesn't have data
            if not result or not result.get("cpes"):
                result = self._search_nvd_api(product_name, vendor, product, limit)
            
            if not result or not result.get("cpes"):
                return ToolResult(
                    success=True,
                    data={
                        "cpes": [],
                        "message": "No CPE entries found. Try different search terms or ensure CPE dictionary is populated.",
                        "search_params": {
                            "product_name": product_name,
                            "vendor": vendor,
                            "product": product,
                            "version": version,
                        }
                    },
                    source="cpe_lookup",
                    timestamp=datetime.utcnow().isoformat()
                )
            
            return ToolResult(
                success=True,
                data={
                    "cpes": result["cpes"],
                    "source": result.get("source", "unknown"),
                    "total_results": result.get("total_results", len(result["cpes"])),
                },
                source="cpe_lookup",
                timestamp=datetime.utcnow().isoformat()
            )
        except Exception as e:
            logger.error(f"Error in CPE lookup: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="cpe_lookup",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e)
            )


def create_cpe_lookup_tool() -> StructuredTool:
    """Create LangChain tool for CPE lookup."""
    tool_instance = CPELookupTool()
    
    def _execute(
        product_name: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
        limit: int = 20
    ) -> Dict[str, Any]:
        result = tool_instance.execute(product_name, vendor, product, version, limit)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="cpe_lookup",
        description="Lookup CPE (Common Platform Enumeration) entries for software and products. Search by product name, vendor, or specific product/version. Returns CPE URIs, vendor/product information, and version details. Use this to discover how software is identified in vulnerability databases before using cpe_resolver to find CVEs.",
        args_schema=CPELookupInput,
    )
