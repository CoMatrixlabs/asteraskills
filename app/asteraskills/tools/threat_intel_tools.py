"""
Threat intelligence tools (AlienVault OTX, VirusTotal).
These tools query external APIs for threat intelligence.
"""

import os
import logging
import requests
from typing import Dict, Any, Optional
from datetime import datetime

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.tools.base import ToolResult, SecurityTool
from asteraskills.tools.otxv2 import OTXv2

logger = logging.getLogger(__name__)


# ============================================================================
# AlienVault OTX Pulse Search Tool
# ============================================================================

class OTXPulseInput(BaseModel):
    """Input schema for OTX pulse search tool."""
    query: str = Field(description="Search query (IoC, CVE, malware family, etc.)")
    limit: int = Field(default=10, description="Maximum number of results (1-50)")


class AlienVaultOTXTool(SecurityTool):
    """
    Search AlienVault OTX for threat intelligence pulses.
    
    Uses the official OTX Python SDK (OTXv2) which provides:
    - Built-in retry logic with exponential backoff
    - Better error handling
    - Session management for connection reuse
    - Automatic handling of rate limits (429) and server errors (5xx)
    
    Reference: https://github.com/AlienVault-OTX/OTX-Python-SDK
    API Docs: https://otx.alienvault.com/api/
    """
    
    def __init__(self):
        self.api_key = os.getenv("OTX_API_KEY")
        if not self.api_key:
            logger.warning("OTX_API_KEY not set. OTX tool will not work.")
            self.otx_client = None
        else:
            # Initialize OTX SDK client with retry logic built-in
            # The SDK automatically handles retries for 429, 500, 502, 503, 504 errors
            self.otx_client = OTXv2(self.api_key, server="https://otx.alienvault.com")
    
    @property
    def tool_name(self) -> str:
        return "otx_pulse_search"
    
    def cache_key(self, **kwargs) -> str:
        query = kwargs.get("query", "")
        limit = kwargs.get("limit", 10)
        return f"otx:{query}:{limit}"
    
    def execute(self, query: str, limit: int = 10) -> ToolResult:
        """Execute OTX pulse search using the official SDK."""
        if not self.api_key or not self.otx_client:
            return ToolResult(
                success=False,
                data=None,
                source="otx_api",
                timestamp=datetime.utcnow().isoformat(),
                error_message="OTX_API_KEY not configured"
            )
        
        try:
            limit = max(1, min(50, limit))
            
            # Use SDK's search_pulses method which includes:
            # - Built-in retry logic (5 retries with exponential backoff)
            # - Automatic handling of rate limits (429) and server errors (5xx)
            # - Pagination support
            # - Better error handling
            data = self.otx_client.search_pulses(query=query, max_results=limit)
            
            pulses = []
            for pulse in data.get("results", []):
                pulses.append({
                    "id": pulse.get("id"),
                    "name": pulse.get("name"),
                    "description": pulse.get("description"),
                    "author": pulse.get("author", {}).get("username") if isinstance(pulse.get("author"), dict) else None,
                    "created": pulse.get("created"),
                    "modified": pulse.get("modified"),
                    "tags": pulse.get("tags", []),
                    "indicators_count": pulse.get("indicators_count", 0),
                })
            
            return ToolResult(
                success=True,
                data={"query": query, "pulses": pulses},
                source="otx_api",
                timestamp=datetime.utcnow().isoformat()
            )
        except Exception as e:
            logger.error(f"Error in OTX pulse search: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="otx_api",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e)
            )


def create_otx_pulse_tool() -> StructuredTool:
    """Create LangChain tool for OTX pulse search."""
    tool_instance = AlienVaultOTXTool()
    
    def _execute(query: str, limit: int = 10) -> Dict[str, Any]:
        result = tool_instance.execute(query, limit)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="otx_pulse_search",
        description="Search AlienVault OTX (Open Threat Exchange) for threat intelligence pulses. Returns information about malware campaigns, IoCs, and adversary intelligence.",
        args_schema=OTXPulseInput,
    )


# ============================================================================
# VirusTotal Lookup Tool
# ============================================================================

class VirusTotalInput(BaseModel):
    """Input schema for VirusTotal lookup tool."""
    resource: str = Field(description="Resource to check (hash, URL, domain, or IP address)")
    resource_type: Optional[str] = Field(default=None, description="Resource type (hash, url, domain, ip_address)")


class VirusTotalTool(SecurityTool):
    """Lookup file/URL/domain/IP reputation on VirusTotal."""
    
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        if not self.api_key:
            logger.warning("VIRUSTOTAL_API_KEY not set. VirusTotal tool will not work.")
    
    @property
    def tool_name(self) -> str:
        return "virustotal_lookup"
    
    def cache_key(self, **kwargs) -> str:
        resource = kwargs.get("resource", "")
        resource_type = kwargs.get("resource_type", "")
        return f"virustotal:{resource}:{resource_type}"
    
    def execute(self, resource: str, resource_type: Optional[str] = None) -> ToolResult:
        """Execute VirusTotal lookup."""
        if not self.api_key:
            return ToolResult(
                success=False,
                data=None,
                source="virustotal_api",
                timestamp=datetime.utcnow().isoformat(),
                error_message="VIRUSTOTAL_API_KEY not configured"
            )
        
        try:
            headers = {"x-apikey": self.api_key}
            
            # Auto-detect resource type if not provided
            if not resource_type:
                if len(resource) == 32 or len(resource) == 40 or len(resource) == 64:
                    resource_type = "hash"
                elif resource.startswith("http"):
                    resource_type = "url"
                elif "." in resource and not resource.replace(".", "").replace(":", "").isdigit():
                    resource_type = "domain"
                else:
                    resource_type = "ip_address"
            
            # Map resource type to endpoint
            endpoint_map = {
                "hash": f"/files/{resource}",
                "url": "/urls",
                "domain": f"/domains/{resource}",
                "ip_address": f"/ip_addresses/{resource}",
            }
            
            endpoint = endpoint_map.get(resource_type)
            if not endpoint:
                return ToolResult(
                    success=False,
                    data=None,
                    source="virustotal_api",
                    timestamp=datetime.utcnow().isoformat(),
                    error_message=f"Invalid resource type: {resource_type}"
                )
            
            # For URLs, need to submit first then get report
            if resource_type == "url":
                # Submit URL
                submit_response = requests.post(
                    f"{self.base_url}{endpoint}",
                    headers=headers,
                    data={"url": resource},
                    timeout=10
                )
                submit_response.raise_for_status()
                submit_data = submit_response.json()
                analysis_id = submit_data.get("data", {}).get("id")
                
                # Get report
                report_response = requests.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=10
                )
                report_response.raise_for_status()
                data = report_response.json()
            else:
                # Direct lookup
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=headers,
                    timeout=10
                )
                response.raise_for_status()
                data = response.json()
            
            # Extract key information
            result_data = {
                "resource": resource,
                "resource_type": resource_type,
                "data": data.get("data", {}),
            }
            
            return ToolResult(
                success=True,
                data=result_data,
                source="virustotal_api",
                timestamp=datetime.utcnow().isoformat()
            )
        except Exception as e:
            logger.error(f"Error in VirusTotal lookup: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="virustotal_api",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e)
            )


def create_virustotal_tool() -> StructuredTool:
    """Create LangChain tool for VirusTotal lookup."""
    tool_instance = VirusTotalTool()
    
    def _execute(resource: str, resource_type: Optional[str] = None) -> Dict[str, Any]:
        result = tool_instance.execute(resource, resource_type)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="virustotal_lookup",
        description="Lookup file hashes, URLs, domains, or IP addresses on VirusTotal for reputation and malware detection. Returns detection ratios and analysis results.",
        args_schema=VirusTotalInput,
    )
