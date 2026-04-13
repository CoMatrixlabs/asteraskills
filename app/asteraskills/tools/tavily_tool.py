"""
Tavily search tool for web-based security intelligence gathering.
"""

import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.tools.base import ToolResult, SecurityTool

logger = logging.getLogger(__name__)

try:
    from tavily import TavilyClient
    TAVILY_AVAILABLE = True
except ImportError:
    TAVILY_AVAILABLE = False
    logger.warning("Tavily client not available. Install with: pip install tavily-python")


class TavilySearchInput(BaseModel):
    """Input schema for Tavily search tool."""
    query: str = Field(description="Search query for security intelligence")
    max_results: int = Field(default=5, description="Maximum number of results to return (1-10)")
    search_depth: str = Field(default="basic", description="Search depth: 'basic' or 'advanced'")


class TavilySearchTool(SecurityTool):
    """
    Tavily search tool for discovering security intelligence from the web.
    
    Tavily is a search API optimized for LLM applications, providing
    relevant, summarized results from web sources.
    """
    
    def __init__(self):
        self.api_key = os.getenv("TAVILY_API_KEY")
        if not self.api_key:
            logger.warning("TAVILY_API_KEY not set. Tavily search tool will not work.")
        elif TAVILY_AVAILABLE:
            self.client = TavilyClient(api_key=self.api_key)
        else:
            self.client = None
            logger.warning("Tavily client not available. Install with: pip install tavily-python")
    
    @property
    def tool_name(self) -> str:
        return "tavily_search"
    
    def cache_key(self, **kwargs) -> str:
        query = kwargs.get("query", "")
        max_results = kwargs.get("max_results", 5)
        search_depth = kwargs.get("search_depth", "basic")
        return f"tavily:{query}:{max_results}:{search_depth}"
    
    def execute(self, query: str, max_results: int = 5, search_depth: str = "basic") -> ToolResult:
        """Execute Tavily search."""
        timestamp = datetime.utcnow().isoformat()
        
        if not self.api_key:
            return ToolResult(
                success=False,
                data=None,
                source="tavily_api",
                timestamp=timestamp,
                error_message="TAVILY_API_KEY not configured"
            )
        
        if not TAVILY_AVAILABLE or not self.client:
            return ToolResult(
                success=False,
                data=None,
                source="tavily_api",
                timestamp=timestamp,
                error_message="Tavily client not available. Install with: pip install tavily-python"
            )
        
        try:
            # Validate max_results
            max_results = max(1, min(10, max_results))
            
            # Validate search_depth
            if search_depth not in ["basic", "advanced"]:
                search_depth = "basic"
            
            # Perform search
            response = self.client.search(
                query=query,
                max_results=max_results,
                search_depth=search_depth,
                include_answer=True,
                include_raw_content=False,
                include_images=False
            )
            
            # Format results
            results = {
                "query": query,
                "answer": response.get("answer", ""),
                "results": []
            }
            
            for item in response.get("results", [])[:max_results]:
                results["results"].append({
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "content": item.get("content", ""),
                    "score": item.get("score", 0.0),
                })
            
            return ToolResult(
                success=True,
                data=results,
                source="tavily_api",
                timestamp=timestamp
            )
        except Exception as e:
            logger.error(f"Error in Tavily search: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="tavily_api",
                timestamp=timestamp,
                error_message=str(e)
            )


def create_tavily_search_tool() -> StructuredTool:
    """Create LangChain tool for Tavily search."""
    tool_instance = TavilySearchTool()
    
    def _execute(query: str, max_results: int = 5, search_depth: str = "basic") -> Dict[str, Any]:
        result = tool_instance.execute(query, max_results, search_depth)
        return result.to_dict()
    
    return StructuredTool.from_function(
        func=_execute,
        name="tavily_search",
        description="Search the web for security intelligence using Tavily. Returns relevant articles, blog posts, and documentation about vulnerabilities, exploits, threat intelligence, and security research. Use this to discover up-to-date information that may not be in structured databases.",
        args_schema=TavilySearchInput,
    )
