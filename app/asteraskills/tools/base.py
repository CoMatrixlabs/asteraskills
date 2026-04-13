"""
Base classes and utilities for security intelligence tools.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional
from datetime import datetime


@dataclass
class ToolResult:
    """Standard result format for all security tools."""
    success: bool
    data: Any
    source: str  # "nvd_api" | "postgres_cache" | "exploit_db" | etc.
    timestamp: str
    cache_hit: bool = False
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "success": self.success,
            "data": self.data,
            "source": self.source,
            "timestamp": self.timestamp,
            "cache_hit": self.cache_hit,
            "error_message": self.error_message,
        }


class SecurityTool(ABC):
    """Base class for all security intelligence tools."""
    
    @abstractmethod
    def execute(self, **kwargs) -> ToolResult:
        """Run the tool with given parameters."""
        pass
    
    @abstractmethod
    def cache_key(self, **kwargs) -> str:
        """Generate cache key for result deduplication."""
        pass
    
    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return the name of the tool."""
        pass
