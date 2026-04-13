"""
Reporter factory and base class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Literal

from risk_scanner.core.models import ScanResult

ReportFormat = Literal["sarif", "json", "markdown", "csv", "html"]


class BaseReporter(ABC):
    @abstractmethod
    def render(self, result: ScanResult) -> str:
        """Render the scan result to the target format string."""


def get_reporter(fmt: ReportFormat) -> BaseReporter:
    from risk_scanner.reporters.sarif import SARIFReporter
    from risk_scanner.reporters.json_reporter import JSONReporter
    from risk_scanner.reporters.markdown import MarkdownReporter
    from risk_scanner.reporters.csv_reporter import CSVReporter
    from risk_scanner.reporters.html import HTMLReporter

    _map = {
        "sarif": SARIFReporter,
        "json": JSONReporter,
        "markdown": MarkdownReporter,
        "csv": CSVReporter,
        "html": HTMLReporter,
    }
    cls = _map.get(fmt)
    if cls is None:
        raise ValueError(f"Unknown report format: {fmt!r}. Choose from: {list(_map)}")
    return cls()
