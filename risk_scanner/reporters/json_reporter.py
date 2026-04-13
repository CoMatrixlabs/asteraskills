"""
JSON reporter — full ScanResult as indented JSON.
"""

from __future__ import annotations

import json

from risk_scanner.core.models import ScanResult
from risk_scanner.reporters import BaseReporter


class JSONReporter(BaseReporter):
    def render(self, result: ScanResult) -> str:
        return json.dumps(result.model_dump(mode="json"), indent=2, default=str)
