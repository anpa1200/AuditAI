import time
import logging
from abc import ABC, abstractmethod
from assessment.models import ModuleResult

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    name: str = "base"

    def run(self) -> ModuleResult:
        start = time.time()
        try:
            raw_output, findings = self._scan()
            duration = time.time() - start
            return ModuleResult(
                module_name=self.name,
                findings=findings,
                raw_output=raw_output,
                module_risk_score=0,
                module_summary="Pending AI analysis",
                duration_seconds=duration,
            )
        except Exception as e:
            duration = time.time() - start
            logger.error(f"Scanner {self.name} failed: {e}", exc_info=True)
            return ModuleResult(
                module_name=self.name,
                findings=[],
                raw_output={"error": str(e)},
                module_risk_score=0,
                module_summary=f"Scanner failed: {e}",
                duration_seconds=duration,
                error=str(e),
            )

    @abstractmethod
    def _scan(self) -> tuple[dict, list]:
        """Return (raw_output_dict, findings_list). Findings list may be empty
        (AI analysis fills it in); raw_output is what gets sent to AI."""
        ...
