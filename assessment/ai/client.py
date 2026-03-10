import json
import logging
import time
from anthropic import Anthropic, APIError, RateLimitError
from assessment.config import ANTHROPIC_API_KEY, DEFAULT_MODEL
from assessment.ai.prompts import SYSTEM_PROMPT

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds


class AIClient:
    def __init__(self, model: str = DEFAULT_MODEL, api_key: str = ""):
        self.model = model
        self.client = Anthropic(api_key=api_key or ANTHROPIC_API_KEY)

    def analyze(self, prompt: str, max_tokens: int = 4096) -> dict:
        """Send a prompt and return parsed JSON response."""
        for attempt in range(MAX_RETRIES):
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0,
                )
                content = response.content[0].text.strip()
                # Strip markdown code fences if present
                if content.startswith("```"):
                    lines = content.splitlines()
                    content = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
                return json.loads(content)

            except RateLimitError:
                wait = RETRY_DELAY * (2 ** attempt)
                logger.warning(f"Rate limited, waiting {wait}s (attempt {attempt+1}/{MAX_RETRIES})")
                time.sleep(wait)
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {e}")
                if attempt == MAX_RETRIES - 1:
                    return {"error": f"JSON decode failed: {e}", "findings": [], "module_risk_score": 0, "module_summary": "AI analysis failed"}
                time.sleep(RETRY_DELAY)
            except APIError as e:
                logger.error(f"API error: {e}")
                if attempt == MAX_RETRIES - 1:
                    return {"error": str(e), "findings": [], "module_risk_score": 0, "module_summary": "AI analysis failed"}
                time.sleep(RETRY_DELAY)

        return {"error": "max retries exceeded", "findings": [], "module_risk_score": 0, "module_summary": "AI analysis failed"}
