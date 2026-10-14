import json
import logging
import time
from anthropic import Anthropic, APIError, RateLimitError, AuthenticationError
from assessment.config import ANTHROPIC_API_KEY, DEFAULT_MODEL
from assessment.ai.prompts import SYSTEM_PROMPT
from assessment.ai.errors import InsufficientCreditsError

logger = logging.getLogger(__name__)

MAX_RETRIES = 4
RETRY_DELAY = 15  # seconds — base delay for rate limit backoff (Tier 1 accounts)

# Error messages that are permanent — no point retrying
_FATAL_PHRASES = (
    "credit balance is too low",
    "insufficient_quota",
    "billing",
    "payment",
    "Your organization has hit its usage limit",
)


def _is_fatal_api_error(exc: Exception) -> bool:
    """Return True if the error is permanent and retrying will not help."""
    msg = str(exc).lower()
    return any(phrase.lower() in msg for phrase in _FATAL_PHRASES)


class AIClient:
    def __init__(self, model: str = DEFAULT_MODEL, api_key: str = ""):
        self.model = model
        self.client = Anthropic(api_key=api_key or ANTHROPIC_API_KEY, max_retries=0, timeout=60.0)

    def analyze(self, prompt: str, max_tokens: int = 4096) -> dict:
        """Send a prompt and return parsed JSON response."""
        for attempt in range(MAX_RETRIES):
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                if getattr(response, "stop_reason", None) == "max_tokens":
                    raise ValueError("AI response exceeded the token limit")
                text = getattr(response.content[0], "text", None) if response.content else None
                if not isinstance(text, str):
                    raise ValueError("AI response has no text content")
                content = text.strip()
                # Strip markdown code fences if present
                if content.startswith("```"):
                    lines = content.splitlines()
                    content = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
                parsed = json.loads(content)
                if not isinstance(parsed, dict):
                    raise ValueError("AI response must be a JSON object")
                return parsed

            except AuthenticationError as e:
                raise InsufficientCreditsError(
                    f"Authentication failed — check that ANTHROPIC_API_KEY is valid: {e}"
                ) from e

            except RateLimitError:
                wait = RETRY_DELAY * (2 ** attempt)
                if attempt < MAX_RETRIES - 1:
                    logger.warning(f"Rate limited, waiting {wait}s (attempt {attempt+1}/{MAX_RETRIES})")
                    time.sleep(wait)
                else:
                    logger.error("Rate limited: all %s attempts exhausted", MAX_RETRIES)

            except ValueError as e:
                logger.error(f"Invalid AI response: {e}")
                if attempt == MAX_RETRIES - 1:
                    return {
                        "error": f"Invalid AI response: {e}",
                        "module_risk_score": None,
                        "module_summary": "AI analysis failed",
                    }
                time.sleep(RETRY_DELAY)

            except APIError as e:
                if _is_fatal_api_error(e):
                    raise InsufficientCreditsError(
                        "Anthropic API rejected the request due to insufficient credits or billing issue.\n"
                        "  → Check your balance at https://console.anthropic.com/settings/billing\n"
                        "  → If you just topped up, wait a few minutes for credits to propagate.\n"
                        "  → Re-run with --no-ai to get scanner-only output while you resolve billing."
                    ) from e
                logger.error(f"API error (attempt {attempt+1}/{MAX_RETRIES}): {e}")
                if attempt == MAX_RETRIES - 1:
                    return {
                        "error": str(e),
                        "module_risk_score": None,
                        "module_summary": "AI analysis failed",
                    }
                time.sleep(RETRY_DELAY)

        return {
            "error": "max retries exceeded",
            "module_risk_score": None,
            "module_summary": "AI analysis failed",
        }
