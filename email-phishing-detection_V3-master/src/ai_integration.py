# src/ai_integration.py
import json
import logging
import asyncio
from typing import Dict, Any

try:
    import aiohttp
except ImportError:
    aiohttp = None
    logging.getLogger(__name__).error(
        "aiohttp library not found. AI integration module is non-functional."
    )

from config.config import CONFIG

logger = logging.getLogger(__name__)

AI_JSON_OUTPUT_STRUCTURE = """{
  "phishing_score": "integer (0-10, where 0 is clean and 10 is definitively malicious phishing)",
  "verdict": "string ('CLEAN', 'SUSPICIOUS', 'MALICIOUS')",
  "confidence": "float (0.0-1.0, model's confidence in the verdict)",
  "explanation": "string (Detailed reasoning for the verdict...)",
  "suspicious_elements": ["string (List specific elements identified as suspicious)"],
  "identified_brands": ["string (List of potential brand names identified)"],
  "recommendations": ["string (List of recommendations)"]
}"""


# --- Safe AI Prompt Builder ---
def build_ai_prompt_safe(analysis_data: dict) -> dict:
    """
    Safely builds AI prompt from email analysis data.
    Ensures Headers, Body, and Attachments exist even if empty.
    """
    headers = analysis_data.get("Headers") or {}
    body = analysis_data.get("Body") or {}
    attachments = analysis_data.get("Attachments") or {}

    safe_data = {
        "Headers": headers,
        "Body": body,
        "Attachments": attachments
    }

    prompt_content = f"""
You are an expert cybersecurity analyst specializing in phishing detection.
Analyze the following email data and return ONLY the structured JSON output
with fields: phishing_score, verdict, confidence, explanation, suspicious_elements,
identified_brands, recommendations.

Email Data:
{json.dumps(safe_data, indent=2)}

Respond ONLY in JSON format, do NOT include any extra text or markdown.
"""
    return {"role": "user", "content": prompt_content}


# --- AI Analysis Function ---
async def analyze_with_ai(analysis_data: dict, session: "aiohttp.ClientSession") -> dict:
    """
    Sends analysis data to AI model asynchronously and returns structured JSON.
    """
    if aiohttp is None:
        return {"error": "library_missing", "message": "aiohttp library is required."}

    api_key = CONFIG.get("AI_API_KEY")
    api_url = CONFIG.get("AI_API_URL")
    model = CONFIG.get("AI_MODEL")
    ai_timeout_config = CONFIG.get("AI_TIMEOUT", (10, 60))

    if not api_key or not api_url or not model:
        logger.error("AI config missing: API_KEY, API_URL, or AI_MODEL not set.")
        return {"error": "config_missing", "message": "AI configuration incomplete."}

    # Build safe prompt
    prompt_message = build_ai_prompt_safe(analysis_data)

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": CONFIG.get("USER_AGENT", "EmailPhishingDetector/Unknown"),
        "Referer": "http://localhost",
        "X-Title": "Email Phishing Detector"
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are an AI security assistant."},
            {"role": "user", "content": prompt_message["content"]}
        ],
        "max_tokens": CONFIG.get("AI_MAX_TOKENS", 2000),
        "temperature": CONFIG.get("AI_TEMPERATURE", 0.2)
    }

    timeout = aiohttp.ClientTimeout(connect=ai_timeout_config[0], total=sum(ai_timeout_config))

    try:
        async with session.post(api_url, headers=headers, json=payload, timeout=timeout) as resp:
            resp.raise_for_status()
            result_json = await resp.json()

            choices = result_json.get("choices")
            if not choices:
                raise ValueError(f"Invalid AI response, missing 'choices': {result_json}")

            content_str = choices[0].get("message", {}).get("content")
            if not content_str:
                raise ValueError(f"Invalid AI response, missing 'content': {result_json}")

            # Clean content string (remove ```json or ``` wrappers)
            content_str = content_str.strip()
            if content_str.startswith("```json"):
                content_str = content_str[7:].rstrip("```").strip()
            elif content_str.startswith("```"):
                content_str = content_str[3:].rstrip("```").strip()

            # Parse JSON
            ai_data = json.loads(content_str)

            # Validate required fields
            required_fields = list(json.loads(AI_JSON_OUTPUT_STRUCTURE).keys())
            missing = [f for f in required_fields if f not in ai_data]
            if missing:
                ai_data["error"] = "missing_fields"
                ai_data["message"] = f"Missing fields: {missing}"

            logger.info(f"AI analysis successful. Verdict: {ai_data.get('verdict')}, Score: {ai_data.get('phishing_score')}")
            return ai_data

    except aiohttp.ClientResponseError as e:
        logger.error(f"HTTP error {e.status}: {e.message}")
        return {"error": f"http_{e.status}", "message": str(e)}
    except asyncio.TimeoutError:
        logger.error("AI request timed out.")
        return {"error": "timeout", "message": "AI request timed out."}
    except aiohttp.ClientError as e:
        logger.error(f"Client error: {e}")
        return {"error": "client_error", "message": str(e)}
    except ValueError as e:
        logger.error(f"Parsing error: {e}")
        return {"error": "parsing_error", "message": str(e)}
    except Exception as e:
        logger.exception("Unexpected error during AI analysis.")
        return {"error": "unknown", "message": str(e)}
