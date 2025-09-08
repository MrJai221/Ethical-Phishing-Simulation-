# config/config.py

# This is the V3.1 of code. So every edit here is an update of V2 code 
import os
from typing import Dict, List, Any, Tuple
import logging
import sys  # Added for stderr output on critical errors

# Initialize logger early to catch issues during config load
logging.basicConfig(level="INFO", format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Config:
    """
    Configuration management class for the Email Phishing Detector.

    Loads default settings and allows overriding them via environment variables
    or a dictionary. Includes basic validation for critical parameters.

    Access configuration values using CONFIG.get('KEY_NAME').
    """

    # Default configuration values
    DEFAULTS: Dict[str, Any] = {
        # AI Integration (e.g., OpenRouter supporting various models)
        "AI_API_URL": "https://openrouter.ai/api/v1/chat/completions",
        "AI_API_KEY": "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",  # <-- Hardcoded AI key
        "AI_MODEL": "deepseek/deepseek-chat",  # Specify the AI model
        "AI_TIMEOUT": (10, 60),  # Connect timeout (10s), read timeout (60s)
        "AI_MAX_TOKENS": 2000,  # Max tokens for AI response
        "AI_TEMPERATURE": 0.2,  # AI creativity

        # VirusTotal Integration
        "VIRUSTOTAL_API_KEY": "ac13e45e191044d03522052929761c7fd7ed07dec21050d6e36bc15f84751c7d",  # <-- Hardcoded VT key
        "VT_TIMEOUT": (10, 30),
        "VT_REQUEST_DELAY_SECONDS": 1.0,  # Delay between VT requests

        # Database Caching
        "DATABASE_PATH": "cache/vt_cache.db",
        "CACHE_DURATION_SECONDS": 6 * 3600,  # 6 hours

        # OCR for Images in Attachments
        "OCR_ENABLED": True,
        "OCR_LANGUAGES": ['eng'],
        "TESSERACT_CMD": None,  # Path to tesseract executable if not in PATH

        # File Handling
        "SUPPORTED_FILES": [".eml", ".msg"],
        "MAX_FILE_SIZE": 10 * 1024 * 1024,  # 10MB

        # General
        "DATE_FORMAT": "%Y-%m-%d %H:%M:%S",
        "USER_AGENT": "EmailPhishingDetector/1.1 (Async+OCR)",
        "LOG_LEVEL": "INFO",
        "LOG_FORMAT": '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    }

    def __init__(self, overrides: Dict = None):
        """Initializes the configuration object."""
        self.config = self.DEFAULTS.copy()
        if overrides:
            for key, value in overrides.items():
                if key in self.config:
                    self.config[key] = value
                else:
                    logger.warning(f"Override provided for unknown config key: {key}")

        # ⚠️ Disabled env override (we are using hardcoded keys now)
        # if not self.config.get("AI_API_KEY"):
        #     self.config["AI_API_KEY"] = os.getenv("OPENROUTER_API_KEY", "")
        # if not self.config.get("VIRUSTOTAL_API_KEY"):
        #     self.config["VIRUSTOTAL_API_KEY"] = os.getenv("VIRUSTOTAL_API_KEY", "")

        try:
            self.validate()
            logger.info("Configuration loaded and validated.")
            if not self.config.get("AI_API_KEY"):
                logger.warning("AI_API_KEY is not configured. AI analysis will be disabled or fail.")
            if not self.config.get("VIRUSTOTAL_API_KEY"):
                logger.warning("VIRUSTOTAL_API_KEY is not configured. VirusTotal checks will be disabled or fail.")
            if self.config.get("OCR_ENABLED"):
                tesseract_cmd_path = self.config.get("TESSERACT_CMD")
                if tesseract_cmd_path:
                    try:
                        import pytesseract
                        pytesseract.pytesseract.tesseract_cmd = tesseract_cmd_path
                        logger.info(f"Set Tesseract command path to: {tesseract_cmd_path}")
                    except ImportError:
                        logger.warning("pytesseract library not found, cannot set Tesseract command path. OCR will fail.")
                    except Exception as e:
                        logger.error(f"Error setting Tesseract command path: {e}")

        except ValueError as e:
            logger.critical(f"CRITICAL CONFIGURATION ERROR: {e}")
            print(f"CRITICAL CONFIGURATION ERROR: {e}", file=sys.stderr)
            sys.exit(1)

        # Apply logging configuration
        self._configure_logging()

    def _configure_logging(self):
        """Configures the root logger based on settings."""
        log_level = self.config.get("LOG_LEVEL", "INFO").upper()
        log_format = self.config.get("LOG_FORMAT")
        numeric_level = getattr(logging, log_level, None)
        if not isinstance(numeric_level, int):
            log_level = "INFO"
            numeric_level = getattr(logging, log_level, None)
            logger.warning(f"Invalid LOG_LEVEL configured. Defaulting to {log_level}.")
        logging.basicConfig(level=numeric_level, format=log_format, force=True)
        logger.info(f"Logging configured to level {log_level}.")

    def validate(self) -> None:
        """Performs basic validation on critical configuration parameters."""
        if not isinstance(self.config["SUPPORTED_FILES"], list) or not all(isinstance(ext, str) and ext.startswith('.') for ext in self.config["SUPPORTED_FILES"]):
            raise ValueError("SUPPORTED_FILES must be a list of strings starting with '.'")
        if not isinstance(self.config["MAX_FILE_SIZE"], int) or self.config["MAX_FILE_SIZE"] <= 0:
            raise ValueError("MAX_FILE_SIZE must be a positive integer.")

        for key in ["AI_TIMEOUT", "VT_TIMEOUT"]:
            timeout = self.config[key]
            if not isinstance(timeout, tuple) or len(timeout) != 2 or not all(isinstance(t, (int, float)) and t >= 0 for t in timeout):
                raise ValueError(f"{key} must be a tuple of two non-negative numbers.")

        if not isinstance(self.config["VT_REQUEST_DELAY_SECONDS"], (int, float)) or self.config["VT_REQUEST_DELAY_SECONDS"] < 0:
            raise ValueError("VT_REQUEST_DELAY_SECONDS must be a non-negative number.")
        if not isinstance(self.config["CACHE_DURATION_SECONDS"], int) or self.config["CACHE_DURATION_SECONDS"] < 0:
            raise ValueError("CACHE_DURATION_SECONDS must be a non-negative integer.")
        if not isinstance(self.config["DATABASE_PATH"], str) or not self.config["DATABASE_PATH"]:
            raise ValueError("DATABASE_PATH must be a non-empty string.")

        log_level_str = self.config["LOG_LEVEL"].upper()
        if log_level_str not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            logger.warning(f"Invalid LOG_LEVEL '{self.config['LOG_LEVEL']}'. Defaulting to INFO.")

        if self.config["OCR_ENABLED"]:
            if not isinstance(self.config["OCR_LANGUAGES"], list) or not all(isinstance(lang, str) and len(lang) == 3 for lang in self.config["OCR_LANGUAGES"]):
                raise ValueError("OCR_LANGUAGES must be a list of 3-letter language codes.")
            if self.config["TESSERACT_CMD"] is not None and not isinstance(self.config["TESSERACT_CMD"], str):
                raise ValueError("TESSERACT_CMD must be a string path or None.")

        if not isinstance(self.config["AI_API_URL"], str) or not self.config["AI_API_URL"].startswith("http"):
            logger.warning(f"AI_API_URL '{self.config['AI_API_URL']}' doesn't look like a valid URL.")

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves a configuration value by key."""
        return self.config.get(key, default)

# --- Global Instance ---
try:
    CONFIG = Config()
except Exception as e:
    logger.critical(f"Failed to initialize configuration: {e}", exc_info=True)
    print(f"CRITICAL ERROR: Failed to initialize configuration: {e}", file=sys.stderr)
    sys.exit(1)
