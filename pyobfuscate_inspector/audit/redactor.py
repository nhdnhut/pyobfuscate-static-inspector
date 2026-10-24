"""Redactor for masking sensitive credentials, tokens, and secrets in audit reports."""

import re
from typing import Tuple


class SecretRedactor:
    """Detects and redacts API tokens, Discord webhooks, Telegram bot tokens, and passwords."""

    PATTERNS = [
        # Discord Webhooks
        (
            re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/(\d+)/([a-zA-Z0-9_\-]+)", re.IGNORECASE),
            r"https://discord.com/api/webhooks/\1/[REDACTED_WEBHOOK_TOKEN]",
        ),
        # Telegram Bot Tokens (standalone or inside api.telegram.org/bot...)
        (
            re.compile(r"((?:bot|\b)\d{8,12}:)[a-zA-Z0-9_\-]{30,40}\b"),
            r"\1[REDACTED_TELEGRAM_TOKEN]",
        ),
        # OpenAI / Standard sk- tokens
        (
            re.compile(r"\b(sk-[a-zA-Z0-9]{20,})\b"),
            r"sk-[REDACTED_API_KEY]",
        ),
        # JWT Tokens
        (
            re.compile(r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b"),
            r"[REDACTED_JWT_TOKEN]",
        ),
        # Private Keys
        (
            re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----[^-]+-----END (?:RSA )?PRIVATE KEY-----", re.DOTALL),
            r"[REDACTED_PRIVATE_KEY]",
        ),
        # Password assignments: password = "..."
        (
            re.compile(r"""((?:password|passwd|pwd|secret|api_key|token)\s*=\s*['"])([^'"]+)(['"])""", re.IGNORECASE),
            r"\1***REDACTED***\3",
        ),
        # URLs with embedded basic auth passwords: http://user:pass@host
        (
            re.compile(r"(https?://[^:]+:)([^@]+)(@)", re.IGNORECASE),
            r"\1***REDACTED***\3",
        ),
    ]

    @classmethod
    def redact(cls, text: str) -> Tuple[str, bool]:
        """Redacts sensitive strings from the given text.

        Returns (redacted_text, was_redacted_bool).
        """
        if not text:
            return text, False

        modified = text
        was_redacted = False

        for pattern, replacement in cls.PATTERNS:
            new_text, count = pattern.subn(replacement, modified)
            if count > 0:
                modified = new_text
                was_redacted = True

        return modified, was_redacted
