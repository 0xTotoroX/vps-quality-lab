"""Redact authentication material in untrusted diagnostic strings."""

import re
from urllib.parse import unquote, urlsplit, urlunsplit

SENSITIVE = re.compile(r"(?:password|passwd|token|secret|api[_-]?key|authorization|signature)", re.IGNORECASE)


def redact_urls(text: str) -> str:
    def replace(match):
        raw = match.group(0)
        try:
            parts = urlsplit(raw)
            decoded = unquote(unquote(parts.query))
            if parts.username or parts.password or SENSITIVE.search(decoded):
                host = parts.hostname or "redacted"
                if parts.port:
                    host += ":" + str(parts.port)
                return urlunsplit((parts.scheme, host, parts.path, "[authentication-redacted]", ""))
        except ValueError:
            return "[URL redacted]"
        return raw
    return re.sub(r"https?://[^\s<>\"'`]+", replace, text)


def safe_output(value):
    if isinstance(value, str):
        return redact_urls(value)
    if isinstance(value, list):
        return [safe_output(item) for item in value]
    if isinstance(value, dict):
        return {key: "[redacted]" if (SENSITIVE.search(str(key)) and not str(key).endswith("_env")
                                      and not isinstance(item, (dict, list))) else safe_output(item)
                for key, item in value.items()}
    return value
