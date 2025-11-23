"""
Helpers for normalizing targets passed to scanners.
Ensures a scheme is present and trims obvious user input mistakes.
"""

from urllib.parse import urlparse, urlunparse


def normalize_url(raw_target: str, default_scheme: str = "https") -> str:
    cleaned = raw_target.strip()
    if not cleaned:
        raise ValueError("Target cannot be empty")

    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"{default_scheme}://{cleaned}"

    parsed = urlparse(cleaned)
    netloc = parsed.netloc or parsed.path
    path = parsed.path if parsed.netloc else ""

    normalized = parsed._replace(
        scheme=parsed.scheme or default_scheme,
        netloc=netloc,
        path=path or "/",
    )
    return urlunparse(normalized)


def ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else f"{url}/"
