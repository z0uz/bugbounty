"""
HTTP client utilities with sane defaults for security scanning.
Provides retries, backoff, and consistent timeouts to reduce noisy failures.
"""

from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


class HttpClient:
    def __init__(
        self,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        user_agent: Optional[str] = None,
        proxies: Optional[Dict[str, str]] = None,
    ) -> None:
        self.timeout = timeout
        self.session = requests.Session()

        retry = Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods={"GET", "POST", "HEAD", "OPTIONS"},
            raise_on_status=False,
            respect_retry_after_header=True,
        )

        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=50)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        default_headers = {
            "User-Agent": user_agent
            or "BugBountyToolkit/1.0 (+security-recon; https://github.com/)",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        self.session.headers.update(default_headers)

        if proxies:
            self.session.proxies.update(proxies)

    def request(self, method: str, url: str, **kwargs: Any) -> Optional[requests.Response]:
        timeout = kwargs.pop("timeout", self.timeout)
        try:
            return self.session.request(method=method, url=url, timeout=timeout, **kwargs)
        except requests.RequestException:
            # We intentionally swallow network noise so scanners can continue.
            return None

    def get(self, url: str, **kwargs: Any) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def close(self) -> None:
        self.session.close()
