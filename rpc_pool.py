from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any, List, Optional, Sequence, Union
from urllib.parse import urlsplit

import requests

logger = logging.getLogger(__name__)

DEFAULT_RPC_URL = "https://api.mainnet-beta.solana.com"
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_RETRIES_PER_NODE = 1
MAX_RPC_ATTEMPTS = 3

# JSON-RPC error codes that indicate a temporary node-side problem.
RETRYABLE_RPC_ERROR_CODES = {-32005, -32004, -32016, -32603}


class RpcError(RuntimeError):
    """Non-retryable error returned by the Solana JSON-RPC API."""


def parse_rpc_urls(env_value: str) -> List[str]:
    if not env_value:
        return [DEFAULT_RPC_URL]
    urls = [u.strip() for u in env_value.split(",") if u.strip()]
    return urls if urls else [DEFAULT_RPC_URL]


def mask_url(url: str) -> str:
    """Return only scheme://host so API keys embedded in RPC URLs never reach logs."""
    try:
        parts = urlsplit(url)
        if parts.scheme and parts.hostname:
            return f"{parts.scheme}://{parts.hostname}"
    except ValueError:
        pass
    return "<invalid-rpc-url>"


def _backoff_delay(attempt: int) -> float:
    """Fast exponential backoff with small jitter: ~0.3s, ~0.6s ..."""
    return (0.3 * (2 ** attempt)) + random.uniform(0, 0.1)


class RpcFailoverPool:
    """HTTP client for a list of Solana RPC nodes with rapid retries and thread-safe failover."""

    def __init__(self, rpc_urls: Union[str, Sequence[str]]) -> None:
        if isinstance(rpc_urls, str):
            self.rpc_urls = parse_rpc_urls(rpc_urls)
        else:
            self.rpc_urls = [u.strip() for u in rpc_urls if u and u.strip()]

        if not self.rpc_urls:
            self.rpc_urls = [DEFAULT_RPC_URL]

        self.current_index = 0
        self._lock = threading.Lock()
        self._session = requests.Session()

    # Resource management -------------------------------------------------

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "RpcFailoverPool":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # Node selection ------------------------------------------------------

    def get_current_url(self) -> str:
        with self._lock:
            return self.rpc_urls[self.current_index]

    def rotate(self) -> str:
        with self._lock:
            if len(self.rpc_urls) > 1:
                self.current_index = (self.current_index + 1) % len(self.rpc_urls)
                new_url = self.rpc_urls[self.current_index]
                logger.warning(f"Switching to fallback RPC node: {mask_url(new_url)}")
                return new_url
            return self.rpc_urls[self.current_index]

    # HTTP layer ----------------------------------------------------------

    def post(self, **kwargs) -> requests.Response:
        """
        POST to the current node. Retries on network errors, HTTP 429 and 5xx
        with rapid failover to the next node when a node keeps failing (or rejects with 401/403).
        """
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT_SECONDS)

        for _ in range(len(self.rpc_urls)):
            current_url = self.get_current_url()
            masked = mask_url(current_url)

            for attempt in range(MAX_RETRIES_PER_NODE):
                try:
                    response = self._session.post(current_url, **kwargs)
                except requests.RequestException as e:
                    logger.warning(
                        f"RPC communication error with {masked}: {type(e).__name__}. "
                        f"Attempt {attempt + 1}/{MAX_RETRIES_PER_NODE}."
                    )
                else:
                    status = response.status_code
                    if status in (401, 403):
                        logger.warning(f"RPC {masked} rejected the request with status {status}.")
                        response.close()
                        break  # Retrying the same node will not help, fail over.
                    if status == 429 or status >= 500:
                        logger.warning(
                            f"RPC {masked} returned status {status}. "
                            f"Attempt {attempt + 1}/{MAX_RETRIES_PER_NODE}."
                        )
                        response.close()
                    else:
                        return response

                if attempt < MAX_RETRIES_PER_NODE - 1:
                    time.sleep(_backoff_delay(attempt))

            self.rotate()

        raise RuntimeError("All RPC nodes in the pool failed or timed out.")

    # JSON-RPC layer ------------------------------------------------------

    def call(self, method: str, params: Optional[list] = None) -> Any:
        """
        Execute a JSON-RPC call and return its "result".

        Retries on invalid JSON and on temporary node-side JSON-RPC errors.
        Raises RpcError for permanent JSON-RPC errors.
        """
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or [],
        }
        last_problem = "unknown error"

        for attempt in range(MAX_RPC_ATTEMPTS):
            try:
                response = self.post(json=payload)
            except RuntimeError as re:
                last_problem = str(re)
                logger.warning(f"RPC post failed: {last_problem}. Attempt {attempt + 1}/{MAX_RPC_ATTEMPTS}.")
                if attempt < MAX_RPC_ATTEMPTS - 1:
                    time.sleep(_backoff_delay(attempt))
                continue

            with response:
                try:
                    data = response.json()
                except ValueError:
                    data = None

            if not isinstance(data, dict):
                last_problem = "RPC node returned an invalid JSON response"
            elif "error" in data:
                error = data["error"]
                code = error.get("code") if isinstance(error, dict) else None
                if code not in RETRYABLE_RPC_ERROR_CODES:
                    raise RpcError(f"Solana RPC Error: {error}")
                last_problem = f"temporary Solana RPC error: {error}"
            else:
                return data.get("result")

            logger.warning(f"{last_problem}. Attempt {attempt + 1}/{MAX_RPC_ATTEMPTS}.")
            self.rotate()
            if attempt < MAX_RPC_ATTEMPTS - 1:
                time.sleep(_backoff_delay(attempt))

        raise RuntimeError(f"Solana RPC call failed after {MAX_RPC_ATTEMPTS} attempts: {last_problem}")
