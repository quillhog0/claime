from __future__ import annotations

import asyncio
import logging
import random
import threading
import time
from typing import Any, List, Optional, Sequence, Union
from urllib.parse import urlsplit

import httpx

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
    """Async HTTP client for a list of Solana RPC nodes with latency scoring and failover."""

    def __init__(self, rpc_urls: Union[str, Sequence[str]]) -> None:
        if isinstance(rpc_urls, str):
            self.rpc_urls = parse_rpc_urls(rpc_urls)
        else:
            self.rpc_urls = [u.strip() for u in rpc_urls if u and u.strip()]

        if not self.rpc_urls:
            self.rpc_urls = [DEFAULT_RPC_URL]

        self.current_index = 0
        self._lock = threading.Lock()
        self.node_scores = {url: 1.0 for url in self.rpc_urls}
        self.latency_ewma = {url: 0.0 for url in self.rpc_urls}

    # Resource management -------------------------------------------------

    async def aclose(self) -> None:
        return None

    def close(self) -> None:
        return None

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

    def _record_node_result(self, url: str, success: bool, status_code: Optional[int] = None, latency_ms: Optional[float] = None) -> None:
        with self._lock:
            score = self.node_scores.get(url, 1.0)
            if latency_ms is not None:
                prev = self.latency_ewma.get(url, latency_ms)
                self.latency_ewma[url] = (prev * 0.8) + (latency_ms * 0.2)
            if success:
                new_score = max(0.35, score * 0.8)
                self.node_scores[url] = new_score
            else:
                penalty = 5.0
                if status_code == 429:
                    penalty = 25.0
                elif status_code is not None and status_code >= 500:
                    penalty = 15.0
                self.node_scores[url] = max(0.35, score + penalty)

    async def post_async(self, **kwargs) -> httpx.Response:
        """POST to a node with retry and EWMA-based node performance scoring."""
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT_SECONDS)

        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT_SECONDS,
            limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
        ) as client:
            for _ in range(len(self.rpc_urls)):
                current_url = self.get_current_url()
                masked = mask_url(current_url)

                for attempt in range(MAX_RETRIES_PER_NODE):
                    start = time.monotonic()
                    try:
                        response = await client.post(current_url, **kwargs)
                    except httpx.HTTPError as e:
                        latency_ms = (time.monotonic() - start) * 1000.0
                        self._record_node_result(current_url, False, None, latency_ms)
                        logger.warning(
                            f"RPC communication error with {masked}: {type(e).__name__}. "
                            f"Attempt {attempt + 1}/{MAX_RETRIES_PER_NODE}."
                        )
                    else:
                        latency_ms = (time.monotonic() - start) * 1000.0
                        status = response.status_code
                        if status in (401, 403):
                            self._record_node_result(current_url, False, status, latency_ms)
                            logger.warning(f"RPC {masked} rejected the request with status {status}.")
                            await response.aclose()
                            break
                        if status == 429 or status >= 500:
                            self._record_node_result(current_url, False, status, latency_ms)
                            logger.warning(
                                f"RPC {masked} returned status {status}. "
                                f"Attempt {attempt + 1}/{MAX_RETRIES_PER_NODE}."
                            )
                            await response.aclose()
                        else:
                            self._record_node_result(current_url, True, status, latency_ms)
                            return response

                    if attempt < MAX_RETRIES_PER_NODE - 1:
                        await asyncio.sleep(_backoff_delay(attempt))

                self.rotate()

            raise RuntimeError("All RPC nodes in the pool failed or timed out.")

    def post(self, **kwargs) -> httpx.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT_SECONDS)
        with httpx.Client(
            timeout=DEFAULT_TIMEOUT_SECONDS,
            limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
        ) as client:
            for _ in range(len(self.rpc_urls)):
                current_url = self.get_current_url()
                masked = mask_url(current_url)
                for attempt in range(MAX_RETRIES_PER_NODE):
                    start = time.monotonic()
                    try:
                        response = client.post(current_url, **kwargs)
                    except httpx.HTTPError as e:
                        self._record_node_result(current_url, False, None, (time.monotonic() - start) * 1000.0)
                        logger.warning(
                            f"RPC communication error with {masked}: {type(e).__name__}. "
                            f"Attempt {attempt + 1}/{MAX_RETRIES_PER_NODE}."
                        )
                    else:
                        latency_ms = (time.monotonic() - start) * 1000.0
                        status = response.status_code
                        if status in (401, 403):
                            self._record_node_result(current_url, False, status, latency_ms)
                            logger.warning(f"RPC {masked} rejected the request with status {status}.")
                            response.close()
                            break
                        if status == 429 or status >= 500:
                            self._record_node_result(current_url, False, status, latency_ms)
                            logger.warning(
                                f"RPC {masked} returned status {status}. "
                                f"Attempt {attempt + 1}/{MAX_RETRIES_PER_NODE}."
                            )
                            response.close()
                        else:
                            self._record_node_result(current_url, True, status, latency_ms)
                            return response
                    if attempt < MAX_RETRIES_PER_NODE - 1:
                        time.sleep(_backoff_delay(attempt))
                self.rotate()
            raise RuntimeError("All RPC nodes in the pool failed or timed out.")

    # JSON-RPC layer ------------------------------------------------------

    async def call_async(self, method: str, params: Optional[list] = None) -> Any:
        """Execute a JSON-RPC call and return its result for async consumers."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or [],
        }
        last_problem = "unknown error"

        for attempt in range(MAX_RPC_ATTEMPTS):
            try:
                response = await self.post_async(json=payload)
            except RuntimeError as re:
                last_problem = str(re)
                logger.warning(f"RPC post failed: {last_problem}. Attempt {attempt + 1}/{MAX_RPC_ATTEMPTS}.")
                if attempt < MAX_RPC_ATTEMPTS - 1:
                    await asyncio.sleep(_backoff_delay(attempt))
                continue

            try:
                data = response.json()
            except ValueError:
                data = None
            finally:
                await response.aclose()

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
                await asyncio.sleep(_backoff_delay(attempt))

        raise RuntimeError(f"Solana RPC call failed after {MAX_RPC_ATTEMPTS} attempts: {last_problem}")

    def call(self, method: str, params: Optional[list] = None) -> Any:
        return asyncio.run(self.call_async(method, params))
