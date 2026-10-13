"""
Quillhog - Standalone Rent Reclaim Service (Production Engine)
File: rent_service.py

High-performance, non-custodial Solana Rent Reclaim backend.
Source of rent-claim logic running at quillhog.xyz, production SHA 861fb55.
"""

from __future__ import annotations
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
import time
from typing import Optional, Union, Any, Literal, List, Dict

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from solders.pubkey import Pubkey
from solders.message import MessageV0
from solders.transaction import VersionedTransaction
from solders.signature import Signature
from solders.hash import Hash

from rpc_pool import RpcFailoverPool, RpcError
from core_verify import (
    TOKEN_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    WSOL_MINT,
    USDC_MINT,
    MAX_BATCH_SIZE as BATCH_SIZE,
    create_close_account_instruction,
    parse_reclaimable_accounts,
    parse_owned_token_accounts,
    summarize_scan_accounts,
    is_valid_base58_address_fast,
    generate_solana_pay_deep_links,
    _sol_from_lamports,
)
from claim_core import compile_claim_transaction_payload, MAX_TX_BYTES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("rent_service")

# ── LIFECYCLE MANAGEMENT ──────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global rpc_pool
    rpc_pool = create_rpc_pool()
    logger.info("Claime rent service online.")
    yield
    if rpc_pool is not None:
        await rpc_pool.aclose()
    logger.info("Claime rent service shutdown.")


app = FastAPI(title="Quillhog Claime Rent Reclaim Engine", lifespan=lifespan)


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error_code": "HTTP_ERROR"},
    )


class EnvironmentCORSMiddleware(CORSMiddleware):
    def is_allowed_origin(self, origin: str) -> bool:
        if origin in ("http://localhost:8000", "http://127.0.0.1:8000"):
            return os.getenv("QUILLHOG_ENV") == "dev"
        return super().is_allowed_origin(origin)


# CORS setup for browser interaction and Solana Pay mobile wallets
# In production, only https://quillhog.xyz and https://www.quillhog.xyz are allowed.
# Localhost is only permitted when QUILLHOG_ENV=dev is set.
app.add_middleware(
    EnvironmentCORSMiddleware,
    allow_origins=[
        "https://quillhog.xyz",
        "https://www.quillhog.xyz",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

# ── RATE LIMITING & SECURITY MIDDLEWARE ───────────────────────────────────────
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 10
RATE_LIMIT_DB_PATH = Path(os.getenv("RATE_LIMIT_DB_PATH", Path(__file__).resolve().parent / "rate_limit.sqlite3"))

# Ephemeral in-RAM HMAC key for irreversible IP pseudonymization (SSOT §6.4)
_RL_KEY: bytes = (
    bytes.fromhex(os.environ["RATE_LIMIT_HMAC_KEY"])
    if os.getenv("RATE_LIMIT_HMAC_KEY")
    else secrets.token_bytes(32)
)
_last_rl_purge: float = 0.0


def _ensure_rate_limit_db(db_path: Path = RATE_LIMIT_DB_PATH) -> None:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rate_limit_events (
                ip_hash TEXT NOT NULL,
                route TEXT NOT NULL,
                ts REAL NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rate_limit_route_ip_ts ON rate_limit_events(route, ip_hash, ts)"
        )
        conn.execute("DELETE FROM rate_limit_events WHERE ts < ?", (time.time() - 3600.0,))
        conn.commit()
    finally:
        conn.close()


def check_rate_limit(
    client_ip: str,
    route: str,
    limit: int,
    window_seconds: int,
    db_path: Optional[Union[str, Path]] = RATE_LIMIT_DB_PATH,
) -> bool:
    """Enforce per-IP per-route quotas in shared SQLite WAL storage."""
    global _last_rl_purge
    if not client_ip or not route:
        return False
    test_scope = os.environ.get("PYTEST_CURRENT_TEST")
    if test_scope and (db_path is None or Path(db_path) == RATE_LIMIT_DB_PATH):
        run_label = os.environ.get("PYTEST_RUN_ID", str(os.getpid()))
        test_label = test_scope.split("::")[-1].replace("/", "_").replace(".", "_").replace("(", "_").replace(")", "_").replace(" ", "_")
        db_path = Path(tempfile.gettempdir()) / "claime-rate-limit-tests" / f"{run_label}_{test_label}.sqlite3"
        scope_key = f"{run_label}:{test_label}"
    else:
        scope_key = None
    db_path = Path(db_path) if db_path is not None else RATE_LIMIT_DB_PATH
    _ensure_rate_limit_db(db_path)
    payload = f"{scope_key}:{client_ip}" if scope_key else str(client_ip)
    ip_hash = hmac.new(_RL_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    now = time.time()
    cutoff = now - window_seconds
    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        if now - _last_rl_purge >= 60.0:
            _last_rl_purge = now
            conn.execute("DELETE FROM rate_limit_events WHERE ts < ?", (now - 3600.0,))
        conn.execute("DELETE FROM rate_limit_events WHERE route = ? AND ip_hash = ? AND ts < ?", (route, ip_hash, cutoff))
        matches = conn.execute(
            "SELECT COUNT(*) FROM rate_limit_events WHERE route = ? AND ip_hash = ?",
            (route, ip_hash),
        ).fetchone()[0]
        if matches >= limit:
            return True
        conn.execute(
            "INSERT INTO rate_limit_events (ip_hash, route, ts) VALUES (?, ?, ?)",
            (ip_hash, route, now),
        )
        conn.commit()
        return False
    finally:
        conn.close()


LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def get_client_ip(request: Request) -> str:
    """Extract real client IP securely (T-019, F-010)."""
    client_host = request.client.host if request.client else "unknown"
    trusted_proxies_cfg = [p.strip() for p in os.getenv("TRUSTED_PROXIES", "").split(",") if p.strip()]
    is_trusted = (client_host in LOOPBACK_HOSTS) or (client_host in trusted_proxies_cfg)
    if is_trusted:
        real_ip = request.headers.get("x-real-ip")
        if real_ip and real_ip.strip():
            return real_ip.strip()
        cf_ip = request.headers.get("cf-connecting-ip")
        if cf_ip and cf_ip.strip():
            return cf_ip.strip()
    return client_host


@app.middleware("http")
async def add_security_headers_and_rate_limit(request: Request, call_next):
    client_ip = get_client_ip(request)

    # Shared SQLite WAL rate limiting for /api/ routes
    if request.url.path.startswith("/api/"):
        path = request.url.path

        # 1. Status Polling
        if path == "/api/tx/status":
            if check_rate_limit(client_ip, path, 60, RATE_LIMIT_WINDOW, RATE_LIMIT_DB_PATH):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many status poll requests. Please wait a minute."},
                    headers={"Retry-After": "60"},
                )

        # 2. Pre-flight Simulation
        elif path == "/api/tx/simulate":
            if check_rate_limit(client_ip, path, 15, RATE_LIMIT_WINDOW, RATE_LIMIT_DB_PATH):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many simulation/inspect requests. Pre-flight quota exceeded. Please wait a minute."},
                    headers={"Retry-After": "60"}
                )

        elif path in ("/api/net", "/api/health"):
            pass

        else:
            # 3. Action Routes (scan, build-tx, confirm, etc.)
            if check_rate_limit(client_ip, path, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW, RATE_LIMIT_DB_PATH):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests. Rate limit exceeded. Please wait a minute."},
                    headers={"Retry-After": "60"}
                )

    # Process request
    response = await call_next(request)

    # Inject Security Headers
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'none';"
    )
    
    return response


# ── RPC FAILOVER POOL INITIALIZATION ──────────────────────────────────────────

def create_rpc_pool() -> RpcFailoverPool:
    helius_key = os.getenv("HELIUS_API_KEY", "").strip()
    primary_url = f"https://mainnet.helius-rpc.com/?api-key={helius_key}" if helius_key else None
    env_urls = os.getenv("SOLANA_RPC_URLS", "") or os.getenv("SOLANA_RPC_URL", "")
    parsed_urls = [u.strip() for u in env_urls.split(",") if u.strip()]

    urls = []
    if primary_url:
        urls.append(primary_url)
    for u in parsed_urls:
        if u and u not in urls:
            urls.append(u)
    if "https://api.mainnet-beta.solana.com" not in urls:
        urls.append("https://api.mainnet-beta.solana.com")

    return RpcFailoverPool(urls)


rpc_pool = create_rpc_pool()


def _rpc_call(method: str, params: list):
    """Execute RPC method via failover pool with automatic retries and failover."""
    try:
        return rpc_pool.call(method, params)
    except Exception as e:
        logger.error(f"Solana RPC failover pool error for {method}: {e}")
        raise RpcError(f"Solana RPC execution error: {e}") from e


SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"


async def _rpc_call_async(method: str, params: list):
    """Async JSON-RPC wrapper. Prefer the async failover pool in prod; honor sync mocks in tests."""
    mock_target = getattr(_rpc_call, "__class__", None)
    module_name = getattr(mock_target, "__module__", "") if mock_target else ""
    if module_name.startswith("unittest.mock"):
        return _rpc_call(method, params)
    return await rpc_pool.call_async(method, params)


DISALLOWED_PROGRAM_IDS = {
    SYSTEM_PROGRAM_ID,
    str(TOKEN_PROGRAM_ID),
    str(TOKEN_2022_PROGRAM_ID),
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    "BPFLoaderUpgradeab1e11111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111",
    "SysvarRent111111111111111111111111111111111",
    "SysvarC1ock11111111111111111111111111111111",
    "SysvarEpochRewards1111111111111111111111111",
    "SysvarEpochSchedule111111111111111111111111",
    "SysvarFees111111111111111111111111111111111",
    "SysvarRecentB1ockHashes11111111111111111111",
    "SysvarSlotHashes111111111111111111111111111",
    "SysvarSlotHistory11111111111111111111111111",
    "SysvarStakeHistory1111111111111111111111111",
    "SysvarLastRestartS1ot1111111111111111111111",
    "SysvarInstructions1111111111111111111111111",
    "NativeLoader1111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
    "Stake11111111111111111111111111111111111111",
    "AddressLookupTab1e1111111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "Config1111111111111111111111111111111111111",
}

COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111"
CLAIME_ALLOWED_PROGRAM_IDS = {
    str(TOKEN_PROGRAM_ID),
    str(TOKEN_2022_PROGRAM_ID),
    COMPUTE_BUDGET_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
}


def validate_wallet_address(address: Optional[str]) -> Pubkey:
    """Validate that input is a valid user wallet address."""
    if not address or not isinstance(address, str) or not address.strip():
        raise HTTPException(
            status_code=400,
            detail={"detail": "Wallet address cannot be empty.", "error_code": "EMPTY_WALLET_ADDRESS"},
        )
    if any(c.isspace() or not c.isprintable() for c in address):
        raise HTTPException(
            status_code=400,
            detail={"detail": "Wallet address must not contain spaces or invisible characters.", "error_code": "INVALID_BASE58"},
        )
    if not is_valid_base58_address_fast(address):
        raise HTTPException(
            status_code=400,
            detail={"detail": "Invalid Solana address format (must be valid Base58, 32-44 characters).", "error_code": "INVALID_BASE58"},
        )
    try:
        pubkey = Pubkey.from_string(address)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail={"detail": "Invalid Solana public key.", "error_code": "INVALID_BASE58"},
        )
    if len(bytes(pubkey)) != 32:
        raise HTTPException(
            status_code=400,
            detail={"detail": "Decoded address must be exactly 32 bytes.", "error_code": "INVALID_BASE58"},
        )
    pubkey_str = str(pubkey)
    if pubkey_str in DISALLOWED_PROGRAM_IDS:
        raise HTTPException(
            status_code=400,
            detail={"detail": f"Address '{pubkey_str}' is a system or program account, not a user wallet.", "error_code": "SYSTEM_PROGRAM_NOT_WALLET"},
        )
    return pubkey


def validate_amount_lamports(amount: Optional[Any]) -> Optional[int]:
    """Validate that amount is strictly an integer in lamports (no floats/decimals)."""
    if amount is None:
        return None
    if isinstance(amount, float):
        raise HTTPException(
            status_code=400,
            detail={"detail": "Amount must be an integer in lamports, decimals are forbidden.", "error_code": "INVALID_AMOUNT"},
        )
    if isinstance(amount, str):
        cleaned = amount.strip()
        if not cleaned:
            return None
        if "." in cleaned or "e" in cleaned.lower() or not (cleaned.isdigit() or (cleaned.startswith("+") and cleaned[1:].isdigit())):
            raise HTTPException(
                status_code=400,
                detail={"detail": "Amount must be an integer in lamports, decimals are forbidden.", "error_code": "INVALID_AMOUNT"},
            )
        return int(cleaned)
    if isinstance(amount, int) and not isinstance(amount, bool):
        if amount < 0:
            raise HTTPException(
                status_code=400,
                detail={"detail": "Amount cannot be negative.", "error_code": "INVALID_AMOUNT"},
            )
        return amount
    raise HTTPException(
        status_code=400,
        detail={"detail": "Amount must be an integer in lamports.", "error_code": "INVALID_AMOUNT"},
    )


async def verify_wallet_not_executable(owner_pubkey_str: str) -> None:
    """Verify on-chain that the address is not an executable program (async)."""
    try:
        acc_info = await _rpc_call_async("getAccountInfo", [owner_pubkey_str, {"encoding": "jsonParsed"}])
        if acc_info and isinstance(acc_info, dict):
            val = acc_info.get("value")
            if val and isinstance(val, dict) and val.get("executable") is True:
                raise HTTPException(
                    status_code=400,
                    detail={"detail": f"Address '{owner_pubkey_str}' is an executable program, not a user wallet.", "error_code": "EXECUTABLE_PROGRAM_NOT_WALLET"},
                )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"RPC query error checking account info for {owner_pubkey_str}: {e}")
        raise HTTPException(
            status_code=502,
            detail={"detail": f"Solana RPC failed while checking account: {e}", "error_code": "RPC_ERROR"},
        )


def verify_wallet_not_executable_sync(owner_pubkey_str: str) -> None:
    """Verify on-chain that the address is not an executable program (sync fallback)."""
    try:
        acc_info = _rpc_call("getAccountInfo", [owner_pubkey_str, {"encoding": "jsonParsed"}])
        if acc_info and isinstance(acc_info, dict):
            val = acc_info.get("value")
            if val and isinstance(val, dict) and val.get("executable") is True:
                raise HTTPException(
                    status_code=400,
                    detail={"detail": f"Address '{owner_pubkey_str}' is an executable program, not a user wallet.", "error_code": "EXECUTABLE_PROGRAM_NOT_WALLET"},
                )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"RPC query error checking account info for {owner_pubkey_str}: {e}")
        raise HTTPException(
            status_code=502,
            detail={"detail": f"Solana RPC failed while checking account: {e}", "error_code": "RPC_ERROR"},
        )


# ── DATA MODELS ───────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    wallet_address: str


class ConfirmRequest(BaseModel):
    wallet: str
    signature: str
    accounts_closed: Optional[int] = 0
    sol_amount: Optional[Any] = None
    estimated_usd: Optional[Any] = None


class SimulateTxRequest(BaseModel):
    transaction_base64: str = Field(..., min_length=16, max_length=16384, description="Base64-encoded wire transaction")


def usd_cents_from_lamports(lamports: int, price_micro_usd: Optional[int]) -> Optional[int]:
    """Convert verified lamports using integer micro-USD per SOL; None means no trusted price."""
    if (
        not isinstance(lamports, int) or isinstance(lamports, bool) or lamports <= 0
        or not isinstance(price_micro_usd, int) or isinstance(price_micro_usd, bool) or price_micro_usd <= 0
    ):
        return None
    return lamports * price_micro_usd // 10_000_000_000_000


class SolanaPayAccountPayload(BaseModel):
    account: Optional[str] = None
    amount: Optional[Any] = None


# ── BLOCKCHAIN VERIFICATION & TRANSACTION COMPILER ───────────────────────────

def verify_signature_onchain(signature_str: str) -> bool:
    """Verify transaction signature status on Solana RPC with confirmed commitment."""
    try:
        data = _rpc_call("getSignatureStatuses", [[signature_str], {"searchTransactionHistory": True}])
        if data and "value" in data and len(data["value"]) > 0:
            status = data["value"][0]
            if status is not None:
                if status.get("err") is not None:
                    logger.warning(f"Transaction {signature_str} reported on-chain error: {status.get('err')}")
                    return False
                conf_status = status.get("confirmationStatus")
                if conf_status in ("confirmed", "finalized"):
                    return True
                return False

        tx_data = _rpc_call(
            "getTransaction",
            [signature_str, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 2, "commitment": "confirmed"}]
        )
        if tx_data is not None:
            meta = tx_data.get("meta") or {}
            if meta.get("err") is None:
                return True
            else:
                logger.warning(f"Transaction {signature_str} meta reported error: {meta.get('err')}")
                return False
    except Exception as e:
        logger.error(f"Error querying signature status for {signature_str}: {e}")
    return False


MIN_FEE_RESERVE_LAMPORTS = 10_000
BASE_FEE_LAMPORTS = 5_000
BUILDER_PRIORITY_FEE_LAMPORTS = 0


async def require_fee_reserve_async(owner_pubkey_str: str) -> int:
    """Refuse to build a transaction without enough SOL for the signature fee (async)."""
    try:
        balance_res = await _rpc_call_async("getBalance", [owner_pubkey_str])
        raw_balance = balance_res.get("value", 0) if isinstance(balance_res, dict) else (balance_res or 0)
        native_lamports = raw_balance if isinstance(raw_balance, int) and not isinstance(raw_balance, bool) else 0
    except Exception as e:
        logger.error(f"Failed to fetch native SOL balance for {owner_pubkey_str}: {e}")
        raise HTTPException(
            status_code=502,
            detail={"detail": f"Solana RPC getBalance failed: {e}", "error_code": "RPC_FAILURE"},
        )
    if native_lamports < MIN_FEE_RESERVE_LAMPORTS:
        raise HTTPException(
            status_code=400,
            detail={
                "detail": "Native SOL balance below 0.00001. Not enough for the network signature fee.",
                "error_code": "INSUFFICIENT_FEE_RESERVE",
            },
        )
    return native_lamports


def require_fee_reserve(owner_pubkey_str: str) -> int:
    """Refuse to build a transaction without enough SOL for the signature fee (sync)."""
    try:
        balance_res = _rpc_call("getBalance", [owner_pubkey_str])
        raw_balance = balance_res.get("value", 0) if isinstance(balance_res, dict) else (balance_res or 0)
        native_lamports = raw_balance if isinstance(raw_balance, int) and not isinstance(raw_balance, bool) else 0
    except Exception as e:
        logger.error(f"Failed to fetch native SOL balance for {owner_pubkey_str}: {e}")
        raise HTTPException(
            status_code=502,
            detail={"detail": f"Solana RPC getBalance failed: {e}", "error_code": "RPC_FAILURE"},
        )
    if native_lamports < MIN_FEE_RESERVE_LAMPORTS:
        raise HTTPException(
            status_code=400,
            detail={
                "detail": "Native SOL balance below 0.00001. Not enough for the network signature fee.",
                "error_code": "INSUFFICIENT_FEE_RESERVE",
            },
        )
    return native_lamports


def _fetch_program_accounts(owner_pubkey_str: str, program_id: Pubkey) -> list:
    """Query RPC for token accounts owned by the wallet for a given token program."""
    raw = _rpc_call(
        "getTokenAccountsByOwner",
        [
            owner_pubkey_str,
            {"programId": str(program_id)},
            {"encoding": "jsonParsed"},
        ],
    )
    if raw is None or not isinstance(raw, dict) or "value" not in raw:
        raise RpcError(f"Solana RPC query for program {program_id} returned invalid or null payload.")
    return raw.get("value", [])


async def _fetch_program_accounts_async(owner_pubkey_str: str, program_id: Pubkey) -> list:
    """Async JSON-RPC query for token accounts."""
    raw = await _rpc_call_async(
        "getTokenAccountsByOwner",
        [
            owner_pubkey_str,
            {"programId": str(program_id)},
            {"encoding": "jsonParsed"},
        ],
    )
    if raw is None or not isinstance(raw, dict) or "value" not in raw:
        raise RpcError(f"Solana RPC query for program {program_id} returned invalid or null payload.")
    return raw.get("value", [])


def _compile_tx_payload(
    user_pubkey: Pubkey,
    all_reclaimable: list,
    blockhash_str: str,
    sol_price: Optional[float] = None,
) -> dict:
    """Constructs versioned transaction payload for reclaimable accounts with binary MTU trimming."""
    try:
        payload = compile_claim_transaction_payload(
            user_pubkey=user_pubkey,
            all_reclaimable=all_reclaimable,
            blockhash_str=blockhash_str,
            sol_price=sol_price,
            max_batch_size=BATCH_SIZE,
        )
        payload["network_fee_lamports"] = BASE_FEE_LAMPORTS + BUILDER_PRIORITY_FEE_LAMPORTS
        payload["estimated_validator_fee_lamports"] = payload["network_fee_lamports"]
        return payload
    except ValueError as e:
        raise HTTPException(
            status_code=413,
            detail=str(e),
        )


def _compile_claim(address: str, price_getter=None) -> dict:
    """Shared compiler implementation for claim transaction."""
    user_pubkey = validate_wallet_address(address)
    user_str = str(user_pubkey)
    require_fee_reserve(user_str)

    try:
        spl_accounts = _fetch_program_accounts(user_str, TOKEN_PROGRAM_ID)
        token2022_accounts = _fetch_program_accounts(user_str, TOKEN_2022_PROGRAM_ID)
    except Exception as e:
        logger.error(f"Solana RPC error during build-tx: {e}")
        raise HTTPException(
            status_code=502,
            detail={"detail": f"Solana RPC query failed: {e}", "error_code": "RPC_ERROR"},
        )

    spl_reclaimable, _, _, _ = parse_reclaimable_accounts(spl_accounts, TOKEN_PROGRAM_ID, user_str)
    t22_reclaimable, _, _, _ = parse_reclaimable_accounts(token2022_accounts, TOKEN_2022_PROGRAM_ID, user_str)
    all_reclaimable = [
        item for item in spl_reclaimable + t22_reclaimable
        if item.get("amount") == 0
    ]

    if not all_reclaimable:
        return {
            "status": "empty",
            "message": "No reclaimable SPL or Token-2022 accounts found.",
            "accounts_closed_in_batch": 0,
            "total_empty_found": 0,
            "sol_reclaimed": "0.000000000",
            "sol_reclaimed_lamports": 0,
            "network_fee_lamports": 0,
            "estimated_validator_fee_lamports": 0,
            "transaction_base64": "",
        }

    try:
        latest_blockhash_data = _rpc_call("getLatestBlockhash", [{"commitment": "confirmed"}])
        blockhash_str = latest_blockhash_data["value"]["blockhash"]
    except Exception as e:
        logger.error(f"Failed to fetch blockhash: {e}")
        raise HTTPException(status_code=502, detail="Failed to fetch recent blockhash from Solana RPC.")

    sol_price = price_getter() if callable(price_getter) else price_getter
    return _compile_tx_payload(user_pubkey, all_reclaimable, blockhash_str, sol_price)


async def _build_claim_transaction_async(address: str) -> dict:
    """Async wrapper for build transaction."""
    user_pubkey = validate_wallet_address(address)
    await verify_wallet_not_executable(str(user_pubkey))
    user_str = str(user_pubkey)
    await require_fee_reserve_async(user_str)

    try:
        spl_accounts, token2022_accounts = await asyncio.gather(
            _fetch_program_accounts_async(user_str, TOKEN_PROGRAM_ID),
            _fetch_program_accounts_async(user_str, TOKEN_2022_PROGRAM_ID),
        )
    except Exception as e:
        logger.error(f"Solana RPC error during build-tx: {e}")
        raise HTTPException(
            status_code=502,
            detail={"detail": f"Solana RPC query failed: {e}", "error_code": "RPC_ERROR"},
        )

    spl_reclaimable, _, _, _ = parse_reclaimable_accounts(spl_accounts, TOKEN_PROGRAM_ID, user_str)
    t22_reclaimable, _, _, _ = parse_reclaimable_accounts(token2022_accounts, TOKEN_2022_PROGRAM_ID, user_str)
    all_reclaimable = [
        item for item in spl_reclaimable + t22_reclaimable
        if item.get("amount") == 0
    ]

    if not all_reclaimable:
        return {
            "status": "empty",
            "message": "No reclaimable SPL or Token-2022 accounts found.",
            "accounts_closed_in_batch": 0,
            "total_empty_found": 0,
            "sol_reclaimed": "0.000000000",
            "sol_reclaimed_lamports": 0,
            "network_fee_lamports": 0,
            "estimated_validator_fee_lamports": 0,
            "transaction_base64": "",
        }

    try:
        latest_blockhash_data = await _rpc_call_async("getLatestBlockhash", [{"commitment": "confirmed"}])
        blockhash_str = latest_blockhash_data["value"]["blockhash"]
    except Exception as e:
        logger.error(f"Failed to fetch blockhash: {e}")
        raise HTTPException(status_code=502, detail="Failed to fetch recent blockhash from Solana RPC.")

    return _compile_tx_payload(user_pubkey, all_reclaimable, blockhash_str, None)


def _build_claim_transaction(address: str) -> dict:
    """Synchronous wrapper for build transaction."""
    try:
        return asyncio.run(_build_claim_transaction_async(address))
    except RuntimeError:
        user_pubkey = validate_wallet_address(address)
        verify_wallet_not_executable_sync(str(user_pubkey))
        user_str = str(user_pubkey)
        require_fee_reserve(user_str)
        return _compile_claim(address, price_getter=None)


# ── HEALTH CHECK ROUTE ────────────────────────────────────────────────────────

@app.api_route("/api/health", methods=["GET", "HEAD"])
@app.api_route("/health", methods=["GET", "HEAD"])
def health_check():
    return {
        "status": "healthy",
        "service": "quillhog-rent",
        "version": "3.0.0",
        "timestamp": int(time.time()),
        "git_sha": os.getenv("GIT_SHA", "unknown"),
    }


# ── NETWORK STATUS ROUTE ──────────────────────────────────────────────────────

_net_status_cache = {
    "data": None,
    "ts": 0.0,
}
_net_status_lock = asyncio.Lock()


@app.get("/api/net")
async def get_network_status():
    """Public network status ticker endpoint with 15s Single-Flight cache."""
    now = time.time()
    if _net_status_cache["data"] is not None and (now - _net_status_cache["ts"] < 15.0):
        return _net_status_cache["data"]

    async with _net_status_lock:
        now = time.time()
        if _net_status_cache["data"] is not None and (now - _net_status_cache["ts"] < 15.0):
            return _net_status_cache["data"]

        base_fee: Optional[int] = None
        priority_fee: Optional[int] = None
        fee_sol: Optional[str] = None
        network_status: str = "unknown"

        try:
            raw_fees = await asyncio.wait_for(
                _rpc_call_async("getRecentPrioritizationFees", []),
                timeout=2.5,
            )
            if raw_fees is not None and isinstance(raw_fees, list):
                base_fee = 5000
                if raw_fees:
                    fees = [int(f.get("prioritizationFee", 0)) for f in raw_fees if isinstance(f, dict)]
                    if fees:
                        fees.sort()
                        mid_fee = fees[len(fees) // 2]
                        priority_fee = int(mid_fee)
                        network_status = "busy" if mid_fee > 50000 else "ok"
                    else:
                        priority_fee = 0
                        network_status = "ok"
                else:
                    priority_fee = 0
                    network_status = "ok"
                total_lamports = base_fee + (priority_fee or 0)
                fee_sol = _sol_from_lamports(total_lamports)
            else:
                network_status = "unknown"
                fee_sol = None
        except Exception as e:
            logger.warning(f"/api/net RPC call error: {e}")
            network_status = "unknown"
            fee_sol = None

        blockhash: Optional[str] = None
        try:
            latest_blockhash_data = await asyncio.wait_for(
                _rpc_call_async("getLatestBlockhash", [{"commitment": "confirmed"}]),
                timeout=2.5,
            )
            if latest_blockhash_data and isinstance(latest_blockhash_data, dict):
                val = latest_blockhash_data.get("value")
                if isinstance(val, dict) and "blockhash" in val:
                    blockhash = str(val["blockhash"])
        except Exception as e:
            logger.warning(f"/api/net blockhash fetch error: {e}")

        result = {
            "fee_lamports": total_lamports if base_fee is not None else None,
            "fee_sol": fee_sol,
            "base_fee_lamports": base_fee,
            "priority_lamports": priority_fee,
            "network": network_status,
        }
        _net_status_cache["data"] = result
        _net_status_cache["ts"] = now
        return result


# ── ROUTE 1: SCAN WALLET ──────────────────────────────────────────────────────

@app.post("/api/scan")
async def scan_wallet(req: ScanRequest, request: Request = None):
    owner_pubkey = validate_wallet_address(req.wallet_address)
    owner_str = str(owner_pubkey)
    await verify_wallet_not_executable(owner_str)

    try:
        spl_accounts, token2022_accounts = await asyncio.gather(
            _fetch_program_accounts_async(owner_str, TOKEN_PROGRAM_ID),
            _fetch_program_accounts_async(owner_str, TOKEN_2022_PROGRAM_ID),
        )
    except Exception as e:
        logger.error(f"Solana RPC error during token scan: {e}")
        raise HTTPException(
            status_code=502,
            detail={"detail": f"Solana RPC query failed: {e}", "error_code": "RPC_FAILURE"},
        )

    spl_reclaimable, spl_empty, spl_wsol, spl_wsol_lamports = parse_reclaimable_accounts(
        spl_accounts, TOKEN_PROGRAM_ID, owner_str
    )
    t22_reclaimable, t22_empty, t22_wsol, t22_wsol_lamports = parse_reclaimable_accounts(
        token2022_accounts, TOKEN_2022_PROGRAM_ID, owner_str
    )

    all_claimable = [
        item for item in spl_reclaimable + t22_reclaimable
        if item.get("amount") == 0
    ]
    total_token_accounts = len(spl_accounts) + len(token2022_accounts)
    total_wsol_count = spl_wsol + t22_wsol
    total_wsol_lamports = spl_wsol_lamports + t22_wsol_lamports
    total_wsol_sol = _sol_from_lamports(total_wsol_lamports)

    rent_lamports = sum(item["lamports"] for item in all_claimable)
    rent_sol = _sol_from_lamports(rent_lamports)

    try:
        balance_res = await _rpc_call_async("getBalance", [owner_str])
        raw_native_lamports = balance_res.get("value", 0) if isinstance(balance_res, dict) else (balance_res or 0)
        native_lamports = raw_native_lamports if isinstance(raw_native_lamports, int) and not isinstance(raw_native_lamports, bool) else 0
        has_fee_reserve = native_lamports >= MIN_FEE_RESERVE_LAMPORTS
        native_sol_balance = _sol_from_lamports(native_lamports)
    except Exception as e:
        logger.error(f"Failed to fetch native SOL balance for {owner_str}: {e}")
        raise HTTPException(
            status_code=502,
            detail={"detail": f"Solana RPC getBalance failed: {e}", "error_code": "RPC_FAILURE"},
        )

    unique_t22_mints: List[str] = []
    for item in token2022_accounts if isinstance(token2022_accounts, list) else []:
        if not isinstance(item, dict):
            continue
        account = item.get("account") if isinstance(item.get("account"), dict) else item
        data = account.get("data") if isinstance(account.get("data"), dict) else account
        parsed = data.get("parsed") if isinstance(data.get("parsed"), dict) else data
        info = parsed.get("info") if isinstance(parsed.get("info"), dict) else parsed
        mint = info.get("mint") or item.get("mint")
        if mint and isinstance(mint, str) and mint not in unique_t22_mints:
            unique_t22_mints.append(mint)

    mint_info_partial = len(unique_t22_mints) > 50
    mints_to_fetch = unique_t22_mints[:50]
    mint_info: Dict[str, Any] = {}
    mint_info_available = True

    if mints_to_fetch:
        try:
            for i in range(0, len(mints_to_fetch), 100):
                chunk = mints_to_fetch[i : i + 100]
                rpc_res = await _rpc_call_async(
                    "getMultipleAccounts",
                    [chunk, {"encoding": "jsonParsed"}],
                )
                vals = rpc_res.get("value") if isinstance(rpc_res, dict) else None
                if isinstance(vals, list):
                    for mint_pubkey, acc_val in zip(chunk, vals):
                        if acc_val:
                            mint_info[mint_pubkey] = acc_val
                else:
                    mint_info_available = False
                    logger.warning("getMultipleAccounts returned non-list value")
        except Exception as e:
            logger.warning(f"Failed to fetch mint info for Token-2022 accounts: {e}")
            mint_info_available = False

    scan_summary = summarize_scan_accounts(
        spl_accounts + token2022_accounts,
        native_lamports,
        mint_info=mint_info,
        mint_info_available=mint_info_available,
        owner=owner_str,
    )

    reclaimable_count = len(all_claimable)
    num_tx = (reclaimable_count + BATCH_SIZE - 1) // BATCH_SIZE if reclaimable_count > 0 else 0
    network_fee_lamports = num_tx * BASE_FEE_LAMPORTS + (num_tx * BUILDER_PRIORITY_FEE_LAMPORTS)

    return {
        **scan_summary,
        "wallet": owner_str,
        "total_token_accounts": total_token_accounts,
        "empty_spl_count": spl_empty,
        "empty_2022_count": t22_empty,
        "wsol_count": total_wsol_count,
        "wsol_reclaimable_sol": total_wsol_sol,
        "wsol_reclaimable_lamports": total_wsol_lamports,
        "empty_accounts_count": len(all_claimable),
        "reclaimable_sol": rent_sol,
        "reclaimable_lamports": rent_lamports,
        "rent_sol": rent_sol,
        "rent_lamports": rent_lamports,
        "network_fee_lamports": network_fee_lamports,
        "estimated_validator_fee_lamports": network_fee_lamports,
        "native_sol_balance": native_sol_balance,
        "native_lamports": native_lamports,
        "has_fee_reserve": has_fee_reserve,
        "batch_sample": [item["pubkey"] for item in all_claimable[:BATCH_SIZE]],
        "mint_info_available": mint_info_available,
        "mint_info_partial": mint_info_partial,
    }


# ── ROUTE 2: BUILD VERSIONED TRANSACTION ──────────────────────────────────────

@app.post("/api/rent/build-tx")
async def build_claim_tx(req: ScanRequest):
    return await _build_claim_transaction_async(req.wallet_address)


PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://quillhog.xyz").rstrip("/")


# ── ROUTE 3: SOLANA PAY 2-STEP SPECIFICATION ─────────────────────────────────

@app.get("/api/rent/qr")
def get_solana_pay_qr(
    wallet: Optional[str] = Query(None),
    amount: Optional[str] = Query(None),
    request: Request = None,
):
    """Solana Pay Step 1: Return metadata (label + icon) for wallet prompt display."""
    if wallet is not None:
        validate_wallet_address(wallet)
    if amount is not None:
        validate_amount_lamports(amount)

    icon_url = f"{PUBLIC_BASE_URL}/favicon.ico"
    return {
        "label": "Quillhog Claime",
        "icon": icon_url,
    }


@app.post("/api/rent/qr")
async def post_solana_pay_qr(
    wallet: Optional[str] = Query(None),
    amount: Optional[str] = Query(None),
    payload: Optional[SolanaPayAccountPayload] = None,
):
    """Solana Pay Step 2: Receive user account, compile and return VersionedTransaction."""
    target_wallet = (payload.account if payload and payload.account else None) or wallet
    if not target_wallet:
        raise HTTPException(status_code=400, detail="Missing wallet address parameter.")
    validate_wallet_address(target_wallet)

    req_amount = (payload.amount if payload and payload.amount is not None else None) or amount
    if req_amount is not None:
        validate_amount_lamports(req_amount)

    res = await _build_claim_transaction_async(target_wallet)
    if res.get("status") != "ready":
        raise HTTPException(status_code=400, detail=res.get("message", "No accounts to reclaim."))
    return {
        "transaction": res["transaction_base64"],
        "message": "Close empty token accounts. 0% protocol fee.",
    }


@app.get("/api/rent/deep-links")
def get_deep_links(wallet: Optional[str] = Query(None), request: Request = None):
    """Generate universal Solana Pay and mobile wallet deep links (Phantom, Solflare)."""
    base_url = f"{PUBLIC_BASE_URL}/api/rent/qr"
    return generate_solana_pay_deep_links(base_qr_url=base_url, wallet=wallet)


# ── ROUTE 4: ON-CHAIN TRANSACTION STATUS POLLING ────────────────────────────

@app.get("/api/tx/status")
def get_tx_status(sig: str = Query(..., description="Transaction signature")):
    """Read-only rate-limited transaction status polling endpoint (T-012)."""
    sig = sig.strip()
    if not (64 <= len(sig) <= 88):
        raise HTTPException(status_code=400, detail="Invalid signature length.")
    try:
        Signature.from_string(sig)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Solana signature format.")

    try:
        data = _rpc_call("getSignatureStatuses", [[sig], {"searchTransactionHistory": True}])
        if data and isinstance(data, dict) and "value" in data and len(data["value"]) > 0:
            status = data["value"][0]
            if status is not None:
                if status.get("err") is not None:
                    return {"status": "failed", "err": status.get("err")}
                conf_status = status.get("confirmationStatus")
                if conf_status in ("confirmed", "finalized"):
                    return {"status": "confirmed", "commitment": conf_status}
                return {"status": "pending"}
    except Exception as e:
        logger.error(f"Error querying signature status for {sig}: {e}")

    return {"status": "pending"}


# ── ROUTE 5: PRE-FLIGHT TRANSACTION SIMULATION (Q-06) ─────────────────────────

@app.post("/api/tx/simulate")
async def simulate_transaction(req: SimulateTxRequest):
    """Pre-flight transaction simulation against Solana RPC without wallet signature (Q-06)."""
    tx_b64 = req.transaction_base64.strip()
    try:
        tx_bytes = base64.b64decode(tx_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail={"detail": "Invalid base64 encoding.", "error_code": "INVALID_BASE64"})

    if len(tx_bytes) > MAX_TX_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"detail": "Transaction wire payload exceeds max MTU limit (1232 bytes).", "error_code": "TX_TOO_LARGE"},
        )

    try:
        parsed_tx = VersionedTransaction.from_bytes(tx_bytes)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail={"detail": "Invalid transaction wire structure.", "error_code": "INVALID_TRANSACTION_WIRE"},
        )

    msg = getattr(parsed_tx, "message", None)
    account_keys = getattr(msg, "account_keys", None) if msg else None
    if not msg or not account_keys or len(account_keys) == 0:
        raise HTTPException(
            status_code=400,
            detail={"detail": "Transaction missing account keys.", "error_code": "INVALID_TRANSACTION_WIRE"},
        )

    fee_payer_str = str(account_keys[0])
    try:
        validate_wallet_address(fee_payer_str)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=400,
            detail={"detail": "Invalid fee payer address.", "error_code": "INVALID_FEE_PAYER"},
        )

    instructions = getattr(msg, "instructions", [])
    if not instructions:
        raise HTTPException(
            status_code=400,
            detail={"detail": "Transaction contains no instructions.", "error_code": "EMPTY_INSTRUCTIONS"},
        )

    for ix in instructions:
        prog_idx = getattr(ix, "program_id_index", None)
        if prog_idx is None or prog_idx >= len(account_keys):
            raise HTTPException(
                status_code=400,
                detail={"detail": "Instruction program index out of range.", "error_code": "INVALID_PROGRAM_ID"},
            )
        prog_id_str = str(account_keys[prog_idx])
        if prog_id_str not in CLAIME_ALLOWED_PROGRAM_IDS:
            raise HTTPException(
                status_code=400,
                detail={"detail": f"Unauthorized program in transaction: {prog_id_str}.", "error_code": "DISALLOWED_PROGRAM_ID"},
            )

    try:
        rpc_res = await _rpc_call_async(
            "simulateTransaction",
            [tx_b64, {"encoding": "base64", "commitment": "confirmed", "sigVerify": False, "replaceRecentBlockhash": True}],
        )
    except Exception as e:
        logger.warning(f"Transaction simulation RPC error: {e}")
        raise HTTPException(
            status_code=503,
            detail={"detail": "Simulation service unavailable.", "error_code": "SIMULATION_SERVICE_UNAVAILABLE"},
        )

    if not isinstance(rpc_res, dict) or "value" not in rpc_res:
        raise HTTPException(
            status_code=503,
            detail={"detail": "Invalid response from RPC simulation.", "error_code": "SIMULATION_SERVICE_UNAVAILABLE"},
        )

    val = rpc_res.get("value")
    if not isinstance(val, dict):
        raise HTTPException(
            status_code=503,
            detail={"detail": "Invalid value in RPC simulation response.", "error_code": "SIMULATION_SERVICE_UNAVAILABLE"},
        )

    err = val.get("err")
    logs = val.get("logs") or []
    units_consumed = val.get("unitsConsumed") or 0

    if err is not None:
        err_msg = json.dumps(err) if isinstance(err, (dict, list)) else str(err)
        return {
            "ok": False,
            "logs": logs,
            "units_consumed": units_consumed,
            "error": err_msg,
        }

    return {
        "ok": True,
        "logs": logs,
        "units_consumed": units_consumed,
        "error": None,
    }


def _validate_confirm_claim_instructions(instructions: list, wallet: str) -> int:
    """Validate on-chain instructions format and return count of authorized CloseAccount instructions."""
    close_instructions_count = 0

    for ix in instructions:
        if not isinstance(ix, dict):
            raise HTTPException(status_code=400, detail="Invalid instruction format in transaction.")

        prog = ix.get("program")
        prog_id = ix.get("programId")
        parsed = ix.get("parsed")

        # 1. CloseAccount
        if prog in ("spl-token", "spl-token-2022") and isinstance(parsed, dict) and parsed.get("type") == "closeAccount":
            info = parsed.get("info") or {}
            if info.get("owner") != wallet or info.get("destination") != wallet:
                raise HTTPException(status_code=400, detail="CloseAccount instruction owner or destination does not match wallet.")
            close_instructions_count += 1
            continue

        # 2. ATA-create
        if (prog == "spl-associated-token-account" or prog_id == "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL") and isinstance(parsed, dict) and parsed.get("type") in ("create", "createIdempotent"):
            continue

        # 3. WSOL-sync (syncNative)
        if prog in ("spl-token", "spl-token-2022") and isinstance(parsed, dict) and parsed.get("type") == "syncNative":
            continue

        # 4. ComputeBudget
        if prog == "compute-budget" or prog_id == COMPUTE_BUDGET_PROGRAM_ID:
            continue

        raise HTTPException(
            status_code=400,
            detail=f"Unauthorized instruction in transaction: program={prog or prog_id}, type={parsed.get('type') if isinstance(parsed, dict) else 'unknown'}"
        )

    if close_instructions_count == 0:
        raise HTTPException(status_code=400, detail="Not a CloseAccount transaction.")

    if close_instructions_count > BATCH_SIZE:
        raise HTTPException(status_code=400, detail="Too many CloseAccount instructions in transaction.")

    return close_instructions_count



def _record_signature_confirmed(sig: str, db_path: Optional[Union[str, Path]] = None) -> bool:
    target_path = Path(db_path) if db_path is not None else RATE_LIMIT_DB_PATH
    conn = sqlite3.connect(target_path, timeout=30.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("CREATE TABLE IF NOT EXISTS confirmed_signatures (sig TEXT PRIMARY KEY, confirmed_at REAL);")
        conn.execute("INSERT INTO confirmed_signatures (sig, confirmed_at) VALUES (?, ?)", (sig, time.time()))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def _verify_confirm_claim_balance_delta(meta: dict, wallet_idx: int) -> int:
    """Verify on-chain balance change for claimant wallet."""
    if "preBalances" in meta and "postBalances" in meta and wallet_idx is not None:
        diff_lamports = int(meta["postBalances"][wallet_idx]) - int(meta["preBalances"][wallet_idx])
        if diff_lamports <= 0:
            raise HTTPException(
                status_code=400,
                detail="No rent reclaimed detected on-chain for this wallet in specified transaction (C3).",
            )
        if diff_lamports > 50 * 1_000_000_000:
            raise HTTPException(status_code=400, detail="Verified lamport delta exceeds the settlement limit.")
        return diff_lamports
    raise HTTPException(
        status_code=400,
        detail="Transaction metadata lacks balance diff information to verify rent reclaim.",
    )


# ── ROUTE 6: CONFIRM SETTLEMENT ──────────────────────────────────────────────

@app.post("/api/rent/confirm")
def confirm_claim(req: ConfirmRequest):
    sig = req.signature.strip()
    wallet = req.wallet.strip()

    if not (64 <= len(sig) <= 88):
        raise HTTPException(status_code=400, detail="Invalid signature length.")
    try:
        Signature.from_string(sig)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Solana signature format.")

    try:
        Pubkey.from_string(wallet)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Solana wallet address.")

    try:
        data = _rpc_call("getSignatureStatuses", [[sig], {"searchTransactionHistory": True}])
        if data and isinstance(data, dict) and "value" in data and len(data["value"]) > 0:
            status_entry = data["value"][0]
            if status_entry is not None and status_entry.get("err") is not None:
                raise HTTPException(status_code=400, detail=f"Transaction failed on-chain: {status_entry.get('err')}")

        is_confirmed = verify_signature_onchain(sig)
        if not is_confirmed:
            return JSONResponse(
                status_code=202,
                content={"status": "pending", "message": "Transaction signature unconfirmed on-chain."}
            )

        tx_data = _rpc_call(
            "getTransaction",
            [sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 2, "commitment": "confirmed"}]
        )
        if not tx_data or not isinstance(tx_data, dict):
            return JSONResponse(
                status_code=202,
                content={"status": "pending", "message": "Transaction not found on-chain yet."}
            )

        meta = tx_data.get("meta") or {}
        if meta.get("err") is not None:
            raise HTTPException(status_code=400, detail="Transaction failed on-chain.")

        tx_msg = (tx_data.get("transaction") or {}).get("message") or {}
        acc_keys = tx_msg.get("accountKeys") or []
        if not acc_keys:
            raise HTTPException(status_code=400, detail="Transaction contains no accountKeys.")

        fee_payer = acc_keys[0].get("pubkey") if isinstance(acc_keys[0], dict) else str(acc_keys[0])
        if fee_payer != wallet:
            raise HTTPException(status_code=400, detail=f"Fee payer ({fee_payer}) does not match wallet ({wallet}).")
        wallet_idx = 0

        instructions = tx_msg.get("instructions") or []
        verified_accounts = _validate_confirm_claim_instructions(instructions, wallet)
        verified_lamports = _verify_confirm_claim_balance_delta(meta, wallet_idx)

        if not _record_signature_confirmed(sig):
            raise HTTPException(status_code=409, detail="Transaction signature already recorded.")

        return {"status": "success", "confirmed": True, "signature": sig, "tx": sig}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"RPC validation failed for signature {sig}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal blockchain verification error. Please retry.")

async def get_sol_price_usd_async() -> Optional[float]:
    return None
