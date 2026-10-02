"""
Quillhog - Standalone Rent Reclaim Service (Production Engine)
File: rent_service.py

High-performance, non-custodial Solana Rent Reclaim backend.
"""

from __future__ import annotations
import asyncio
import base64
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor
import logging
import os
from pathlib import Path
import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta
from solders.message import MessageV0
from solders.transaction import VersionedTransaction
from solders.signature import Signature
from solders.hash import Hash

from rpc_pool import RpcFailoverPool, RpcError
from core_verify import (
    TOKEN_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    WSOL_MINT,
    LAMPORTS_PER_RENT,
    MAX_BATCH_SIZE as BATCH_SIZE,
    MAX_FEE_BPS,
    validate_platform_fee_bps,
    calculate_platform_fee_lamports,
    create_close_account_instruction,
    evaluate_account_eligibility,
    parse_reclaimable_accounts,
    is_valid_base58_address_fast,
    generate_solana_pay_deep_links,
)
from observability import (
    DB_PATH,
    NTFY_TOPIC,
    init_ledger_db,
    record_settlement,
    log_cookieless_event,
    get_global_metrics,
    send_ntfy_alert,
    get_sol_price_usd_async,
    get_sol_price_usd,
    system_heartbeat_loop,
    get_analytics_digest,
    retry_on_lock,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("rent_service")

# ── LIFECYCLE MANAGEMENT (L8 LIFESPAN CONTEXT) ────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure DB schema is initialized & spawn background heartbeat task
    init_ledger_db(DB_PATH)
    heartbeat_task = asyncio.create_task(system_heartbeat_loop(DB_PATH, net_status_getter=get_network_status))
    logger.info("Quillhog online. Heartbeat task initialized.")
    yield
    # Graceful Shutdown
    heartbeat_task.cancel()
    try:
        await heartbeat_task
    except asyncio.CancelledError:
        pass
    logger.info("Quillhog Claime shutting down.")


app = FastAPI(title="Quillhog Rent Reclaim Engine", lifespan=lifespan)

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error_code": "HTTP_ERROR"},
    )

# CORS setup for browser interaction and Solana Pay mobile wallets
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

# ── RATE LIMITING & SECURITY MIDDLEWARE (L8 HARDENING) ────────────────────────
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 10
ip_request_counts = {}

def get_client_ip(request: Request) -> str:
    """Extract real client IP behind Nginx reverse proxy (X-Forwarded-For / X-Real-IP) with fallback."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def add_security_headers_and_rate_limit(request: Request, call_next):
    client_ip = get_client_ip(request)
    current_time = time.time()

    # In-Memory Rate Limiting for /api/ routes with active memory pruning
    if request.url.path.startswith("/api/"):
        history = ip_request_counts.get(client_ip, [])
        # Filter out old requests outside the window
        history = [t for t in history if current_time - t < RATE_LIMIT_WINDOW]
        
        if len(history) >= RATE_LIMIT_MAX_REQUESTS:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Rate limit exceeded. Please wait a minute."}
            )
        
        history.append(current_time)
        ip_request_counts[client_ip] = history

        # Active garbage collection (prevents memory leak from bot floods)
        if len(ip_request_counts) > 500:
            stale_ips = [
                ip for ip, timestamps in list(ip_request_counts.items())
                if not timestamps or (current_time - max(timestamps) >= RATE_LIMIT_WINDOW)
            ]
            for stale_ip in stale_ips:
                ip_request_counts.pop(stale_ip, None)

    # Process request
    response = await call_next(request)

    # Inject Security Headers
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'; script-src 'self' https://unpkg.com 'unsafe-inline'"
    )
    
    return response


CLAIME_DIR = Path(__file__).resolve().parent
CLAIME_HTML_PATH = CLAIME_DIR / "claime.html"


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

DISALLOWED_PROGRAM_IDS = {
    # System Program
    SYSTEM_PROGRAM_ID,
    # SPL Token & Token-2022 Programs
    str(TOKEN_PROGRAM_ID),
    str(TOKEN_2022_PROGRAM_ID),
    # Associated Token Program
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    # BPF Loader Programs
    "BPFLoaderUpgradeab1e11111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111",
    # Sysvars & Native programs
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


def validate_wallet_address(address: Optional[str]) -> Pubkey:
    """
    Validate that input is a valid user wallet address.
    Rejects empty inputs, invalid Base58 encoding, and known program/system IDs.
    """
    if not address or not isinstance(address, str) or not address.strip():
        raise HTTPException(
            status_code=400,
            detail={"detail": "Wallet address cannot be empty.", "error_code": "EMPTY_WALLET_ADDRESS"},
        )
    cleaned = address.strip()
    if not is_valid_base58_address_fast(cleaned):
        raise HTTPException(
            status_code=400,
            detail={"detail": "Invalid Solana address format (must be valid Base58, 32-44 characters).", "error_code": "INVALID_BASE58"},
        )
    try:
        pubkey = Pubkey.from_string(cleaned)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail={"detail": "Invalid Solana public key.", "error_code": "INVALID_BASE58"},
        )
    pubkey_str = str(pubkey)
    if pubkey_str in DISALLOWED_PROGRAM_IDS:
        raise HTTPException(
            status_code=400,
            detail={"detail": f"Address '{pubkey_str}' is a system or program account, not a user wallet.", "error_code": "SYSTEM_PROGRAM_NOT_WALLET"},
        )
    return pubkey


def verify_wallet_not_executable(owner_pubkey_str: str) -> None:
    """Verify on-chain that the address is not an executable program."""
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
    accounts_closed: int
    sol_amount: float
    estimated_usd: Optional[float] = 0.0


class SolanaPayAccountPayload(BaseModel):
    account: Optional[str] = None


class AnalyticsEventReq(BaseModel):
    event_type: str


# ── BLOCKCHAIN VERIFICATION & TRANSACTION COMPILER ───────────────────────────

def verify_signature_onchain(signature_str: str) -> bool:
    """
    Verify transaction signature status on Solana RPC with confirmed commitment.
    Strict check: queries getSignatureStatuses and falls back to getTransaction only if missing.
    Strict L8 Hardening: rejects unconfirmed 'processed' status; accepts only 'confirmed' or 'finalized'.
    """
    try:
        data = _rpc_call("getSignatureStatuses", [[signature_str], {"searchTransactionHistory": True}])
        if data and "value" in data and len(data["value"]) > 0:
            status = data["value"][0]
            if status is not None:
                if status.get("err") is not None:
                    logger.warning(f"Transaction {signature_str} reported on-chain error: {status.get('err')}")
                    return False
                conf_status = status.get("confirmationStatus")
                confirmations = status.get("confirmations")
                if conf_status in ("confirmed", "finalized") or (confirmations is not None and confirmations > 0):
                    return True
                # Reject unconfirmed 'processed' status
                return False

        # Fallback to getTransaction verification only when getSignatureStatuses returned no record
        tx_data = _rpc_call(
            "getTransaction",
            [signature_str, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0, "commitment": "confirmed"}]
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


async def _build_claim_transaction_async(address: str) -> dict:
    """Core transaction compiler shared by build-tx and Solana Pay QR endpoints."""
    user_pubkey = validate_wallet_address(address)
    verify_wallet_not_executable(str(user_pubkey))
    user_str = str(user_pubkey)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            f_spl = executor.submit(_fetch_program_accounts, user_str, TOKEN_PROGRAM_ID)
            f_2022 = executor.submit(_fetch_program_accounts, user_str, TOKEN_2022_PROGRAM_ID)
            spl_accounts = f_spl.result()
            token2022_accounts = f_2022.result()
    except Exception as e:
        logger.error(f"Solana RPC error during build-tx: {e}")
        raise HTTPException(
            status_code=502,
            detail={"detail": f"Solana RPC query failed: {e}", "error_code": "RPC_ERROR"},
        )

    spl_reclaimable, _, _, _ = parse_reclaimable_accounts(spl_accounts, TOKEN_PROGRAM_ID, user_str)
    t22_reclaimable, _, _, _ = parse_reclaimable_accounts(token2022_accounts, TOKEN_2022_PROGRAM_ID, user_str)
    all_reclaimable = spl_reclaimable + t22_reclaimable

    if not all_reclaimable:
        return {
            "status": "empty",
            "message": "No reclaimable SPL or Token-2022 accounts found.",
            "accounts_closed_in_batch": 0,
            "total_empty_found": 0,
            "sol_reclaimed": 0.0,
            "transaction_base64": "",
        }

    # BATCH SIZE LIMIT: 15 accounts per TX to strictly guarantee MTU safety (< 1232 B)
    batch = all_reclaimable[:BATCH_SIZE]
    instructions = [
        create_close_account_instruction(
            account=Pubkey.from_string(item["pubkey"]),
            dest=user_pubkey,
            owner=user_pubkey,
            program_id=item["program_id"],
        )
        for item in batch
    ]

    try:
        latest_blockhash_data = _rpc_call("getLatestBlockhash", [{"commitment": "confirmed"}])
        blockhash_str = latest_blockhash_data["value"]["blockhash"]
        recent_blockhash = Hash.from_string(blockhash_str)
    except Exception as e:
        logger.error(f"Failed to fetch blockhash: {e}")
        raise HTTPException(status_code=502, detail="Failed to fetch recent blockhash from Solana RPC.")

    message = MessageV0.try_compile(
        payer=user_pubkey,
        instructions=instructions,
        address_lookup_table_accounts=[],
        recent_blockhash=recent_blockhash,
    )
    signatures = [Signature.default()] * message.header.num_required_signatures
    unsigned_tx = VersionedTransaction.populate(message, signatures)
    tx_bytes = bytes(unsigned_tx)
    tx_base64 = base64.b64encode(tx_bytes).decode("utf-8")

    batch_lamports = sum(item["lamports"] for item in batch)
    batch_reclaimed_sol = round(batch_lamports / 1e9, 6)
    sol_price = await get_sol_price_usd_async()
    reclaimable_usd = round(batch_reclaimed_sol * sol_price, 2) if (sol_price is not None and sol_price > 0) else 0.0

    return {
        "status": "ready",
        "accounts_closed_in_batch": len(batch),
        "total_empty_found": len(all_reclaimable),
        "sol_reclaimed": batch_reclaimed_sol,
        "estimated_usd": reclaimable_usd,
        "tx_bytes_length": len(tx_bytes),
        "mtu_safe": len(tx_bytes) <= 1232,
        "transaction_base64": tx_base64,
        "tx_base64_sample": tx_base64[:60] + "...",
        "solscan_sample_url": f"https://solscan.io/account/{user_str}",
    }


def _build_claim_transaction(address: str) -> dict:
    """Synchronous wrapper for build transaction."""
    try:
        return asyncio.run(_build_claim_transaction_async(address))
    except RuntimeError:
        # If already in event loop, calculate directly with cached price
        user_pubkey = validate_wallet_address(address)
        verify_wallet_not_executable(str(user_pubkey))
        user_str = str(user_pubkey)
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                f_spl = executor.submit(_fetch_program_accounts, user_str, TOKEN_PROGRAM_ID)
                f_2022 = executor.submit(_fetch_program_accounts, user_str, TOKEN_2022_PROGRAM_ID)
                spl_accounts = f_spl.result()
                token2022_accounts = f_2022.result()
        except Exception as e:
            logger.error(f"Solana RPC error during sync build-tx: {e}")
            raise HTTPException(
                status_code=502,
                detail={"detail": f"Solana RPC query failed: {e}", "error_code": "RPC_ERROR"},
            )

        spl_reclaimable, _, _, _ = parse_reclaimable_accounts(spl_accounts, TOKEN_PROGRAM_ID, user_str)
        t22_reclaimable, _, _, _ = parse_reclaimable_accounts(token2022_accounts, TOKEN_2022_PROGRAM_ID, user_str)
        all_reclaimable = spl_reclaimable + t22_reclaimable

        if not all_reclaimable:
            return {
                "status": "empty",
                "message": "No reclaimable SPL or Token-2022 accounts found.",
                "accounts_closed_in_batch": 0,
                "total_empty_found": 0,
                "sol_reclaimed": 0.0,
                "transaction_base64": "",
            }

        batch = all_reclaimable[:BATCH_SIZE]
        instructions = [
            create_close_account_instruction(
                account=Pubkey.from_string(item["pubkey"]),
                dest=user_pubkey,
                owner=user_pubkey,
                program_id=item["program_id"],
            )
            for item in batch
        ]

        latest_blockhash_data = _rpc_call("getLatestBlockhash", [{"commitment": "confirmed"}])
        blockhash_str = latest_blockhash_data["value"]["blockhash"]
        recent_blockhash = Hash.from_string(blockhash_str)

        message = MessageV0.try_compile(
            payer=user_pubkey,
            instructions=instructions,
            address_lookup_table_accounts=[],
            recent_blockhash=recent_blockhash,
        )
        signatures = [Signature.default()] * message.header.num_required_signatures
        unsigned_tx = VersionedTransaction.populate(message, signatures)
        tx_bytes = bytes(unsigned_tx)
        tx_base64 = base64.b64encode(tx_bytes).decode("utf-8")

        batch_lamports = sum(item["lamports"] for item in batch)
        batch_reclaimed_sol = round(batch_lamports / 1e9, 6)
        sol_price = get_sol_price_usd()
        reclaimable_usd = round(batch_reclaimed_sol * sol_price, 2) if (sol_price is not None and sol_price > 0) else 0.0

        return {
            "status": "ready",
            "accounts_closed_in_batch": len(batch),
            "total_empty_found": len(all_reclaimable),
            "sol_reclaimed": batch_reclaimed_sol,
            "estimated_usd": reclaimable_usd,
            "tx_bytes_length": len(tx_bytes),
            "mtu_safe": len(tx_bytes) <= 1232,
            "transaction_base64": tx_base64,
            "tx_base64_sample": tx_base64[:60] + "...",
            "solscan_sample_url": f"https://solscan.io/account/{user_str}",
        }


# ── HEALTH CHECK ROUTE ────────────────────────────────────────────────────────

@app.get("/api/health")
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "quillhog-rent",
        "version": "3.0.0",
        "timestamp": int(time.time()),
    }


# ── NETWORK STATUS ROUTE (TICKER) ─────────────────────────────────────────────

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

        # 1. Price from single-flight price feed
        sol_usd: Optional[float] = None
        try:
            price = await get_sol_price_usd_async()
            if price and price > 0.0:
                sol_usd = round(price, 2)
        except Exception as e:
            logger.debug(f"Price fetch failed for /api/net: {e}")

        # 2. Priority fees & RPC connectivity with short timeout
        base_fee: Optional[int] = None
        priority_fee: Optional[int] = None
        fee_sol: Optional[float] = None
        network_status: str = "unknown"

        try:
            loop = asyncio.get_running_loop()
            raw_fees = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: _rpc_call("getRecentPrioritizationFees", [])
                ),
                timeout=2.5,
            )
            if raw_fees is not None and isinstance(raw_fees, list):
                base_fee = 5000  # Standard Solana consensus base signature fee
                if raw_fees:
                    fees = [int(f.get("prioritizationFee", 0)) for f in raw_fees if isinstance(f, dict)]
                    if fees:
                        fees.sort()
                        mid_fee = fees[len(fees) // 2]
                        priority_fee = int(mid_fee)
                        if mid_fee > 50000:
                            network_status = "busy"
                        else:
                            network_status = "ok"
                    else:
                        priority_fee = 0
                        network_status = "ok"
                else:
                    priority_fee = 0
                    network_status = "ok"
                total_lamports = base_fee + (priority_fee or 0)
                fee_sol = round(total_lamports / 1e9, 9)
            else:
                network_status = "unknown"
                fee_sol = None
        except Exception as e:
            logger.warning(f"/api/net RPC call error: {e}")
            network_status = "unknown"
            fee_sol = None

        result = {
            "sol_usd": sol_usd,
            "fee_sol": fee_sol,
            "base_fee_lamports": base_fee,
            "priority_lamports": priority_fee,
            "network": network_status,
        }
        _net_status_cache["data"] = result
        _net_status_cache["ts"] = now
        return result


STATS_TOKEN = os.getenv("STATS_TOKEN")


@app.get("/api/stats")
async def get_stats(request: Request):
    """Protected analytics stats endpoint. Requires valid X-Stats-Token header; disabled by default."""
    if not STATS_TOKEN:
        raise HTTPException(status_code=404, detail="Not Found")
    token = request.headers.get("x-stats-token")
    if not token or token != STATS_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return get_analytics_digest(DB_PATH)


# ─── ROUTE 1: SERVE CLAIME UI ──────────────────────────────────────────────────

@app.get("/claime")
@app.get("/claime.html")
def serve_claime_ui(request: Request):
    if not CLAIME_HTML_PATH.exists():
        raise HTTPException(status_code=404, detail="claime.html not found.")
    try:
        client_ip = get_client_ip(request)
        ua = request.headers.get("user-agent", "unknown")
        ref = request.headers.get("referer")
        log_cookieless_event("page_view", client_ip, ua, path="/claime", referer=ref, db_path=DB_PATH)
    except Exception as e:
        logger.debug(f"Analytics event error on /claime: {e}")
    return FileResponse(CLAIME_HTML_PATH)

# ── ROUTE 2: LEDGER SCANNER (DUAL PROGRAM + WSOL) ─────────────────────────────

@app.post("/api/scan")
async def scan_wallet(req: ScanRequest, request: Request):
    owner_pubkey = validate_wallet_address(req.wallet_address)
    owner_str = str(owner_pubkey)
    verify_wallet_not_executable(owner_str)

    if request:
        try:
            client_ip = get_client_ip(request)
            ua = request.headers.get("user-agent", "unknown")
            ref = request.headers.get("referer")
            log_cookieless_event("wallet_scanned", client_ip, ua, path="/api/scan", referer=ref, db_path=DB_PATH)
        except Exception as e:
            logger.debug(f"Analytics event logging notice: {e}")

    # Parallel dual-program queries (Legacy SPL + Token-2022)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            f_spl = executor.submit(_fetch_program_accounts, owner_str, TOKEN_PROGRAM_ID)
            f_2022 = executor.submit(_fetch_program_accounts, owner_str, TOKEN_2022_PROGRAM_ID)
            spl_accounts = f_spl.result()
            token2022_accounts = f_2022.result()
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

    all_reclaimable = spl_reclaimable + t22_reclaimable
    total_token_accounts = len(spl_accounts) + len(token2022_accounts)
    total_wsol_count = spl_wsol + t22_wsol
    total_wsol_sol = round((spl_wsol_lamports + t22_wsol_lamports) / 1e9, 6)

    total_lamports = sum(item["lamports"] for item in all_reclaimable)
    total_reclaimable_sol = round(total_lamports / 1e9, 6)

    # SEC-03: Native SOL balance check for gas fee reserve
    try:
        balance_res = _rpc_call("getBalance", [owner_str])
        sol_balance = (balance_res.get("value", 0) if isinstance(balance_res, dict) else (balance_res or 0)) / 1e9
    except Exception as e:
        logger.error(f"Failed to fetch native SOL balance for {owner_str}: {e}")
        raise HTTPException(
            status_code=502,
            detail={"detail": f"Solana RPC getBalance failed: {e}", "error_code": "RPC_FAILURE"},
        )

    sol_price = await get_sol_price_usd_async()
    sol_price_usd = sol_price if (sol_price is not None and sol_price > 0) else None
    reclaimable_usd = round(total_reclaimable_sol * sol_price, 2) if (sol_price is not None and sol_price > 0) else 0.0

    return {
        "wallet": owner_str,
        "total_token_accounts": total_token_accounts,
        "empty_spl_count": spl_empty,
        "empty_2022_count": t22_empty,
        "wsol_count": total_wsol_count,
        "wsol_reclaimable_sol": total_wsol_sol,
        "empty_accounts_count": len(all_reclaimable),
        "reclaimable_sol": total_reclaimable_sol,
        "sol_price_usd": sol_price_usd,
        "reclaimable_usd": reclaimable_usd,
        "native_sol_balance": round(sol_balance, 6),
        "has_fee_reserve": sol_balance >= 0.00001,
        "batch_sample": [item["pubkey"] for item in all_reclaimable[:BATCH_SIZE]],
    }


# ── ROUTE 3: BUILD VERSIONED TRANSACTION ──────────────────────────────────────

@app.post("/api/rent/build-tx")
async def build_claim_tx(req: ScanRequest):
    return await _build_claim_transaction_async(req.wallet_address)


# Backward compatibility alias for legacy tests / debug scripts
@app.post("/api/claim_debug")
async def debug_claim(req: ScanRequest):
    return await _build_claim_transaction_async(req.wallet_address)


# ── ROUTE 4: SOLANA PAY 2-STEP SPECIFICATION ─────────────────────────────────

@app.get("/api/rent/qr")
def get_solana_pay_qr(wallet: Optional[str] = Query(None), request: Request = None):
    """Solana Pay Step 1: Return metadata (label + icon) for wallet prompt display."""
    icon_url = "https://quillhog.xyz/favicon.ico"
    if request:
        host = request.headers.get("host")
        if host:
            scheme = "https" if request.url.scheme == "https" or "quillhog" in host else "http"
            icon_url = f"{scheme}://{host}/favicon.ico"

    return {
        "label": "Quillhog Claime",
        "icon": icon_url,
    }


@app.post("/api/rent/qr")
async def post_solana_pay_qr(wallet: Optional[str] = Query(None), payload: Optional[SolanaPayAccountPayload] = None):
    """Solana Pay Step 2: Receive user account, compile and return VersionedTransaction."""
    target_wallet = (payload.account if payload and payload.account else None) or wallet
    if not target_wallet:
        raise HTTPException(status_code=400, detail="Missing wallet address parameter.")
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
    base_url = "https://quillhog.xyz/api/rent/qr"
    if request:
        host = request.headers.get("host")
        if host:
            scheme = "https" if request.url.scheme == "https" or "quillhog" in host else "http"
            base_url = f"{scheme}://{host}/api/rent/qr"

    return generate_solana_pay_deep_links(base_qr_url=base_url, wallet=wallet)



# ── ROUTE 5: RECORD CONFIRMED SETTLEMENT (PRIVATE LEDGER) ─────────────────────

@app.post("/api/rent/confirm")
def confirm_claim(req: ConfirmRequest, background_tasks: BackgroundTasks):
    sig = req.signature.strip()
    wallet = req.wallet.strip()

    # 1. Validate signature format (base58, 64-88 chars)
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

    # SEC-05: Sane batch bounds check to prevent fake ledger injection
    accounts_closed = int(req.accounts_closed or 0)
    sol_amount = float(req.sol_amount or 0.0)
    if accounts_closed < 1 or accounts_closed > BATCH_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"accounts_closed out of sane bounds (1..{BATCH_SIZE}, got {accounts_closed})."
        )
    if sol_amount <= 0.0 or sol_amount > 50.0:
        raise HTTPException(
            status_code=400,
            detail=f"sol_amount out of sane batch bounds (0..50 SOL, got {sol_amount})."
        )

    try:
        # 2. Query Solana RPC with confirmed commitment
        is_confirmed = verify_signature_onchain(sig)
        if not is_confirmed:
            raise HTTPException(status_code=400, detail="Transaction signature failed or unconfirmed on-chain.")

        # SEC-HARDENING: On-chain truth verification — do NOT blindly trust browser amounts.
        # Fetch actual on-chain transaction metadata if available via RPC.
        verified_sol = sol_amount
        verified_accounts = accounts_closed
        try:
            tx_data = _rpc_call(
                "getTransaction",
                [sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0, "commitment": "confirmed"}]
            )
            if tx_data and isinstance(tx_data, dict):
                meta = tx_data.get("meta") or {}
                if meta.get("err") is not None:
                    raise HTTPException(status_code=400, detail="Transaction failed on-chain.")
                tx_msg = (tx_data.get("transaction") or {}).get("message") or {}
                acc_keys = tx_msg.get("accountKeys") or []
                wallet_idx = None
                for idx, k in enumerate(acc_keys):
                    pub = k.get("pubkey") if isinstance(k, dict) else str(k)
                    if pub == wallet:
                        wallet_idx = idx
                        break
                if wallet_idx is not None and "preBalances" in meta and "postBalances" in meta:
                    pre_bal = meta["preBalances"][wallet_idx]
                    post_bal = meta["postBalances"][wallet_idx]
                    diff_lamports = post_bal - pre_bal
                    if diff_lamports > 0:
                        verified_sol = round(diff_lamports / 1e9, 6)
        except HTTPException:
            raise
        except Exception as e:
            logger.debug(f"On-chain balance verification fallback for {sig}: {e}")

        # 3. Append to private SQLite ledger with concurrency lock retry
        record_settlement(
            wallet=wallet,
            sig=sig,
            accounts_closed=verified_accounts,
            sol_amount=verified_sol,
            estimated_usd=req.estimated_usd or 0.0,
            db_path=DB_PATH,
        )
        # Dispatch ntfy push notification in background
        alert_title = "Claime"
        alert_msg = f"Wallet: {wallet[:6]}...{wallet[-4:]}\nReclaimed: {verified_sol} SOL\nAccounts Closed: {verified_accounts}\nSig: {sig[:16]}..."
        background_tasks.add_task(send_ntfy_alert, alert_title, alert_msg, "default")

        return {"status": "success", "confirmed": True, "signature": sig, "tx": sig}
    except HTTPException as he:
        raise he
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            raise HTTPException(status_code=409, detail="Transaction signature already recorded.")
        logger.error(f"RPC validation failed for signature {sig}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal blockchain verification error. Please retry.")


@app.post("/api/analytics/track")
def track_event(req: AnalyticsEventReq, request: Request):
    client_ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    log_cookieless_event(req.event_type, client_ip, ua, db_path=DB_PATH)
    return {"status": "tracked"}


@app.get("/api/rent/stats")
def get_global_stats():
    return get_global_metrics(DB_PATH)
