"""
Quillhog Observability & Telemetry Engine (MOD-07 Observability Module)
File: observability.py

Decoupled telemetry, cookieless analytics, private SQLite WAL ledger,
ntfy push notifications, and single-flight async price caching.
"""

from __future__ import annotations
import asyncio
import functools
import hashlib
import logging
import os
from pathlib import Path
import random
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import httpx

logger = logging.getLogger("rent_service.observability")

# Environment & Storage Defaults
DEFAULT_DB_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("RECLAIM_DB_PATH", str(DEFAULT_DB_DIR / "reclaim_vault.db")))
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "").strip()
ANALYTICS_SALT = os.getenv("ANALYTICS_SALT")

# Price Cache & Single-Flight Async Lock (with error backoff)
_price_cache: Dict[str, Any] = {"price": None, "ts": 0.0, "retry_after": 0.0}
_price_lock = asyncio.Lock()


# ── CONCURRENCY & DB LOCK RETRY SHIELD ─────────────────────────────────────────

def retry_on_lock(max_retries: int = 5, delay: float = 0.1):
    """Decorator to retry SQLite operations on database locked/busy with exponential backoff and jitter."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(1, max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except sqlite3.OperationalError as e:
                    msg = str(e).lower()
                    if ("locked" not in msg and "busy" not in msg) or attempt == max_retries:
                        raise
                    sleep_time = min(delay * (2 ** (attempt - 1)), 2.0) + random.uniform(0, 0.05)
                    logger.warning(
                        "Database locked in %s. Retry %d/%d in %.3fs.",
                        func.__name__, attempt, max_retries - 1, sleep_time,
                    )
                    time.sleep(sleep_time)
            raise RuntimeError("Database lock retries exceeded")
        return wrapper
    return decorator


# ── DATABASE SCHEMA & INITIALIZATION ──────────────────────────────────────────

@retry_on_lock(max_retries=5, delay=0.1)
def init_ledger_db(db_path: Path = DB_PATH):
    """Initialize private SQLite metrics ledger and cookieless analytics tables in WAL mode."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reclaimed_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_address TEXT NOT NULL,
                tx_signature TEXT UNIQUE NOT NULL,
                accounts_closed INTEGER NOT NULL,
                sol_amount REAL NOT NULL,
                estimated_usd REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analytics_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                client_ip_hash TEXT NOT NULL,
                path TEXT,
                referer_host TEXT,
                user_agent TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # Safe migration: add columns to existing table without dropping
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(analytics_events);")
        existing_cols = {row[1] for row in cursor.fetchall()}
        if "path" not in existing_cols:
            conn.execute("ALTER TABLE analytics_events ADD COLUMN path TEXT;")
        if "referer_host" not in existing_cols:
            conn.execute("ALTER TABLE analytics_events ADD COLUMN referer_host TEXT;")
        conn.commit()
    finally:
        conn.close()


@retry_on_lock(max_retries=5, delay=0.1)
def record_settlement(
    wallet: str,
    sig: str,
    accounts_closed: int,
    sol_amount: float,
    estimated_usd: float,
    db_path: Path = DB_PATH,
):
    """Record verified transaction in private ledger with SQLite write lock retry protection."""
    db_path = Path(db_path)
    init_ledger_db(db_path)
    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        conn.execute(
            """
            INSERT INTO reclaimed_ledger (wallet_address, tx_signature, accounts_closed, sol_amount, estimated_usd)
            VALUES (?, ?, ?, ?, ?)
            """,
            (wallet, sig, accounts_closed, sol_amount, estimated_usd or 0.0),
        )
        conn.commit()
    finally:
        conn.close()


def _extract_referer_host(referer: Optional[str]) -> Optional[str]:
    """Extract host only from referer string, stripping path and query string."""
    if not referer:
        return None
    ref_str = referer.strip()
    if not ref_str:
        return None
    if "://" not in ref_str and not ref_str.startswith("//"):
        ref_str = "//" + ref_str
    try:
        parsed = urlparse(ref_str)
        host = parsed.hostname or parsed.netloc
        if host:
            return host.lower().split(":")[0]
    except Exception:
        pass
    return None


@retry_on_lock(max_retries=5, delay=0.1)
def log_cookieless_event(
    event_type: str,
    client_ip: str,
    user_agent: str,
    path: Optional[str] = None,
    referer: Optional[str] = None,
    db_path: Path = DB_PATH,
    salt: Optional[str] = None,
):
    """Record cookieless, salted hashed analytics events preserving absolute user privacy (0 PII)."""
    effective_salt = salt if salt is not None else (os.getenv("ANALYTICS_SALT") or ANALYTICS_SALT)
    if not effective_salt:
        return
    db_path = Path(db_path)
    init_ledger_db(db_path)
    salted_value = f"{effective_salt}:{client_ip}"
    ip_hash = hashlib.sha256(salted_value.encode("utf-8")).hexdigest()[:16]
    clean_path = path.split("?")[0].strip() if path else None
    ref_host = _extract_referer_host(referer)
    ua_trunc = (user_agent or "")[:255]

    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        conn.execute(
            """
            INSERT INTO analytics_events (event_type, client_ip_hash, path, referer_host, user_agent)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event_type, ip_hash, clean_path, ref_host, ua_trunc),
        )
        conn.commit()
    finally:
        conn.close()


def get_global_metrics(db_path: Path = DB_PATH) -> Dict[str, Any]:
    """Fetch aggregated public metrics from private ledger safely."""
    db_path = Path(db_path)
    init_ledger_db(db_path)
    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*), COALESCE(SUM(sol_amount), 0.0), COALESCE(SUM(accounts_closed), 0) FROM reclaimed_ledger")
        row = cursor.fetchone()
        total_claims = row[0] if row else 0
        total_sol = round(row[1] if row else 0.0, 4)
        total_accounts = row[2] if row else 0
    finally:
        conn.close()
    return {
        "total_claims": total_claims,
        "total_sol_reclaimed": total_sol,
        "total_accounts_closed": total_accounts,
    }


# ── NOTIFICATIONS & PUSH ENGINE (ASYNC HTTPX) ────────────────────────────────

async def send_ntfy_alert(title: str, message: str, priority: str = "default"):
    """Dispatch real-time push notifications to ntfy.sh topic asynchronously with timeout protection."""
    if not NTFY_TOPIC:
        return
    url = f"https://ntfy.sh/{NTFY_TOPIC}"
    try:
        async with httpx.AsyncClient(timeout=5.0) as http_client:
            await http_client.post(
                url,
                content=message.encode("utf-8"),
                headers={
                    "Title": title,
                    "Priority": priority,
                    "Tags": "moneybag,robot",
                },
            )
    except Exception as e:
        logger.error(f"Failed to send ntfy alert: {e}")


# ── SINGLE-FLIGHT ASYNC PRICE FEED ───────────────────────────────────────────

async def get_sol_price_usd_async() -> Optional[float]:
    """
    Fetch live SOL/USD price asynchronously with 5-minute cache and Single-Flight async lock.
    Includes failure backoff protection to avoid hammering upstream on errors.
    """
    now = time.time()
    if now - _price_cache["ts"] < 300 and _price_cache["price"] is not None:
        return _price_cache["price"]
    if now < _price_cache.get("retry_after", 0.0):
        return _price_cache["price"]

    # Single-Flight lock: only one coroutine fetches fresh price from upstream
    async with _price_lock:
        # Re-check timestamp in case another coroutine already updated it while waiting
        if now - _price_cache["ts"] < 300 and _price_cache["price"] is not None:
            return _price_cache["price"]
        if now < _price_cache.get("retry_after", 0.0):
            return _price_cache["price"]

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get("https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd")
                if resp.status_code == 200:
                    price = resp.json().get("solana", {}).get("usd")
                    if price:
                        _price_cache["price"] = float(price)
                        _price_cache["ts"] = now
                        _price_cache["retry_after"] = 0.0
                        return float(price)
                _price_cache["retry_after"] = now + 30.0
        except Exception as e:
            logger.debug(f"Async price fetch fallback triggered: {e}")
            _price_cache["retry_after"] = now + 30.0

    return _price_cache["price"]


def get_sol_price_usd() -> Optional[float]:
    """Synchronous fallback reading directly from in-memory cache."""
    return _price_cache["price"]


# ── BACKGROUND HEALTH HEARTBEAT LOOP & PRAGUE SLOTS ──────────────────────────

def get_next_prague_slot(from_dt: Optional[datetime] = None) -> datetime:
    """Calculate the exact next target slot among [00:00, 06:00, 12:00, 18:00] in Europe/Prague timezone."""
    tz = ZoneInfo("Europe/Prague")
    now = from_dt if from_dt is not None else datetime.now(tz)
    if now.tzinfo is None:
        now = now.replace(tzinfo=tz)
    else:
        now = now.astimezone(tz)

    slots = [0, 6, 12, 18]
    candidates = [now.replace(hour=h, minute=0, second=0, microsecond=0) for h in slots]
    future = [c for c in candidates if c > now]
    if future:
        return min(future)
    tomorrow = now + timedelta(days=1)
    return tomorrow.replace(hour=0, minute=0, second=0, microsecond=0)


def get_seconds_to_next_prague_slot(from_dt: Optional[datetime] = None) -> float:
    """Return seconds remaining until the next Prague slot (00, 06, 12, 18)."""
    tz = ZoneInfo("Europe/Prague")
    now = from_dt if from_dt is not None else datetime.now(tz)
    if now.tzinfo is None:
        now = now.replace(tzinfo=tz)
    else:
        now = now.astimezone(tz)
    nxt = get_next_prague_slot(now)
    diff = (nxt - now).total_seconds()
    return max(diff, 1.0)


def get_analytics_digest(db_path: Path = DB_PATH) -> Dict[str, Any]:
    """Calculate cookieless analytics summary for periodic ntfy digest."""
    db_path = Path(db_path)
    init_ledger_db(db_path)
    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        cursor = conn.cursor()
        # Today counts (since midnight UTC / start of day)
        cursor.execute("""
            SELECT 
                COALESCE(SUM(CASE WHEN path = '/' THEN 1 ELSE 0 END), 0) as home_count,
                COALESCE(SUM(CASE WHEN path LIKE '/claime%' THEN 1 ELSE 0 END), 0) as claime_count,
                COALESCE(SUM(CASE WHEN event_type = 'wallet_scanned' OR path = '/api/scan' THEN 1 ELSE 0 END), 0) as scan_count
            FROM analytics_events
            WHERE created_at >= datetime('now', 'start of day');
        """)
        row = cursor.fetchone()
        home_today = row[0] if row else 0
        claime_today = row[1] if row else 0
        scan_today = row[2] if row else 0

        # Recent active distinct visitors in last 15 min
        cursor.execute("""
            SELECT COUNT(DISTINCT client_ip_hash)
            FROM analytics_events
            WHERE created_at >= datetime('now', '-15 minutes');
        """)
        row = cursor.fetchone()
        now_active = row[0] if row else 0

        # 7-day distinct visitors
        cursor.execute("""
            SELECT COUNT(DISTINCT client_ip_hash)
            FROM analytics_events
            WHERE created_at >= datetime('now', '-7 days');
        """)
        row = cursor.fetchone()
        distinct_7d = row[0] if row else 0

        # Top referers (last 7 days, up to 3)
        cursor.execute("""
            SELECT COALESCE(NULLIF(referer_host, ''), 'direct') as ref, COUNT(*) as c
            FROM analytics_events
            WHERE created_at >= datetime('now', '-7 days')
            GROUP BY ref
            ORDER BY c DESC
            LIMIT 3;
        """)
        top_refs = [(r[0], r[1]) for r in cursor.fetchall()]
        if not top_refs:
            top_refs = [("direct", 0)]
    finally:
        conn.close()

    global_metrics = get_global_metrics(db_path)
    return {
        "home_today": home_today,
        "claime_today": claime_today,
        "scan_today": scan_today,
        "now_active": now_active,
        "distinct_7d": distinct_7d,
        "top_refs": top_refs,
        "total_claims": global_metrics["total_claims"],
        "total_sol_reclaimed": global_metrics["total_sol_reclaimed"],
    }


def format_digest_message(
    net_status: str,
    sol_price: Optional[float],
    fee_sol: Optional[float],
    analytics: Dict[str, Any],
) -> str:
    """Format clean ASCII telemetry digest matching Nina/Riley specification."""
    price_str = f"${round(sol_price)}" if sol_price is not None else "$—"
    fee_str = f"{fee_sol:.6f}".rstrip("0") if fee_sol is not None else "—"
    if fee_str.endswith("."):
        fee_str += "0"

    ref_parts = [f"{ref} {count}" for ref, count in analytics.get("top_refs", [])]
    top_ref_str = ", ".join(ref_parts) if ref_parts else "direct 0"

    claims_num = analytics.get("total_claims", 0)
    sol_rec = analytics.get("total_sol_reclaimed", 0.0)

    return (
        f"Quillhog\n"
        f"net: {net_status} | SOL {price_str} | fee {fee_str}\n"
        f"today: / {analytics.get('home_today', 0)} | /claime {analytics.get('claime_today', 0)} | scan {analytics.get('scan_today', 0)} | now {analytics.get('now_active', 0)}\n"
        f"7d distinct: {analytics.get('distinct_7d', 0)}\n"
        f"top ref: {top_ref_str}\n"
        f"claims ledger: {claims_num} | SOL reclaimed: {sol_rec:.3f}"
    )


async def system_heartbeat_loop(db_path: Path = DB_PATH, net_status_getter=None):
    """Background heartbeat reporting cluster & analytics metrics at 00:00, 06:00, 12:00, 18:00 Europe/Prague."""
    while True:
        try:
            wait_sec = get_seconds_to_next_prague_slot()
            logger.info("Heartbeat waiting %.1f seconds until next Europe/Prague slot", wait_sec)
            await asyncio.sleep(wait_sec)

            sol_price = await get_sol_price_usd_async()
            net_status = "ok"
            fee_sol = 0.000015
            if net_status_getter:
                try:
                    net_info = await net_status_getter()
                    if isinstance(net_info, dict):
                        net_status = net_info.get("network", "unknown")
                        if net_info.get("sol_usd") is not None:
                            sol_price = net_info.get("sol_usd")
                        if net_info.get("fee_sol") is not None:
                            fee_sol = net_info.get("fee_sol")
                except Exception as e:
                    logger.debug("Failed to fetch net status in heartbeat: %s", e)

            analytics = get_analytics_digest(db_path)
            digest_msg = format_digest_message(net_status, sol_price, fee_sol, analytics)
            await send_ntfy_alert("Quillhog", digest_msg, priority="default")
        except asyncio.CancelledError:
            break
        except Exception as ex:
            logger.error("Heartbeat loop error: %s", ex)
            await asyncio.sleep(60)
