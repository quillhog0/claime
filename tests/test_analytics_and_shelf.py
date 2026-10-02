"""
Riley QA & Red Team: Web Analytics, Prague Slots & Shelf Invariant Test Suite
File: tests/test_analytics_and_shelf.py
"""

import os
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient

from rent_service import app
from observability import (
    init_ledger_db,
    log_cookieless_event,
    get_analytics_digest,
    format_digest_message,
    get_next_prague_slot,
    get_seconds_to_next_prague_slot,
)


@pytest.fixture
def client():
    return TestClient(app)


def resolve_html_file(filename: str) -> Path:
    if filename == "claime.html":
        return Path(__file__).resolve().parent.parent / "claime.html"
    web_p = Path(__file__).resolve().parent.parent.parent.parent / "web" / filename
    if web_p.exists():
        return web_p
    return Path(__file__).resolve().parent.parent / filename







def test_claime_has_no_transparency_panels():
    """Verify claime.html removed the 3 technical transparency panels."""
    p = resolve_html_file("claime.html")
    content = p.read_text(encoding="utf-8")
    assert "transparency-grid" not in content, "VETO: claime.html still contains transparency-grid!"
    assert "transparency-panel" not in content, "VETO: claime.html still contains transparency-panel!"
    assert "LEGAL HYGIENE & ON-CHAIN INVARIANTS" not in content, "VETO: claime.html has internal label!"


def test_analytics_event_writing_tmp_db():
    """Verify that page views and scan events write path, referer_host, and IP hash to SQLite."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_db = Path(tmpdir) / "test_analytics.db"
        init_ledger_db(tmp_db)
        
        with patch.dict(os.environ, {"ANALYTICS_SALT": "test_salt_v1"}):
            # Log page view on /
            log_cookieless_event(
                event_type="page_view",
                client_ip="192.168.1.100",
                user_agent="Mozilla/5.0 Test",
                path="/?foo=bar",
                referer="https://x.com/quillhog0?s=20",
                db_path=tmp_db,
            )
            
            # Log page view on /claime
            log_cookieless_event(
                event_type="page_view",
                client_ip="192.168.1.101",
                user_agent="Mozilla/5.0 Test",
                path="/claime",
                referer="https://t.me/quillhog_bot",
                db_path=tmp_db,
            )
            
            # Log scan event
            log_cookieless_event(
                event_type="wallet_scanned",
                client_ip="192.168.1.102",
                user_agent="Mozilla/5.0 Test",
                path="/api/scan",
                referer=None,
                db_path=tmp_db,
            )
        
        conn = sqlite3.connect(tmp_db)
        try:
            cursor = conn.cursor()
            rows = cursor.execute("SELECT event_type, path, referer_host, client_ip_hash FROM analytics_events ORDER BY id ASC").fetchall()
            assert len(rows) == 3
            
            # Row 1: query string stripped, referer host extracted
            assert rows[0][0] == "page_view"
            assert rows[0][1] == "/"
            assert rows[0][2] == "x.com"
            assert len(rows[0][3]) == 16
            
            # Row 2: /claime with t.me
            assert rows[1][0] == "page_view"
            assert rows[1][1] == "/claime"
            assert rows[1][2] == "t.me"
            
            # Row 3: direct referer
            assert rows[2][0] == "wallet_scanned"
            assert rows[2][1] == "/api/scan"
            assert rows[2][2] is None
        finally:
            conn.close()
            
        digest = get_analytics_digest(tmp_db)
        assert digest["home_today"] == 1
        assert digest["claime_today"] == 1
        assert digest["scan_today"] == 1
        assert digest["distinct_7d"] == 3


def test_api_net_rpc_fail_returns_null_fee_sol(client):
    """When RPC fails, fee_sol must be null, NOT 0.0 or fabricated number, and network unknown."""
    with patch("rent_service._rpc_call", side_effect=Exception("RPC timeout failure")):
        # Invalidate cache
        import rent_service
        rent_service._net_status_cache["data"] = None
        rent_service._net_status_cache["ts"] = 0.0
        
        resp = client.get("/api/net")
        assert resp.status_code == 200
        data = resp.json()
        assert data["fee_sol"] is None, "VETO: fee_sol must be null on RPC failure!"
        assert data["network"] == "unknown", "VETO: network must be unknown on RPC failure!"


def test_no_public_stats_without_token(client):
    """Verify /api/stats cannot be accessed publicly without token."""
    # 1. Unset STATS_TOKEN -> 404
    with patch.dict(os.environ, {}, clear=True):
        import rent_service
        rent_service.STATS_TOKEN = None
        resp = client.get("/api/stats")
        assert resp.status_code == 404
        
    # 2. Set STATS_TOKEN but request without header -> 401
    import rent_service
    rent_service.STATS_TOKEN = "secret_l8_token_123"
    resp = client.get("/api/stats")
    assert resp.status_code == 401
    
    # 3. Wrong token -> 401
    resp = client.get("/api/stats", headers={"X-Stats-Token": "wrong_token"})
    assert resp.status_code == 401
    
    # 4. Valid token -> 200
    resp = client.get("/api/stats", headers={"X-Stats-Token": "secret_l8_token_123"})
    assert resp.status_code == 200
    data = resp.json()
    assert "home_today" in data
    assert "claime_today" in data
    
    # Reset
    rent_service.STATS_TOKEN = None


def test_ntfy_prague_slot_scheduling():
    """Verify ntfy next-run calculation aligns with slots 00, 06, 12, 18 in Europe/Prague."""
    tz = ZoneInfo("Europe/Prague")
    test_cases = [
        (datetime(2026, 9, 30, 0, 15, tzinfo=tz), datetime(2026, 9, 30, 6, 0, tzinfo=tz)),
        (datetime(2026, 9, 30, 5, 59, tzinfo=tz), datetime(2026, 9, 30, 6, 0, tzinfo=tz)),
        (datetime(2026, 9, 30, 6, 1, tzinfo=tz), datetime(2026, 9, 30, 12, 0, tzinfo=tz)),
        (datetime(2026, 9, 30, 11, 59, tzinfo=tz), datetime(2026, 9, 30, 12, 0, tzinfo=tz)),
        (datetime(2026, 9, 30, 12, 1, tzinfo=tz), datetime(2026, 9, 30, 18, 0, tzinfo=tz)),
        (datetime(2026, 9, 30, 17, 59, tzinfo=tz), datetime(2026, 9, 30, 18, 0, tzinfo=tz)),
        (datetime(2026, 9, 30, 18, 1, tzinfo=tz), datetime(2026, 10, 1, 0, 0, tzinfo=tz)),
        (datetime(2026, 9, 30, 23, 59, tzinfo=tz), datetime(2026, 10, 1, 0, 0, tzinfo=tz)),
    ]
    for current, expected_next in test_cases:
        actual_next = get_next_prague_slot(current)
        assert actual_next == expected_next, f"At {current}, expected {expected_next} but got {actual_next}"
        wait_sec = get_seconds_to_next_prague_slot(current)
        assert wait_sec > 0
        assert round(wait_sec) == round((expected_next - current).total_seconds())


def test_digest_message_format():
    """Verify digest message has no emojis and no word 'Harvester'."""
    analytics = {
        "home_today": 12,
        "claime_today": 4,
        "scan_today": 3,
        "now_active": 1,
        "distinct_7d": 28,
        "top_refs": [("t.me", 5), ("x.com", 3), ("direct", 20)],
        "total_claims": 5,
        "total_sol_reclaimed": 0.042,
    }
    msg = format_digest_message(
        net_status="ok",
        sol_price=119.0,
        fee_sol=0.000015,
        analytics=analytics,
    )
    assert "Harvester" not in msg, "VETO: digest contains the word 'Harvester'!"
    assert "🟢" not in msg and "🔴" not in msg and "🟡" not in msg, "VETO: digest contains semaphore emoji!"
    assert "Quillhog" in msg
    assert "net: ok | SOL $119 | fee 0.000015" in msg
    assert "today: / 12 | /claime 4 | scan 3 | now 1" in msg
    assert "7d distinct: 28" in msg
    assert "top ref: t.me 5, x.com 3, direct 20" in msg
    assert "claims ledger: 5 | SOL reclaimed: 0.042" in msg








def test_api_net_exact_keys(client):
    """Verify /api/net returns exact unified keys expected by documentation."""
    resp = client.get("/api/net")
    assert resp.status_code == 200
    data = resp.json()
    expected_keys = {"sol_usd", "fee_sol", "base_fee_lamports", "priority_lamports", "network"}
    assert set(data.keys()) == expected_keys, f"VETO: /api/net keys {set(data.keys())} != {expected_keys}"







