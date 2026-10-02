"""
Riley QA & Red Team: Web Analytics, Prague Slots & Shelf Invariant Test Suite
File: tests/test_analytics_and_shelf.py
"""

import os
import re
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock
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

def test_index_has_no_check_or_wallet_input():
    """Verify index.html has no CHECK button and no wallet address input field."""
    idx_path = resolve_html_file("index.html")
    assert idx_path.exists(), "index.html must exist"
    content = idx_path.read_text(encoding="utf-8")
    
    # Must not contain wallet/address input
    assert not re.search(r'<input[^>]+(wallet|address)', content, re.IGNORECASE), "VETO: index.html has wallet input!"
    # Must not contain CHECK button
    assert not re.search(r'>CHECK<|id=["\']checkBtn["\']|class=["\'][^"\']*btn-check', content, re.IGNORECASE), "VETO: index.html has CHECK button!"


def test_ticker_no_lamports_and_has_clean_fallbacks():
    """Verify ticker does not display 'lamports' and default fallback in DOM is '—'."""
    for filename in ["index.html", "claime.html"]:
        p = resolve_html_file(filename)
        content = p.read_text(encoding="utf-8")
        
        # Word 'lamports' must not be in the file
        assert "lamports" not in content.lower(), f"VETO: {filename} contains the word 'lamports'!"
        
        # DOM elements for ticker must have '—' as initial content
        for fid in ["netSolPrice", "netFeeSol", "netStatus"]:
            m = re.search(rf'id=[\'"]{fid}[\'"][^>]*>([^<]+)<', content)
            assert m is not None, f"{filename} missing ticker element {fid}"
            assert m.group(1).strip() == "—", f"{filename} element {fid} default is not '—'"


def test_live_badge_css_not_turquoise_green():
    """Verify LIVE badge CSS does not use #00F5A0 or turquoise green."""
    for filename in ["index.html", "claime.html"]:
        p = resolve_html_file(filename)
        content = p.read_text(encoding="utf-8")
        assert "#00F5A0" not in content.upper(), f"VETO: {filename} contains turquoise/green #00F5A0!"


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


def test_shelf_cards_and_single_live_badge():
    """Verify shelf has 3 cards and exactly one LIVE badge (Claime)."""
    idx_path = resolve_html_file("index.html")
    content = idx_path.read_text(encoding="utf-8")
    
    # 3 cards
    assert 'class="shelf-card"' in content
    assert content.count('class="shelf-card"') == 3, "VETO: shelf-grid must have exactly 3 cards!"
    
    # Exactly one LIVE in cards
    live_badges = re.findall(r'>LIVE<', content)
    assert len(live_badges) == 1, f"VETO: Expected exactly 1 LIVE badge in shelf, got {len(live_badges)}"
    
    # Claime has live button
    assert 'href="/claime"' in content
    assert 'OPEN CLAIME' in content
    
    # Record has NEXT and /record
    assert '>NEXT<' in content
    assert 'href="/record"' in content
    
    # Till has SOON and /till
    assert '>SOON<' in content
    assert 'href="/till"' in content


def test_record_and_till_pages_and_routes(client):
    """Verify record.html and till.html static files have no input and no t.me CTA."""
    for filename in ["record.html", "till.html"]:
        file_path = resolve_html_file(filename)
        assert file_path.exists(), f"VETO: {filename} missing in web static!"
        content = file_path.read_text(encoding="utf-8")
        
        # No input fields
        assert not re.search(r'<input', content, re.IGNORECASE), f"VETO: {filename} contains input fields!"
        
        # No t.me as CTA
        assert "t.me" not in content, f"VETO: {filename} contains t.me link!"


def test_forbidden_words_across_shelf():
    """Verify 0 forbidden words across all shelf pages."""
    forbidden = ["koinly", "one click", "guaranteed", "blog"]
    for filename in ["index.html", "claime.html", "record.html", "till.html"]:
        p = resolve_html_file(filename)
        content = p.read_text(encoding="utf-8").lower()
        for word in forbidden:
            assert word not in content, f"VETO: {filename} contains forbidden word '{word}'!"


def test_api_net_exact_keys(client):
    """Verify /api/net returns exact unified keys expected by documentation."""
    resp = client.get("/api/net")
    assert resp.status_code == 200
    data = resp.json()
    expected_keys = {"sol_usd", "fee_sol", "base_fee_lamports", "priority_lamports", "network"}
    assert set(data.keys()) == expected_keys, f"VETO: /api/net keys {set(data.keys())} != {expected_keys}"


def test_roxy_cut_shelf_invariants(client):
    """Riley QA & Red Team: Verify all Roxy Cut invariants across / and subpages."""
    base_dir = Path(__file__).resolve().parent.parent

    # 1. / (index.html)
    idx_content = resolve_html_file("index.html").read_text(encoding="utf-8")
    assert "t.me" not in idx_content.lower(), "VETO: index.html has t.me!"
    assert "rail" not in idx_content.lower(), "VETO: index.html has word 'rail'!"
    assert not re.search(r'>CHECK<|id=["\']checkBtn["\']|class=["\'][^"\']*btn-check', idx_content, re.IGNORECASE)
    assert "01 //" not in idx_content and "02 //" not in idx_content and "03 //" not in idx_content, "VETO: index.html has 01-03 statements!"
    assert "shelf-statements" not in idx_content, "VETO: index.html has shelf-statements block!"

    # Record card has 10 USDC
    assert "10 USDC" in idx_content or "10&nbsp;USDC" in idx_content, "VETO: Record card missing 10 USDC!"

    # Exactly one LIVE badge in shelf cards
    live_badges = re.findall(r'>LIVE<', idx_content)
    assert len(live_badges) == 1, f"VETO: expected 1 LIVE badge, got {len(live_badges)}"

    # Spikes floor on / and /claime
    assert "spikes-wrapper" in idx_content, "VETO: index.html missing spikes-wrapper!"
    claime_content = resolve_html_file("claime.html").read_text(encoding="utf-8")
    assert "spikes-wrapper" in claime_content, "VETO: claime.html missing spikes-wrapper!"

    # Construction tape on /record and /till, and no spike as sole floor
    for path, fname, stamp in [("/record", "record.html", "NEXT"), ("/till", "till.html", "SOON")]:
        content = resolve_html_file(fname).read_text(encoding="utf-8")

        # 0 input, 0 download/checkout button
        assert not re.search(r'<input', content, re.IGNORECASE), f"VETO: {fname} contains input!"
        assert not re.search(r'>download<|>checkout<|btn-download|btn-checkout', content, re.IGNORECASE), f"VETO: {fname} contains download/checkout!"

        # Stamp badge
        assert stamp in content, f"VETO: {fname} missing stamp {stamp}!"
        assert "stamp-badge" in content, f"VETO: {fname} missing stamp-badge class!"

        # Construction tape floor
        assert "construction-tape" in content, f"VETO: {fname} missing construction-tape floor!"
        assert "spikes-wrapper" not in content, f"VETO: {fname} must not have spikes as floor!"

    # GitHub href and unified footer on all 4 pages
    for fname in ["index.html", "claime.html", "record.html", "till.html"]:
        content = resolve_html_file(fname).read_text(encoding="utf-8")
        assert "github.com/quillhog0" in content, f"VETO: {fname} missing github.com/quillhog0 link!"
        assert "[ Shelf ]" in content, f"VETO: {fname} missing [ Shelf ] link in footer!"
        assert "[ X ]" in content, f"VETO: {fname} missing [ X ] link in footer!"
        assert "[ GitHub ]" in content, f"VETO: {fname} missing [ GitHub ] link in footer!"
        assert "// NOTICE" in content, f"VETO: {fname} missing // NOTICE!"

        # 0 forbidden words
        forbidden = [
            "one click",
            "guaranteed",
            "risk-free",
            "koinly",
            "harvester",
            "infrastructure compiling",
            "marquee",
        ]
        lower_content = content.lower()
        for fw in forbidden:
            assert fw not in lower_content, f"VETO: {fname} contains forbidden term '{fw}'!"


def test_footer_live_invariants(client):
    """Riley QA: Verify footer-live requirements across all 4 pages."""
    base_dir = Path(__file__).resolve().parent.parent
    pages = ["index.html", "claime.html", "record.html", "till.html"]

    for fname in pages:
        p = resolve_html_file(fname)
        content = p.read_text(encoding="utf-8")

        # 1. 0 instances of nested brackets '[ [' or '] ]'
        assert "[ [" not in content, f"VETO: {fname} contains nested '[ ['"
        assert "] ]" not in content, f"VETO: {fname} contains nested '] ]'"

        # 2. site-foot-links present
        assert 'class="site-foot-links"' in content, f"VETO: {fname} missing site-foot-links class!"
        assert '<nav class="site-foot-links">' in content, f"VETO: {fname} missing <nav class=\"site-foot-links\">!"

        # 3. white-space: nowrap in CSS for footer links
        assert "white-space: nowrap;" in content, f"VETO: {fname} missing white-space: nowrap in CSS!"

        # 4. GitHub + X + Shelf present on all 4 pages
        assert 'href="/"' in content and "[ Shelf ]" in content, f"VETO: {fname} missing Shelf link!"
        assert "https://x.com/quillhog0" in content and "[ X ]" in content, f"VETO: {fname} missing X link!"
        assert "https://github.com/quillhog0" in content and "[ GitHub ]" in content, f"VETO: {fname} missing GitHub link!"

        # 5. 320px smoke: text of link has 'Shelf' and ']' on the same <a> node inside site-foot-links
        nav_match = re.search(r'<nav class="site-foot-links">(.*?)</nav>', content, re.DOTALL)
        assert nav_match is not None, f"VETO: {fname} missing <nav class=\"site-foot-links\">"
        shelf_match = re.search(r'<a\s+href="/"[^>]*>([^<]+)</a>', nav_match.group(1))
        assert shelf_match is not None, f"VETO: {fname} missing Shelf <a> node in foot links"
        shelf_text = shelf_match.group(1).strip()
        assert "Shelf" in shelf_text and "]" in shelf_text and "[" in shelf_text
        assert shelf_text == "[ Shelf ]", f"VETO: {fname} Shelf text is '{shelf_text}', expected '[ Shelf ]'"

        # 6. Ticker defaults before JS must be '—', not hardcoded numbers
        assert '$117' not in content, f"VETO: {fname} has hardcoded $117!"
        assert '$118' not in content, f"VETO: {fname} has hardcoded $118!"
        # In DOM default, netFeeSol must be '—'
        m_fee = re.search(r'id=["\']netFeeSol["\'][^>]*>([^<]+)<', content)
        assert m_fee is not None and m_fee.group(1).strip() == "—", f"VETO: {fname} netFeeSol default is not '—'"
        m_price = re.search(r'id=["\']netSolPrice["\'][^>]*>([^<]+)<', content)
        assert m_price is not None and m_price.group(1).strip() == "—", f"VETO: {fname} netSolPrice default is not '—'"

    # 7. /record has exactly one visible NEXT in artifact stamp (not secondary badge under hog)
    rec_content = resolve_html_file("record.html").read_text(encoding="utf-8")
    next_occurrences = re.findall(r'>NEXT<', rec_content)
    assert len(next_occurrences) == 1, f"VETO: record.html has {len(next_occurrences)} NEXT badges, expected exactly 1!"
    assert '<div class="stamp-badge">NEXT</div>' in rec_content

    # 8. /till has exactly one visible SOON in artifact stamp (not secondary badge under hog)
    till_content = resolve_html_file("till.html").read_text(encoding="utf-8")
    soon_occurrences = re.findall(r'>SOON<', till_content)
    assert len(soon_occurrences) == 1, f"VETO: till.html has {len(soon_occurrences)} SOON badges, expected exactly 1!"
    assert '<div class="stamp-badge">SOON</div>' in till_content



