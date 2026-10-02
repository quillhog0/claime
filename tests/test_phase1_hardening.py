"""
Quillhog - Phase 1 Hardening & Subsystem Verification Test Suite
File: tests/test_phase1_hardening.py

Validates:
1. Fast Base58 validator edge cases & speed.
2. Solana Pay deep link generators & API endpoint.
3. Automated SQLite WAL atomic backup & checksum creation.
4. Privacy & data retention audit logic.
5. Daily X poster content generation.
6. Telegram support diagnostic bot logic.
"""

from __future__ import annotations
import os
from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

from core_verify import (
    is_valid_base58_address_fast,
    generate_solana_pay_deep_links,
)
import sys
_parked_dir = Path(__file__).resolve().parent.parent.parent.parent / "_parked"
if _parked_dir.exists() and str(_parked_dir) not in sys.path:
    sys.path.insert(0, str(_parked_dir))
from rent_service import app
from scripts.backup_wal import perform_atomic_wal_backup, calculate_sha256, rotate_old_backups
from scripts.data_retention_audit import audit_privacy_compliance, prune_stale_analytics
from scripts.daily_x_poster import generate_daily_x_post
from scripts.telegram_support_bot import handle_support_query


client = TestClient(app)


class TestPhase1Hardening:

    def test_fast_base58_validation(self):
        # Valid addresses
        assert is_valid_base58_address_fast("11111111111111111111111111111111") is True
        assert is_valid_base58_address_fast("So11111111111111111111111111111111111111112") is True
        assert is_valid_base58_address_fast("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA") is True

        # Invalid addresses (forbidden chars: 0, O, I, l or special chars)
        assert is_valid_base58_address_fast("01111111111111111111111111111111") is False  # contains '0'
        assert is_valid_base58_address_fast("O11111111111111111111111111111111") is False  # contains 'O'
        assert is_valid_base58_address_fast("I11111111111111111111111111111111") is False  # contains 'I'
        assert is_valid_base58_address_fast("l11111111111111111111111111111111") is False  # contains 'l'
        assert is_valid_base58_address_fast("too_short") is False
        assert is_valid_base58_address_fast("") is False
        assert is_valid_base58_address_fast(12345) is False

    def test_solana_pay_deep_link_generation(self):
        links = generate_solana_pay_deep_links(
            base_qr_url="https://quillhog.xyz/api/rent/qr",
            wallet="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        )
        assert "solana_pay_uri" in links
        assert links["solana_pay_uri"].startswith("solana:https://quillhog.xyz/api/rent/qr?wallet=")
        assert "phantom_universal" in links
        assert "phantom_native" in links
        assert "solflare_universal" in links
        assert "solflare_native" in links

    def test_deep_links_endpoint(self):
        res = client.get("/api/rent/deep-links?wallet=TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        assert res.status_code == 200
        data = res.json()
        assert "solana_pay_uri" in data
        assert "phantom_universal" in data

    def test_atomic_wal_backup_engine(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            backup_dir = Path(tmp_dir) / "backups"
            backup_file = perform_atomic_wal_backup(backup_dir=backup_dir)
            assert backup_file.exists()
            assert backup_file.name.endswith(".db.gz")
            assert backup_file.stat().st_size > 0

            # Verify checksum file
            sha_file = Path(str(backup_file) + ".sha256")
            assert sha_file.exists()
            recorded_hash = sha_file.read_text(encoding="utf-8").split()[0]
            actual_hash = calculate_sha256(backup_file)
            assert recorded_hash == actual_hash

    def test_privacy_and_data_retention_audit(self):
        res = audit_privacy_compliance()
        assert res["status"] == "ok"
        assert res["zero_pii_verified"] is True
        assert res["raw_ip_violations"] == 0

        pruned = prune_stale_analytics(retention_days=30)
        assert isinstance(pruned, int)

    def test_daily_x_poster_generation(self):
        tweet = generate_daily_x_post()
        assert "QUILLHOG DAILY ON-CHAIN RECLAIM REPORT" in tweet
        assert "Total Rent Harvested" in tweet
        assert "https://quillhog.xyz" in tweet

    def test_telegram_support_bot_handler(self):
        # 1. Fallback / help prompt
        help_msg = handle_support_query("hello")
        assert "Ahoj!" in help_msg or "diagnostický asistent" in help_msg

        # 2. Wallet address detection
        wallet_msg = handle_support_query("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        assert "Adresa peněženky detekována" in wallet_msg
