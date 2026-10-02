import os
import sqlite3
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

import rent_service
from rent_service import (
    app,
    init_ledger_db,
    LAMPORTS_PER_RENT,
    TOKEN_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    WSOL_MINT,
    create_close_account_instruction,
)
from solders.pubkey import Pubkey
from solders.signature import Signature

TEST_WALLET = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"

client = TestClient(app)


class TestRentService(unittest.TestCase):
    def setUp(self):
        # Create an isolated temporary database for test runs
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.temp_db_path = Path(self.temp_db.name)
        rent_service.ip_request_counts.clear()
        init_ledger_db(self.temp_db_path)
        self.db_patcher = patch.object(rent_service, "DB_PATH", self.temp_db_path)
        self.db_patcher.start()

    def tearDown(self):
        self.db_patcher.stop()
        if self.temp_db_path.exists():
            try:
                os.remove(self.temp_db_path)
            except Exception:
                pass


    def test_health_endpoints(self):
        for path in ["/api/health", "/health"]:
            resp = client.get(path)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "healthy")
            self.assertEqual(data["service"], "quillhog-rent")

    def test_scan_invalid_address(self):
        response = client.post("/api/scan", json={"wallet_address": "invalid_addr_123"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid Solana address format", response.json()["detail"])

    @patch("rent_service._rpc_call")
    def test_scan_dual_program_and_wsol(self, mock_rpc):
        def rpc_side_effect(method, params):
            if method == "getTokenAccountsByOwner":
                program_filter = params[1]["programId"]
                if program_filter == str(TOKEN_PROGRAM_ID):
                    return {
                        "value": [
                            # Empty SPL account
                            {
                                "pubkey": str(Pubkey.from_bytes(bytes([1] * 32))),
                                "account": {
                                    "lamports": 2039280,
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "mint": "11111111111111111111111111111111",
                                                "tokenAmount": {"amount": "0"},
                                            }
                                        }
                                    },
                                },
                            },
                            # Non-empty regular token account (ignored)
                            {
                                "pubkey": str(Pubkey.from_bytes(bytes([2] * 32))),
                                "account": {
                                    "lamports": 2039280,
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "mint": "11111111111111111111111111111111",
                                                "tokenAmount": {"amount": "5000"},
                                            }
                                        }
                                    },
                                },
                            },
                            # WSOL account with wrapped balance (MUST BE INCLUDED)
                            {
                                "pubkey": str(Pubkey.from_bytes(bytes([3] * 32))),
                                "account": {
                                    "lamports": 50000000,  # 0.05 SOL total
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "mint": WSOL_MINT,
                                                "tokenAmount": {"amount": "47960720"},
                                            }
                                        }
                                    },
                                },
                            },
                        ]
                    }
                elif program_filter == str(TOKEN_2022_PROGRAM_ID):
                    return {
                        "value": [
                            # Empty Token-2022 account
                            {
                                "pubkey": str(Pubkey.from_bytes(bytes([4] * 32))),
                                "account": {
                                    "lamports": 2039280,
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "mint": "11111111111111111111111111111111",
                                                "tokenAmount": {"amount": "0"},
                                            }
                                        }
                                    },
                                },
                            }
                        ]
                    }
            return None

        mock_rpc.side_effect = rpc_side_effect
        addr = TEST_WALLET
        response = client.post("/api/scan", json={"wallet_address": addr})
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["total_token_accounts"], 4)
        self.assertEqual(data["empty_spl_count"], 1)
        self.assertEqual(data["empty_2022_count"], 1)
        self.assertEqual(data["wsol_count"], 1)
        self.assertEqual(data["wsol_reclaimable_sol"], 0.05)
        self.assertEqual(data["empty_accounts_count"], 3)  # 1 SPL + 1 T22 + 1 WSOL

        expected_sol = round((2039280 + 2039280 + 50000000) / 1e9, 6)
        self.assertEqual(data["reclaimable_sol"], expected_sol)
        self.assertGreater(data["reclaimable_usd"], 0)

    @patch("rent_service._rpc_call")
    def test_debug_claim_no_reclaimable_accounts(self, mock_rpc):
        mock_rpc.return_value = {"value": []}
        addr = TEST_WALLET
        response = client.post("/api/claim_debug", json={"wallet_address": addr})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "empty")

    @patch("rent_service._rpc_call")
    def test_build_tx_endpoint_mixed_spl_token2022_mtu_safe(self, mock_rpc):
        def rpc_side_effect(method, params):
            if method == "getTokenAccountsByOwner":
                program_filter = params[1]["programId"]
                if program_filter == str(TOKEN_PROGRAM_ID):
                    return {
                        "value": [
                            {
                                "pubkey": str(Pubkey.from_bytes(bytes([i + 1] * 32))),
                                "account": {
                                    "lamports": 2039280,
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "mint": "11111111111111111111111111111111",
                                                "tokenAmount": {"amount": "0"},
                                            }
                                        }
                                    },
                                },
                            }
                            for i in range(8)
                        ]
                    }
                elif program_filter == str(TOKEN_2022_PROGRAM_ID):
                    return {
                        "value": [
                            {
                                "pubkey": str(Pubkey.from_bytes(bytes([i + 10] * 32))),
                                "account": {
                                    "lamports": 2039280,
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "mint": "11111111111111111111111111111111",
                                                "tokenAmount": {"amount": "0"},
                                            }
                                        }
                                    },
                                },
                            }
                            for i in range(7)
                        ]
                    }
            elif method == "getLatestBlockhash":
                return {
                    "value": {
                        "blockhash": "11111111111111111111111111111111"
                    }
                }
            return None

        mock_rpc.side_effect = rpc_side_effect
        addr = TEST_WALLET
        response = client.post("/api/rent/build-tx", json={"wallet_address": addr})
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["status"], "ready")
        self.assertEqual(data["accounts_closed_in_batch"], 15)  # 8 SPL + 7 Token-2022
        self.assertEqual(data["total_empty_found"], 15)
        self.assertTrue(data["mtu_safe"])
        self.assertLessEqual(data["tx_bytes_length"], 1232)
        self.assertIn("transaction_base64", data)
        self.assertIn("solscan_sample_url", data)

    def test_create_close_account_instruction_program_ids(self):
        acc = Pubkey.from_string("11111111111111111111111111111111")
        dest = Pubkey.from_string("11111111111111111111111111111111")
        owner = Pubkey.from_string("11111111111111111111111111111111")

        ix_spl = create_close_account_instruction(acc, dest, owner, TOKEN_PROGRAM_ID)
        self.assertEqual(ix_spl.program_id, TOKEN_PROGRAM_ID)
        self.assertEqual(ix_spl.data, bytes([9]))

        ix_t22 = create_close_account_instruction(acc, dest, owner, TOKEN_2022_PROGRAM_ID)
        self.assertEqual(ix_t22.program_id, TOKEN_2022_PROGRAM_ID)
        self.assertEqual(ix_t22.data, bytes([9]))

    @patch("rent_service.verify_signature_onchain")
    def test_confirm_endpoint_success_and_duplicate_prevention(self, mock_verify):
        mock_verify.return_value = True
        dummy_sig = str(Signature.from_bytes(bytes([5] * 64)))
        wallet = "11111111111111111111111111111111"

        payload = {
            "wallet": wallet,
            "signature": dummy_sig,
            "accounts_closed": 14,
            "sol_amount": 0.02855,
            "estimated_usd": 4.28,
        }

        # First confirmation -> 200 OK
        resp1 = client.post("/api/rent/confirm", json=payload)
        self.assertEqual(resp1.status_code, 200)
        self.assertIn(resp1.json().get("status"), ["success", "recorded"])
        self.assertEqual(resp1.json()["tx"], dummy_sig)

        # Duplicate confirmation with same signature -> 409 Conflict
        resp2 = client.post("/api/rent/confirm", json=payload)
        self.assertEqual(resp2.status_code, 409)
        self.assertIn("already recorded", resp2.json()["detail"].lower())

    @patch("rent_service.verify_signature_onchain")
    def test_confirm_endpoint_failed_onchain(self, mock_verify):
        mock_verify.return_value = False
        dummy_sig = str(Signature.from_bytes(bytes([7] * 64)))
        wallet = "11111111111111111111111111111111"

        payload = {
            "wallet": wallet,
            "signature": dummy_sig,
            "accounts_closed": 5,
            "sol_amount": 0.01,
            "estimated_usd": 1.5,
        }

        resp = client.post("/api/rent/confirm", json=payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("failed or unconfirmed", resp.json()["detail"].lower())

    def test_confirm_endpoint_invalid_signature_format(self):
        payload = {
            "wallet": "11111111111111111111111111111111",
            "signature": "too_short_sig",
            "accounts_closed": 1,
            "sol_amount": 0.002,
        }
        resp = client.post("/api/rent/confirm", json=payload)
        self.assertEqual(resp.status_code, 400)

    @patch("rent_service._rpc_call")
    def test_solana_pay_qr_endpoints(self, mock_rpc):
        def rpc_side_effect(method, params):
            if method == "getTokenAccountsByOwner":
                return {
                    "value": [
                        {
                            "pubkey": str(Pubkey.from_bytes(bytes([1] * 32))),
                            "account": {
                                "lamports": 2039280,
                                "data": {
                                    "parsed": {
                                        "info": {
                                            "mint": "11111111111111111111111111111111",
                                            "tokenAmount": {"amount": "0"},
                                        }
                                    }
                                },
                            },
                        }
                    ]
                }
            elif method == "getLatestBlockhash":
                return {"value": {"blockhash": "11111111111111111111111111111111"}}
            return None

        mock_rpc.side_effect = rpc_side_effect

        # 1. GET (Step 1): standard 2-step Solana Pay label/icon metadata only
        resp_meta = client.get("/api/rent/qr")
        self.assertEqual(resp_meta.status_code, 200)
        self.assertEqual(resp_meta.json()["label"], "Quillhog Claime")
        self.assertIn("favicon.ico", resp_meta.json()["icon"])
        self.assertNotIn("transaction", resp_meta.json())

        # 2. POST (Step 2): with account body -> transaction specification
        wallet = TEST_WALLET
        resp_post = client.post("/api/rent/qr", json={"account": wallet})
        self.assertEqual(resp_post.status_code, 200)
        self.assertIn("transaction", resp_post.json())
        self.assertIn("Close empty token accounts", resp_post.json()["message"])

    @patch("rent_service._rpc_call")
    def test_token_2022_extensions_filtering(self, mock_rpc):
        wallet_str = TEST_WALLET
        foreign_authority = str(Pubkey.from_bytes(bytes([9] * 32)))

        def rpc_side_effect(method, params):
            if method == "getTokenAccountsByOwner":
                program_filter = params[1]["programId"]
                if program_filter == str(TOKEN_PROGRAM_ID):
                    return {"value": []}
                elif program_filter == str(TOKEN_2022_PROGRAM_ID):
                    return {
                        "value": [
                            # 1. Valid Token-2022 account (owner matches closeAuthority or none)
                            {
                                "pubkey": str(Pubkey.from_bytes(bytes([10] * 32))),
                                "account": {
                                    "lamports": 2039280,
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "mint": "11111111111111111111111111111111",
                                                "tokenAmount": {"amount": "0"},
                                                "closeAuthority": wallet_str,
                                            }
                                        }
                                    },
                                },
                            },
                            # 2. Invalid Token-2022: foreign closeAuthority (MUST BE SKIPPED)
                            {
                                "pubkey": str(Pubkey.from_bytes(bytes([11] * 32))),
                                "account": {
                                    "lamports": 2039280,
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "mint": "11111111111111111111111111111111",
                                                "tokenAmount": {"amount": "0"},
                                                "closeAuthority": foreign_authority,
                                            }
                                        }
                                    },
                                },
                            },
                            # 3. Invalid Token-2022: transferFeeAmount withheldAmount > 0 (MUST BE SKIPPED)
                            {
                                "pubkey": str(Pubkey.from_bytes(bytes([12] * 32))),
                                "account": {
                                    "lamports": 2039280,
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "mint": "11111111111111111111111111111111",
                                                "tokenAmount": {"amount": "0"},
                                                "extensions": [
                                                    {
                                                        "extension": "transferFeeAmount",
                                                        "state": {"withheldAmount": "500"},
                                                    }
                                                ],
                                            }
                                        }
                                    },
                                },
                            },
                        ]
                    }
            return None

        mock_rpc.side_effect = rpc_side_effect
        response = client.post("/api/scan", json={"wallet_address": wallet_str})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        # Only the 1 valid Token-2022 account should be included
        self.assertEqual(data["empty_2022_count"], 1)
        self.assertEqual(data["empty_accounts_count"], 1)
        self.assertEqual(data["batch_sample"], [str(Pubkey.from_bytes(bytes([10] * 32)))])

    def test_db_retry_on_lock_concurrency(self):
        attempts = 0

        @rent_service.retry_on_lock(max_retries=3, delay=0.01)
        def flaky_db_write():
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise sqlite3.OperationalError("database is locked")
            return "written"

        result = flaky_db_write()
        self.assertEqual(result, "written")
        self.assertEqual(attempts, 3)
    @patch("rent_service._rpc_call")
    def test_scan_filters_frozen_accounts_and_returns_native_sol(self, mock_rpc):
        """SEC-04 & SEC-03: Frozen accounts are excluded and native_sol_balance is returned."""
        def rpc_side_effect(method, params):
            if method == "getBalance":
                return {"value": 50000000}  # 0.05 SOL
            elif method == "getTokenAccountsByOwner":
                program_filter = params[1]["programId"]
                if program_filter == str(TOKEN_PROGRAM_ID):
                    return {
                        "value": [
                            # 1. Normal empty SPL account (reclaimable)
                            {
                                "pubkey": str(Pubkey.from_bytes(bytes([10] * 32))),
                                "account": {
                                    "lamports": 2039280,
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "mint": "11111111111111111111111111111111",
                                                "tokenAmount": {"amount": "0"},
                                                "state": "initialized",
                                            }
                                        }
                                    },
                                },
                            },
                            # 2. Frozen empty SPL account (MUST BE FILTERED OUT)
                            {
                                "pubkey": str(Pubkey.from_bytes(bytes([11] * 32))),
                                "account": {
                                    "lamports": 2039280,
                                    "data": {
                                        "parsed": {
                                            "info": {
                                                "mint": "11111111111111111111111111111111",
                                                "tokenAmount": {"amount": "0"},
                                                "state": "frozen",
                                            }
                                        }
                                    },
                                },
                            },
                        ]
                    }
                return {"value": []}
            return None

        mock_rpc.side_effect = rpc_side_effect
        test_wallet = str(Pubkey.from_bytes(bytes([7] * 32)))
        response = client.post("/api/scan", json={"wallet_address": test_wallet})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Only 1 account is reclaimable, the frozen one was skipped
        self.assertEqual(data["empty_spl_count"], 1)
        self.assertEqual(data["empty_accounts_count"], 1)
        self.assertEqual(data["native_sol_balance"], 0.05)
        self.assertTrue(data["has_fee_reserve"])

    def test_confirm_endpoint_out_of_bounds_rejection(self):
        dummy_sig = str(Signature.from_bytes(bytes([8] * 64)))
        wallet = "11111111111111111111111111111111"

        # 1. accounts_closed > BATCH_SIZE (15)
        resp = client.post("/api/rent/confirm", json={
            "wallet": wallet,
            "signature": dummy_sig,
            "accounts_closed": 100,
            "sol_amount": 0.05,
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("accounts_closed out of sane bounds", resp.json()["detail"])

        # 2. accounts_closed < 1
        resp = client.post("/api/rent/confirm", json={
            "wallet": wallet,
            "signature": dummy_sig,
            "accounts_closed": 0,
            "sol_amount": 0.05,
        })
        self.assertEqual(resp.status_code, 400)

        # 3. sol_amount > 50 SOL (insane batch ceiling)
        resp = client.post("/api/rent/confirm", json={
            "wallet": wallet,
            "signature": dummy_sig,
            "accounts_closed": 5,
            "sol_amount": 1000.0,
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("sol_amount out of sane batch bounds", resp.json()["detail"])

    @patch("rent_service._rpc_call")
    def test_verify_signature_onchain_rejects_unconfirmed_processed(self, mock_rpc):
        from rent_service import verify_signature_onchain

        # Status 'processed' is NOT enough (must be 'confirmed' or 'finalized')
        mock_rpc.return_value = {
            "value": [
                {
                    "confirmationStatus": "processed",
                    "confirmations": 0,
                    "err": None,
                }
            ]
        }
        self.assertFalse(verify_signature_onchain("sig123"))

        # Status 'confirmed' is valid
        mock_rpc.return_value = {
            "value": [
                {
                    "confirmationStatus": "confirmed",
                    "confirmations": 10,
                    "err": None,
                }
            ]
        }
        self.assertTrue(verify_signature_onchain("sig123"))

    def test_rpc_pool_concurrent_rotation_thread_safety(self):
        import concurrent.futures
        from rpc_pool import RpcFailoverPool

        urls = [f"https://rpc{i}.solana.com" for i in range(5)]
        pool = RpcFailoverPool(urls)

        def rotate_worker():
            for _ in range(50):
                curr = pool.get_current_url()
                self.assertIn(curr, urls)
                pool.rotate()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(rotate_worker) for _ in range(8)]
            for f in futures:
                f.result()

        pool.close()

    def test_riley_system_program_is_rejected(self):
        # 1. System program address rejected on scan
        res_scan = client.post("/api/scan", json={"wallet_address": "11111111111111111111111111111111"})
        self.assertEqual(res_scan.status_code, 400)
        data = res_scan.json()
        self.assertEqual(data.get("error_code"), "SYSTEM_PROGRAM_NOT_WALLET")
        self.assertIn("system or program account", data.get("detail", ""))
        self.assertNotIn("reclaimable_sol", data)

        # 2. Token program address rejected on scan
        res_token = client.post("/api/scan", json={"wallet_address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"})
        self.assertEqual(res_token.status_code, 400)
        self.assertEqual(res_token.json().get("error_code"), "SYSTEM_PROGRAM_NOT_WALLET")

        # 3. System program rejected on build-tx
        res_tx = client.post("/api/rent/build-tx", json={"wallet_address": "11111111111111111111111111111111"})
        self.assertEqual(res_tx.status_code, 400)
        self.assertEqual(res_tx.json().get("error_code"), "SYSTEM_PROGRAM_NOT_WALLET")

    def test_riley_invalid_base58_is_rejected(self):
        # Empty string
        res = client.post("/api/scan", json={"wallet_address": ""})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json().get("error_code"), "EMPTY_WALLET_ADDRESS")

        # Whitespace
        res = client.post("/api/scan", json={"wallet_address": "    "})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json().get("error_code"), "EMPTY_WALLET_ADDRESS")

        # Forbidden characters in Base58 (0, O, I, l)
        res = client.post("/api/scan", json={"wallet_address": "0OIl11111111111111111111111111111111"})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json().get("error_code"), "INVALID_BASE58")

        # Too short
        res = client.post("/api/scan", json={"wallet_address": "not_an_address"})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json().get("error_code"), "INVALID_BASE58")

    @patch("rent_service._rpc_call")
    def test_riley_rpc_pool_fail_is_not_clean_wallet(self, mock_rpc):
        from rpc_pool import RpcError
        mock_rpc.side_effect = RpcError("Simulated total RPC node failure / cluster timeout")

        res = client.post("/api/scan", json={"wallet_address": TEST_WALLET})
        # MUST NOT be 200 OK
        self.assertNotEqual(res.status_code, 200)
        self.assertEqual(res.status_code, 502)
        data = res.json()
        self.assertIn("error_code", data)
        self.assertNotIn("total_token_accounts", data)
        self.assertNotIn("clean wallet", str(data).lower())

    @patch("rent_service._rpc_call")
    @patch("rent_service.get_sol_price_usd_async")
    def test_scan_when_price_fetcher_returns_none(self, mock_price, mock_rpc):
        """When price fetcher returns None, POST /api/scan must succeed (200), reclaimable_usd == 0, sol_price_usd is None."""
        mock_price.return_value = None

        def rpc_side_effect(method, params):
            if method == "getBalance":
                return {"value": 100000000}
            if method == "getTokenAccountsByOwner":
                return {
                    "value": [
                        {
                            "pubkey": str(Pubkey.from_bytes(bytes([1] * 32))),
                            "account": {
                                "lamports": 2039280,
                                "data": {
                                    "parsed": {
                                        "info": {
                                            "mint": "11111111111111111111111111111111",
                                            "tokenAmount": {"amount": "0"},
                                        }
                                    }
                                },
                            },
                        }
                    ]
                }
            return None

        mock_rpc.side_effect = rpc_side_effect
        addr = TEST_WALLET
        response = client.post("/api/scan", json={"wallet_address": addr})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["reclaimable_usd"], 0)
        self.assertIsNone(data["sol_price_usd"])

