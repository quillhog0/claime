import base64
import json
import os
import sqlite3
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient

import rent_service
from rent_service import (
    app,
    TOKEN_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    create_close_account_instruction,
)
from core_verify import WSOL_MINT
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.instruction import Instruction
from solders.message import MessageV0
from solders.hash import Hash
from solders.transaction import VersionedTransaction

TEST_WALLET = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"

client = TestClient(app)


class TestRentService(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.temp_db_path = Path(self.temp_db.name)
        self.db_patcher = patch.object(rent_service, "RATE_LIMIT_DB_PATH", self.temp_db_path)
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
            self.assertIn("git_sha", data)

        with patch.dict(os.environ, {"GIT_SHA": "feedbeef1234"}):
            resp = client.get("/api/health")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["git_sha"], "feedbeef1234")

    def test_security_headers_and_csp(self):
        """L-13: FastAPI fallback CSP connect-src matches nginx 'connect-src self;'."""
        resp = client.get("/api/health")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        csp = resp.headers.get("Content-Security-Policy", "")
        self.assertIn("connect-src 'self';", csp)
        self.assertNotIn("connect-src 'self' https:;", csp)

    def test_scan_invalid_address(self):
        response = client.post("/api/scan", json={"wallet_address": "invalid_addr_123"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid Solana address format", response.json()["detail"])

    @patch("rent_service._rpc_call")
    @patch("rent_service.get_sol_price_usd_async", new_callable=AsyncMock, return_value=180.0)
    def test_scan_dual_program_and_wsol(self, mock_price, mock_rpc):
        def rpc_side_effect(method, params):
            if method == "getBalance":
                return {"value": 10_000_000}
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
        self.assertEqual(data["wsol_reclaimable_sol"], "0.050000000")
        self.assertEqual(data["empty_accounts_count"], 2)  # 1 SPL + 1 T22 (WSOL has amount > 0, so it is unwrap)

        expected_sol = "0.004078560"
        self.assertEqual(data["reclaimable_sol"], expected_sol)
        self.assertEqual(data["rent_sol"], expected_sol)
        self.assertEqual(data["rent_accounts"], 2)
        self.assertEqual(data["skipped_accounts"], [])
        self.assertNotIn("sol_price_usd", data)
        self.assertNotIn("reclaimable_usd", data)

    @patch("rent_service._rpc_call")
    def test_build_claim_no_reclaimable_accounts(self, mock_rpc):
        def rpc_side_effect(method, params):
            if method == "getBalance":
                return {"value": 10_000_000}
            return {"value": []}
        mock_rpc.side_effect = rpc_side_effect
        addr = TEST_WALLET
        response = client.post("/api/rent/build-tx", json={"wallet_address": addr})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "empty")

    @patch("rent_service._rpc_call")
    def test_build_tx_endpoint_mixed_spl_token2022_mtu_safe(self, mock_rpc):
        def rpc_side_effect(method, params):
            if method == "getBalance":
                return {"value": 10_000_000}
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

    @patch("rent_service.verify_signature_onchain", return_value=True)
    @patch("rent_service._rpc_call")
    def test_confirm_endpoint_success_and_duplicate_prevention(self, mock_rpc, mock_verify):
        dummy_sig = str(Signature.from_bytes(bytes([5] * 64)))
        wallet = "11111111111111111111111111111111"

        mock_rpc.return_value = {
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": wallet}],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "parsed": {
                                "type": "closeAccount",
                                "info": {"destination": wallet, "owner": wallet}
                            }
                        }
                    ]
                }
            },
            "meta": {
                "err": None,
                "preBalances": [1000000],
                "postBalances": [3039280],
            }
        }

        payload = {
            "wallet": wallet,
            "signature": dummy_sig,
            "accounts_closed": 1,
            "sol_amount": 0.002039,
            "estimated_usd": 0.36,
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
    @patch("rent_service._rpc_call")
    def test_confirm_endpoint_failed_onchain(self, mock_rpc, mock_verify):
        mock_verify.return_value = False
        mock_rpc.return_value = {"value": [{"err": {"InstructionError": [0, "Custom"]}}]}
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
        self.assertIn("failed on-chain", resp.json()["detail"].lower())

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
            if method == "getBalance":
                return {"value": 10_000_000}
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

        # 1b. GET with valid wallet passes validation
        resp_meta_val = client.get(f"/api/rent/qr?wallet={TEST_WALLET}")
        self.assertEqual(resp_meta_val.status_code, 200)

        # 1c. GET with invalid wallet fails with 400 INVALID_BASE58
        resp_meta_inv = client.get("/api/rent/qr?wallet=INVALID")
        self.assertEqual(resp_meta_inv.status_code, 400)
        self.assertEqual(resp_meta_inv.json().get("error_code"), "INVALID_BASE58")

        # 2. POST (Step 2): with account body -> transaction specification
        wallet = TEST_WALLET
        resp_post = client.post("/api/rent/qr", json={"account": wallet})
        self.assertEqual(resp_post.status_code, 200)
        self.assertIn("transaction", resp_post.json())
        self.assertIn("Close empty token accounts", resp_post.json()["message"])

        # 2b. POST with invalid account fails with 400 INVALID_BASE58
        resp_post_inv = client.post("/api/rent/qr", json={"account": "INVALID"})
        self.assertEqual(resp_post_inv.status_code, 400)
        self.assertEqual(resp_post_inv.json().get("error_code"), "INVALID_BASE58")

    def test_rent_qr_validation_strict(self):
        """C-20 P3: /api/rent/qr strict address (Base58, 32 bytes, no spaces) and integer amount validation."""
        # 1. Invalid address -> 400
        r_inv = client.get("/api/rent/qr?wallet=invalid_not_base58!!!")
        self.assertEqual(r_inv.status_code, 400)

        # 2. Address with space (leading, trailing, or embedded) -> 400
        r_space_trail = client.get(f"/api/rent/qr?wallet={TEST_WALLET}%20")
        self.assertEqual(r_space_trail.status_code, 400)
        r_space_lead = client.get(f"/api/rent/qr?wallet=%20{TEST_WALLET}")
        self.assertEqual(r_space_lead.status_code, 400)
        r_space_post = client.post("/api/rent/qr", json={"account": f" {TEST_WALLET} "})
        self.assertEqual(r_space_post.status_code, 400)

        # 3. Decimal amount -> 400
        r_dec_get = client.get(f"/api/rent/qr?wallet={TEST_WALLET}&amount=1.5")
        self.assertEqual(r_dec_get.status_code, 400)
        r_dec_post = client.post("/api/rent/qr", json={"account": TEST_WALLET, "amount": 0.5})
        self.assertEqual(r_dec_post.status_code, 400)
        r_dec_str = client.post("/api/rent/qr", json={"account": TEST_WALLET, "amount": "100.25"})
        self.assertEqual(r_dec_str.status_code, 400)

        # 4. Integer amount in lamports -> 200 on GET
        r_int_get = client.get(f"/api/rent/qr?wallet={TEST_WALLET}&amount=5000000")
        self.assertEqual(r_int_get.status_code, 200)

    @patch("rent_service._rpc_call")
    def test_token_2022_extensions_filtering(self, mock_rpc):
        wallet_str = TEST_WALLET
        foreign_authority = str(Pubkey.from_bytes(bytes([9] * 32)))

        def rpc_side_effect(method, params):
            if method == "getBalance":
                return {"value": 10_000_000}
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
        self.assertEqual(data["native_sol_balance"], "0.050000000")
        self.assertTrue(data["has_fee_reserve"])

    @patch("rent_service.verify_signature_onchain", return_value=True)
    @patch("rent_service._rpc_call")
    def test_confirm_rejects_onchain_close_count_above_batch_limit(self, mock_rpc, mock_verify):
        dummy_sig = str(Signature.from_bytes(bytes([8] * 64)))
        wallet = "11111111111111111111111111111111"
        close_ix = {
            "program": "spl-token",
            "parsed": {
                "type": "closeAccount",
                "info": {"destination": wallet, "owner": wallet},
            },
        }
        mock_rpc.return_value = {
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": wallet}],
                    "instructions": [close_ix for _ in range(16)],
                }
            },
            "meta": {"err": None, "preBalances": [1_000_000], "postBalances": [2_000_000]},
        }

        response = client.post("/api/rent/confirm", json={
            "wallet": wallet,
            "signature": dummy_sig,
            "accounts_closed": 1,
            "sol_amount": 0.05,
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("Too many CloseAccount instructions", response.json()["detail"])

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
                return {"value": 10_000_000}
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
        self.assertNotIn("reclaimable_usd", data)
        self.assertNotIn("sol_price_usd", data)

    @patch("rent_service.verify_signature_onchain", return_value=True)
    @patch("rent_service._rpc_call")
    def test_confirm_endpoint_foreign_transfer_rejected(self, mock_rpc, mock_verify):
        """Confirm with non-close transaction (e.g. transfer) must return 400."""
        wallet = "11111111111111111111111111111111"
        dummy_sig = str(Signature.from_bytes(bytes([9] * 64)))
        mock_rpc.return_value = {
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": wallet}],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "parsed": {
                                "type": "transfer",
                                "info": {"source": wallet, "destination": "other", "amount": "100"}
                            }
                        }
                    ]
                }
            },
            "meta": {"err": None}
        }
        resp = client.post("/api/rent/confirm", json={
            "wallet": wallet,
            "signature": dummy_sig,
            "accounts_closed": 1,
            "sol_amount": 0.002,
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Unauthorized instruction in transaction", resp.json()["detail"])

    @patch("rent_service.verify_signature_onchain", return_value=True)
    @patch("rent_service._rpc_call")
    def test_confirm_endpoint_wallet_not_in_account_keys_rejected(self, mock_rpc, mock_verify):
        """Confirm where wallet is not the fee payer (accountKeys[0]) must return 400."""
        wallet = "11111111111111111111111111111111"
        dummy_sig = str(Signature.from_bytes(bytes([9] * 64)))
        mock_rpc.return_value = {
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": "OtherWallet111111111111111111111111111111"}],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "parsed": {
                                "type": "closeAccount",
                                "info": {"destination": wallet, "owner": wallet}
                            }
                        }
                    ]
                }
            },
            "meta": {"err": None}
        }
        resp = client.post("/api/rent/confirm", json={
            "wallet": wallet,
            "signature": dummy_sig,
            "accounts_closed": 1,
            "sol_amount": 0.002,
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Fee payer", resp.json()["detail"])

    @patch("rent_service.verify_signature_onchain", return_value=True)
    @patch("rent_service._rpc_call")
    def test_confirm_endpoint_mixed_foreign_instruction_rejected(self, mock_rpc, mock_verify):
        """Confirm containing a closeAccount AND a foreign instruction must return 400."""
        wallet = "11111111111111111111111111111111"
        dummy_sig = str(Signature.from_bytes(bytes([9] * 64)))
        mock_rpc.return_value = {
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": wallet}],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "parsed": {
                                "type": "closeAccount",
                                "info": {"destination": wallet, "owner": wallet}
                            }
                        },
                        {
                            "program": "spl-token",
                            "parsed": {
                                "type": "transfer",
                                "info": {"source": wallet, "destination": "other", "amount": "100"}
                            }
                        }
                    ]
                }
            },
            "meta": {"err": None}
        }
        resp = client.post("/api/rent/confirm", json={
            "wallet": wallet,
            "signature": dummy_sig,
            "accounts_closed": 1,
            "sol_amount": 0.002,
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Unauthorized instruction in transaction", resp.json()["detail"])

    @patch("rent_service.verify_signature_onchain", return_value=False)
    @patch("rent_service._rpc_call", return_value={"value": [{"confirmationStatus": "processed", "err": None}]})
    def test_confirm_endpoint_returns_202_when_pending(self, mock_rpc, mock_verify):
        """Confirm for unconfirmed/pending transaction must return 202 Accepted with status=pending."""
        wallet = "11111111111111111111111111111111"
        dummy_sig = str(Signature.from_bytes(bytes([9] * 64)))
        resp = client.post("/api/rent/confirm", json={
            "wallet": wallet,
            "signature": dummy_sig,
            "accounts_closed": 1,
            "sol_amount": 0.002,
        })
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(resp.json()["status"], "pending")

    @patch("rent_service._rpc_call")
    def test_tx_status_endpoint(self, mock_rpc):
        """GET /api/tx/status returns pending, confirmed, failed, or 400 on bad sig."""
        dummy_sig = str(Signature.from_bytes(bytes([11] * 64)))

        # 1. Invalid signature format
        resp = client.get("/api/tx/status?sig=too_short")
        self.assertEqual(resp.status_code, 400)

        # 2. Confirmed status
        mock_rpc.return_value = {"value": [{"confirmationStatus": "confirmed", "err": None}]}
        resp = client.get(f"/api/tx/status?sig={dummy_sig}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "confirmed")

        # 3. Finalized status
        mock_rpc.return_value = {"value": [{"confirmationStatus": "finalized", "err": None}]}
        resp = client.get(f"/api/tx/status?sig={dummy_sig}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "confirmed")

        # 4. Failed status
        mock_rpc.return_value = {"value": [{"confirmationStatus": "confirmed", "err": {"InstructionError": [0, "Custom"]}}]}
        resp = client.get(f"/api/tx/status?sig={dummy_sig}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "failed")

        # 5. Pending (processed)
        mock_rpc.return_value = {"value": [{"confirmationStatus": "processed", "err": None}]}
        resp = client.get(f"/api/tx/status?sig={dummy_sig}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "pending")

        # 6. Pending (not indexed yet)
        mock_rpc.return_value = {"value": [None]}
        resp = client.get(f"/api/tx/status?sig={dummy_sig}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "pending")

    @patch("rent_service.verify_signature_onchain", return_value=True)
    @patch("rent_service._rpc_call")
    def test_confirm_endpoint_valid_close_transaction_success(self, mock_rpc, mock_verify):
        """Confirm with valid CloseAccount transaction returns 200 and calculates accounts_closed from ix."""
        wallet = "11111111111111111111111111111111"
        dummy_sig = str(Signature.from_bytes(bytes([10] * 64)))
        mock_rpc.return_value = {
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": wallet}],
                    "instructions": [
                        {
                            "program": "spl-token",
                            "parsed": {
                                "type": "closeAccount",
                                "info": {"destination": wallet, "owner": wallet}
                            }
                        },
                        {
                            "program": "spl-token-2022",
                            "parsed": {
                                "type": "closeAccount",
                                "info": {"destination": wallet, "owner": wallet}
                            }
                        }
                    ]
                }
            },
            "meta": {
                "err": None,
                "preBalances": [1000000],
                "postBalances": [5078560],
            }
        }
        resp = client.post("/api/rent/confirm", json={
            "wallet": wallet,
            "signature": dummy_sig,
            "accounts_closed": 5,
            "sol_amount": 0.01,
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["tx"], dummy_sig)

    def test_sqlite_shared_rate_limit_store(self):
        """Shared per-IP buckets must survive worker/process boundaries via SQLite WAL."""
        from pathlib import Path
        from rent_service import check_rate_limit

        db_path = Path("/tmp/quillhog-rate-limit-test.sqlite")
        if db_path.exists():
            db_path.unlink()

        key = "203.0.113.10"
        route = "/api/scan"
        assert check_rate_limit(key, route, limit=2, window_seconds=60, db_path=db_path) is False
        assert check_rate_limit(key, route, limit=2, window_seconds=60, db_path=db_path) is False
        assert check_rate_limit(key, route, limit=2, window_seconds=60, db_path=db_path) is True

    def test_rate_limit_hmac_keyed_hash_and_retention(self):
        """Verify keyed HMAC hashing and time-based retention cleanup in SQLite rate limiter."""
        import hashlib
        import sqlite3
        import time
        from pathlib import Path
        from rent_service import check_rate_limit

        db_path = Path("/tmp/quillhog-rate-limit-hmac-test.sqlite")
        if db_path.exists():
            db_path.unlink()

        ip1 = "198.51.100.10"
        ip2 = "198.51.100.20"
        route = "/api/scan"

        # 1. Check rate limit for ip1 and ip2
        self.assertFalse(check_rate_limit(ip1, route, limit=5, window_seconds=60, db_path=db_path))
        self.assertFalse(check_rate_limit(ip2, route, limit=5, window_seconds=60, db_path=db_path))

        # 2. Inspect raw rows in SQLite: verify ip_hash != sha256(ip)[:16] and distinct IPs have distinct hashes
        conn = sqlite3.connect(db_path)
        rows = conn.execute("SELECT ip_hash, ts FROM rate_limit_events ORDER BY ts ASC").fetchall()
        self.assertEqual(len(rows), 2)
        hash1, hash2 = rows[0][0], rows[1][0]
        self.assertNotEqual(hash1, hashlib.sha256(ip1.encode("utf-8")).hexdigest()[:16])
        self.assertNotEqual(hash2, hashlib.sha256(ip2.encode("utf-8")).hexdigest()[:16])
        self.assertNotEqual(hash1, hash2)

        # 3. Time-based retention cleanup: insert row older than 3600 seconds
        old_ts = time.time() - 4000.0
        conn.execute("INSERT INTO rate_limit_events (ip_hash, route, ts) VALUES ('oldhash', '/api/scan', ?)", (old_ts,))
        conn.commit()
        conn.close()

        # Advance _last_rl_purge to force retention cleanup
        import rent_service
        rent_service._last_rl_purge = 0.0

        # Trigger check_rate_limit to trigger global cleanup
        check_rate_limit("198.51.100.30", route, limit=5, window_seconds=60, db_path=db_path)

        conn = sqlite3.connect(db_path)
        old_rows = conn.execute("SELECT ip_hash FROM rate_limit_events WHERE ip_hash = 'oldhash'").fetchall()
        conn.close()
        self.assertEqual(len(old_rows), 0, "Events older than 3600 seconds must be purged by retention cleanup")

    def test_rate_limit_spoofed_forwarded_for_ignored(self):
        """T-019: Non-loopback spoofed headers are ignored; loopback takes X-Real-IP."""
        from fastapi import Request
        from rent_service import get_client_ip

        # 1. Non-loopback peer cannot spoof via CF-Connecting-IP, X-Real-IP, or X-Forwarded-For
        untrusted_req = Request({
            "type": "http",
            "client": ("198.51.100.25", 54321),
            "headers": [
                (b"cf-connecting-ip", b"1.1.1.1"),
                (b"x-real-ip", b"3.3.3.3"),
                (b"x-forwarded-for", b"2.2.2.2"),
            ],
        })
        self.assertEqual(get_client_ip(untrusted_req), "198.51.100.25")

        # 2. Loopback peer takes X-Real-IP (overwritten by nginx to $remote_addr)
        loopback_req = Request({
            "type": "http",
            "client": ("127.0.0.1", 54321),
            "headers": [
                (b"cf-connecting-ip", b"1.1.1.1"),
                (b"x-real-ip", b"203.0.113.195"),
                (b"x-forwarded-for", b"2.2.2.2"),
            ],
        })
        self.assertEqual(get_client_ip(loopback_req), "203.0.113.195")

        # 3. Direct client request with spoofed forwarded headers succeeds without error
        headers_spoof = {"x-forwarded-for": "1.2.3.4"}
        resp = client.get("/api/health", headers=headers_spoof)
        self.assertEqual(resp.status_code, 200)

    def test_all_429_branches_include_retry_after(self):
        """T-053: All 429 rate limit branches must include Retry-After: 60 header."""
        with patch("rent_service.check_rate_limit", return_value=True):
            # 1. Status poll branch
            r1 = client.get("/api/tx/status?sig=" + ("5" * 64))
            self.assertEqual(r1.status_code, 429)
            self.assertEqual(r1.headers.get("retry-after"), "60")

            # 2. Inspect / simulate branch
            r2 = client.post("/api/tx/simulate", json={"transaction_base64": "dummy"})
            self.assertEqual(r2.status_code, 429)
            self.assertEqual(r2.headers.get("retry-after"), "60")

            # 3. Action routes branch
            r3 = client.post("/api/scan", json={"wallet_address": "11111111111111111111111111111111"})
            self.assertEqual(r3.status_code, 429)
            self.assertEqual(r3.headers.get("retry-after"), "60")

    @patch("rent_service._rpc_call_async")
    @patch("rent_service._fetch_program_accounts_async")
    @patch("rent_service.verify_wallet_not_executable")
    @patch("rent_service.require_fee_reserve_async")
    def test_builders_emit_no_fee_transfer(self, mock_reserve, mock_verify, mock_fetch, mock_rpc):
        """
        Verify that claim builder emits 0 protocol fee transfers,
        no System program fee drain, and every CloseAccount targets dest == owner.
        """
        import base64
        from solders.transaction import VersionedTransaction

        mock_reserve.return_value = None
        mock_verify.return_value = None
        mock_rpc.return_value = {
            "value": {"blockhash": "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM"}
        }

        owner_pk_str = TEST_WALLET
        token_acc_pk = str(Pubkey.from_bytes(bytes([2] * 32)))
        system_program_id = "11111111111111111111111111111111"

        def verify_tx_invariants(tx_b64, expected_owner):
            tx = VersionedTransaction.from_bytes(base64.b64decode(tx_b64))
            msg = tx.message
            account_keys = [str(k) for k in msg.account_keys]

            for ix in msg.instructions:
                prog_id = account_keys[ix.program_id_index]
                # System Program must never be invoked as an instruction program in builders
                self.assertNotEqual(
                    prog_id, system_program_id,
                    "System Program must never be called as an instruction program"
                )

                # For SPL Token / Token-2022 programs:
                if prog_id in (str(TOKEN_PROGRAM_ID), str(TOKEN_2022_PROGRAM_ID)):
                    data = bytes(ix.data)
                    # Opcode 9 = CloseAccount
                    if len(data) >= 1 and data[0] == 9:
                        self.assertGreaterEqual(len(ix.accounts), 3)
                        dest_key = account_keys[ix.accounts[1]]
                        owner_key = account_keys[ix.accounts[2]]
                        self.assertEqual(dest_key, expected_owner, "CloseAccount destination must equal owner")
                        self.assertEqual(owner_key, expected_owner, "CloseAccount owner authority must equal owner")

        # 1. Claim Builder
        empty_acc = {
            "pubkey": token_acc_pk,
            "account": {
                "lamports": 2039280,
                "data": {
                    "parsed": {
                        "info": {
                            "mint": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
                            "owner": owner_pk_str,
                            "tokenAmount": {"amount": "0", "decimals": 6},
                        }
                    }
                }
            }
        }
        mock_fetch.side_effect = [[empty_acc], []]
        res_claim = client.post("/api/rent/build-tx", json={"wallet_address": owner_pk_str})
        self.assertEqual(res_claim.status_code, 200)
        verify_tx_invariants(res_claim.json()["transaction_base64"], owner_pk_str)

    @patch("rent_service._fetch_program_accounts_async")
    @patch("rent_service._rpc_call")
    @patch("rent_service._rpc_call_async")
    def test_scan_and_builder_eligibility_alignment(self, mock_rpc_async, mock_rpc, mock_fetch):
        """T-013: Scan and builder must agree on eligible accounts.
        Frozen, Token-2022 withheld fee, and close authority mismatch accounts are skipped
        and recorded in skipped_accounts. Empty USDC accounts are eligible and closed."""
        from core_verify import summarize_scan_accounts

        owner_pk_str = TEST_WALLET
        other_wallet = "Other11111111111111111111111111111111111111"
        usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

        # 1. Empty USDC account (eligible)
        acc_usdc = {
            "pubkey": "USDCAccount11111111111111111111111111111111",
            "account": {
                "lamports": 2039280,
                "owner": str(TOKEN_PROGRAM_ID),
                "data": {
                    "parsed": {
                        "info": {
                            "mint": usdc_mint,
                            "owner": owner_pk_str,
                            "state": "initialized",
                            "tokenAmount": {"amount": "0", "decimals": 6},
                        }
                    }
                },
            },
        }

        # 2. Empty standard SPL account (eligible)
        acc_spl = {
            "pubkey": "SPLAccount111111111111111111111111111111111",
            "account": {
                "lamports": 2039280,
                "owner": str(TOKEN_PROGRAM_ID),
                "data": {
                    "parsed": {
                        "info": {
                            "mint": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
                            "owner": owner_pk_str,
                            "state": "initialized",
                            "tokenAmount": {"amount": "0", "decimals": 6},
                        }
                    }
                },
            },
        }

        # 3. Frozen account (skipped -> frozen)
        acc_frozen = {
            "pubkey": "FrozenAccount111111111111111111111111111111",
            "account": {
                "lamports": 2039280,
                "owner": str(TOKEN_PROGRAM_ID),
                "data": {
                    "parsed": {
                        "info": {
                            "mint": "FrozenMint111111111111111111111111111111111",
                            "owner": owner_pk_str,
                            "state": "frozen",
                            "tokenAmount": {"amount": "0", "decimals": 6},
                        }
                    }
                },
            },
        }

        # 4. Token-2022 account with withheld fees (skipped -> fee_withheld)
        acc_fee = {
            "pubkey": "FeeAccount1111111111111111111111111111111111",
            "account": {
                "lamports": 2039280,
                "owner": str(TOKEN_2022_PROGRAM_ID),
                "data": {
                    "parsed": {
                        "info": {
                            "mint": "FeeMint1111111111111111111111111111111111111",
                            "owner": owner_pk_str,
                            "state": "initialized",
                            "tokenAmount": {"amount": "0", "decimals": 6},
                            "extensions": [
                                {
                                    "extension": "transferFeeAmount",
                                    "state": {"withheldAmount": 5000},
                                }
                            ],
                        }
                    }
                },
            },
        }

        # 5. Account with close authority mismatch (skipped -> authority)
        acc_auth = {
            "pubkey": "AuthMismatchAccount1111111111111111111111111",
            "account": {
                "lamports": 2039280,
                "owner": str(TOKEN_PROGRAM_ID),
                "data": {
                    "parsed": {
                        "info": {
                            "mint": "AuthMint111111111111111111111111111111111111",
                            "owner": owner_pk_str,
                            "closeAuthority": other_wallet,
                            "state": "initialized",
                            "tokenAmount": {"amount": "0", "decimals": 6},
                        }
                    }
                },
            },
        }

        # 6. WSOL account with balance (not counted in rent_accounts, counted in wrap)
        acc_wsol = {
            "pubkey": "WSOLAccount111111111111111111111111111111111",
            "account": {
                "lamports": 50000000,
                "owner": str(TOKEN_PROGRAM_ID),
                "data": {
                    "parsed": {
                        "info": {
                            "mint": WSOL_MINT,
                            "owner": owner_pk_str,
                            "state": "initialized",
                            "tokenAmount": {"amount": "50000000", "decimals": 9},
                        }
                    }
                },
            },
        }

        spl_accounts = [acc_usdc, acc_spl, acc_frozen, acc_auth, acc_wsol]
        t22_accounts = [acc_fee]
        all_accounts = spl_accounts + t22_accounts

        # A) Verify summarize_scan_accounts directly
        summary = summarize_scan_accounts(all_accounts, native_lamports=5_000_000, owner=owner_pk_str)
        self.assertEqual(summary["rent_accounts"], 2, "Only acc_usdc and acc_spl should be eligible for rent claim")
        self.assertEqual(summary["rent_lamports"], 2039280 + 2039280)
        self.assertEqual(len(summary["skipped_accounts"]), 3)

        skipped_by_pubkey = {item["pubkey"]: item["reason"] for item in summary["skipped_accounts"]}
        self.assertEqual(skipped_by_pubkey[acc_frozen["pubkey"]], "frozen")
        self.assertEqual(skipped_by_pubkey[acc_fee["pubkey"]], "fee_withheld")
        self.assertEqual(skipped_by_pubkey[acc_auth["pubkey"]], "authority")

        # B) Verify via /api/scan and /api/rent/build-tx
        mock_fetch.side_effect = [spl_accounts, t22_accounts, spl_accounts, t22_accounts]
        mock_rpc_async.side_effect = lambda method, params: (
            {"value": 10_000_000} if method == "getBalance"
            else {"value": {"blockhash": "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM" + "n"}} if method == "getLatestBlockhash"
            else {"value": None} if method == "getAccountInfo"
            else {"value": []} if method == "getMultipleAccounts"
            else {}
        )
        mock_rpc.side_effect = lambda method, params: (
            {"value": {"blockhash": "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM" + "n"}}
            if method == "getLatestBlockhash"
            else {"value": []}
        )

        scan_res = client.post("/api/scan", json={"wallet_address": owner_pk_str})
        self.assertEqual(scan_res.status_code, 200)
        scan_data = scan_res.json()

        build_res = client.post("/api/rent/build-tx", json={"wallet_address": owner_pk_str})
        self.assertEqual(build_res.status_code, 200)
        build_data = build_res.json()

        # Strict agreement between scan and builder:
        self.assertEqual(scan_data["rent_accounts"], len(build_data["close_accounts"]))
        self.assertEqual(scan_data["rent_accounts"], build_data["total_empty_found"])
        self.assertEqual(scan_data["reclaimable_sol"], build_data["sol_reclaimed"])
        self.assertEqual(scan_data["wsol_reclaimable_sol"], "0.050000000")

        closed_pubkeys = {item["pubkey"] for item in build_data["close_accounts"]}
        self.assertEqual(closed_pubkeys, {acc_usdc["pubkey"], acc_spl["pubkey"]})

    @patch("rent_service._fetch_program_accounts_async")
    @patch("rent_service._rpc_call")
    @patch("rent_service._rpc_call_async")
    def test_scan_returns_integer_network_fee_matching_builder(self, mock_rpc_async, mock_rpc, mock_fetch):
        """C-05: /api/scan must return integer network_fee_lamports matching builder fee."""
        owner_pk_str = TEST_WALLET
        acc_empty = {
            "pubkey": str(Pubkey.from_bytes(bytes([10] * 32))),
            "account": {
                "lamports": 2039280,
                "data": {
                    "parsed": {
                        "info": {
                            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                            "owner": owner_pk_str,
                            "state": "initialized",
                            "tokenAmount": {"amount": "0", "decimals": 6},
                        }
                    }
                },
            },
        }
        mock_fetch.side_effect = lambda owner, prog: (
            [acc_empty] if str(prog) == str(TOKEN_PROGRAM_ID) else []
        )
        mock_rpc_async.side_effect = lambda method, params: (
            {"value": 50000000} if method == "getBalance"
            else {"value": {"blockhash": "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofMn"}} if method == "getLatestBlockhash"
            else None
        )
        mock_rpc.side_effect = lambda method, params: (
            {"value": {"blockhash": "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofMn"}} if method == "getLatestBlockhash"
            else {"value": []}
        )

        scan_res = client.post("/api/scan", json={"wallet_address": owner_pk_str})
        self.assertEqual(scan_res.status_code, 200)
        scan_data = scan_res.json()

        # Strict integer check on network_fee_lamports in /api/scan
        self.assertIn("network_fee_lamports", scan_data)
        self.assertIsInstance(scan_data["network_fee_lamports"], int)
        self.assertNotIsInstance(scan_data["network_fee_lamports"], bool)
        self.assertEqual(scan_data["network_fee_lamports"], 5000)

        build_res = client.post("/api/rent/build-tx", json={"wallet_address": owner_pk_str})
        self.assertEqual(build_res.status_code, 200)
        build_data = build_res.json()

        self.assertIn("network_fee_lamports", build_data)
        self.assertIsInstance(build_data["network_fee_lamports"], int)
        self.assertNotIsInstance(build_data["network_fee_lamports"], bool)
        self.assertEqual(scan_data["network_fee_lamports"], build_data["network_fee_lamports"])

    @patch("rent_service._fetch_program_accounts_async")
    @patch("rent_service._rpc_call_async")
    def test_trimming_and_413_boundary(self, mock_rpc_async, mock_fetch):
        """T-015: Trimming sets trimmed: True when batch exceeds 1232B, and 413 only when 1 account cannot fit."""
        from rent_service import _compile_tx_payload
        from solders.pubkey import Pubkey
        from solders.transaction import VersionedTransaction
        from fastapi import HTTPException

        owner_pk = Pubkey.from_string(TEST_WALLET)
        blockhash = "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM"

        # Generate 15 fake zero-amount accounts
        accounts = [
            {
                "pubkey": str(Pubkey.from_bytes(bytes([i % 250 + 1] * 32))),
                "lamports": 2039280,
                "amount": 0,
                "program_id": TOKEN_PROGRAM_ID,
            }
            for i in range(15)
        ]

        # Normal compilation fits in 1232 B, trimmed should be False
        normal_payload = _compile_tx_payload(owner_pk, accounts, blockhash, 150.0)
        self.assertEqual(normal_payload["status"], "ready")
        self.assertFalse(normal_payload["trimmed"])
        self.assertTrue(normal_payload["mtu_safe"])

        # Patch VersionedTransaction bytes to simulate MTU boundary
        original_bytes = VersionedTransaction.__bytes__
        try:
            # Simulate: 10 accounts or more exceed 1232 B (return 1300 B), but <= 9 accounts fit (return 800 B)
            def mock_bytes(self):
                num_ix = len(self.message.instructions)
                if num_ix > 9:
                    return b"X" * 1300
                return b"X" * 800

            VersionedTransaction.__bytes__ = mock_bytes
            trimmed_payload = _compile_tx_payload(owner_pk, accounts, blockhash, 150.0)
            self.assertEqual(trimmed_payload["status"], "ready")
            self.assertTrue(trimmed_payload["trimmed"])
            self.assertEqual(trimmed_payload["accounts_closed_in_batch"], 9)
            self.assertTrue(trimmed_payload["mtu_safe"])

            # Simulate: even 1 account exceeds 1232 B -> HTTP 413
            def mock_bytes_all_oversized(self):
                return b"X" * 1300

            VersionedTransaction.__bytes__ = mock_bytes_all_oversized
            with self.assertRaises(HTTPException) as ctx:
                _compile_tx_payload(owner_pk, accounts, blockhash, 150.0)
            self.assertEqual(ctx.exception.status_code, 413)

        finally:
            VersionedTransaction.__bytes__ = original_bytes

    @staticmethod
    def _create_mock_tx_b64(program_id_str=None, payer_str=None):
        payer = Pubkey.from_string(payer_str or TEST_WALLET)
        prog = Pubkey.from_string(program_id_str or str(TOKEN_PROGRAM_ID))
        ix = Instruction(prog, b"test", [])
        msg = MessageV0.try_compile(payer, [ix], [], Hash.default())
        tx = VersionedTransaction.populate(msg, [Signature.default()])
        return base64.b64encode(bytes(tx)).decode()

    @patch("rent_service._rpc_call_async")
    def test_tx_simulate_success(self, mock_rpc_async):
        """Valid transaction simulation returns ok=True with logs and units_consumed."""
        mock_rpc_async.return_value = {
            "context": {"slot": 100},
            "value": {
                "err": None,
                "logs": ["Program 11111111111111111111111111111111 invoke [1]", "Program success"],
                "unitsConsumed": 2100,
            },
        }
        valid_b64 = self._create_mock_tx_b64()
        res = client.post("/api/tx/simulate", json={"transaction_base64": valid_b64})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["ok"])
        self.assertIsNone(data["error"])
        self.assertEqual(data["units_consumed"], 2100)
        self.assertEqual(len(data["logs"]), 2)

    @patch("rent_service._rpc_call_async")
    def test_tx_simulate_onchain_error(self, mock_rpc_async):
        """Simulation returning on-chain err returns ok=False with error string."""
        mock_rpc_async.return_value = {
            "context": {"slot": 100},
            "value": {
                "err": {"InstructionError": [0, "Custom: 1"]},
                "logs": ["Program fail"],
                "unitsConsumed": 450,
            },
        }
        valid_b64 = self._create_mock_tx_b64()
        res = client.post("/api/tx/simulate", json={"transaction_base64": valid_b64})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertFalse(data["ok"])
        self.assertIn("InstructionError", data["error"])
        self.assertEqual(data["units_consumed"], 450)

    @patch("rent_service._rpc_call_async")
    def test_tx_simulate_rpc_failure(self, mock_rpc_async):
        """When RPC fails, returns 503 Service Unavailable without leaking exception text (L-2)."""
        mock_rpc_async.side_effect = Exception("RPC timeout internal error text")
        valid_b64 = self._create_mock_tx_b64()
        res = client.post("/api/tx/simulate", json={"transaction_base64": valid_b64})
        self.assertEqual(res.status_code, 503)
        self.assertNotIn("internal error text", res.text)
        self.assertEqual(res.json()["error_code"], "SIMULATION_SERVICE_UNAVAILABLE")

    def test_tx_simulate_invalid_base64(self):
        """Invalid base64 returns 400 Bad Request."""
        res = client.post("/api/tx/simulate", json={"transaction_base64": "!!!not-valid-base64-content!!!"})
        self.assertEqual(res.status_code, 400)

    def test_tx_simulate_mtu_limit(self):
        """L-2: Payload exceeding MAX_TX_BYTES (1232) is rejected by server validator with 413."""
        huge_bytes = b"\x00" * 1233
        b64 = base64.b64encode(huge_bytes).decode()
        res = client.post("/api/tx/simulate", json={"transaction_base64": b64})
        self.assertEqual(res.status_code, 413)
        self.assertEqual(res.json()["error_code"], "TX_TOO_LARGE")

    def test_tx_simulate_alien_program_rejected(self):
        """Reject transactions containing alien program IDs not on Claime allowlist with 400."""
        alien_tx_b64 = self._create_mock_tx_b64(program_id_str="Vote111111111111111111111111111111111111111")
        res = client.post("/api/tx/simulate", json={"transaction_base64": alien_tx_b64})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["error_code"], "DISALLOWED_PROGRAM_ID")

    def test_tx_simulate_invalid_fee_payer_rejected(self):
        """Reject transactions with invalid fee payer (e.g. system program or non-wallet) with 400."""
        invalid_payer_tx_b64 = self._create_mock_tx_b64(payer_str="11111111111111111111111111111111")
        res = client.post("/api/tx/simulate", json={"transaction_base64": invalid_payer_tx_b64})
        self.assertEqual(res.status_code, 400)

    def test_tx_simulate_rate_limit(self):
        """Rate limit applies to /api/tx/simulate returning 429 when quota exceeded."""
        valid_b64 = self._create_mock_tx_b64()
        with patch("rent_service.check_rate_limit", return_value=True):
            res = client.post("/api/tx/simulate", json={"transaction_base64": valid_b64})
            self.assertEqual(res.status_code, 429)
            self.assertEqual(res.headers.get("retry-after"), "60")
            self.assertIn("Pre-flight quota exceeded", res.json()["detail"])

    def test_tx_simulate_invalid_wire(self):
        """L-2: Corrupt wire format is rejected by server validator."""
        corrupt_bytes = b"\xff\xff\xff\xff" * 10
        b64 = base64.b64encode(corrupt_bytes).decode()
        res = client.post("/api/tx/simulate", json={"transaction_base64": b64})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["error_code"], "INVALID_TRANSACTION_WIRE")

    def test_host_header_poisoning_defense(self):
        """T-052: Host header poisoning must not reflect into generated URLs."""
        # 1. /api/rent/qr
        res = client.get("/api/rent/qr", headers={"Host": "evil.example"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertNotIn("evil.example", data["icon"])
        self.assertTrue(data["icon"].startswith("https://quillhog.xyz"))

        # 2. /api/rent/deep-links
        res_dl = client.get("/api/rent/deep-links", headers={"Host": "evil.example"})
        self.assertEqual(res_dl.status_code, 200)
        data_dl = res_dl.json()
        for key, url in data_dl.items():
            self.assertNotIn("evil.example", url)
            self.assertIn("quillhog.xyz", url)

    def test_cors_production_disallows_localhost(self):
        """C-20 P4: In production, http://localhost:8000 is rejected from CORS allowed origins."""
        old_env = os.environ.get("QUILLHOG_ENV")
        try:
            os.environ.pop("QUILLHOG_ENV", None)

            # Simple request from localhost in prod receives no Access-Control-Allow-Origin
            res_simple = client.get("/api/health", headers={"Origin": "http://localhost:8000"})
            self.assertEqual(res_simple.status_code, 200)
            self.assertIsNone(res_simple.headers.get("access-control-allow-origin"))

            # Preflight request from localhost in prod receives 400
            res_preflight = client.options(
                "/api/scan",
                headers={
                    "Origin": "http://localhost:8000",
                    "Access-Control-Request-Method": "POST",
                },
            )
            self.assertEqual(res_preflight.status_code, 400)

            # Production origin (quillhog.xyz) is allowed
            res_prod = client.get("/api/health", headers={"Origin": "https://quillhog.xyz"})
            self.assertEqual(res_prod.headers.get("access-control-allow-origin"), "https://quillhog.xyz")
        finally:
            if old_env is not None:
                os.environ["QUILLHOG_ENV"] = old_env
            else:
                os.environ.pop("QUILLHOG_ENV", None)

    def test_cors_dev_allows_localhost(self):
        """C-20 P4: When QUILLHOG_ENV=dev, http://localhost:8000 is permitted in CORS."""
        old_env = os.environ.get("QUILLHOG_ENV")
        try:
            os.environ["QUILLHOG_ENV"] = "dev"

            # Simple request from localhost in dev receives Access-Control-Allow-Origin
            res_simple = client.get("/api/health", headers={"Origin": "http://localhost:8000"})
            self.assertEqual(res_simple.status_code, 200)
            self.assertEqual(res_simple.headers.get("access-control-allow-origin"), "http://localhost:8000")

            # Preflight request from localhost in dev receives 200
            res_preflight = client.options(
                "/api/scan",
                headers={
                    "Origin": "http://localhost:8000",
                    "Access-Control-Request-Method": "POST",
                },
            )
            self.assertEqual(res_preflight.status_code, 200)
            self.assertEqual(res_preflight.headers.get("access-control-allow-origin"), "http://localhost:8000")
        finally:
            if old_env is not None:
                os.environ["QUILLHOG_ENV"] = old_env
            else:
                os.environ.pop("QUILLHOG_ENV", None)
