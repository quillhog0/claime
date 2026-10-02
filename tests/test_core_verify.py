"""
Unit Tests for Quillhog Core Verification Engine (MOD-07)
File: tests/test_core_verify.py
"""

import unittest
from solders.pubkey import Pubkey

from core_verify import (
    TOKEN_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    WSOL_MINT,
    LAMPORTS_PER_RENT,
    MAX_BATCH_SIZE,
    MAX_FEE_BPS,
    validate_platform_fee_bps,
    calculate_platform_fee_lamports,
    create_close_account_instruction,
    evaluate_account_eligibility,
    parse_reclaimable_accounts,
)


class TestCoreVerify(unittest.TestCase):
    def setUp(self):
        self.owner_pubkey = Pubkey.from_string("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU")
        self.owner_str = str(self.owner_pubkey)
        self.other_pubkey = Pubkey.from_string("9xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU")
        self.token_account_pk = Pubkey.from_string("3xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU")

    def test_platform_fee_validation_and_arithmetic(self):
        # Claime architectural invariant: strictly 0% protocol fee
        self.assertEqual(validate_platform_fee_bps(0), 0)
        with self.assertRaises(ValueError):
            validate_platform_fee_bps(500)
        with self.assertRaises(ValueError):
            validate_platform_fee_bps(1000)

    def test_non_custodial_destination_invariant(self):
        # Valid: dest == owner
        ix = create_close_account_instruction(
            account=self.token_account_pk,
            dest=self.owner_pubkey,
            owner=self.owner_pubkey,
            program_id=TOKEN_PROGRAM_ID,
        )
        self.assertEqual(ix.program_id, TOKEN_PROGRAM_ID)
        self.assertEqual(ix.data, bytes([9]))

        # Invalid: dest != owner must raise ValueError (non-custodial violation)
        with self.assertRaises(ValueError) as ctx:
            create_close_account_instruction(
                account=self.token_account_pk,
                dest=self.other_pubkey,
                owner=self.owner_pubkey,
                program_id=TOKEN_PROGRAM_ID,
            )
        self.assertIn("Non-custodial invariant violation", str(ctx.exception))

    def test_sec_04_frozen_account_filtered(self):
        raw_account = {
            "pubkey": str(self.token_account_pk),
            "account": {
                "lamports": LAMPORTS_PER_RENT,
                "data": {
                    "parsed": {
                        "info": {
                            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                            "state": "frozen",
                            "tokenAmount": {"amount": "0"},
                        }
                    }
                },
            },
        }
        is_eligible, is_wsol, lamports, reason = evaluate_account_eligibility(
            raw_account, TOKEN_PROGRAM_ID, self.owner_str
        )
        self.assertFalse(is_eligible)
        self.assertEqual(reason, "FROZEN_ACCOUNT")

    def test_sec_01_close_authority_mismatch_filtered(self):
        raw_account = {
            "pubkey": str(self.token_account_pk),
            "account": {
                "lamports": LAMPORTS_PER_RENT,
                "data": {
                    "parsed": {
                        "info": {
                            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                            "state": "initialized",
                            "closeAuthority": str(self.other_pubkey),
                            "tokenAmount": {"amount": "0"},
                        }
                    }
                },
            },
        }
        is_eligible, is_wsol, lamports, reason = evaluate_account_eligibility(
            raw_account, TOKEN_PROGRAM_ID, self.owner_str
        )
        self.assertFalse(is_eligible)
        self.assertEqual(reason, "CLOSE_AUTHORITY_MISMATCH")

    def test_sec_02_token2022_withheld_fees_filtered(self):
        raw_account = {
            "pubkey": str(self.token_account_pk),
            "account": {
                "lamports": LAMPORTS_PER_RENT,
                "data": {
                    "parsed": {
                        "info": {
                            "mint": "Token2022MintAddress111111111111111111111",
                            "state": "initialized",
                            "tokenAmount": {"amount": "0"},
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
        is_eligible, is_wsol, lamports, reason = evaluate_account_eligibility(
            raw_account, TOKEN_2022_PROGRAM_ID, self.owner_str
        )
        self.assertFalse(is_eligible)
        self.assertEqual(reason, "TOKEN2022_WITHHELD_FEES_PRESENT")

    def test_wsol_unwrapping_eligibility(self):
        raw_account = {
            "pubkey": str(self.token_account_pk),
            "account": {
                "lamports": 50_000_000,  # 0.05 SOL locked
                "data": {
                    "parsed": {
                        "info": {
                            "mint": WSOL_MINT,
                            "state": "initialized",
                            "tokenAmount": {"amount": "50000000"},
                        }
                    }
                },
            },
        }
        is_eligible, is_wsol, lamports, reason = evaluate_account_eligibility(
            raw_account, TOKEN_PROGRAM_ID, self.owner_str
        )
        self.assertTrue(is_eligible)
        self.assertTrue(is_wsol)
        self.assertEqual(lamports, 50_000_000)
        self.assertEqual(reason, "WSOL_ELIGIBLE")

    def test_empty_standard_spl_eligibility(self):
        raw_account = {
            "pubkey": str(self.token_account_pk),
            "account": {
                "lamports": LAMPORTS_PER_RENT,
                "data": {
                    "parsed": {
                        "info": {
                            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                            "state": "initialized",
                            "tokenAmount": {"amount": "0"},
                        }
                    }
                },
            },
        }
        is_eligible, is_wsol, lamports, reason = evaluate_account_eligibility(
            raw_account, TOKEN_PROGRAM_ID, self.owner_str
        )
        self.assertTrue(is_eligible)
        self.assertFalse(is_wsol)
        self.assertEqual(lamports, LAMPORTS_PER_RENT)
        self.assertEqual(reason, "EMPTY_BALANCE_ELIGIBLE")

    def test_defensive_parsing_missing_keys(self):
        # Empty and malformed inputs should safely return not eligible instead of raising KeyError
        malformed_inputs = [
            {},
            {"pubkey": "test"},
            {"pubkey": "test", "account": {}},
            {"pubkey": "test", "account": {"data": {}}},
            {"pubkey": "test", "account": {"data": {"parsed": {}}}},
        ]
        for item in malformed_inputs:
            is_eligible, is_wsol, lamports, _ = evaluate_account_eligibility(
                item, TOKEN_PROGRAM_ID, self.owner_str
            )
            self.assertFalse(is_eligible)


if __name__ == "__main__":
    unittest.main()

