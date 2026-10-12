"""
Unit tests for Quillhog Claime Core Engine (claim_core.py / C-01).

Validates:
1. Non-custodial: Transactions are strictly unsigned (Signature.default()).
2. Invariant: dest == owner == signer on every close instruction. Attempting dest != owner raises ValueError.
3. No Burn/Transfer: Only CloseAccount instructions (opcode 9). No burn (opcode 8), no transfer instructions.
4. Only Empty Accounts: Accounts with non-zero amounts are strictly ignored.
5. MTU Boundary: Serialized transaction wire format never exceeds 1232 bytes.
6. Integer Financials: Lamport math is pure integer arithmetic without floats.
"""

import base64
import pytest
from solders.hash import Hash
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from claim_core import (
    TOKEN_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    MAX_BATCH_SIZE,
    MAX_TX_BYTES,
    create_close_account_instruction,
    filter_empty_accounts,
    sol_from_lamports,
    compile_claim_transaction_payload,
)


def test_dest_equals_owner_invariant():
    owner = Pubkey.new_unique()
    account = Pubkey.new_unique()

    # Valid: dest == owner
    ix = create_close_account_instruction(account, owner, owner, TOKEN_PROGRAM_ID)
    assert ix.program_id == TOKEN_PROGRAM_ID
    assert ix.data == bytes([9])
    assert len(ix.accounts) == 3
    assert ix.accounts[0].pubkey == account
    assert not ix.accounts[0].is_signer
    assert ix.accounts[1].pubkey == owner
    assert not ix.accounts[1].is_signer
    assert ix.accounts[2].pubkey == owner
    assert ix.accounts[2].is_signer

    # Invalid: dest != owner -> must raise ValueError
    attacker = Pubkey.new_unique()
    with pytest.raises(ValueError, match="Non-custodial invariant violation"):
        create_close_account_instruction(account, attacker, owner, TOKEN_PROGRAM_ID)


def test_compile_claim_transaction_unsigned_and_no_burn():
    wallet = Pubkey.new_unique()
    reclaimable = [
        {"pubkey": str(Pubkey.new_unique()), "lamports": 2039280, "amount": 0, "program_id": TOKEN_PROGRAM_ID},
        {"pubkey": str(Pubkey.new_unique()), "lamports": 2039280, "amount": 0, "program_id": TOKEN_2022_PROGRAM_ID},
    ]
    blockhash = str(Hash.default())

    res = compile_claim_transaction_payload(wallet, reclaimable, blockhash)
    assert res["status"] == "ready"
    assert res["accounts_closed_in_batch"] == 2
    assert res["total_empty_found"] == 2
    assert res["sol_reclaimed_lamports"] == 4078560
    assert res["sol_reclaimed"] == "0.004078560"
    assert res["mtu_safe"] is True

    # Deserialize wire transaction
    tx_bytes = base64.b64decode(res["transaction_base64"])
    assert len(tx_bytes) <= MAX_TX_BYTES

    tx = VersionedTransaction.from_bytes(tx_bytes)
    # Check signatures are default / unsigned
    for sig in tx.signatures:
        assert sig == Signature.default()

    # Verify instructions inside message
    msg = tx.message
    for compiled_ix in msg.instructions:
        program_id = msg.account_keys[compiled_ix.program_id_index]
        assert program_id in (TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID)
        # Opcode 9 = CloseAccount
        assert compiled_ix.data == bytes([9]), f"Unexpected opcode in claim tx: {compiled_ix.data}"


def test_filter_empty_accounts_strictly_skips_non_zero():
    accounts = [
        {"pubkey": "acc1", "amount": 0, "lamports": 1000},
        {"pubkey": "acc2", "amount": 1, "lamports": 1000},
        {"pubkey": "acc3", "amount": 1000000, "lamports": 1000},
        {"pubkey": "acc4", "amount": 0, "lamports": 2000},
    ]
    empty = filter_empty_accounts(accounts)
    assert len(empty) == 2
    assert [a["pubkey"] for a in empty] == ["acc1", "acc4"]


def test_integer_lamport_conversion():
    assert sol_from_lamports(2039280) == "0.002039280"
    assert sol_from_lamports(1000000000) == "1.000000000"
    assert sol_from_lamports(0) == "0.000000000"

    with pytest.raises(TypeError):
        sol_from_lamports(0.002)  # type: ignore

    with pytest.raises(TypeError):
        sol_from_lamports("100")  # type: ignore

    with pytest.raises(ValueError):
        sol_from_lamports(-100)


def test_mtu_batch_size_cap():
    wallet = Pubkey.new_unique()
    # Create 30 empty accounts (exceeding MAX_BATCH_SIZE = 18)
    reclaimable = [
        {"pubkey": str(Pubkey.new_unique()), "lamports": 2039280, "amount": 0, "program_id": TOKEN_PROGRAM_ID}
        for _ in range(50)
    ]
    blockhash = str(Hash.default())

    # Default batch size = 18 fits in MTU
    res = compile_claim_transaction_payload(wallet, reclaimable, blockhash)
    assert res["status"] == "ready"
    assert res["total_empty_found"] == 50
    assert res["accounts_closed_in_batch"] == MAX_BATCH_SIZE
    assert res["tx_bytes_length"] <= MAX_TX_BYTES

    # Large candidate batch triggers binary MTU trimming
    res_large = compile_claim_transaction_payload(wallet, reclaimable, blockhash, max_batch_size=50)
    assert res_large["status"] == "ready"
    assert res_large["trimmed"] is True
    assert res_large["tx_bytes_length"] <= MAX_TX_BYTES
