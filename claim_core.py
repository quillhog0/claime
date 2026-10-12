"""
Quillhog Claime Core Engine.
Pure, non-custodial Solana transaction compiler for recovering rent from empty token accounts.

Invariants:
1. 100% Non-custodial: Unsigned transactions only (Signature.default()). Server never accesses private keys.
2. Hardened Owner Security: dest == owner == signer. Closed rent returns strictly to the wallet owner.
3. Zero Token Burns: Closes empty (amount == 0) SPL and Token-2022 accounts only. Never burns or transfers tokens.
4. MTU Safe: Binary search batch packing ensuring serialized wire transaction <= 1232 bytes.
5. Integer Arithmetic: All lamport calculations use pure integer math. Zero float.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional, Union

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

# Canonical Solana Program IDs
TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
TOKEN_2022_PROGRAM_ID = Pubkey.from_string("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")

MAX_BATCH_SIZE = 18
MAX_TX_BYTES = 1232


def create_close_account_instruction(
    account: Union[Pubkey, str],
    dest: Union[Pubkey, str],
    owner: Union[Pubkey, str],
    program_id: Union[Pubkey, str] = TOKEN_PROGRAM_ID,
) -> Instruction:
    """
    Compile SPL Token / Token-2022 CloseAccount instruction (instruction index 9).
    Enforces strict non-custodial invariant: dest == owner == signer.
    
    Layout:
    1. account (writable, non-signer)
    2. destination (writable, non-signer)
    3. owner / signer (readonly, signer)
    """
    account_pk = Pubkey.from_string(account) if isinstance(account, str) else account
    dest_pk = Pubkey.from_string(dest) if isinstance(dest, str) else dest
    owner_pk = Pubkey.from_string(owner) if isinstance(owner, str) else owner
    prog_pk = Pubkey.from_string(program_id) if isinstance(program_id, str) else program_id

    if dest_pk != owner_pk:
        raise ValueError(
            f"Non-custodial invariant violation: destination ({dest_pk}) must match owner ({owner_pk})"
        )

    keys = [
        AccountMeta(pubkey=account_pk, is_signer=False, is_writable=True),
        AccountMeta(pubkey=dest_pk, is_signer=False, is_writable=True),
        AccountMeta(pubkey=owner_pk, is_signer=True, is_writable=False),
    ]
    data = bytes([9])  # CloseAccount opcode
    return Instruction(prog_pk, data, keys)


def filter_empty_accounts(accounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter candidate accounts to ensure only zero-balance accounts are selected for closing."""
    return [
        item for item in accounts
        if isinstance(item, dict) and item.get("amount") == 0
    ]


def sol_from_lamports(lamports: int) -> str:
    """Integer-safe conversion from lamports to SOL decimal string without float arithmetic."""
    if not isinstance(lamports, int) or isinstance(lamports, bool):
        raise TypeError(f"lamports must be an int, got {type(lamports).__name__}")
    if lamports < 0:
        raise ValueError("lamports cannot be negative")
    whole = lamports // 1_000_000_000
    rem = lamports % 1_000_000_000
    return f"{whole}.{rem:09d}"


def compile_claim_transaction_payload(
    user_pubkey: Union[Pubkey, str],
    all_reclaimable: List[Dict[str, Any]],
    blockhash_str: str,
    sol_price: Optional[float] = None,
    max_batch_size: int = MAX_BATCH_SIZE,
) -> Dict[str, Any]:
    """
    Constructs unsigned versioned transaction payload for reclaimable accounts with binary MTU trimming.
    
    Returns standard claim execution payload dict.
    Raises ValueError if packet exceeds MTU even for 1 account.
    """
    user_pk = Pubkey.from_string(user_pubkey) if isinstance(user_pubkey, str) else user_pubkey
    user_str = str(user_pk)
    zero_amount_accounts = filter_empty_accounts(all_reclaimable)
    candidate_batch = zero_amount_accounts[:max_batch_size]
    recent_blockhash = Hash.from_string(blockhash_str)

    low = 1
    high = len(candidate_batch)
    best_k = 0
    best_tx_bytes: Optional[bytes] = None
    best_batch: List[Dict[str, Any]] = []

    while low <= high:
        mid = (low + high) // 2
        batch = candidate_batch[:mid]
        instructions = [
            create_close_account_instruction(
                account=Pubkey.from_string(item["pubkey"]) if isinstance(item["pubkey"], str) else item["pubkey"],
                dest=user_pk,
                owner=user_pk,
                program_id=item.get("program_id", TOKEN_PROGRAM_ID),
            )
            for item in batch
        ]
        msg = MessageV0.try_compile(
            payer=user_pk,
            instructions=instructions,
            address_lookup_table_accounts=[],
            recent_blockhash=recent_blockhash,
        )
        signatures = [Signature.default()] * msg.header.num_required_signatures
        tx = VersionedTransaction.populate(msg, signatures)
        b = bytes(tx)
        if len(b) <= MAX_TX_BYTES:
            best_k = mid
            best_tx_bytes = b
            best_batch = batch
            low = mid + 1
        else:
            high = mid - 1

    if best_k == 0 or best_tx_bytes is None:
        raise ValueError("Claim transaction exceeds the Solana packet limit.")

    trimmed = best_k < len(candidate_batch)
    tx_base64 = base64.b64encode(best_tx_bytes).decode("utf-8")
    batch_lamports = sum(int(item.get("lamports", 0)) for item in best_batch)
    batch_reclaimed_sol = sol_from_lamports(batch_lamports)

    return {
        "status": "ready",
        "accounts_closed_in_batch": len(best_batch),
        "total_empty_found": len(zero_amount_accounts),
        "sol_reclaimed": batch_reclaimed_sol,
        "sol_reclaimed_lamports": batch_lamports,
        "tx_bytes_length": len(best_tx_bytes),
        "mtu_safe": True,
        "trimmed": trimmed,
        "transaction_base64": tx_base64,
        "close_accounts": [
            {"pubkey": str(item["pubkey"]), "amount": str(item.get("amount", 0))}
            for item in best_batch
        ],
        "tx_base64_sample": tx_base64[:60] + "...",
        "solscan_sample_url": f"https://solscan.io/account/{user_str}",
    }
