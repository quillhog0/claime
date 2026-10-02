"""
Quillhog Core Verification Module
File: core_verify.py

Pure computational logic and security invariants for Solana Rent Reclaim.
ZERO network I/O, ZERO FastAPI/HTTP dependencies, ZERO database access.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple, Union

from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta


# ── CANONICAL CONSTANTS & INVARIANTS ──────────────────────────────────────────

# Native SPL Token Program
TOKEN_PROGRAM_ID: Pubkey = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

# SPL Token-2022 Program (Token Extensions)
TOKEN_2022_PROGRAM_ID: Pubkey = Pubkey.from_string("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")

# Native Wrapped SOL Mint
WSOL_MINT: str = "So11111111111111111111111111111111111111112"

# Standard SPL Token Account Rent Exemption Reserve (in Lamports: 0.00203928 SOL)
LAMPORTS_PER_RENT: int = 2_039_280

# Solana IPv6 / UDP packet MTU ceiling: 1232 bytes serialized transaction limit
MAX_BATCH_SIZE: int = 15

# Protocol fee is hardcoded to 0% (0 basis points)
# Rule D-03: Hardcoded upper bound. Environment variables CANNOT exceed this.
MAX_FEE_BPS = 0
PROTOCOL_FEE_BPS = 0


# ── PLATFORM FEE VALIDATION & INTEGER ARITHMETIC ─────────────────────────────

def validate_platform_fee_bps(fee_bps: int) -> int:
    """
    Validates that the requested platform fee basis points is within safety bounds [0, MAX_FEE_BPS].
    Raises ValueError if fee_bps is negative or exceeds the hardcoded architectural ceiling (0 bps = 0%).
    """
    if not isinstance(fee_bps, int):
        raise TypeError(f"fee_bps must be an integer, got {type(fee_bps).__name__}")
    if fee_bps < 0:
        raise ValueError(f"fee_bps cannot be negative (got {fee_bps})")
    if fee_bps > MAX_FEE_BPS:
        raise ValueError(
            f"fee_bps {fee_bps} exceeds hardcoded architectural ceiling MAX_FEE_BPS ({MAX_FEE_BPS} bps = 0%)"
        )
    return fee_bps


def calculate_platform_fee_lamports(total_reclaimed_lamports: int, fee_bps: int) -> int:
    """
    Calculate fee in lamports using pure integer arithmetic to prevent floating-point rounding errors.
    Formula: (total_reclaimed_lamports * fee_bps) // 10000
    """
    validated_bps = validate_platform_fee_bps(fee_bps)
    if total_reclaimed_lamports <= 0 or validated_bps == 0:
        return 0
    return (total_reclaimed_lamports * validated_bps) // 10000


# ── ON-CHAIN INSTRUCTION COMPILER ─────────────────────────────────────────────

def create_close_account_instruction(
    account: Union[Pubkey, str],
    dest: Union[Pubkey, str],
    owner: Union[Pubkey, str],
    program_id: Union[Pubkey, str] = TOKEN_PROGRAM_ID,
) -> Instruction:
    """
    Compile SPL Token / Token-2022 CloseAccount instruction (instruction index 9).
    Enforces strict non-custodial invariant: dest == owner.
    
    Layout:
    1. account (writable)
    2. destination (writable)
    3. owner / signer (readonly, signer)
    """
    account_pk = Pubkey.from_string(account) if isinstance(account, str) else account
    dest_pk = Pubkey.from_string(dest) if isinstance(dest, str) else dest
    owner_pk = Pubkey.from_string(owner) if isinstance(owner, str) else owner
    prog_pk = Pubkey.from_string(program_id) if isinstance(program_id, str) else program_id

    # Strict Invariant Verification: Destination MUST equal Owner
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


# ── ACCOUNT ELIGIBILITY & SECURITY FILTERS (SEC-01 TO SEC-04) ─────────────────

def evaluate_account_eligibility(
    account_item: Dict[str, Any],
    program_id: Union[Pubkey, str],
    owner: Union[Pubkey, str],
) -> Tuple[bool, bool, int, str]:
    """
    Pure evaluation of a Solana RPC parsed token account.
    Defensively parses dictionaries to prevent KeyError on missing extension structures.

    Returns:
        (is_eligible: bool, is_wsol: bool, lamports: int, reason: str)
    """
    owner_str = str(owner).strip()
    prog_pk = Pubkey.from_string(program_id) if isinstance(program_id, str) else program_id

    pubkey_str = str(account_item.get("pubkey", ""))
    if not pubkey_str:
        return False, False, 0, "MISSING_PUBKEY"

    acc_data = account_item.get("account")
    if not isinstance(acc_data, dict):
        return False, False, 0, "INVALID_ACCOUNT_DATA"

    lamports = int(acc_data.get("lamports", LAMPORTS_PER_RENT) or LAMPORTS_PER_RENT)
    parsed_root = acc_data.get("data")
    if not isinstance(parsed_root, dict):
        return False, False, 0, "UNPARSED_ACCOUNT_DATA"

    parsed = parsed_root.get("parsed")
    if not isinstance(parsed, dict):
        return False, False, 0, "MISSING_PARSED_PAYLOAD"

    info = parsed.get("info")
    if not isinstance(info, dict):
        return False, False, 0, "MISSING_INFO_DICT"

    mint = str(info.get("mint", ""))
    token_amount = info.get("tokenAmount")
    raw_amount = token_amount.get("amount", 0) if isinstance(token_amount, dict) else 0
    try:
        amount = int(raw_amount or 0)
    except (ValueError, TypeError):
        amount = 0

    # SEC-04: Filter out frozen token accounts
    account_state = str(info.get("state", "")).lower()
    if account_state == "frozen":
        return False, False, 0, "FROZEN_ACCOUNT"

    # Universal Close Authority & Extension Parsing
    close_auth = info.get("closeAuthority")
    withheld_amount = int(info.get("withheldAmount", 0) or 0)

    # Token-2022 Specific Extension Traversal
    if prog_pk == TOKEN_2022_PROGRAM_ID:
        extensions = parsed.get("extensions") or info.get("extensions") or []
        if isinstance(extensions, list):
            for ext in extensions:
                if isinstance(ext, dict):
                    ext_name = ext.get("extension")
                    state = ext.get("state")
                    if isinstance(state, dict):
                        if ext_name == "closeAuthority":
                            close_auth = state.get("closeAuthority")
                        elif ext_name == "transferFeeAmount":
                            withheld_amount = int(state.get("withheldAmount", 0) or 0)

        # SEC-02: Withheld transfer fees prevent account closure on-chain
        if withheld_amount > 0:
            return False, False, 0, "TOKEN2022_WITHHELD_FEES_PRESENT"

    # SEC-01: Universal Close Authority Check
    if close_auth and owner_str and str(close_auth) != owner_str:
        return False, False, 0, "CLOSE_AUTHORITY_MISMATCH"

    # WSOL accounts: Reclaimable even if amount > 0 (unwrapping native SOL)
    if mint == WSOL_MINT:
        return True, True, lamports, "WSOL_ELIGIBLE"

    # Standard SPL accounts: Reclaimable only if balance is zero
    if amount == 0:
        return True, False, lamports, "EMPTY_BALANCE_ELIGIBLE"

    return False, False, 0, "NON_ZERO_BALANCE"


def parse_reclaimable_accounts(
    accounts_list: List[Dict[str, Any]],
    program_id: Union[Pubkey, str],
    owner: Union[Pubkey, str],
) -> Tuple[List[Dict[str, Any]], int, int, int]:
    """
    Pure parser over raw RPC account items.
    
    Returns:
        (reclaimable_items, empty_standard_count, wsol_count, wsol_lamports_total)
    """
    prog_pk = Pubkey.from_string(program_id) if isinstance(program_id, str) else program_id
    reclaimable: List[Dict[str, Any]] = []
    empty_standard_count = 0
    wsol_count = 0
    wsol_lamports_total = 0

    if not isinstance(accounts_list, list):
        return [], 0, 0, 0

    for item in accounts_list:
        if not isinstance(item, dict):
            continue

        is_eligible, is_wsol, lamports, _ = evaluate_account_eligibility(
            account_item=item,
            program_id=prog_pk,
            owner=owner,
        )

        if is_eligible:
            pubkey_str = str(item.get("pubkey", ""))
            if is_wsol:
                wsol_count += 1
                wsol_lamports_total += lamports
                reclaimable.append({
                    "pubkey": pubkey_str,
                    "program_id": prog_pk,
                    "lamports": lamports,
                    "is_wsol": True,
                })
            else:
                empty_standard_count += 1
                reclaimable.append({
                    "pubkey": pubkey_str,
                    "program_id": prog_pk,
                    "lamports": lamports,
                    "is_wsol": False,
                })

    return reclaimable, empty_standard_count, wsol_count, wsol_lamports_total


# ── FAST BASE58 VALIDATION & SOLANA PAY DEEP LINKS (PHASE 1 ENGINE) ──────────

BASE58_ALPHABET = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

def is_valid_base58_address_fast(address: str) -> bool:
    """
    Sub-microsecond Base58 format pre-validation.
    Ensures length is 32-44 characters and contains only valid Base58 characters.
    """
    if not isinstance(address, str):
        return False
    cleaned = address.strip()
    if not (32 <= len(cleaned) <= 44):
        return False
    return all(c in BASE58_ALPHABET for c in cleaned)


def generate_solana_pay_deep_links(
    base_qr_url: str,
    wallet: Optional[str] = None,
    label: str = "Quillhog Claime",
    message: str = "Close empty token accounts",
) -> Dict[str, str]:
    """
    Generates standardized Solana Pay URIs and Mobile Wallet Deep Links (Phantom, Solflare).
    """
    import urllib.parse

    target_url = base_qr_url.strip()
    if wallet:
        param = urllib.parse.urlencode({"wallet": wallet.strip()})
        delimiter = "&" if "?" in target_url else "?"
        target_url = f"{target_url}{delimiter}{param}"

    solana_uri = f"solana:{target_url}"
    encoded_target = urllib.parse.quote(target_url, safe="")

    # Standardized Mobile Deep-link schemas
    phantom_universal = f"https://phantom.app/ul/browse/{encoded_target}?ref=quillhog"
    phantom_native = f"phantom://v1/open?url={encoded_target}"
    solflare_universal = f"https://solflare.com/ul/v1/browse/{encoded_target}"
    solflare_native = f"solflare://ul/v1/browse/{encoded_target}"

    return {
        "solana_pay_uri": solana_uri,
        "target_url": target_url,
        "phantom_universal": phantom_universal,
        "phantom_native": phantom_native,
        "solflare_universal": solflare_universal,
        "solflare_native": solflare_native,
    }

