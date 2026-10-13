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

ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
SYSTEM_PROGRAM_ID: Pubkey = Pubkey.from_string("11111111111111111111111111111111")

# Native Wrapped SOL Mint
WSOL_MINT: str = "So11111111111111111111111111111111111111112"
USDC_MINT: str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

# Standard SPL Token Account Rent Exemption Reserve (in Lamports: 0.00203928 SOL)
LAMPORTS_PER_RENT: int = 2_039_280

# Solana IPv6 / UDP packet MTU ceiling: 1232 bytes serialized transaction limit
MAX_BATCH_SIZE: int = 15

# Architectural Ceiling for Platform Fee: 0.00% (0 basis points)
# Rule D-03: Hardcoded upper bound. Environment variables CANNOT exceed this.
MAX_FEE_BPS: int = 0


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


# ── ON-CHAIN INSTRUCTION COMPILER ─────────────────────────────────────────────

from claim_core import create_close_account_instruction


def parse_owned_token_accounts(
    accounts_list: List[Dict[str, Any]],
    program_id: Union[Pubkey, str],
    owner: Union[Pubkey, str],
) -> List[Dict[str, Any]]:
    """Extract usable parsed token-account fields, requiring the requested token owner."""
    prog_pk = Pubkey.from_string(program_id) if isinstance(program_id, str) else program_id
    owner_str = str(owner).strip()
    parsed_accounts: List[Dict[str, Any]] = []
    if not isinstance(accounts_list, list):
        return parsed_accounts

    for item in accounts_list:
        if not isinstance(item, dict):
            continue
        pubkey = item.get("pubkey")
        account = item.get("account")
        data = account.get("data") if isinstance(account, dict) else None
        parsed = data.get("parsed") if isinstance(data, dict) else None
        info = parsed.get("info") if isinstance(parsed, dict) else None
        if not isinstance(pubkey, str) or not pubkey or not isinstance(info, dict):
            continue
        if str(info.get("owner", "")).strip() != owner_str:
            continue

        token_amount = info.get("tokenAmount")
        if not isinstance(token_amount, dict) or "amount" not in token_amount:
            continue
        raw_amount = token_amount.get("amount")
        if raw_amount is None or isinstance(raw_amount, bool):
            continue
        try:
            amount = int(raw_amount)
            decimals = int(token_amount.get("decimals", 0) or 0)
        except (TypeError, ValueError):
            continue
        if amount < 0 or amount >= 2**64 or not 0 <= decimals <= 255:
            continue

        extensions = parsed.get("extensions") or info.get("extensions") or []
        extension_names: List[str] = []
        close_authority = info.get("closeAuthority")
        withheld_amount = _scan_integer(info.get("withheldAmount"))
        if isinstance(extensions, list):
            for extension in extensions:
                if not isinstance(extension, dict):
                    continue
                extension_name = str(extension.get("extension", ""))
                extension_names.append(extension_name)
                state = extension.get("state")
                if not isinstance(state, dict):
                    continue
                if extension_name == "closeAuthority":
                    close_authority = state.get("closeAuthority")
                elif extension_name == "transferFeeAmount":
                    withheld_amount = _scan_integer(state.get("withheldAmount"))

        mint = info.get("mint")
        if not isinstance(mint, str) or not mint:
            continue
        parsed_accounts.append({
            "pubkey": pubkey,
            "program_id": prog_pk,
            "mint": mint,
            "amount": amount,
            "decimals": decimals,
            "state": str(info.get("state", "")).lower(),
            "close_authority": close_authority,
            "withheld_amount": withheld_amount,
            "extensions": extension_names,
        })

    return parsed_accounts


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

    raw_lamports = acc_data.get("lamports")
    if not isinstance(raw_lamports, int) or isinstance(raw_lamports, bool) or raw_lamports <= 0:
        return False, False, 0, "MISSING_LAMPORTS"
    lamports = raw_lamports
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
    if not isinstance(token_amount, dict) or "amount" not in token_amount:
        return False, False, 0, "MISSING_TOKEN_AMOUNT"
    raw_amount = token_amount.get("amount")
    if raw_amount is None or isinstance(raw_amount, bool):
        return False, False, 0, "INVALID_TOKEN_AMOUNT"
    try:
        amount = int(raw_amount)
    except (ValueError, TypeError):
        return False, False, 0, "INVALID_TOKEN_AMOUNT"
    if amount < 0:
        return False, False, 0, "INVALID_TOKEN_AMOUNT"

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
        if amount > 0:
            return True, True, lamports, "WSOL_ELIGIBLE"
        return True, False, lamports, "EMPTY_BALANCE_ELIGIBLE"

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
            account_data = item.get("account")
            data = account_data.get("data") if isinstance(account_data, dict) else None
            parsed = data.get("parsed") if isinstance(data, dict) else None
            info = parsed.get("info") if isinstance(parsed, dict) else None
            token_amount = info.get("tokenAmount") if isinstance(info, dict) else None
            raw_amount = token_amount.get("amount", 0) if isinstance(token_amount, dict) else 0
            amount = _scan_integer(raw_amount)
            if is_wsol:
                wsol_count += 1
                wsol_lamports_total += lamports
                reclaimable.append({
                    "pubkey": pubkey_str,
                    "program_id": prog_pk,
                    "lamports": lamports,
                    "amount": amount,
                    "is_wsol": True,
                })
            else:
                empty_standard_count += 1
                reclaimable.append({
                    "pubkey": pubkey_str,
                    "program_id": prog_pk,
                    "lamports": lamports,
                    "amount": amount,
                    "is_wsol": False,
                })

    return reclaimable, empty_standard_count, wsol_count, wsol_lamports_total


def _scan_integer(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _sol_from_lamports(lamports: int) -> str:
    whole_sol, fractional_lamports = divmod(lamports, 1_000_000_000)
    return f"{whole_sol}.{fractional_lamports:09d}"


def summarize_scan_accounts(
    accounts_list: Any,
    native_lamports: int = 0,
    mint_info: Optional[Dict[str, Any]] = None,
    mint_info_available: bool = True,
    owner: Optional[Union[Pubkey, str]] = None,
) -> Dict[str, Any]:
    """Summarize scan classifications using only fields present in fetched accounts."""
    native_lamports = _scan_integer(native_lamports)
    rent_accounts = 0
    rent_lamports = 0
    skipped_accounts: List[Dict[str, Any]] = []
    rent_details: List[Dict[str, Any]] = []

    for item in accounts_list if isinstance(accounts_list, list) else []:
        if not isinstance(item, dict):
            continue
        account = item.get("account")
        account = account if isinstance(account, dict) else {}
        data = account.get("data")
        data = data if isinstance(data, dict) else {}
        parsed = data.get("parsed")
        parsed = parsed if isinstance(parsed, dict) else {}
        info = parsed.get("info")
        info = info if isinstance(info, dict) else {}
        token_amount = info.get("tokenAmount")
        token_amount = token_amount if isinstance(token_amount, dict) else {}

        amount = _scan_integer(token_amount.get("amount"))
        decimals = _scan_integer(token_amount.get("decimals"))
        mint = info.get("mint")
        mint = mint if isinstance(mint, str) and mint else ""
        if not mint:
            continue

        pubkey_str = str(item.get("pubkey", ""))
        acc_owner = account.get("owner")
        prog_pk = TOKEN_2022_PROGRAM_ID if str(acc_owner) == str(TOKEN_2022_PROGRAM_ID) else TOKEN_PROGRAM_ID
        item_owner = str(owner).strip() if owner else str(info.get("owner", "")).strip()

        eval_item = item if pubkey_str else {**item, "pubkey": "11111111111111111111111111111111"}
        is_eligible, is_wsol_elig, elig_lamports, elig_reason = evaluate_account_eligibility(
            account_item=eval_item,
            program_id=prog_pk,
            owner=item_owner,
        )

        account_lamports = _scan_integer(account.get("lamports"))

        if amount == 0:
            if is_eligible:
                rent_accounts += 1
                rent_lamports += account_lamports
                if len(rent_details) < 5:
                    rent_details.append({"mint": mint, "lamports": account_lamports})
            else:
                reason_map = {
                    "FROZEN_ACCOUNT": "frozen",
                    "TOKEN2022_WITHHELD_FEES_PRESENT": "fee_withheld",
                    "CLOSE_AUTHORITY_MISMATCH": "authority",
                }
                mapped_reason = reason_map.get(elig_reason, elig_reason.lower())
                skipped_accounts.append({
                    "pubkey": pubkey_str,
                    "mint": mint,
                    "reason": mapped_reason,
                    "lamports": account_lamports,
                })

    return {
        "native_lamports": native_lamports,
        "native_sol": _sol_from_lamports(native_lamports),
        "rent_accounts": rent_accounts,
        "rent_lamports": rent_lamports,
        "rent_sol": _sol_from_lamports(rent_lamports),
        "skipped_accounts": skipped_accounts,
        "rent_details": rent_details,
        "mint_info_available": mint_info_available,
    }


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

