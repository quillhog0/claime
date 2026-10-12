# QUILLHOG // CLAIME CORE

> **100% Non-Custodial Solana Rent Reclaimer Engine.**  
> Pure, deterministic Python core for constructing unsigned Solana transactions that close empty SPL and Token-2022 token accounts and return rent deposits directly to the wallet owner.

---

## ⚡ What is Claime Core?

Claime Core contains the pure transaction compilation and invariant enforcement logic extracted directly from Quillhog Claime:

* **100% Non-Custodial:** Emits only unsigned `VersionedTransaction` payloads (`Signature.default()`). The compiler never generates, accesses, or holds private keys.
* **Strict Invariant Guard:** Hardcodes `dest == owner == signer` on all `CloseAccount` instructions. Reclaimed SOL rent returns exclusively to the signing owner wallet.
* **Zero Burns / Zero Transfers:** Never burns tokens (no opcode 8 instructions) and never transfers tokens. Closes empty (`amount == 0`) accounts only.
* **MTU Safety:** Binary search transaction packing ensuring serialized wire payloads strictly fit inside the Solana UDP MTU ceiling (<= 1232 bytes).
* **Integer Financials:** Pure integer lamport arithmetic without floating-point calculations.

---

## 🚫 What is NOT in this Repository

This repository publishes **exclusively the core transaction compilation engine**. It does not contain:

* Network RPC polling / endpoints,
* Proprietary rate-limiting, telemetry, and analytics,
* Revoke / Leash / Split / Wrap transaction builders,
* Frontend UI, styling, and Web3 wallet adapters,
* Deployment configuration or other Quillhog internal services.

The live production deployment at [quillhog.xyz/claime](https://quillhog.xyz/claime) includes these extended features while executing this exact open-source core logic for claim-rent compilation.

---

## 🧪 Testing & Verification

Requirements: Python >= 3.10 with `solders` and `pytest`.

Install dependencies:
```bash
pip install -r requirements.txt
```

Run test suite:
```bash
pytest -v
```
