# QUILLHOG // CLAIME

> **100% Non-Custodial Solana Rent Reclaimer.**  
> Verifiable, open-source engine for reclaiming locked SOL rent deposits from empty SPL Token and Token-2022 accounts.
> 
> **Source of rent-claim logic running at quillhog.xyz, production SHA 861fb55**

---

## ⚡ What is Claime?

Claime is a non-custodial tool for inspecting Solana accounts and reclaiming locked SOL rent deposits from empty token accounts:

* **What it does:** Scans a Solana wallet for empty SPL and Token-2022 token accounts (`amount == 0`), compiles unsigned `VersionedTransaction` payloads containing `CloseAccount` instructions, and releases the rent reserve (~0.00203928 SOL per account) directly back to the wallet.
* **100% Non-Custodial:** The server never generates, handles, or stores private keys or seed phrases. All transaction payloads are compiled as unsigned messages (`Signature.default()`).
* **User signs only:** The user reviews, simulates, and signs transactions exclusively inside their own self-custody wallet (e.g. Phantom, Solflare).
* **0% Protocol Fee:** Quillhog charges a 0% protocol fee. 100% of the reclaimed rent SOL goes directly to your wallet. Standard Solana network signature fees apply and are paid directly to network validators.
* **Owner-Only Destination:** Every close instruction strictly hardcodes `dest == owner == signer`. Funds cannot be diverted to any third party.
* **Client-Side Bytecode Firewall:** `claime.js` inspects transaction bytecode before signing to guarantee that only `CloseAccount` instructions are present and that reclaimed SOL returns strictly to the signer.
* **Fail-Closed Simulation:** Pre-flight RPC simulation verifies transactions before prompt. If simulation fails or is unavailable, transaction execution immediately halts without prompting the wallet.
* **Integer Arithmetic:** All financial and lamport calculations use pure integer arithmetic. Floating-point math is strictly forbidden.

---

## 📁 Repository Structure

```text
├── claim_core.py             # Pure transaction compilation core & binary MTU packer
├── core_verify.py            # Account eligibility rules & verification invariants
├── rent_service.py           # Standalone FastAPI service (scan, build-tx, simulate, status, qr, confirm)
├── rpc_pool.py               # Resilient Solana RPC failover client
├── web/
│   └── static/
│       └── js/
│           └── claime.js     # Client-side rent claim engine, bytecode firewall & simulation
├── tests/
│   ├── test_claim_core.py                    # Pytest: compiler invariants & MTU boundaries
│   ├── test_core_verify.py                   # Pytest: eligibility & non-custodial rules
│   ├── test_rent_service.py                  # Pytest: service endpoints, simulate & rate-limiting
│   ├── test_f008_antidrainer.js              # Node: client-side bytecode inspection & firewall
│   ├── test_f010_computebudget.js            # Node: compute budget limits & signer checks
│   ├── test_tx_simulate.js                   # Node: fail-closed simulation behavior
│   ├── test_h01_frozen_provider.js           # Node: frozen wallet provider compatibility
│   ├── test_c16_thank_you_screen.js          # Node: post-claim thank you screen & balance display
│   ├── test_f025_input_validation.js         # Node: wallet address input validation
│   ├── test_f014_batches_and_concurrency.js  # Node: batching & concurrency controls
│   ├── test_b17_success_message_preserved.js # Node: confirmation UI preservation
│   └── test_f012_tx_status.js                # Node: on-chain confirmation status polling
├── requirements.txt          # Python dependencies
├── LICENSE                   # MIT License
├── NOTICE                    # Mandatory notice
└── README.md
```

---

## Scope

This repository contains only the rent-claim core.

---

## 🧪 Testing & Verification

### Python Tests (Pytest)
Requires Python >= 3.10:
```bash
pip install -r requirements.txt
pytest -v
```

### Node Tests (Client-Side Verification)
Requires Node.js >= 18:
```bash
for test in tests/*.js; do node "$test"; done
```

---

## 📜 License & Compliance

Published under the MIT License. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
