/**
 * Quillhog Claime — Inactive Token Account Rent Reclaimer Client Logic
 * Non-custodial, 0% protocol fee, ephemeral direct CloseAccount signing.
 */

(function () {
    "use strict";

    function escapeHtml(s) {
        if (typeof s !== "string") return s;
        return s
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    let currentScanData = null;
    let lastSuccessSignature = "";
    let lastSuccessAddress = "";
    const accountListenerProviders = new WeakSet();

    const getSolanaProvider = async () => {
        for (let i = 0; i < 3; i++) {
            if (window.backpack?.solana) return { provider: window.backpack.solana, name: "Backpack" };
            if (window.backpack) return { provider: window.backpack, name: "Backpack" };
            if (window.solflare) return { provider: window.solflare, name: "Solflare" };
            if (window.phantom?.solana) return { provider: window.phantom.solana, name: "Phantom" };
            if (window.solana) {
                const isBackpack = Boolean(window.solana.isBackpack || window.backpack);
                const isPhantom = Boolean(window.solana.isPhantom);
                return {
                    provider: window.solana,
                    name: isBackpack ? "Backpack" : isPhantom ? "Phantom" : "Solana",
                };
            }
            await new Promise((r) => setTimeout(r, 50));
        }
        return null;
    };

    function getConnectedSolanaProvider() {
        const providers = [
            window.backpack?.solana,
            window.backpack,
            window.solflare,
            window.phantom?.solana,
            window.solana,
        ].filter(Boolean);
        const provider = providers.find((candidate) => candidate.isConnected && candidate.publicKey);
        return provider ? { provider } : null;
    }

    function resetClaimeUIState() {
        const dbgDiv = document.getElementById("txDebug");
        if (dbgDiv) {
            dbgDiv.innerHTML = "";
            dbgDiv.style.display = "none";
        }
    }

    function scanCount(data, key) {
        const value = data[key];
        return typeof value === "number" && Number.isFinite(value) && value >= 0
            ? Math.trunc(value)
            : 0;
    }

    const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const USDT_MINT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
    const WSOL_MINT = "So11111111111111111111111111111111111111112";

    const KNOWN_MINTS = {
        [USDC_MINT]: "USDC",
        [USDT_MINT]: "USDT",
        [WSOL_MINT]: "WSOL",
    };

    let cachedNetworkFee = null;

    function shortenIdentifier(value) {
        if (typeof value !== "string" || !value) return "Unavailable";
        return `${value.slice(0, 4)}...${value.slice(-4)}`;
    }

    function formatTokenMint(value) {
        if (typeof value !== "string" || !value) return "Unavailable";
        if (KNOWN_MINTS[value]) return KNOWN_MINTS[value];
        return shortenIdentifier(value);
    }

    function renderTokenMint(value) {
        if (typeof value !== "string" || !value) return "<span>Unavailable</span>";
        if (KNOWN_MINTS[value]) {
            return `<span class="token-name">${escapeHtml(KNOWN_MINTS[value])}</span>`;
        }
        const short = escapeHtml(shortenIdentifier(value));
        const safeMint = escapeHtml(value);
        return `<span class="token-mint-wrap"><span class="token-mint-short">${short}</span> <span class="token-mint-actions"><button type="button" class="btn-copy-mint" data-mint="${safeMint}" aria-label="Copy mint address">copy</button> <a href="https://explorer.solana.com/address/${safeMint}" target="_blank" rel="noopener noreferrer" class="link-explorer" aria-label="View mint on Solana Explorer">explorer</a></span></span>`;
    }

    function renderAddressWithActions(addr) {
        if (!addr || typeof addr !== "string") return "<span>Unavailable</span>";
        const short = escapeHtml(shortenIdentifier(addr));
        const safeAddr = escapeHtml(addr);
        return `<span class="token-mint-wrap"><span class="token-mint-short">${short}</span> <span class="token-mint-actions"><button type="button" class="btn-copy-mint" data-mint="${safeAddr}" aria-label="Copy address">copy</button> <a href="https://explorer.solana.com/address/${safeAddr}" target="_blank" rel="noopener noreferrer" class="link-explorer" aria-label="View address on Solana Explorer">explorer</a></span></span>`;
    }

    const U64_MAX = 18446744073709551615n;

    function formatRawTokenAmount(rawUnits, decimals) {
        try {
            const rawStr = String(rawUnits ?? "0");
            const bi = BigInt(rawStr);
            if (bi === U64_MAX) return "unlimited";
            const dec = Number(decimals ?? 0);
            if (dec === 0 || isNaN(dec)) return rawStr;
            const divisor = 10n ** BigInt(dec);
            const integerPart = bi / divisor;
            const remainder = bi % divisor;
            if (remainder === 0n) return integerPart.toString();
            const fracStr = remainder.toString().padStart(dec, "0").replace(/0+$/, "");
            return `${integerPart}.${fracStr}`;
        } catch (_) {
            if (String(rawUnits ?? "") === "18446744073709551615") return "unlimited";
            return String(rawUnits ?? "0");
        }
    }

    function calculateNetYield(rentLamports, networkFeeLamports) {
        try {
            const rent = BigInt(rentLamports ?? 0);
            if (networkFeeLamports === null || networkFeeLamports === undefined) {
                return {
                    hasFee: false,
                    feeLamports: null,
                    feeSol: null,
                    netLamports: rent,
                    netSol: formatLamports(rent),
                };
            }
            const fee = BigInt(networkFeeLamports);
            const net = rent > fee ? rent - fee : 0n;
            return {
                hasFee: true,
                feeLamports: fee,
                feeSol: formatLamports(fee),
                netLamports: net,
                netSol: formatLamports(net),
            };
        } catch (_) {
            return {
                hasFee: false,
                feeLamports: null,
                feeSol: null,
                netLamports: 0n,
                netSol: "0.000000000",
            };
        }
    }

    function scanDetails(items, renderItem) {
        if (!Array.isArray(items) || items.length === 0) return "";
        return `<div class="scan-details">${items.slice(0, 5).map(renderItem).join("")}</div>`;
    }

    function scanHasPositiveInteger(data, key) {
        try {
            return BigInt(data[key] ?? 0) > 0n;
        } catch (_) {
            return false;
        }
    }

    function formatLamports(value) {
        try {
            const lamports = BigInt(value ?? 0);
            if (lamports < 0n) return "0.000000000";
            return `${lamports / 1000000000n}.${(lamports % 1000000000n).toString().padStart(9, "0")}`;
        } catch (_) {
            return "0.000000000";
        }
    }

    function trimSolAmount(val) {
        if (val === null || typeof val === "undefined") return "0";
        let str = "";
        if (typeof val === "bigint" || (typeof val === "number" && Number.isInteger(val))) {
            str = formatLamports(val);
        } else {
            str = String(val).trim();
        }
        if (!str.includes(".")) {
            return str || "0";
        }
        // Remove trailing zeros after decimal point
        let trimmed = str.replace(/0+$/, "");
        if (trimmed.endsWith(".")) {
            trimmed = trimmed.slice(0, -1);
        }
        if (!trimmed || trimmed === "0" || trimmed === "-0") {
            return "0";
        }
        return trimmed;
    }

    function plural(n, singular, pluralForm) {
        return n === 1 ? `${n} ${singular}` : `${n} ${pluralForm}`;
    }

    function renderScan(data, addr) {
        const resDiv = document.getElementById("scanResult");
        const nativeLamports = data.native_lamports ?? 0;
        let belowFeeReserve = true;
        try {
            belowFeeReserve = BigInt(nativeLamports) < 10000n;
        } catch (_) {}

        const nativeSol = typeof data.native_sol === "string"
            ? data.native_sol
            : formatLamports(nativeLamports);
        const rentAccounts = scanCount(data, "rent_accounts");
        const rentSol = typeof data.rent_sol === "string" ? data.rent_sol : formatLamports(data.rent_lamports);

        const scanTreeDetails = (items, renderItem) => {
            if (!Array.isArray(items) || items.length === 0) return "";
            const slice = items.slice(0, 10);
            return `<div class="scan-details">${slice.map((item, idx) => {
                const isLast = idx === slice.length - 1;
                const branch = isLast ? "└── " : "├── ";
                return `<div class="scan-detail-item"><span class="scan-detail-branch">${branch}</span>${renderItem(item)}</div>`;
            }).join("")}</div>`;
        };

        const rentDetails = scanTreeDetails(data.rent_details, (item) =>
            `<span class="scan-detail-content"><span class="scan-detail-info"><span class="scan-detail-addr">${renderTokenMint(item.mint)}</span><span class="scan-detail-amount"><span class="bullet-sep"> &bull; </span>${escapeHtml(formatLamports(item.lamports))} SOL</span></span></span>`
        );

        currentScanData = data;

        const feeLamports = (data && data.network_fee_lamports !== undefined && data.network_fee_lamports !== null)
            ? data.network_fee_lamports
            : (cachedNetworkFee ? cachedNetworkFee.feeLamports : null);
        const netYield = calculateNetYield(data.rent_lamports, feeLamports);

        resDiv.innerHTML = `
            <!-- Hero Reclaim Box -->
            <div class="scan-hero-box">
                <div class="scan-hero-top">
                    <span class="scan-hero-label">// SCAN DONE</span>
                    <span class="scan-hero-wallet">${renderAddressWithActions(addr)}</span>
                </div>
                <div class="scan-hero-main">
                    <div>
                        <div class="scan-hero-amount">${rentAccounts > 0 ? `${escapeHtml(rentSol)} SOL` : "0.000000000 SOL"}</div>
                        <div class="scan-hero-sub">
                            ${rentAccounts > 0 
                                ? `${rentAccounts} empty token ${rentAccounts === 1 ? "account" : "accounts"} &bull; <span class="nobr-fee">0%&nbsp;PROTOCOL&nbsp;FEE</span>`
                                : "0 empty accounts to close"}
                        </div>
                        ${rentAccounts > 0 ? `
                        <div class="scan-hero-fee">
                            ${netYield.hasFee
                                ? `Network fee: ~${escapeHtml(netYield.feeSol)} SOL per signature (paid to Solana validators) &bull; Net yield: ~${escapeHtml(netYield.netSol)} SOL`
                                : `Estimated validator network fee (~0.000005–0.000015 SOL per batch) determined at signing based on live cluster state<span class="scan-fee-proto-tag"> &bull; 0% protocol fee</span>`}
                        </div>
                        ` : ""}
                    </div>
                </div>
                ${rentAccounts > 0 ? `
                    <button class="btn-primary scan-hero-btn rent-action" type="button" data-address="${escapeHtml(addr)}" ${belowFeeReserve ? "disabled" : ""}>
                        CLAIM RENT &bull; ${escapeHtml(rentSol)} SOL
                    </button>
                ` : ""}
                <div class="scan-hero-meta">
                    <span>NATIVE BALANCE: ${escapeHtml(nativeSol)} SOL</span>
                    <span>STATUS: ${rentAccounts > 0 ? "RECLAIM READY" : "NOTHING TO CLOSE"}</span>
                </div>
            </div>

            <!-- Detailed Breakdown List -->
            <div class="scan-lines">
                <div class="scan-group">
                    <div class="scan-line">
                        <span class="scan-line-label">RENT.</span>
                        <span class="scan-line-total">${rentAccounts} empty &bull; ${escapeHtml(rentSol)} SOL</span>
                        ${rentAccounts > 0 ? `<button class="scan-action rent-action" type="button" data-address="${escapeHtml(addr)}" ${belowFeeReserve ? "disabled" : ""}>Close these accounts</button>` : "<span></span>"}
                    </div>
                    ${rentAccounts > 0 ? rentDetails : ""}
                </div>

            </div>

            ${rentAccounts > 0 && belowFeeReserve ? `<div class="scan-fee-message" role="status">Not enough SOL for the network fee (minimum 0.000010000 SOL required).</div>` : ""}


            <div class="scan-notice">// NOTICE. Public Solana ledger inspection. Network fees apply.</div>
            <div id="txDebug" class="tx-debug" style="display:none;"></div>
        `;
    }

    let scanRequestId = 0;
    let scanAbortController = null;

    function formatBatchNotice(closedInBatch, totalEmpty) {
        if (typeof totalEmpty === "number" && typeof closedInBatch === "number" && totalEmpty > closedInBatch) {
            return `This transaction closes ${closedInBatch} of ${totalEmpty} accounts (batch size 15). Run again for the rest.`;
        }
        return null;
    }

    async function scanAddress() {
        resetClaimeUIState();
        const input = document.getElementById("walletInput");
        const addr = input ? input.value.trim() : "";
        const resDiv = document.getElementById("scanResult");
        const checkBtn = document.getElementById("checkBtn");

        function renderScanError(msg) {
            if (resDiv) {
                resDiv.style.display = "block";
                if (typeof resDiv.setAttribute === "function") {
                    resDiv.setAttribute("role", "alert");
                }
                resDiv.textContent = msg;
                resDiv.innerHTML = `<div class="scan-error-box" role="alert" style="border: 1px solid var(--quill); padding: 12px; margin-top: 10px; font-family: var(--font-mono); color: var(--cream); overflow-wrap: anywhere;">${escapeHtml(msg)}</div>`;
            }
        }

        if (!addr) {
            renderScanError("Paste a Solana wallet address first.");
            if (input && typeof input.focus === "function") {
                input.focus();
            }
            return;
        }

        if (addr.length < 32 || addr.length > 44) {
            renderScanError(`That does not look like a Solana address. Invalid address length (${addr.length} chars; must be between 32 and 44).`);
            if (input && typeof input.focus === "function") {
                input.focus();
            }
            return;
        }

        if (!/^[1-9A-HJ-NP-Za-km-z]+$/.test(addr)) {
            renderScanError("That does not look like a Solana address. Invalid base58 format (characters 0, O, I, l are forbidden).");
            if (input && typeof input.focus === "function") {
                input.focus();
            }
            return;
        }

        if (addr !== lastSuccessAddress) {
            lastSuccessSignature = "";
            lastSuccessAddress = "";
        }

        const Controller = typeof AbortController !== "undefined"
            ? AbortController
            : (typeof window !== "undefined" && window.AbortController ? window.AbortController : null);

        if (Controller) {
            if (scanAbortController) {
                scanAbortController.abort();
            }
            scanAbortController = new Controller();
        }
        const currentReqId = ++scanRequestId;

        if (checkBtn) {
            checkBtn.disabled = true;
        }

        currentScanData = null;
        if (resDiv) {
            resDiv.style.display = "block";
            if (typeof resDiv.setAttribute === "function") {
                resDiv.setAttribute("aria-live", "polite");
            }
            if (typeof resDiv.removeAttribute === "function") {
                resDiv.removeAttribute("role");
            }
            resDiv.innerHTML = `
                <div class="scan-loading-box">
                    <span class="scanning-pulse">Reading token accounts… → Checking delegates… → Done</span>
                    <div class="scan-loading-hint">usually 2–7 seconds</div>
                </div>
            `;
        }

        try {
            const resp = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ wallet_address: addr }),
                signal: scanAbortController ? scanAbortController.signal : undefined,
            });

            if (currentReqId < scanRequestId) {
                return;
            }

            if (resp.status === 400) {
                let errorMsg = "Invalid address.";
                try {
                    const errData = await resp.json();
                    const detailStr = (typeof errData?.detail === "object" ? errData?.detail?.detail : errData?.detail) || "";
                    if (detailStr.includes("is a system or program account") || errData?.detail?.error_code === "SYSTEM_PROGRAM_NOT_WALLET") {
                        errorMsg = detailStr;
                    }
                } catch (_) {}
                renderScanError(errorMsg);
                return;
            }

            if (resp.status === 429) {
                const retryAfter = resp.headers?.get ? resp.headers.get("Retry-After") : null;
                const seconds = retryAfter ? escapeHtml(String(retryAfter)) : "30";
                renderScanError(`Rate limit exceeded. Try again in ${seconds} seconds.`);
                return;
            }

            if (resp.status >= 500) {
                renderScanError("Something went wrong on our side. Try again.");
                return;
            }

            const data = await resp.json();
            if (currentReqId < scanRequestId) {
                return;
            }

            if (!resp.ok) {
                renderScanError("Something went wrong on our side. Try again.");
                return;
            }

            renderScan(data, addr);
        } catch (err) {
            if (err && (err.name === "AbortError" || err.message === "The user aborted a request.")) {
                return;
            }
            if (currentReqId === scanRequestId && resDiv) {
                renderScanError("Something went wrong on our side. Try again.");
            }
        } finally {
            if (currentReqId === scanRequestId && checkBtn) {
                checkBtn.disabled = false;
            }
        }
    }

    const ALLOWED_CLAIM_PROGRAMS = new Set([
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // SPL Token
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", // Token-2022
        "ComputeBudget111111111111111111111111111111", // Compute Budget
    ]);

    /**
     * F-008: Bit-level client-side bytecode verification of the unsigned VersionedTransaction.
     * Enforces mathematical invariant: destination == owner == signer across all token instructions.
     * Strictly rejects Address Lookup Tables, untrusted programs, non-CloseAccount opcodes, and drainers.
     */
    function validateAndDisassembleClaimTransaction(versionedTx, walletAddress, buildData = null) {
        if (!versionedTx || !versionedTx.message) {
            throw new Error("Invalid transaction structure: missing message payload.");
        }
        const msg = versionedTx.message;

        // F-008: Reject Address Lookup Tables (ALTs) - Claim txs must be static
        if (msg.addressTableLookups && msg.addressTableLookups.length > 0) {
            throw new Error(
                "SECURITY ALERT: Untrusted Address Lookup Tables detected. Claim transactions must use static accounts only."
            );
        }

        const staticKeys = msg.staticAccountKeys
            ? msg.staticAccountKeys.map((k) =>
                  typeof k.toBase58 === "function" ? k.toBase58() : String(k)
              )
            : [];

        if (!staticKeys || staticKeys.length === 0) {
            throw new Error("SECURITY ALERT: Transaction contains no static accounts.");
        }

        // Safety caps for ComputeBudget instructions (approx. 0.0001 SOL priority fee cap)
        const MAX_CU_LIMIT = 400000;
        const MAX_CU_PRICE_MICROLAMPORTS = 100000n;
        const MAX_PRIORITY_FEE_LAMPORTS = 100000n;

        // T-010: Verify exactly 1 required signer matching walletAddress
        const numSigners = msg.header ? msg.header.numRequiredSignatures : 1;
        if (numSigners !== 1 || staticKeys[0] !== walletAddress) {
            throw new Error(
                `SECURITY ALERT: Transaction must have exactly 1 signer matching wallet ${walletAddress} (got ${numSigners} signers, staticKeys[0]=${staticKeys[0]}).`
            );
        }

        const compiledInstructions = msg.compiledInstructions || [];
        if (compiledInstructions.length === 0) {
            throw new Error("SECURITY ALERT: Transaction contains 0 instructions.");
        }

        // T-010: Mandatory buildData.close_accounts verification
        if (!buildData || !Array.isArray(buildData.close_accounts)) {
            throw new Error("SECURITY ALERT: server omitted close_accounts");
        }

        let closeCount = 0;
        const closedAccounts = [];
        const closeAccounts = new Map(
            buildData.close_accounts.map((account) => [account.pubkey, account.amount])
        );
        const programsUsed = new Set();
        let cuLimitSeen = false;
        let cuLimit = null;
        let cuPriceSeen = false;
        let cuPriceMicroLamports = null;

        for (let i = 0; i < compiledInstructions.length; i++) {
            const ix = compiledInstructions[i];
            if (ix.programIdIndex >= staticKeys.length) {
                throw new Error(`SECURITY ALERT: Instruction ${i} references out-of-bounds program index.`);
            }
            const programId = staticKeys[ix.programIdIndex];
            programsUsed.add(programId);

            if (!ALLOWED_CLAIM_PROGRAMS.has(programId)) {
                throw new Error(
                    `SECURITY ALERT: Untrusted program call detected in transaction: ${programId}`
                );
            }

            if (programId === "ComputeBudget111111111111111111111111111111") {
                const dataBytes = ix.data;
                // T-010: Reject opcode 0, 1, and >3; allow at most one opcode 2 and one opcode 3
                if (!dataBytes || dataBytes.length === 0) {
                    throw new Error("SECURITY ALERT: Empty ComputeBudget instruction data.");
                }
                const opcode = dataBytes[0];
                if (opcode !== 2 && opcode !== 3) {
                    throw new Error(
                        `SECURITY ALERT: Disallowed ComputeBudget opcode detected: ${opcode}. Only SetComputeUnitLimit (2) and SetComputeUnitPrice (3) are permitted.`
                    );
                }
                if (opcode === 2) {
                    if (cuLimitSeen) {
                        throw new Error("SECURITY ALERT: Duplicate SetComputeUnitLimit instruction detected.");
                    }
                    cuLimitSeen = true;
                    if (dataBytes.length !== 5) {
                        throw new Error(
                            `SECURITY ALERT: Invalid data length for SetComputeUnitLimit: expected 5 bytes, got ${dataBytes.length}.`
                        );
                    }
                    cuLimit = (
                        (dataBytes[1] |
                        (dataBytes[2] << 8) |
                        (dataBytes[3] << 16) |
                        (dataBytes[4] << 24)) >>> 0
                    );
                    if (cuLimit > MAX_CU_LIMIT) {
                        throw new Error(
                            `SECURITY ALERT: Compute unit limit exceeds safe ceiling (${cuLimit} > ${MAX_CU_LIMIT}).`
                        );
                    }
                } else if (opcode === 3) {
                    if (cuPriceSeen) {
                        throw new Error("SECURITY ALERT: Duplicate SetComputeUnitPrice instruction detected.");
                    }
                    cuPriceSeen = true;
                    if (dataBytes.length !== 9) {
                        throw new Error(
                            `SECURITY ALERT: Invalid data length for SetComputeUnitPrice: expected 9 bytes, got ${dataBytes.length}.`
                        );
                    }
                    let priceVal = 0n;
                    for (let b = 0; b < 8; b++) {
                        priceVal |= BigInt(dataBytes[1 + b]) << BigInt(8 * b);
                    }
                    cuPriceMicroLamports = priceVal;
                    if (cuPriceMicroLamports > MAX_CU_PRICE_MICROLAMPORTS) {
                        throw new Error(
                            `SECURITY ALERT: Compute unit price exceeds safe ceiling (${cuPriceMicroLamports} > ${MAX_CU_PRICE_MICROLAMPORTS}).`
                        );
                    }
                }
                continue;
            }

            if (
                programId === "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" ||
                programId === "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
            ) {
                const dataBytes = ix.data;
                if (!dataBytes || dataBytes.length < 1) {
                    throw new Error(`SECURITY ALERT: Empty instruction data in token instruction ${i}.`);
                }
                // Check instruction byte for CloseAccount (opcode 9)
                if (dataBytes[0] === 8 || dataBytes[0] === 15) {
                    throw new Error(
                        `SECURITY ALERT: Burn instruction opcode ${dataBytes[0]} is forbidden.`
                    );
                }
                if (dataBytes[0] !== 9) {
                    throw new Error(
                        `SECURITY ALERT: Non-CloseAccount instruction detected in token program! Opcode: ${dataBytes[0]} (CloseAccount is 9)`
                    );
                }

                // Verify accounts structure for CloseAccount: [source_account, destination, owner]
                const accountIndices = ix.accountKeyIndexes;
                if (!accountIndices || accountIndices.length < 3) {
                    throw new Error(
                        `SECURITY ALERT: CloseAccount instruction ${i} missing required account keys (expected 3, got ${accountIndices ? accountIndices.length : 0}).`
                    );
                }
                if (accountIndices.length > 3) {
                    throw new Error(
                        `SECURITY ALERT: CloseAccount instruction ${i} contains unexpected extra multisig accounts.`
                    );
                }

                if (
                    accountIndices[0] >= staticKeys.length ||
                    accountIndices[1] >= staticKeys.length ||
                    accountIndices[2] >= staticKeys.length
                ) {
                    throw new Error(`SECURITY ALERT: Instruction ${i} contains out-of-bounds account index.`);
                }

                const sourceAcc = staticKeys[accountIndices[0]];
                const destKey = staticKeys[accountIndices[1]];
                const ownerKey = staticKeys[accountIndices[2]];

                if (!closeAccounts.has(sourceAcc) || BigInt(closeAccounts.get(sourceAcc)) !== 0n) {
                    throw new Error("CloseAccount may close only token accounts with amount zero.");
                }

                if (destKey !== walletAddress) {
                    throw new Error(
                        `SECURITY ALERT: CloseAccount destination does not match wallet! Got ${destKey}, expected ${walletAddress}`
                    );
                }

                if (ownerKey !== walletAddress) {
                    throw new Error(
                        `SECURITY ALERT: CloseAccount owner/authority does not match wallet! Got ${ownerKey}, expected ${walletAddress}`
                    );
                }

                closedAccounts.push(sourceAcc);
                closeCount++;
            }
        }

        // T-010: Verify product limit * price <= MAX_PRIORITY_FEE_LAMPORTS
        if (cuPriceSeen) {
            const effectiveLimit = cuLimitSeen ? BigInt(cuLimit) : 200000n;
            const priorityFeeLamports = (effectiveLimit * cuPriceMicroLamports) / 1000000n;
            if (priorityFeeLamports > MAX_PRIORITY_FEE_LAMPORTS) {
                throw new Error(
                    `SECURITY ALERT: ComputeBudget total priority fee exceeds safe ceiling (${priorityFeeLamports} > ${MAX_PRIORITY_FEE_LAMPORTS} lamports).`
                );
            }
        }

        if (closeCount === 0) {
            throw new Error("SECURITY ALERT: Transaction contains 0 verified CloseAccount instructions.");
        }
        if (closeCount !== closeAccounts.size) {
            throw new Error("CloseAccount account metadata does not match the transaction.");
        }

        const friendlyPrograms = Array.from(programsUsed).map((p) => {
            if (p === "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA") return "SPL Token";
            if (p === "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb") return "Token-2022";
            if (p === "ComputeBudget111111111111111111111111111111") return "Compute Budget";
            return p;
        });

        return {
            isValid: true,
            closeCount: closeCount,
            closedAccounts: closedAccounts,
            programs: friendlyPrograms,
            destination: walletAddress,
            owner: walletAddress,
            protocolFeeBps: 0,
            outgoingTransfers: 0,
        };
    }

    function validateClaimTransactionClientSide(versionedTx, walletAddress, buildData) {
        const verification = validateAndDisassembleClaimTransaction(versionedTx, walletAddress, buildData);
        return verification.closeCount;
    }

    function setActionButtonsFlightState(inFlight) {
        if (typeof document === "undefined" || !document.querySelectorAll) return;
        const buttons = document.querySelectorAll(".scan-action, .rent-action");
        buttons.forEach((btn) => {
            if (inFlight) {
                btn.dataset.prevDisabled = btn.disabled ? "1" : "0";
                btn.disabled = true;
            } else {
                const wasDisabled = btn.dataset.prevDisabled === "1";
                delete btn.dataset.prevDisabled;
                if (wasDisabled) {
                    btn.disabled = true;
                } else {
                    btn.disabled = false;
                }
            }
        });
    }

    async function ensureConnected(provider, expectedAddr) {
        if (!provider) {
            throw new Error("No wallet provider available.");
        }

        if (!provider.isConnected) {
            if (typeof provider.connect !== "function") {
                throw new Error("Wallet provider does not support connect().");
            }
            await provider.connect();
        }

        if (!provider.publicKey) {
            throw new Error("Wallet connected but has no public key.");
        }

        const connectedAddr =
            typeof provider.publicKey.toBase58 === "function"
                ? provider.publicKey.toBase58()
                : String(provider.publicKey);

        if (typeof provider.on === "function" && !accountListenerProviders.has(provider)) {
            accountListenerProviders.add(provider);
            try {
                provider.on("accountChanged", (newPubkey) => {
                    if (!newPubkey) return;
                    const newAddr = typeof newPubkey.toBase58 === "function" ? newPubkey.toBase58() : String(newPubkey);
                    const input = typeof document !== "undefined" && document.getElementById ? document.getElementById("walletInput") : null;
                    const currentVal = input ? input.value.trim() : "";
                    if (currentVal && currentVal !== newAddr) {
                        const dbg = typeof document !== "undefined" && document.getElementById ? document.getElementById("txDebug") : null;
                        if (dbg) {
                            dbg.style.display = "block";
                            dbg.innerHTML = `
                                <div style="margin-top:12px; padding:12px 14px; border:1px solid var(--quill); background:rgba(255,86,0,0.08); font-size:13px; line-height:1.5; color:#FEEFD9;">
                                    <span style="color:var(--quill); font-weight:700;">⚠ Wallet switched account</span><br/>
                                    Active in wallet: <strong style="color:var(--quill);">${escapeHtml(shortenIdentifier(newAddr))}</strong><br/>
                                    Scanned address: <strong style="color:var(--quill);">${escapeHtml(shortenIdentifier(currentVal))}</strong><br/>
                                    <div style="margin-top:8px; font-size:13px;">
                                        <button type="button" id="btnSwitchToConnected" style="background:none; border:none; color:var(--quill); text-decoration:underline; cursor:pointer; font-weight:700; padding:0; font-family:inherit;">Switch scanner to active wallet (${escapeHtml(shortenIdentifier(newAddr))})</button>
                                    </div>
                                </div>
                            `;
                            const btn = dbg.querySelector("#btnSwitchToConnected");
                            if (btn) {
                                btn.addEventListener("click", () => {
                                    if (input) input.value = newAddr;
                                    if (typeof window.scanAddress === "function") {
                                        window.scanAddress();
                                    }
                                });
                            }
                        }
                    }
                });
            } catch (err) {
                // Ignore listener registration failures on non-standard providers
            }
        }

        if (connectedAddr !== expectedAddr) {
            const dbg = typeof document !== "undefined" && document.getElementById ? document.getElementById("txDebug") : null;
            if (dbg) {
                dbg.style.display = "block";
                dbg.innerHTML = `
                    <div style="margin-top:12px; padding:12px 14px; border:1px solid var(--quill); background:rgba(255,86,0,0.08); font-size:13px; line-height:1.5; color:#FEEFD9;">
                        <span style="color:var(--quill); font-weight:700;">⚠ Wallet account mismatch</span><br/>
                        Active in wallet: <strong style="color:var(--quill);">${escapeHtml(shortenIdentifier(connectedAddr))}</strong><br/>
                        Scanned address: <strong style="color:var(--quill);">${escapeHtml(shortenIdentifier(expectedAddr))}</strong><br/>
                        <div style="margin-top:8px; font-size:13px;">
                            Switch account in Solflare/Phantom to match <strong>${escapeHtml(shortenIdentifier(expectedAddr))}</strong>, or <button type="button" id="btnSwitchToConnected" style="background:none; border:none; color:var(--quill); text-decoration:underline; cursor:pointer; font-weight:700; padding:0; font-family:inherit;">switch scanner to active wallet (${escapeHtml(shortenIdentifier(connectedAddr))})</button>.
                        </div>
                    </div>
                `;
                const btnSwitch = dbg.querySelector("#btnSwitchToConnected");
                if (btnSwitch) {
                    btnSwitch.addEventListener("click", () => {
                        const input = typeof document !== "undefined" && document.getElementById ? document.getElementById("walletInput") : null;
                        if (input) input.value = connectedAddr;
                        if (typeof window.scanAddress === "function") {
                            window.scanAddress();
                        }
                    });
                }
            }
            throw new Error("Connected wallet does not match the scanned address");
        }

        return connectedAddr;
    }
    const ensureConnectedWalletMatch = ensureConnected;

    function extractSignature(res) {
        if (typeof res === "string") return res;
        if (res && typeof res === "object") {
            const rawSig =
                res.signature !== undefined
                    ? res.signature
                    : res.txSignature || res.txid || res;
            if (typeof rawSig === "string") return rawSig;
            if (rawSig instanceof Uint8Array || Array.isArray(rawSig)) {
                if (window.solanaWeb3?.bs58) {
                    return window.solanaWeb3.bs58.encode(Uint8Array.from(rawSig));
                }
                if (window.solanaWeb3?.PublicKey) {
                    return new window.solanaWeb3.PublicKey(rawSig).toBase58();
                }
                return String(rawSig);
            }
            if (typeof rawSig?.toString === "function" && rawSig.toString() !== "[object Object]") {
                return rawSig.toString();
            }
        }
        return null;
    }

    async function simulatePreflightTransaction(transactionBase64, statusDiv, onRetry = null) {
        if (!transactionBase64) return { ok: true };

        const showSafetyUnavailable = () => {
            if (statusDiv) {
                statusDiv.style.display = "block";
                statusDiv.innerHTML = `<span class="tx-error-msg" style="color:var(--quill); line-height:1.4;">✕ Safety check unavailable – nothing was sent. Try again in a minute.</span> <button type="button" class="btn-try-again" id="btnSimulateTryAgain" style="margin-left:10px; background:var(--card); border:1px solid var(--quill); color:var(--cream); padding:4px 10px; font-family:inherit; font-size:12px; cursor:pointer;">Try again</button>`;
                const btn = statusDiv.querySelector("#btnSimulateTryAgain") || statusDiv.querySelector(".btn-try-again");
                if (btn && typeof onRetry === "function") {
                    btn.onclick = (e) => {
                        if (e && e.preventDefault) e.preventDefault();
                        onRetry();
                    };
                }
            }
        };

        const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
        const timeoutId = controller ? setTimeout(() => controller.abort(), 15000) : null;
        try {
            if (statusDiv) {
                statusDiv.style.display = "block";
                statusDiv.innerHTML = "<span class='scanning-pulse' style='display:block; margin-top:10px; font-size:13px;'>● Simulating transaction pre-flight on-chain...</span>";
            }
            const fetchOpts = {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ transaction_base64: transactionBase64 }),
            };
            if (controller) {
                fetchOpts.signal = controller.signal;
            }
            const resp = await fetch("/api/tx/simulate", fetchOpts);
            if (!resp || !resp.ok) {
                showSafetyUnavailable();
                return { ok: false, safetyUnavailable: true, error: "Safety check unavailable – nothing was sent. Try again in a minute." };
            }
            let data;
            try {
                data = await resp.json();
            } catch {
                showSafetyUnavailable();
                return { ok: false, safetyUnavailable: true, error: "Safety check unavailable – nothing was sent. Try again in a minute." };
            }
            if (!data || typeof data !== "object") {
                showSafetyUnavailable();
                return { ok: false, safetyUnavailable: true, error: "Safety check unavailable – nothing was sent. Try again in a minute." };
            }
            if (data.ok === false) {
                return { ok: false, safetyUnavailable: false, error: data.error || "Simulation reported an execution error.", logs: data.logs };
            }
            return { ok: true, units_consumed: data?.units_consumed };
        } catch {
            showSafetyUnavailable();
            return { ok: false, safetyUnavailable: true, error: "Safety check unavailable – nothing was sent. Try again in a minute." };
        } finally {
            if (timeoutId) clearTimeout(timeoutId);
        }
    }

    async function pollTransactionStatus(signature, statusDiv, maxWaitMs = 90000, targetCommitment = "confirmed") {
        const startTime = Date.now();
        let delayMs = 1000;
        const sigExplorerLink = `<a href="https://solscan.io/tx/${escapeHtml(signature)}" target="_blank" rel="noopener" style="color:var(--quill); text-decoration:underline;">${escapeHtml(shortenIdentifier(signature))}</a>`;

        if (statusDiv && targetCommitment !== "finalized") {
            statusDiv.style.display = "block";
            statusDiv.innerHTML = `<span class="scanning-pulse" style="display:block; margin-top:10px; font-size:13px;">Submitted – waiting for confirmation… (${sigExplorerLink})</span>`;
        }

        while (Date.now() - startTime < maxWaitMs) {
            try {
                const resp = await fetch(`/api/tx/status?sig=${encodeURIComponent(signature)}`);
                if (resp.ok) {
                    const data = await resp.json();
                    if (data.status === "failed") {
                        return { status: "failed", err: data.err };
                    }
                    const isFinalized = data.status === "finalized" || data.commitment === "finalized";
                    if (targetCommitment === "finalized") {
                        if (isFinalized) {
                            return { status: "confirmed", commitment: "finalized" };
                        }
                    } else {
                        if (data.status === "confirmed" || isFinalized) {
                            return { status: "confirmed", commitment: data.commitment || "confirmed" };
                        }
                    }
                }
            } catch (e) {
                // Ignore transient network errors during poll
            }
            await new Promise((r) => setTimeout(r, delayMs));
            delayMs = Math.min(delayMs * 1.5, 5000);
        }

        return { status: "timeout" };
    }

    async function confirmClaimWithRetry(wallet, signature, buildData, maxRetries = 5) {
        let delay = 1000;
        for (let i = 0; i < maxRetries; i++) {
            try {
                const res = await fetch("/api/rent/confirm", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        wallet: wallet,
                        signature: signature,
                        accounts_closed: buildData.accounts_closed_in_batch,
                    }),
                });
                if (res.status === 200) {
                    return await res.json();
                }
                if (res.status === 202) {
                    await new Promise((r) => setTimeout(r, delay));
                    delay = Math.min(delay * 2, 5000);
                    continue;
                }
                break;
            } catch (e) {
                await new Promise((r) => setTimeout(r, delay));
                delay = Math.min(delay * 2, 5000);
            }
        }
        return null;
    }

    async function processTransactionResolution({
        signature,
        statusElement,
        pollFn = (typeof window !== "undefined" && window.pollTransactionStatus) ? window.pollTransactionStatus : pollTransactionStatus,
        onConfirmed,
        onFailed,
        onTimeout,
    }) {
        const pollRes = await pollFn(signature, statusElement);
        if (pollRes && pollRes.status === "confirmed") {
            if (typeof onConfirmed === "function") {
                await onConfirmed(pollRes);
            }
            return { status: "confirmed", pollRes };
        } else if (pollRes && pollRes.status === "failed") {
            if (typeof onFailed === "function") {
                await onFailed(pollRes);
            } else if (statusElement) {
                statusElement.style.display = "block";
                statusElement.innerHTML = `<span class="tx-error-msg" style="color:var(--quill); margin-top:10px; display:block;">✕ Transaction failed on-chain. <a href="https://solscan.io/tx/${escapeHtml(signature)}" target="_blank" rel="noopener" style="color:var(--quill); text-decoration:underline;">View on Solscan ↗</a></span>`;
            }
            return { status: "failed", pollRes };
        } else {
            if (typeof onTimeout === "function") {
                await onTimeout(pollRes);
            } else if (statusElement) {
                statusElement.style.display = "block";
                statusElement.innerHTML = `<span style="color:var(--muted-gray); margin-top:10px; display:block;">Not confirmed yet – check the signature in an explorer: <a href="https://solscan.io/tx/${escapeHtml(signature)}" target="_blank" rel="noopener" style="color:var(--quill); text-decoration:underline;">${escapeHtml(signature)}</a></span>`;
            }
            return { status: "timeout", pollRes };
        }
    }

    async function executeClaim(targetAddr) {
        lastSuccessSignature = "";
        lastSuccessAddress = "";
        const dbgDiv = document.getElementById("txDebug");
        const rentButton = document.querySelector(".rent-action");
        const addr =
            targetAddr ||
            rentButton?.dataset?.address ||
            document.getElementById("walletInput")?.value?.trim() ||
            "";

        if (!addr) return;

        setActionButtonsFlightState(true);

        if (dbgDiv) {
            dbgDiv.style.display = "block";
            dbgDiv.innerHTML =
                "<span class='scanning-pulse' style='display:block; margin-top:10px; font-size:13px;'>● Verifying bytecode and preparing transaction...</span>";
        }

        try {
            const resp = await fetch("/api/rent/build-tx", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ wallet_address: addr }),
            });
            const buildData = await resp.json();

            if (buildData.status !== "ready" || !buildData.transaction_base64) {
                const isZeroAccounts =
                    buildData.status === "empty" ||
                    buildData.accounts_closed_in_batch === 0 ||
                    (buildData.message &&
                        buildData.message.toLowerCase().includes("no reclaimable"));

                if (isZeroAccounts) {
                    if (dbgDiv) {
                        dbgDiv.style.display = "block";
                        dbgDiv.textContent = "No rent to return.";
                    }
                    return;
                }

                if (dbgDiv) {
                    const errMsg =
                        typeof buildData.detail === "object" && buildData.detail?.detail
                            ? buildData.detail.detail
                            : typeof buildData.detail === "string"
                            ? buildData.detail
                            : buildData.message || "Failed to compile transaction.";

                    dbgDiv.style.display = "block";
                    dbgDiv.innerHTML = `<span class="tx-error-msg" style="color:var(--quill); margin-top:10px; line-height:1.4;">✕ ${escapeHtml(
                        errMsg
                    )}</span>`;
                }
                return;
            }

            if (typeof solanaWeb3 === "undefined" || !solanaWeb3.VersionedTransaction) {
                throw new Error("Client runtime error: Solana Web3 library not loaded.");
            }

            const txBytes = Uint8Array.from(atob(buildData.transaction_base64), (c) => c.charCodeAt(0));
            const versionedTx = solanaWeb3.VersionedTransaction.deserialize(txBytes);

            validateAndDisassembleClaimTransaction(versionedTx, addr, buildData);

            const batchNotice = formatBatchNotice(buildData.accounts_closed_in_batch, buildData.total_empty_found);
            const batchNoticeHtml = batchNotice
                ? `<div class="batch-notice" style="color:var(--cream); margin-top:6px; font-size:13px;">${escapeHtml(batchNotice)}</div>`
                : "";

            const sim = await simulatePreflightTransaction(buildData.transaction_base64, dbgDiv, () => executeClaim(addr));
            if (!sim.ok) {
                if (sim.safetyUnavailable) {
                    return;
                }
                throw new Error(`Pre-flight simulation failed: ${sim.error}`);
            }

            if (dbgDiv) {
                dbgDiv.innerHTML = `<span class='scanning-pulse' style='display:block; margin-top:10px; font-size:13px; color:var(--quill);'>Pre-sign check and simulation passed. Prompting wallet for signature...</span>${batchNoticeHtml}`;
            }

            const walletInfo = await getSolanaProvider();
            if (!walletInfo) {
                throw new Error("No wallet extension detected.");
            }
            const provider = walletInfo.provider;
            await ensureConnected(provider, addr);

            const res = await provider.signAndSendTransaction(versionedTx);
            const signature = extractSignature(res);

            if (!signature) {
                throw new Error("Wallet did not return a valid transaction signature.");
            }

            await processTransactionResolution({
                signature,
                statusElement: dbgDiv,
                onConfirmed: async () => {
                    await confirmClaimWithRetry(addr, signature, buildData);

                    const closed = buildData.accounts_closed_in_batch || 0;
                    const total = buildData.total_empty_found || closed;
                    const isAllClosed = total > 0 ? (closed >= total) : true;

                    let reclaimedSol = "";
                    if (buildData) {
                        if (typeof buildData.sol_reclaimed_lamports === "number" || typeof buildData.sol_reclaimed_lamports === "bigint" || (typeof buildData.sol_reclaimed_lamports === "string" && buildData.sol_reclaimed_lamports !== "")) {
                            reclaimedSol = formatLamports(buildData.sol_reclaimed_lamports);
                        } else if (typeof buildData.sol_reclaimed === "string" && buildData.sol_reclaimed) {
                            reclaimedSol = buildData.sol_reclaimed;
                        }
                    }
                    if (!reclaimedSol && currentScanData) {
                        if (typeof currentScanData.rent_lamports !== "undefined" && currentScanData.rent_lamports !== null) {
                            reclaimedSol = formatLamports(currentScanData.rent_lamports);
                        } else if (typeof currentScanData.rent_sol === "string" && currentScanData.rent_sol) {
                            reclaimedSol = currentScanData.rent_sol;
                        }
                    }
                    const scanResContainer = document.getElementById("scanResult");
                    if (scanResContainer) {
                        renderSuccessUI(scanResContainer, signature, reclaimedSol);
                    }

                    if (isAllClosed) {
                        // All accounts closed: keep thank-you screen and DO NOT rescan
                        if (dbgDiv) {
                            dbgDiv.innerHTML = "";
                            dbgDiv.style.display = "none";
                        }
                        return;
                    }

                    // Partial / batch claim: wait until transaction commitment is "finalized", NEVER earlier
                    if (dbgDiv) {
                        const remaining = total - closed;
                        dbgDiv.style.display = "block";
                        dbgDiv.innerHTML = `<div class="batch-remaining-notice" style="color:var(--cream); margin-top:8px; font-size:13px;">✓ Batch confirmed (${closed} accounts closed). ${remaining} accounts remaining to reclaim. Waiting for finalized commitment before updating scanner…</div>`;
                    }

                    await pollTransactionStatus(signature, dbgDiv, 90000, "finalized");

                    if (typeof window.scanAddress === "function") {
                        await window.scanAddress();
                    }
                },
                onFailed: async () => {
                    if (dbgDiv) {
                        dbgDiv.style.display = "block";
                        dbgDiv.innerHTML = `<span class="tx-error-msg" style="color:var(--quill); margin-top:10px; display:block;">✕ Transaction failed on-chain. <a href="https://solscan.io/tx/${escapeHtml(signature)}" target="_blank" rel="noopener" style="color:var(--quill); text-decoration:underline;">View on Solscan ↗</a></span>`;
                    }
                }
            });
        } catch (err) {
            const rawMsg = err?.message || "";
            const isUserRejection =
                rawMsg.toLowerCase().includes("reject") ||
                rawMsg.toLowerCase().includes("cancel") ||
                rawMsg.toLowerCase().includes("user rejected") ||
                err?.code === 4001 ||
                err?.name === "WalletSignTransactionError";

            let displayErr = "Transaction rejected or expired.";
            if (isUserRejection) {
                displayErr = "Transaction cancelled in wallet.";
            } else if (rawMsg.toLowerCase().includes("internal error") || err?.code === -32603) {
                displayErr =
                    "Wallet rejected simulation or window was closed. In Solflare, tick '[✓] I trust this site' to enable Approve, or make sure your active account matches the scanned address.";
            } else if (rawMsg) {
                displayErr = rawMsg;
            }

            if (dbgDiv) {
                dbgDiv.style.display = "block";
                if (dbgDiv.querySelector("#btnSimulateTryAgain") || dbgDiv.querySelector(".btn-try-again")) {
                    return;
                }
                if (err?.message === "Connected wallet does not match the scanned address" && dbgDiv.querySelector("#btnSwitchToConnected")) {
                    // Mismatch banner already rendered
                } else {
                    dbgDiv.innerHTML = `<div class="tx-error-msg" style="color:${
                        isUserRejection ? "var(--muted-gray)" : "var(--quill)"
                    }; margin-top:10px;">✕ ${escapeHtml(displayErr)}</div>`;
                }
            }
        } finally {
            setActionButtonsFlightState(false);
        }
    }

    function renderSuccessUI(container, signature = "", reclaimedSol = "") {
        if (!container) return;
        const dbgDiv = document.getElementById("txDebug");
        if (dbgDiv) {
            dbgDiv.innerHTML = "";
            dbgDiv.style.display = "none";
        }
        if (signature) {
            lastSuccessSignature = signature;
            const input = document.getElementById("walletInput");
            lastSuccessAddress = input ? input.value.trim() : "";
        }

        // Amount calculation: strict integer lamport formatting or formatted string, trimmed for display
        let displayAmount = "";
        if (typeof reclaimedSol === "number" || typeof reclaimedSol === "bigint") {
            displayAmount = trimSolAmount(formatLamports(reclaimedSol));
        } else if (typeof reclaimedSol === "string" && reclaimedSol) {
            displayAmount = trimSolAmount(reclaimedSol);
        } else if (currentScanData && typeof currentScanData.rent_lamports !== "undefined" && currentScanData.rent_lamports !== null) {
            displayAmount = trimSolAmount(formatLamports(currentScanData.rent_lamports));
        } else if (currentScanData && currentScanData.rent_sol) {
            displayAmount = trimSolAmount(currentScanData.rent_sol);
        }
        if (!displayAmount || displayAmount === "0.") {
            displayAmount = "0";
        }

        const shortSig = signature ? `${signature.slice(0, 8)}...${signature.slice(-8)}` : "";
        const sigLink = signature
            ? `<div class="success-tx-link" style="margin-bottom:14px;"><a href="https://solscan.io/tx/${escapeHtml(signature)}" target="_blank" rel="noopener noreferrer" style="color:var(--quill); text-decoration:underline; font-size:13px; font-family:var(--font-mono); word-break:break-all;">✓ View transaction on Solscan ↗ (${escapeHtml(shortSig)})</a></div>`
            : "";

        // Tip address defined in SSOT (docs/QUILLHOG.md)
        const TIP_WALLET_ADDRESS = "Tips6HksSd9QF1fMi7DKkASXoS8qdB1emoDwY3zRzVY";

        container.innerHTML = `
            <div class="scan-success" style="padding:24px 18px; border:1px solid var(--border-subtle); background:var(--card); border-radius:4px; text-align:center; max-width:640px; margin:0 auto; box-sizing:border-box;">
                <h2 class="success-title" style="color:var(--cream); font-size:1.35rem; font-weight:700; letter-spacing:-0.02em; margin-top:0; margin-bottom:10px;">Rent returned.</h2>
                <div class="success-amount" style="font-size:1.25rem; font-weight:700; color:var(--quill); font-family:var(--font-mono); font-variant-numeric:tabular-nums; margin-bottom:14px; word-break:break-word;">+${escapeHtml(displayAmount)} SOL is back in your wallet.</div>
                <div class="success-free-note" style="color:var(--cream); font-size:13.5px; margin-bottom:4px;">0% protocol fee. We take 0% of what you claim.</div>
                <div class="success-tip-prompt" style="color:var(--muted-gray); font-size:13px; margin-bottom:14px;">If Claime saved you time, a tip keeps it running.</div>
                <div class="success-tip-box" style="margin-bottom:14px; display:inline-flex; flex-direction:column; align-items:center; justify-content:center; gap:8px; background:rgba(255,255,255,0.03); border:1px solid var(--border-subtle); padding:10px 14px; border-radius:3px; max-width:100%; box-sizing:border-box;">
                    <div class="tip-address" style="font-family:var(--font-mono); color:var(--cream); font-size:12px; word-break:break-all; user-select:all; -webkit-user-select:all; line-height:1.4;">${escapeHtml(TIP_WALLET_ADDRESS)}</div>
                    <button type="button" id="btnCopyTip" class="btn-copy-tip" aria-label="Copy tip address" style="background:none; border:1px solid var(--border-subtle); color:var(--cream); padding:4px 10px; cursor:pointer; font-family:var(--font-mono); font-size:12px; border-radius:2px;">[Copy]</button>
                </div>
                ${sigLink}
                <div class="success-follow" style="margin-top:0;">
                    <a href="https://x.com/quillhog0" target="_blank" rel="noopener noreferrer" class="btn-follow" style="display:inline-block; color:var(--cream); text-decoration:none; font-family:var(--font-mono); font-size:13px; padding:7px 16px; border:1px solid var(--border-subtle); border-radius:3px;"><span aria-hidden="true">𝕏</span> Follow @quillhog0 on X</a>
                </div>
            </div>
        `;

        const btnCopyTip = typeof container.querySelector === "function" ? container.querySelector("#btnCopyTip") : null;
        if (btnCopyTip) {
            btnCopyTip.addEventListener("click", () => {
                let resetTimer = null;
                const showFeedback = (text, delay) => {
                    btnCopyTip.textContent = text;
                    clearTimeout(resetTimer);
                    resetTimer = setTimeout(() => {
                        btnCopyTip.textContent = "[Copy]";
                    }, delay);
                };

                const onSuccess = () => showFeedback("Copied ✓", 2000);
                const onFailure = () => showFeedback("Copy failed – select the address", 3000);

                if (typeof navigator !== "undefined" && navigator && navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
                    try {
                        const p = navigator.clipboard.writeText(TIP_WALLET_ADDRESS);
                        if (p && typeof p.then === "function") {
                            return p.then(() => {
                                onSuccess();
                            }).catch(() => {
                                onFailure();
                            });
                        } else {
                            onSuccess();
                        }
                    } catch (_) {
                        onFailure();
                    }
                } else if (typeof document !== "undefined" && document.createElement) {
                    try {
                        const ta = document.createElement("textarea");
                        ta.value = TIP_WALLET_ADDRESS;
                        ta.style.position = "fixed";
                        ta.style.opacity = "0";
                        document.body.appendChild(ta);
                        ta.select();
                        const ok = document.execCommand("copy");
                        document.body.removeChild(ta);
                        if (ok) {
                            onSuccess();
                        } else {
                            onFailure();
                        }
                    } catch (_) {
                        onFailure();
                    }
                } else {
                    onFailure();
                }
            });
        }
    }

    function initClaimeListeners() {
        const walletInput = document.getElementById("walletInput");
        if (walletInput) {
            walletInput.addEventListener("input", (e) => {
                if (e.target.value.trim() !== lastSuccessAddress) {
                    lastSuccessSignature = "";
                    lastSuccessAddress = "";
                }
            });
            walletInput.addEventListener("keydown", (e) => {
                if (e.key === "Enter") {
                    e.preventDefault();
                    scanAddress();
                }
            });
        }

        const checkBtn = document.getElementById("checkBtn");
        if (checkBtn) {
            checkBtn.addEventListener("click", () => {
                scanAddress();
            });
        }

        const scanRes = document.getElementById("scanResult");
        if (scanRes) {
            scanRes.addEventListener("click", (e) => {
                const copyBtn = e.target.closest(".btn-copy-mint");
                if (copyBtn && copyBtn.dataset.mint) {
                    const mintAddr = copyBtn.dataset.mint;
                    if (typeof navigator !== "undefined" && navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(mintAddr).then(() => {
                            const orig = copyBtn.textContent;
                            copyBtn.textContent = "copied";
                            setTimeout(() => { copyBtn.textContent = orig; }, 1500);
                        }).catch(() => {});
                    }
                    return;
                }

                const rentAction = e.target.closest(".rent-action");
                if (rentAction && !rentAction.disabled) {
                    executeClaim(rentAction.dataset.address);
                    return;
                }

            });
        }
    }

    // Expose global methods
    window.scanAddress = scanAddress;
    window.executeClaim = executeClaim;
    window.ensureConnected = ensureConnected;
    window.setActionButtonsFlightState = setActionButtonsFlightState;
    window.escapeHtml = escapeHtml;
    window.validateAndDisassembleClaimTransaction = validateAndDisassembleClaimTransaction;
    window.validateClaimTransactionClientSide = validateClaimTransactionClientSide;
    window.renderScan = renderScan;
    window.simulatePreflightTransaction = simulatePreflightTransaction;
    window.pollTransactionStatus = pollTransactionStatus;
    window.processTransactionResolution = processTransactionResolution;
    window.confirmClaimWithRetry = confirmClaimWithRetry;
    window.extractSignature = extractSignature;
    window.formatBatchNotice = formatBatchNotice;
    window.plural = plural;
    window.renderTokenMint = renderTokenMint;
    window.renderAddressWithActions = renderAddressWithActions;
    window.formatRawTokenAmount = formatRawTokenAmount;
    window.calculateNetYield = calculateNetYield;
    window.KNOWN_MINTS = KNOWN_MINTS;
    window.renderSuccessUI = renderSuccessUI;
    window.trimSolAmount = trimSolAmount;

    function onReady() {
        initClaimeListeners();
    }

    if (document.readyState === "loading") {
        window.addEventListener("DOMContentLoaded", onReady);
    } else {
        onReady();
    }
})();
