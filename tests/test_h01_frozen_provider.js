// Regression test for HOTFIX H-01: Frozen provider object compatibility
// Ensures wallet providers after Object.freeze() do not throw "Cannot define property _hasClaimeAccountListener, object is not extensible"
// and that listeners are not registered twice, and that listener registration errors do not abort claim flow.

const fs = require('fs');
const assert = require('assert');
const vm = require('vm');

const rawJs = fs.readFileSync('./web/static/js/claime.js', 'utf8');
const claimeJsContent = rawJs.replace(
    "})();",
    "window.setCurrentScanDataForTesting = (data) => { currentScanData = data; };\n})();"
);

console.log("==================================================");
console.log("⚡ HOTFIX H-01 TEST SUITE: FROZEN WALLET PROVIDER");
console.log("==================================================");

const SCANNED_WALLET = "FNB2fv2S5T2CjfzCF6BJ6pzUAJ8YH1iTca4BrECqJnQL";
const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

function createMockElement(id = "", className = "") {
    const el = {
        id,
        className,
        classList: {
            contains: (cls) => className.split(" ").includes(cls),
            add: (cls) => { className += " " + cls; },
            remove: (cls) => { className = className.replace(cls, "").trim(); },
        },
        dataset: {},
        style: {},
        innerHTML: "",
        textContent: "",
        disabled: false,
        addEventListener: () => {},
        remove: () => {},
        querySelector: () => null,
        closest: () => el,
    };
    return el;
}

function createTestContext(provider) {
    const elements = new Map();
    const txDebug = createMockElement("txDebug");
    const scanResult = createMockElement("scanResult");
    const walletInput = createMockElement("walletInput");
    walletInput.value = SCANNED_WALLET;
    const rentBtn = createMockElement("rentBtn", "scan-action rent-action");
    rentBtn.dataset.address = SCANNED_WALLET;

    elements.set("txDebug", txDebug);
    elements.set("scanResult", scanResult);
    elements.set("walletInput", walletInput);
    elements.set("rentBtn", rentBtn);

    const doc = {
        getElementById: (id) => elements.get(id) || null,
        querySelector: (sel) => {
            if (sel.includes("rent-action")) return rentBtn;
            const cleanId = sel.replace("#", "");
            return elements.get(cleanId) || null;
        },
        querySelectorAll: () => [rentBtn],
        createElement: (tag) => createMockElement("", ""),
    };

    const mockSolanaWeb3 = {
        VersionedTransaction: {
            deserialize: (bytes) => ({
                message: {
                    header: { numRequiredSignatures: 1 },
                    staticAccountKeys: [
                        SCANNED_WALLET,
                        "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                        TOKEN_PROGRAM_ID,
                    ],
                    addressTableLookups: [],
                    compiledInstructions: [
                        {
                            programIdIndex: 2,
                            accountKeyIndexes: [1, 0, 0],
                            data: new Uint8Array([9]), // CloseAccount
                        },
                    ],
                },
            }),
        },
    };

    const sandbox = {
        document: doc,
        solanaWeb3: mockSolanaWeb3,
        fetch: async (url, opts) => {
            if (typeof url === "string" && url.includes("/api/rent/build-tx")) {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        status: "ready",
                        transaction_base64: Buffer.from("dummy-tx-bytes").toString("base64"),
                        close_accounts: [{ pubkey: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", amount: 0 }],
                        accounts_closed_in_batch: 1,
                        total_empty_found: 1,
                        estimated_reclaimed_sol: "0.00203928",
                        lamports_reclaimed: 2039280,
                    }),
                };
            }
            if (typeof url === "string" && url.includes("/api/tx/status")) {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({ status: "confirmed" }),
                };
            }
            if (typeof url === "string" && url.includes("/api/rent/confirm")) {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({ status: "ok" }),
                };
            }
            if (typeof url === "string" && url.includes("/api/tx/simulate")) {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({ ok: true, logs: [], units_consumed: 1500, error: null }),
                };
            }
            return { ok: true, status: 200, json: async () => ({}) };
        },
        setTimeout: (fn) => { if (typeof fn === 'function') fn(); return 1; },
        clearTimeout: () => {},
        setInterval: () => 1,
        clearInterval: () => {},
        location: { href: "https://quillhog.xyz/claime" },
        AbortController: AbortController,
        atob: (str) => Buffer.from(str, 'base64').toString('binary'),
        btoa: (str) => Buffer.from(str, 'binary').toString('base64'),
        console: console,
    };
    sandbox.window = sandbox;
    if (provider) {
        sandbox.window.solana = provider;
    }

    vm.createContext(sandbox);
    vm.runInContext(claimeJsContent, sandbox);
    return { ctx: sandbox, elements, win: sandbox };
}

async function runTests() {
    let testCount = 0;

    // --- TEST 1: ensureConnected on Object.freeze(provider) does not throw ---
    {
        let listenerRegistrations = 0;
        const providerObj = {
            isConnected: true,
            publicKey: {
                toBase58: () => SCANNED_WALLET,
            },
            on: (event, handler) => {
                if (event === "accountChanged") {
                    listenerRegistrations++;
                }
            },
            connect: async () => {},
            signAndSendTransaction: async () => ({ signature: "mockSig111" }),
        };
        const frozenProvider = Object.freeze(providerObj);
        assert.ok(Object.isFrozen(frozenProvider), "Provider must be frozen");

        const { ctx } = createTestContext(frozenProvider);

        // First call
        await ctx.ensureConnected(frozenProvider, SCANNED_WALLET);
        assert.strictEqual(listenerRegistrations, 1, "Listener should be registered exactly once");

        // Second call on the same provider - must not re-register
        await ctx.ensureConnected(frozenProvider, SCANNED_WALLET);
        assert.strictEqual(listenerRegistrations, 1, "Listener must NOT be registered a second time on same provider");

        console.log("✔ Test 1 passed: ensureConnected works with Object.freeze(provider) and registers listener once");
        testCount++;
    }

    // --- TEST 2: executeClaim flow with Object.freeze(provider) ---
    {
        let signCalled = false;
        const providerObj = {
            isConnected: true,
            publicKey: {
                toBase58: () => SCANNED_WALLET,
            },
            on: (event, handler) => {},
            connect: async () => {},
            signAndSendTransaction: async () => {
                signCalled = true;
                return { signature: "mockSigClaim123" };
            },
        };
        const frozenProvider = Object.freeze(providerObj);

        const { ctx, elements } = createTestContext(frozenProvider);

        // Mock helpers in ctx to bypass heavy crypto disassembly & polling
        ctx.validateAndDisassembleClaimTransaction = () => true;
        ctx.simulatePreflightTransaction = async () => ({ ok: true, success: true, feeExceeds: false });
        ctx.processTransactionResolution = async () => ({ confirmed: true, signature: "mockSigClaim123" });
        ctx.confirmClaimWithRetry = async () => true;

        // Set current scan data
        ctx.setCurrentScanDataForTesting({
            accounts: [{ address: "TokenAcc1", mint: "Mint1", amount: 0, rent_lamports: 2039280 }],
            total_reclaimable_sol: "0.00203928",
            scanned_address: SCANNED_WALLET,
            network_fee_lamports: 5000,
            accounts_closed_in_batch: 1,
            total_empty_found: 1,
        });

        const btn = elements.get("rentBtn");
        await ctx.executeClaim(SCANNED_WALLET);

        assert.strictEqual(signCalled, true, "signAndSendTransaction must be called during claim flow");
        console.log("✔ Test 2 passed: executeClaim completes without exception on frozen provider");
        testCount++;
    }

    // --- TEST 3: provider.on throwing error does not abort ensureConnected or claim ---
    {
        const faultyProviderObj = {
            isConnected: true,
            publicKey: {
                toBase58: () => SCANNED_WALLET,
            },
            on: (event, handler) => {
                throw new Error("Simulated on() registration failure on non-standard wallet");
            },
            connect: async () => {},
            signAndSendTransaction: async () => ({ signature: "mockSigFaulty1" }),
        };
        const frozenFaulty = Object.freeze(faultyProviderObj);

        const { ctx } = createTestContext(frozenFaulty);
        await ctx.ensureConnected(frozenFaulty, SCANNED_WALLET);

        console.log("✔ Test 3 passed: provider.on failure gracefully caught, claim connection succeeds");
        testCount++;
    }

    console.log("==================================================");
    console.log(`✅ ALL ${testCount} H-01 FROZEN PROVIDER TESTS PASSED`);
    console.log("==================================================");
}

runTests().catch((err) => {
    console.error("❌ Test failed:", err);
    process.exit(1);
});
