// Test C-16 / C-17 / C-18: Thank you screen refinement (renderSuccessUI in claime.js)
// Verifies:
// 1. Amount formatting: trimmed trailing zeros (0.001488440 -> 0.00148844, 0.0100000 -> 0.01),
//    whole SOL (1.000000000 -> 1), very small amounts (1 lamport -> 0.000000001),
//    never "0." or empty string.
// 2. Exact C-17/C-18 copy, tip box with [Copy] button, Solscan link, Follow on X.
// 3. Complete absence of obsolete [Scan another wallet] and [Shelf] buttons.
// 4. Full claim does NOT trigger rescan.
// 5. Partial claim waits for 'finalized' commitment before triggering rescan.
const fs = require('fs');
const assert = require('assert');
const vm = require('vm');

const claimeJsContent = fs.readFileSync('./web/static/js/claime.js', 'utf8');

console.log("==================================================");
console.log("⚡ TEST SUITE: C-18 THANK-YOU SCREEN REFINEMENT");
console.log("==================================================");

const DUMMY_WALLET = "FNB2fv2S5T2CjfzCF6BJ6pzUAJ8YH1iTca4BrECqJnQL";
const DUMMY_SIG = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYj7WNXT5w35Lxs5264tzPDf85QZyRzWNWePm8SLhk";
const TIP_WALLET_ADDRESS = "Tips6HksSd9QF1fMi7DKkASXoS8qdB1emoDwY3zRzVY";

function createSandbox({ pollResponses = [], buildTxOverrides = {} }) {
    const elements = new Map();

    function createElement(id = "", className = "") {
        let listeners = {};
        return {
            id,
            className,
            classList: {
                contains: (cls) => (className || "").split(" ").includes(cls),
                add: (cls) => { className = (className || "") + " " + cls; },
                remove: (cls) => {
                    className = (className || "").split(" ").filter(c => c !== cls).join(" ");
                },
            },
            dataset: { address: DUMMY_WALLET },
            style: {},
            innerHTML: "",
            textContent: "",
            value: "",
            disabled: false,
            focused: false,
            focus: function() { this.focused = true; },
            addEventListener: function(event, handler) {
                listeners[event] = listeners[event] || [];
                listeners[event].push(handler);
            },
            dispatchEvent: function(event) {
                const handlers = listeners[event.type || event] || [];
                handlers.forEach(h => h(event));
            },
            click: function() {
                const handlers = listeners["click"] || [];
                handlers.forEach(h => h({ type: "click" }));
            },
            remove: () => {},
            querySelector: function(sel) {
                if (sel === "#btnCopyTip") {
                    return this._btnCopyTip || null;
                }
                return null;
            },
            closest: function() { return this; },
        };
    }

    const scanResult = createElement("scanResult");
    elements.set("scanResult", scanResult);
    const txDebug = createElement("txDebug");
    elements.set("txDebug", txDebug);
    const walletInput = createElement("walletInput");
    walletInput.value = DUMMY_WALLET;
    elements.set("walletInput", walletInput);
    const checkBtn = createElement("checkBtn");
    elements.set("checkBtn", checkBtn);

    const doc = {
        getElementById: (id) => {
            if (!elements.has(id)) elements.set(id, createElement(id));
            return elements.get(id);
        },
        querySelector: (sel) => {
            if (sel === "#checkBtn") return checkBtn;
            if (sel === ".rent-action") {
                const ra = createElement("rentAction", "rent-action");
                ra.dataset.address = DUMMY_WALLET;
                return ra;
            }
            return createElement();
        },
        querySelectorAll: () => [],
        addEventListener: () => {},
        readyState: "complete",
    };

    let pollIndex = 0;
    const dummyBase64 = Buffer.from(new Uint8Array(64)).toString("base64");

    const mockFetch = async (url, opts = {}) => {
        if (url.includes("/api/rent/build-tx")) {
            return {
                ok: true,
                json: async () => ({
                    status: "ready",
                    transaction_base64: dummyBase64,
                    accounts_closed_in_batch: 1,
                    total_empty_found: 1,
                    sol_reclaimed: "0.002039280",
                    sol_reclaimed_lamports: 2039280,
                    close_accounts: [
                        { pubkey: "Account11111111111111111111111111111111", amount: "0" },
                    ],
                    ...buildTxOverrides,
                }),
            };
        }
        if (url.includes("/api/rent/confirm")) {
            return {
                ok: true,
                status: 200,
                json: async () => ({ status: "confirmed", signature: DUMMY_SIG }),
            };
        }
        if (url.includes("/api/tx/simulate")) {
            return {
                ok: true,
                json: async () => ({ ok: true, units_consumed: 5000 }),
            };
        }
        if (url.includes("/api/tx/status")) {
            const resp = pollResponses[Math.min(pollIndex, pollResponses.length - 1)] || {
                status: "confirmed",
                commitment: "confirmed",
                signature: DUMMY_SIG,
            };
            pollIndex++;
            return {
                ok: true,
                json: async () => resp,
            };
        }
        if (url.includes("/api/scan")) {
            return {
                ok: true,
                json: async () => ({
                    status: "ok",
                    wallet_address: DUMMY_WALLET,
                    native_lamports: 50000000,
                    rent_accounts: 0,
                    rent_lamports: 0,
                    network_fee_lamports: 5000,
                    estimated_validator_fee_lamports: 5000,

                }),
            };
        }
        return { ok: true, json: async () => ({}) };
    };

    const mockWallet = {
        isPhantom: true,
        isConnected: true,
        publicKey: { toBase58: () => DUMMY_WALLET },
        connect: async () => ({ publicKey: { toBase58: () => DUMMY_WALLET } }),
        signAndSendTransaction: async () => ({ signature: DUMMY_SIG }),
        on: () => {},
    };

    let clipboardText = "";
    const mockNavigator = {
        clipboard: {
            writeText: async (txt) => {
                clipboardText = txt;
            },
        },
    };

    const sandbox = {
        window: {},
        document: doc,
        fetch: mockFetch,
        solana: mockWallet,
        navigator: mockNavigator,
        getClipboardText: () => clipboardText,
        solanaWeb3: {
            VersionedTransaction: {
                deserialize: () => ({
                    message: {
                        header: { numRequiredSignatures: 1 },
                        staticAccountKeys: [
                            { toBase58: () => DUMMY_WALLET },
                            { toBase58: () => "Account11111111111111111111111111111111" },
                            { toBase58: () => "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" },
                        ],
                        compiledInstructions: [
                            { programIdIndex: 2, data: new Uint8Array([9]), accountKeyIndexes: [1, 0, 0] },
                        ],
                    },
                    signatures: [new Uint8Array(64)],
                    serialize: () => new Uint8Array(64),
                }),
            },
            PublicKey: class { constructor(v) { this.v = v; } toBase58() { return String(this.v); } },
        },
        sessionStorage: { getItem: () => null, setItem: () => null },
        URLSearchParams: class { get() { return null; } },
        atob: (str) => Buffer.from(str, 'base64').toString('binary'),
        btoa: (str) => Buffer.from(str, 'binary').toString('base64'),
        setTimeout: setTimeout,
        clearTimeout: clearTimeout,
        console: { log: () => {}, warn: () => {}, error: () => {} },
    };
    sandbox.window = sandbox;

    vm.createContext(sandbox);
    vm.runInContext(claimeJsContent, sandbox);

    return { sandbox, scanResult, walletInput, txDebug };
}

async function runAllTests() {
    // ----------------------------------------------------
    // TEST 1: renderSuccessUI content verification (C-17/C-18 layout, copy & trimmed amount)
    // ----------------------------------------------------
    {
        const { sandbox, walletInput } = createSandbox({});
        walletInput.value = DUMMY_WALLET;

        const container = {
            innerHTML: "",
            querySelector: function(sel) {
                return null;
            },
        };

        // Pass 0.004078560 (has trailing 0)
        sandbox.window.renderSuccessUI(container, DUMMY_SIG, "0.004078560");
        const html = container.innerHTML;

        // 1. Nadpis: "Rent returned." (skutečný heading h2)
        assert(html.includes("Rent returned."), "Must contain title: 'Rent returned.'");
        assert(html.includes("<h2 class=\"success-title\""), "Must be semantic h2 heading");

        // 2. Pod ním výrazně: "+<částka> SOL is back in your wallet." (bez koncových nul: 0.00407856)
        assert(html.includes("+0.00407856 SOL is back in your wallet."), "Must display: '+0.00407856 SOL is back in your wallet.' (trailing 0 trimmed)");

        // 3. "0% protocol fee. We take 0% of what you claim."
        assert(html.includes("0% protocol fee. We take 0% of what you claim."), "Must contain: '0% protocol fee. We take 0% of what you claim.'");

        // 4. "If Claime saved you time, a tip keeps it running."
        assert(html.includes("If Claime saved you time, a tip keeps it running."), "Must contain: 'If Claime saved you time, a tip keeps it running.'");

        // 5. Celá tip adresa v monospace s tlačítkem [Copy] a aria-label
        assert(html.includes(TIP_WALLET_ADDRESS), `Must show full tip address: '${TIP_WALLET_ADDRESS}'`);
        assert(html.includes("btnCopyTip"), "Must contain copy button with id btnCopyTip");
        assert(html.includes('aria-label="Copy tip address"'), "Must contain aria-label='Copy tip address'");

        // 6. Solscan odkaz
        assert(html.includes("https://solscan.io/tx/" + DUMMY_SIG), "Must contain link to Solscan");
        assert(html.includes("✓ View transaction on Solscan ↗"), "Must contain '✓ View transaction on Solscan ↗'");
        assert(html.includes("5VERv8NM...ePm8SLhk"), "Must show shortened signature format in link");

        // 7. Sledování na síti X (𝕏 zabaleno do aria-hidden="true")
        assert(html.includes("https://x.com/quillhog0"), "Must contain link to X account");
        assert(html.includes("Follow @quillhog0 on X"), "Must contain 'Follow @quillhog0 on X'");
        assert(html.includes('<span aria-hidden="true">𝕏</span>'), "Must wrap '𝕏' in aria-hidden='true'");

        // 8. Tlačítka [Scan another wallet] a [Shelf] MUSÍ BÝT ODSTRANĚNA
        assert(!html.includes("btnScanAnother"), "Must NOT contain [Scan another wallet] button");
        assert(!html.includes("[ Scan another wallet ]"), "Must NOT contain [ Scan another wallet ] text");
        assert(!html.includes("btn-shelf"), "Must NOT contain Shelf button");
        assert(!html.includes("[ Shelf ]"), "Must NOT contain [ Shelf ] text");

        console.log("PASS: Test 1 - renderSuccessUI displays correct C-19 full tip address, a11y labels, heading, and trimmed amount");
    }

    // ----------------------------------------------------
    // TEST 2: Full claim does NOT trigger rescan; thank-you screen stays with real trimmed SOL amount
    // ----------------------------------------------------
    {
        const { sandbox, scanResult, walletInput } = createSandbox({
            pollResponses: [{ status: "confirmed", commitment: "confirmed", signature: DUMMY_SIG }],
            buildTxOverrides: {
                accounts_closed_in_batch: 2,
                total_empty_found: 2,
                sol_reclaimed: "0.004078560",
                sol_reclaimed_lamports: 4078560,
            },
        });

        let rescanCalled = false;
        sandbox.window.scanAddress = () => {
            rescanCalled = true;
        };

        await sandbox.window.executeClaim(DUMMY_WALLET);

        assert.strictEqual(rescanCalled, false, "rescan (window.scanAddress) must NOT be called when all accounts are closed");
        assert(scanResult.innerHTML.includes("Rent returned."), "Thank-you screen must remain in scanResult");
        assert(scanResult.innerHTML.includes("+0.00407856 SOL is back in your wallet."), "Reclaimed SOL must be trimmed of trailing zero");
        assert(scanResult.innerHTML.includes("5VERv8NM...ePm8SLhk"), "Solscan tx link must be displayed");
        console.log("PASS: Test 2 - Complete claim does NOT trigger rescan, displays +0.00407856 SOL is back in your wallet");
    }

    // ----------------------------------------------------
    // TEST 3: Partial / batch claim waits for 'finalized' before triggering rescan
    // ----------------------------------------------------
    {
        let pollCount = 0;
        let rescanCalledAtPollCount = null;

        const pollResponses = [
            { status: "confirmed", commitment: "confirmed", signature: DUMMY_SIG },
            { status: "confirmed", commitment: "confirmed", signature: DUMMY_SIG },
            { status: "confirmed", commitment: "finalized", signature: DUMMY_SIG },
        ];

        const { sandbox, scanResult } = createSandbox({
            pollResponses,
            buildTxOverrides: {
                accounts_closed_in_batch: 1,
                total_empty_found: 2,
                sol_reclaimed: "0.002039280",
                sol_reclaimed_lamports: 2039280,
            },
        });

        const originalFetch = sandbox.fetch;
        sandbox.fetch = async (url, opts) => {
            if (url.includes("/api/tx/status")) {
                pollCount++;
            }
            return originalFetch(url, opts);
        };

        let rescanCalled = false;
        sandbox.window.scanAddress = () => {
            rescanCalled = true;
            rescanCalledAtPollCount = pollCount;
        };

        await sandbox.window.executeClaim(DUMMY_WALLET);

        assert.strictEqual(rescanCalled, true, "rescan must be called when accounts remain to be claimed");
        assert(pollCount >= 3, `Must poll until finalized commitment was returned (polled ${pollCount} times)`);
        assert(rescanCalledAtPollCount >= 3, "Rescan must only be triggered after finalized commitment");
        console.log("PASS: Test 3 - Partial claim waits for 'finalized' commitment before triggering rescan");
    }

    // ----------------------------------------------------
    // TEST 4: [Copy] button copies tip address and shows 'Copied ✓' for 2 seconds
    // ----------------------------------------------------
    {
        const { sandbox, scanResult, walletInput } = createSandbox({});
        walletInput.value = DUMMY_WALLET;

        let copyClickListener = null;
        const mockBtn = {
            textContent: "[Copy]",
            addEventListener: (event, fn) => {
                if (event === "click") copyClickListener = fn;
            },
        };

        scanResult.querySelector = (sel) => {
            if (sel === "#btnCopyTip") return mockBtn;
            return null;
        };

        sandbox.window.renderSuccessUI(scanResult, DUMMY_SIG, "0.002039280");
        assert(typeof copyClickListener === "function", "btnCopyTip click listener must be attached");

        // Click [Copy]
        await copyClickListener();

        // 1. Full address copied to clipboard
        assert.strictEqual(sandbox.getClipboardText(), TIP_WALLET_ADDRESS, "Must copy entire tip address to clipboard");

        // 2. Button text changes to 'Copied ✓'
        assert.strictEqual(mockBtn.textContent, "Copied ✓", "Button text must show 'Copied ✓'");

        // 3. After 2 seconds, button reverts to '[Copy]'
        await new Promise(r => setTimeout(r, 2100));
        assert.strictEqual(mockBtn.textContent, "[Copy]", "Button text must revert to '[Copy]' after 2s");

        console.log("PASS: Test 4 - [Copy] button copies full tip address and temporarily indicates Copied ✓");
    }

    // ----------------------------------------------------
    // TEST 4b: [Copy] button failure handling (C-19 P2)
    // ----------------------------------------------------
    {
        const { sandbox, scanResult, walletInput } = createSandbox({});
        walletInput.value = DUMMY_WALLET;

        // Force clipboard failure
        sandbox.navigator.clipboard.writeText = async () => {
            throw new Error("Clipboard write permission denied");
        };

        let copyClickListener = null;
        const mockBtn = {
            textContent: "[Copy]",
            addEventListener: (event, fn) => {
                if (event === "click") copyClickListener = fn;
            },
        };

        scanResult.querySelector = (sel) => {
            if (sel === "#btnCopyTip") return mockBtn;
            return null;
        };

        sandbox.window.renderSuccessUI(scanResult, DUMMY_SIG, "0.002039280");
        assert(typeof copyClickListener === "function", "btnCopyTip click listener must be attached");

        // Click [Copy] with failing clipboard
        await copyClickListener();

        // Must NOT show 'Copied ✓'
        assert.notStrictEqual(mockBtn.textContent, "Copied ✓", "'Copied ✓' must NOT be shown when clipboard write fails");
        // Must show 'Copy failed – select the address'
        assert.strictEqual(mockBtn.textContent, "Copy failed – select the address", "Must show 'Copy failed – select the address'");

        // After 3 seconds, button reverts to '[Copy]'
        await new Promise(r => setTimeout(r, 3100));
        assert.strictEqual(mockBtn.textContent, "[Copy]", "Button text must revert to '[Copy]' after failure feedback");

        console.log("PASS: Test 4b - [Copy] button handles clipboard failure gracefully and never shows 'Copied ✓'");
    }

    // ----------------------------------------------------
    // TEST 5: Old success banners are completely removed from renderScan
    // ----------------------------------------------------
    {
        const { sandbox, scanResult } = createSandbox({});
        const scanData = {
            native_lamports: 100000000,
            rent_accounts: 1,
            rent_lamports: 2039280,
            network_fee_lamports: 5000,
            estimated_validator_fee_lamports: 5000,
            close_accounts: [{ pubkey: "Acc111", amount: "0" }],
            mint_info_available: true,
        };

        sandbox.window.renderScan(scanData, DUMMY_WALLET);
        const html = scanResult.innerHTML;

        assert(!html.includes("scan-success-banner"), "renderScan must NOT render old scan-success-banner");
        assert(!html.includes("Rent reclaimed successfully!"), "renderScan must NOT render old success text");
        console.log("PASS: Test 5 - renderScan does not contain obsolete success banner");
    }

    // ----------------------------------------------------
    // TEST 6: Amount formatting unit tests (C-18 requirement 1 & 4)
    // ----------------------------------------------------
    {
        const { sandbox } = createSandbox({});
        const trim = sandbox.window.trimSolAmount;
        assert(typeof trim === "function", "trimSolAmount must be exposed on window");

        // 1. Trailing zeros: 0.001488440 -> 0.00148844
        assert.strictEqual(trim("0.001488440"), "0.00148844", "Must trim 0.001488440 to 0.00148844");

        // 2. Trailing zeros: 0.0100000 -> 0.01
        assert.strictEqual(trim("0.0100000"), "0.01", "Must trim 0.0100000 to 0.01");

        // 3. Whole SOL: 1.000000000 -> 1, 5.000000000 -> 5
        assert.strictEqual(trim("1.000000000"), "1", "Must trim 1.000000000 to 1");
        assert.strictEqual(trim("5.000000000"), "5", "Must trim 5.000000000 to 5");
        assert.strictEqual(trim(1000000000n), "1", "Must format 1 billion lamports to 1");

        // 4. Very small amounts: 0.000000001 (1 lamport)
        assert.strictEqual(trim("0.000000001"), "0.000000001", "Must preserve single lamport");
        assert.strictEqual(trim(1n), "0.000000001", "Must format 1n lamport to 0.000000001");

        // 5. Zero SOL: 0.000000000 -> 0 (never "0." or empty)
        assert.strictEqual(trim("0.000000000"), "0", "Zero SOL must display as 0");
        assert.strictEqual(trim(0n), "0", "0n lamports must display as 0");

        // 6. Edge cases: "0.", "", null, undefined
        assert.strictEqual(trim("0."), "0", "Malformed '0.' must display as 0");
        assert.strictEqual(trim(""), "0", "Empty string must display as 0");
        assert.strictEqual(trim(null), "0", "Null must display as 0");
        assert.strictEqual(trim(undefined), "0", "Undefined must display as 0");

        // 7. renderSuccessUI integration with various amounts
        const container = { innerHTML: "" };
        sandbox.window.renderSuccessUI(container, DUMMY_SIG, "0.001488440");
        assert(container.innerHTML.includes("+0.00148844 SOL is back in your wallet."), "renderSuccessUI must display +0.00148844 SOL");

        sandbox.window.renderSuccessUI(container, DUMMY_SIG, "1.000000000");
        assert(container.innerHTML.includes("+1 SOL is back in your wallet."), "renderSuccessUI must display +1 SOL for whole SOL");

        sandbox.window.renderSuccessUI(container, DUMMY_SIG, "0.000000001");
        assert(container.innerHTML.includes("+0.000000001 SOL is back in your wallet."), "renderSuccessUI must display +0.000000001 SOL for 1 lamport");

        console.log("PASS: Test 6 - Amount formatting tests pass for trailing zeros, whole SOL, very small amounts, and edge cases");
    }

    console.log("==================================================");
    console.log("✓ ALL C-18 TESTS PASSED!");
    console.log("==================================================");
}

runAllTests().catch((err) => {
    console.error("TEST FAILED:", err);
    process.exit(1);
});
