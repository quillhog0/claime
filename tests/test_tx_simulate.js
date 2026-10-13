/**
 * Verification of Q-06: Pre-flight transaction simulation
 * Validates that simulation failure aborts transaction execution before signing,
 * fail-closed behavior on HTTP errors (429, 503, 500), fetch failures, and timeouts.
 */

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const claimeJsPath = path.resolve(__dirname, "../web/static/js/claime.js");
const claimeJsContent = fs.readFileSync(claimeJsPath, "utf8");

const SCANNED_WALLET = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

function createTestContext({ simulateResponse, customProvider }) {
    const elements = new Map();

    function createElement(id, className = "") {
        let _innerHTML = "";
        let childBtn = null;
        const el = {
            id,
            className,
            dataset: {},
            style: {},
            get innerHTML() {
                return _innerHTML;
            },
            set innerHTML(val) {
                _innerHTML = val;
                if (typeof val === "string" && (val.includes("btnSimulateTryAgain") || val.includes("btn-try-again"))) {
                    childBtn = {
                        id: "btnSimulateTryAgain",
                        className: "btn-try-again",
                        onclick: null,
                        addEventListener: (evt, fn) => {
                            if (evt === "click") childBtn.onclick = fn;
                        },
                        click() {
                            if (this.onclick) this.onclick();
                        },
                    };
                } else {
                    childBtn = null;
                }
            },
            textContent: "",
            disabled: false,
            addEventListener: () => {},
            remove: () => {
                if (id) elements.delete(id);
            },
            querySelector: (sel) => {
                if (childBtn && (sel.includes("btnSimulateTryAgain") || sel.includes("btn-try-again"))) {
                    return childBtn;
                }
                return null;
            },
            closest: () => el,
        };
        return el;
    }

    const txDebug = createElement("txDebug");
    const scanResult = createElement("scanResult");
    const walletInput = createElement("walletInput");
    walletInput.value = SCANNED_WALLET;
    const rentBtn = createElement("rentBtn", "scan-action rent-action");
    rentBtn.dataset.address = SCANNED_WALLET;
    

    elements.set("txDebug", txDebug);
    elements.set("scanResult", scanResult);
    elements.set("walletInput", walletInput);

    const doc = {
        getElementById: (id) => elements.get(id) || null,
        querySelector: (sel) => {
            if (sel.includes("rent-action")) return rentBtn;
            
            return null;
        },
        querySelectorAll: () => [],
        readyState: "complete",
        addEventListener: () => {},
        body: createElement("body"),
    };

    const mockSolanaWeb3 = {
        VersionedTransaction: {
            deserialize: () => ({
                message: {
                    staticAccountKeys: [
                        { toBase58: () => SCANNED_WALLET },
                        { toBase58: () => "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" },
                        { toBase58: () => TOKEN_PROGRAM_ID },
                    ],
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

    const mockFetch = async (url, opts) => {
        if (typeof url === "string" && url.includes("/api/tx/simulate")) {
            if (simulateResponse) return simulateResponse(url, opts);
            return {
                ok: true,
                status: 200,
                json: async () => ({ ok: true, logs: [], units_consumed: 1500, error: null }),
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
        return {
            ok: true,
            status: 200,
            json: async () => ({
                status: "ready",
                transaction_base64: Buffer.from("dummy-valid-serialized-transaction-bytes").toString("base64"),
                close_accounts: [{ pubkey: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", amount: 0 }],
                accounts_closed_in_batch: 1,
                sol_reclaimed: 0.002,
            }),
        };
    };

    const sandbox = {
        window: {},
        document: doc,
        fetch: mockFetch,
        solanaWeb3: mockSolanaWeb3,
        sessionStorage: { getItem: () => null, setItem: () => null },
        URLSearchParams: class { get() { return null; } },
        atob: (str) => Buffer.from(str, "base64").toString("binary"),
        btoa: (str) => Buffer.from(str, "binary").toString("base64"),
        setTimeout: setTimeout,
        clearTimeout: clearTimeout,
        console: console,
        AbortController: AbortController,
    };

    if (customProvider) {
        sandbox.window.solana = customProvider;
    }

    vm.createContext(sandbox);
    vm.runInContext(claimeJsContent, sandbox);

    return { sandbox, doc, txDebug, rentBtn };
}

async function run() {
    let passed = 0;

    // Test 1: simulatePreflightTransaction returns ok=true on success
    {
        const { sandbox } = createTestContext({});
        const res = await sandbox.window.simulatePreflightTransaction("dummy_base64", null);
        assert.strictEqual(res.ok, true);
        assert.strictEqual(res.units_consumed, 1500);
        console.log("✓ Test 1: simulatePreflightTransaction parses successful response");
        passed++;
    }

    // Test 2: When simulation reports on-chain error, executeClaim aborts BEFORE calling wallet signAndSendTransaction
    {
        let signCalled = false;
        const fakeProvider = {
            isConnected: true,
            publicKey: { toBase58: () => SCANNED_WALLET },
            signTransaction: async () => {
                signCalled = true;
                assert.fail("CRITICAL BUG: signTransaction MUST NOT be invoked when simulation fails!");
            },
            signAndSendTransaction: async () => {
                signCalled = true;
                assert.fail("CRITICAL BUG: signAndSendTransaction MUST NOT be invoked when simulation fails!");
            },
        };

        const { sandbox, txDebug } = createTestContext({
            simulateResponse: async () => ({
                ok: true,
                status: 200,
                json: async () => ({
                    ok: false,
                    error: '{"InstructionError": [0, "Custom: 1"]}',
                    logs: ["Program log: Instruction failed"],
                }),
            }),
            customProvider: fakeProvider,
        });

        await sandbox.window.executeClaim(SCANNED_WALLET);

        assert.strictEqual(signCalled, false, "Wallet signature must not be requested!");
        assert.ok(txDebug.innerHTML.includes("Pre-flight simulation failed"), "Error must be rendered in UI");
        console.log("✓ Test 2: executeClaim aborts without prompting wallet when simulation fails");
        passed++;
    }

    // Test 3: Fail-closed on HTTP 429: wallet.signTransaction/signAndSendTransaction never called, displays safety message + Try again
    {
        let signCalled = false;
        const fakeProvider = {
            isConnected: true,
            publicKey: { toBase58: () => SCANNED_WALLET },
            signTransaction: async () => {
                signCalled = true;
                assert.fail("wallet.signTransaction must never be called on HTTP 429");
            },
            signAndSendTransaction: async () => {
                signCalled = true;
                assert.fail("wallet.signAndSendTransaction must never be called on HTTP 429");
            },
        };

        const { sandbox, txDebug } = createTestContext({
            simulateResponse: async () => ({
                ok: false,
                status: 429,
                json: async () => ({ detail: "Rate limit exceeded" }),
            }),
            customProvider: fakeProvider,
        });

        await sandbox.window.executeClaim(SCANNED_WALLET);

        assert.strictEqual(signCalled, false, "Wallet signature must not be requested on 429!");
        assert.ok(txDebug.innerHTML.includes("Safety check unavailable – nothing was sent. Try again in a minute."), "Must show safety check unavailable message");
        assert.ok(txDebug.innerHTML.includes("Try again"), "Must render Try again button");
        console.log("✓ Test 3: Fail-closed on HTTP 429: wallet signature never requested, safety message displayed");
        passed++;
    }

    // Test 4: Fail-closed on HTTP 503: wallet.signTransaction/signAndSendTransaction never called, displays safety message + Try again
    {
        let signCalled = false;
        const fakeProvider = {
            isConnected: true,
            publicKey: { toBase58: () => SCANNED_WALLET },
            signTransaction: async () => {
                signCalled = true;
                assert.fail("wallet.signTransaction must never be called on HTTP 503");
            },
            signAndSendTransaction: async () => {
                signCalled = true;
                assert.fail("wallet.signAndSendTransaction must never be called on HTTP 503");
            },
        };

        const { sandbox, txDebug } = createTestContext({
            simulateResponse: async () => ({
                ok: false,
                status: 503,
                json: async () => ({ detail: "RPC service unavailable" }),
            }),
            customProvider: fakeProvider,
        });

        await sandbox.window.executeClaim(SCANNED_WALLET);

        assert.strictEqual(signCalled, false, "Wallet signature must not be requested on 503!");
        assert.ok(txDebug.innerHTML.includes("Safety check unavailable – nothing was sent. Try again in a minute."), "Must show safety check unavailable message");
        assert.ok(txDebug.innerHTML.includes("Try again"), "Must render Try again button");
        console.log("✓ Test 4: Fail-closed on HTTP 503: wallet signature never requested, safety message displayed");
        passed++;
    }

    // Test 5: Fail-closed on HTTP 500: wallet.signTransaction/signAndSendTransaction never called
    {
        let signCalled = false;
        const fakeProvider = {
            isConnected: true,
            publicKey: { toBase58: () => SCANNED_WALLET },
            signTransaction: async () => {
                signCalled = true;
                assert.fail("wallet.signTransaction must never be called on HTTP 500");
            },
            signAndSendTransaction: async () => {
                signCalled = true;
                assert.fail("wallet.signAndSendTransaction must never be called on HTTP 500");
            },
        };

        const { sandbox, txDebug } = createTestContext({
            simulateResponse: async () => ({
                ok: false,
                status: 500,
                json: async () => ({ detail: "Internal Server Error" }),
            }),
            customProvider: fakeProvider,
        });

        await sandbox.window.executeClaim(SCANNED_WALLET);

        assert.strictEqual(signCalled, false, "Wallet signature must not be requested on 500!");
        assert.ok(txDebug.innerHTML.includes("Safety check unavailable – nothing was sent. Try again in a minute."), "Must show safety check unavailable message");
        assert.ok(txDebug.innerHTML.includes("Try again"), "Must render Try again button");
        console.log("✓ Test 5: Fail-closed on HTTP 500: wallet signature never requested, safety message displayed");
        passed++;
    }

    // Test 6: Fail-closed on fetch failure (network error)
    {
        let signCalled = false;
        const fakeProvider = {
            isConnected: true,
            publicKey: { toBase58: () => SCANNED_WALLET },
            signTransaction: async () => {
                signCalled = true;
                assert.fail("wallet.signTransaction must never be called on fetch failure");
            },
            signAndSendTransaction: async () => {
                signCalled = true;
                assert.fail("wallet.signAndSendTransaction must never be called on fetch failure");
            },
        };

        const { sandbox, txDebug } = createTestContext({
            simulateResponse: async () => {
                throw new Error("Failed to fetch");
            },
            customProvider: fakeProvider,
        });

        await sandbox.window.executeClaim(SCANNED_WALLET);

        assert.strictEqual(signCalled, false, "Wallet signature must not be requested on network error!");
        assert.ok(txDebug.innerHTML.includes("Safety check unavailable – nothing was sent. Try again in a minute."), "Must show safety check unavailable message");
        assert.ok(txDebug.innerHTML.includes("Try again"), "Must render Try again button");
        console.log("✓ Test 6: Fail-closed on fetch failure: wallet signature never requested, safety message displayed");
        passed++;
    }

    // Test 7: Fail-closed on timeout (AbortError)
    {
        let signCalled = false;
        const fakeProvider = {
            isConnected: true,
            publicKey: { toBase58: () => SCANNED_WALLET },
            signTransaction: async () => {
                signCalled = true;
                assert.fail("wallet.signTransaction must never be called on timeout");
            },
            signAndSendTransaction: async () => {
                signCalled = true;
                assert.fail("wallet.signAndSendTransaction must never be called on timeout");
            },
        };

        const { sandbox, txDebug } = createTestContext({
            simulateResponse: async () => {
                const err = new Error("The operation was aborted");
                err.name = "AbortError";
                throw err;
            },
            customProvider: fakeProvider,
        });

        await sandbox.window.executeClaim(SCANNED_WALLET);

        assert.strictEqual(signCalled, false, "Wallet signature must not be requested on timeout!");
        assert.ok(txDebug.innerHTML.includes("Safety check unavailable – nothing was sent. Try again in a minute."), "Must show safety check unavailable message");
        assert.ok(txDebug.innerHTML.includes("Try again"), "Must render Try again button");
        console.log("✓ Test 7: Fail-closed on timeout: wallet signature never requested, safety message displayed");
        passed++;
    }

    // Test 8: Try again button triggers retry
    {
        let retried = false;
        const { sandbox } = createTestContext({
            simulateResponse: async () => ({
                ok: false,
                status: 500,
                json: async () => ({ detail: "Simulate error" }),
            }),
        });
        const statusDiv = {
            innerHTML: "",
            style: {},
            querySelector: (sel) => {
                if (sel.includes("btnSimulateTryAgain") || sel.includes("btn-try-again")) {
                    return btn;
                }
                return null;
            },
        };
        const btn = {
            onclick: null,
            click() {
                if (this.onclick) this.onclick();
            },
        };

        const res = await sandbox.window.simulatePreflightTransaction(
            "dummy_base64",
            statusDiv,
            () => {
                retried = true;
            }
        );
        assert.strictEqual(res.ok, false);
        assert.strictEqual(res.safetyUnavailable, true);
        assert.ok(btn.onclick !== null, "Retry button onclick handler must be attached");
        btn.click();
        assert.strictEqual(retried, true, "Clicking Try again button must trigger retry callback");
        console.log("✓ Test 8: Try again button is interactive and triggers retry handler");
        passed++;
    }

    console.log(`\nALL ${passed} SIMULATION INTEGRATION TESTS PASSED.`);
}

run().catch((err) => {
    console.error("Test failed:", err);
    process.exit(1);
});
