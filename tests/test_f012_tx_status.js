// Red Team Verification Test Suite for T-012 (On-chain Confirmation Polling & Confirm Retry)
const fs = require('fs');
const assert = require('assert');
const vm = require('vm');

const claimeJsContent = fs.readFileSync('./web/static/js/claime.js', 'utf8');

console.log("==================================================");
console.log("⚡ RED TEAM AUDIT SUITE: T-012 ON-CHAIN CONFIRMATION POLLING");
console.log("==================================================");

function createTestSandbox(mockFetch) {
    const elements = new Map();

    function createElement(id = "", className = "") {
        return {
            id,
            className,
            classList: {
                contains: (cls) => className.split(" ").includes(cls),
                add: (cls) => { className += " " + cls; },
            },
            dataset: {},
            style: {},
            innerHTML: "",
            textContent: "",
            disabled: false,
            addEventListener: () => {},
            remove: () => {},
            querySelector: () => null,
            closest: function() { return this; },
        };
    }

    const txDebug = createElement("txDebug");
    const scanResult = createElement("scanResult");
    const walletInput = createElement("walletInput");

    elements.set("txDebug", txDebug);
    elements.set("scanResult", scanResult);
    elements.set("walletInput", walletInput);

    const doc = {
        getElementById: (id) => elements.get(id) || null,
        querySelector: () => null,
        querySelectorAll: () => [],
        addEventListener: () => {},
        readyState: "complete",
    };

    const sandbox = {
        window: {},
        document: doc,
        fetch: mockFetch,
        solanaWeb3: {
            VersionedTransaction: { deserialize: () => ({}) },
            PublicKey: class { constructor(v) { this.v = v; } toBase58() { return String(this.v); } },
        },
        sessionStorage: { getItem: () => null, setItem: () => null },
        URLSearchParams: class { get() { return null; } },
        atob: (str) => Buffer.from(str, 'base64').toString('binary'),
        btoa: (str) => Buffer.from(str, 'binary').toString('base64'),
        setTimeout: setTimeout,
        clearTimeout: clearTimeout,
        console: console,
    };

    vm.createContext(sandbox);
    vm.runInContext(claimeJsContent, sandbox);

    return { sandbox, txDebug, scanResult };
}

async function runTests() {
    let passed = 0;
    const testSig = "5abc111111111111111111111111111111111111111111111111111111111111";

    // Test 1: pollTransactionStatus returns confirmed immediately if first poll is confirmed
    {
        let pollCount = 0;
        const mockFetch = async (url) => {
            if (url.includes("/api/tx/status")) {
                pollCount++;
                return {
                    ok: true,
                    json: async () => ({ status: "confirmed" }),
                };
            }
            return { ok: false };
        };

        const { sandbox, txDebug } = createTestSandbox(mockFetch);
        const res = await sandbox.window.pollTransactionStatus(testSig, txDebug, 5000);

        assert.strictEqual(res.status, "confirmed");
        assert.strictEqual(pollCount, 1);
        assert.ok(txDebug.innerHTML.includes("Submitted – waiting for confirmation…"), "Status text not set");
        console.log("✓ Test 1: pollTransactionStatus resolves 'confirmed' on immediate confirmation");
        passed++;
    }

    // Test 2: pollTransactionStatus retries on 'pending' and resolves when 'confirmed'
    {
        let pollCount = 0;
        const mockFetch = async (url) => {
            if (url.includes("/api/tx/status")) {
                pollCount++;
                if (pollCount < 3) {
                    return {
                        ok: true,
                        json: async () => ({ status: "pending" }),
                    };
                }
                return {
                    ok: true,
                    json: async () => ({ status: "confirmed" }),
                };
            }
            return { ok: false };
        };

        const { sandbox, txDebug } = createTestSandbox(mockFetch);
        const res = await sandbox.window.pollTransactionStatus(testSig, txDebug, 10000);

        assert.strictEqual(res.status, "confirmed");
        assert.strictEqual(pollCount, 3);
        console.log("✓ Test 2: pollTransactionStatus polls through 'pending' until 'confirmed'");
        passed++;
    }

    // Test 3: pollTransactionStatus resolves 'failed' when RPC reports failed
    {
        const mockFetch = async (url) => {
            if (url.includes("/api/tx/status")) {
                return {
                    ok: true,
                    json: async () => ({ status: "failed", err: { InstructionError: [0, "Custom"] } }),
                };
            }
            return { ok: false };
        };

        const { sandbox, txDebug } = createTestSandbox(mockFetch);
        const res = await sandbox.window.pollTransactionStatus(testSig, txDebug, 5000);

        assert.strictEqual(res.status, "failed");
        assert.ok(res.err !== undefined);
        console.log("✓ Test 3: pollTransactionStatus resolves 'failed' when status endpoint reports failure");
        passed++;
    }

    // Test 4: pollTransactionStatus returns 'timeout' when maxWaitMs expires
    {
        const mockFetch = async (url) => {
            if (url.includes("/api/tx/status")) {
                return {
                    ok: true,
                    json: async () => ({ status: "pending" }),
                };
            }
            return { ok: false };
        };

        const { sandbox, txDebug } = createTestSandbox(mockFetch);
        // Short timeout for fast test
        const res = await sandbox.window.pollTransactionStatus(testSig, txDebug, 1500);

        assert.strictEqual(res.status, "timeout");
        console.log("✓ Test 4: pollTransactionStatus returns 'timeout' when deadline exceeded");
        passed++;
    }

    // Test 5: confirmClaimWithRetry retries on HTTP 202 and returns data on HTTP 200
    {
        let confirmAttempts = 0;
        const mockFetch = async (url, opts) => {
            if (url.includes("/api/rent/confirm")) {
                confirmAttempts++;
                if (confirmAttempts === 1) {
                    return {
                        status: 202,
                        ok: false,
                        json: async () => ({ status: "pending", message: "Still indexing on RPC" }),
                    };
                }
                return {
                    status: 200,
                    ok: true,
                    json: async () => ({ status: "ok", tx: testSig, accounts_closed: 2, sol_reclaimed: 0.004 }),
                };
            }
            return { ok: false };
        };

        const { sandbox } = createTestSandbox(mockFetch);
        const buildData = { accounts_closed_in_batch: 2, sol_reclaimed: 0.004 };
        const result = await sandbox.window.confirmClaimWithRetry("FNB2fv2S5T2CjfzCF6BJ6pzUAJ8YH1iTca4BrECqJnQL", testSig, buildData, 5);

        assert.ok(result !== null);
        assert.strictEqual(result.status, "ok");
        assert.strictEqual(confirmAttempts, 2);
        console.log("✓ Test 5: confirmClaimWithRetry retries on 202 and completes on 200");
        passed++;
    }

    // Test 6: extractSignature parses strings, objects, and buffers
    {
        const { sandbox } = createTestSandbox(async () => ({ ok: true }));
        const ext = sandbox.window.extractSignature;

        assert.strictEqual(ext(testSig), testSig);
        assert.strictEqual(ext({ signature: testSig }), testSig);
        assert.strictEqual(ext({ txSignature: testSig }), testSig);
        assert.strictEqual(ext({ txid: testSig }), testSig);
        assert.strictEqual(ext(null), null);
        console.log("✓ Test 6: extractSignature handles various wallet response shapes");
        passed++;
    }

    console.log("==================================================");
    console.log(`✅ ALL ${passed} T-012 CLIENT STATUS POLLING TESTS PASSED`);
    console.log("==================================================");
}

runTests().catch((err) => {
    console.error("❌ TEST SUITE FAILED:", err);
    process.exit(1);
});
