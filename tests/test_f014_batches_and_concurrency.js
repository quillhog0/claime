// Red Team Verification Test Suite for T-014 (Batches, UI state, request concurrency)
const fs = require('fs');
const assert = require('assert');
const vm = require('vm');

const claimeJsContent = fs.readFileSync('./web/static/js/claime.js', 'utf8');

console.log("==================================================");
console.log("⚡ RED TEAM AUDIT SUITE: T-014 BATCHES & REQUEST CONCURRENCY");
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
            value: "",
            disabled: false,
            addEventListener: function(event, handler) {
                this.listeners = this.listeners || {};
                this.listeners[event] = handler;
            },
            remove: () => {},
            querySelector: () => null,
            closest: function() { return this; },
        };
    }

    const txDebug = createElement("txDebug");
    const scanResult = createElement("scanResult");
    const walletInput = createElement("walletInput");
    const checkBtn = createElement("checkBtn", "btn-primary");

    elements.set("txDebug", txDebug);
    elements.set("scanResult", scanResult);
    elements.set("walletInput", walletInput);
    elements.set("checkBtn", checkBtn);

    const doc = {
        getElementById: (id) => elements.get(id) || null,
        querySelector: (sel) => {
            if (sel === "#checkBtn") return checkBtn;
            if (sel === ".rent-action") return createElement("rentAction", "rent-action");
            return null;
        },
        querySelectorAll: () => [],
        addEventListener: () => {},
        readyState: "complete",
    };

    const sandbox = {
        window: {},
        document: doc,
        fetch: mockFetch,
        AbortController: AbortController,
        solanaWeb3: {
            VersionedTransaction: { deserialize: () => ({ message: { staticAccountKeys: [] } }) },
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

    return { sandbox, txDebug, scanResult, walletInput, checkBtn };
}

async function runTests() {
    let passed = 0;

    // Test 1: formatBatchNotice correctly formats notice when total > closed
    {
        const { sandbox } = createTestSandbox(async () => {});
        const notice1 = sandbox.window.formatBatchNotice(15, 60);
        assert.strictEqual(
            notice1,
            "This transaction closes 15 of 60 accounts (batch size 15). Run again for the rest.",
            "Should format batch message when total exceeds batch"
        );

        const notice2 = sandbox.window.formatBatchNotice(15, 15);
        assert.strictEqual(notice2, null, "Should return null when all accounts fit in one batch");

        const notice3 = sandbox.window.formatBatchNotice(5, 5);
        assert.strictEqual(notice3, null, "Should return null when total equals closed");

        console.log("✓ Test 1: formatBatchNotice produces correct messaging");
        passed++;
    }

    // Test 2: Request concurrency: delayed first response is ignored; second response wins
    {
        let requestCount = 0;
        let delayedResolve;
        const mockFetch = async (url, options) => {
            requestCount++;
            const body = JSON.parse(options.body);
            if (body.wallet_address === "11111111111111111111111111111111") {
                // First request delayed
                await new Promise((resolve) => {
                    delayedResolve = resolve;
                    // If aborted, reject with AbortError
                    if (options.signal) {
                        options.signal.addEventListener("abort", () => {
                            const err = new Error("The user aborted a request.");
                            err.name = "AbortError";
                            resolve({
                                ok: false,
                                status: 0,
                                json: async () => ({}),
                            });
                        });
                    }
                });
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        rent_accounts: 1,
                        rent_sol: "0.002039280",
                        rent_lamports: 2039280,
                    }),
                };
            } else if (body.wallet_address === "22222222222222222222222222222222") {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        rent_accounts: 45,
                        rent_sol: "0.091767600",
                        rent_lamports: 91767600,
                    }),
                };
            }
        };

        const { sandbox, walletInput, scanResult } = createTestSandbox(mockFetch);

        walletInput.value = "11111111111111111111111111111111";
        const scan1Promise = sandbox.window.scanAddress();

        walletInput.value = "22222222222222222222222222222222";
        const scan2Promise = sandbox.window.scanAddress();

        await scan2Promise;

        // Finish delayed scan1 after scan2 resolved
        if (delayedResolve) delayedResolve();
        await scan1Promise;

        assert.strictEqual(requestCount, 2, "Both requests were triggered");
        assert(
            scanResult.innerHTML.includes("45 empty token accounts"),
            `scanResult must reflect the newer Address2 response (45 accounts), got: ${scanResult.innerHTML}`
        );
        assert(
            !scanResult.innerHTML.includes("1 empty token account<"),
            "scanResult must NOT be overwritten by stale Address1 response"
        );

        console.log("✓ Test 2: Scan concurrency correctly aborts/ignores stale request (newer wins)");
        passed++;
    }

    // Test 3: CHECK button is disabled during in-flight scan and re-enabled after
    {
        let finishFetch;
        const mockFetch = async () => {
            await new Promise((r) => { finishFetch = r; });
            return {
                ok: true,
                status: 200,
                json: async () => ({ rent_accounts: 0 }),
            };
        };

        const { sandbox, walletInput, checkBtn } = createTestSandbox(mockFetch);
        walletInput.value = "33333333333333333333333333333333";

        assert.strictEqual(checkBtn.disabled, false, "CHECK button should be enabled initially");

        const scanPromise = sandbox.window.scanAddress();
        assert.strictEqual(checkBtn.disabled, true, "CHECK button must be disabled while scan is in flight");

        finishFetch();
        await scanPromise;

        assert.strictEqual(checkBtn.disabled, false, "CHECK button must be restored to enabled after scan completes");

        console.log("✓ Test 3: CHECK button properly disabled in flight and restored");
        passed++;
    }

    // Test 4: Rate limit 429 displays Retry-After seconds
    {
        const mockFetch = async () => {
            return {
                ok: false,
                status: 429,
                headers: {
                    get: (name) => (name.toLowerCase() === "retry-after" ? "42" : null),
                },
                json: async () => ({ detail: "Rate limit exceeded" }),
            };
        };

        const { sandbox, walletInput, scanResult } = createTestSandbox(mockFetch);
        walletInput.value = "44444444444444444444444444444444";

        await sandbox.window.scanAddress();

        assert.strictEqual(
            scanResult.textContent,
            "Rate limit exceeded. Try again in 42 seconds.",
            `scanResult must display retry-after seconds on 429, got: ${scanResult.textContent}`
        );

        console.log("✓ Test 4: Rate limit 429 renders Retry-After seconds");
        passed++;
    }

    // Test 5: Batch notice appears when total_empty_found > accounts_closed_in_batch
    {
        const buildDataMultiBatch = {
            status: "ready",
            accounts_closed_in_batch: 15,
            total_empty_found: 60,
            transaction_base64: Buffer.from("dummy").toString("base64"),
        };

        const notice = sandboxNoticeTest(buildDataMultiBatch);
        assert(
            notice && notice.includes("closes 15 of 60 accounts (batch size 15). Run again for the rest."),
            `Batch notice must be formatted for multi-batch, got: ${notice}`
        );

        const buildDataSingleBatch = {
            status: "ready",
            accounts_closed_in_batch: 8,
            total_empty_found: 8,
            transaction_base64: Buffer.from("dummy").toString("base64"),
        };
        const singleNotice = sandboxNoticeTest(buildDataSingleBatch);
        assert.strictEqual(singleNotice, null, "No batch notice should be displayed when single batch fits all");

        console.log("✓ Test 5: Multi-batch notice correctly triggers on total > batch");
        passed++;
    }

    console.log("==================================================");
    console.log(`✅ ALL ${passed} T-014 BATCH & CONCURRENCY TESTS PASSED`);
    console.log("==================================================");
}

function sandboxNoticeTest(buildData) {
    const { sandbox } = createTestSandbox(async () => {});
    return sandbox.window.formatBatchNotice(
        buildData.accounts_closed_in_batch,
        buildData.total_empty_found
    );
}

runTests().catch((err) => {
    console.error("❌ Test failed:", err);
    process.exit(1);
});
