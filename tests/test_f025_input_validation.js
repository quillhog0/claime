// Red Team Verification Test Suite for T-025 (Empty input, validation, error mapping, loading steps)
const fs = require('fs');
const assert = require('assert');
const vm = require('vm');

const claimeJsContent = fs.readFileSync('./web/static/js/claime.js', 'utf8');

console.log("==================================================");
console.log("⚡ RED TEAM AUDIT SUITE: T-025 INPUT VALIDATION & ERROR UX");
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
            focused: false,
            attributes: {},
            setAttribute: function(name, val) { this.attributes[name] = val; },
            getAttribute: function(name) { return this.attributes[name]; },
            removeAttribute: function(name) { delete this.attributes[name]; },
            focus: function() { this.focused = true; },
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
        console: console,
        setTimeout: setTimeout,
        clearTimeout: clearTimeout,
    };

    sandbox.window = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(claimeJsContent, sandbox);

    return { sandbox, walletInput, scanResult, checkBtn };
}

async function runTests() {
    let passed = 0;

    // Test 1: Empty input triggers role="alert", focus on #walletInput, and zero fetch calls
    {
        let fetchCalled = false;
        const mockFetch = async () => { fetchCalled = true; return { ok: true, status: 200, json: async () => ({}) }; };
        const { sandbox, walletInput, scanResult } = createTestSandbox(mockFetch);

        walletInput.value = "";
        await sandbox.window.scanAddress();

        assert.strictEqual(fetchCalled, false, "fetch must not be called on empty input");
        assert.strictEqual(walletInput.focused, true, "walletInput.focus() must be called on empty input");
        assert.strictEqual(scanResult.getAttribute("role"), "alert", "scanResult must have role='alert'");
        assert(
            scanResult.innerHTML.includes("Paste a Solana wallet address first."),
            `Must alert 'Paste a Solana wallet address first.', got: ${scanResult.innerHTML}`
        );

        console.log("✓ Test 1: Empty input displays alert message, calls focus(), and prevents fetch");
        passed++;
    }

    // Test 2: Invalid base58 characters reject before API and call focus
    {
        let fetchCalled = false;
        const mockFetch = async () => { fetchCalled = true; return { ok: true, status: 200, json: async () => ({}) }; };
        const { sandbox, walletInput, scanResult } = createTestSandbox(mockFetch);

        walletInput.value = "00000000000000000000000000000000"; // '0' is not in base58
        await sandbox.window.scanAddress();

        assert.strictEqual(fetchCalled, false, "fetch must not be called on invalid base58");
        assert.strictEqual(walletInput.focused, true, "walletInput.focus() must be called on invalid base58");
        assert(
            scanResult.innerHTML.includes("That does not look like a Solana address."),
            `Must alert 'That does not look like a Solana address.', got: ${scanResult.innerHTML}`
        );

        console.log("✓ Test 2: Non-base58 address rejected on client without calling API");
        passed++;
    }

    // Test 3: Short address (< 32 chars) rejected on client
    {
        let fetchCalled = false;
        const mockFetch = async () => { fetchCalled = true; return { ok: true, status: 200, json: async () => ({}) }; };
        const { sandbox, walletInput, scanResult } = createTestSandbox(mockFetch);

        walletInput.value = "1111111111111111"; // 16 chars
        await sandbox.window.scanAddress();

        assert.strictEqual(fetchCalled, false, "fetch must not be called on short address");
        assert(
            scanResult.innerHTML.includes("That does not look like a Solana address."),
            "Must alert invalid Solana address on short length"
        );

        console.log("✓ Test 3: Short address (< 32 chars) rejected on client");
        passed++;
    }

    // Test 4: Server 400 mapped to clean English without internal detail leak
    {
        const mockFetch = async () => ({
            ok: false,
            status: 400,
            json: async () => ({ detail: "Internal regex failed in solders.pubkey parsing" }),
        });
        const { sandbox, walletInput, scanResult } = createTestSandbox(mockFetch);

        walletInput.value = "11111111111111111111111111111111";
        await sandbox.window.scanAddress();

        assert(scanResult.innerHTML.includes("Invalid address."), `Expected 'Invalid address.', got: ${scanResult.innerHTML}`);
        assert(!scanResult.innerHTML.includes("solders.pubkey"), "Must NOT leak internal backend detail");
        assert(scanResult.innerHTML.includes("border: 1px solid var(--quill)"), "Must be rendered in styled bordered box");

        console.log("✓ Test 4: Server 400 mapped to simple message without internal detail leak");
        passed++;
    }

    // Test 5: Server 500 mapped to 'Something went wrong on our side. Try again.'
    {
        const mockFetch = async () => ({
            ok: false,
            status: 500,
            json: async () => ({ detail: "Database lock error in sqlite3" }),
        });
        const { sandbox, walletInput, scanResult } = createTestSandbox(mockFetch);

        walletInput.value = "11111111111111111111111111111111";
        await sandbox.window.scanAddress();

        assert(
            scanResult.innerHTML.includes("Something went wrong on our side. Try again."),
            `Expected friendly 5xx error, got: ${scanResult.innerHTML}`
        );
        assert(!scanResult.innerHTML.includes("sqlite3"), "Must NOT leak backend exception detail");

        console.log("✓ Test 5: Server 500 mapped to friendly error block");
        passed++;
    }

    // Test 6: Loading indicator contains static steps and usually 2-7 seconds hint
    {
        let finishFetch;
        const mockFetch = async () => {
            await new Promise((r) => { finishFetch = r; });
            return { ok: true, status: 200, json: async () => ({ rent_accounts: 0 }) };
        };
        const { sandbox, walletInput, scanResult } = createTestSandbox(mockFetch);

        walletInput.value = "11111111111111111111111111111111";
        const scanPromise = sandbox.window.scanAddress();

        assert(
            scanResult.innerHTML.includes("Reading token accounts… → Checking delegates… → Done"),
            `Loading indicator must display static step progress, got: ${scanResult.innerHTML}`
        );
        assert(
            scanResult.innerHTML.includes("usually 2–7 seconds"),
            `Loading indicator must display static time hint without fake counter, got: ${scanResult.innerHTML}`
        );
        assert.strictEqual(scanResult.getAttribute("aria-live"), "polite", "scanResult must have aria-live='polite'");

        finishFetch();
        await scanPromise;

        console.log("✓ Test 6: Loading indicator presents static steps and polite aria-live");
        passed++;
    }

    console.log("==================================================");
    console.log(`✅ ALL ${passed} T-025 INPUT VALIDATION & ERROR TESTS PASSED`);
    console.log("==================================================");
}

runTests().catch((err) => {
    console.error("❌ TEST FAILED:", err);
    process.exit(1);
});
