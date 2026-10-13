// Test suite for B-17: Success message banner preserved across rescan with shortened signature and Solscan link
const fs = require('fs');
const assert = require('assert');
const vm = require('vm');

const rawJs = fs.readFileSync('./web/static/js/claime.js', 'utf8');
const claimeJsContent = rawJs.replace(
    "})();",
    "window.setSuccessSignatureForTesting = (sig, addr) => { lastSuccessSignature = sig; lastSuccessAddress = addr; };\nwindow.getSuccessSignatureForTesting = () => lastSuccessSignature;\n})();"
);

console.log("==================================================");
console.log("⚡ TEST SUITE: B-17 SUCCESS BANNER PRESERVATION");
console.log("==================================================");

function setupSandbox() {
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
            addEventListener: function() {},
            remove: () => {},
            querySelector: () => null,
            closest: function() { return this; },
        };
    }

    const scanResult = createElement("scanResult");
    elements.set("scanResult", scanResult);
    const walletInput = createElement("walletInput");
    elements.set("walletInput", walletInput);
    const checkBtn = createElement("checkBtn");
    elements.set("checkBtn", checkBtn);

    const doc = {
        getElementById: (id) => elements.get(id) || null,
        querySelector: () => null,
        querySelectorAll: () => [],
        addEventListener: () => {},
        readyState: "complete",
    };

    const windowObj = {
        document: doc,
        addEventListener: () => {},
        location: { origin: "https://quillhog.xyz" },
        solana: null,
    };

    const context = vm.createContext({
        window: windowObj,
        document: doc,
        console: console,
        fetch: () => Promise.resolve({ ok: true, json: () => Promise.resolve({}) }),
        BigInt: BigInt,
        Date: Date,
        setTimeout: () => {},
        clearTimeout: () => {},
        setInterval: () => {},
        clearInterval: () => {},
        Array: Array,
        Object: Object,
        String: String,
        Number: Number,
        Boolean: Boolean,
        Map: Map,
        Set: Set,
    });

    vm.runInContext(claimeJsContent, context);
    return { windowObj, scanResult, walletInput };
}

const DUMMY_WALLET = "FNB2fv2S5T2CjfzCF6BJ6pzUAJ8YH1iTca4BrECqJnQL";
const DUMMY_SIG = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYj7WNXT5w35Lxs5264tzPDf85QZyRzWNWePm8SLhk";

// Test 1: renderSuccessUI displays shortened signature link
{
    const { windowObj, scanResult, walletInput } = setupSandbox();
    walletInput.value = DUMMY_WALLET;

    windowObj.renderSuccessUI(scanResult, DUMMY_SIG);
    const html = scanResult.innerHTML;

    assert(html.includes("Rent returned."), "Must contain Rent returned.");
    assert(html.includes("https://solscan.io/tx/" + DUMMY_SIG), "Must contain Solscan link with signature");
    assert(html.includes("5VERv8NM...ePm8SLhk"), "Must show shortened signature format");
    console.log("PASS: Test 1 - renderSuccessUI renders shortened signature link");
}

// Test 2: C-16 removed old success banner from renderScan to avoid displaying over scans
{
    const { windowObj, scanResult, walletInput } = setupSandbox();
    walletInput.value = DUMMY_WALLET;
    windowObj.setSuccessSignatureForTesting(DUMMY_SIG, DUMMY_WALLET);

    const cleanRescanData = {
        native_lamports: 50000000,
        rent_accounts: 0,
        rent_lamports: 0,
        network_fee_lamports: 5000,
        estimated_validator_fee_lamports: 5000,
        mint_info_available: true,
    };

    windowObj.renderScan(cleanRescanData, DUMMY_WALLET);
    const html = scanResult.innerHTML;

    assert(!html.includes("scan-success-banner"), "Must NOT contain scan-success-banner (removed in C-16)");
    assert(html.includes("// SCAN DONE"), "Must also contain scan results below");
    console.log("PASS: Test 2 - renderScan does not render obsolete banner (C-16)");
}

// Test 3: If different address is scanned, banner is suppressed
{
    const { windowObj, scanResult, walletInput } = setupSandbox();
    walletInput.value = DUMMY_WALLET;
    windowObj.setSuccessSignatureForTesting(DUMMY_SIG, DUMMY_WALLET);

    const otherWallet = "71K1111111111111111111111111111111111111111";
    const cleanData = {
        native_lamports: 50000000,
        rent_accounts: 0,
        rent_lamports: 0,
        network_fee_lamports: 5000,
        estimated_validator_fee_lamports: 5000,
        mint_info_available: true,
    };

    windowObj.renderScan(cleanData, otherWallet);
    const html = scanResult.innerHTML;

    assert(!html.includes("scan-success-banner"), "Must NOT contain scan-success-banner for different wallet");
    console.log("PASS: Test 3 - Different wallet suppresses previous success banner");
}

console.log("ALL B-17 TESTS PASSED!");
