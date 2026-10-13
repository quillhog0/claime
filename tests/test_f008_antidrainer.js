// Red Team Verification Test Suite for F-008 (Anti-Drainer Client-Side Bytecode Inspection)
const fs = require('fs');
const assert = require('assert');

// Extract validateAndDisassembleClaimTransaction from claime.js
const claimeJsContent = fs.readFileSync('./web/static/js/claime.js', 'utf8');

// Create sandbox to extract function
const sandbox = {
    window: {},
    document: {
        getElementById: () => null,
        querySelector: () => null,
        addEventListener: () => null,
    },
    sessionStorage: {
        getItem: () => null,
        setItem: () => null,
    },
    URLSearchParams: class {
        get() { return null; }
    }
};

const fnDefMatch = claimeJsContent.match(/function validateAndDisassembleClaimTransaction[\s\S]*?\n    \}/);
if (!fnDefMatch) {
    throw new Error("Could not find validateAndDisassembleClaimTransaction in claime.js!");
}

const ALLOWED_MATCH = claimeJsContent.match(/const ALLOWED_CLAIM_PROGRAMS = new Set\(\[[\s\S]*?\]\);/);
if (!ALLOWED_MATCH) {
    throw new Error("Could not find ALLOWED_CLAIM_PROGRAMS in claime.js!");
}

const evaluator = new Function(
    'ALLOWED_CLAIM_PROGRAMS_CODE',
    'FN_CODE',
    `
    ${ALLOWED_MATCH[0]}
    ${fnDefMatch[0]}
    return validateAndDisassembleClaimTransaction;
    `
);

const validateAndDisassemble = evaluator();

console.log("==================================================");
console.log("⚡ RED TEAM AUDIT SUITE: F-008 CLIENT-SIDE ANTI-DRAINER");
console.log("==================================================");

const USER_WALLET = "FNB2fv2S5T2CjfzCF6BJ6pzUAJ8YH1iTca4BrECqJnQL";
const ATTACKER_WALLET = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";
const COMPUTE_BUDGET_ID = "ComputeBudget111111111111111111111111111111";
const defaultBuildData = {
    close_accounts: [{ pubkey: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", amount: 0 }]
};

// ── TEST 1: Valid CloseAccount Transaction ──
{
    const validTx = {
        message: {
            header: { numRequiredSignatures: 1 },
            staticAccountKeys: [
                USER_WALLET,                                     // 0: Payer & signer
                "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", // 1: Token Account to close
                TOKEN_PROGRAM_ID,                                // 2: SPL Token Program
            ],
            addressTableLookups: [],
            compiledInstructions: [
                {
                    programIdIndex: 2,
                    accountKeyIndexes: [1, 0, 0], // source=1, dest=0 (user), owner=0 (user)
                    data: new Uint8Array([9])     // CloseAccount opcode
                }
            ]
        }
    };

    const res = validateAndDisassemble(validTx, USER_WALLET, defaultBuildData);
    assert.strictEqual(res.isValid, true);
    assert.strictEqual(res.closeCount, 1);
    assert.strictEqual(res.destination, USER_WALLET);
    assert.strictEqual(res.owner, USER_WALLET);
    console.log("✓ PASS: Test 1 - Legitimate CloseAccount passes validation.");
}

// ── TEST 2: Drainer Attack 1 - System Program SOL Transfer ──
{
    const drainerTx = {
        message: {
            header: { numRequiredSignatures: 1 },
            staticAccountKeys: [
                USER_WALLET,
                ATTACKER_WALLET,
                SYSTEM_PROGRAM_ID
            ],
            addressTableLookups: [],
            compiledInstructions: [
                {
                    programIdIndex: 2, // System Program
                    accountKeyIndexes: [0, 1],
                    data: new Uint8Array([2, 0, 0, 0, 0, 0, 0, 0]) // Transfer
                }
            ]
        }
    };

    assert.throws(
        () => validateAndDisassemble(drainerTx, USER_WALLET, defaultBuildData),
        /Untrusted program call detected/,
        "Must reject System Program transfer!"
    );
    console.log("✓ PASS: Test 2 - Drainer System Program SOL transfer rejected.");
}

// ── TEST 3: Drainer Attack 2 - Address Lookup Table (ALT) Injection ──
{
    const altTx = {
        message: {
            header: { numRequiredSignatures: 1 },
            staticAccountKeys: [USER_WALLET, TOKEN_PROGRAM_ID],
            addressTableLookups: [{ accountKey: "SomeLookupTablePubkey" }],
            compiledInstructions: []
        }
    };

    assert.throws(
        () => validateAndDisassemble(altTx, USER_WALLET, defaultBuildData),
        /Untrusted Address Lookup Tables detected/,
        "Must reject ALTs!"
    );
    console.log("✓ PASS: Test 3 - Address Lookup Table injection rejected.");
}

// ── TEST 4: Drainer Attack 3 - Destination diverted to Attacker Wallet ──
{
    const divertedDestTx = {
        message: {
            header: { numRequiredSignatures: 1 },
            staticAccountKeys: [
                USER_WALLET,
                "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                ATTACKER_WALLET,
                TOKEN_PROGRAM_ID
            ],
            addressTableLookups: [],
            compiledInstructions: [
                {
                    programIdIndex: 3,
                    accountKeyIndexes: [1, 2, 0], // source=1, dest=2 (ATTACKER!), owner=0 (user)
                    data: new Uint8Array([9])
                }
            ]
        }
    };

    assert.throws(
        () => validateAndDisassemble(divertedDestTx, USER_WALLET, defaultBuildData),
        /CloseAccount destination does not match wallet/,
        "Must reject diverted rent destination!"
    );
    console.log("✓ PASS: Test 4 - Diverted rent destination rejected.");
}

// ── TEST 5: Drainer Attack 4 - Unauthorized Owner/Authority ──
{
    const wrongOwnerTx = {
        message: {
            header: { numRequiredSignatures: 1 },
            staticAccountKeys: [
                USER_WALLET,
                "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                ATTACKER_WALLET,
                TOKEN_PROGRAM_ID
            ],
            addressTableLookups: [],
            compiledInstructions: [
                {
                    programIdIndex: 3,
                    accountKeyIndexes: [1, 0, 2], // source=1, dest=0 (user), owner=2 (ATTACKER!)
                    data: new Uint8Array([9])
                }
            ]
        }
    };

    assert.throws(
        () => validateAndDisassemble(wrongOwnerTx, USER_WALLET, defaultBuildData),
        /CloseAccount owner\/authority does not match wallet/,
        "Must reject wrong owner authority!"
    );
    console.log("✓ PASS: Test 5 - Unauthorized owner authority rejected.");
}

// ── TEST 6: Drainer Attack 5 - SPL Token Transfer Opcode (Opcode 3) ──
{
    const tokenTransferTx = {
        message: {
            header: { numRequiredSignatures: 1 },
            staticAccountKeys: [
                USER_WALLET,
                "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                TOKEN_PROGRAM_ID
            ],
            addressTableLookups: [],
            compiledInstructions: [
                {
                    programIdIndex: 2,
                    accountKeyIndexes: [1, 0, 0],
                    data: new Uint8Array([3, 100, 0, 0, 0]) // Opcode 3 = Transfer!
                }
            ]
        }
    };

    assert.throws(
        () => validateAndDisassemble(tokenTransferTx, USER_WALLET, defaultBuildData),
        /Non-CloseAccount instruction detected in token program/,
        "Must reject Token Transfer opcode!"
    );
    console.log("✓ PASS: Test 6 - Token transfer opcode 3 rejected.");
}

// ── TEST 7: Drainer Attack 6 - Extra Multisig Signer Injection ──
{
    const multisigTx = {
        message: {
            header: { numRequiredSignatures: 1 },
            staticAccountKeys: [
                USER_WALLET,
                "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                ATTACKER_WALLET,
                TOKEN_PROGRAM_ID
            ],
            addressTableLookups: [],
            compiledInstructions: [
                {
                    programIdIndex: 3,
                    accountKeyIndexes: [1, 0, 0, 2], // 4 accounts: extra multisig signer!
                    data: new Uint8Array([9])
                }
            ]
        }
    };

    assert.throws(
        () => validateAndDisassemble(multisigTx, USER_WALLET, defaultBuildData),
        /unexpected extra multisig accounts/,
        "Must reject extra multisig accounts!"
    );
    console.log("✓ PASS: Test 7 - Multisig injection rejected.");
}

// ── TEST 8: Zero CloseAccount instructions ──
{
    const emptyTx = {
        message: {
            header: { numRequiredSignatures: 1 },
            staticAccountKeys: [USER_WALLET, COMPUTE_BUDGET_ID],
            addressTableLookups: [],
            compiledInstructions: [
                {
                    programIdIndex: 1, // Compute budget only
                    accountKeyIndexes: [],
                    data: new Uint8Array([3, 50, 0, 0, 0, 0, 0, 0, 0]) // SetComputeUnitPrice 9 bytes
                }
            ]
        }
    };

    assert.throws(
        () => validateAndDisassemble(emptyTx, USER_WALLET, { close_accounts: [] }),
        /Transaction contains 0 verified CloseAccount instructions/,
        "Must reject tx without CloseAccount!"
    );
    console.log("✓ PASS: Test 8 - Transaction with zero CloseAccount instructions rejected.");
}

console.log("==================================================");
console.log("⚡ ALL 8 RED TEAM CLIENT-SIDE FIREWALL TESTS PASSED!");
console.log("==================================================");
