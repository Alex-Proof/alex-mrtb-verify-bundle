import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { deriveOutcomeFromTrace, verifyBundleObject } from "../dist/verify.js";

// 06.11.2026 (externe Kritik, GitHub-Issue #9): verify() in verify.py lehnte JEDES Bundle ab,
// dessen schema_version nicht in DEVTASK_V2_SCHEMA_VERSIONS lag oder dessen capability nicht
// "devtask.execution@1.0" war -- inklusive V1-Bundles und aller memory.*-capability-Bundles,
// sogar das eigene sample-bundle.json im Repo. verify.ts verifizierte dieselben Bundles korrekt.
// Dieser Test deckt: (1) die Grund-Regression (sample-bundle.json), (2) die 6
// memory.*-capabilities je einmal verified/failed/inconclusive, TS<->Python, und (3) den
// Legacy-Signaturpfad mit/ohne trustedPublicKey (Spiegel zu trust-anchor-legacy-path-bypass.test.mjs).

const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const sha256 = value => createHash("sha256").update(value).digest("hex");
const ev = (prefix, obj) => prefix + JSON.stringify(obj);

function buildHashChain(events) {
  const chain = [];
  let prev = "genesis";
  for (const e of events) {
    const hash = sha256(prev + e);
    chain.push(hash);
    prev = hash;
  }
  return chain;
}

function pythonVerify(bundle, trustedKeyPem, approvalKeyPem) {
  const dir = mkdtempSync(join(tmpdir(), "memory-cap-"));
  const inputPath = join(dir, "bundle.json");
  writeFileSync(inputPath, JSON.stringify(bundle), "utf8");
  let keyPath = null;
  if (trustedKeyPem !== undefined) {
    keyPath = join(dir, "key.pem");
    writeFileSync(keyPath, trustedKeyPem, "utf8");
  }
  const args = [verifierDir + "/verify.py", inputPath];
  if (keyPath) args.push(keyPath);
  const result = spawnSync(process.env.PYTHON ?? "python", args, { encoding: "utf8" });
  return result;
}

function pythonDeriveOutcomeFromTrace(capability, events) {
  const dir = mkdtempSync(join(tmpdir(), "derive-outcome-"));
  const inputPath = join(dir, "events.json");
  writeFileSync(inputPath, JSON.stringify(events), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "events=json.load(open(sys.argv[2],encoding='utf-8'))",
    "print(m.derive_outcome_from_trace(sys.argv[3],events))",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, inputPath, capability], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

test("07.11.2026 fix: sample-bundle.json without a trusted_key is SELF-CONSISTENT ONLY, not VERIFIED, identically in Node and Python", () => {
  // Vorher (Issue #9) gaben beide CLIs hier VERIFIED/exit 0 aus, obwohl kein Anker gepruefi wurde --
  // das Loch, das die AWM-Sketch-Review (07.11.2026) am lebenden Repo nachgewiesen hat
  // (forged-resigned-bundle.json: eigener Key, veraendertes Event, neu signiert -> VERIFIED ohne Anker).
  const bundlePath = fileURLToPath(new URL("../sample-bundle.json", import.meta.url));
  const node = spawnSync("node", ["dist/verify.js", "sample-bundle.json"], { cwd: verifierDir, encoding: "utf8" });
  const python = spawnSync(process.env.PYTHON ?? "python", ["verify.py", "sample-bundle.json"], { cwd: verifierDir, encoding: "utf8" });
  assert.equal(node.status, 7, node.stderr + node.stdout);
  assert.equal(python.status, 7, python.stderr + python.stdout);
  assert.match(node.stdout, /SELF-CONSISTENT ONLY/);
  assert.match(python.stdout, /SELF-CONSISTENT ONLY/);
  JSON.parse(readFileSync(bundlePath, "utf8"));
});

test("07.11.2026 fix: forged-resigned-bundle.json (own keypair, edited event, fully re-signed) is rejected once a real trust anchor is pinned", () => {
  // Reproduziert den Angriff, den die Sketch-Review verlangt hat: gefaelschtes Bundle mit
  // selbst erzeugtem Schluessel bekommt ohne Anker SELF-CONSISTENT ONLY, mit dem echten
  // gepinnten Anker REJECTED: untrusted_signer -- nie VERIFIED.
  const forgedPath = fileURLToPath(new URL("../forged-resigned-bundle.json", import.meta.url));
  const forged = JSON.parse(readFileSync(forgedPath, "utf8"));
  const signer = freshEd25519();
  const node = spawnSync("node", ["dist/verify.js", "forged-resigned-bundle.json"], { cwd: verifierDir, encoding: "utf8" });
  assert.equal(node.status, 7, node.stderr + node.stdout);
  assert.match(node.stdout, /SELF-CONSISTENT ONLY/);
  const tsWithWrongAnchor = verifyBundleObject(forged, signer.publicKey);
  assert.deepEqual(tsWithWrongAnchor, { ok: false, reason: "untrusted_signer" });
  const pyWithWrongAnchor = pythonVerify(forged, signer.publicKey, undefined);
  assert.equal(pyWithWrongAnchor.status, 2);
  assert.match(pyWithWrongAnchor.stdout, /^REJECTED: untrusted_signer/);
});

test("invalid-tampered-bundle.json is rejected by Python with the same exit code as Node (Issue #9 regression guard)", () => {
  const node = spawnSync("node", ["dist/verify.js", "invalid-tampered-bundle.json"], { cwd: verifierDir, encoding: "utf8" });
  const python = spawnSync(process.env.PYTHON ?? "python", ["verify.py", "invalid-tampered-bundle.json"], { cwd: verifierDir, encoding: "utf8" });
  assert.equal(node.status, 2);
  assert.equal(python.status, 2);
  assert.match(python.stdout, /^REJECTED: invalid_signature/);
});

function freshEd25519() {
  return generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
}

function signedMemoryBundle(privateKey, publicKey, capability, events, outcome, extra = {}) {
  const payload = {
    bundle_id: "test-bundle", capability, run_id: "run-1", claim_ladder: "L0",
    executed_at: new Date().toISOString(), trace_events: events, trace_hash_chain: buildHashChain(events),
    outcome, ...extra,
  };
  const signature = sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64");
  return { ...payload, public_key: publicKey, signature };
}

// Ein verified/failed/inconclusive-Fall pro memory.*-capability -- TS (deriveOutcomeFromTrace) und
// Python (derive_outcome_from_trace) muessen byte-gleich uebereinstimmen, dann das Gesamtbundle
// (verifyBundleObject vs. verify.py verify()) ebenso.
const MEMORY_CAPABILITY_CASES = {
  "memory.provenance.attached@1.0": {
    verified: [ev("memory_write:", { entry_id: "e1", actual_agent_id: "a1", provenance_agent_id: "a1", actual_source_hash: "h1", provenance_source_hash: "h1" })],
    failed: [ev("memory_write:", { entry_id: "e1", actual_agent_id: "a1", provenance_agent_id: "a2", actual_source_hash: "h1", provenance_source_hash: "h1" })],
    inconclusive: [],
  },
  "memory.delete.enforced@1.0": {
    verified: [ev("memory_state_read:", { entry_id: "e1", exists: false, phase: "after_delete", source: "storage_probe" })],
    failed: [ev("memory_state_read:", { entry_id: "e1", exists: true, phase: "after_delete", source: "storage_probe" })],
    inconclusive: [],
  },
  "memory.tenant.isolation@1.0": {
    verified: [ev("tenant_access_probe:", { entry_id: "e1", requesting_tenant: "t1", target_tenant: "t2", allowed: false, source: "isolation_probe" })],
    failed: [ev("tenant_access_probe:", { entry_id: "e1", requesting_tenant: "t1", target_tenant: "t2", allowed: true, source: "isolation_probe" })],
    inconclusive: [],
  },
  "memory.write.integrity@1.0": {
    verified: [
      ev("memory_content_change:", { entry_id: "e1", phase: "before", content_hash: "h1", source: "content_probe" }),
      ev("memory_content_change:", { entry_id: "e1", phase: "after", content_hash: "h2", source: "content_probe" }),
    ],
    failed: [
      ev("memory_content_change:", { entry_id: "e1", phase: "before", content_hash: "h1", source: "content_probe" }),
      ev("memory_content_change:", { entry_id: "e1", phase: "after", content_hash: "h1", source: "content_probe" }),
    ],
    inconclusive: [],
  },
  "memory.audit.tamper_evident@1.0": {
    verified: [ev("audit_chain_check:", { chain_valid: true, mutated_order: false, source: "audit_chain_probe" })],
    failed: [ev("audit_chain_check:", { chain_valid: false, mutated_order: true, source: "audit_chain_probe" })],
    inconclusive: [],
  },
  "memory.recovery.verified@1.0": {
    verified: [ev("memory_recovery:", { snapshot_id: "s1", requested_state_hash: "h1", recovered_state_hash: "h1", restored: true, source: "recovery_probe" })],
    failed: [ev("memory_recovery:", { snapshot_id: "s1", requested_state_hash: "h1", recovered_state_hash: "h2", restored: true, source: "recovery_probe" })],
    inconclusive: [],
  },
};

test("derive_outcome_from_trace: TS and Python agree for all 6 memory.* capabilities (verified/failed/inconclusive)", () => {
  for (const [capability, cases] of Object.entries(MEMORY_CAPABILITY_CASES)) {
    for (const [expected, events] of Object.entries(cases)) {
      const ts = deriveOutcomeFromTrace(capability, events);
      assert.equal(ts, expected, `TS verdict for ${capability}/${expected}`);
      const py = pythonDeriveOutcomeFromTrace(capability, events);
      assert.equal(py, expected, `Python verdict for ${capability}/${expected}`);
    }
  }
});

test("verifyBundleObject() library call still accepts a signed memory.* bundle without a trusted_key (self-consistency, library level unchanged); the CLI wrapper no longer calls that VERIFIED", () => {
  for (const [capability, cases] of Object.entries(MEMORY_CAPABILITY_CASES)) {
    const signer = freshEd25519();
    const bundle = signedMemoryBundle(signer.privateKey, signer.publicKey, capability, cases.verified, "verified");
    const tsResult = verifyBundleObject(bundle);
    assert.deepEqual(tsResult, { ok: true }, `TS library for ${capability}`);
    const pyResult = pythonVerify(bundle, undefined, undefined);
    assert.equal(pyResult.status, 7, `Python CLI for ${capability}: ${pyResult.stderr}`);
    assert.match(pyResult.stdout, /SELF-CONSISTENT ONLY/, `Python CLI stdout for ${capability}`);
  }
});

test("Python verify() rejects a tampered outcome declaration for a memory.* bundle, matching verifyBundleObject() (Issue #9)", () => {
  const signer = freshEd25519();
  const events = MEMORY_CAPABILITY_CASES["memory.audit.tamper_evident@1.0"].failed;
  const bundle = signedMemoryBundle(signer.privateKey, signer.publicKey, "memory.audit.tamper_evident@1.0", events, "verified");
  const tsResult = verifyBundleObject(bundle);
  assert.equal(tsResult.ok, false);
  assert.match(tsResult.reason, /^trace_outcome_mismatch:/);
  const pyResult = pythonVerify(bundle, undefined, undefined);
  assert.equal(pyResult.status, 2);
  assert.match(pyResult.stdout, /^REJECTED: trace_outcome_mismatch:/);
});

// Legacy-Signaturpfad (4 Faelle): self-signed V1-Bundle MIT und OHNE trustedPublicKey, je ein
// korrekter und ein falscher Schluessel -- Python-Spiegel zu trust-anchor-legacy-path-bypass.test.mjs.
test("Python legacy signature path: trusted_key omitted -> CLI reports SELF-CONSISTENT ONLY (exit 7), never VERIFIED", () => {
  const signer = freshEd25519();
  const events = MEMORY_CAPABILITY_CASES["memory.audit.tamper_evident@1.0"].verified;
  const bundle = signedMemoryBundle(signer.privateKey, signer.publicKey, "memory.audit.tamper_evident@1.0", events, "verified");

  const tsResult = verifyBundleObject(bundle);
  assert.deepEqual(tsResult, { ok: true });
  const pyResult = pythonVerify(bundle, undefined, undefined);
  assert.equal(pyResult.status, 7, pyResult.stderr);
  assert.match(pyResult.stdout, /SELF-CONSISTENT ONLY/);
});

test("Python legacy signature path: trusted_key provided and matching verifies", () => {
  const signer = freshEd25519();
  const events = MEMORY_CAPABILITY_CASES["memory.audit.tamper_evident@1.0"].verified;
  const bundle = signedMemoryBundle(signer.privateKey, signer.publicKey, "memory.audit.tamper_evident@1.0", events, "verified");

  const tsResult = verifyBundleObject(bundle, signer.publicKey);
  assert.deepEqual(tsResult, { ok: true });
  const pyResult = pythonVerify(bundle, signer.publicKey, undefined);
  assert.equal(pyResult.status, 0, pyResult.stderr);
  assert.match(pyResult.stdout, /^VERIFIED/);
});

test("Python legacy signature path: trusted_key provided but WRONG rejects as untrusted_signer", () => {
  const signer = freshEd25519();
  const other = freshEd25519();
  const events = MEMORY_CAPABILITY_CASES["memory.audit.tamper_evident@1.0"].verified;
  const bundle = signedMemoryBundle(signer.privateKey, signer.publicKey, "memory.audit.tamper_evident@1.0", events, "verified");

  const tsResult = verifyBundleObject(bundle, other.publicKey);
  assert.deepEqual(tsResult, { ok: false, reason: "untrusted_signer" });
  const pyResult = pythonVerify(bundle, other.publicKey, undefined);
  assert.equal(pyResult.status, 2);
  assert.match(pyResult.stdout, /^REJECTED: untrusted_signer/);
});

test("Python legacy signature path: unknown capability without trusted_key still verifies (no pinning claim)", () => {
  const signer = freshEd25519();
  const events = [];
  const bundle = signedMemoryBundle(signer.privateKey, signer.publicKey, "memory.capture@1.0", events, "inconclusive");

  const tsResult = verifyBundleObject(bundle);
  assert.equal(tsResult.ok, false);
  assert.match(tsResult.reason, /^non_verified_outcome:/);
  const pyResult = pythonVerify(bundle, undefined, undefined);
  assert.equal(pyResult.status, 2);
  assert.match(pyResult.stdout, /^REJECTED: non_verified_outcome:/);
});
