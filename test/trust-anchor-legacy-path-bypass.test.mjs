import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { verifyBundleObject } from "../dist/verify.js";

function evidenceSignerKeyId(publicKey) {
  return `ed25519:${createHash("sha256").update(publicKey).digest("hex")}`;
}

// 06.11.2026: real finding via the public Evidence-Forgery Challenge (challenge.alexproof.de,
// isolated VM, imports this exact verify.ts unmodified). verifyBundleObject() checked
// trustedPublicKey only inside the isDevTaskV2Schema() branch -- a self-signed bundle without
// schema_version (or with an unknown value) fell into an old "legacy" path that verified the
// signature only against the public_key embedded in the bundle itself, never against
// trustedPublicKey. Fixed: public_key must match an explicitly passed trustedPublicKey in every
// branch, not just the devtask-v2 one. Calls WITHOUT a trustedPublicKey argument are unchanged
// (genuine legacy bundles predating this hardening).

function freshEd25519() {
  return generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
}

function buildHashChain(events) {
  const chain = [];
  let prev = "genesis";
  for (const event of events) {
    const hash = createHash("sha256").update(prev + event).digest("hex");
    chain.push(hash);
    prev = hash;
  }
  return chain;
}

// 06.11.2026 (Fix fuer GitHub-Issue #13, unsupported_capability-Default-Deny): dieser Test prueft
// ausschliesslich Trust-Anchor-Pinning im Legacy-Pfad, nicht Capability-/Outcome-Semantik --
// deshalb eine echte, bekannte capability (memory.audit.tamper_evident@1.0) mit einer minimalen,
// trivial "verified" ableitenden Trace statt der frueheren, jetzt als unsupported_capability
// abgelehnten freien capability "test".
const TAMPER_EVIDENT_TRACE_EVENTS = [`audit_chain_check:${JSON.stringify({ source: "audit_chain_probe", chain_valid: true })}`];

function selfSignedLegacyBundle(privateKey, publicKey, extra = {}) {
  const payload = {
    bundle_id: "test-bundle", capability: "memory.audit.tamper_evident@1.0", run_id: "run-1", claim_ladder: "L0",
    executed_at: new Date().toISOString(), trace_events: TAMPER_EVIDENT_TRACE_EVENTS, trace_hash_chain: buildHashChain(TAMPER_EVIDENT_TRACE_EVENTS),
    outcome: "verified", ...extra,
  };
  const signature = sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64");
  return { ...payload, public_key: publicKey, signature };
}

test("rejects a self-signed bundle without schema_version when trustedPublicKey does not match", () => {
  const attacker = freshEd25519();
  const trusted = freshEd25519();
  const bundle = selfSignedLegacyBundle(attacker.privateKey, attacker.publicKey);

  const result = verifyBundleObject(bundle, trusted.publicKey);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "untrusted_signer");
});

test("rejects a self-signed bundle with an unknown foreign schema_version when trustedPublicKey does not match", () => {
  const attacker = freshEd25519();
  const trusted = freshEd25519();
  const bundle = selfSignedLegacyBundle(attacker.privateKey, attacker.publicKey, { schema_version: "memory.capture@1.0" });

  const result = verifyBundleObject(bundle, trusted.publicKey);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "untrusted_signer");
});

test("genuine legacy verification WITHOUT a trustedPublicKey argument is unchanged", () => {
  const signer = freshEd25519();
  const bundle = selfSignedLegacyBundle(signer.privateKey, signer.publicKey);

  const result = verifyBundleObject(bundle);
  assert.deepEqual(result, { ok: true });
});

test("a pinned bundle with a correctly matching trustedPublicKey remains valid", () => {
  const signer = freshEd25519();
  const bundle = selfSignedLegacyBundle(signer.privateKey, signer.publicKey);

  const result = verifyBundleObject(bundle, signer.publicKey);
  assert.deepEqual(result, { ok: true });
});

// 27.11.2026 (Robustheits-Fund, Parity zu alex-core's verify.ts/verify.test.mjs): PEM comparisons
// were byte-sensitive -- a PEM file saved with CRLF instead of LF no longer matched the
// public_key embedded in the bundle (always "\n", since it comes from a JSON string). Both
// variants (LF, CRLF) of the same PEM must yield the same result.
test("CRLF and LF variants of the same trustedPublicKey yield the same result (legacy path)", () => {
  const signer = freshEd25519();
  const bundle = selfSignedLegacyBundle(signer.privateKey, signer.publicKey);
  const crlfKey = signer.publicKey.replace(/\n/g, "\r\n");

  const lfResult = verifyBundleObject(bundle, signer.publicKey);
  const crlfResult = verifyBundleObject(bundle, crlfKey);
  assert.deepEqual(lfResult, { ok: true });
  assert.deepEqual(crlfResult, lfResult);
});

test("CRLF and LF variants of the same example_evidence key yield the same result", () => {
  const exampleEvidenceSigner = freshEd25519();
  const realEvidenceAnchor = freshEd25519();
  const bundle = selfSignedLegacyBundle(exampleEvidenceSigner.privateKey, exampleEvidenceSigner.publicKey);
  const crlfExampleEvidenceKey = exampleEvidenceSigner.publicKey.replace(/\n/g, "\r\n");

  const lfResult = verifyBundleObject(bundle, realEvidenceAnchor.publicKey, undefined, exampleEvidenceSigner.publicKey);
  const crlfResult = verifyBundleObject(bundle, realEvidenceAnchor.publicKey, undefined, crlfExampleEvidenceKey);
  assert.deepEqual(lfResult, { ok: true, classification: "example_evidence_only" });
  assert.deepEqual(crlfResult, lfResult);
});

function selfSignedV2Bundle(privateKey, publicKey) {
  const payload = {
    schema_version: "evidence-package@2.0", bundle_id: "test-v2-bundle", capability: "devtask.execution@1.0",
    run_id: "task-1:1", claim_ladder: "L0", executed_at: new Date().toISOString(), trace_events: [], trace_hash_chain: [],
    outcome: "inconclusive", signer_key_id: evidenceSignerKeyId(publicKey),
  };
  const signature = sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64");
  return { ...payload, public_key: publicKey, signature };
}

test("CRLF and LF variants of the same trustedPublicKey yield the same result (DevTask-V2 path, incl. signer_key_id hash)", () => {
  const signer = freshEd25519();
  const bundle = selfSignedV2Bundle(signer.privateKey, signer.publicKey);
  const crlfKey = signer.publicKey.replace(/\n/g, "\r\n");

  const lfResult = verifyBundleObject(bundle, signer.publicKey);
  const crlfResult = verifyBundleObject(bundle, crlfKey);
  assert.notEqual(lfResult.reason, "untrusted_signer");
  assert.deepEqual(crlfResult, lfResult);
});

// 27.11.2026 (Prompt 2, third variant of the same bug class): the approval_attestation.public_key
// comparison against trustedApprovalPublicKey (approval_attestation_required branch) was not part
// of the above CRLF fix yet. A CRLF-stored --approval-key file did not match the
// approval_attestation.public_key embedded in the bundle (always "\n", since it comes from JSON).
function selfSignedApprovalRequiredBundle(privateKey, publicKey, approverPrivateKey, approverPublicKey) {
  const bundleWithoutApproval = selfSignedLegacyBundle(privateKey, publicKey, { approval_attestation_required: true });
  const approvalPayload = {
    schema_version: "approval-attestation@1.0",
    actor_id: "tester",
    approved_at: new Date().toISOString(),
    bundle_sha256: createHash("sha256").update(JSON.stringify(bundleWithoutApproval)).digest("hex"),
  };
  const approvalSignature = sign(null, Buffer.from(JSON.stringify(approvalPayload)), approverPrivateKey).toString("base64");
  const approval_attestation = {
    ...approvalPayload,
    signer_key_id: evidenceSignerKeyId(approverPublicKey),
    public_key: approverPublicKey,
    signature: approvalSignature,
  };
  return { ...bundleWithoutApproval, approval_attestation };
}

test("CRLF and LF variants of the same trustedApprovalPublicKey yield the same result (approval_attestation_required path)", () => {
  const signer = freshEd25519();
  const approver = freshEd25519();
  const bundle = selfSignedApprovalRequiredBundle(signer.privateKey, signer.publicKey, approver.privateKey, approver.publicKey);
  const crlfApprovalKey = approver.publicKey.replace(/\n/g, "\r\n");

  const lfResult = verifyBundleObject(bundle, signer.publicKey, approver.publicKey);
  const crlfResult = verifyBundleObject(bundle, signer.publicKey, crlfApprovalKey);
  assert.equal(lfResult.ok, true);
  assert.deepEqual(crlfResult, lfResult);
});
