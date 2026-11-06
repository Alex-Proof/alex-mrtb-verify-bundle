import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { verifyBundleObject } from "../dist/verify.js";

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

function selfSignedLegacyBundle(privateKey, publicKey, extra = {}) {
  const payload = {
    bundle_id: "test-bundle", capability: "test", run_id: "run-1", claim_ladder: "L0",
    executed_at: new Date().toISOString(), trace_events: [], trace_hash_chain: [],
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
