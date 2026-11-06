import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { verifyBundleObject, crossCheckObserverReceipt } from "../dist/verify.js";

// 06.11.2026 (externe Kritik, GitHub-Issue #13, mit Andre abgestimmt): verifyBundleObject() liess
// den gesamten Trace-Outcome-Abgleich aus, wenn bundle.capability keiner der 7 bekannten
// Konstanten entsprach -- ein gueltig signiertes Bundle mit frei erfundener capability, leerer
// Trace und outcome:"verified" bestand dadurch ohne jeden Trace-Beleg. Default-Deny nur, wenn
// trustedPublicKey ueberhaupt uebergeben wurde.

function freshEd25519() {
  return generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
}

function selfSignedBundle(privateKey, publicKey, extra = {}) {
  const payload = {
    bundle_id: "test-bundle", capability: "freely.invented.capability@1.0", run_id: "run-1",
    claim_ladder: "L0", executed_at: new Date().toISOString(), trace_events: [], trace_hash_chain: [],
    outcome: "verified", ...extra,
  };
  const signature = sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64");
  return { ...payload, public_key: publicKey, signature };
}

test("rejects an unknown, freely invented capability with an empty trace when trustedPublicKey is pinned", () => {
  const signer = freshEd25519();
  const bundle = selfSignedBundle(signer.privateKey, signer.publicKey);

  const result = verifyBundleObject(bundle, signer.publicKey);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "unsupported_capability:freely.invented.capability@1.0");
});

test("an unpinned legacy call (no trustedPublicKey) stays unchanged for an unknown capability", () => {
  const signer = freshEd25519();
  const bundle = selfSignedBundle(signer.privateKey, signer.publicKey);

  const result = verifyBundleObject(bundle);
  assert.deepEqual(result, { ok: true });
});

test("the core self-test capability is exempt from the unknown-capability gate even when pinned", () => {
  const signer = freshEd25519();
  const bundle = selfSignedBundle(signer.privateKey, signer.publicKey, { capability: "alex.core.self_test@1.0" });

  const result = verifyBundleObject(bundle, signer.publicKey);
  assert.deepEqual(result, { ok: true });
});

// 06.11.2026 (externe Kritik, GitHub-Issue #4): crossCheckObserverReceipt() fetched observer_url
// straight out of the bundle being verified -- an attacker could point it at any internal/local
// endpoint and have it serve itself a fake "independent witness" confirmation (SSRF + forgeable
// self-confirmation). Fixed: an optional expectedObserverUrl rejects a mismatching observer_url
// BEFORE any fetch happens.

function startServer(handler) {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, () => resolve(server));
  });
}

test("crossCheckObserverReceipt rejects a bundle-supplied observer_url that doesn't match the expected one, without fetching it", async () => {
  let fetched = false;
  const attackerServer = await startServer((req, res) => {
    fetched = true;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  });
  try {
    const attackerUrl = `http://127.0.0.1:${attackerServer.address().port}/fake-observer`;
    const bundle = {
      bundle_id: "b", capability: "devtask.execution@1.0", run_id: "r", claim_ladder: "L1",
      executed_at: new Date().toISOString(), trace_events: [], trace_hash_chain: [], outcome: "verified",
      observer_receipt: { observer_url: attackerUrl, schema_version: "observer-receipt@1.0" },
    };
    const result = await crossCheckObserverReceipt(bundle, "https://real-observer.example/ingest");
    assert.deepEqual(result, { ok: false, reason: "observer_url_not_allowed" });
    assert.equal(fetched, false, "must reject before ever fetching the attacker-controlled URL");
  } finally {
    attackerServer.close();
  }
});

test("crossCheckObserverReceipt remains unpinned (no SSRF guard) when no expectedObserverUrl is passed", async () => {
  const bundle = {
    bundle_id: "b", capability: "devtask.execution@1.0", run_id: "r", claim_ladder: "L1",
    executed_at: new Date().toISOString(), trace_events: [], trace_hash_chain: [], outcome: "verified",
    observer_receipt: { observer_url: "http://127.0.0.1:1/does-not-matter-here", schema_version: "observer-receipt@1.0" },
  };
  const result = await crossCheckObserverReceipt(bundle);
  assert.notEqual(result.reason, "observer_url_not_allowed");
});
