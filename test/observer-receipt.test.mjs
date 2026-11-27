import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { crossCheckObserverReceipt, verifyObserverReceiptSignatureOffline, verifyBundleObject } from "../dist/verify.js";

const verifierDir = fileURLToPath(new URL("..", import.meta.url));

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);
function sha256(...bufs) { const h = createHash("sha256"); for (const b of bufs) h.update(b); return h.digest(); }
function leafHash(data) { return sha256(LEAF_PREFIX, data); }

function canonicalBundleJson(bundle) {
  const { observer_receipt, ...rest } = bundle;
  return JSON.stringify(rest);
}

/** Startet einen minimalen Mock-Observer, der genau EIN Blatt kennt -- fuer den unabhaengigen
 *  Verifier reicht das, um crossCheckObserverReceipt() gegen einen echten HTTP-Server (statt
 *  gegen ein handgestricktes fetch-Mock) zu pruefen. */
async function startMockObserver({ tamperInclusion = false, anchorStatus = "bitcoin_confirmed" } = {}) {
  let bundleSha256, receivedAt = "2026-09-05T00:00:00.000Z", leaf, rootHash;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/observer/ingest") {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        bundleSha256 = body.bundle_sha256;
        leaf = leafHash(Buffer.from(JSON.stringify({
          bundle_id: body.bundle_id, bundle_sha256: body.bundle_sha256, run_id: body.run_id,
          executed_at: body.executed_at, received_at: receivedAt,
        })));
        rootHash = leaf.toString("hex"); // einzelnes Blatt -- Root == Blatt-Hash, kein Audit-Path noetig.
        res.writeHead(201, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ leaf_index: 0, received_at: receivedAt }));
        return;
      }
      if (req.method === "GET" && req.url?.startsWith("/observer/receipt/")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          found: true,
          bundle_sha256: bundleSha256,
          received_at: receivedAt,
          inclusion: { root_hash: tamperInclusion ? "0".repeat(64) : rootHash, leaf_count: 1, audit_path: [] },
          anchor: { anchor_id: "mock-anchor", status: anchorStatus, created_at: receivedAt },
        }));
        return;
      }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  return { server, url: `http://localhost:${port}` };
}

function buildBundle(observerUrl) {
  const bundle = {
    bundle_id: "obs-test-1", run_id: "run-1", executed_at: "2026-09-05T00:00:00.000Z",
    capability: "devtask.execution@1.0", claim_ladder: "L2", outcome: "verified",
  };
  const bundleSha256 = sha256(Buffer.from(canonicalBundleJson(bundle))).toString("hex");
  return { bundle, bundleSha256 };
}

test("crossCheckObserverReceipt: wertet einen unbelegten bitcoin_confirmed-Status nicht als Bitcoin-Beweis", async (t) => {
  const { server, url } = await startMockObserver({ anchorStatus: "bitcoin_confirmed" });
  t.after(() => server.close());
  const { bundle, bundleSha256 } = buildBundle(url);
  // Push simulieren -- direkt gegen den Mock-Observer, wie observerRelay.server.ts es taete.
  await fetch(`${url}/observer/ingest`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ bundle_id: bundle.bundle_id, bundle_sha256: bundleSha256, run_id: bundle.run_id, executed_at: bundle.executed_at }),
  });
  const withReceipt = { ...bundle, observer_receipt: { schema_version: "observer-receipt@1.0", observer_url: url, leaf_index: 0, received_at: "2026-09-05T00:00:00.000Z" } };
  const result = await crossCheckObserverReceipt(withReceipt);
  assert.deepEqual(result, { ok: true, anchor_status: "observer_reported_bitcoin_confirmed" });
});

test("crossCheckObserverReceipt: meldet not_applicable ohne observer_receipt", async () => {
  const result = await crossCheckObserverReceipt({ bundle_id: "x" });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "not_applicable_no_observer_receipt");
});

test("crossCheckObserverReceipt: lehnt einen manipulierten Merkle-Root ab", async (t) => {
  const { server, url } = await startMockObserver({ tamperInclusion: true });
  t.after(() => server.close());
  const { bundle, bundleSha256 } = buildBundle(url);
  await fetch(`${url}/observer/ingest`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ bundle_id: bundle.bundle_id, bundle_sha256: bundleSha256, run_id: bundle.run_id, executed_at: bundle.executed_at }),
  });
  const withReceipt = { ...bundle, observer_receipt: { schema_version: "observer-receipt@1.0", observer_url: url, leaf_index: 0, received_at: "2026-09-05T00:00:00.000Z" } };
  const result = await crossCheckObserverReceipt(withReceipt);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "inclusion_proof_invalid");
});

test("crossCheckObserverReceipt: lehnt ab, wenn der Bundle-Inhalt nach dem Push manipuliert wurde", async (t) => {
  const { server, url } = await startMockObserver();
  t.after(() => server.close());
  const { bundle, bundleSha256 } = buildBundle(url);
  await fetch(`${url}/observer/ingest`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ bundle_id: bundle.bundle_id, bundle_sha256: bundleSha256, run_id: bundle.run_id, executed_at: bundle.executed_at }),
  });
  const tamperedBundle = { ...bundle, outcome: "failed" }; // Inhalt geaendert NACH dem (simulierten) Push.
  const withReceipt = { ...tamperedBundle, observer_receipt: { schema_version: "observer-receipt@1.0", observer_url: url, leaf_index: 0, received_at: "2026-09-05T00:00:00.000Z" } };
  const result = await crossCheckObserverReceipt(withReceipt);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "bundle_sha256_mismatch");
});

test("crossCheckObserverReceipt: unerreichbarer Observer liefert einen Fehlergrund statt zu werfen", async () => {
  const withReceipt = {
    bundle_id: "x", run_id: "r", executed_at: "t", capability: "c", claim_ladder: "L1", outcome: "verified",
    observer_receipt: { schema_version: "observer-receipt@1.0", observer_url: "http://localhost:1", leaf_index: 0, received_at: "t" },
  };
  const result = await crossCheckObserverReceipt(withReceipt);
  assert.equal(result.ok, false);
  assert.match(result.reason, /^observer_unreachable:/);
});

// Offline-verifiable observer signature (Nov 2026): mirrors the describe-block of the same name
// in alex-core's internal test suite -- standalone verifier, no shared import, so the signature
// is produced here directly instead of via an imported canonical().
function canonicalPayload(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalPayload).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalPayload(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function signedObserverBundle({ leafIndex = 3, receivedAt = "2026-09-05T00:00:00.000Z" } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const bundle = { bundle_id: "b1", run_id: "r1", executed_at: "t1", outcome: "verified" };
  const bundleSha256 = createHash("sha256").update(JSON.stringify(bundle)).digest("hex");
  const payload = {
    schema_version: "observer-signature@1.0", entry_type: "bundle_attestation@1.0",
    bundle_id: bundle.bundle_id, run_id: bundle.run_id, leaf_index: leafIndex, received_at: receivedAt,
    bundle_sha256: bundleSha256,
  };
  const signature = sign(null, Buffer.from(canonicalPayload(payload), "utf8"), privateKey).toString("base64");
  return {
    publicKeyPem,
    bundleWithReceipt: {
      ...bundle,
      observer_receipt: { schema_version: "observer-receipt@1.0", observer_url: "http://example.invalid", leaf_index: leafIndex, received_at: receivedAt, signature },
    },
  };
}

test("verifyObserverReceiptSignatureOffline: akzeptiert eine echte, gegen den gepinnten Public Key gueltige Signatur", () => {
  const { publicKeyPem, bundleWithReceipt } = signedObserverBundle();
  assert.deepEqual(verifyObserverReceiptSignatureOffline(bundleWithReceipt, publicKeyPem), { ok: true });
});

test("verifyObserverReceiptSignatureOffline: lehnt eine Signatur ab, wenn die Bundle-Nutzlast nach dem Signieren manipuliert wurde", () => {
  const { publicKeyPem, bundleWithReceipt } = signedObserverBundle();
  const tampered = { ...bundleWithReceipt, outcome: "inconclusive" };
  assert.deepEqual(verifyObserverReceiptSignatureOffline(tampered, publicKeyPem), { ok: false, reason: "observer_signature_invalid" });
});

test("verifyObserverReceiptSignatureOffline: lehnt eine Signatur ab, wenn leaf_index nach dem Signieren manipuliert wurde", () => {
  const { publicKeyPem, bundleWithReceipt } = signedObserverBundle();
  const tampered = { ...bundleWithReceipt, observer_receipt: { ...bundleWithReceipt.observer_receipt, leaf_index: 999 } };
  assert.deepEqual(verifyObserverReceiptSignatureOffline(tampered, publicKeyPem), { ok: false, reason: "observer_signature_invalid" });
});

test("verifyObserverReceiptSignatureOffline: bleibt Altverhalten (kein Fail), wenn observer_receipt gar keine Signatur traegt", () => {
  const { bundleWithReceipt } = signedObserverBundle();
  const { signature: _omit, ...receiptWithoutSignature } = bundleWithReceipt.observer_receipt;
  const legacyBundle = { ...bundleWithReceipt, observer_receipt: receiptWithoutSignature };
  assert.deepEqual(verifyObserverReceiptSignatureOffline(legacyBundle, "irrelevant"), { ok: false, reason: "signature_missing" });
});

test("verifyObserverReceiptSignatureOffline: meldet explizit, wenn kein Observer-Public-Key gepinnt ist, statt stillschweigend durchzulassen", () => {
  const { bundleWithReceipt } = signedObserverBundle();
  assert.deepEqual(verifyObserverReceiptSignatureOffline(bundleWithReceipt), { ok: false, reason: "no_observer_signing_public_key_pinned" });
});

test("verifyBundleObject: lehnt ein ansonsten gueltiges Bundle mit manipulierter Observer-Signatur ab", () => {
  const { publicKey: mainPublicKey, privateKey: mainPrivateKey } = generateKeyPairSync("ed25519");
  const mainPublicKeyPem = mainPublicKey.export({ type: "spki", format: "pem" }).toString();
  const unsigned = {
    bundle_id: "b1", capability: "core_self_test", run_id: "r1", executed_at: "2026-11-27T00:00:00.000Z",
    claim_ladder: "L1", outcome: "verified", trace_events: [], trace_hash_chain: [],
  };
  const signature = sign(null, Buffer.from(JSON.stringify(unsigned)), mainPrivateKey).toString("base64");
  const signedBundle = { ...unsigned, public_key: mainPublicKeyPem, signature };

  const { publicKeyPem: observerPublicKeyPem } = signedObserverBundle();
  const { bundleWithReceipt: attackerSigned } = signedObserverBundle();
  const bundleWithForgedObserverReceipt = { ...signedBundle, observer_receipt: attackerSigned.observer_receipt };

  const result = verifyBundleObject(bundleWithForgedObserverReceipt, undefined, undefined, undefined, observerPublicKeyPem);
  assert.deepEqual(result, { ok: false, reason: "observer_signature_invalid" });
});

// TS/Python-Parity (verify-bundle-duplicate-logic-drift-Prinzip, siehe alex-core): beide
// Verifier muessen fuer dieselbe Signatur zum selben Ergebnis kommen, nicht nur jeder fuer sich.
function pythonVerifyObserverSignature(bundle, observerKeyPem) {
  const dir = mkdtempSync(join(tmpdir(), "observer-py-"));
  const bundlePath = join(dir, "bundle.json");
  const keyPath = join(dir, "observer.pem");
  writeFileSync(bundlePath, JSON.stringify(bundle));
  writeFileSync(keyPath, observerKeyPem ?? "");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "b=json.load(open(sys.argv[2],encoding='utf-8'))",
    "key=open(sys.argv[3],encoding='utf-8').read() if sys.argv[3] else None",
    "ok,reason=m.verify_observer_receipt_signature_offline(b, key or None)",
    "print(json.dumps({'ok':ok,'reason':reason}))",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, bundlePath, observerKeyPem ? keyPath : ""], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("verifyObserverReceiptSignatureOffline: TypeScript und Python akzeptieren dieselbe echte Signatur identisch", () => {
  const { publicKeyPem, bundleWithReceipt } = signedObserverBundle();
  assert.deepEqual(verifyObserverReceiptSignatureOffline(bundleWithReceipt, publicKeyPem), { ok: true });
  assert.deepEqual(pythonVerifyObserverSignature(bundleWithReceipt, publicKeyPem), { ok: true, reason: null });
});

test("verifyObserverReceiptSignatureOffline: TypeScript und Python lehnen eine manipulierte Signatur identisch ab", () => {
  const { publicKeyPem, bundleWithReceipt } = signedObserverBundle();
  const tampered = { ...bundleWithReceipt, outcome: "inconclusive" };
  assert.deepEqual(verifyObserverReceiptSignatureOffline(tampered, publicKeyPem), { ok: false, reason: "observer_signature_invalid" });
  assert.deepEqual(pythonVerifyObserverSignature(tampered, publicKeyPem), { ok: false, reason: "observer_signature_invalid" });
});
