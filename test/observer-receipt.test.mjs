import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { crossCheckObserverReceipt } from "../dist/verify.js";

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

test("crossCheckObserverReceipt: akzeptiert eine echte Inklusion mit bitcoin-bestaetigtem Anker", async (t) => {
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
  assert.deepEqual(result, { ok: true, anchor_status: "bitcoin_confirmed" });
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
