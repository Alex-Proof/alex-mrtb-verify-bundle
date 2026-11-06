import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

// 06.11.2026 (externe Kritik, GitHub-Issues #6/#8): verifyBundleObject() in verify.ts prueft bei
// isDevTaskV2Schema()-Bundles mit gesetztem controller_evidence.contract_snapshot, ob
// sha256(JSON.stringify(snapshot)) zum contract_hash aus dem passenden devtask_contract_bound-
// Trace-Event passt (Issue #6), und baut fuer evidence-package@2.1/2.2/2.3-mit-customer_evidence
// deterministisch einen deutschen Text, der exakt gegen customer_evidence.customer_summary
// verglichen wird (Issue #8). verify.py fuehrte beide Pruefungen bisher an keiner Stelle durch --
// ein sonst voll "verified" signiertes Bundle mit manipuliertem Snapshot oder frei erfundenem
// Summary wurde faelschlich akzeptiert. Fixtures mit dem echten TS-Verifier gebaut (frischer
// Testschluessel), nicht von Hand konstruiert.

const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const contractSnapshotFixture = fileURLToPath(new URL("../evidence-package-2-0-contract-snapshot-tampered.json", import.meta.url));
const customerSummaryFixture = fileURLToPath(new URL("../evidence-package-2-1-customer-summary-tampered.json", import.meta.url));

function pythonVerify(path) {
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "b=json.load(open(sys.argv[2],encoding='utf-8'))",
    "ok,reason=m.verify(dict(b),b['public_key'],None)",
    "print(json.dumps({'ok':ok,'reason':reason}))",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, path], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("Python rejects a contract_snapshot that does not match the devtask_contract_bound hash (Issue #6)", () => {
  JSON.parse(readFileSync(contractSnapshotFixture, "utf8"));
  assert.deepEqual(pythonVerify(contractSnapshotFixture), { ok: false, reason: "contract_snapshot_hash_mismatch" });
});

test("Python rejects a customer_summary that does not match the deterministic build (Issue #8)", () => {
  JSON.parse(readFileSync(customerSummaryFixture, "utf8"));
  assert.deepEqual(pythonVerify(customerSummaryFixture), { ok: false, reason: "customer_summary_mismatch" });
});
