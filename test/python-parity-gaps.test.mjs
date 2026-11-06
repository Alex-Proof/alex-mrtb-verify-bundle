import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

// 06.11.2026 (externe Kritik): verify.ts prueft approval_attestation_required nur per JS-Truthy
// ("if (bundle.approval_attestation_required)"), verify.py bisher per strikter Gleichheit zu
// Python True ("is True"). Ein Bundle mit approval_attestation_required: 1 (statt true) wurde von
// TS weiterhin als "Freigabe erforderlich" gewertet, von Python aber nicht -- ein sonst
// freigabepflichtiges Bundle ohne gueltige approval_attestation waere in Python faelschlich
// akzeptiert worden. _js_truthy() schliesst diese Luecke.
function pythonJsTruthy(value) {
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "print(json.dumps(m._js_truthy(json.loads(sys.argv[2]))))",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, JSON.stringify(value)], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("Python _js_truthy matches JS Boolean() coercion for every JSON-representable value", () => {
  for (const [value, expected] of [
    [true, true], [false, false], [1, true], [0, false], [-1, true],
    ["x", true], ["", false], [null, false], [[], true], [{}, true],
  ]) {
    assert.equal(pythonJsTruthy(value), Boolean(value), `_js_truthy(${JSON.stringify(value)})`);
    assert.equal(pythonJsTruthy(value), expected);
  }
});

// 06.11.2026 (externe Kritik, GitHub-Issue #10): receipt_chain_entry (ADR 06 / vNext 4.12) haengt
// als AEUSSERSTE Schicht an und war nie Teil der signierten Nutzlast -- verify.py strippte es
// bisher an keiner Stelle, wodurch jedes sonst gueltige Bundle mit receipt_chain_entry faelschlich
// invalid_signature lieferte.
function pythonVerifyRaw(bundle) {
  const dir = mkdtempSync(join(tmpdir(), "receipt-chain-"));
  const inputPath = join(dir, "bundle.json");
  writeFileSync(inputPath, JSON.stringify(bundle), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "b=json.load(open(sys.argv[3],encoding='utf-8'))",
    "ok,reason=m.verify(dict(b),sys.argv[2],None)",
    "print(json.dumps({'ok':ok,'reason':reason}))",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, bundle.public_key, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("Python accepts a bundle with receipt_chain_entry attached, identical to the same bundle without it (Issue #10)", () => {
  const bundle = JSON.parse(readFileSync(fileURLToPath(new URL("../independence/demo-pr-38.json", import.meta.url)), "utf8"));
  const without = pythonVerifyRaw(bundle);
  const withEntry = pythonVerifyRaw({ ...bundle, receipt_chain_entry: { schema_version: "receipt-chain-entry@1.0", leaf_index: 7, prev_hash: "a".repeat(64) } });
  assert.deepEqual(withEntry, without, "receipt_chain_entry must not change the verdict");
});

// 06.11.2026 (externe Kritik, GitHub-Issue #11): source_start/source_end zaehlen in TS UTF-16-
// Code-Units, in Python bisher native Codepoints -- bei Zeichen ausserhalb der Basic Multilingual
// Plane (Emoji) wichen beide Zaehlweisen auseinander.
function pythonClaimOffsetsUtf16() {
  const script = [
    "import importlib.util,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "original_output='\\U0001F600X'",
    "output_hash='sha256:'+m.sha256_text(original_output)",
    "claim_type='fact'",
    "emoji_claim={'source_start':0,'source_end':2,'source_text':'\\U0001F600','type':claim_type,'route':m.CLAIM_ROUTE_BY_TYPE[claim_type],'claim_id':m._claim_id(output_hash,0,2,claim_type),'dependencies':[]}",
    "x_claim={'source_start':2,'source_end':3,'source_text':'X','type':claim_type,'route':m.CLAIM_ROUTE_BY_TYPE[claim_type],'claim_id':m._claim_id(output_hash,2,3,claim_type),'dependencies':[]}",
    "artifact={'schema_version':'claim-decomposition@1.0','transformer_version':m.CLAIM_DECOMPOSER_VERSION,'routing_rule_version':m.CLAIM_ROUTING_RULE_VERSION,'original_output_sha256':output_hash,'review':{'proposal_source':'untrusted','status':'unreviewed','reviewed_by':None,'reviewed_at':None},'claims':[emoji_claim,x_claim]}",
    "print(m.validate_claim_decomposition(artifact,original_output,False))",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

test("Python claim-decomposition offsets count UTF-16 code units, not codepoints, for emoji text (Issue #11)", () => {
  assert.equal(pythonClaimOffsetsUtf16(), "None", "offset 0:2 must hit exactly the emoji under UTF-16 counting, not an error");
});
