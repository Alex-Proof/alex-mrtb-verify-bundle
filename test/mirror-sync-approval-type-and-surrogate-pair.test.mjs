import assert from "node:assert/strict";
import { generateKeyPairSync, sign, createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateDevTaskEvidenceSpecV1, validateClaimDecomposition, verifyBundleObject } from "../dist/verify.js";

// 08.11.2026 (Mirror-Sync-Nachtrag): Mono-Repo-Commit 25c34d0 ("approval_attestation_required
// Typ-Verwechslung + Surrogat-Crash im Differenz-Fuzzer schliessen") hatte NUR packages/
// langchain-alex/src/langchain_alex/_verifier.py gefixt, nie dieses oeffentliche Mirror-Repo
// (tools/verify-bundle/verify.ts + eigenstaendiges verify.py hier) -- drei echte Luecken blieben
// hier offen, bis dieser Nachtrag sie portiert hat. Jeder Fall unten beweist live, dass der Fix
// in DIESEM Repo tatsaechlich greift, nicht nur im Mono-Repo.

const verifierDir = fileURLToPath(new URL("..", import.meta.url));

function pythonExec(script, ...args) {
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, ...args], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

// --- Fund 1: approval_attestation_required muss strikt Boolean sein, nicht nur truthy. ---

function devtask22BundleStruct(approvalRequired) {
  return {
    schema_version: "evidence-package@2.2", spec_version: "devtask.execution@1.0",
    bundle_id: "mirror-sync-test", capability: "devtask.execution@1.0", run_id: "mirror-sync-test:1",
    claim_ladder: "L0", executed_at: "2026-11-08T00:00:00.000Z",
    trace_events: [], trace_hash_chain: [], outcome: "inconclusive",
    signature: "irrelevant-for-structural-check", public_key: "irrelevant-for-structural-check",
    signer_key_id: "irrelevant", required_evidence: [],
    controller_evidence: {
      producer: "privileged_controller", task_id: "t", attempt_number: 1, base_commit: null,
      result_reference: null, diff_stat_sha256: null, diff_full: null, diff_full_sha256: null,
      execution_reference: null, validation_reference: null, approval_reference: null,
      sandbox_reference: null, sandbox_attestation: null, agent_run_id: null,
    },
    approval_attestation_required: approvalRequired,
  };
}

test("TS: validateDevTaskEvidenceSpecV1 rejects approval_attestation_required=1 (truthy, not boolean)", () => {
  assert.equal(validateDevTaskEvidenceSpecV1(devtask22BundleStruct(1)), "spec_validation_failed:approval_attestation_required_type");
});

test("TS: validateDevTaskEvidenceSpecV1 still accepts a real boolean", () => {
  assert.equal(validateDevTaskEvidenceSpecV1(devtask22BundleStruct(false)), null);
});

test("Python: validate_spec_v1 rejects approval_attestation_required=1 (truthy, not boolean)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mirror-sync-spec-"));
  const inPath = join(dir, "bundle.json");
  writeFileSync(inPath, JSON.stringify(devtask22BundleStruct(1)), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "b=json.load(open(sys.argv[2],encoding='utf-8'))",
    "print(m.validate_spec_v1(b))",
  ].join(";");
  assert.equal(pythonExec(script, inPath), "spec_validation_failed:approval_attestation_required_type");
});

// --- Fund 2: eine Claim-Grenze mitten in einem Surrogatpaar (Emoji) darf kein ungefangenes,
// halbes Unicode-Zeichen erzeugen -- muss regulaer als invalid_claim_offsets abgelehnt werden. ---

const sha256 = (value) => createHash("sha256").update(value, "utf8").digest("hex");

function surrogateSplitArtifact() {
  const originalOutput = "A\u{1F600}B."; // "A" + Surrogatpaar (2 Code-Units) + "B" + "."
  const hash = `sha256:${sha256(originalOutput)}`;
  return {
    artifact: {
      schema_version: "claim-decomposition@1.0", transformer_version: "claim-decomposer@1.0",
      routing_rule_version: "claim-routing-rules@1.0", original_output_sha256: hash,
      review: { proposal_source: "untrusted", status: "unreviewed", reviewed_by: null, reviewed_at: null },
      // Grenze bei Index 2 liegt MITTEN im Surrogatpaar (Index 1-3 sind die zwei Code-Units des Emoji).
      claims: [{ source_start: 0, source_end: 2, source_text: "A\uD83D", type: "fact", route: "retrieval", claim_id: "irrelevant", dependencies: [] }],
    },
    originalOutput,
  };
}

test("TS: validateClaimDecomposition rejects a claim boundary that splits a surrogate pair", () => {
  const { artifact, originalOutput } = surrogateSplitArtifact();
  assert.equal(validateClaimDecomposition(artifact, originalOutput, false), "invalid_claim_offsets");
});

test("Python: validate_claim_decomposition rejects a claim boundary that splits a surrogate pair (no UnicodeEncodeError crash)", () => {
  const { artifact, originalOutput } = surrogateSplitArtifact();
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "artifact=json.loads(sys.argv[2])",
    "print(m.validate_claim_decomposition(artifact,sys.argv[3],False))",
  ].join(";");
  assert.equal(pythonExec(script, JSON.stringify(artifact), originalOutput), "invalid_claim_offsets");
});

// --- Fund 3: TS und Python muessen bei approval_attestation_required=true OHNE approval_attestation
// denselben Ablehnungsgrund liefern (missing_approval_attestation), unabhaengig davon, ob ein
// approval-Trust-Anchor ueberhaupt uebergeben wurde. Vorher lieferte Python hier
// "missing_approval_trust_anchor" (Trust-Anchor-Pruefung lief vor der Attestation-Praesenz-Pruefung) --
// eine echte Divergenz zum selben Fall in TS. alex.core.self_test@1.0 ist absichtlich gewaehlt: diese
// capability ist von jeder Trace-/Outcome-Ableitung ausgenommen, isoliert also exakt den
// Attestation-Reihenfolge-Fix ohne weitere Pfade zu beruehren. ---

function selfTestBundleSignedButUnapproved() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const payload = {
    bundle_id: "mirror-sync-approval-order", capability: "alex.core.self_test@1.0",
    run_id: "mirror-sync-approval-order:1", claim_ladder: "L0", executed_at: "2026-11-08T00:00:00.000Z",
    trace_events: [], trace_hash_chain: [], outcome: "verified", approval_attestation_required: true,
  };
  const signature = sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64");
  return { bundle: { ...payload, signature, public_key: pem }, pem };
}

test("TS: missing approval_attestation is reported before missing approval trust anchor", () => {
  const { bundle, pem } = selfTestBundleSignedButUnapproved();
  assert.deepEqual(verifyBundleObject(bundle, pem), { ok: false, reason: "missing_approval_attestation" });
});

test("Python: missing approval_attestation is reported before missing approval trust anchor (parity with TS)", () => {
  const { bundle, pem } = selfTestBundleSignedButUnapproved();
  const dir = mkdtempSync(join(tmpdir(), "mirror-sync-approval-order-"));
  const inPath = join(dir, "bundle.json");
  writeFileSync(inPath, JSON.stringify(bundle), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "b=json.load(open(sys.argv[2],encoding='utf-8'))",
    "ok,reason=m.verify(dict(b),sys.argv[3],None)",
    "print(json.dumps({'ok':ok,'reason':reason}))",
  ].join(";");
  assert.deepEqual(JSON.parse(pythonExec(script, inPath, pem)), { ok: false, reason: "missing_approval_attestation" });
});
