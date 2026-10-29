import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildVerdictArtifactV1, verifyVerdictArtifactV1 } from "../dist/verify.js";

// Phase 3 (29.10.2026): TS<->Python-Paritaet fuer verdict-artifact@1.0. Die Akte wird mit dem
// exportierten TS buildVerdictArtifactV1() aus einem validen, signierten Quell-Bundle erzeugt; beide
// Verifier leiten dieselbe erwartete Akte neu ab (build_verdict_artifact_v1 in Python) und vergleichen
// byte-gleich. Der verifier_build_sha256 ist hier ein fester Parameter fuer BEIDE Seiten.
const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const sha256 = v => createHash("sha256").update(v).digest("hex");
const BUILD_HASH = "sha256:" + "a".repeat(64);

// Wohlgeformtes, signiertes evidence-package@2.0-Quell-Bundle: contract_snapshot mit passendem
// devtask_contract_bound-Event (contract_hash == sha256(JSON.stringify(snapshot))), konsistente
// trace_hash_chain, korrektes required_evidence. Outcome bleibt "inconclusive" (nur contract-Event,
// kein attempt/outcome) -- das ist fuer eine Verdict-Akte erlaubt (non_verified_outcome:inconclusive).
function sourceBundle({ omitPolicy = false } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const contract_snapshot = { rawText: "Bitte README ergaenzen.", acceptanceCriteria: ["README aktualisiert"], protectExistingTests: false };
  const contractHash = sha256(JSON.stringify(contract_snapshot));
  const contractEvent = `devtask_contract_bound:${JSON.stringify({ task_id: "t1", attempt_number: 1, contract_hash: contractHash, risk_class: "R2", protect_existing_tests: false })}`;
  const trace_events = [contractEvent];
  const trace_hash_chain = [sha256("genesis" + contractEvent)];
  const controller = {
    producer: "privileged_controller", task_id: "t1", attempt_number: 1, base_commit: null,
    result_reference: null, diff_stat_sha256: null, diff_full: null, diff_full_sha256: null,
    execution_reference: null, validation_reference: null, approval_reference: null,
    sandbox_reference: null, sandbox_attestation: null, agent_run_id: null,
    contract_snapshot,
  };
  if (!omitPolicy) controller.policy_snapshot_sha256 = sha256("policy-snapshot");
  const payload = {
    schema_version: "evidence-package@2.0", bundle_id: "verdict-source", capability: "devtask.execution@1.0",
    run_id: "t1:1", claim_ladder: "L0", executed_at: "2026-10-29T00:00:00.000Z",
    trace_events, trace_hash_chain, outcome: "inconclusive",
    signer_key_id: `ed25519:${sha256(pem)}`, controller_evidence: controller,
    required_evidence: ["contract", "attempt", "execution_context", "validation", "outcome", "base_commit", "diff_full"],
  };
  const signature = sign(null, Buffer.from(JSON.stringify(payload), "utf8"), privateKey).toString("base64");
  return { bundle: { ...payload, signature, public_key: pem }, pem };
}

function pythonVerifyVerdict(artifact, trustedKey, buildHash) {
  const dir = mkdtempSync(join(tmpdir(), "verdict-"));
  const inputPath = join(dir, "input.json");
  writeFileSync(inputPath, JSON.stringify({ artifact, trusted_key: trustedKey, build_hash: buildHash }), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "d=json.load(open(sys.argv[2],encoding='utf-8'))",
    "ok,reason=m.verify_verdict_artifact_v1(d['artifact'],d['trusted_key'],d['build_hash'])",
    "print('ok' if ok else reason)",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function tsVerifyVerdict(artifact, trustedKey, buildHash) {
  const r = verifyVerdictArtifactV1(artifact, trustedKey, buildHash);
  return r.ok ? "ok" : r.reason;
}

test("verdict-artifact: TS and Python agree on a valid verdict and every reason-code", () => {
  const cases = [];
  { const { bundle, pem } = sourceBundle(); const v = buildVerdictArtifactV1(bundle, BUILD_HASH); cases.push(["valid", v, pem, BUILD_HASH, "ok"]); }
  { const { bundle, pem } = sourceBundle(); const v = buildVerdictArtifactV1(bundle, BUILD_HASH); cases.push(["unsupported_verdict_schema", { ...v, schema_version: "verdict-artifact@2.0" }, pem, BUILD_HASH, "unsupported_verdict_schema"]); }
  { const { bundle, pem } = sourceBundle(); const v = buildVerdictArtifactV1(bundle, BUILD_HASH); cases.push(["verdict_derivation_mismatch", { ...v, decision: { ...v.decision, verdict: "verified" } }, pem, BUILD_HASH, "verdict_derivation_mismatch"]); }
  { const { bundle, pem } = sourceBundle(); const v = buildVerdictArtifactV1(bundle, BUILD_HASH); cases.push(["invalid_verifier_build_hash", v, pem, "not-a-valid-hash", "invalid_verifier_build_hash"]); }
  { const { bundle, pem } = sourceBundle(); const v = buildVerdictArtifactV1(bundle, BUILD_HASH); const tampered = { ...v, source_bundle: { ...v.source_bundle, controller_evidence: { ...v.source_bundle.controller_evidence } } }; delete tampered.source_bundle.controller_evidence.policy_snapshot_sha256; cases.push(["missing_frozen_policy_hash", tampered, pem, BUILD_HASH, "missing_frozen_policy_hash"]); }
  { const { bundle, pem } = sourceBundle(); const v = buildVerdictArtifactV1(bundle, BUILD_HASH); cases.push(["source_bundle_untrusted_signer", v, generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString(), BUILD_HASH, "source_bundle_untrusted_signer"]); }

  for (const [name, artifact, key, buildHash, expected] of cases) {
    const ts = tsVerifyVerdict(artifact, key, buildHash);
    assert.equal(ts, expected, `TS verdict "${name}"`);
    assert.equal(pythonVerifyVerdict(artifact, key, buildHash), ts, `parity verdict "${name}"`);
  }
});
