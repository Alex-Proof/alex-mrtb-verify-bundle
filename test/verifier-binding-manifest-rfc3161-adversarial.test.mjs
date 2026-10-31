import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildVerifierBindingManifestV1, verifyVerifierBindingManifestV1, verifyRfc3161TsaChain } from "../dist/verify.js";

// 31.10.2026 (externer Haertungsvorschlag, SaSame @sasame-mcp.bsky.social, auf Bluesky): "after
// RFC3161 issuance, mutate one manifest field while keeping the token, then separately keep the
// manifest and mutate the bundle. Both should fail verification. That tests whether the timestamp
// binds the exact evidence, not just the run."
//
// Nutzt independence/demo-pr-38.json -- ein ECHTES, bei FreeTSA bezogenes Zeitstempel-Token, kein
// Mock. Beide Faelle laufen in TS UND Python, gegen dasselbe reale Bundle.
const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const fixturePath = fileURLToPath(new URL("../independence/demo-pr-38.json", import.meta.url));
const bundle = JSON.parse(readFileSync(fixturePath, "utf8"));
const trustedKey = bundle.public_key;
const trustedApprovalKey = bundle.approval_attestation.public_key;

function pythonVerify(manifest, bundleArg) {
  const dir = mkdtempSync(join(tmpdir(), "rfc3161-adversarial-"));
  const inputPath = join(dir, "input.json");
  writeFileSync(inputPath, JSON.stringify({ manifest, bundle: bundleArg, trustedKey, trustedApprovalKey }), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "d=json.load(open(sys.argv[2],encoding='utf-8'))",
    "ok,reason=m.verify_verifier_binding_manifest_v1(d['manifest'],d['bundle'],d['trustedKey'],d['trustedApprovalKey'])",
    "print('ok' if ok else reason)",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

test("verifier-binding-manifest + real RFC3161 token: the untouched baseline verifies ok", () => {
  const manifest = buildVerifierBindingManifestV1(bundle);
  assert.ok(manifest.repo_state_timestamp, "fixture must carry a real rfc3161_timestamp");
  const ts = verifyVerifierBindingManifestV1(manifest, bundle, trustedKey, trustedApprovalKey);
  assert.deepEqual(ts, { ok: true });
  assert.equal(pythonVerify(manifest, bundle), "ok");
});

test("adversarial check 1: one manifest field forged, repo_state_timestamp (the token) left byte-identical -> rejected", () => {
  const manifest = buildVerifierBindingManifestV1(bundle);
  const forged = { ...manifest, diff_hash: "0".repeat(64) };
  assert.deepEqual(forged.repo_state_timestamp, manifest.repo_state_timestamp, "token must stay untouched for this check to be meaningful");

  const ts = verifyVerifierBindingManifestV1(forged, bundle, trustedKey, trustedApprovalKey);
  assert.equal(ts.ok, false);
  assert.equal(pythonVerify(forged, bundle), ts.reason);
});

test("adversarial check 2: manifest left byte-identical, bundle mutated underneath it -> rejected", () => {
  const manifest = buildVerifierBindingManifestV1(bundle);
  const mutatedBundle = JSON.parse(JSON.stringify(bundle));
  mutatedBundle.controller_evidence.diff_full += "\n// injected line";

  const ts = verifyVerifierBindingManifestV1(manifest, mutatedBundle, trustedKey, trustedApprovalKey);
  assert.equal(ts.ok, false);
  assert.equal(pythonVerify(manifest, mutatedBundle), ts.reason);
});

// 31.10.2026, Nachtrag auf SaSames eigene Rueckfrage: die beiden Faelle oben scheitern BEIDE schon
// vor der RFC3161-Pruefung selbst (Fall 1 ueber manifest_derivation_mismatch, Fall 2 ebenfalls --
// evidence_package_sha256 bindet das gesamte Bundle). Keiner beweist, dass die RFC3161-Bindung
// SELBST etwas prueft. SaSames Vorschlag: einen echten, bei FreeTSA gueltigen Token nehmen, der
// aber fuer ein ANDERES Bundle ausgestellt wurde, und ihn hier einsetzen. Das unveraenderte Bundle
// muss die Herleitung bestehen (das Manifest wird korrekt AUS dem -- jetzt mit dem fremden Token
// versehenen -- Bundle neu gebaut, nichts weicht ab), und erst DANACH muss die RFC3161-Bindung
// selbst fehlschlagen, weil der Token zu einem anderen Hash passt. Echtes Quell-Bundle hier bewusst
// SYNTHETISCH (kein `approval_attestation`): alle vier echten Fixtures mit vollstaendigen Feldern
// haben approval_attestation_required=true, dessen bundle_sha256-Pruefung den fremden Token-Tausch
// VORHER abfaengt (bundle_sha256 wurde ueber den urspruenglichen Token berechnet) -- das wuerde die
// RFC3161-Pruefung selbst wieder maskieren, genau das Problem, das dieser Test beheben soll.
function syntheticBundleWithoutApproval() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const sha256 = v => createHash("sha256").update(v).digest("hex");
  const canonical = value => {
    if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
    if (value && typeof value === "object") return `{${Object.keys(value).sort().filter(k => value[k] !== undefined).map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
    return JSON.stringify(value);
  };
  const run = { task_id: "adversarial-src", attempt_number: 1 };
  const contract_snapshot = { rawText: "x", acceptanceCriteria: ["ok"], protectExistingTests: false };
  const repositoryState = { schema_version: "repository-state@1.0", base_commit: "a".repeat(40), result_commit: "b".repeat(40), tree_before_sha256: sha256("before"), tree_after_sha256: sha256("after"), changed_files: [] };
  const traceEvents = [
    `devtask_contract_bound:${JSON.stringify({ ...run, contract_hash: sha256(JSON.stringify(contract_snapshot)), risk_class: "R1" })}`,
    `devtask_attempt_started:${JSON.stringify({ ...run, started_at: "2026-10-31T00:00:00Z" })}`,
    `devtask_execution_context:${JSON.stringify({ ...run, execution_reference: "attempt:1", sandbox_reference: null })}`,
    `devtask_validation:${JSON.stringify({ ...run, validation_status: "passed", validation_reference: "validation:1" })}`,
    `devtask_diff_evidence:${JSON.stringify({ ...run, diff_stat_sha256: sha256("stat"), diff_full_sha256: sha256("diff"), scope: "diff_stat_and_full" })}`,
    `devtask_outcome:${JSON.stringify({ ...run, outcome: "ABORTED", completed_at: "2026-10-31T00:01:00Z" })}`,
  ];
  let prev = "genesis";
  const trace_hash_chain = traceEvents.map(e => (prev = sha256(prev + e)));
  const controller_evidence = {
    producer: "privileged_controller", ...run, base_commit: repositoryState.base_commit, result_reference: null,
    policy_snapshot_sha256: sha256("policy-snapshot"), diff_stat_sha256: sha256("stat"), diff_full: "diff",
    diff_full_sha256: sha256("diff"), execution_reference: "attempt:1", validation_reference: "validation:1",
    approval_reference: null, sandbox_reference: null, sandbox_attestation: null, agent_run_id: null,
    contract_snapshot, repository_state: repositoryState,
  };
  const payload = {
    schema_version: "evidence-package@2.2", spec_version: "devtask.execution@1.0", bundle_id: "adversarial-src",
    capability: "devtask.execution@1.0", run_id: "adversarial-src:1", claim_ladder: "L0", executed_at: "2026-10-31T00:01:00Z",
    trace_events: traceEvents, trace_hash_chain, outcome: "failed", signer_key_id: `ed25519:${sha256(pem)}`, controller_evidence,
    required_evidence: ["contract", "attempt", "execution_context", "validation", "outcome", "base_commit", "diff_full", "repository_state"],
    approval_attestation_required: false,
  };
  const signature = sign(null, Buffer.from(canonical(payload), "utf8"), privateKey).toString("base64");
  return { bundle: { ...payload, signature, public_key: pem }, pem };
}

function pythonVerifyNoApproval(manifest, bundleArg, key) {
  const dir = mkdtempSync(join(tmpdir(), "rfc3161-foreign-token-"));
  const inputPath = join(dir, "input.json");
  writeFileSync(inputPath, JSON.stringify({ manifest, bundle: bundleArg, trustedKey: key }), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "d=json.load(open(sys.argv[2],encoding='utf-8'))",
    "ok,reason=m.verify_verifier_binding_manifest_v1(d['manifest'],d['bundle'],d['trustedKey'])",
    "print('ok' if ok else reason)",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

test("adversarial check 3: a real, validly-chained FreeTSA token issued for a DIFFERENT bundle is rejected on binding, not on derivation", () => {
  const { bundle: syntheticBundle, pem } = syntheticBundleWithoutApproval();
  const foreignToken = bundle.rfc3161_timestamp; // demo-pr-38's own real token -- genuine, wrong bundle.

  // The token itself is not a forgery -- its CMS signature and FreeTSA chain are genuinely valid.
  assert.deepEqual(verifyRfc3161TsaChain(foreignToken), { ok: true });

  const sabotaged = { ...syntheticBundle, rfc3161_timestamp: foreignToken };
  const manifest = buildVerifierBindingManifestV1(sabotaged);
  // Derivation must NOT be where this fails: the manifest is built fresh from the (otherwise
  // untouched) sabotaged bundle, so every field -- including the copied-in foreign token --
  // matches what re-deriving it would produce again.
  const rebuilt = buildVerifierBindingManifestV1(sabotaged);
  assert.deepEqual(manifest, rebuilt);

  const result = verifyVerifierBindingManifestV1(manifest, sabotaged, pem);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "rfc3161_timestamp_hash_mismatch");
  assert.equal(pythonVerifyNoApproval(manifest, sabotaged, pem), result.reason);
});
