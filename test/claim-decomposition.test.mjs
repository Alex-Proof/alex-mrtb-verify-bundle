import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateClaimDecomposition, verifyBundleObject } from "../dist/verify.js";

// 29.10.2026 (vNext 4.18 Claim-Zerlegung): Paritaets-Regression fuer die aus dem lokalen verify.ts /
// _verifier.py portierte claim_decomposition-Pruefung. Gleiches Muster wie python-rfc3161.test.mjs:
// dasselbe Artefakt durch den TS- und den eigenstaendigen Python-Verifier jagen -- Verdikt UND
// reason-code muessen bytegleich sein. Die Pruefung selbst (validate_claim_decomposition) ist der
// portable Kern; die aeussere verify()-Verdrahtung praefixt nur "claim_decomposition_".
const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const sha256 = value => createHash("sha256").update(value).digest("hex");

const CLAIM_DECOMPOSER_VERSION = "claim-decomposer@1.0";
const CLAIM_ROUTING_RULE_VERSION = "claim-routing-rules@1.0";
function claimId(outputHash, start, end, type) {
  return `claim:sha256:${sha256(`${CLAIM_DECOMPOSER_VERSION}\0${outputHash}\0${start}\0${end}\0${type}`)}`;
}

const seg1 = "Paris is the capital of France.";
const seg2 = "2 + 2 = 4.";
const originalOutput = `${seg1} ${seg2}`;
const outputHash = `sha256:${sha256(originalOutput)}`;

function claim({ start, end, type, route, status = "verified", dependencies = [] }) {
  return {
    claim_id: claimId(outputHash, start, end, type),
    source_start: start, source_end: end, source_text: originalOutput.slice(start, end),
    type, dependencies, route, status, reason: null,
  };
}

function validArtifact() {
  return {
    schema_version: "claim-decomposition@1.0",
    transformer_version: CLAIM_DECOMPOSER_VERSION,
    routing_rule_version: CLAIM_ROUTING_RULE_VERSION,
    original_output: originalOutput,
    original_output_sha256: outputHash,
    review: { proposal_source: "untrusted", status: "reviewed", reviewed_by: "andre", reviewed_at: "2026-10-29T00:00:00.000Z" },
    claims: [
      claim({ start: 0, end: seg1.length, type: "fact", route: "retrieval" }),
      claim({ start: seg1.length + 1, end: originalOutput.length, type: "numeric", route: "calculation_engine" }),
    ],
  };
}

// None/null auf der Python-Seite -> "ok", damit beide Verifier byte-gleich vergleichbar sind.
function pythonValidate(artifact, requireReview = true) {
  const dir = mkdtempSync(join(tmpdir(), "claimdec-"));
  const inputPath = join(dir, "input.json");
  writeFileSync(inputPath, JSON.stringify({ artifact, original_output: artifact.original_output, require_review: requireReview }), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "d=json.load(open(sys.argv[2],encoding='utf-8'))",
    "r=m.validate_claim_decomposition(d['artifact'],d['original_output'],d['require_review'])",
    "print(r if r is not None else 'ok')",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function tsValidate(artifact, requireReview = true) {
  const reason = validateClaimDecomposition(artifact, artifact.original_output, requireReview);
  return reason === null ? "ok" : reason;
}

// Jede Mutation erzeugt genau EINE Abweichung und muss in BEIDEN Verifiern denselben reason-code liefern.
const mutations = {
  valid: a => a,
  unsupported_schema_version: a => ({ ...a, schema_version: "claim-decomposition@2.0" }),
  unsupported_transformer_version: a => ({ ...a, transformer_version: "claim-decomposer@0.9" }),
  unsupported_routing_rule_version: a => ({ ...a, routing_rule_version: "claim-routing-rules@0.9" }),
  original_output_hash_mismatch: a => ({ ...a, original_output_sha256: `sha256:${"0".repeat(64)}` }),
  invalid_proposal_source: a => ({ ...a, review: { ...a.review, proposal_source: "trusted" } }),
  review_required: a => ({ ...a, review: { proposal_source: "untrusted", status: "unreviewed", reviewed_by: null, reviewed_at: null } }),
  invalid_review_metadata: a => ({ ...a, review: { ...a.review, reviewed_by: "" } }),
  missing_claims: a => ({ ...a, claims: [] }),
  invalid_claim_offsets: a => ({ ...a, claims: [{ ...a.claims[0], source_end: a.claims[0].source_start }] }),
  source_text_mismatch: a => ({ ...a, claims: [{ ...a.claims[0], source_text: "Berlin is the capital of France" }] }),
  routing_mismatch: a => ({ ...a, claims: [{ ...a.claims[0], route: "calculation_engine" }] }),
  claim_id_mismatch: a => ({ ...a, claims: [{ ...a.claims[0], claim_id: `claim:sha256:${"1".repeat(64)}` }] }),
  invalid_claim_dependency: a => ({ ...a, claims: [{ ...a.claims[0], dependencies: [""] }] }),
};

test("claim_decomposition: TS and Python verifier agree on every reason-code", () => {
  for (const [name, mutate] of Object.entries(mutations)) {
    const expected = name === "valid" ? "ok" : name;
    const artifact = mutate(validArtifact());
    const ts = tsValidate(artifact);
    const py = pythonValidate(artifact);
    assert.equal(ts, expected, `TS verdict for ${name}`);
    assert.equal(py, ts, `parity TS<->Python for ${name}`);
  }
});

test("recommendation/mixed status constraints match across verifiers", () => {
  const rec = validArtifact();
  rec.claims[1] = claim({ start: seg1.length + 1, end: originalOutput.length, type: "recommendation", route: "human_review", status: "verified" });
  assert.equal(tsValidate(rec), "recommendation_status_mismatch");
  assert.equal(pythonValidate(rec), "recommendation_status_mismatch");

  const mixed = validArtifact();
  mixed.claims[1] = claim({ start: seg1.length + 1, end: originalOutput.length, type: "mixed", route: "none", status: "verified" });
  assert.equal(tsValidate(mixed), "unverifiable_status_mismatch");
  assert.equal(pythonValidate(mixed), "unverifiable_status_mismatch");
});

// Integration auf der TS-Seite: claim_decomposition ist Teil der signierten Nutzlast und wird VOR der
// Signaturpruefung strukturell geprueft (Struktur vor Signatur). Der Python-verify()-Wrapper hat
// dieselbe Verdrahtung, greift aber nur fuer capability "devtask.execution@1.0" -- die byte-genaue
// Parity des gemeinsamen Kerns ist oben bereits bewiesen.
function signedBundleWithDecomposition(artifact) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const event = "memory_write:{\"entry_id\":\"e1\",\"actual_agent_id\":\"a\",\"provenance_agent_id\":\"a\",\"actual_source_hash\":\"h\",\"provenance_source_hash\":\"h\"}";
  const payload = {
    bundle_id: "claimdec_bundle", capability: "memory.provenance.attached@1.0", run_id: "claimdec_run",
    claim_ladder: "L2", executed_at: "2026-10-29T00:00:00.000Z",
    trace_events: [event], trace_hash_chain: [createHash("sha256").update("genesis" + event).digest("hex")],
    outcome: "verified", claim_decomposition: artifact,
  };
  return {
    ...payload,
    signature: sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64"),
    public_key: publicKey.export({ type: "spki", format: "pem" }),
  };
}

test("verifyBundleObject accepts a signed bundle carrying a valid claim_decomposition", () => {
  assert.deepEqual(verifyBundleObject(signedBundleWithDecomposition(validArtifact())), { ok: true });
});

test("verifyBundleObject rejects a tampered claim_decomposition before checking the signature", () => {
  const bundle = signedBundleWithDecomposition(validArtifact());
  bundle.claim_decomposition.claims[0].source_text = "Berlin is the capital of France";
  assert.deepEqual(verifyBundleObject(bundle), { ok: false, reason: "claim_decomposition_source_text_mismatch" });
});
