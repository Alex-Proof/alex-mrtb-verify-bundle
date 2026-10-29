import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { canonicalEvidenceJson } from "../dist/verify.js";

// Phase 0 (29.10.2026): Fundament-Paritaetstest fuer die Kanonisierung. verify.test.mjs bindet bereits
// den TS-canonicalEvidenceJson gegen das Goldfile; dieser Test beweist, dass der eigenstaendige Python-
// Verifier (canonical_evidence_bytes) BYTE-GLEICH kanonisiert -- dieselbe rekursive Schluessel-
// sortierung, kompakte Separatoren (",",":") und UTF-8-Ausgabe (ensure_ascii=False). Das ist die
// Grundlage fuer jede sprachuebergreifende Hash-/Signatur-Paritaet (u.a. das policy_sha256 der
// Sandbox-Attestation in Phase 1). Bytes gehen base64-kodiert durch die Prozessgrenze, damit die
// Windows-Konsolen-Codepage das Nicht-ASCII-Zeichen im Goldfile ("ae") nicht verfaelscht.
const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const goldPath = fileURLToPath(new URL("../spec/canonicalization-v1.gold.json", import.meta.url));
const gold = JSON.parse(readFileSync(goldPath, "utf8"));
const sha256 = value => createHash("sha256").update(value).digest("hex");

function pythonCanonical(path) {
  const script = [
    "import importlib.util,json,sys,base64,hashlib",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "v=json.load(open(sys.argv[2],encoding='utf-8'))['input']",
    "b=m.canonical_evidence_bytes(v)",
    "print(json.dumps({'b64':base64.b64encode(b).decode(),'sha256':hashlib.sha256(b).hexdigest()}))",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, path], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("canonical_evidence_bytes: Python matches the goldfile and the TypeScript canonicalizer byte-for-byte", () => {
  const { b64, sha256: pySha } = pythonCanonical(goldPath);
  const pyCanonical = Buffer.from(b64, "base64").toString("utf8");

  // 1) Python == Goldfile (Bytes + sha256)
  assert.equal(pyCanonical, gold.canonical_utf8, "Python canonical bytes must equal the goldfile");
  assert.equal(pySha, gold.sha256, "Python canonical sha256 must equal the goldfile");

  // 2) TS == Goldfile (gleiche Bindung wie verify.test.mjs, hier als Anker wiederholt)
  const ts = canonicalEvidenceJson(gold.input);
  assert.equal(ts, gold.canonical_utf8, "TS canonical must equal the goldfile");
  assert.equal(sha256(ts), gold.sha256, "TS canonical sha256 must equal the goldfile");

  // 3) Paritaet: Python == TS (die eigentliche Fundament-Zusicherung fuer Phase 1+)
  assert.equal(pyCanonical, ts, "parity: Python canonical_evidence_bytes == TS canonicalEvidenceJson");
});
