import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { verifyRfc3161Binding, verifyRfc3161TsaChain } from "../dist/verify.js";

const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const privateFixtures = [31, 33, 35, 36, 37, 38, 39]
  .map(number => fileURLToPath(new URL(`../../../public/downloads/verify-bundle/demo-pr-${number}.json`, import.meta.url)));
const publicFixtures = [
  fileURLToPath(new URL("../evidence/pr-19-deepseek.json", import.meta.url)),
  fileURLToPath(new URL("../evidence/pr-20-hermes.json", import.meta.url)),
  fileURLToPath(new URL("../evidence/pr-31-deepseek.json", import.meta.url)),
  fileURLToPath(new URL("../independence/demo-pr-38.json", import.meta.url)),
];
const fixtures = (privateFixtures.every(existsSync) ? privateFixtures : publicFixtures).filter(existsSync);

function pythonChecks(path) {
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "b=json.load(open(sys.argv[2],encoding='utf-8'))",
    "bo,br=m.verify_rfc3161_binding(b)",
    "co,cr=m.verify_rfc3161_tsa_chain(b['rfc3161_timestamp']) if bo else (False,None)",
    "print(json.dumps({'binding':'ok' if bo else br,'chain':'ok' if co else cr}))",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, path], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("Python RFC-3161 checks match the TypeScript verifier on real bundles", () => {
  assert.ok(fixtures.length > 0, "no RFC-3161 fixture found");
  for (const path of fixtures) {
    const bundle = JSON.parse(readFileSync(path, "utf8"));
    const binding = verifyRfc3161Binding(bundle);
    const chain = binding.ok ? verifyRfc3161TsaChain(bundle.rfc3161_timestamp) : { ok: false };
    assert.deepEqual(pythonChecks(path), {
      binding: binding.ok ? "ok" : binding.reason,
      chain: chain.ok ? "ok" : chain.reason,
    }, path);
  }
});

test("Python RFC-3161 binding rejects a changed timestamped_sha256", () => {
  const path = fixtures[0];
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "b=json.load(open(sys.argv[2],encoding='utf-8'))",
    "b['rfc3161_timestamp']['timestamped_sha256']='0'*64",
    "print(m.verify_rfc3161_binding(b)[1])",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, path], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "timestamp_hash_mismatch");
});
