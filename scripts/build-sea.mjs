#!/usr/bin/env node
// Baut eine eigenstaendige, lokal lauffaehige Programmdatei aus dist/verify.js (Node Single
// Executable Application, kein externes Node noetig). Fuer wen gedacht: Nicht-Entwickler, die ein
// signiertes Beweispaket pruefen wollen, ohne Node/npm zu installieren. Der Quellcode (verify.ts)
// bleibt die primaere, direkt lesbare Vertrauensquelle -- diese Datei ist ein zusaetzlicher,
// bequemerer Vertriebsweg mit Checksumme (siehe release.yml), kein Ersatz dafuer.
//
// Zwei Stellen in dist/verify.js nutzen `import.meta.url`, das in einer gebuendelten CJS/SEA-Datei
// nicht existiert:
//  1. Der ESM-Selbstaufruf-Wächter ("nur main() ausfuehren, wenn direkt per node aufgerufen") --
//     in einer SEA-Binary IST dieser Aufruf immer der direkte Aufruf, der Wächter wird durch einen
//     unconditional main()-Call ersetzt.
//  2. ownBuildHash in der verdict-artifact-Pruefung haengt die Signaturpruefung an den SHA-256 der
//     EIGENEN Quelldatei -- in einer SEA-Binary gibt es keine separate, lesbare Quelldatei mehr
//     (der Code steckt im Blob). Statt einen falschen/irrefuehrenden Hash zu erfinden, wirft die
//     SEA-Binary hier bewusst einen klaren Fehler: verdict-artifact-Pruefung bleibt der Quell-
//     Checkout vorbehalten (node dist/verify.js), wo die Selbstpruefung ihren Sinn behaelt.
import { execFileSync } from "node:child_process";
import { copyFileSync, chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const require = createRequire(import.meta.url);
const esbuildBin = require.resolve("esbuild/bin/esbuild");
const postjectCli = require.resolve("postject/dist/cli.js");
const distVerify = path.join(root, "dist", "verify.js");
const seaEntry = path.join(root, "build", "sea-entry.mjs");
const seaBundle = path.join(root, "build", "sea-bundle.cjs");
const seaConfigPath = path.join(root, "build", "sea-config.json");
const seaBlobPath = path.join(root, "build", "sea-prep.blob");

const outName = process.argv[2];
if (!outName) {
  console.error("Usage: node scripts/build-sea.mjs <output-path>");
  process.exit(1);
}

if (!existsSync(distVerify)) {
  console.error(`${distVerify} fehlt -- vorher 'npm run build' ausfuehren.`);
  process.exit(1);
}

rmSync(path.join(root, "build"), { recursive: true, force: true });
mkdirSync(path.join(root, "build"), { recursive: true });

const GUARD_OLD = `if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    main().catch((error) => { console.error(error); process.exit(1); });
}`;
const GUARD_NEW = `main().catch((error) => { console.error(error); process.exit(1); });`;

const BUILD_HASH_OLD = `const ownBuildHash = "sha256:" + createHash("sha256").update(readFileSync(fileURLToPath(import.meta.url))).digest("hex");`;
const BUILD_HASH_NEW = `throw new Error("verdict-artifact verification needs a source checkout (node dist/verify.js), not the packaged standalone binary -- see README 'Prebuilt binaries'");`;

let source = readFileSync(distVerify, "utf8");
if (!source.includes(GUARD_OLD)) throw new Error("ESM-Selbstaufruf-Waechter in dist/verify.js nicht gefunden -- verify.ts wurde vermutlich geaendert, build-sea.mjs muss nachgezogen werden.");
if (!source.includes(BUILD_HASH_OLD)) throw new Error("ownBuildHash-Berechnung in dist/verify.js nicht gefunden -- verify.ts wurde vermutlich geaendert, build-sea.mjs muss nachgezogen werden.");
source = source.replace(GUARD_OLD, GUARD_NEW).replace(BUILD_HASH_OLD, BUILD_HASH_NEW);
if (source.includes("import.meta.url")) throw new Error("import.meta.url nach dem Patch noch vorhanden -- unerwartete dritte Stelle, build-sea.mjs muss nachgezogen werden.");
writeFileSync(seaEntry, source);

execFileSync(process.execPath, [esbuildBin, seaEntry, "--bundle", "--platform=node", "--format=cjs", `--outfile=${seaBundle}`], { stdio: "inherit" });

writeFileSync(seaConfigPath, JSON.stringify({
  main: seaBundle,
  output: seaBlobPath,
  disableExperimentalSEAWarning: true,
}, null, 2));
execFileSync("node", ["--experimental-sea-config", seaConfigPath], { stdio: "inherit", cwd: root });

copyFileSync(process.execPath, outName);
if (process.platform === "darwin") {
  execFileSync("codesign", ["--remove-signature", outName], { stdio: "inherit" });
}
chmodSync(outName, 0o755);

const fuse = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";
const postjectArgs = [outName, "NODE_SEA_BLOB", seaBlobPath, "--sentinel-fuse", fuse];
if (process.platform === "darwin") postjectArgs.push("--macho-segment-name", "NODE_SEA");
execFileSync(process.execPath, [postjectCli, ...postjectArgs], { stdio: "inherit" });

if (process.platform === "darwin") {
  execFileSync("codesign", ["--sign", "-", outName], { stdio: "inherit" });
}

const sha256 = createHash("sha256").update(readFileSync(outName)).digest("hex");
console.log(`Built ${outName} (sha256: ${sha256})`);
