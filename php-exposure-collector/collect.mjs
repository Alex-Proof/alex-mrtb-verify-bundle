#!/usr/bin/env node
/**
 * php-exposure-collector/collect.mjs -- PHP2Shell-Exposure-Collector (CVE-2026-109618,
 * CVE-2026-109619). Laeuft LOKAL auf dem zu pruefenden PHP-Host.
 *
 * Read-only, keine Exploit-Probes: liest `php -v`, `/etc/os-release` und eine passende
 * read-only Paketmanager-Abfrage (dpkg-query/rpm/apk, je nach os-release). Schreibt NICHTS
 * ausser der am Ende empfangenen, signierten Antwort-Datei.
 *
 * EINZIGER Netzwerkzugriff: ein einzelner POST der oben gesammelten Rohdaten an den Sign-Endpoint
 * (Default https://alexproof.de/api/evidence/php-exposure/sign). Dieser Endpoint signiert mit dem
 * ALEX-Evidence-Schluessel, der NIE auf diese Maschine kommt -- der Collector kann sich dadurch
 * nie selbst ein falsches PATCHED signieren, weil der Server den Verdict selbst aus den rohen
 * Strings neu berechnet, nicht vom Client entgegennimmt. Mit --dry-run wird NICHTS gesendet --
 * stattdessen werden exakt die Rohdaten ausgegeben, die sonst gesendet wuerden, zur Kontrolle vor
 * dem ersten echten Lauf.
 *
 * Usage:
 *   node collect.mjs [--out datei.json] [--endpoint URL] [--php /pfad/zu/php]
 *                     [--distro-changelog-note "Text + URL"] [--dry-run]
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { hostname as osHostname } from "node:os";

const DEFAULT_ENDPOINT = "https://alexproof.de/api/evidence/php-exposure/sign";
const DEFAULT_OUT = "php-exposure-evidence.json";

function parseArgs(argv) {
  const args = { out: DEFAULT_OUT, endpoint: DEFAULT_ENDPOINT, php: "php", distroChangelogNote: null, dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--out") args.out = argv[++i];
    else if (arg === "--endpoint") args.endpoint = argv[++i];
    else if (arg === "--php") args.php = argv[++i];
    else if (arg === "--distro-changelog-note") args.distroChangelogNote = argv[++i];
    else if (arg === "--dry-run") args.dryRun = true;
    else { console.error(`Unbekanntes Argument: ${arg}`); process.exitCode = 1; }
  }
  return args;
}

function runReadOnly(command, commandArgs) {
  try {
    return execFileSync(command, commandArgs, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    // execFileSync wirft auch bei Exit-Code != 0 (z.B. "keine passenden Pakete gefunden") --
    // das ist hier kein Fehler des Collectors, sondern ein gueltiges "nichts gefunden"-Ergebnis.
    return typeof error.stdout === "string" ? error.stdout : "";
  }
}

function readOsRelease() {
  try {
    return readFileSync("/etc/os-release", "utf8");
  } catch {
    return "";
  }
}

function detectPackageManager(osReleaseOutput) {
  const idMatch = /^ID=(.*)$/m.exec(osReleaseOutput);
  const idLikeMatch = /^ID_LIKE=(.*)$/m.exec(osReleaseOutput);
  const id = (idMatch?.[1] ?? "").replace(/"/g, "").toLowerCase();
  const idLike = (idLikeMatch?.[1] ?? "").replace(/"/g, "").toLowerCase();
  const haystack = `${id} ${idLike}`;
  if (/\b(debian|ubuntu)\b/.test(haystack)) return "dpkg";
  if (/\b(rhel|fedora|centos|rocky|almalinux|suse)\b/.test(haystack)) return "rpm";
  if (/\balpine\b/.test(haystack)) return "apk";
  return "none";
}

function queryPackageManager(packageManager) {
  if (packageManager === "dpkg") {
    return runReadOnly("dpkg-query", ["-W", "-f=${Package} ${Version}\n", "php*"]).trim();
  }
  if (packageManager === "rpm") {
    return runReadOnly("rpm", ["-qa", "--queryformat=%{NAME} %{VERSION}-%{RELEASE}\n", "php*"]).trim();
  }
  if (packageManager === "apk") {
    const all = runReadOnly("apk", ["info", "-vv"]);
    return all.split("\n").filter((line) => /php/i.test(line)).join("\n").trim();
  }
  return "";
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  let phpVersionOutput;
  try {
    phpVersionOutput = execFileSync(args.php, ["-v"], { encoding: "utf8" });
  } catch (error) {
    console.error(`Konnte "${args.php} -v" nicht ausfuehren: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  const osReleaseOutput = readOsRelease();
  const packageManager = detectPackageManager(osReleaseOutput);
  const packageQueryOutput = queryPackageManager(packageManager);

  const rawEvidence = {
    php_version_output: phpVersionOutput,
    os_release_output: osReleaseOutput,
    package_manager: packageManager,
    package_query_output: packageQueryOutput,
    distro_changelog_note: args.distroChangelogNote,
    collected_at: new Date().toISOString(),
    hostname: osHostname(),
  };

  if (args.dryRun) {
    console.log("--dry-run: es wird NICHTS gesendet. Das sind exakt die Rohdaten, die sonst an");
    console.log(`${args.endpoint} gesendet wuerden:\n`);
    console.log(JSON.stringify(rawEvidence, null, 2));
    return;
  }

  console.error(`Sende Rohdaten (php -v, os-release, Paketmanager-Query) an ${args.endpoint} ...`);
  console.error("Das ist der einzige Netzwerkzugriff dieses Skripts.");

  const response = await fetch(args.endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(rawEvidence),
  });
  const body = await response.text();
  if (!response.ok) {
    console.error(`Sign-Endpoint meldete ${response.status}: ${body}`);
    process.exitCode = 1;
    return;
  }

  writeFileSync(args.out, body, "utf8");
  const artifact = JSON.parse(body);
  console.log(`Signiertes Artefakt geschrieben nach ${args.out}`);
  console.log(`Verdict: ${artifact.assessment.verdict} (parsed_php_version=${artifact.assessment.parsed_php_version}, rule_version=${artifact.assessment.rule_version})`);
  console.log(`Pruefen mit: node ../dist/verify.js ${args.out} <public-key.pem>  (siehe ../README.md, Abschnitt "PHP2Shell-Exposure-Collector")`);
}

main();
