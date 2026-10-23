# PHP2Shell-Exposure-Collector

Prueft lokal, ob der PHP auf diesem Host von CVE-2026-109618/CVE-2026-109619 ("PHP2Shell",
kritische unauthentifizierte RCE in PHP selbst, CVSSv4 9.2, Patches am 21./22.10.2026) betroffen
ist, und laesst sich das Ergebnis vom ALEX-Vertrauensanker signieren -- offline nachpruefbar mit
dem `verify.ts`/`verify.js` dieses Repos (Repo-Root, eine Ebene oberhalb dieses Ordners).

## Was das Skript tut (und was nicht)

- **Liest nur:** `php -v`, `/etc/os-release`, eine passende read-only Paketabfrage
  (`dpkg-query`/`rpm`/`apk`, je nach erkannter Distribution). Keine Exploit-Probes, kein
  Schreibzugriff auf dem gepruefte Host (ausser der am Ende geschriebenen Ergebnisdatei).
- **Einziger Netzwerkzugriff:** ein POST der oben gesammelten Rohdaten an
  `https://alexproof.de/api/evidence/php-exposure/sign`. Dieser Endpoint berechnet das Verdict
  selbst (das Skript kann sich also nie ein falsches Ergebnis signieren lassen) und signiert mit
  dem ALEX-Evidence-Schluessel, der dieses Skript nie erreicht.
- **Vor dem ersten echten Lauf:** `--dry-run` zeigt exakt die Rohdaten, die sonst gesendet
  wuerden, ohne irgendetwas zu senden.

## Benutzung

```bash
# 1. Erst ansehen, was gesendet werden würde:
node collect.mjs --dry-run

# 2. Echter Lauf:
node collect.mjs --out mein-host-php-exposure.json

# 3. Offline pruefen -- einmalig im Repo-Root bauen, dann von hier aus pruefen:
cd .. && npm install && npm run build && cd php-exposure-collector
node ../dist/verify.js mein-host-php-exposure.json <public-key.pem>
```

Den `<public-key.pem>` fuer Schritt 3 unabhaengig vom Bundle beziehen -- niemals aus der
Ergebnisdatei selbst entnehmen. Trust-Anchor: `public_key_pem` aus
`https://alexproof.de/.well-known/alex-pubkey.json` (identischer Schluessel wie fuer die uebrigen
Evidence-Artefakte in diesem Repo, siehe README im Repo-Root).

## Wenn PHP ueber ein Linux-Paket installiert ist (dpkg/rpm/apk)

Das Verdict bleibt dann absichtlich `UNKNOWN`, solange nicht bestaetigt ist, dass die
Distribution den Fix per Backport nachgezogen hat -- eine Paketversionsnummer alleine beweist das
nicht (manche Distributionen patchen per Release-Suffix, ohne die PHP-Versionsnummer zu erhoehen).
Pruefe den Security-Tracker deiner Distribution (z.B. `security-tracker.debian.org`,
`access.redhat.com/security`) und uebergib das Ergebnis explizit:

```bash
node collect.mjs --distro-changelog-note "Debian security-tracker: CVE-2026-109618 PATCHED in 8.2.35-1~deb12u1, https://security-tracker.debian.org/tracker/CVE-2026-109618"
```

Der Text muss das Wort `PATCHED` oder `VULNERABLE` enthalten, sonst bleibt der Verdict `UNKNOWN`.

## Optionen

| Flag | Bedeutung |
|---|---|
| `--out <datei>` | Zieldatei fuer das signierte Artefakt (Default: `php-exposure-evidence.json`) |
| `--endpoint <url>` | Sign-Endpoint (Default: `https://alexproof.de/api/evidence/php-exposure/sign`) |
| `--php <pfad>` | Alternativer `php`-Binary-Pfad, falls nicht auf PATH |
| `--distro-changelog-note "<text>"` | Siehe oben |
| `--dry-run` | Nichts senden, nur die Rohdaten anzeigen |

## Bekannte Grenzen

- **Kein Scanner fuer fremde Server/Appliances** -- nur Self-Check auf dem eigenen Host.
- **Keine Live-CVE-Datenbank, keine automatische Regel-Aktualisierung.** Die Fix-Versionstabelle
  (`php-exposure-rules@2026-10-22.1`) ist serverseitig gepinnt und versioniert (im privaten
  alex-core-Repo: `core/phpExposureEvidence.server.ts`, Stand 22.10.2026). Neue
  Advisories/Backports nach diesem Datum fliessen nicht automatisch ein -- das Skript veraltet
  stillschweigend, falls PHP2Shell-Nachfolgefixes erscheinen und diese Tabelle nicht aktualisiert
  wird.
- **`verify.py` (der netzlose Python-Zweitverifier in diesem Repo) kennt `php-exposure-evidence@1.0`
  noch nicht** -- bisher nur in `verify.ts`/`verify.js` implementiert. Fuer eine zweite,
  sprachunabhaengige Pruefung aktuell nicht nutzbar.
