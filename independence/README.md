# Independence Test Kit

**Zuletzt bearbeitet:** 2026-11-28 (Warnung gegen Fehlanwendung auf neue Bundles ergaenzt, siehe
Nachtrag unten)
**Von:** Alex-Proof

> **`independence/verify.py` ist auf Quellstand `b3d1148` (2026-09-06) eingefroren und prueft nur
> `demo-pr-38.json`.** Fuehre ihn NIE gegen ein anderes/neueres Evidence-Bundle aus -- er kennt
> z.B. keine `evidence-package@2.3`-Bundles und kein `epistemic_gate`-Feld (beide erst nach dem
> Freeze eingefuehrt) und wuerde ein echtes, gueltiges neueres Bundle faelschlich als
> `unsupported_schema_or_capability` oder `invalid_signature` ablehnen. Fuer JEDES andere Bundle
> -- auch ein weiteres `demo-pr-*.json` -- den lebenden `../verify.py`/`../dist/verify.js`
> verwenden, wie im Haupt-README unter "Pruef es selbst" dokumentiert.

Dieses Verzeichnis enthaelt den eingefrorenen Werkzeugsatz und drei reale Pruefprotokolle
desselben Evidence Package ohne Vertrauen in eine laufende ALEX-Instanz. Das veroeffentlichbare
Paket entsteht mit `npm pack`.

## Eingefrorener Testgegenstand

- Evidence Package: `demo-pr-38.json`
- Trust-Anchor-Snapshot: `trust-anchor-20260906.json`, vor Test C separat bezogen
- daraus aufgeloeste Schluessel: `trusted-evidence.pem`, `trusted-approval.pem`
- Verifier: `./verify.py`, eingefrorene Kopie des Quellstands `b3d11484041ae6579baec694a75de404d682c2cc`
- normative Unterlagen: `./spec/`, dieselbe eingefrorene Kopie

## Tatsaechlich notwendige Bestandteile

| Bestandteil | Ausfuehrung | Rolle |
|---|---:|---|
| `verify.py` (diese Kopie, nicht `../verify.py`) | ja | Prueft Schema, Signaturen, Hash-Kette, Ableitungen und Bindungen |
| Python 3 | ja | Nur Standardbibliothek |
| OpenSSL | ja | Ed25519-Signaturpruefung; keine Python-Pakete |
| Evidence Package | ja | Portabler Pruefgegenstand |
| Evidence-PEM | ja | Separater Anker der Bundle-Signatur |
| Approval-PEM | fuer PR 38 ja | Separater Anker der Freigabe-Signatur |
| Trust-Anchor-JSON | ja, als Herkunftsnachweis | Eingefrorene Quelle der PEMs; kein Live-Endpunkt |
| `spec/` inkl. Invarianten (diese Kopie) | normativ ja, technisch nein | Auditierbare Definition; wird nicht vom Programm eingelesen |
| Node.js/npm/ALEX-Code/DB/API | nein | Nicht verwendet |

Reproduktion aus dem Paket-Root:

```bash
sha256sum -c independence/SHA256SUMS
python3 independence/verify.py independence/demo-pr-38.json \
  independence/trusted-evidence.pem independence/trusted-approval.pem
```

Die Protokolle belegen getrennt: offline, fremde Umgebung und gestoppte ALEX-Runtime.
Coverage-Kennzahl und Lifecycle sind ausdruecklich nicht Teil dieser Pruefung.

## Nachtrag 2026-11-19: Warum `verify.py`/`spec/` jetzt eigene Kopien in diesem Ordner sind

Externer Pruefer (Matthew, EFMW Zoo) hat die Offline-Prozedur wiederholt und `sha256sum -c
independence/SHA256SUMS` ausgefuehrt: `verify.py` und `spec/devtask.execution@1.0.schema.json`
fielen mit `FAILED` durch, alle anderen sieben Dateien mit `OK`. Ursache: das Manifest verwies
bisher auf die LEBENDEN Dateien `../verify.py` und `../spec/` statt auf eine eigene Kopie. Beide
wurden seit dem Freeze dieses Kits (2026-09-06) berechtigt weiterentwickelt --
`spec/devtask.execution@1.0.schema.json` am 28.09. (Pflichtfeld `epistemic_gate`), `verify.py`
zuletzt am 15.11. (A-016, WebAuthn-Freigabe-Pruefung) -- wodurch das Manifest fuer jeden, der die
dokumentierten Schritte woertlich befolgt, einen falschen Manipulationsverdacht erzeugte. Am
eigentlich getesteten Quellstand `b3d1148` selbst war nichts veraendert; Matthews eigene
Nachpruefung gegen `b3d1148` bestaetigte das.

Fix: `verify.py` und `spec/` liegen jetzt als eigene, unveraenderliche Kopien von Stand `b3d1148`
in diesem Ordner (`independence/verify.py`, `independence/spec/`) -- nicht mehr als Verweis auf die
weiterentwickelte Hauptkopie im Repo-Root. `SHA256SUMS` und die Befehle oben zeigen jetzt auf diese
Kopien. Das Kit bleibt dadurch dauerhaft reproduzierbar, auch wenn `../verify.py` kuenftig weitere
Sicherheitsfixes bekommt -- ohne dass jemand erst einen alten Commit auschecken muss, um die neun
Dateien wieder gruen zu bekommen.

## Nachtrag 2026-11-28: Namensverwechslung -- eingefroren heisst nicht "der unabhaengige Verifier"

Externer Pruefer (Staford Titus, AMEP) hat `independence/verify.py` gegen zwei NEUE, von Andre
direkt bereitgestellte Bundles ausgefuehrt (`demo-pr-41`, ein Canary-Bundle) statt gegen das hier
eingefrorene `demo-pr-38.json`. Beide neuen Bundles nutzen `evidence-package@2.3` mit
`epistemic_gate` -- Felder, die erst NACH dem Freeze vom 2026-09-06 eingefuehrt wurden
(`epistemic_gate` 2026-09-28, Schema 2.3 spaeter). `independence/verify.py` kennt beides nicht:
`DEVTASK_V2_SCHEMA_VERSIONS` endet bei `evidence-package@2.2`, und die signierte Nutzlast schliesst
`epistemic_gate` nicht aus -- ein TATSAECHLICH gueltiges neueres Bundle faellt deshalb hier
faelschlich durch, waehrend derselbe Lauf gegen den lebenden `../verify.py`/`../dist/verify.js`
korrekt VERIFIED liefert.

Das ist kein Fehler in der eingefrorenen Kopie selbst (sie tut genau das, wofuer sie gebaut wurde:
`demo-pr-38.json` gegen Quellstand `b3d1148` reproduzierbar pruefen) -- sondern eine
Namensverwechslung, die der Ordnername `independence/` nahelegt: er klingt nach "der unabhaengige
Verifier allgemein", ist aber "der eingefrorene Reproduktions-Snapshot fuer genau EIN historisches
Bundle". Fix: die Warnung oben am Dateianfang + derselbe Hinweis als Kommentar direkt im
Skriptkopf von `verify.py` (dort, wo jemand, der die Datei einfach oeffnet statt dieses README zu
lesen, es zuerst sieht).
