# exposure-report
Aktive Dienste ermitteln unter SLES15

`exposure-report.sh` zeigt je Server, welche Dienste lauschen, ob firewalld sie
durchlässt und ob sie damit **aus dem Internet** (EXTERN) oder nur **im internen
Netz** (INTERN) erreichbar sind. Das Skript ändert nichts und schreibt keine Dateien.

## Voraussetzungen

- SLES 15 (getestet mit openSUSE Leap 15.6 = SLES 15 SP6-Basis, bash 4.4, firewalld 2.0.1)
- `iproute2` (`ss`, `ip`); optional `firewalld`, `nft`/`iptables`, `podman`/`docker`
- root oder ein Benutzer mit **passwortlosem** `sudo` (`sudo -n`)

### sudo auf SLES

Die SLES-Standard-`sudoers` enthält `Defaults targetpw` und `ALL ALL=(ALL) ALL`.
Damit fragt sudo nach dem **root-Passwort**, und `sudo -n` schlägt in Rundeck fehl.
Für den Rundeck-Benutzer braucht es daher z.B. `/etc/sudoers.d/rundeck` (Modus 0440):

```
rundeck ALL=(root) NOPASSWD: ALL
```

Ohne root/sudo läuft das Skript trotzdem, liefert aber keine Prozessnamen und
keine Firewall-Bewertung (die Ports erscheinen dann als `PRUEFEN`) und endet mit
Exit-Code 2, damit der Node in Rundeck auffällt.

## Ausführung mit Rundeck

Job → Workflow → Schritt *Script* (Inline) oder *Script file or URL*, Node-Filter
auf die SLES-Server. Der Benutzer der Node-Verbindung muss passwortloses sudo haben
(siehe oben); das Skript ruft `sudo -n` selbst auf. Alternativ das ganze Skript als
root starten (Advanced → *Invocation String*: `sudo -n`).

Exit-Codes: `0` OK · `1` `ss`/`ip` fehlen · `2` ohne root/sudo, Ergebnis unvollständig

## Ausgabe

1. **Interfaces** mit Netzklasse (öffentlich/privat) und firewalld-Zone
2. **firewalld-Zonen** inkl. Quellen, Services, Ports, Forward-Ports, Rich Rules
3. **Lauschende Dienste**: eine Zeile je Socket und Interface
4. **Zusammenfassung je Dienst**: höchste Einstufung über alle Interfaces
5. Veröffentlichte Ports von podman/docker-Containern
6. **Maschinenlesbare Zeilen** `INV;host;proto;port;bind;prozess;unit;iface;netz;zone;firewall;bewertung`

Einstufungen:

| Bewertung | Bedeutung |
|-----------|-----------|
| EXTERN    | öffentliche IP am Interface und Port offen (auch: nur für bestimmte öffentliche Quellen, z.B. per Rich Rule) |
| PRUEFEN   | Freigabe für ipset/MAC/`NOT`-Quellen, Sperr-Rich-Rule ohne Quelle, firewalld nicht abfragbar oder IP keinem Interface zuordenbar |
| INTERN    | private IP am Interface oder Port nur für private Quellnetze freigegeben (Rich Rule oder Zone mit `sources`) |
| BLOCKIERT | Dienst lauscht, aber firewalld sperrt den Port |
| LOKAL     | nur Loopback |

### Gesamtübersicht über alle Server

Rundeck-Log der Ausführung herunterladen (*Log Output* → *Download*) und die
`INV`-Zeilen herausfiltern:

```bash
grep -h '^INV;' rundeck-*.log | cut -d';' -f2- > exposure.csv      # Semikolon-CSV
grep -h '^INV;' rundeck-*.log | awk -F';' '$12=="EXTERN"'            # nur extern erreichbare
```

## Was ausgewertet wird

- Wildcard-Sockets (`0.0.0.0` nur IPv4-Interfaces, `::`/`*` alle Interfaces),
  an ein Interface gebundene Sockets (`%eth0`), IPv6 Link-Local, `::ffff:`-Adressen
- firewalld: Zone je Interface (sonst Default-Zone), Target `ACCEPT`, Services
  (inkl. `includes`), Ports und Portbereiche, Forward-Ports, Rich Rules
  (Port/Service/alle Ports, Quelladresse, accept/reject/drop), Zonen mit Quell-Bindung
- `docker-proxy`-Ports werden als offen gewertet, weil Docker per DNAT an den
  firewalld-Zonen vorbei weiterleitet

## Grenzen

- Es zählt nur die IP am Server. NAT oder Portweiterleitungen an der Perimeter-Firewall
  (private IP, trotzdem aus dem Internet erreichbar) sieht das Skript nicht.
- Ausgewertet wird die Runtime-Konfiguration von firewalld, nicht die permanente.
- Rich Rules mit `priority`, `destination`, `family` und Zone-Drifting werden nicht
  im Detail nachgebildet. Im Zweifel zeigt der Zonen-Abschnitt alle Regeln an.
- Ohne firewalld werden nur die Anzahl der nft/iptables-Regeln gemeldet und die
  Ports als `ungefiltert?` eingestuft.
