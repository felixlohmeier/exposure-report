# Beispiel

Echte Ausgabe von `exposure-report.sh` auf zwei Testservern (openSUSE Leap 15.6 =
SLES 15 SP6-Basis, firewalld 2.0.1). Alle Adressen stammen aus Dokumentations- bzw.
privaten Bereichen (`203.0.113.0/24` und `198.51.100.0/24` stehen hier für das Internet).

| Datei | Inhalt |
|-------|--------|
| [`web01.example.com.log`](web01.example.com.log) | Log eines Webservers in der DMZ (so erscheint es je Node im Rundeck-Log) |
| [`db01.example.com.log`](db01.example.com.log)   | Log eines internen Datenbankservers |
| [`exposure.csv`](exposure.csv)                   | Gesamtübersicht beider Server, aus den `INV`-Zeilen erzeugt |

## Szenario

**web01.example.com**: `eth0` 203.0.113.10 (öffentlich, Zone `public`), `eth1` 10.20.0.11 (Zone `internal`)

| Dienst | firewalld | Ergebnis |
|--------|-----------|----------|
| nginx 80/443 | `public`: http, https | **EXTERN** |
| java 8443 | Rich Rule: nur von 198.51.100.20 | **EXTERN** (nur eine Partner-IP) |
| snmpd 161/udp | Rich Rule: nur von ipset `monitoring` | **PRUEFEN** (Inhalt des ipset unbekannt) |
| sshd 22, node_exporter 9100 | nur in Zone `internal` frei | **INTERN** |
| java 8080 | nirgends freigegeben | BLOCKIERT |
| php-fpm 9000, chronyd 323 | lauscht nur auf 127.0.0.1 | LOKAL |

**db01.example.com**: `eth0` 10.20.0.21 (privat, Zone `public`), Zone `admin` mit Quelle 10.50.0.0/24

| Dienst | firewalld | Ergebnis |
|--------|-----------|----------|
| sshd 22 | `public`: ssh | INTERN (private IP) |
| postgres 5432 | Rich Rule `service name="postgresql"` nur von 10.20.0.0/24 | INTERN |
| node_exporter 9100, postgres_exporter 9187 | nur in Zone `admin` (Quelle 10.50.0.0/24) | INTERN |
| rpcbind 111 | nicht freigegeben | BLOCKIERT |
| redis 6379 | lauscht nur auf 127.0.0.1 | LOKAL |

Hinweise:
- In der Spalte `UNIT` steht hier `-`, weil im Testcontainer kein systemd läuft.
  Auf echten SLES-Servern steht dort z.B. `sshd.service`.
- `ss` zeigt Prozessnamen auf 15 Zeichen gekürzt, deshalb `postgres_export`.

## Gesamtübersicht erzeugen

```bash
{ echo "host;proto;port;bind;prozess;unit;iface;netz;zone;firewall;bewertung"
  grep -h '^INV;' *.log | cut -d';' -f2-; } > exposure.csv

# nur Dienste, die aus dem Internet erreichbar sind
grep -h '^INV;' *.log | awk -F';' '$12=="EXTERN"'
```

Ergebnis für dieses Beispiel:

```
INV;web01.example.com;tcp;80;0.0.0.0;nginx;-;eth0;oeffentlich;public;offen;EXTERN
INV;web01.example.com;tcp;443;0.0.0.0;nginx;-;eth0;oeffentlich;public;offen;EXTERN
INV;web01.example.com;tcp;8443;0.0.0.0;java;-;eth0;oeffentlich;public;nur-von:198.51.100.20(Rich-Rule);EXTERN
```
