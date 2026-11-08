#!/bin/bash
# exposure-report.sh – Read-only-Übersicht: welche Dienste lauschen wo,
# lässt firewalld sie durch, und sind sie extern oder intern erreichbar?
# Für SLES15 mit firewalld. Ändert nichts, schreibt keine Dateien.
# Ausführen als root oder als Benutzer mit passwortlosem "sudo -n".

set -u
export LC_ALL=C
HOST=$(hostname -f 2>/dev/null || hostname)

# ---------- Rechte ----------
if [ "$(id -u)" -eq 0 ]; then SUDO=""
elif sudo -n true 2>/dev/null; then SUDO="sudo -n"
else SUDO=""; echo "WARNUNG: keine root-/sudo-Rechte - Prozesse und Firewall-Daten unvollstaendig."; fi

# ---------- Hilfsfunktionen ----------
is_public_ip() {   # 0 = öffentlich routbare IP
  local ip=$1 a b
  case "$ip" in
    *:*) case "${ip,,}" in
           ::1|fe8*|fe9*|fea*|feb*|fc*|fd*) return 1 ;;
           2*|3*) return 0 ;;
           *) return 1 ;;
         esac ;;
    *) IFS=. read -r a b _ _ <<<"$ip"
       [ "$a" = 10 ] || [ "$a" = 127 ] && return 1
       [ "$a" = 169 ] && [ "$b" = 254 ] && return 1
       [ "$a" = 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ] && return 1
       [ "$a" = 192 ] && [ "$b" = 168 ] && return 1
       [ "$a" = 100 ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ] && return 1
       return 0 ;;
  esac
}

declare -A IF_NET IF_IPS IP_IF IF_ZONE IF_ZLABEL
declare -A ZONE_TARGET ZONE_PORTS ZONE_RICH SVC_PORTS

load_zone() {      # liest Zone (runtime) inkl. Ports der freigegebenen Services
  local z=$1 info svcs ports s
  info=$($SUDO firewall-cmd --info-zone="$z" 2>/dev/null)
  ZONE_TARGET[$z]=$(sed -n 's/^ *target: *//p' <<<"$info")
  svcs=$(sed -n 's/^ *services: *//p' <<<"$info")
  ports=$(sed -n 's/^ *ports: *//p' <<<"$info")
  ZONE_RICH[$z]=$(sed -n '/rich rules:/,$p' <<<"$info" | tail -n +2 | grep -v '^[[:space:]]*$')
  for s in $svcs; do
    if [ -z "${SVC_PORTS[$s]+x}" ]; then
      SVC_PORTS[$s]=$($SUDO firewall-cmd --info-service="$s" 2>/dev/null | sed -n 's/^ *ports: *//p')
    fi
    ports="$ports ${SVC_PORTS[$s]}"
  done
  ZONE_PORTS[$z]=$ports
}

fw_check() {       # Ausgabe: offen | Rich-Rule | gesperrt...
  local z=$1 port=$2 proto=$3 p lo hi
  [ "${ZONE_TARGET[$z]:-}" = "ACCEPT" ] && { echo "offen(Target-ACCEPT)"; return; }
  for p in ${ZONE_PORTS[$z]:-}; do
    [ "${p##*/}" = "$proto" ] || continue
    p=${p%/*}; lo=${p%-*}; hi=${p#*-}
    [ "$port" -ge "$lo" ] && [ "$port" -le "$hi" ] && { echo "offen"; return; }
  done
  if [ -n "${ZONE_RICH[$z]:-}" ]; then
    grep -q "port=\"$port\"" <<<"${ZONE_RICH[$z]}" && { echo "Rich-Rule"; return; }
    echo "gesperrt(Rich-Rules-pruefen)"; return
  fi
  echo "gesperrt"
}

# ---------- Interfaces ----------
while read -r _ ifc _ addr _; do
  ifc=${ifc%@*}
  case "$ifc" in lo|veth*) continue ;; esac
  ip=${addr%/*}
  IF_IPS[$ifc]="${IF_IPS[$ifc]:-}${IF_IPS[$ifc]:+ }$ip"
  IP_IF[$ip]=$ifc
  if is_public_ip "$ip"; then IF_NET[$ifc]="oeffentlich"
  elif [ -z "${IF_NET[$ifc]:-}" ]; then IF_NET[$ifc]="privat"; fi
done < <(ip -o addr show 2>/dev/null)

# ---------- firewalld ----------
FW_ACTIVE=0; DEFZONE=""
if $SUDO firewall-cmd --state >/dev/null 2>&1; then
  FW_ACTIVE=1
  DEFZONE=$($SUDO firewall-cmd --get-default-zone 2>/dev/null)
  for ifc in "${!IF_NET[@]}"; do
    z=$($SUDO firewall-cmd --get-zone-of-interface="$ifc" 2>/dev/null)
    if [ -z "$z" ] || [ "$z" = "no zone" ]; then
      IF_ZONE[$ifc]=$DEFZONE; IF_ZLABEL[$ifc]="$DEFZONE(default)"
    else
      IF_ZONE[$ifc]=$z; IF_ZLABEL[$ifc]=$z
    fi
  done
  for z in $(printf '%s\n' "${IF_ZONE[@]}" | sort -u); do load_zone "$z"; done
fi

# ---------- Lauschende Sockets auswerten ----------
ROWS=()
while read -r proto _ _ _ local _ procinfo; do
  port=${local##*:}
  [[ $port =~ ^[0-9]+$ ]] || continue
  addr=${local%:*}; addr=${addr#\[}; addr=${addr%\]}
  bindif=""
  if [[ $addr == *%* ]]; then bindif=${addr#*%}; addr=${addr%%\%*}; fi
  pname=$(sed -n 's/.*(("\([^"]*\)".*/\1/p' <<<"$procinfo"); pname=${pname:--}
  pid=$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' <<<"$procinfo")
  unit=""
  [ -n "$pid" ] && unit=$(grep -o '[^/]*\.\(service\|scope\)' /proc/"$pid"/cgroup 2>/dev/null | head -1)
  unit=${unit:--}

  case "$addr" in
    127.*|::1|::ffff:127.*) targets="lo" ;;
    0.0.0.0|::|'*'|'') targets=$bindif; [ -z "$targets" ] && targets="${!IF_NET[*]}" ;;
    *) targets=${IP_IF[$addr]:-?} ;;
  esac

  for t in $targets; do
    if [ "$t" = "lo" ]; then
      net="lokal"; zone="-"; fw="-"; rating="LOKAL"
    else
      net=${IF_NET[$t]:-?}
      if [ "$FW_ACTIVE" -eq 1 ] && [ -n "${IF_ZONE[$t]:-}" ]; then
        zone=${IF_ZLABEL[$t]}; fw=$(fw_check "${IF_ZONE[$t]}" "$port" "$proto")
      else
        zone="-"; fw="ungefiltert?"
      fi
      case "$fw" in
        gesperrt*)  rating="BLOCKIERT" ;;
        Rich-Rule*) rating="PRUEFEN" ;;
        *) if [ "$net" = "oeffentlich" ]; then rating="EXTERN"
           elif [ "$net" = "?" ]; then rating="PRUEFEN"
           else rating="INTERN"; fi ;;
      esac
    fi
    ROWS+=("$proto;$port;$addr;$pname;$unit;$t;$net;$zone;$fw;$rating")
  done
done < <($SUDO ss -tulpn 2>/dev/null | tail -n +2)

SORTED=$(printf '%s\n' "${ROWS[@]}" | grep -v '^$' | sort -u | sort -t';' -k2,2n)
ORDER="EXTERN PRUEFEN INTERN BLOCKIERT LOKAL"

# ---------- Ausgabe ----------
OS=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unbekannt}")
echo "=========================================================================="
echo " Netzwerk-Exposition: $HOST | $OS | $(date '+%F %T')"
echo "=========================================================================="
echo "Interfaces:"
for ifc in "${!IF_NET[@]}"; do
  printf '  %-14s %-12s Zone: %-20s %s\n' "$ifc" "${IF_NET[$ifc]}" "${IF_ZLABEL[$ifc]:--}" "${IF_IPS[$ifc]}"
done
echo "  Default-Route ueber: $(ip route show default 2>/dev/null | awk '{print $5; exit}')"
echo
if [ "$FW_ACTIVE" -eq 1 ]; then
  echo "firewalld: aktiv (Default-Zone: $DEFZONE). Aktive Zonen inkl. Quell-Bindungen:"
  $SUDO firewall-cmd --get-active-zones 2>/dev/null | sed 's/^/  /'
else
  echo "firewalld: NICHT aktiv. nft-Regelzeilen: $($SUDO nft list ruleset 2>/dev/null | grep -c . )"
  echo "  -> Filterung ggf. ueber nft/iptables direkt, manuell pruefen."
fi
echo
echo "Lauschende Dienste:"
{ echo "PROTO;PORT;BIND;PROZESS;UNIT;IFACE;NETZ;ZONE;FIREWALL;BEWERTUNG"
  for r in $ORDER; do grep ";$r\$" <<<"$SORTED"; done
} | if command -v column >/dev/null 2>&1; then column -t -s';'; else tr ';' '\t'; fi
echo
echo "Zusammenfassung:"
for r in $ORDER; do
  list=$(grep ";$r\$" <<<"$SORTED" | awk -F';' '{print $4"("$2"/"$1")"}' | sort -u | tr '\n' ' ')
  printf '  %-10s %s\n' "$r:" "${list:-keine}"
done

for c in podman docker; do
  command -v "$c" >/dev/null 2>&1 || continue
  out=$($SUDO "$c" ps --format '{{.Names}}  {{.Ports}}' 2>/dev/null)
  [ -n "$out" ] || continue
  echo
  echo "$c-Container (veroeffentlichte Ports):"
  echo "$out" | sed 's/^/  /'
  [ "$c" = docker ] && echo "  HINWEIS: Docker setzt eigene iptables-Regeln und kann firewalld-Zonen umgehen."
done

echo
echo "Legende: EXTERN = oeffentliche IP am Interface + Firewall offen | INTERN = private IP + offen"
echo "         PRUEFEN = Rich-Rule oder unklare Zuordnung | Private IPs koennen per NAT trotzdem von aussen erreichbar sein."
echo
echo "# Maschinenlesbar: host;proto;port;bind;prozess;unit;iface;netz;zone;firewall;bewertung"
grep -v '^$' <<<"$SORTED" | sed "s/^/INV;$HOST;/"
exit 0
