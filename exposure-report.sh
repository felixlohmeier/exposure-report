#!/bin/bash
# exposure-report.sh – Read-only-Übersicht: welche Dienste lauschen wo,
# lässt firewalld sie durch, und sind sie extern oder intern erreichbar?
#
# Für SLES15 mit firewalld (getestet mit firewalld 2.0 / bash 4.4).
# Ändert nichts, schreibt keine Dateien.
# Ausführen als root oder als Benutzer mit passwortlosem "sudo -n"
# (z.B. als Rundeck-Job, Ausgabe landet je Node im Log).
#
# Exit-Code: 0 = OK, 1 = Pflicht-Tools fehlen, 2 = ohne root/sudo gelaufen
#            (Ergebnis unvollständig: Prozesse/Firewall fehlen)

set -u
export LC_ALL=C
# Nicht-interaktive SSH-Sessions (Rundeck) haben oft kein sbin im PATH
PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"

HOST=$(timeout 5 hostname -f 2>/dev/null) || HOST=""
[ -n "$HOST" ] || HOST=$(uname -n)

for t in ss ip; do
  command -v "$t" >/dev/null 2>&1 || { echo "FEHLER: '$t' nicht gefunden (Paket iproute2)."; exit 1; }
done

# ---------- Rechte ----------
PRIV=1
if [ "$(id -u)" -eq 0 ]; then SUDO=""
elif sudo -n true 2>/dev/null; then SUDO="sudo -n"
else SUDO=""; PRIV=0
  echo "WARNUNG: keine root-/sudo-Rechte - Prozesse und Firewall-Daten unvollstaendig."
fi

# ---------- Hilfsfunktionen ----------
is_public_ip() {   # 0 = öffentlich routbar; akzeptiert auch CIDR (Netzadresse zählt)
  local ip=${1%/*} a b
  case "$ip" in
    *:*) case "${ip,,}" in
           ::ffff:*) is_public_ip "${ip#*::ffff:}"; return ;;
           ::|::1|fe[89ab]*|f[cd]*|ff*) return 1 ;;
           2*|3*) return 0 ;;                       # 2000::/3 Global Unicast
           *) return 1 ;;
         esac ;;
    *.*.*.*)
       IFS=. read -r a b _ _ <<<"$ip"
       [[ $a =~ ^[0-9]+$ && $b =~ ^[0-9]+$ ]] || return 1
       case "$a" in 0|10|127) return 1 ;; esac
       [ "$a" -ge 224 ] && return 1                 # Multicast/reserviert
       [ "$a" = 169 ] && [ "$b" = 254 ] && return 1
       [ "$a" = 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ] && return 1
       [ "$a" = 192 ] && [ "$b" = 168 ] && return 1
       [ "$a" = 100 ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ] && return 1   # CGNAT
       return 0 ;;
    *) return 1 ;;
  esac
}

src_class() {      # Klassifiziert eine Liste von Quellen: oeffentlich | privat | unklar
  local s cls=privat
  for s in $1; do
    case "$s" in
      ipset:*) [ "$cls" = privat ] && cls=unklar ;;
      *) if [[ $s =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then   # MAC-Adresse
           [ "$cls" = privat ] && cls=unklar
         elif is_public_ip "$s"; then echo oeffentlich; return; fi ;;
    esac
  done
  echo "$cls"
}

declare -A IF_NET IF_NET4 IF_IPS IP_IF IF_ZONE IF_ZLABEL
declare -A ZONE_TARGET ZONE_PORTS ZONE_RICH ZONE_SRCS ZONE_FWD ZONE_INFO SVC_PORTS
SRC_ZONES=()

svc_ports() {      # Ports eines firewalld-Service (inkl. "includes:"), gecacht
  local s=$1 info inc i out
  if [ -z "${SVC_PORTS[$s]+x}" ]; then
    SVC_PORTS[$s]=""     # Schutz vor Endlosrekursion
    info=$($SUDO firewall-cmd --info-service="$s" 2>/dev/null)
    out=$(sed -n 's/^ *ports: *//p' <<<"$info")
    inc=$(sed -n 's/^ *includes: *//p' <<<"$info")
    for i in $inc; do out="$out $(svc_ports "$i")"; done
    SVC_PORTS[$s]=$out
  fi
  echo "${SVC_PORTS[$s]}"
}

load_zone() {      # liest Zone (runtime) inkl. Ports der freigegebenen Services
  local z=$1 info svcs ports s
  [ -n "${ZONE_INFO[$z]+x}" ] && return
  info=$($SUDO firewall-cmd --info-zone="$z" 2>/dev/null)
  ZONE_INFO[$z]=$info
  ZONE_TARGET[$z]=$(sed -n 's/^ *target: *//p' <<<"$info")
  ZONE_SRCS[$z]=$(sed -n 's/^ *sources: *//p' <<<"$info")
  # forward-ports: alte Versionen einzeilig, firewalld >=1.0 je Regel eine Tab-Zeile
  ZONE_FWD[$z]=$(awk '/^ *forward-ports:/ { sub(/^ *forward-ports: */, ""); print; f = 1; next }
                      f && /^\t/ { sub(/^\t+/, ""); print; next } { f = 0 }' <<<"$info" | tr '\n' ' ')
  svcs=$(sed -n 's/^ *services: *//p' <<<"$info")
  ports=$(sed -n 's/^ *ports: *//p' <<<"$info")
  ZONE_RICH[$z]=$(sed -n '/^ *rich rules:/,$p' <<<"$info" | tail -n +2 | grep -v '^[[:space:]]*$')
  for s in $svcs; do ports="$ports $(svc_ports "$s")"; done
  ZONE_PORTS[$z]=$ports
}

port_in_list() {   # port_in_list "<22/tcp 8000-8100/tcp ...>" port proto
  local p lo hi
  for p in $1; do
    [ "${p##*/}" = "$3" ] || continue
    p=${p%/*}; lo=${p%-*}; hi=${p#*-}
    [[ $lo =~ ^[0-9]+$ && $hi =~ ^[0-9]+$ ]] || continue
    [ "$2" -ge "$lo" ] && [ "$2" -le "$hi" ] && return 0
  done
  return 1
}

RE_PORT='(^|[[:space:]])port port="([0-9]+)(-([0-9]+))?" protocol="([a-z]+)"'
RE_SVC='service name="([^"]+)"'
RE_SRC='source address="([^"]+)"'
RE_SRCSET='source ipset="([^"]+)"'
RE_SRCMAC='source mac="([^"]+)"'
RE_ELEM='(^|[[:space:]])(port|service|protocol|icmp-block|icmp-type|forward-port|source-port|masquerade|tcp-mss-clamp)[[:space:]]'

# Bewertet Port in einer Zone. Ergebnis in globalen Variablen:
#   FW_STATUS = open | restricted | review | blocked
#   FW_DETAIL = Klartext, FW_SRCS = erlaubte Quellen (bei restricted)
fw_eval() {
  local z=$1 port=$2 proto=$3 rule act src match base=0 bdetail="offen" \
        any=0 review=0 denyall=0 srcs="" denysrcs="" f
  FW_STATUS=blocked; FW_DETAIL="gesperrt"; FW_SRCS=""
  if [ "${ZONE_TARGET[$z]:-}" = "ACCEPT" ]; then
    FW_STATUS=open; FW_DETAIL="offen(Target-ACCEPT)"; return
  fi
  port_in_list "${ZONE_PORTS[$z]:-}" "$port" "$proto" && base=1
  [ "$base" -eq 0 ] && for f in ${ZONE_FWD[$z]:-}; do   # port=80:proto=tcp:toport=8080:toaddr=
    [[ $f == *":proto=$proto:"* && $f == *":toaddr=" ]] || continue
    if [[ $f == *":toport=$port:"* ]] || { [[ $f == *":toport=:"* ]] && [[ $f == "port=$port:"* ]]; }; then
      base=1; bdetail="offen(Forward-${f%%:*})"
    fi
  done
  while IFS= read -r rule; do
    [ -n "${rule//[[:space:]]/}" ] || continue
    act=$(grep -oE '(^|[[:space:]])(accept|reject|drop|mark)([[:space:]]|$)' <<<"$rule" | tail -1 | tr -d '[:space:]')
    [ -n "$act" ] && [ "$act" != mark ] || continue
    match=0
    if [[ $rule =~ $RE_PORT ]]; then
      local lo=${BASH_REMATCH[2]} hi=${BASH_REMATCH[4]:-${BASH_REMATCH[2]}} pr=${BASH_REMATCH[5]}
      [ "$pr" = "$proto" ] && [ "$port" -ge "$lo" ] && [ "$port" -le "$hi" ] && match=1
    elif [[ $rule =~ $RE_SVC ]]; then
      port_in_list "$(svc_ports "${BASH_REMATCH[1]}")" "$port" "$proto" && match=1
    elif ! [[ $rule =~ $RE_ELEM ]]; then
      match=1                                   # Regel ohne Port/Service: gilt für alle Ports
    fi
    [ "$match" -eq 1 ] || continue
    src="*"
    if [[ $rule == *"source NOT"* ]]; then src="?"
    elif [[ $rule =~ $RE_SRC ]]; then src=${BASH_REMATCH[1]}
    elif [[ $rule =~ $RE_SRCSET ]]; then src="ipset:${BASH_REMATCH[1]}"
    elif [[ $rule =~ $RE_SRCMAC ]]; then src=${BASH_REMATCH[1]}
    fi
    if [ "$act" = accept ]; then
      case "$src" in '*') any=1 ;; '?') review=1 ;; *) srcs="$srcs $src" ;; esac
    else
      case "$src" in '*'|'?') denyall=1 ;; *) denysrcs="$denysrcs $src" ;; esac
    fi
  done <<<"${ZONE_RICH[$z]:-}"

  if [ "$base" -eq 1 ] || [ "$any" -eq 1 ]; then
    [ "$base" -eq 0 ] && bdetail="offen(Rich-Rule)"
    if [ "$denyall" -eq 1 ]; then FW_STATUS=review; FW_DETAIL="$bdetail+Rich-Sperre-pruefen"
    elif [ -n "$denysrcs" ]; then denysrcs=${denysrcs# }; FW_STATUS=open; FW_DETAIL="$bdetail(gesperrt-fuer:${denysrcs// /,})"
    else FW_STATUS=open; FW_DETAIL=$bdetail; fi
  elif [ -n "$srcs" ] && [ "$review" -eq 0 ]; then
    FW_STATUS=restricted; FW_SRCS=${srcs# }; FW_DETAIL="nur-von:${FW_SRCS// /,}(Rich-Rule)"
  elif [ "$review" -eq 1 ]; then
    FW_STATUS=review; FW_DETAIL="Rich-Rule-pruefen"
  fi
}

# Bewertung für ein Interface: Interface-Zone + alle Zonen mit Quell-Bindung
fw_eval_iface() {
  local z=$1 port=$2 proto=$3 sz st dt srcs="" details="" rev=0
  fw_eval "$z" "$port" "$proto"
  [ "$FW_STATUS" = open ] && return
  st=$FW_STATUS; dt=$FW_DETAIL
  [ "$st" = restricted ] && { srcs=$FW_SRCS; details=$dt; }
  [ "$st" = review ] && rev=1
  for sz in "${SRC_ZONES[@]}"; do
    fw_eval "$sz" "$port" "$proto"
    case "$FW_STATUS" in
      open)       srcs="$srcs ${ZONE_SRCS[$sz]}"; details="$details nur-von:$(tr ' ' ',' <<<"${ZONE_SRCS[$sz]}")(Zone-$sz)" ;;
      restricted) srcs="$srcs $FW_SRCS"; details="$details ${FW_DETAIL%(*}(Zone-$sz)" ;;
      review)     rev=1 ;;
    esac
  done
  if [ -n "${srcs// /}" ] && [ "$rev" -eq 0 ]; then
    FW_STATUS=restricted; FW_SRCS=${srcs# }; details=${details# }; FW_DETAIL=${details// /+}
  elif [ "$rev" -eq 1 ]; then
    FW_STATUS=review; FW_DETAIL="Rich-Rule-pruefen"
  else
    FW_STATUS=$st; FW_DETAIL=$dt
  fi
}

# ---------- Interfaces ----------
while read -r _ ifc fam addr _; do
  ifc=${ifc%@*}
  case "$ifc" in lo|veth*) continue ;; esac
  ip=${addr%/*}
  IF_IPS[$ifc]="${IF_IPS[$ifc]:-}${IF_IPS[$ifc]:+ }$ip"
  IP_IF[$ip]=$ifc
  if is_public_ip "$ip"; then cls=oeffentlich; else cls=privat; fi
  [ "$cls" = oeffentlich ] || [ -z "${IF_NET[$ifc]:-}" ] && IF_NET[$ifc]=$cls
  if [ "$fam" = inet ]; then
    [ "$cls" = oeffentlich ] || [ -z "${IF_NET4[$ifc]:-}" ] && IF_NET4[$ifc]=$cls
  fi
done < <(ip -o addr show 2>/dev/null)
IFACES=$(printf '%s\n' "${!IF_NET[@]}" | sort)
IFACES4=$(printf '%s\n' "${!IF_NET4[@]}" | sort)

# ---------- firewalld ----------
FW_ACTIVE=0; FW_UNKNOWN=0; DEFZONE=""; ACTIVE_ZONES=""
fw_running() { systemctl is-active --quiet firewalld 2>/dev/null || ps -C firewalld -o stat= 2>/dev/null | grep -qv '^Z'; }
if fw_running && ! $SUDO firewall-cmd --state >/dev/null 2>&1; then
  FW_UNKNOWN=1     # laeuft, aber ohne Rechte nicht abfragbar ("not running" via D-Bus/polkit)
elif command -v firewall-cmd >/dev/null 2>&1 && $SUDO firewall-cmd --state >/dev/null 2>&1; then
  FW_ACTIVE=1
  DEFZONE=$($SUDO firewall-cmd --get-default-zone 2>/dev/null)
  ACTIVE_ZONES=$($SUDO firewall-cmd --get-active-zones 2>/dev/null)
  declare -A IFZ_RAW
  cur=""
  while IFS= read -r line; do
    case "$line" in
      ''|' '*|$'\t'*)
        case "$line" in
          *interfaces:*) for i in ${line#*interfaces:}; do IFZ_RAW[$i]=$cur; done ;;
          *sources:*)    l=${line#*sources:}; [ -n "${l//[[:space:]]/}" ] && SRC_ZONES+=("$cur") ;;
        esac ;;
      *) cur=${line%% *} ;;
    esac
  done <<<"$ACTIVE_ZONES"
  for ifc in $IFACES; do
    if [ -n "${IFZ_RAW[$ifc]:-}" ]; then IF_ZONE[$ifc]=${IFZ_RAW[$ifc]}; IF_ZLABEL[$ifc]=${IFZ_RAW[$ifc]}
    else IF_ZONE[$ifc]=$DEFZONE; IF_ZLABEL[$ifc]="$DEFZONE(default)"; fi
  done
  for z in $(printf '%s\n' "${IF_ZONE[@]}" "${SRC_ZONES[@]}" | sort -u); do load_zone "$z"; done
fi

# ---------- Lauschende Sockets auswerten ----------
ROWS=()
while read -r proto _ _ _ local _ procinfo; do
  port=${local##*:}
  [[ $port =~ ^[0-9]+$ ]] || continue
  addr=${local%:*}                          # z.B. [fe80::1]%eth0, 0.0.0.0%int1, *
  bindif=""
  if [[ $addr == *%* ]]; then bindif=${addr##*%}; addr=${addr%\%*}; fi
  addr=${addr#\[}; addr=${addr%\]}
  [[ $addr == *%* ]] && { bindif=${addr##*%}; addr=${addr%\%*}; }   # alte ss-Variante [fe80::1%eth0]
  pname=$(sed -n 's/.*(("\([^"]*\)".*/\1/p' <<<"$procinfo"); pname=${pname:--}
  pid=$(sed -n 's/^users:(("[^"]*",pid=\([0-9]*\).*/\1/p' <<<"$procinfo")
  unit=""
  if [ -n "$pid" ]; then
    unit=$(sed -n 's#^\(0::\|[0-9]*:name=systemd:\)##p' /proc/"$pid"/cgroup 2>/dev/null \
           | grep -o '[^/]*\.\(service\|scope\|socket\)' | tail -1)
  fi
  unit=${unit:--}
  lookup=${addr#::ffff:}

  case "$addr" in
    127.*|::1|::ffff:127.*) targets="lo"; fam=4 ;;
    0.0.0.0)                targets=${bindif:-$IFACES4}; fam=4 ;;
    ::|'*'|'')              targets=${bindif:-$IFACES}; fam=6 ;;
    *)                      targets=${IP_IF[$lookup]:-?}; [[ $addr == *:* ]] && fam=6 || fam=4 ;;
  esac
  [ "$bindif" = lo ] && targets=lo

  for t in $targets; do
    if [ "$t" = "lo" ]; then
      net="lokal"; zone="-"; fw="-"; rating="LOKAL"
    else
      if [ "$fam" = 4 ]; then net=${IF_NET4[$t]:-${IF_NET[$t]:-?}}; else net=${IF_NET[$t]:-?}; fi
      if [ "$pname" = docker-proxy ]; then
        zone=${IF_ZLABEL[$t]:--}; FW_STATUS=open; FW_SRCS=""; fw="Docker-DNAT(Zone-greift-nicht)"
      elif [ "$FW_ACTIVE" -eq 1 ] && [ -n "${IF_ZONE[$t]:-}" ]; then
        zone=${IF_ZLABEL[$t]}
        fw_eval_iface "${IF_ZONE[$t]}" "$port" "$proto"; fw=$FW_DETAIL
      elif [ "$FW_UNKNOWN" -eq 1 ]; then
        zone="?"; FW_STATUS=review; FW_SRCS=""; fw="firewalld-nicht-abfragbar"
      else
        zone="-"; FW_STATUS=open; FW_SRCS=""
        if [ "$FW_ACTIVE" -eq 1 ]; then fw="Interface-unbekannt"; else fw="ungefiltert?"; fi
      fi
      case "$FW_STATUS" in
        blocked)    rating="BLOCKIERT" ;;
        review)     rating="PRUEFEN" ;;
        restricted) case "$net:$(src_class "$FW_SRCS")" in
                      oeffentlich:oeffentlich) rating="EXTERN" ;;
                      oeffentlich:unklar|\?:*) rating="PRUEFEN" ;;
                      *)                       rating="INTERN" ;;
                    esac ;;
        *)          case "$net" in
                      oeffentlich) rating="EXTERN" ;;
                      privat)      rating="INTERN" ;;
                      *)           rating="PRUEFEN" ;;
                    esac ;;
      esac
    fi
    ROWS+=("$proto;$port;$addr;$pname;$unit;$t;$net;$zone;$fw;$rating")
  done
done < <($SUDO ss -tulpn 2>/dev/null | tail -n +2)

ORDER="EXTERN PRUEFEN INTERN BLOCKIERT LOKAL"
SORTED=$(printf '%s\n' "${ROWS[@]}" | grep -v '^$' | sort -u | sort -t';' -k2,2n -k1,1 -k6,6)

# ---------- Ausgabe ----------
OS=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unbekannt}")
echo "=========================================================================="
echo " Netzwerk-Exposition: $HOST | $OS | $(date '+%F %T')"
echo "=========================================================================="
echo "Interfaces:"
for ifc in $IFACES; do
  printf '  %-14s %-12s Zone: %-20s %s\n' "$ifc" "${IF_NET[$ifc]}" "${IF_ZLABEL[$ifc]:--}" "${IF_IPS[$ifc]}"
done
echo "  Default-Route ueber: $(ip route show default 2>/dev/null | awk '{print $5; exit}')"
echo
if [ "$FW_UNKNOWN" -eq 1 ]; then
  echo "firewalld: laeuft, aber nicht abfragbar (fehlende Rechte oder D-Bus) -> Firewall-Bewertung fehlt."
elif [ "$FW_ACTIVE" -eq 1 ]; then
  echo "firewalld: aktiv (Default-Zone: $DEFZONE). Aktive Zonen:"
  for z in $(printf '%s\n' "${!ZONE_INFO[@]}" | sort); do
    printf '  %-12s target=%s' "$z" "${ZONE_TARGET[$z]:-?}"
    [ -n "${ZONE_SRCS[$z]// /}" ] && printf ' | Quellen: %s' "${ZONE_SRCS[$z]}"
    printf ' | Services: %s' "$(sed -n 's/^ *services: *//p' <<<"${ZONE_INFO[$z]}")"
    printf ' | Ports: %s\n' "$(sed -n 's/^ *ports: *//p' <<<"${ZONE_INFO[$z]}")"
    [ -n "${ZONE_FWD[$z]// /}" ] && echo "               Forward-Ports: ${ZONE_FWD[$z]}"
    [ -n "${ZONE_RICH[$z]}" ] && sed 's/^[[:space:]]*/               Rich: /' <<<"${ZONE_RICH[$z]}"
  done
else
  echo "firewalld: NICHT aktiv."
  echo "  nft-Regelzeilen: $($SUDO nft list ruleset 2>/dev/null | grep -c .)" \
       " | iptables-Regeln: $($SUDO iptables -S 2>/dev/null | grep -c '^-A')"
  echo "  -> Filterung ggf. ueber nft/iptables direkt, manuell pruefen."
fi
echo
echo "Lauschende Dienste:"
{ echo "PROTO;PORT;BIND;PROZESS;UNIT;IFACE;NETZ;ZONE;FIREWALL;BEWERTUNG"
  for r in $ORDER; do grep ";$r\$" <<<"$SORTED"; done
} | if command -v column >/dev/null 2>&1; then column -t -s';'; else tr ';' '\t'; fi
echo
echo "Zusammenfassung je Dienst (hoechste Einstufung ueber alle Interfaces):"
for r in $ORDER; do grep ";$r\$" <<<"$SORTED"; done | awk -F';' '
  { k = $1 "/" $2 " " $4
    if (!(k in best)) { best[k] = $10; unit[k] = $5; det[k] = $9; ord[++n] = k }
    if ($10 == best[k] && index("," ifs[k] ",", "," $6 ",") == 0) ifs[k] = ifs[k] (ifs[k] ? "," : "") $6 }
  END { if (n == 0) print "  keine lauschenden Dienste gefunden"
        for (j = 1; j <= n; j++) { k = ord[j]; split(k, a, " ")
          printf "  %-10s %-10s %-16s %-24s via %-16s %s\n", best[k], a[1], a[2], unit[k], ifs[k], det[k] } }'
echo

for c in podman docker; do
  command -v "$c" >/dev/null 2>&1 || continue
  out=$($SUDO "$c" ps --format '{{.Names}}  {{.Ports}}' 2>/dev/null)
  [ -n "$out" ] || continue
  echo "$c-Container (veroeffentlichte Ports):"
  echo "$out" | sed 's/^/  /'
  echo "  HINWEIS: Container-Ports werden per DNAT weitergeleitet und koennen firewalld-Zonen umgehen."
  echo
done

echo "Legende: EXTERN    = oeffentliche IP am Interface und Firewall offen (ggf. nur fuer oeffentliche Quellen)"
echo "         INTERN    = private IP am Interface oder nur fuer private Quellnetze freigegeben"
echo "         PRUEFEN   = Freigabe fuer ipset/MAC/NOT-Quelle, Sperr-Rich-Rule ohne Quelle oder unklare
                     Interface-Zuordnung (z.B. IP auf lo, nonlocal bind) -> manuell pruefen"
echo "         BLOCKIERT = lauscht, aber von firewalld gesperrt | LOKAL = nur Loopback"
echo "         Private IPs koennen per NAT/Portweiterleitung am Perimeter trotzdem von aussen erreichbar sein."
[ "$PRIV" -eq 0 ] && echo "ACHTUNG: ohne root/sudo gelaufen - Ergebnis UNVOLLSTAENDIG."
echo
echo "# Maschinenlesbar: INV;host;proto;port;bind;prozess;unit;iface;netz;zone;firewall;bewertung"
grep -v '^$' <<<"$SORTED" | sed "s/^/INV;$HOST;/"
[ "$PRIV" -eq 1 ] && exit 0 || exit 2
