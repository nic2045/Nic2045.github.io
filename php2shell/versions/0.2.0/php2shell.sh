#!/usr/bin/env bash
# php2shell.sh - PHP CVE exposure analysis for Ubuntu hosts (read-only, changes nothing)
#
# DESCRIPTION
#   Collects host data, finds PHP packages and PHP web apps, asks Ubuntu Pro
#   ("pro fix <CVE> --dry-run") about the given CVEs and prints a verdict with a recommendation.
#
# USAGE
#   ./php2shell.sh [-h|--help] [CVE-ID ...]     default: CVE-2026-109618 CVE-2026-109619
#   OUTDIR=/var/tmp/php2shell ./php2shell.sh CVE-2026-109618
#   NO_COLOR=1 ./php2shell.sh                    plain output (also automatic when not on a terminal)
#
# PRIVILEGES (least privilege)
#   Run as a normal user. Do NOT start the whole script with "sudo bash".
#   Only two read probes use "sudo -n" (non-interactive, only if passwordless sudo exists):
#     - apache2ctl -M                        (is mod_php loaded?)
#     - reading /var/log/apache2/*access*.log (PHP usage statistics)
#   Without sudo (and not root) these probes use a fallback or are skipped. Every skipped or
#   limited check is listed at the end of the report ("Skipped / limited checks") and in the log.
#
# OUTPUT   $OUTDIR (default ./php2shell_logs)
#   <host>_<ts>.log     detailed log (timestamps, raw command output, full package list)
#   <host>_<ts>.result  complete report as shown on screen (no colors)
#
# EXIT CODES   0 = OK / not affected, 1 = affected, 2 = unclear, 3 = cannot create output dir, 4 = bad arguments
#
# Version: 0.2.0   (x-release-please-version)
#
# Changelog
#   0.1.0 (2026-10-22)
#     - First published version (read-only PHP CVE exposure analysis for Ubuntu hosts)
#
# NOTE  No "set -e/-u/pipefail" on purpose: this is a probe script, a failing probe (e.g. grep without
#       match) must not stop the report.

SCRIPT_VERSION=0.2.0   # x-release-please-version

usage() {
  cat <<'EOF'
php2shell.sh - PHP CVE exposure analysis (read-only)

Usage:   ./php2shell.sh [-h|--help] [CVE-ID ...]
         OUTDIR=<dir> ./php2shell.sh [CVE-ID ...]
Default: CVE-2026-109618 CVE-2026-109619

Run as a normal user. sudo -n is used only for 'apache2ctl -M' and the Apache access logs,
and only if passwordless sudo is available. Do not run the whole script with 'sudo bash'.
Exit codes: 0 OK, 1 affected, 2 unclear, 3 output dir error, 4 bad arguments
EOF
}

case "${1:-}" in -h | --help) usage; exit 0 ;; esac
CVES=("$@")
[ $# -eq 0 ] && CVES=(CVE-2026-109618 CVE-2026-109619)
for c in "${CVES[@]}"; do
  [[ "$c" =~ ^CVE-[0-9]{4}-[0-9]+$ ]] || { echo "Invalid CVE ID: $c" >&2; usage >&2; exit 4; }
done

export LC_ALL=C   # the script parses English tool output (pro, apt), independent of the system language
umask 077         # log and report contain host names, IPs and paths: readable by the current user only

OUTDIR="${OUTDIR:-./php2shell_logs}"
mkdir -p "$OUTDIR" || { echo "Cannot create $OUTDIR" >&2; exit 3; }
TS=$(date +%Y%m%d_%H%M%S)
BASE="$OUTDIR/$(hostname)_$TS"
LOG="$BASE.log"
RESULT="$BASE.result"
RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; C=$'\e[36m'; W=$'\e[1m'; N=$'\e[0m'
else R=; G=; Y=; B=; C=; W=; N=; fi

log() { printf '%s | %s\n' "$(date '+%F %T')" "$*" >> "$LOG"; }
logblock() { { echo "----- $1 -----"; cat; echo "----- end -----"; } >> "$LOG"; }
hdr() { echo; echo "${B}${W}━━ $1 ━━${N}"; log "SECTION: $1"; }
kv() { printf '  %s%-22s%s %s\n' "$C" "$1" "$N" "$2"; log "$1: $2"; }

SKIPPED=()   # checks that were skipped or only partly possible; listed at the end of the report
skip() { SKIPPED+=("$1"); log "SKIPPED: $1"; }
show_skipped() {
  if [ ${#SKIPPED[@]} -eq 0 ]; then echo; echo "  Skipped checks: ${G}none${N}"; log "Skipped checks: none"; return; fi
  echo; echo "  ${Y}${W}Skipped / limited checks (${#SKIPPED[@]}) - result may be incomplete:${N}"
  printf '    - %s\n' "${SKIPPED[@]}"
  if [ "$MODE" = user ] && printf '%s\n' "${SKIPPED[@]}" | grep -qi 'sudo'; then
    echo "    Run again as a user with passwordless 'sudo -n' to cover the sudo-dependent checks."
  fi
}

main() {
  # Privilege mode: root | sudo (passwordless sudo -n) | user (no elevation)
  SUDO=()
  if [ "$(id -u)" -eq 0 ]; then MODE=root
  elif sudo -n true 2>/dev/null; then MODE=sudo; SUDO=(sudo -n)
  else MODE=user; fi
  log "START php2shell $SCRIPT_VERSION | user=$(id -un) | mode=$MODE | CVEs=${CVES[*]}"

  echo "${W}PHP CVE exposure report${N}  $(date '+%F %T')  CVEs: ${CVES[*]}"
  echo "  Log: $LOG"; echo "  Result: $RESULT"
  case "$MODE" in
    root) echo "  ${Y}Privileges: running as root (not needed - a normal user with 'sudo -n' is enough)${N}" ;;
    sudo) echo "  ${G}Privileges: user $(id -un) + sudo -n, used only for: apache2ctl -M, Apache access logs${N}" ;;
    user) echo "  ${Y}Privileges: user $(id -un), no passwordless sudo -> skipped: apache2ctl -M (fallback: mods-enabled), Apache access logs${N}" ;;
  esac

  ###################### 1/4 HOST ######################
  hdr "1/4 HOST"
  [ -r /etc/os-release ] && . /etc/os-release
  kv "Hostname"         "$(hostname)"
  kv "FQDN"             "$(hostname -f 2>/dev/null)"
  kv "IP addresses"     "$(hostname -I 2>/dev/null)"
  kv "Default gateway"  "$(ip route 2>/dev/null | awk '/default/{print $3; exit}')"
  kv "OS"               "${PRETTY_NAME:-unknown}"
  kv "Kernel"           "$(uname -r)"
  kv "Virtualization"   "$(systemd-detect-virt 2>/dev/null)"
  kv "Uptime"           "$(uptime -p)"
  kv "Last apt update"  "$(stat -c %y /var/lib/apt/periodic/update-success-stamp 2>/dev/null | cut -d. -f1)"
  kv "Ubuntu Pro / ESM" "$(pro status 2>/dev/null | awk '/^esm-(apps|infra)/{printf "%s:%s ",$1,$3}')"
  if [ -f /var/run/reboot-required ]; then kv "Reboot required" "${Y}YES${N}"; else kv "Reboot required" "no"; fi

  ###################### 2/4 SERVICES & APPS ######################
  hdr "2/4 AFFECTED SERVICES & APPLICATIONS"
  PHPPK=$(dpkg -l 'php*' 'libapache2-mod-php*' 2>/dev/null | awk '/^ii/{print $2" "$3}')
  CORE=$(echo "$PHPPK" | awk '$1 ~ /^php[0-9]+\.[0-9]+$/{print $1}')
  NOPHP=0
  if [ -z "$PHPPK" ]; then NOPHP=1; echo "  ${G}No PHP packages installed (dpkg)${N}"; log "PHP packages: none"
  else
    kv "PHP packages" "$(echo "$PHPPK" | wc -l) installed (full list in log)"
    echo "$PHPPK" | logblock "PHP package list"
  fi
  command -v php > /dev/null && kv "PHP CLI" "$(php -v | head -1)"
  OTHERPHP=$(ls /usr/local/bin/php* /opt/*/bin/php 2>/dev/null | tr '\n' ' ')
  [ -n "$OTHERPHP" ] && echo "  ${Y}PHP outside dpkg: $OTHERPHP (not covered by apt fix)${N}" && log "Non-dpkg PHP: $OTHERPHP"
  if command -v docker > /dev/null && ! docker ps > /dev/null 2>&1; then skip "Docker container check - no permission to talk to docker"; fi
  DK=$(docker ps --format '{{.Names}} ({{.Image}})' 2>/dev/null | grep -i php | tr '\n' ' ')
  [ -n "$DK" ] && echo "  ${Y}PHP containers: $DK (patch separately)${N}" && log "PHP containers: $DK"

  echo; echo "  ${W}Services:${N}"
  APACHE=$(systemctl is-active apache2 2>/dev/null)
  NGINX=$(systemctl is-active nginx 2>/dev/null)
  FPM=$(systemctl list-units --type=service --state=active --no-legend 'php*fpm*' 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
  MODPHP=$({ "${SUDO[@]}" apache2ctl -M 2>/dev/null || ls /etc/apache2/mods-enabled 2>/dev/null; } | grep -i 'php' | head -1)
  if [ "$MODE" = user ] && command -v apache2ctl > /dev/null; then skip "apache2ctl -M (loaded Apache modules) - no sudo, mods-enabled used as fallback"; fi
  kv "apache2" "${APACHE:-n/a}"
  kv "mod_php loaded" "${MODPHP:-no}$([ "$MODE" = user ] && echo ' (checked via mods-enabled, no sudo)')"
  kv "nginx" "${NGINX:-n/a}"
  kv "php-fpm" "${FPM:-not active}"
  kv "Web ports listening" "$(ss -tln 2>/dev/null | awk 'NR>1{print $4}' | grep -E ':(80|443|8080|8443)$' | sort -u | tr '\n' ' ')"
  EXPOSED=0
  { [ "$APACHE" = active ] && [ -n "$MODPHP" ]; } && EXPOSED=1
  [ -n "$FPM" ] && EXPOSED=1

  detect_app() { # $1 = directory -> sets APP, VER
    local d="$1"; APP=""; VER=""
    if   [ ! -d "$d" ]; then APP="path does not exist"; return
    elif [ ! -r "$d" ]; then APP="not readable (needs a user with read access or sudo)"; skip "App detection for $d - directory not readable"; return
    elif [ -f "$d/wp-includes/version.php" ]; then APP="WordPress"; VER=$(grep -oP '\$wp_version\s*=\s*\x27\K[^\x27]+' "$d/wp-includes/version.php")
    elif [ -f "$d/version.php" ] && grep -q OC_Version "$d/version.php" 2>/dev/null; then APP="Nextcloud/ownCloud"; VER=$(grep -oP '\$OC_VersionString\s*=\s*\x27\K[^\x27]+' "$d/version.php")
    elif [ -d "$d/typo3conf" ] || [ -d "$d/typo3" ]; then APP="TYPO3"
    elif [ -f "$d/configuration.php" ] && [ -d "$d/administrator" ]; then APP="Joomla"
    elif [ -f "$d/core/lib/Drupal.php" ]; then APP="Drupal"
    elif [ -f "$d/../artisan" ] || [ -f "$d/artisan" ]; then APP="Laravel"
    elif [ -f "$d/../bin/console" ]; then APP="Symfony"
    elif [ -f "$d/index.php" ] && grep -qi phpmyadmin "$d/index.php" 2>/dev/null; then APP="phpMyAdmin"
    elif [ -d "$d/glpi" ] || [ -f "$d/inc/includes.php" ]; then APP="GLPI"
    elif [ -f "$d/index.php" ]; then APP="PHP app (unknown) | content: $(ls "$d" | head -8 | tr '\n' ' ')"
    elif [ -n "$(find "$d" -maxdepth 2 -name '*.php' -print -quit 2>/dev/null)" ]; then APP="PHP files (unknown) | content: $(ls "$d" | head -8 | tr '\n' ' ')"
    else APP="no PHP found (static?)"; fi
  }

  APPS=()
  echo; echo "  ${W}Apache vhosts -> applications:${N}"
  for f in /etc/apache2/sites-enabled/*; do
    [ -e "$f" ] || continue
    sn=$(grep -hiE '^\s*Server(Name|Alias)' "$f" | awk '{print $2}' | sort -u | tr '\n' ' ')
    while IFS= read -r dr; do
      [ -n "$dr" ] || continue
      detect_app "$dr"
      printf '    %s%-28s%s %s\n      -> %s%s %s%s\n' "$W" "${sn:-(no ServerName)}" "$N" "$dr" "$Y" "$APP" "$VER" "$N"
      log "VHOST file=$f name=${sn:-none} root=$dr app=$APP $VER"
      APPS+=("${sn:-$dr} -> $APP $VER")
    done < <(grep -hiE '^\s*DocumentRoot' "$f" | awk '{print $2}' | tr -d '"' | sort -u)
  done
  ALIASES=$(grep -hiE '^\s*Alias\s' /etc/apache2/sites-enabled/* /etc/apache2/conf-enabled/* 2>/dev/null | sort -u)
  [ -n "$ALIASES" ] && { echo "  ${W}Alias paths (often extra apps, e.g. phpMyAdmin):${N}"; echo "$ALIASES" | sed 's/^/    /'; echo "$ALIASES" | logblock "Apache Alias"; }
  if [ "$NGINX" = active ]; then
    echo "  ${W}nginx:${N}"; grep -hE '^\s*(server_name|root)\s' /etc/nginx/sites-enabled/* 2>/dev/null | sed 's/^/    /'
  fi
  PKGAPPS=$(dpkg -l 2>/dev/null | awk '/^ii/ && $2 ~ /^(phpmyadmin|wordpress|nextcloud|glpi|roundcube|mediawiki|zabbix-frontend-php|dokuwiki|matomo|cacti|librenms)/{print $2" "$3}')
  [ -n "$PKGAPPS" ] && { echo "  ${W}PHP apps installed as packages:${N}"; echo "$PKGAPPS" | sed 's/^/    /'; echo "$PKGAPPS" | logblock "Packaged PHP apps"; }

  LOGFILES=(/var/log/apache2/*access*.log)
  if [ -e "${LOGFILES[0]}" ]; then
    if [ "$MODE" = user ] && [ ! -r "${LOGFILES[0]}" ]; then
      echo; echo "  ${Y}PHP usage (access logs): skipped - not readable without sudo${N}"; skip "PHP usage from Apache access logs - not readable without sudo"
    else
      PHPHITS=$("${SUDO[@]}" cat "${LOGFILES[@]}" 2>/dev/null | grep -cE '\.php')
      echo; echo "  ${W}PHP usage (current access logs):${N} ${PHPHITS:-0} requests to *.php"
      TOP=$("${SUDO[@]}" cat "${LOGFILES[@]}" 2>/dev/null | grep -oE '"(GET|POST) [^ ?"]+\.php' | awk '{print $2}' | sort | uniq -c | sort -rn | head -5)
      echo "$TOP" | sed 's/^/    /'; echo "$TOP" | logblock "Top PHP URLs"
    fi
  fi

  ###################### 3/4 CVE ######################
  hdr "3/4 CVE RESULT"
  command -v pro > /dev/null || skip "CVE status via 'pro fix --dry-run' - Ubuntu Pro client ('pro') not found"
  AFFECTED=0; UNCLEAR=0; RAWOUT=""
  for c in "${CVES[@]}"; do
    if ! command -v pro > /dev/null; then
      printf '  %s%-18s%s %b\n' "$W" "$c" "$N" "${Y}UNKNOWN (pro not available)${N}"
      log "CVE $c => UNKNOWN | pro not available"; UNCLEAR=1; continue
    fi
    out=$(pro fix "$c" --dry-run 2>&1)
    echo "$out" | logblock "pro fix $c --dry-run"
    title=$(echo "$out" | head -1 | cut -c1-80)
    fixv=$(echo "$out" | grep -oE 'version [0-9][^ ]+' | awk '{print $2}' | sort -uV | tail -1)
    if   echo "$out" | grep -qiE 'not found|not a valid|no such'; then st="${Y}UNKNOWN (check CVE ID)${N}"; stp="UNKNOWN"; UNCLEAR=1
    elif echo "$out" | grep -qiE 'is resolved'; then st="${G}RESOLVED${N}"; stp="RESOLVED"
    elif echo "$out" | grep -qiE 'no affected source|not affected'; then st="${G}NOT AFFECTED${N}"; stp="NOT AFFECTED"
    elif echo "$out" | grep -qiE 'affected source package|not resolved'; then st="${R}${W}AFFECTED${N}"; stp="AFFECTED"; AFFECTED=1
    else st="${Y}UNCLEAR (raw output below)${N}"; stp="UNCLEAR"; UNCLEAR=1; RAWOUT="$RAWOUT\n--- $c ---\n$out\n"; fi
    printf '  %s%-18s%s %b\n' "$W" "$c" "$N" "$st"
    [ -n "$title" ] && echo "      $title"
    [ -n "$fixv" ] && echo "      Fix version per Ubuntu: ${W}$fixv${N}"
    log "CVE $c => $stp | fix=$fixv"
  done
  [ -n "$RAWOUT" ] && printf '%b\n' "$RAWOUT" | head -30

  echo; echo "  ${W}Version comparison (installed vs. repo):${N}"
  UPDATE_READY=0
  for p in $CORE; do
    inst=$(dpkg-query -W -f='${Version}' "$p"); cand=$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate:/{print $2}')
    if [ -n "$cand" ] && dpkg --compare-versions "$cand" gt "$inst"; then
      echo "    $p: $inst  ->  candidate ${G}$cand${N} (update ready)"; UPDATE_READY=1
    else echo "    $p: $inst  (candidate: ${cand:-n/a}, no newer package visible)"; fi
    log "VERSION $p installed=$inst candidate=${cand:-n/a} update_ready=$UPDATE_READY"
    apt-cache policy "$p" 2>/dev/null | logblock "apt-cache policy $p"
  done
  apt-mark showhold 2>/dev/null | logblock "apt-mark showhold"

  ###################### 4/4 VERDICT ######################
  hdr "4/4 VERDICT & RECOMMENDATION"
  if [ $NOPHP -eq 1 ] && [ -z "$OTHERPHP$DK" ]; then
    echo "  ${G}${W}[OK] NOT AFFECTED${N} - no PHP on this host."; log "VERDICT: NOT AFFECTED (no PHP)"; show_skipped; return 0
  fi
  echo "  Host: $(hostname) | Exposure: $([ $EXPOSED -eq 1 ] && echo "${R}PHP reachable via web server${N}" || echo "${G}no web-facing PHP active${N}")"
  [ ${#APPS[@]} -gt 0 ] && { echo "  Affected apps:"; printf '    * %s\n' "${APPS[@]}"; }
  echo
  if [ $AFFECTED -eq 1 ] && [ $EXPOSED -eq 1 ]; then
    echo "  ${R}${W}[ACTION] AFFECTED + web-exposed -> PATCH SOON${N}"; V="AFFECTED+EXPOSED"; RC=1
  elif [ $AFFECTED -eq 1 ]; then
    echo "  ${Y}${W}[WARN] AFFECTED, but no web-facing PHP -> patch in regular cycle${N}"; V="AFFECTED"; RC=1
  elif [ $UNCLEAR -eq 1 ]; then
    echo "  ${Y}${W}[?] UNCLEAR -> verify CVE ID / raw output in log${N}"; V="UNCLEAR"; RC=2
  else
    echo "  ${G}${W}[OK] No action required${N}"; V="OK"; RC=0
  fi
  log "VERDICT: $V (exposed=$EXPOSED update_ready=$UPDATE_READY)"
  if [ $AFFECTED -eq 1 ]; then
    echo "  ${W}Recommendation (NOT executed):${N}"
    if [ $UPDATE_READY -eq 1 ]; then
      echo "   1. Update is available in the repo -> apply in next maintenance window"
      echo "   2. Afterwards restart services: apache2 / php-fpm"
    else
      echo "   1. Fix NOT visible in repo -> check mirror/sync/pinning (apt update, apt-mark showhold)"
      echo "   2. Meanwhile: reduce exposure (WAF / access restriction) for affected apps"
    fi
    echo "   3. Verify afterwards: run this script again"
  fi
  show_skipped
  return "${RC:-0}"
}

main 2>&1 | tee "$RAW"
RC=${PIPESTATUS[0]}
sed 's/\x1b\[[0-9;]*m//g' "$RAW" > "$RESULT"
log "END rc=$RC"
echo; echo "Saved: $LOG"; echo "Saved: $RESULT"
exit "$RC"
