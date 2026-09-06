#!/usr/bin/env bash
#
# vigil-ioc-sim-ingest.sh — simulated threat-feed ingestion for a local Vigil SOC
#
# Pulls indicators from public, keyless IOC sources, relabels them as the
# member-only sharing organizations a production SOC would subscribe to
# (TX-ISAO, CISA AIS, MS-ISAC, FS-ISAC, Health-ISAC, InfraGard, CTA, OTX,
# CIRCL/MISP), and upserts them into the local Vigil `threat_indicators`
# table so agents and finding enrichment have something real to match on.
#
# Every row it writes carries the label `simulated`, so simulated intel is
# always distinguishable from — and purgeable independently of — real feed
# data (see --purge). Rows fabricated offline also carry `synthetic`.
#
# Target table (infra/database/init/14_threat_indicators.sql):
#   threat_indicators(indicator_type, indicator_value, source, collection_id,
#                     confidence, threat_level, labels, valid_from,
#                     valid_until, raw_stix, first_seen, last_seen)
#   UNIQUE (source, indicator_type, indicator_value)
#
# Notes on the wider pipeline:
#   * Finding enrichment reads this table via
#     services/daemon/processor.py::_lookup_threat_indicators, which is gated
#     on the `cloudforce_one` integration being enabled. Use --enable-lookup
#     once to flip that on in ~/.vigil/integrations_config.json.
#   * Matching is exact-value on the (indicator_type, indicator_value) index.
#     The current schema has no vector column on threat_indicators (the
#     embedding column was dropped in migration 23), so there is no pgvector
#     similarity path for indicators to populate.
#
# Usage: vigil-ioc-sim-ingest.sh --help
#
set -Eeuo pipefail
IFS=$'\n\t'

readonly PROG="${0##*/}"
readonly VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Defaults (override via flags or environment)
# ---------------------------------------------------------------------------
LIMIT="${VIGIL_IOC_LIMIT:-250}"          # indicators per source, post-dedupe
TTL_DAYS="${VIGIL_IOC_TTL_DAYS:-14}"     # valid_until = now + TTL
HTTP_TIMEOUT="${VIGIL_IOC_HTTP_TIMEOUT:-25}"
SOURCES_ARG="${VIGIL_IOC_SOURCES:-keyless}"
OUT_DIR="${VIGIL_IOC_OUT_DIR:-}"         # default: a temp dir, cleaned up
DB_URL="${VIGIL_IOC_DB_URL:-}"           # else DATABASE_URL / POSTGRES_* / .env
ENV_FILE="${VIGIL_IOC_ENV_FILE:-}"       # else auto-detect Vigil .env
PG_CONTAINER="${VIGIL_IOC_PG_CONTAINER:-deeptempo-postgres}"
LOCK_FILE="${VIGIL_IOC_LOCK:-/tmp/vigil-ioc-sim-ingest.lock}"
UA="${VIGIL_IOC_USER_AGENT:-vigil-soc-ioc-sim/1.0 (local lab ingest)}"

SIM_AS_ORGS=1        # relabel indicators as the doc's sharing orgs
ALLOW_SYNTHETIC=1    # fabricate a batch when a source is unreachable
SYNTHETIC_ONLY=0
ALLOW_PRIVATE=0      # never ingest RFC1918 & friends unless asked
DRY_RUN=0
DO_PURGE=0
DO_STATS=0
ENABLE_LOOKUP=0
KEEP_ARTIFACTS=0
VERBOSE=0

# ---------------------------------------------------------------------------
# Source registry.  fetch kind:
#   text  — plain list, one indicator per line (comments stripped)
#   json  — any JSON; candidate tokens harvested from all string/number leaves
#   csv   — delimited text; candidate tokens harvested per line
#   misp  — CIRCL OSINT MISP feed (manifest.json + per-event JSON)
# Fields: kind|url|default_threat_level|base_confidence|needs
# ---------------------------------------------------------------------------
declare -A SOURCE_SPEC=(
  [tor_exit]="text|https://check.torproject.org/torbulkexitlist|medium|55|none"
  [blocklist_de]="text|https://lists.blocklist.de/lists/all.txt|medium|60|none"
  [sans_isc]="json|https://isc.sans.edu/api/topips/records/__LIMIT__?json|high|70|none"
  [circl_osint]="misp|https://www.circl.lu/doc/misp/feed-osint|high|75|none"
  [urlhaus]="csv|https://urlhaus.abuse.ch/downloads/csv_recent/|high|80|abusech"
  [feodo]="text|https://feodotracker.abuse.ch/downloads/ipblocklist.txt|critical|85|abusech"
  [threatfox]="csv|https://threatfox.abuse.ch/export/csv/recent/|high|80|abusech"
  [otx]="json|https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50|medium|65|otx"
)
readonly KEYLESS_SOURCES=(tor_exit blocklist_de sans_isc circl_osint)
readonly ALL_SOURCES=(tor_exit blocklist_de sans_isc circl_osint urlhaus feodo threatfox otx)

# Sharing organizations from the feed inventory. `_sim` suffix is deliberate:
# a real subscription would write `tx_isao`, never `tx_isao_sim`.
readonly SIM_ORGS=(
  tx_isao_sim cisa_ais_sim ms_isac_sim fs_isac_sim
  health_isac_sim infragard_sim cta_sim otx_sim circl_misp_sim
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
if [[ -t 2 ]]; then
  C_RED=$'\033[31m'; C_YLW=$'\033[33m'; C_GRN=$'\033[32m'
  C_DIM=$'\033[2m';  C_BLD=$'\033[1m';  C_RST=$'\033[0m'
else
  C_RED=""; C_YLW=""; C_GRN=""; C_DIM=""; C_BLD=""; C_RST=""
fi

_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log()  { printf '%s [%s] %s\n'            "$(_ts)" "info"  "$*" >&2; }
ok()   { printf '%s [%s] %s%s%s\n'        "$(_ts)" "ok"    "$C_GRN" "$*" "$C_RST" >&2; }
warn() { printf '%s [%s] %s%s%s\n'        "$(_ts)" "warn"  "$C_YLW" "$*" "$C_RST" >&2; }
err()  { printf '%s [%s] %s%s%s\n'        "$(_ts)" "error" "$C_RED" "$*" "$C_RST" >&2; }
dbg()  { if (( VERBOSE )); then printf '%s [%s] %s%s%s\n' "$(_ts)" "debug" "$C_DIM" "$*" "$C_RST" >&2; fi; }
die()  { err "$*"; trap - ERR; exit 1; }

on_err() {
  local rc=$? line=${1:-?}
  err "aborted at line ${line} (exit ${rc})"
  exit "$rc"
}
trap 'on_err $LINENO' ERR

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
  cat <<__USAGE__
${PROG} ${VERSION} — simulated public-IOC ingestion into a local Vigil SOC

USAGE
  ${PROG} [options]

SOURCES
  --sources LIST        Comma-separated source ids, or: keyless | all
                        (default: keyless)
  --list-sources        Print the source registry and exit
  --limit N             Max indicators per source after dedupe (default: ${LIMIT})
  --ttl-days N          valid_until = now + N days (default: ${TTL_DAYS})

SIMULATION
  --no-sim-orgs         Keep the upstream source id instead of relabeling
                        rows as TX-ISAO / CISA AIS / MS-ISAC / ...
  --synthetic-only      Never touch the network; fabricate every batch from
                        documentation ranges (RFC 5737 / RFC 3849 / .invalid)
  --no-synthetic        Do not fabricate on fetch failure; fail loudly instead
  --allow-private       Permit RFC1918 / loopback / link-local values
                        (off by default: they cause internal false positives)

DATABASE
  --db-url DSN          postgresql://... (default: DATABASE_URL, then
                        POSTGRES_* / Vigil .env, then docker exec)
  --env-file PATH       Vigil .env to source the DSN from
  --pg-container NAME   Fallback docker container (default: ${PG_CONTAINER})
  --dry-run             Normalize and write artifacts, touch no database
  --purge               Delete every row labeled 'simulated', then exit
  --stats               Print threat_indicators inventory, then exit
  --enable-lookup       Add 'cloudforce_one' to enabled_integrations in
                        ~/.vigil/integrations_config.json so finding
                        enrichment actually consults this table

MISC
  --out-dir DIR         Keep normalized NDJSON/CSV artifacts here
  --keep-artifacts      Keep the temp working dir on exit
  --cron-hint           Print a crontab / systemd timer snippet and exit
  -v, --verbose         Debug logging
  -h, --help            This text
  --version             Print version

ENVIRONMENT
  ABUSECH_AUTH_KEY      abuse.ch Auth-Key (urlhaus, feodo, threatfox)
  OTX_API_KEY           AlienVault OTX API key (otx)
  VIGIL_IOC_*           Every default above has a VIGIL_IOC_ override

EXAMPLES
  # keyless public feeds, relabeled as ISAC/ISAO sources, into local Postgres
  ${PROG} --limit 500

  # air-gapped lab: fabricate a full multi-source batch, no egress
  ${PROG} --synthetic-only --sources all --limit 200

  # everything, including keyed sources, with a clean slate first
  ${PROG} --purge && ABUSECH_AUTH_KEY=xxx OTX_API_KEY=yyy ${PROG} --sources all
__USAGE__
}

cron_hint() {
  cat <<HINT
# crontab: refresh simulated intel every 6 hours (flock keeps runs serial)
0 */6 * * * /usr/local/bin/${PROG} --sources keyless --limit 500 >> /var/log/vigil-ioc-sim.log 2>&1

# systemd equivalent
# /etc/systemd/system/vigil-ioc-sim.service
#   [Service]
#   Type=oneshot
#   EnvironmentFile=-/etc/default/vigil-ioc-sim
#   ExecStart=/usr/local/bin/${PROG} --sources keyless --limit 500
# /etc/systemd/system/vigil-ioc-sim.timer
#   [Timer]
#   OnCalendar=*-*-* 0/6:00:00
#   Persistent=true
#   [Install]
#   WantedBy=timers.target
# systemctl enable --now vigil-ioc-sim.timer
HINT
}

list_sources() {
  printf '%-14s %-6s %-9s %-5s %s\n' ID KIND SEVERITY CONF AUTH
  local s spec kind url lvl conf needs
  for s in "${ALL_SOURCES[@]}"; do
    spec="${SOURCE_SPEC[$s]}"
    IFS='|' read -r kind url lvl conf needs <<<"$spec"
    printf '%-14s %-6s %-9s %-5s %s\n' "$s" "$kind" "$lvl" "$conf" "$needs"
  done
  printf '\nkeyless = %s\n' "$(IFS=' '; printf '%s' "${KEYLESS_SOURCES[*]}")"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
  while (($#)); do
    case "$1" in
      --sources)        SOURCES_ARG="${2:?--sources needs a value}"; shift 2 ;;
      --sources=*)      SOURCES_ARG="${1#*=}"; shift ;;
      --limit)          LIMIT="${2:?}"; shift 2 ;;
      --limit=*)        LIMIT="${1#*=}"; shift ;;
      --ttl-days)       TTL_DAYS="${2:?}"; shift 2 ;;
      --ttl-days=*)     TTL_DAYS="${1#*=}"; shift ;;
      --db-url)         DB_URL="${2:?}"; shift 2 ;;
      --db-url=*)       DB_URL="${1#*=}"; shift ;;
      --env-file)       ENV_FILE="${2:?}"; shift 2 ;;
      --env-file=*)     ENV_FILE="${1#*=}"; shift ;;
      --pg-container)   PG_CONTAINER="${2:?}"; shift 2 ;;
      --pg-container=*) PG_CONTAINER="${1#*=}"; shift ;;
      --out-dir)        OUT_DIR="${2:?}"; shift 2 ;;
      --out-dir=*)      OUT_DIR="${1#*=}"; shift ;;
      --no-sim-orgs)    SIM_AS_ORGS=0; shift ;;
      --synthetic-only) SYNTHETIC_ONLY=1; shift ;;
      --no-synthetic)   ALLOW_SYNTHETIC=0; shift ;;
      --allow-private)  ALLOW_PRIVATE=1; shift ;;
      --dry-run)        DRY_RUN=1; shift ;;
      --purge)          DO_PURGE=1; shift ;;
      --stats)          DO_STATS=1; shift ;;
      --enable-lookup)  ENABLE_LOOKUP=1; shift ;;
      --keep-artifacts) KEEP_ARTIFACTS=1; shift ;;
      --list-sources)   list_sources; exit 0 ;;
      --cron-hint)      cron_hint; exit 0 ;;
      -v|--verbose)     VERBOSE=1; shift ;;
      -h|--help)        usage; exit 0 ;;
      --version)        printf '%s %s\n' "$PROG" "$VERSION"; exit 0 ;;
      *)                usage >&2; die "unknown argument: $1" ;;
    esac
  done

  [[ "$LIMIT"    =~ ^[0-9]+$ && "$LIMIT"    -gt 0 ]] || die "--limit must be a positive integer"
  [[ "$TTL_DAYS" =~ ^[0-9]+$ && "$TTL_DAYS" -gt 0 ]] || die "--ttl-days must be a positive integer"
  (( SYNTHETIC_ONLY && ! ALLOW_SYNTHETIC )) && die "--synthetic-only and --no-synthetic conflict"
  return 0
}

resolve_sources() {
  local raw="$1"
  case "$raw" in
    all)     SELECTED=("${ALL_SOURCES[@]}");     return 0 ;;
    keyless) SELECTED=("${KEYLESS_SOURCES[@]}"); return 0 ;;
  esac
  SELECTED=()
  local s
  while IFS= read -r s || [[ -n "$s" ]]; do
    s="${s//[[:space:]]/}"
    [[ -z "$s" ]] && continue
    [[ -v SOURCE_SPEC[$s] ]] || die "unknown source '$s' (see --list-sources)"
    SELECTED+=("$s")
  done < <(tr ',' '\n' <<<"$raw")
  ((${#SELECTED[@]})) || die "--sources resolved to nothing"
}

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
need_cmd() { command -v "$1" >/dev/null 2>&1; }

check_deps() {
  local missing=()
  for c in awk sed grep sort jq date mktemp; do
    need_cmd "$c" || missing+=("$c")
  done
  (( SYNTHETIC_ONLY )) || need_cmd curl || missing+=(curl)
  ((${#missing[@]})) && die "missing required commands: ${missing[*]}"
  return 0
}

# ---------------------------------------------------------------------------
# Database plumbing
# ---------------------------------------------------------------------------
PSQL_MODE=""            # local | docker
declare -a PSQL_CMD=()

load_env_dsn() {
  [[ -n "$DB_URL" ]] && return 0
  [[ -n "${DATABASE_URL:-}" ]] && { DB_URL="$DATABASE_URL"; return 0; }

  local candidates=()
  [[ -n "$ENV_FILE" ]] && candidates+=("$ENV_FILE")
  candidates+=("./.env" "../.env" "/opt/vigil/.env" "/srv/vigil/.env" "$HOME/vigil/.env")

  local f line
  for f in "${candidates[@]}"; do
    [[ -r "$f" ]] || continue
    # Read the DSN without sourcing the file (never execute a config file).
    line="$(grep -m1 -E '^[[:space:]]*(export[[:space:]]+)?DATABASE_URL[[:space:]]*=' "$f" 2>/dev/null || true)"
    if [[ -n "$line" ]]; then
      line="${line#*=}"
      line="${line%\"}"; line="${line#\"}"
      line="${line%\'}"; line="${line#\'}"
      DB_URL="$line"
      dbg "DSN from ${f}"
      return 0
    fi
  done

  if [[ -n "${POSTGRES_USER:-}" || -n "${POSTGRES_DB:-}" ]]; then
    DB_URL="postgresql://${POSTGRES_USER:-deeptempo}:${POSTGRES_PASSWORD:-}@${POSTGRES_HOST:-localhost}:${POSTGRES_PORT:-5432}/${POSTGRES_DB:-deeptempo_soc}"
    dbg "DSN assembled from POSTGRES_* environment"
  fi
  return 0
}

setup_psql() {
  load_env_dsn
  if need_cmd psql && [[ -n "$DB_URL" ]]; then
    PSQL_CMD=(psql "$DB_URL" -v ON_ERROR_STOP=1 -q -X -A -t)
    if "${PSQL_CMD[@]}" -c 'SELECT 1' >/dev/null 2>&1; then
      PSQL_MODE="local"; dbg "psql: local client"; return 0
    fi
    dbg "local psql could not connect with the resolved DSN"
  fi
  if need_cmd docker && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$PG_CONTAINER"; then
    local db="${POSTGRES_DB:-deeptempo_soc}" user="${POSTGRES_USER:-deeptempo}"
    if [[ "$DB_URL" =~ ^postgres(ql)?://([^:/?#]+)(:[^@]*)?@[^/]+/([^?#]+) ]]; then
      user="${BASH_REMATCH[2]}"; db="${BASH_REMATCH[4]}"
    fi
    PSQL_CMD=(docker exec -i "$PG_CONTAINER" psql -U "$user" -d "$db" -v ON_ERROR_STOP=1 -q -X -A -t)
    if "${PSQL_CMD[@]}" -c 'SELECT 1' >/dev/null 2>&1; then
      PSQL_MODE="docker"; dbg "psql: docker exec ${PG_CONTAINER} (${user}/${db})"; return 0
    fi
  fi
  PSQL_CMD=(); PSQL_MODE=""
  return 1
}

require_db() {
  setup_psql || die "no reachable Postgres. Pass --db-url, set DATABASE_URL, or start the ${PG_CONTAINER} container. Use --dry-run to work without a database."
  local n
  n="$("${PSQL_CMD[@]}" -c "SELECT to_regclass('public.threat_indicators') IS NOT NULL" || true)"
  [[ "$n" == "t" ]] || die "table threat_indicators is absent — run Vigil's schema init (infra/database/init/14_threat_indicators.sql) first"
}

# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------
http_get() {
  local url="$1" out="$2"; shift 2
  local -a hdrs=("$@") args=()
  local h
  for h in "${hdrs[@]:-}"; do [[ -n "$h" ]] && args+=(-H "$h"); done
  curl --fail --silent --show-error --location \
       --max-time "$HTTP_TIMEOUT" --connect-timeout 10 \
       --retry 2 --retry-delay 2 \
       -A "$UA" "${args[@]}" -o "$out" "$url"
}

# Harvest candidate indicator tokens from a downloaded artifact.
harvest_tokens() {
  local kind="$1" file="$2"
  case "$kind" in
    text|csv|misp)
      sed -e 's/\r$//' -e 's/#.*$//' "$file"
      ;;
    json)
      # Schema-agnostic: every string/number leaf becomes a candidate.
      jq -r '[paths(scalars) as $p | getpath($p) | tostring] | .[]' "$file" 2>/dev/null \
        || sed -e 's/[{}",[]/ /g' "$file"
      ;;
  esac
}

fetch_source() {
  local src="$1" workdir="$2"
  local kind url lvl conf needs
  IFS='|' read -r kind url lvl conf needs <<<"${SOURCE_SPEC[$src]}"
  url="${url//__LIMIT__/$LIMIT}"

  local -a hdrs=()
  case "$needs" in
    abusech)
      [[ -n "${ABUSECH_AUTH_KEY:-}" ]] || { warn "${src}: ABUSECH_AUTH_KEY unset — abuse.ch requires an Auth-Key"; return 1; }
      hdrs+=("Auth-Key: ${ABUSECH_AUTH_KEY}")
      ;;
    otx)
      [[ -n "${OTX_API_KEY:-}" ]] || { warn "otx: OTX_API_KEY unset"; return 1; }
      hdrs+=("X-OTX-API-KEY: ${OTX_API_KEY}")
      ;;
  esac

  local raw="${workdir}/${src}.raw"
  if [[ "$kind" == "misp" ]]; then
    fetch_misp_feed "$url" "$raw" "${workdir}" || return 1
  else
    http_get "$url" "$raw" "${hdrs[@]:-}" || { warn "${src}: fetch failed (${url})"; return 1; }
  fi
  [[ -s "$raw" ]] || { warn "${src}: empty response"; return 1; }

  harvest_tokens "$kind" "$raw" > "${workdir}/${src}.tokens"
  return 0
}

# CIRCL OSINT MISP feed: manifest.json lists event uuids; pull the newest few.
fetch_misp_feed() {
  local base="$1" out="$2" workdir="$3"
  local manifest="${workdir}/misp-manifest.json"
  http_get "${base}/manifest.json" "$manifest" || { warn "circl_osint: manifest fetch failed"; return 1; }

  local -a uuids=()
  mapfile -t uuids < <(jq -r 'to_entries | sort_by(.value.date) | reverse | .[0:6] | .[].key' "$manifest" 2>/dev/null || true)
  ((${#uuids[@]})) || { warn "circl_osint: manifest carried no events"; return 1; }

  : > "$out"
  local u ev got=0
  for u in "${uuids[@]}"; do
    ev="${workdir}/misp-${u}.json"
    if http_get "${base}/${u}.json" "$ev"; then
      jq -r '(.Event.Attribute // [])[]?, ((.Event.Object // [])[]?.Attribute // [])[]?
             | select(.type | test("^(ip-src|ip-dst|domain|hostname|url|md5|sha1|sha256|email|email-src)$"))
             | .value' "$ev" >> "$out" 2>/dev/null || true
      got=1
    fi
    [[ "$(wc -l < "$out")" -ge "$LIMIT" ]] && break
  done
  (( got )) || return 1
  [[ -s "$out" ]] || return 1
  return 0
}

# ---------------------------------------------------------------------------
# Classification / validation:  tokens -> "type<TAB>value"
# ---------------------------------------------------------------------------
classify_tokens() {
  local allow_private="$1"
  # Deliberately free of interval expressions ({n,m}) and nested quantifiers:
  # mawk builds silently fail to match those, which would drop whole IOC
  # classes without any error. Lengths are checked with length() instead.
  awk -v allow_private="$allow_private" '
    function valid_v4(ip,   o, i) {
      if (split(ip, o, ".") != 4) return 0
      for (i = 1; i <= 4; i++) {
        if (o[i] !~ /^[0-9]+$/)                            return 0
        if (length(o[i]) > 3 || o[i] + 0 > 255)             return 0
        if (length(o[i]) > 1 && substr(o[i], 1, 1) == "0")  return 0
      }
      return 1
    }
    function reserved_v4(ip,   o) {
      split(ip, o, ".")
      if (o[1]+0 == 0   || o[1]+0 == 10  || o[1]+0 == 127) return 1
      if (o[1]+0 >= 224)                                   return 1
      if (o[1]+0 == 172 && o[2]+0 >= 16 && o[2]+0 <= 31)   return 1
      if (o[1]+0 == 192 && o[2]+0 == 168)                  return 1
      if (o[1]+0 == 169 && o[2]+0 == 254)                  return 1
      if (o[1]+0 == 100 && o[2]+0 >= 64 && o[2]+0 <= 127)  return 1
      return 0
    }
    function valid_domain(d,   parts, i, k, lbl) {
      if (d ~ /\.\./)          return 0
      k = split(d, parts, ".")
      if (k < 2)                return 0
      for (i = 1; i <= k; i++) {
        lbl = parts[i]
        if (length(lbl) < 1 || length(lbl) > 63) return 0
        if (lbl !~ /^[-_0-9a-z]+$/)              return 0
        if (lbl ~ /^[-_]/ || lbl ~ /[-_]$/)      return 0
      }
      if (parts[k] !~ /^[a-z]+$/ || length(parts[k]) < 2) return 0
      return 1
    }
    function valid_email(e,   parts) {
      if (split(e, parts, "@") != 2)  return 0
      if (length(parts[1]) < 1)       return 0
      return valid_domain(parts[2])
    }
    # Hosts that publish or index feeds: their own links show up inside CSV and
    # JSON payloads (urlhaus_link, references, pulse permalinks) and must never
    # become indicators.
    function is_feed_host(h,   probe, parts, k, i) {
      probe = h
      while (probe != "") {
        if (index(DENY, "|" probe "|") > 0) return 1
        i = index(probe, ".")
        if (i == 0) return 0
        probe = substr(probe, i + 1)
        if (split(probe, parts, ".") < 2) return 0
      }
      return 0
    }
    function url_host(u,   h, i) {
      h = u
      sub(/^[a-z]+:\/\//, "", h)
      i = index(h, "/");  if (i > 0) h = substr(h, 1, i - 1)
      i = index(h, "@");  if (i > 0) h = substr(h, i + 1)
      i = index(h, ":");  if (i > 0) h = substr(h, 1, i - 1)
      return h
    }
    function emit(t, v) { print t "\t" v }
    BEGIN {
      DENY = "|urlhaus.abuse.ch|threatfox.abuse.ch|feodotracker.abuse.ch" \
             "|bazaar.abuse.ch|sslbl.abuse.ch|abuse.ch|otx.alienvault.com" \
             "|alienvault.com|isc.sans.edu|sans.edu|circl.lu|misp-project.org" \
             "|torproject.org|blocklist.de|spamhaus.org|cisa.gov|mitre.org" \
             "|virustotal.com|github.com|githubusercontent.com|twitter.com" \
             "|x.com|t.co|pastebin.com|any.run|hybrid-analysis.com" \
             "|malwarebazaar.com|shadowserver.org|team-cymru.org|"
    }
    {
      n = split($0, f, /[[:space:],;|"'"'"']+/)
      for (i = 1; i <= n; i++) {
        t = f[i]
        gsub(/^[[:punct:]]+|[[:punct:]]+$/, "", t)
        if (t == "" || length(t) > 2048) continue

        # hashes: hex-only, length decides the algorithm
        if (t ~ /^[0-9a-fA-F]+$/) {
          if (length(t) == 64) { emit("hash_sha256", tolower(t)); continue }
          if (length(t) == 40) { emit("hash_sha1",   tolower(t)); continue }
          if (length(t) == 32) { emit("hash_md5",    tolower(t)); continue }
        }

        # urls — scheme lowercased for the test, value kept verbatim
        low = tolower(t)
        if (low ~ /^https?:\/\// && length(t) > 10) {
          if (!is_feed_host(url_host(low))) emit("url", t)
          continue
        }

        # email
        if (index(t, "@") > 0 && t ~ /^[[:alnum:]._%+-]+@[[:alnum:].-]+$/) {
          if (valid_email(low)) { emit("email", low); continue }
          continue
        }

        # ipv4, optionally with :port; /32 tolerated, real CIDR skipped
        cand = t
        sub(/:[0-9]+$/, "", cand)
        if (cand ~ /\/32$/) sub(/\/32$/, "", cand)
        if (index(cand, "/") > 0) continue   # CIDR: exact-match lookups cannot hit it
        if (cand ~ /^[0-9.]+$/) {
          if (!valid_v4(cand))                          continue
          if (!allow_private && reserved_v4(cand))       continue
          emit("ip", cand); continue
        }

        # ipv6: hex and colons only, 2..7 colons (documentation range included)
        if (low ~ /^[0-9a-f:]+$/ && index(low, ":") > 0) {
          if (index(low, "::") == 0 && low !~ /[a-f]/) continue  # e.g. 10:05:00
          colons = gsub(/:/, ":", low)
          if (colons >= 2 && colons <= 7 && length(low) <= 45) {
            if (!allow_private && (low ~ /^fe8/ || low ~ /^fc/ || low ~ /^fd/ || low == "::1")) continue
            emit("ip", low)
          }
          continue
        }

        # domain / hostname
        if (length(low) <= 253 && index(low, ".") > 0 && valid_domain(low)) {
          if (!is_feed_host(low)) emit("domain", low)
          continue
        }
      }
    }
  '
}

# ---------------------------------------------------------------------------
# Simulation layer:  "type<TAB>value" -> NDJSON rows ready for the DB
# ---------------------------------------------------------------------------
simulate_rows() {
  local src="$1" base_conf="$2" base_level="$3" synthetic="$4"
  local valid_from="$5" valid_until="$6"

  local sim_orgs_json orgs_arg
  sim_orgs_json="$(printf '%s\n' "${SIM_ORGS[@]}" | jq -R . | jq -sc .)"
  orgs_arg="$sim_orgs_json"

  jq -R -c \
    --arg src "$src" \
    --arg level "$base_level" \
    --argjson base_conf "$base_conf" \
    --argjson orgs "$orgs_arg" \
    --argjson sim_orgs "$SIM_AS_ORGS" \
    --argjson synthetic "$synthetic" \
    --arg valid_from "$valid_from" \
    --arg valid_until "$valid_until" '
    # deterministic per-value hash: stable jitter and stable org assignment
    def h: explode | reduce .[] as $c (17; (. * 131 + $c) % 100003);
    def clamp($lo; $hi): if . < $lo then $lo elif . > $hi then $hi else . end;
    def levels: ["low","medium","high","critical"];

    split("\t") as $r
    | select(($r | length) == 2 and $r[0] != "" and $r[1] != "")
    | ($r[0]) as $type
    | ($r[1]) as $value
    | ($value | h) as $hv
    | (if $sim_orgs == 1 then $orgs[$hv % ($orgs | length)] else $src end) as $source
    | (($base_conf + (($hv % 15) - 7)) | clamp(10; 95)) as $conf
    | ((levels | index($level)) // 1) as $li
    | ($li
       + (if ($hv % 7) == 0 then 1 else 0 end)
       - (if ($hv % 11) == 0 then 1 else 0 end)
       | clamp(0; 3)) as $lidx
    | (levels[$lidx]) as $threat
    | ("simulated-" + $src + "-" + ($hv | tostring)) as $stix_suffix
    | {
        indicator_type: $type,
        indicator_value: $value,
        source: $source,
        collection_id: ("sim/" + $src),
        confidence: $conf,
        threat_level: $threat,
        labels: ([
            "simulated",
            ("upstream:" + $src),
            ("ioc-type:" + $type)
          ] + (if $synthetic == 1 then ["synthetic"] else ["public-osint"] end)),
        valid_from: $valid_from,
        valid_until: $valid_until,
        raw_stix: {
          type: "indicator",
          spec_version: "2.1",
          id: ("indicator--" + ($stix_suffix | @base64 | ascii_downcase | .[0:8]
                 | gsub("[^a-f0-9]"; "0")) + "-0000-4000-8000-000000000000"),
          created: ($valid_from + "Z"),
          modified: ($valid_from + "Z"),
          name: ("Simulated " + $type + " indicator from " + $src),
          description: "Ingested by vigil-ioc-sim-ingest.sh. Simulated feed traffic — not a real subscription from this organization.",
          confidence: $conf,
          indicator_types: ["malicious-activity"],
          valid_from: ($valid_from + "Z"),
          valid_until: ($valid_until + "Z"),
          pattern_type: "stix",
          pattern: (
            if $type == "ip" then "[ipv4-addr:value = \u0027" + $value + "\u0027]"
            elif $type == "domain" then "[domain-name:value = \u0027" + $value + "\u0027]"
            elif $type == "url" then "[url:value = \u0027" + $value + "\u0027]"
            elif $type == "email" then "[email-addr:value = \u0027" + $value + "\u0027]"
            elif ($type | startswith("hash_")) then
              "[file:hashes.\u0027" + ($type | ltrimstr("hash_") | ascii_upcase
                 | if . == "SHA256" then "SHA-256" elif . == "SHA1" then "SHA-1" else . end)
                 + "\u0027 = \u0027" + $value + "\u0027]"
            else "[x-sim:value = \u0027" + $value + "\u0027]" end
          ),
          labels: ["simulated", ("upstream:" + $src)],
          x_vigil_simulated: true,
          x_vigil_upstream_source: $src,
          x_vigil_synthetic: ($synthetic == 1)
        }
      }
    '
}

# ---------------------------------------------------------------------------
# Synthetic generator (no egress): documentation ranges only
# ---------------------------------------------------------------------------
synth_tokens() {
  local src="$1" n="$2"
  # Deterministic by design: the same source id and count always produce the
  # same batch, so re-runs refresh rows instead of inflating the table.
  # mawk's srand()/rand() is not reliably reproducible, hence the explicit LCG.
  awk -v src="$src" -v n="$n" '
    function nexthex(len,   s, i) {
      s = ""
      for (i = 0; i < len; i++) {
        state = (state * 1103515245 + 12345) % 2147483648
        s = s substr("0123456789abcdef", int(state / 65536) % 16 + 1, 1)
      }
      return s
    }
    BEGIN {
      seed = 7
      for (i = 1; i <= length(src); i++)
        seed = (seed * 131 + index("abcdefghijklmnopqrstuvwxyz_-0123456789", substr(src, i, 1))) % 2147483647
      state = seed
      split("192.0.2 198.51.100 203.0.113", netv4, " ")
      split("mal sim lab drop c2 stage beacon phish", words, " ")
      for (i = 0; i < n; i++) {
        m = i % 5
        if (m == 0) {
          printf "ip\t%s.%d\n", netv4[(i % 3) + 1], (i % 254) + 1
        } else if (m == 1) {
          printf "domain\t%s-%04d.%s.invalid\n", words[(i % 8) + 1], i, src
        } else if (m == 2) {
          printf "url\thttp://%s.%d/%s/%04d\n", netv4[(i % 3) + 1], (i % 254) + 1, words[(i % 8) + 1], i
        } else if (m == 3) {
          printf "hash_sha256\t%s\n", nexthex(64)
        } else {
          printf "hash_md5\t%s\n", nexthex(32)
        }
      }
      # a pair of RFC 3849 documentation addresses for IPv6 coverage
      printf "ip\t2001:db8:%x::%x\n", seed % 65535, (seed % 254) + 1
      printf "ip\t2001:db8:%x::%x\n", (seed / 3) % 65535, (seed % 200) + 2
    }
  '
}

# ---------------------------------------------------------------------------
# Ingest: NDJSON -> CSV -> staged upsert
# ---------------------------------------------------------------------------
ndjson_to_csv() {
  jq -r '[
    .indicator_type, .indicator_value, .source, .collection_id,
    (.confidence | tostring), .threat_level, (.labels | join(",")),
    .valid_from, .valid_until, (.raw_stix | tojson)
  ] | @csv'
}

upsert_csv() {
  local csv="$1" rows result
  rows="$(wc -l < "$csv" | tr -d '[:space:]')"
  [[ "$rows" -gt 0 ]] || { printf '0|0\n'; return 0; }

  result="$(
    {
      cat <<'SQL_HEAD'
BEGIN;
CREATE TEMP TABLE _vigil_ioc_stage (
  indicator_type  text,
  indicator_value text,
  source          text,
  collection_id   text,
  confidence      text,
  threat_level    text,
  labels          text,
  valid_from      text,
  valid_until     text,
  raw_stix        text
) ON COMMIT DROP;
COPY _vigil_ioc_stage FROM STDIN WITH (FORMAT csv);
SQL_HEAD
      cat "$csv"
      printf '\\.\n'
      cat <<'SQL_TAIL'
WITH src AS (
  SELECT DISTINCT ON (source, indicator_type, indicator_value)
         indicator_type,
         indicator_value,
         source,
         nullif(collection_id, '')                       AS collection_id,
         nullif(confidence, '')::numeric(5,2)            AS confidence,
         nullif(threat_level, '')                        AS threat_level,
         CASE WHEN coalesce(labels, '') = '' THEN ARRAY[]::text[]
              ELSE string_to_array(labels, ',') END      AS labels,
         nullif(valid_from, '')::timestamp               AS valid_from,
         nullif(valid_until, '')::timestamp              AS valid_until,
         nullif(raw_stix, '')::jsonb                     AS raw_stix
    FROM _vigil_ioc_stage
   WHERE coalesce(indicator_value, '') <> ''
     AND length(indicator_value) <= 2048
     AND indicator_type IN ('ip','domain','url','hash_md5','hash_sha1','hash_sha256','email')
   ORDER BY source, indicator_type, indicator_value
), up AS (
  INSERT INTO threat_indicators (
    indicator_type, indicator_value, source, collection_id, confidence,
    threat_level, labels, valid_from, valid_until, raw_stix, first_seen, last_seen
  )
  SELECT indicator_type, indicator_value, source, collection_id, confidence,
         threat_level, labels, valid_from, valid_until, raw_stix, NOW(), NOW()
    FROM src
  ON CONFLICT (source, indicator_type, indicator_value) DO UPDATE
     SET last_seen    = NOW(),
         confidence   = COALESCE(EXCLUDED.confidence,   threat_indicators.confidence),
         threat_level = COALESCE(EXCLUDED.threat_level, threat_indicators.threat_level),
         labels       = CASE WHEN cardinality(EXCLUDED.labels) > 0
                             THEN EXCLUDED.labels ELSE threat_indicators.labels END,
         valid_until  = COALESCE(EXCLUDED.valid_until,  threat_indicators.valid_until),
         raw_stix     = COALESCE(EXCLUDED.raw_stix,     threat_indicators.raw_stix)
  RETURNING (xmax = 0) AS was_insert
)
SELECT count(*) FILTER (WHERE was_insert) || '|' || count(*) FILTER (WHERE NOT was_insert)
  FROM up;
COMMIT;
SQL_TAIL
    } | "${PSQL_CMD[@]}" -f - 2>&1
  )" || { err "upsert failed: ${result}"; return 1; }

  # last non-empty line holds "inserted|updated"
  printf '%s\n' "$result" | grep -E '^[0-9]+\|[0-9]+$' | tail -1
}

purge_simulated() {
  require_db
  local n
  n="$("${PSQL_CMD[@]}" -c "WITH d AS (DELETE FROM threat_indicators WHERE 'simulated' = ANY(labels) RETURNING 1) SELECT count(*) FROM d")"
  ok "purged ${n} simulated indicator(s); real feed rows untouched"
}

show_stats() {
  require_db
  printf '\n%sthreat_indicators inventory%s\n' "$C_BLD" "$C_RST"
  "${PSQL_CMD[@]}" -P 'format=aligned' -P 'border=1' -P 'tuples_only=off' -c "
    SELECT source,
           count(*)                                        AS rows,
           count(*) FILTER (WHERE 'simulated' = ANY(labels)) AS simulated,
           count(*) FILTER (WHERE 'synthetic' = ANY(labels)) AS synthetic,
           min(first_seen)::timestamp(0)                   AS first_seen,
           max(last_seen)::timestamp(0)                    AS last_seen,
           count(*) FILTER (WHERE valid_until < NOW())     AS expired
      FROM threat_indicators
     GROUP BY source
     ORDER BY rows DESC;"
  "${PSQL_CMD[@]}" -P 'format=aligned' -P 'border=1' -P 'tuples_only=off' -c "
    SELECT indicator_type, count(*) AS rows
      FROM threat_indicators GROUP BY indicator_type ORDER BY rows DESC;"
}

enable_lookup_integration() {
  local cfg="${VIGIL_DIR:-$HOME/.vigil}/integrations_config.json"
  mkdir -p "$(dirname "$cfg")"
  [[ -f "$cfg" ]] || printf '{"enabled_integrations": []}\n' > "$cfg"
  if jq -e '.enabled_integrations | index("cloudforce_one")' "$cfg" >/dev/null 2>&1; then
    log "finding-enrichment lookup already enabled in ${cfg}"
    return 0
  fi
  local tmp="${cfg}.tmp.$$"
  jq '.enabled_integrations = ((.enabled_integrations // []) + ["cloudforce_one"] | unique)' "$cfg" > "$tmp"
  mv "$tmp" "$cfg"
  ok "enabled the threat_indicators lookup in ${cfg} (restart the daemon to pick it up)"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
WORKDIR=""
cleanup() {
  local rc=$?
  if [[ -n "$WORKDIR" && -d "$WORKDIR" ]]; then
    if (( KEEP_ARTIFACTS )); then
      log "artifacts kept in ${WORKDIR}"
    else
      rm -rf -- "$WORKDIR"
    fi
  fi
  return $rc
}

main() {
  parse_args "$@"
  check_deps

  (( ENABLE_LOOKUP )) && enable_lookup_integration
  (( DO_PURGE ))      && { purge_simulated; exit 0; }
  (( DO_STATS ))      && { show_stats; exit 0; }

  resolve_sources "$SOURCES_ARG"

  # Serialize runs so a cron overlap cannot double-ingest.
  if need_cmd flock; then
    exec 9>"$LOCK_FILE" || die "cannot open lock file ${LOCK_FILE}"
    flock -n 9 || die "another ${PROG} run holds ${LOCK_FILE}"
  fi

  WORKDIR="$(mktemp -d -t vigil-ioc-sim.XXXXXX)"
  trap cleanup EXIT
  local artifact_dir="$WORKDIR"
  if [[ -n "$OUT_DIR" ]]; then
    mkdir -p "$OUT_DIR"; artifact_dir="$OUT_DIR"
  fi

  local valid_from valid_until
  valid_from="$(date -u '+%Y-%m-%dT%H:%M:%S')"
  valid_until="$(date -u -d "+${TTL_DAYS} days" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null \
                 || date -u -v"+${TTL_DAYS}d" '+%Y-%m-%dT%H:%M:%S')"

  if (( DRY_RUN )); then
    warn "dry run: no database writes"
  else
    require_db
    log "database: ${PSQL_MODE}"
  fi

  local ndjson="${artifact_dir}/indicators.ndjson"
  : > "$ndjson"

  local -a summary=()
  local total_norm=0 src kind url lvl conf needs

  for src in "${SELECTED[@]}"; do
    IFS='|' read -r kind url lvl conf needs <<<"${SOURCE_SPEC[$src]}"
    local synthetic=0 tokens="${WORKDIR}/${src}.tokens"

    if (( SYNTHETIC_ONLY )); then
      synth_tokens "$src" "$LIMIT" > "$tokens"; synthetic=1
      dbg "${src}: synthetic batch (synthetic-only mode)"
    elif fetch_source "$src" "$WORKDIR"; then
      dbg "${src}: fetched $(wc -l < "$tokens") candidate line(s)"
    elif (( ALLOW_SYNTHETIC )); then
      warn "${src}: falling back to a synthetic batch"
      synth_tokens "$src" "$LIMIT" > "$tokens"; synthetic=1
    else
      err "${src}: unreachable and --no-synthetic is set"
      summary+=("${src}|failed|0|0")
      continue
    fi

    local normalized="${WORKDIR}/${src}.norm"
    if (( synthetic )); then
      # already type-tagged; still validate through the classifier's rules
      cut -f2 "$tokens" | classify_tokens "$ALLOW_PRIVATE" \
        | sort -u | head -n "$LIMIT" > "$normalized"
    else
      classify_tokens "$ALLOW_PRIVATE" < "$tokens" \
        | sort -u | head -n "$LIMIT" > "$normalized"
    fi

    local n
    n="$(wc -l < "$normalized" | tr -d '[:space:]')"
    if [[ "$n" -eq 0 ]]; then
      warn "${src}: nothing survived validation"
      summary+=("${src}|empty|0|0")
      continue
    fi

    simulate_rows "$src" "$conf" "$lvl" "$synthetic" "$valid_from" "$valid_until" \
      < "$normalized" >> "$ndjson"

    total_norm=$(( total_norm + n ))
    summary+=("${src}|$( ((synthetic)) && echo synthetic || echo fetched )|${n}|0")
    log "${src}: ${n} indicator(s) normalized$( ((synthetic)) && echo ' (synthetic)' )"
  done

  [[ -s "$ndjson" ]] || die "no indicators produced — nothing to ingest"

  local csv="${artifact_dir}/indicators.csv"
  ndjson_to_csv < "$ndjson" > "$csv"
  local csv_rows
  csv_rows="$(wc -l < "$csv" | tr -d '[:space:]')"

  if (( DRY_RUN )); then
    ok "dry run complete: ${csv_rows} row(s) staged"
    printf '  NDJSON : %s\n  CSV    : %s\n' "$ndjson" "$csv" >&2
    printf '\n%ssample%s\n' "$C_BLD" "$C_RST" >&2
    head -3 "$ndjson" | jq -c '{source, indicator_type, indicator_value, confidence, threat_level, labels}' >&2
    print_summary "$csv_rows" "-" "-"
    return 0
  fi

  local res inserted updated
  res="$(upsert_csv "$csv")" || die "ingest failed"
  inserted="${res%%|*}"; updated="${res##*|}"
  local collapsed=$(( csv_rows - inserted - updated ))
  (( collapsed < 0 )) && collapsed=0
  ok "staged ${csv_rows} row(s) -> ${inserted} inserted, ${updated} refreshed, ${collapsed} duplicate(s) collapsed"
  print_summary "$csv_rows" "$inserted" "$updated"

  local live
  live="$("${PSQL_CMD[@]}" -c "SELECT count(*) FROM threat_indicators WHERE 'simulated' = ANY(labels)" || echo '?')"
  log "threat_indicators now holds ${live} simulated row(s) — 'simulated' label makes them purgeable with --purge"

  local cfg="${VIGIL_DIR:-$HOME/.vigil}/integrations_config.json"
  if ! jq -e '.enabled_integrations | index("cloudforce_one")' "$cfg" >/dev/null 2>&1; then
    warn "finding enrichment will not consult this table until the lookup is enabled — run: ${PROG} --enable-lookup"
  fi
}

print_summary() {
  local rows="$1" inserted="$2" updated="$3" line s mode n
  printf '\n%s%-16s %-10s %8s%s\n' "$C_BLD" SOURCE MODE INDICATORS "$C_RST" >&2
  for line in "${summary[@]}"; do
    IFS='|' read -r s mode n _ <<<"$line"
    printf '%-16s %-10s %8s\n' "$s" "$mode" "$n" >&2
  done
  printf '%s%-16s %-10s %8s%s\n' "$C_DIM" "TOTAL" "csv" "$rows" "$C_RST" >&2
  [[ "$inserted" != "-" ]] && printf '%sinserted=%s updated=%s%s\n' "$C_DIM" "$inserted" "$updated" "$C_RST" >&2
  return 0
}

main "$@"
