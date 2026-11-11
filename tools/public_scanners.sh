#!/usr/bin/env bash
# Run the free, well-known malware scanners over a DOWNLOADED copy of the site.
#
#   tools/public_scanners.sh SITE_DIR [OUT_DIR]
#
# Uses whatever is installed; prints install hints for what is missing:
#   ClamAV       + Linux Malware Detect (rfxn) signatures + SaneSecurity signatures.
#                  Stock ClamAV misses most PHP web shells; the rfxn signatures are what catch them.
#   YARA         + php-malware-finder rules (data/php.yar ONLY: the files under its
#                  data/whitelists/ are exclusion lists, not detection rules).
#   WP-CLI       `wp core verify-checksums` only. It does not load WordPress, so it is safe
#                  on a hacked copy. Do NOT run `wp plugin verify-checksums` (or anything else
#                  that boots WordPress) on the hacked copy: that executes the malware.
#                  verify_extensions.py does the plugin check without running anything.
#
# Read-only. Results go to OUT_DIR (default: ./scan-results-<date>), outside the site.
set -u
SITE=${1:?usage: public_scanners.sh SITE_DIR [OUT_DIR]}
OUT=${2:-./scan-results-$(date +%Y%m%d-%H%M%S)}
[ -d "$SITE/wp-includes" ] || { echo "$SITE does not look like a WordPress root" >&2; exit 2; }
mkdir -p "$OUT"
echo "results -> $OUT"

# --- ClamAV ---------------------------------------------------------------
if command -v clamscan >/dev/null; then
  DBS=()
  for d in "${CLAM_DB_DIRS:-}" /var/lib/clamav /usr/local/share/clamav /opt/homebrew/var/lib/clamav; do
    [ -n "$d" ] && [ -d "$d" ] && DBS+=("$d")
  done
  echo "== clamscan (db: ${DBS[*]:-default})"
  if ! ls "${DBS[@]:-/var/lib/clamav}" 2>/dev/null | grep -q '^rfxn'; then
    echo "   NOTE: no rfxn.* signatures found. Get them from Linux Malware Detect:"
    echo "         https://www.rfxn.com/projects/linux-malware-detect/ (copy rfxn.hdb/rfxn.ndb/rfxn.yara"
    echo "         into the ClamAV database folder). SaneSecurity: https://sanesecurity.com/usage/"
  fi
  clamscan -r -i --no-summary --max-filesize=20M --max-scansize=50M "$SITE" > "$OUT/clamav.txt" 2>&1
  echo "   $(grep -c FOUND "$OUT/clamav.txt") hit(s) -> $OUT/clamav.txt"
else
  echo "== clamscan: not installed (Debian/Ubuntu: apt install clamav; macOS: brew install clamav; then freshclam)"
fi

# --- YARA + php-malware-finder -------------------------------------------
PMF=${PMF_RULES:-}
for c in ./php-malware-finder/data/php.yar "$HOME/php-malware-finder/data/php.yar"; do
  [ -z "$PMF" ] && [ -f "$c" ] && PMF=$c
done
if command -v yara >/dev/null && [ -n "$PMF" ]; then
  echo "== yara + php-malware-finder ($PMF)"
  yara -r -w "$PMF" "$SITE" > "$OUT/yara-pmf.txt" 2> "$OUT/yara-errors.txt"
  echo "   $(wc -l < "$OUT/yara-pmf.txt") hit(s) -> $OUT/yara-pmf.txt"
  echo "   php-malware-finder is noisy by design (it flags obfuscation). Hits in files that"
  echo "   verify_core.py / verify_extensions.py say are pristine can be ignored."
else
  echo "== yara: skipped. Install yara (apt install yara / brew install yara) and"
  echo "   git clone https://github.com/jvoisin/php-malware-finder (or set PMF_RULES=/path/to/php.yar)"
fi

# --- WP-CLI core checksums ------------------------------------------------
if command -v wp >/dev/null; then
  echo "== wp core verify-checksums"
  wp core verify-checksums --path="$SITE" --skip-plugins --skip-themes > "$OUT/wp-core-checksums.txt" 2>&1
  tail -1 "$OUT/wp-core-checksums.txt" | sed 's/^/   /'
else
  echo "== wp-cli: not installed (optional; tools/verify_core.py does the same job)"
fi
echo "done. Read the hits; a scanner hit is a lead, not a verdict."
