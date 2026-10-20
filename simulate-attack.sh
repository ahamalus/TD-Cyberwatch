#!/usr/bin/env bash
# Simulate a website compromise on the LOCAL sample site so you can watch CyberWatch detect it.
# The "web shell" written here is inert text that merely looks suspicious; nothing is executed.
#
#   ./simulate-attack.sh         plant a fake web shell, deface the home page, delete a page
#   ./simulate-attack.sh reset   restore the sample site to its original state
set -euo pipefail
cd "$(dirname "$0")/deploy/local"

SITE=sample-site/public_html

if [ "${1:-}" = "reset" ]; then
  # Restore in place: the folder itself is mounted into the running containers.
  find "$SITE" -mindepth 1 -delete
  cp -R sample-site-original/public_html/. "$SITE/"
  echo "Sample site restored. Run a scan to see CyberWatch return to normal."
  exit 0
fi

cat > "$SITE/wp-content/uploads/wso-shell.php" <<'EOF'
<?php
/* CyberWatch local test file: harmless text that resembles a web shell. Not executable code. */
// eval(base64_decode($_POST['cmd']));  <- typical attacker pattern, commented out
EOF
printf '\n<!-- hacked by test-crew: simulated defacement for CyberWatch testing -->\n' >> "$SITE/index.html"
rm -f "$SITE/about.html"

echo "Simulated attack applied to deploy/local/$SITE:"
echo "  + added    wp-content/uploads/wso-shell.php   (script in an upload directory, web-shell name)"
echo "  ~ modified index.html                         (defacement)"
echo "  - deleted  about.html"
echo
echo "Now open the website in CyberWatch and click 'Run scan' (or wait for the schedule)."
echo "Undo with: ./simulate-attack.sh reset"
