#!/bin/bash
# SecureClaw Advisor — Cognitive File Integrity Check
set -euo pipefail

OPENCLAW_DIR=""
for dir in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot" "$HOME/clawd"; do
  [ -d "$dir" ] && OPENCLAW_DIR="$dir" && break
done

[ -z "$OPENCLAW_DIR" ] && echo "❌ No OpenClaw installation found" && exit 1

BASELINE_DIR="$OPENCLAW_DIR/.secureclaw/baselines"
COG_FILES="SOUL.md IDENTITY.md TOOLS.md AGENTS.md SECURITY.md MEMORY.md"

if [ ! -d "$BASELINE_DIR" ]; then
  echo "ℹ️ No baselines found. Creating initial baselines..."
  mkdir -p "$BASELINE_DIR"
  CREATED=0
  for f in $COG_FILES; do
    if [ -f "$OPENCLAW_DIR/$f" ]; then
      shasum -a 256 "$OPENCLAW_DIR/$f" > "$BASELINE_DIR/$f.sha256"
      CREATED=$((CREATED + 1))
    fi
  done
  if [ $CREATED -eq 0 ]; then
    echo "⚠️  No cognitive files found to baseline."
  else
    echo "✅ Baselines created for $CREATED file(s). Future runs will detect changes."
  fi
  exit 0
fi

echo "🔒 Checking cognitive file integrity..."

TAMPERED=0
MISSING=0
CHECKED=0

for f in $COG_FILES; do
  if [ -f "$BASELINE_DIR/$f.sha256" ]; then
    if [ -f "$OPENCLAW_DIR/$f" ]; then
      EXPECTED=$(awk '{print $1}' "$BASELINE_DIR/$f.sha256")
      CURRENT=$(shasum -a 256 "$OPENCLAW_DIR/$f" | awk '{print $1}')
      CHECKED=$((CHECKED + 1))
      if [ "$EXPECTED" != "$CURRENT" ]; then
        echo "🔴 TAMPERED: $f — hash mismatch (was: ${EXPECTED:0:12}... now: ${CURRENT:0:12}...)"
        TAMPERED=$((TAMPERED + 1))
      else
        echo "✅ OK: $f"
      fi
    else
      echo "🔴 DELETED: $f — baseline exists but file is missing!"
      MISSING=$((MISSING + 1))
    fi
  elif [ -f "$OPENCLAW_DIR/$f" ]; then
    echo "⚠️  NEW: $f — exists but has no baseline (run quick-harden.sh to create one)"
  fi
done

ISSUES=$((TAMPERED + MISSING))

if [ $ISSUES -gt 0 ]; then
  echo ""
  echo "🚨 $ISSUES cognitive file issue(s) detected!"
  [ $TAMPERED -gt 0 ] && echo "   $TAMPERED file(s) modified since last baseline."
  [ $MISSING -gt 0 ] && echo "   $MISSING file(s) deleted since last baseline."
  echo ""
  echo "   If these changes were intentional, update baselines:"
  echo "   bash $(dirname "$0")/quick-harden.sh"
  echo ""
  echo "   If NOT intentional, your agent may be compromised!"
  echo "   Recommended: review the changed files immediately."
  exit 2
elif [ $CHECKED -eq 0 ]; then
  echo "⚠️  No cognitive files found to check."
else
  echo ""
  echo "✅ All $CHECKED cognitive file(s) intact."
fi
