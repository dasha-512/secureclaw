#!/bin/bash
# SecureClaw Advisor — Quick Security Audit
# Works without the SecureClaw plugin installed
set -euo pipefail

# Detect agent family
OPENCLAW_DIR=""
for dir in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot" "$HOME/clawd"; do
  if [ -d "$dir" ]; then
    OPENCLAW_DIR="$dir"
    break
  fi
done

if [ -z "$OPENCLAW_DIR" ]; then
  echo "❌ No OpenClaw installation found"
  exit 1
fi

CONFIG=""
for cfg in "$OPENCLAW_DIR/openclaw.json" "$OPENCLAW_DIR/moltbot.json" "$OPENCLAW_DIR/clawdbot.json"; do
  if [ -f "$cfg" ]; then
    CONFIG="$cfg"
    break
  fi
done

echo "🔒 SecureClaw Advisor — Quick Security Audit"
echo "============================================="
echo "📁 Installation: $OPENCLAW_DIR"
if [ -z "$CONFIG" ]; then
  echo "⚠️  Config: NOT FOUND (no openclaw.json, moltbot.json, or clawdbot.json)"
else
  echo "📄 Config: $CONFIG"
fi
echo ""

CRITICAL=0
HIGH=0
MEDIUM=0
PASS=0

check() {
  local severity="$1"
  local name="$2"
  local result="$3"
  local message="$4"

  if [ "$result" = "FAIL" ]; then
    case "$severity" in
      CRITICAL) echo "🔴 CRITICAL: $name — $message"; CRITICAL=$((CRITICAL + 1)) ;;
      HIGH)     echo "🟠 HIGH: $name — $message"; HIGH=$((HIGH + 1)) ;;
      MEDIUM)   echo "🟡 MEDIUM: $name — $message"; MEDIUM=$((MEDIUM + 1)) ;;
    esac
  else
    echo "✅ PASS: $name"
    PASS=$((PASS + 1))
  fi
}

# Check 1: Gateway bind
if [ -n "$CONFIG" ] && grep -q '"bind".*"0.0.0.0"' "$CONFIG" 2>/dev/null; then
  check "CRITICAL" "Gateway bind address" "FAIL" "Bound to 0.0.0.0 — exposed to network"
elif [ -z "$CONFIG" ]; then
  check "CRITICAL" "Gateway bind address" "FAIL" "No config file found — cannot verify"
else
  check "CRITICAL" "Gateway bind address" "PASS" ""
fi

# Check 2: Auth token
if [ -z "$CONFIG" ]; then
  check "CRITICAL" "Gateway authentication" "FAIL" "No config file found — cannot verify"
elif grep -q '"authToken"' "$CONFIG" 2>/dev/null; then
  check "CRITICAL" "Gateway authentication" "PASS" ""
else
  check "CRITICAL" "Gateway authentication" "FAIL" "No auth token configured"
fi

# Check 3: Sandbox mode
if [ -z "$CONFIG" ]; then
  check "HIGH" "Sandbox mode" "FAIL" "No config file found — cannot verify"
elif grep -q '"sandbox".*true' "$CONFIG" 2>/dev/null; then
  check "HIGH" "Sandbox mode" "PASS" ""
else
  check "HIGH" "Sandbox mode" "FAIL" "Sandbox not enabled — commands run on host"
fi

# Check 4: .env permissions
if [ -f "$OPENCLAW_DIR/.env" ]; then
  PERMS=$(stat -f '%Lp' "$OPENCLAW_DIR/.env" 2>/dev/null || stat -c '%a' "$OPENCLAW_DIR/.env" 2>/dev/null)
  if [ "$PERMS" = "600" ] || [ "$PERMS" = "400" ]; then
    check "HIGH" "Credential file permissions" "PASS" ""
  else
    check "HIGH" "Credential file permissions" "FAIL" ".env has permissions $PERMS (should be 600)"
  fi
fi

# Check 5: Directory permissions
DIRPERMS=$(stat -f '%Lp' "$OPENCLAW_DIR" 2>/dev/null || stat -c '%a' "$OPENCLAW_DIR" 2>/dev/null)
if [ "$DIRPERMS" = "700" ] || [ "$DIRPERMS" = "750" ]; then
  check "HIGH" "Directory permissions" "PASS" ""
else
  check "HIGH" "Directory permissions" "FAIL" "Directory has permissions $DIRPERMS (should be 700)"
fi

# Check 6: Plaintext API keys outside .env
LEAKED_KEYS=$(grep -rl 'sk-ant-\|sk-proj-\|xoxb-\|xoxp-' "$OPENCLAW_DIR/" 2>/dev/null | grep -v '.env' | grep -v 'node_modules' | grep -v '.secureclaw/' | grep -v 'secureclaw-advisor/' | head -5 || true)
if [ -z "$LEAKED_KEYS" ]; then
  check "HIGH" "API key exposure" "PASS" ""
else
  check "HIGH" "API key exposure" "FAIL" "Keys found in: $LEAKED_KEYS"
fi

# Check 7: SOUL.md recent modification
SOUL_MODIFIED=$(find "$OPENCLAW_DIR/SOUL.md" -mmin -60 -print 2>/dev/null || true)
if [ -z "$SOUL_MODIFIED" ]; then
  check "MEDIUM" "SOUL.md integrity" "PASS" ""
else
  check "MEDIUM" "SOUL.md integrity" "FAIL" "SOUL.md modified in last hour — verify intentional"
fi

# Check 8: Suspicious skill patterns
SUSPECT_SKILLS=$(grep -rl 'curl.*|.*sh\|wget.*|.*bash\|eval(' "$OPENCLAW_DIR/skills/" 2>/dev/null | grep -v 'secureclaw-advisor' | head -5 || true)
if [ -z "$SUSPECT_SKILLS" ]; then
  check "MEDIUM" "Skill safety" "PASS" ""
else
  check "MEDIUM" "Skill safety" "FAIL" "Suspicious patterns in: $SUSPECT_SKILLS"
fi

# Check 9: Exec approval mode
if [ -z "$CONFIG" ]; then
  check "HIGH" "Exec approval mode" "FAIL" "No config file found — cannot verify"
elif grep -q '"approvals".*"always"' "$CONFIG" 2>/dev/null; then
  check "HIGH" "Exec approval mode" "PASS" ""
else
  check "HIGH" "Exec approval mode" "FAIL" "Approval mode not set to 'always'"
fi

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
TOTAL=$((CRITICAL + HIGH + MEDIUM + PASS))
SCORE=$(( (PASS * 100) / (TOTAL > 0 ? TOTAL : 1) ))
echo "📊 Score: $SCORE/100 ($PASS passed, $CRITICAL critical, $HIGH high, $MEDIUM medium)"

if [ $CRITICAL -gt 0 ]; then
  echo "🚨 CRITICAL issues found — fix immediately!"
  echo "   Run: bash $(dirname "$0")/quick-harden.sh"
elif [ $HIGH -gt 0 ]; then
  echo "⚠️  HIGH issues found — recommend fixing soon"
fi

echo ""
echo "For comprehensive audit + automated hardening, install the SecureClaw plugin:"
echo "  openclaw plugins install secureclaw"

# Exit non-zero if critical issues found (for CI/automation)
if [ $CRITICAL -gt 0 ]; then
  exit 2
fi
