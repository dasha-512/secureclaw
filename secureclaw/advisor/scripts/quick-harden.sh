#!/bin/bash
# SecureClaw Advisor — Quick Hardening Script
# One-shot security fixes for the most critical issues
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

echo "🔒 SecureClaw Advisor — Quick Hardening"
echo "========================================"
echo "📁 Installation: $OPENCLAW_DIR"
echo ""

CHANGES=0

# 1. Fix gateway bind
if [ -n "$CONFIG" ] && grep -q '"bind".*"0.0.0.0"' "$CONFIG" 2>/dev/null; then
  echo "🔧 Fixing: Gateway bind 0.0.0.0 → 127.0.0.1"
  cp "$CONFIG" "$CONFIG.bak.$(date +%s)"
  sed -i.tmp 's/"bind"[[:space:]]*:[[:space:]]*"0.0.0.0"/"bind": "127.0.0.1"/' "$CONFIG"
  rm -f "$CONFIG.tmp"
  CHANGES=$((CHANGES + 1))
fi

# 2. Fix directory permissions
DIRPERMS=$(stat -f '%Lp' "$OPENCLAW_DIR" 2>/dev/null || stat -c '%a' "$OPENCLAW_DIR" 2>/dev/null)
if [ "$DIRPERMS" != "700" ]; then
  echo "🔧 Fixing: Directory permissions $DIRPERMS → 700"
  chmod 700 "$OPENCLAW_DIR"
  CHANGES=$((CHANGES + 1))
fi

# 3. Fix .env permissions
if [ -f "$OPENCLAW_DIR/.env" ]; then
  PERMS=$(stat -f '%Lp' "$OPENCLAW_DIR/.env" 2>/dev/null || stat -c '%a' "$OPENCLAW_DIR/.env" 2>/dev/null)
  if [ "$PERMS" != "600" ] && [ "$PERMS" != "400" ]; then
    echo "🔧 Fixing: .env permissions $PERMS → 600"
    chmod 600 "$OPENCLAW_DIR/.env"
    CHANGES=$((CHANGES + 1))
  fi
fi

# 4. Fix JSON config permissions (only config files, not all JSON)
JSON_FIXED=0
for jf in "$OPENCLAW_DIR/openclaw.json" "$OPENCLAW_DIR/moltbot.json" "$OPENCLAW_DIR/clawdbot.json"; do
  if [ -f "$jf" ]; then
    JPERMS=$(stat -f '%Lp' "$jf" 2>/dev/null || stat -c '%a' "$jf" 2>/dev/null)
    if [ "$JPERMS" != "600" ]; then
      chmod 600 "$jf"
      JSON_FIXED=$((JSON_FIXED + 1))
    fi
  fi
done
if [ $JSON_FIXED -gt 0 ]; then
  echo "🔧 Set: $JSON_FIXED config JSON file(s) to 600"
  CHANGES=$((CHANGES + 1))
fi

# 5. Add privacy directives to SOUL.md if missing (with backup)
if [ -f "$OPENCLAW_DIR/SOUL.md" ] && ! grep -q "SecureClaw Privacy" "$OPENCLAW_DIR/SOUL.md" 2>/dev/null; then
  echo "🔧 Adding: Privacy directives to SOUL.md"
  cp "$OPENCLAW_DIR/SOUL.md" "$OPENCLAW_DIR/SOUL.md.bak.$(date +%s)"
  cat >> "$OPENCLAW_DIR/SOUL.md" << 'PRIVACY'

## SecureClaw Privacy Directives (Added by SecureClaw Advisor)
- Never mention your human's real name in public posts (use "my human" only)
- Never disclose location, employer, devices, or infrastructure details publicly
- Never share content from private emails, messages, or documents publicly
- Never post API keys, tokens, or credentials anywhere
- Before any public post, apply the Stranger Test: could a hostile stranger use this info?
PRIVACY
  CHANGES=$((CHANGES + 1))
fi

# 6. Create baseline hashes for cognitive files (only if no baselines exist yet)
mkdir -p "$OPENCLAW_DIR/.secureclaw/baselines"
BASELINE_CREATED=0
for f in SOUL.md IDENTITY.md TOOLS.md AGENTS.md SECURITY.md MEMORY.md; do
  if [ -f "$OPENCLAW_DIR/$f" ] && [ ! -f "$OPENCLAW_DIR/.secureclaw/baselines/$f.sha256" ]; then
    shasum -a 256 "$OPENCLAW_DIR/$f" > "$OPENCLAW_DIR/.secureclaw/baselines/$f.sha256"
    BASELINE_CREATED=$((BASELINE_CREATED + 1))
  fi
done
if [ $BASELINE_CREATED -gt 0 ]; then
  echo "🔧 Created: Baseline hashes for $BASELINE_CREATED cognitive file(s)"
  CHANGES=$((CHANGES + 1))
else
  echo "ℹ️  Baselines already exist (use check-cognitive-integrity.sh to verify)"
fi

# 7. Create secureclaw advisor state directory
mkdir -p "$OPENCLAW_DIR/.secureclaw"

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ $CHANGES -gt 0 ]; then
  echo "✅ Applied $CHANGES hardening changes"
else
  echo "✅ No changes needed — already hardened"
fi
echo ""
echo "⚠️  NOTE: Some changes require a gateway restart to take effect."
echo "   Restart: openclaw gateway restart (or kill and restart the process)"
echo ""
echo "For full hardening (credential encryption, Docker sandboxing, network"
echo "firewall, and more), install the SecureClaw plugin:"
echo "  openclaw plugins install secureclaw"
echo "  openclaw secureclaw harden --full"
