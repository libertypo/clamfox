#!/usr/bin/env bash
set -euo pipefail

# Local runtime hygiene cleanup for ClamFox.
# - Default mode: dry-run (print what would be removed)
# - Apply mode:   ./scripts/local_hygiene.sh --apply

MODE="dry-run"
FORCE="false"

for arg in "$@"; do
  case "$arg" in
    --apply)
      MODE="apply"
      ;;
    --force)
      FORCE="true"
      ;;
    *)
      echo "Unknown argument: $arg"
      echo "Usage: ./scripts/local_hygiene.sh [--apply] [--force]"
      exit 2
      ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

TARGETS=(
  "host/config.json"
  "host/host_debug.log"
  "host/alert_log.txt"
  "host/tpm_debug.err"
  "host/decode_log.py"
  "host/urldb.txt"
  "host/phishdb.txt"
  "host/whitelistdb.txt"
  "host/vault_sealed_priv.bin"
  "host/vault_sealed_pub.bin"
  "host/verify.sig"
  "host/verify_digest"
  "host/verify_pub"
  "host/vault_pub.pem"
  ".clamfox_host.log"
)

EXTRA_GLOBS=(
  "host/urldb.txt.*"
  "host/phishdb.txt.*"
  "host/whitelistdb.txt.*"
)

found=()
for p in "${TARGETS[@]}"; do
  [[ -e "$p" ]] && found+=("$p")
done

for g in "${EXTRA_GLOBS[@]}"; do
  while IFS= read -r f; do
    [[ -n "$f" ]] && found+=("$f")
  done < <(compgen -G "$g" || true)
done

if [[ ${#found[@]} -eq 0 ]]; then
  echo "No local runtime artifacts found."
  exit 0
fi

# Deduplicate sorted for stable output.
mapfile -t unique_found < <(printf '%s\n' "${found[@]}" | awk '!seen[$0]++' | sort)

safe_candidates=()
skipped_candidates=()

for p in "${unique_found[@]}"; do
  # Never remove tracked files unless explicitly forced.
  if git ls-files --error-unmatch -- "$p" >/dev/null 2>&1; then
    if [[ "$FORCE" == "true" ]]; then
      safe_candidates+=("$p")
    else
      skipped_candidates+=("$p (tracked file)")
    fi
    continue
  fi

  # Prefer removing only ignored/runtime artifacts unless forced.
  if git check-ignore -q -- "$p"; then
    safe_candidates+=("$p")
  else
    if [[ "$FORCE" == "true" ]]; then
      safe_candidates+=("$p")
    else
      skipped_candidates+=("$p (not ignored)")
    fi
  fi
done

echo "Mode: $MODE"
echo "Runtime artifacts detected:"
printf ' - %s\n' "${unique_found[@]}"

if [[ ${#skipped_candidates[@]} -gt 0 ]]; then
  echo "Skipped by safety guard:"
  printf ' - %s\n' "${skipped_candidates[@]}"
fi

if [[ ${#safe_candidates[@]} -eq 0 ]]; then
  echo "No removable runtime artifacts remain after safety checks."
  exit 0
fi

echo "Eligible for cleanup:"
printf ' - %s\n' "${safe_candidates[@]}"

if [[ "$MODE" == "dry-run" ]]; then
  if [[ "$FORCE" == "true" ]]; then
    echo "Dry-run complete. Re-run with --apply --force to remove eligible files."
  else
    echo "Dry-run complete. Re-run with --apply to remove eligible files. Use --force to override safety checks."
  fi
  exit 0
fi

removed=0
for p in "${safe_candidates[@]}"; do
  if [[ -e "$p" ]]; then
    rm -f -- "$p"
    ((removed+=1))
  fi
done

echo "Removed $removed artifact(s)."
