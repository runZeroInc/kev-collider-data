#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

LOGFILE="$ROOT/update.log"
JSON_DIR="$ROOT/json"
CURRENT_BRANCH="$(git symbolic-ref --short HEAD)"

list_json_files() {
  ls -1 "$JSON_DIR"/*.json 2>/dev/null | xargs -n1 basename | sort || true
}

log() {
  echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*" | tee -a "$LOGFILE"
}

fail() {
  log "ERROR: $*"
  exit 1
}

log "START: Updating sources and regenerating KEV JSON..."
git pull -r || fail "Failed rebase. Merge conflict, or uncommitted changes?"

BEFORE_JSON_FILES="$(list_json_files)"

# update_submodule_shallow: fetch only the tip commit (--depth 1).
# Suitable for submodules where only the current working-tree contents matter
# (no git-log history needed).  Works correctly on fresh checkouts and on
# cached/incremental runs alike; force-pushes are handled transparently
# because reset --hard never rebase-diverges.
update_submodule_shallow() {
  local rel_path="$1" branch="$2"
  log "Updating (shallow) $rel_path"
  if [ ! -e "$ROOT/$rel_path/.git" ]; then
    git submodule update --init --depth 1 -- "$rel_path" \
      || fail "Shallow init failed: $rel_path"
  fi
  git -C "$ROOT/$rel_path" fetch --depth 1 origin "$branch" \
    || fail "Shallow fetch failed: $rel_path"
  git -C "$ROOT/$rel_path" reset --hard FETCH_HEAD \
    || fail "Reset failed: $rel_path"
}

# update_submodule_full: fetch the complete history (no --depth limit).
# Required for submodules where `git log --follow` is used to find per-file
# first-commit dates (metasploit-framework, nuclei-templates).  On CI the
# caller is expected to restore a cached .git object store before running
# this script so that the fetch is incremental rather than a full clone.
# reset --hard handles upstream force-pushes without manual intervention.
update_submodule_full() {
  local rel_path="$1" branch="$2" sparse_path="${3:-}"
  log "Updating (full history) $rel_path"
  if [ ! -e "$ROOT/$rel_path/.git" ]; then
    git submodule update --init -- "$rel_path" \
      || fail "Full init failed: $rel_path"
  fi
  if [ -n "$sparse_path" ]; then
    git -C "$ROOT/$rel_path" sparse-checkout set --no-cone "$sparse_path" \
      || fail "Sparse checkout failed: $rel_path"
  fi
  git -C "$ROOT/$rel_path" fetch origin "$branch" \
    || fail "Fetch failed: $rel_path"
  git -C "$ROOT/$rel_path" reset --hard "origin/$branch" \
    || fail "Reset failed: $rel_path"
}

# Shallow submodules — current working-tree content is all that is needed.
update_submodule_shallow "sources/cvelistV5"   "main"
update_submodule_shallow "sources/kev-data"    "develop"
update_submodule_shallow "sources/ctid"        "main"
update_submodule_shallow "sources/epss_scores" "main"

# Full-history submodules — git log is used for first-commit-date lookups.
update_submodule_full "sources/metasploit-framework" "master" "modules"
update_submodule_full "sources/nuclei-templates"     "main"

git add sources || fail "Failed to add sources"
git commit --allow-empty -m "Update sources" || fail "Failed committing source updates"
git push origin "$CURRENT_BRANCH" || fail "Source pointer push failed"

log "Running collect-cves.rb"
./collect-cves.rb || fail "Failed on collect-cves.rb"

log "Running generate_kev_contexts.rb"
rm -f "$JSON_DIR"/*.json || fail "Failed to rm existing JSON files"
./bin/generate_kev_contexts.rb || fail "Failed on generate_kev_contexts.rb"

log "Running validator.rb"
./bin/validator.rb || fail "Failed on validator.rb, is something funny going on?"
log "Validation passed, publishing"

log "Running generate_vendor_product_report.sh"
./bin/generate_vendor_product_report.sh || fail "Failed on generate_vendor_product_report.sh"

git add "$JSON_DIR" "$ROOT/schema" "$ROOT/reports" || fail "Failed git add $JSON_DIR"
git commit -m "Updating KEV JSON" || fail "Failed committing $JSON_DIR"
git push origin "$CURRENT_BRANCH" || fail "KEV JSON push failed"

AFTER_JSON_FILES="$(list_json_files)"
NEW_JSON_FILES="$(comm -13 <(printf '%s\n' "$BEFORE_JSON_FILES" | sed '/^$/d') <(printf '%s\n' "$AFTER_JSON_FILES" | sed '/^$/d'))"

if [ -n "$NEW_JSON_FILES" ]; then
  log "New KEV JSON files added this run:"
  while IFS= read -r file; do
    log "  + $file"
  done <<< "$NEW_JSON_FILES"
else
  log "No new KEV JSON files added this run."
fi

log "END: Publish complete"
