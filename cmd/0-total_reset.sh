#!/usr/bin/env bash
# DANGER ERASE: PKI, TRUST, CERTS, DATABASE, VOLUMES, KEYS

# This script resets everything created by 1‑pki_setup.sh and docker compose.
#   • Stops containers & prunes buildx
#   • Drops data volumes
#   • Wipes cryptographic artefacts in pki/ (roots + leafs) while keeping .gitkeep
#   • Resets test collections in MongoDB if container running
set -euo pipefail

GREEN='\033[1;32m'; RED='\033[1;31m'; NC='\033[0m'
say(){ printf "${GREEN}%s${NC}\n" "$*"; }
err(){ printf "${RED}%s${NC}\n" "$*" >&2; exit 1; }


# Current State
############################################################################
SCRIPT_DIR="$(realpath "$(dirname -- "${BASH_SOURCE[0]}")")"
if [[ -d "$SCRIPT_DIR/pki" ]]; then
  PROJECT_ROOT="$SCRIPT_DIR"
else
  PROJECT_ROOT="$(realpath "$SCRIPT_DIR/..")"
fi
cd "$PROJECT_ROOT" || err "Cannot cd into project root ($PROJECT_ROOT)"
trap 'cd "$PROJECT_ROOT"' EXIT

PKI_DIR="$PROJECT_ROOT/pki"
PINS_DIR="$PROJECT_ROOT/nginx/pins"

# 0) Reset MongoDB database if running
############################################################################
if [ "$(docker container inspect -f '{{.State.Running}}' mongodb 2>/dev/null)" = "true" ]; then
  say "🗑️  Resetting MongoDB documents.."
  docker exec mongodb mongosh -u admin -p adminpassword \
    --authenticationDatabase admin test --eval '
      db.trustedusers.deleteMany({});
      db.users.deleteMany({});
      db.organizations.deleteMany({});
      db.videos.deleteMany({});
      db.videochunks.deleteMany({});
      db.logs.deleteMany({});
    ' || say "⚠️  MongoDB reset failed — continuing anyway"
else
  say "⚠️  MongoDB container not running — skipping DB reset"
fi

# 1) Stop stack
############################################################################
say "📦  docker compose down.."
docker system df
docker compose down --remove-orphans || true
docker rm -f step-ca 2>/dev/null || true


# 2) Drop data volumes
############################################################################
say "🗑  Removing volumes stepca-data & mongodb_data.."
docker volume rm -f stepca-data mongodb_data seccam_stepca-data 2>/dev/null || true
docker system prune -a --volumes -f
docker builder prune -af

# 3) Drop certs, keys & symlinks in pki/
############################################################################
clean_tree() {
  local dir="$1"
  [[ -d $dir ]] || return 0
  # make writable (keys 400)
  find "$dir" -type f ! -name '.gitkeep' -exec chmod u+w {} + 2>/dev/null || true
  # remove files & symlinks
  find "$dir" \( -type f -o -type l \) ! -name '.gitkeep' -exec rm -f {} + 2>/dev/null || true
  # catch root‑owned
  if find "$dir" \( -type f -o -type l \) ! -name '.gitkeep' | grep -q .; then
    echo "↪ root-owned leftovers in $dir, treating.."
    sudo find "$dir" \( -type f -o -type l \) ! -name '.gitkeep' -exec rm -f {} +
  fi
}

say "🧹  Cleaning-up certs"
USER_ID=$(id -un)

clean_tree "$PKI_DIR"
clean_tree "$PINS_DIR"

rm -f "$PROJECT_ROOT/step-root.pem" "$PROJECT_ROOT/.step-ca-password" "$PROJECT_ROOT/${USER_ID}.p12"

# 4) Init clean buildx
############################################################################
say "🔧  Init seccam-builder.."
docker buildx rm -f seccam seccam-builder 2>/dev/null || true

docker buildx create --name seccam-builder --driver docker-container --use
docker buildx inspect --bootstrap
docker ps --filter name=buildx_

DOC="$PROJECT_ROOT/cmd/1-pki_setup.sh"
printf "\n✅  Reset complete. You should now configure PKI with script:\n"
say "         (here) file://$DOC"
