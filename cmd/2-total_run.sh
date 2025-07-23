#!/usr/bin/env bash
set -euo pipefail

function say() { echo -e "\033[32m$*\033[0m"; }
function sayRed() { echo -e "\033[31m$*\033[0m"; }
function err() { echo -e "\033[31m$*\033[0m"; exit 1; }

USER_ID=$(id -un)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ROOT}/.env"
ROOTS_DIR="$ROOT/pki/roots"
P12_PASS=$(grep -E '^BROWSER_P12_PASSWORD=' "$ENV_FILE" | cut -d= -f2)

CLIENT_CERT="$ROOT/pki/leafs/browser/${USER_ID}.fullchain.crt"
CLIENT_KEY="$ROOT/pki/leafs/browser/${USER_ID}.key"
P12_BUNDLE="$ROOT/pki/leafs/browser/${USER_ID}.p12"

# detect compose implementation
if docker compose version &>/dev/null; then
    COMPOSE_CMD=("docker" "compose")
    say "Using compose: docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD=("docker-compose")
    say "Using compose: docker-compose"
else
    sayRed "Neither 'docker-compose' nor 'docker compose' found. Install Docker Compose v2."
fi

say "Project root: ${ROOT}"
cd "$ROOT" || sayRed "Project root not found."

if [[ -f "$ENV_FILE" ]]; then
    say "Using env-file: $ENV_FILE"
    ENV_OPTS=(--env-file "$ENV_FILE")
else
    say "No .env file found: relying on docker-compose.yml env-var"
    ENV_OPTS=()
fi

function reset_builder() {
    say "Resetting builder..."
    docker buildx rm -f seccam seccam-builder 2>/dev/null || true
    docker buildx create --name seccam-builder --driver docker-container --use
    docker buildx inspect --bootstrap
    docker ps --filter name=buildx_
}

if ! docker buildx use seccam-builder 2>/dev/null; then
    say "Initializing builder..."
    reset_builder
fi

say "Stopping previous stack.."
"${COMPOSE_CMD[@]}" "${ENV_OPTS[@]}" down --remove-orphans

function run_compose() {
    local cmd=("${COMPOSE_CMD[@]}" "${ENV_OPTS[@]}" "$@")
    sayRed "Executing: ${cmd[*]}"

    local output
    if ! output=$(
        set -o pipefail
        "${cmd[@]}" 2>&1 | tee /dev/tty
    ); then
        if [[ $output == *"read |0: file"* ]]; then
            say "Builder error detected – resetting"
            reset_builder
            say "Retrying: ${cmd[*]}"
            "${cmd[@]}"
        else
            err "Command failed: ${cmd[*]}\n$output"
        fi
    fi
}

run_compose up -d --build;

say "Waiting for containers to initialize..."
sleep 2

say "👉  Inspecting self-signed root cert:"
openssl x509 -in "$ROOT"/step-root.pem -noout -text | grep -E 'Issuer:|Subject:|Self-signed'
sleep 1

say "👉  Inspecting fullchain.crt inside step-ca container:"
docker exec step-ca step certificate inspect /home/step/leaf/server.fullchain.crt
sleep 2

c_rehash "$ROOTS_DIR"

say "👉  Inspecting TLS handshake:"
curl -v --capath "$ROOTS_DIR" \
           --cert-type P12 --cert "${P12_BUNDLE}:${P12_PASS}" \
           https://localhost:3443/ -o /dev/null
sleep 1

printf "\n"
printf "\n"

say "👉  Mailpit Leaf-cert testing email:"
  bash -c "
  curl -s -X POST https://localhost:3443/mailpit/api/v1/send \
    --cert-type P12 \
    --cert "${P12_BUNDLE}:"${P12_PASS}"" \
    --cacert ./step-root.pem \
    -H 'Content-Type: application/json' \
    -d '{\"From\":{\"Email\":\"bob@seccam.be\"},\"To\":[{\"Email\":\"david.botton@ulb.be\"}],\"Subject\":\"Mailpit Security Posture\",\"Text\":\"Here is Mailpit UI, with its own Step‑CA signed leaf certificate, Web UI & REST API are served only over HTTPS on 3025, mTLS is enforced everywhere in the network starting at nginx, TLS handshakes are fully verified. SMTP listens on 1025 with STARTTLS required, advertising the same certificate, so NodeMailer refuses to downgrade TLS. Certificate pinning is enabled on every request client to server (cfr. X-Server-Cert field). All on‑wire traffic is encrypted and MITM-proof within the limits of the Docker network.\"}' && printf 'You have received an email at Mailpit!'
  "

printf "\n\n Remember to flush cache and cookies.\n"
say " Client   @ https://localhost:3443"
say " Server   @ https://localhost:8888"
say " Mailpit  @ https://localhost:3025"
