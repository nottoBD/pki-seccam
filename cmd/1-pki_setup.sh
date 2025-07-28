#!/usr/bin/env bash

# helpers
################################################################################
function say() { echo -e "\033[32m$*\033[0m"; }
function err() { echo -e "\033[31m$*\033[0m"; exit 1; }

script_dir=$(realpath "$(dirname "$0")")
if [[ -d "$script_dir/../pki" ]]; then
    export PROJECT_ROOT=$(realpath "$script_dir/..")
else
    export PROJECT_ROOT=$script_dir
fi
cd "$PROJECT_ROOT" || err "Failed to enter $PROJECT_ROOT"

# layout variables
################################################################################
export PKI_DIR="$PROJECT_ROOT/pki"
export LEAFS_DIR="$PKI_DIR/leafs"
export ROOTS_DIR="$PKI_DIR/roots"
mkdir -p "$LEAFS_DIR/server" "$LEAFS_DIR/client" "$LEAFS_DIR/mailpit" "$ROOTS_DIR" "$LEAFS_DIR/browser" "$ROOTS_DIR"

# 1) Fresh password
################################################################################
if [[ -f .step-ca-password ]]; then
    export CA_PASSWORD=$(<.step-ca-password)
else
    export CA_PASSWORD=$(openssl rand -hex 32)
    echo -n "$CA_PASSWORD" > .step-ca-password
    chmod 600 .step-ca-password
fi

docker buildx use seccam-builder

# 2) Launch new CA
################################################################################
docker rm -f step-ca step-ca-bootstrap 2>/dev/null || true
docker volume rm -f stepca-data        2>/dev/null || true
docker volume create stepca-data

docker run -d --name step-ca \
  -v stepca-data:/home/step \
  -e DOCKER_STEPCA_INIT_NAME="SecCam-SSD/CA" \
  -e DOCKER_STEPCA_INIT_PASSWORD="$CA_PASSWORD" \
  -e DOCKER_STEPCA_INIT_DNS_NAMES="localhost,step-ca" \
  -e DOCKER_STEPCA_INIT_IPS="127.0.0.1" \
  -e DOCKER_STEPCA_INIT_ACME="true" \
  -e DOCKER_STEPCA_INIT_KTY="RSA" \
  -e DOCKER_STEPCA_INIT_SIZE="2048" \
  -p 9000-9001:9000-9001 \
  smallstep/step-ca:0.28.4

# wait for root ca max 20"
for _ in {1..20}; do
  docker exec step-ca test -f /home/step/certs/root_ca.crt && break
  sleep 1
done

# sync password file, then persist it to .env and shred the temp file
docker exec step-ca sh -c "echo $CA_PASSWORD > /home/step/secrets/password"

ENV_FILE="$PROJECT_ROOT/.env"; touch "$ENV_FILE"
if grep -q '^STEP_CA_PASSWORD=' "$ENV_FILE"; then
  sed -i.bak "s|^STEP_CA_PASSWORD=.*|STEP_CA_PASSWORD=$CA_PASSWORD|" "$ENV_FILE"
else
 echo "STEP_CA_PASSWORD=$CA_PASSWORD" >> "$ENV_FILE"
fi
say "🔑  STEP_CA_PASSWORD stored in $(basename "$ENV_FILE")"
# securely delete the temporary password file
shred -u .step-ca-password

# 3) Provisioner
################################################################################
docker exec step-ca step ca provisioner add seccam-provisioner \
  --type JWK --create --x509-max-dur 8760h --x509-default-dur 8760h \
  --password-file /home/step/secrets/password 2>/dev/null || true

# reload
docker exec step-ca kill -HUP 1 && sleep 1

# 4) Leaf certs
################################################################################
docker exec step-ca bash -c '
  set -e
  mkdir -p /home/step/leaf
  export STEP_CA_URL=https://localhost:9000
  export STEP_ROOT=/home/step/certs/root_ca.crt
  export STEP_PASSWORD_FILE=/home/step/secrets/password

  for name in server client mailpit; do
    step ca certificate ${name}.seccam.internal \
      /home/step/leaf/${name}.crt \
      /home/step/leaf/${name}.key \
      --provisioner seccam-provisioner --password-file $STEP_PASSWORD_FILE \
      --san ${name}.seccam.internal \
      --san $name \
      --san localhost --san 127.0.0.1 --san ::1 \
      --not-after 8760h \
      --kty RSA --size 2048
done'

# 5) Build full chains
################################################################################
docker exec step-ca bash -c '
INT=/home/step/certs/intermediate_ca.crt
for name in server client mailpit; do
  cat /home/step/leaf/${name}.crt "$INT" > /home/step/leaf/${name}.fullchain.crt
done'

docker cp step-ca:/home/step/certs/root_ca.crt         "$ROOTS_DIR/step-root.pem"
docker cp step-ca:/home/step/certs/intermediate_ca.crt "$ROOTS_DIR/intermediate_ca.crt"
ln -sf intermediate_ca.crt "$ROOTS_DIR/$(openssl x509 -noout -hash -in "$ROOTS_DIR/intermediate_ca.crt").0"
command -v c_rehash >/dev/null 2>&1 && c_rehash "$ROOTS_DIR" || openssl rehash "$ROOTS_DIR"

# 6)  Browser client certificate for global mTLS
###############################################################################
USER_ID=$(id -un)
BROWSER_DIR="$LEAFS_DIR/browser"
mkdir -p "$BROWSER_DIR"

# pw PKCS#12 bundle = securesoftware
source "$PROJECT_ROOT/.env" 2>/dev/null || true
P12_PASSWORD="${BROWSER_P12_PASSWORD:-securesoftware}"

REMOTE_DIR="/home/step/leaf/browser"
docker exec step-ca mkdir -p "$REMOTE_DIR"

docker exec step-ca bash -c "
  set -e
  step ca certificate \
    ${USER_ID}.browser.seccam.internal \
    ${REMOTE_DIR}/${USER_ID}.crt \
    ${REMOTE_DIR}/${USER_ID}.key \
    --provisioner seccam-provisioner \
    --password-file /home/step/secrets/password \
    --san ${USER_ID} --san ${USER_ID}.browser \
    --not-after 8760h --kty RSA --size 2048

  cat  ${REMOTE_DIR}/${USER_ID}.crt  /home/step/certs/intermediate_ca.crt \
       > ${REMOTE_DIR}/${USER_ID}.fullchain.crt
"

for ext in key fullchain.crt; do
  docker cp "step-ca:${REMOTE_DIR}/${USER_ID}.${ext}" \
            "$BROWSER_DIR/${USER_ID}.${ext}"
done

openssl pkcs12 -export \
  -inkey   "$BROWSER_DIR/${USER_ID}.key" \
  -in      "$BROWSER_DIR/${USER_ID}.fullchain.crt" \
  -certfile "$ROOTS_DIR/step-root.pem" \
  -name    "SecCam ${USER_ID}" \
  -password pass:"$P12_PASSWORD" \
  -out     "$BROWSER_DIR/${USER_ID}.p12"

cp "$BROWSER_DIR/${USER_ID}.p12" "$PROJECT_ROOT/${USER_ID}.p12"


# 7) Copy to host
################################################################################
for name in server client mailpit; do
  remote_base="/home/step/leaf/${name}"
  local_dir="$LEAFS_DIR/${name}"
  docker cp step-ca:${remote_base}.fullchain.crt "$local_dir/fullchain.crt"
  docker cp step-ca:${remote_base}.key             "$local_dir/${name}.key"
done

CHAIN="$ROOTS_DIR/clients_ca_chain.pem"
cat "$ROOTS_DIR/step-root.pem" "$ROOTS_DIR/intermediate_ca.crt" > "$CHAIN"

echo -e "\033[33m🛈  Browser certificate created:"
echo -e "    • Files in $BROWSER_DIR"
echo -e "    • Import bundle at $PROJECT_ROOT/${USER_ID}.p12  (password: $P12_PASSWORD)\033[0m"

cp "$ROOTS_DIR/step-root.pem" "$PROJECT_ROOT/step-root.pem"

docker rm -f step-ca step-ca-bootstrap 2>/dev/null || true

export SSL_CERT_FILE="$ROOTS_DIR/step-root.pem" #CAfile(anchor)
export SSL_CERT_DIR="$ROOTS_DIR" #CApath(c_rehash)

# fingerprint from fullchain (leaf first cert)
BACKEND_CERT_PATH="$LEAFS_DIR/server/fullchain.crt"
CERT_FINGERPRINT=$(openssl x509 -in "$BACKEND_CERT_PATH" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A)
CA_ROOT_FINGERPRINT=$(openssl x509 -in "$ROOTS_DIR/step-root.pem" -outform der | openssl dgst -sha256 | sed 's/^.* //' | tr 'A-F' 'a-f')

say "👉 CA root SHA‑256 fingerprint:"; printf "%s $CA_ROOT_FINGERPRINT"
say "\n👉 Server cert SHA‑256 fingerprint:"; printf "%s $CERT_FINGERPRINT"

ENV_FILE="$PROJECT_ROOT/.env"; touch "$ENV_FILE"

if grep -q '^NEXT_PUBLIC_BACKEND_CERT_FINGERPRINT=' "$ENV_FILE"; then
  sed -i.bak "s|^NEXT_PUBLIC_BACKEND_CERT_FINGERPRINT=.*|NEXT_PUBLIC_BACKEND_CERT_FINGERPRINT=$CERT_FINGERPRINT|" "$ENV_FILE"
  printf "\n (Updated server fingerprint)"
else
  echo "NEXT_PUBLIC_BACKEND_CERT_FINGERPRINT=$CERT_FINGERPRINT" >> "$ENV_FILE"
  printf "\n (Appended server fingerprint)"
fi
if grep -q '^TOTP_KEY=' "$ENV_FILE"; then
  sed -i.bak "s|^TOTP_KEY=.*|TOTP_KEY=$(openssl rand -hex 32)|" "$ENV_FILE"
  printf "\n (Updated TOTP key)"
else
  echo "TOTP_KEY=$(openssl rand -hex 32)" >> "$ENV_FILE"
  printf "\n (Appended TOTP key)"
fi
if grep -q '^NEXT_PUBLIC_CA_ROOT_FINGERPRINT=' "$ENV_FILE"; then
  sed -i.bak "s|^NEXT_PUBLIC_CA_ROOT_FINGERPRINT=.*|NEXT_PUBLIC_CA_ROOT_FINGERPRINT=$CA_ROOT_FINGERPRINT|" "$ENV_FILE"
  printf "\n (Updated CA root fingerprint)"
else
  echo "NEXT_PUBLIC_CA_ROOT_FINGERPRINT=$CA_ROOT_FINGERPRINT" >> "$ENV_FILE"
  printf "\n (Appended CA root fingerprint)"
fi
printf "\n"


PIN_DIR="$PROJECT_ROOT/nginx/pins";  mkdir -p "$PIN_DIR"
cp "$LEAFS_DIR/server/fullchain.crt"     "$PIN_DIR/server.crt"
cp "$LEAFS_DIR/client/fullchain.crt"     "$PIN_DIR/client.crt"
cp "$LEAFS_DIR/mailpit/fullchain.crt"    "$PIN_DIR/mailpit.crt"


################################################################################

say "👉  Certificate fingerprint successfully configured."
say "👉  Now import fresh $PROJECT_ROOT/step-root.pem & ${USER_ID}.p12 into client trust store!"

DOCKER_SCRIPT="$PROJECT_ROOT/cmd/2-total_run.sh"
say "PKI ready, next step includes running Docker Compose using its wrapper script:"
say "         (here) file://$DOCKER_SCRIPT"
