FROM node:20-alpine

RUN set -eux; \
    apk add --no-cache curl gnupg ca-certificates; \
    curl -fsSL https://packages.smallstep.com/keys/apt/repo-signing-key.gpg -o /etc/apk/keys/smallstep.asc; \
    echo "https://packages.smallstep.com/stable/alpine/edge/main" >> /etc/apk/repositories; \
    apk add --no-cache step-cli

WORKDIR /app/step

COPY package.json ./

RUN npm install --omit=dev --no-audit --no-fund

COPY server.js ./

EXPOSE 3001

CMD ["node", "server.js"]
