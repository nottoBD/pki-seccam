FROM node:20-alpine AS base

WORKDIR /app/client

COPY package*.json ./

ARG NEXT_PUBLIC_BACKEND_CERT_FINGERPRINT
ENV NEXT_PUBLIC_BACKEND_CERT_FINGERPRINT=$NEXT_PUBLIC_BACKEND_CERT_FINGERPRINT

FROM base AS deps
RUN --mount=type=cache,target=/root/.npm \
    npm config set registry https://registry.npmmirror.com && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000 && \
    npm install --prefer-offline --no-audit --no-fund --omit=dev


FROM base
RUN npm install -g npm@latest
COPY --from=deps /app/client/node_modules ./node_modules

COPY . .

EXPOSE 3443

CMD ["npm", "run", "dev"]